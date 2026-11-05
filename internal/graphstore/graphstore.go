// Package graphstore persists Trojan's Code Property Graph (internal/graph) to
// a local SQLite file, so the graph built during one run can be reused and
// incrementally updated in the next instead of being rebuilt from scratch
// every time. This is what makes the graph "compounding local memory" rather
// than a scratch structure that disappears when the process exits.
//
// Save does a full replace of the nodes and edges tables, and Load reads them
// back verbatim, including node keys, the Tags map that internal/orgcontext
// layers onto nodes, and datastore nodes with their reads/writes edges.
// Refresh (refresh.go) adds incremental rebuilds on top, using the
// file_hashes table to skip parsing languages whose files haven't changed.
//
// Storage engine: modernc.org/sqlite, a pure-Go (CGO-free) transpile of
// SQLite accessed through database/sql. This keeps CGO_ENABLED=0 working,
// which the desktop app's cross-compiled builds depend on. Do not switch this
// to mattn/go-sqlite3 or any other cgo-based driver.
//
// Convergence with internal/rag (layer 4): today internal/rag's semantic
// index (internal/rag/store.go) lives in its own flat file, separate from
// this graph database. The natural next step, once sqlite-vec (or an
// equivalent pure-Go vector extension) is wired in, is to add a vector table
// to this same SQLite file alongside `nodes` and `edges`, so the graph
// (layers 1-3) and the embeddings (layer 4) live in one local database file
// per project instead of two separate stores. That migration is out of scope
// here.
package graphstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/dev-zeph/trojan/internal/graph"
)

// DefaultDBPath is the conventional location for the local graph database,
// relative to a project root.
const DefaultDBPath = ".trojan/graph.db"

// SchemaVersion is the graph.db layout this package writes, stored in SQLite's
// user_version. v1 (user_version 0) had no keys, no Guarded/ClientSide, no
// batch bookkeeping and no file_hashes; open migrates it in place.
const SchemaVersion = 2

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
	id          INTEGER PRIMARY KEY,
	kind        TEXT NOT NULL,
	name        TEXT NOT NULL,
	file        TEXT NOT NULL,
	line        INTEGER NOT NULL,
	source      INTEGER NOT NULL,
	pii         INTEGER NOT NULL,
	sink_rule   TEXT NOT NULL,
	severity    TEXT NOT NULL,
	tags        TEXT NOT NULL,
	node_key    TEXT NOT NULL DEFAULT '',
	guarded     INTEGER NOT NULL DEFAULT 0,
	client_side INTEGER NOT NULL DEFAULT 0,
	batches     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS edges (
	src  INTEGER NOT NULL,
	dst  INTEGER NOT NULL,
	kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_hashes (
	relpath  TEXT PRIMARY KEY,
	language TEXT NOT NULL,
	sha256   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// v2Columns are the nodes columns added in schema v2, with the definitions
// ALTER TABLE uses to add them to a v1 database.
var v2Columns = []struct{ name, def string }{
	{"node_key", "TEXT NOT NULL DEFAULT ''"},
	{"guarded", "INTEGER NOT NULL DEFAULT 0"},
	{"client_side", "INTEGER NOT NULL DEFAULT 0"},
	{"batches", "TEXT NOT NULL DEFAULT ''"},
}

// Save persists g to the SQLite database at dbPath, creating the file and
// schema if they do not already exist. This pass does a full replace: any
// existing nodes and edges rows are dropped and rewritten from g.
//
// A graph saved this way isn't tied to a known set of file contents, so Save
// also clears the file hashes; the next Refresh then does a full rebuild
// instead of trusting a graph it can't vouch for.
func Save(dbPath string, g *graph.Graph) error {
	return save(dbPath, g, nil, "")
}

// save writes g and, when hashes is non-nil, replaces the file_hashes table
// and records root (the project root the keys were computed against) in the
// same transaction. With hashes nil the cache is invalidated.
func save(dbPath string, g *graph.Graph, hashes []fileHash, root string) error {
	if g == nil {
		return fmt.Errorf("graphstore: nil graph")
	}

	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("graphstore: begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op if committed

	if err := writeHashes(tx, hashes, root); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM nodes`); err != nil {
		return fmt.Errorf("graphstore: clear nodes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM edges`); err != nil {
		return fmt.Errorf("graphstore: clear edges: %w", err)
	}

	nodeStmt, err := tx.Prepare(`INSERT INTO nodes (id, kind, name, file, line, source, pii, sink_rule, severity, tags,
		node_key, guarded, client_side, batches)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("graphstore: prepare node insert: %w", err)
	}
	defer nodeStmt.Close()

	for _, n := range g.Nodes {
		tagsJSON, err := marshalTags(n.Tags)
		if err != nil {
			return fmt.Errorf("graphstore: marshal tags for node %d: %w", n.ID, err)
		}
		if _, err := nodeStmt.Exec(n.ID, string(n.Kind), n.Name, n.File, n.Line,
			boolToInt(n.Source), boolToInt(n.PII), n.SinkRule, n.Severity, tagsJSON,
			n.Key, boolToInt(n.Guarded), boolToInt(n.ClientSide), strings.Join(n.Batches, ",")); err != nil {
			return fmt.Errorf("graphstore: insert node %d: %w", n.ID, err)
		}
	}

	edgeStmt, err := tx.Prepare(`INSERT INTO edges (src, dst, kind) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("graphstore: prepare edge insert: %w", err)
	}
	defer edgeStmt.Close()

	for _, e := range g.Edges {
		if _, err := edgeStmt.Exec(e.Src, e.Dst, string(e.Kind)); err != nil {
			return fmt.Errorf("graphstore: insert edge (%d->%d): %w", e.Src, e.Dst, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("graphstore: commit: %w", err)
	}
	return nil
}

// Load reads the graph persisted at dbPath. If the database or its tables do
// not exist yet, Load returns an empty graph (via graph.New) and no error, so
// callers can treat "no prior run" the same as "empty graph".
func Load(dbPath string) (*graph.Graph, error) {
	db, err := open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return loadDB(db)
}

// loadDB reads the graph from an already-open database.
func loadDB(db *sql.DB) (*graph.Graph, error) {
	g := graph.New()

	rows, err := db.Query(`SELECT id, kind, name, file, line, source, pii, sink_rule, severity, tags,
		node_key, guarded, client_side, batches
		FROM nodes ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("graphstore: query nodes: %w", err)
	}

	var nodes []graph.Node
	for rows.Next() {
		var (
			n          graph.Node
			kind       string
			sourceInt  int
			piiInt     int
			tagsJSON   string
			guardedInt int
			clientInt  int
			batches    string
		)
		if err := rows.Scan(&n.ID, &kind, &n.Name, &n.File, &n.Line, &sourceInt, &piiInt,
			&n.SinkRule, &n.Severity, &tagsJSON, &n.Key, &guardedInt, &clientInt, &batches); err != nil {
			rows.Close()
			return nil, fmt.Errorf("graphstore: scan node: %w", err)
		}
		n.Kind = graph.NodeKind(kind)
		n.Source = sourceInt != 0
		n.PII = piiInt != 0
		n.Guarded = guardedInt != 0
		n.ClientSide = clientInt != 0
		if batches != "" {
			n.Batches = strings.Split(batches, ",")
		}
		tags, err := unmarshalTags(tagsJSON)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("graphstore: unmarshal tags for node %d: %w", n.ID, err)
		}
		n.Tags = tags
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("graphstore: iterate nodes: %w", err)
	}
	rows.Close()

	edgeRows, err := db.Query(`SELECT src, dst, kind FROM edges ORDER BY rowid ASC`)
	if err != nil {
		return nil, fmt.Errorf("graphstore: query edges: %w", err)
	}

	var edges []graph.Edge
	for edgeRows.Next() {
		var e graph.Edge
		var kind string
		if err := edgeRows.Scan(&e.Src, &e.Dst, &kind); err != nil {
			edgeRows.Close()
			return nil, fmt.Errorf("graphstore: scan edge: %w", err)
		}
		e.Kind = graph.EdgeKind(kind)
		edges = append(edges, e)
	}
	if err := edgeRows.Err(); err != nil {
		edgeRows.Close()
		return nil, fmt.Errorf("graphstore: iterate edges: %w", err)
	}
	edgeRows.Close()

	g.Nodes = nodes
	g.Edges = edges
	return g, nil
}

// open opens (creating if necessary) the SQLite database at dbPath, ensures
// the schema exists, and migrates older layouts to SchemaVersion.
func open(dbPath string) (*sql.DB, error) {
	if err := ensureDir(dbPath); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("graphstore: open %s: %w", dbPath, err)
	}

	// modernc.org/sqlite does not support concurrent writers well through a
	// single *sql.DB pool; keep this to one connection to avoid "database is
	// locked" errors, which is fine given Save/Load are whole-file
	// operations, not a high-throughput API.
	db.SetMaxOpenConns(1)

	// busy_timeout lets a second process (a scan and the MCP server, say)
	// wait for the writer instead of failing with "database is locked". Set
	// per connection, and the pool holds exactly one.
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("graphstore: set busy timeout: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// migrate brings the database to SchemaVersion. A fresh file gets the v2
// schema directly. A v1 file (user_version 0, nodes table without the v2
// columns) has those columns added with defaults, which leaves its rows
// readable; keys stay empty until the next build writes them, and the empty
// file_hashes table makes the next Refresh a full rebuild.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("graphstore: read schema version: %w", err)
	}
	if version == SchemaVersion {
		return nil
	}
	if version > SchemaVersion {
		return fmt.Errorf("graphstore: graph.db schema v%d is newer than this build supports (v%d)", version, SchemaVersion)
	}

	// CREATE TABLE IF NOT EXISTS leaves an existing v1 nodes table alone, so
	// add whatever v2 columns it lacks.
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("graphstore: create schema: %w", err)
	}
	have := make(map[string]bool)
	rows, err := db.Query(`PRAGMA table_info(nodes)`)
	if err != nil {
		return fmt.Errorf("graphstore: inspect nodes: %w", err)
	}
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("graphstore: inspect nodes: %w", err)
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range v2Columns {
		if have[c.name] {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE nodes ADD COLUMN ` + c.name + ` ` + c.def); err != nil {
			return fmt.Errorf("graphstore: migrate nodes.%s: %w", c.name, err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion)); err != nil {
		return fmt.Errorf("graphstore: set schema version: %w", err)
	}
	return nil
}

func marshalTags(tags map[string]string) (string, error) {
	if tags == nil {
		return "null", nil
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalTags(s string) (map[string]string, error) {
	if s == "" || s == "null" {
		return nil, nil
	}
	var tags map[string]string
	if err := json.Unmarshal([]byte(s), &tags); err != nil {
		return nil, err
	}
	return tags, nil
}

// ensureDir creates the parent directory of dbPath (e.g. .trojan/) if it
// does not already exist, unless dbPath has no directory component (such as
// the in-memory ":memory:" path or a bare filename).
func ensureDir(dbPath string) error {
	if dbPath == ":memory:" {
		return nil
	}
	dir := filepath.Dir(dbPath)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("graphstore: create dir %s: %w", dir, err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
