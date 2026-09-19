// Package graphstore persists Trojan's Code Property Graph (internal/graph) to
// a local SQLite file, so the graph built during one run can be reused (and
// eventually incrementally updated) in the next instead of being rebuilt from
// scratch every time. This is what makes the graph "compounding local memory"
// rather than a scratch structure that disappears when the process exits.
//
// The store is intentionally simple for this first pass: Save does a full
// replace of the nodes and edges tables, and Load reads them back verbatim,
// including the Tags map that internal/orgcontext layers onto nodes. There is
// no incremental diffing yet.
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
// here: this package stays self-contained and does not modify internal/rag or
// internal/graph.
package graphstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/dev-zeph/trojan/internal/graph"
)

// DefaultDBPath is the conventional location for the local graph database,
// relative to a project root.
const DefaultDBPath = ".trojan/graph.db"

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
	id        INTEGER PRIMARY KEY,
	kind      TEXT NOT NULL,
	name      TEXT NOT NULL,
	file      TEXT NOT NULL,
	line      INTEGER NOT NULL,
	source    INTEGER NOT NULL,
	pii       INTEGER NOT NULL,
	sink_rule TEXT NOT NULL,
	severity  TEXT NOT NULL,
	tags      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
	src  INTEGER NOT NULL,
	dst  INTEGER NOT NULL,
	kind TEXT NOT NULL
);
`

// Save persists g to the SQLite database at dbPath, creating the file and
// schema if they do not already exist. This pass does a full replace: any
// existing nodes and edges rows are dropped and rewritten from g.
func Save(dbPath string, g *graph.Graph) error {
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

	if _, err := tx.Exec(`DELETE FROM nodes`); err != nil {
		return fmt.Errorf("graphstore: clear nodes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM edges`); err != nil {
		return fmt.Errorf("graphstore: clear edges: %w", err)
	}

	nodeStmt, err := tx.Prepare(`INSERT INTO nodes (id, kind, name, file, line, source, pii, sink_rule, severity, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
			boolToInt(n.Source), boolToInt(n.PII), n.SinkRule, n.Severity, tagsJSON); err != nil {
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

	g := graph.New()

	rows, err := db.Query(`SELECT id, kind, name, file, line, source, pii, sink_rule, severity, tags
		FROM nodes ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("graphstore: query nodes: %w", err)
	}

	var nodes []graph.Node
	for rows.Next() {
		var (
			n         graph.Node
			kind      string
			sourceInt int
			piiInt    int
			tagsJSON  string
		)
		if err := rows.Scan(&n.ID, &kind, &n.Name, &n.File, &n.Line, &sourceInt, &piiInt,
			&n.SinkRule, &n.Severity, &tagsJSON); err != nil {
			rows.Close()
			return nil, fmt.Errorf("graphstore: scan node: %w", err)
		}
		n.Kind = graph.NodeKind(kind)
		n.Source = sourceInt != 0
		n.PII = piiInt != 0
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

// open opens (creating if necessary) the SQLite database at dbPath and
// ensures the schema exists.
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

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("graphstore: create schema: %w", err)
	}
	return db, nil
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
