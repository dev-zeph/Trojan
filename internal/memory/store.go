package memory

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/dev-zeph/trojan/internal/gitignore"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// schemaVersion is bumped when the table layout changes; migrate() is where
// upgrades of older files would go.
const schemaVersion = 1

const schemaV1 = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	id       INTEGER PRIMARY KEY,
	kind     TEXT NOT NULL,
	node_key TEXT NOT NULL DEFAULT '',
	file     TEXT NOT NULL DEFAULT '',
	rule_id  TEXT NOT NULL DEFAULT '',
	title    TEXT NOT NULL DEFAULT '',
	evidence TEXT NOT NULL DEFAULT '',
	source   TEXT NOT NULL DEFAULT '',
	at       INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS events_identity ON events(kind, node_key, file, rule_id);
CREATE INDEX IF NOT EXISTS events_node_key ON events(node_key);
CREATE INDEX IF NOT EXISTS events_file ON events(file);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind);
`

// Store is an open project memory.
type Store struct {
	db   *sql.DB
	root string
}

// Open opens (creating if needed) the memory store for a project. It also
// keeps .trojan out of the project's git history, like the other stores.
func Open(projectRoot string) (*Store, error) {
	abs, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("memory: resolve %s: %w", projectRoot, err)
	}
	dbPath := filepath.Join(abs, filepath.FromSlash(DefaultDBPath))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("memory: create dir for %s: %w", dbPath, err)
	}
	gitignore.EnsureTrojanIgnored(abs)

	// WAL lets readers and one writer overlap; busy_timeout makes a second
	// writer (another process) wait instead of failing with SQLITE_BUSY.
	dsn := "file:" + filepath.ToSlash(dbPath) +
		"?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("memory: open %s: %w", dbPath, err)
	}
	// One connection per handle; cross-process concurrency is SQLite's job.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, root: abs}
	if err := retryBusy(s.migrate); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("memory: begin migrate: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op if committed

	if _, err := tx.Exec(schemaV1); err != nil {
		return fmt.Errorf("memory: create schema: %w", err)
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&n); err != nil {
		return fmt.Errorf("memory: read schema version: %w", err)
	}
	if n == 0 {
		if _, err := tx.Exec(`INSERT INTO schema_version(version) VALUES (?)`, schemaVersion); err != nil {
			return fmt.Errorf("memory: write schema version: %w", err)
		}
	}
	return tx.Commit()
}

// Record saves an event. The same Kind + NodeKey + File + RuleID is stored
// once; recording it again refreshes At, Evidence, Title and Source.
func (s *Store) Record(e Event) error {
	if e.Kind == "" {
		return errors.New("memory: event kind is required")
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.File = normPath(e.File)
	return retryBusy(func() error {
		_, err := s.db.Exec(`
INSERT INTO events(kind, node_key, file, rule_id, title, evidence, source, at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, node_key, file, rule_id) DO UPDATE SET
	title = excluded.title,
	evidence = excluded.evidence,
	source = excluded.source,
	at = excluded.at`,
			string(e.Kind), e.NodeKey, e.File, e.RuleID, e.Title, e.Evidence, string(e.Source), e.At.UnixNano())
		if err != nil {
			return fmt.Errorf("memory: record: %w", err)
		}
		return nil
	})
}

// ForKey returns every event about one graph node.
func (s *Store) ForKey(key string) ([]Event, error) {
	return s.query(`WHERE node_key = ?`, key)
}

// ForFile returns every event about one project-relative file.
func (s *Store) ForFile(relPath string) ([]Event, error) {
	return s.query(`WHERE file = ?`, normPath(relPath))
}

// FalsePositives returns every false-positive event, so triage and tools can
// stop re-raising them.
func (s *Store) FalsePositives() ([]Event, error) {
	return s.query(`WHERE kind = ?`, string(KindFalsePositive))
}

// ByRule returns every event recorded for one scanner rule.
func (s *Store) ByRule(ruleID string) ([]Event, error) {
	return s.query(`WHERE rule_id = ?`, ruleID)
}

// All returns every event, oldest first.
func (s *Store) All() ([]Event, error) {
	return s.query(``)
}

// Delete removes the event with the given identity, reporting whether one
// existed.
func (s *Store) Delete(kind Kind, nodeKey, file, ruleID string) (bool, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`DELETE FROM events WHERE kind = ? AND node_key = ? AND file = ? AND rule_id = ?`,
			string(kind), nodeKey, normPath(file), ruleID)
		if err != nil {
			return fmt.Errorf("memory: delete: %w", err)
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n > 0, err
}

// IsFalsePositive reports whether this finding was previously judged a false
// positive: a false_positive event with the same rule on the same
// (project-relative) file. Triage uses this to stop re-raising dismissed
// findings.
func (s *Store) IsFalsePositive(f normalizer.Finding) (bool, error) {
	file := normPath(relToRoot(s.root, f.FilePath))
	var n int
	err := retryBusy(func() error {
		return s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = ? AND rule_id = ? AND file = ?`,
			string(KindFalsePositive), f.RuleID, file).Scan(&n)
	})
	if err != nil {
		return false, fmt.Errorf("memory: is false positive: %w", err)
	}
	return n > 0, nil
}

// Close releases the store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// EventFromFinding builds an Event from a scanner finding, converting an
// absolute FilePath into a project-relative, forward-slash path.
func EventFromFinding(f normalizer.Finding, kind Kind, source Source, projectRoot string) Event {
	return Event{
		Kind:   kind,
		File:   normPath(relToRoot(projectRoot, f.FilePath)),
		RuleID: f.RuleID,
		Title:  f.Title,
		Source: source,
		At:     time.Now(),
	}
}

func (s *Store) query(where string, args ...any) ([]Event, error) {
	var out []Event
	err := retryBusy(func() error {
		out = nil
		rows, err := s.db.Query(`SELECT kind, node_key, file, rule_id, title, evidence, source, at FROM events `+
			where+` ORDER BY at, id`, args...)
		if err != nil {
			return fmt.Errorf("memory: query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e Event
			var kind, source string
			var at int64
			if err := rows.Scan(&kind, &e.NodeKey, &e.File, &e.RuleID, &e.Title, &e.Evidence, &source, &at); err != nil {
				return fmt.Errorf("memory: scan: %w", err)
			}
			e.Kind, e.Source, e.At = Kind(kind), Source(source), time.Unix(0, at)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// relToRoot makes p project-relative when it sits under root; other paths
// are returned unchanged.
func relToRoot(root, p string) string {
	if p == "" || root == "" || !filepath.IsAbs(p) {
		return p
	}
	if absRoot, err := filepath.Abs(root); err == nil {
		root = absRoot
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return rel
}

// normPath stores paths with forward slashes and no leading "./".
func normPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(filepath.ToSlash(p), "\\", "/")
	return strings.TrimPrefix(p, "./")
}

// retryBusy is a belt-and-braces retry for SQLITE_BUSY/LOCKED that slips past
// busy_timeout (e.g. a WAL checkpoint race between processes).
func retryBusy(fn func() error) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = fn(); err == nil || !isBusy(err) {
			return err
		}
		time.Sleep(time.Duration(10*(i+1)) * time.Millisecond)
	}
	return err
}

func isBusy(err error) bool {
	m := err.Error()
	return strings.Contains(m, "SQLITE_BUSY") || strings.Contains(m, "database is locked") || strings.Contains(m, "SQLITE_LOCKED")
}
