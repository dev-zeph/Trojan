package memory

import (
	"fmt"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── Triage verdict cache ─────────────────────────────────────────────────────
//
// The AI false-alarm check on a code scan is billed per call, so its answers
// are cached here, next to the rest of the project's memory. The key is built
// by the caller (internal/ai.VerdictCacheKey) from the rule, the file and a
// hash of the flagged code, so changed code gets a fresh check. The cache is
// local to this project folder and never shared.

const schemaVerdictCache = `
CREATE TABLE IF NOT EXISTS triage_verdicts (
	key        TEXT PRIMARY KEY,
	verdict    TEXT NOT NULL,
	confidence REAL NOT NULL DEFAULT 0,
	rationale  TEXT NOT NULL DEFAULT '',
	at         INTEGER NOT NULL
);
`

// CachedVerdict is one stored triage answer.
type CachedVerdict struct {
	Verdict    string
	Confidence float64
	Rationale  string
	At         time.Time
}

// CachedVerdicts returns the stored verdicts for the given keys. Keys with no
// entry are simply absent from the map.
func (s *Store) CachedVerdicts(keys []string) (map[string]CachedVerdict, error) {
	out := make(map[string]CachedVerdict, len(keys))
	for start := 0; start < len(keys); start += 500 { // stay under SQLite's variable limit
		end := min(start+500, len(keys))
		chunk := keys[start:end]
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		q := `SELECT key, verdict, confidence, rationale, at FROM triage_verdicts WHERE key IN (?` +
			strings.Repeat(",?", len(chunk)-1) + `)`
		err := retryBusy(func() error {
			rows, err := s.db.Query(q, args...)
			if err != nil {
				return fmt.Errorf("memory: read verdict cache: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var k string
				var v CachedVerdict
				var at int64
				if err := rows.Scan(&k, &v.Verdict, &v.Confidence, &v.Rationale, &at); err != nil {
					return fmt.Errorf("memory: scan verdict cache: %w", err)
				}
				v.At = time.Unix(0, at)
				out[k] = v
			}
			return rows.Err()
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// PutVerdicts stores (or replaces) verdicts by key in one transaction.
func (s *Store) PutVerdicts(vs map[string]CachedVerdict) error {
	if len(vs) == 0 {
		return nil
	}
	return retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("memory: begin verdict cache write: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck // no-op if committed
		for k, v := range vs {
			at := v.At
			if at.IsZero() {
				at = time.Now()
			}
			if _, err := tx.Exec(`
INSERT INTO triage_verdicts(key, verdict, confidence, rationale, at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence,
	rationale = excluded.rationale, at = excluded.at`,
				k, v.Verdict, v.Confidence, v.Rationale, at.UnixNano()); err != nil {
				return fmt.Errorf("memory: write verdict cache: %w", err)
			}
		}
		return tx.Commit()
	})
}

// ── User decisions on a finding ──────────────────────────────────────────────

// UserConfirmed returns confirmed events a person made (in the report, or
// through Claude/MCP on their behalf). Agent and scanner confirmations are left
// out: only a human's "this is real" overrides the AI false-alarm check.
func (s *Store) UserConfirmed() ([]Event, error) {
	return s.query(`WHERE kind = ? AND source IN (?, ?)`, string(KindConfirmed), string(SourceUser), string(SourceClaude))
}

// MarkReal records that a person says this finding is a real issue. Any
// earlier false-alarm decision for the same rule on the same file is removed,
// so the two never disagree.
func (s *Store) MarkReal(f normalizer.Finding, source Source, evidence string) error {
	e := EventFromFinding(f, KindConfirmed, source, s.root)
	if f.Reach != nil {
		e.NodeKey = f.Reach.NodeKey
	}
	e.Evidence = evidence
	if err := s.deleteDecision(KindFalsePositive, e.File, e.RuleID); err != nil {
		return err
	}
	return s.Record(e)
}

// MarkFalseAlarm records that a person says this finding is not a real issue,
// removing any earlier "this is real" decision by a person.
func (s *Store) MarkFalseAlarm(f normalizer.Finding, source Source, evidence string) error {
	e := EventFromFinding(f, KindFalsePositive, source, s.root)
	if f.Reach != nil {
		e.NodeKey = f.Reach.NodeKey
	}
	e.Evidence = evidence
	if err := retryBusy(func() error {
		_, err := s.db.Exec(`DELETE FROM events WHERE kind = ? AND file = ? AND rule_id = ? AND source IN (?, ?)`,
			string(KindConfirmed), e.File, e.RuleID, string(SourceUser), string(SourceClaude))
		if err != nil {
			return fmt.Errorf("memory: clear confirmation: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return s.Record(e)
}

// deleteDecision removes events of one kind for a rule on a file, whatever
// graph node they were keyed to.
func (s *Store) deleteDecision(kind Kind, file, ruleID string) error {
	return retryBusy(func() error {
		_, err := s.db.Exec(`DELETE FROM events WHERE kind = ? AND file = ? AND rule_id = ?`,
			string(kind), normPath(file), ruleID)
		if err != nil {
			return fmt.Errorf("memory: delete decision: %w", err)
		}
		return nil
	})
}

// Root is the absolute project folder this store belongs to.
func (s *Store) Root() string { return s.root }
