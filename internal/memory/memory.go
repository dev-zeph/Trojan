// Package memory is Trojan's per-project security memory: what each scan and
// agent run learned about this codebase (confirmed findings, false positives,
// verified fixes, accepted risks, facts, attack steps that worked). It lives
// locally in .trojan/memory.db and is keyed by stable graph node keys
// (graph.Node.Key) so knowledge carries across scans.
//
// CONTRACT (Wave 0): types and signatures are fixed; the implementation lands
// in Wave 1.
package memory

import (
	"errors"
	"time"
)

// DefaultDBPath is where the store lives, relative to the project root.
const DefaultDBPath = ".trojan/memory.db"

// Kind classifies a memory event.
type Kind string

const (
	KindConfirmed     Kind = "confirmed"      // a finding proven or confirmed real
	KindFalsePositive Kind = "false_positive" // a finding judged not real
	KindFixed         Kind = "fixed"          // a fix verified (scanner re-run or exploit replay)
	KindAcceptedRisk  Kind = "accepted_risk"  // the user chose to live with it
	KindFact          Kind = "fact"           // something an agent learned, e.g. "/api/orders has no ownership check"
	KindAttackStep    Kind = "attack_step"    // a step that worked during a pen test (replayable)
)

// Source says who produced the event.
type Source string

const (
	SourceScanner Source = "scanner"
	SourceAgent   Source = "agent"
	SourceUser    Source = "user"
	SourceClaude  Source = "claude"
)

// Event is one thing Trojan learned about the project.
type Event struct {
	Kind     Kind      `json:"kind"`
	NodeKey  string    `json:"node_key,omitempty"` // graph.Node.Key, when known
	File     string    `json:"file,omitempty"`     // project-relative path
	RuleID   string    `json:"rule_id,omitempty"`  // scanner rule or vuln class
	Title    string    `json:"title"`
	Evidence string    `json:"evidence,omitempty"` // what proved it, or why it was dismissed
	Source   Source    `json:"source"`
	At       time.Time `json:"at"`
}

// ErrNotImplemented is returned until the Wave 1 implementation lands.
var ErrNotImplemented = errors.New("memory: not implemented")

// Store is an open project memory.
type Store struct{}

// Open opens (creating if needed) the memory store for a project.
func Open(projectRoot string) (*Store, error) { return nil, ErrNotImplemented }

// Record saves an event. The same Kind + NodeKey + File + RuleID is stored
// once; recording it again refreshes At and Evidence.
func (s *Store) Record(e Event) error { return ErrNotImplemented }

// ForKey returns every event about one graph node.
func (s *Store) ForKey(key string) ([]Event, error) { return nil, ErrNotImplemented }

// ForFile returns every event about one project-relative file.
func (s *Store) ForFile(relPath string) ([]Event, error) { return nil, ErrNotImplemented }

// FalsePositives returns every false-positive event, so triage and tools can
// stop re-raising them.
func (s *Store) FalsePositives() ([]Event, error) { return nil, ErrNotImplemented }

// Close releases the store.
func (s *Store) Close() error { return nil }
