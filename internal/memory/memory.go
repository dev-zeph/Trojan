// Package memory is Trojan's per-project security memory: what each scan and
// agent run learned about this codebase (confirmed findings, false positives,
// verified fixes, accepted risks, facts, attack steps that worked). It lives
// locally in .trojan/memory.db and is keyed by stable graph node keys
// (graph.Node.Key) so knowledge carries across scans.
//
// Storage engine: modernc.org/sqlite (pure Go, CGO-free), in WAL mode with a
// busy timeout so the MCP server process and a scan process can both write.
// The implementation lives in store.go.
package memory

import "time"

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
