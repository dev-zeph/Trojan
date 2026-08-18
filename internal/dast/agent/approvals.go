package agent

import (
	"sync"
	"time"
)

// approvals.go is the runtime approval queue (§8.3) that makes human-in-the-loop
// NON-BLOCKING: when the classifier gates an action, the loop records it here and
// hands the agent a PENDING_APPROVAL result so it can defer that hypothesis and
// keep testing others, rather than freezing the whole engagement on one prompt.
// The operator's decision arrives asynchronously through the reverse channel
// (server endpoint, phase 3) and is delivered to the loop over Decide → the
// decisions channel.
//
// Model A (chosen): on approval the LOOP executes the exact queued action and
// feeds the result back — the action runs precisely as the operator saw it on the
// card, so the agent can't silently alter an approved request before firing it.

// PendingAction is a state-changing action the classifier held for human review.
// It carries everything the approval card needs to show (§8.4: exact request +
// reason), and everything the loop needs to execute it verbatim on approval.
type PendingAction struct {
	ID       int    `json:"id"`
	Tool     string `json:"tool"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Body     string `json:"body,omitempty"`
	Identity string `json:"identity,omitempty"`
	Reason   string `json:"reason"` // why it was gated (Disposition.Reason)
	Step     int    `json:"step"`
}

// ApprovalDecision is the operator's answer, delivered via the reverse channel.
type ApprovalDecision struct {
	ID      int    `json:"id"`
	Approve bool   `json:"approve"`
	Note    string `json:"note,omitempty"`
}

// Approvals coordinates the pending queue between the loop (which requests and
// resolves) and the reverse channel (which delivers operator decisions). Safe for
// concurrent use. A nil *Approvals means HITL is off — the loop skips the gate
// entirely and preserves today's auto-execute behavior.
type Approvals struct {
	mu      sync.Mutex
	seq     int
	pending map[int]PendingAction
	ch      chan ApprovalDecision
	timeout time.Duration
}

// NewApprovals builds a coordinator. timeout bounds how long the loop waits for a
// decision before defaulting to the SAFE action (deny) — never auto-approve (§8.4).
func NewApprovals(timeout time.Duration) *Approvals {
	if timeout <= 0 {
		timeout = 10 * time.Minute // Agent Approve's 600s default
	}
	return &Approvals{
		pending: make(map[int]PendingAction),
		ch:      make(chan ApprovalDecision, 32),
		timeout: timeout,
	}
}

// Request enqueues a gated action and returns its assigned id.
func (a *Approvals) Request(act PendingAction) PendingAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	act.ID = a.seq
	a.pending[act.ID] = act
	return act
}

// Decide delivers an operator decision to the loop (called by the reverse
// channel). Non-blocking up to the channel buffer; drops nothing in practice
// since decisions are rare relative to the buffer.
func (a *Approvals) Decide(d ApprovalDecision) { a.ch <- d }

// HasPending reports whether any actions await a decision.
func (a *Approvals) HasPending() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending) > 0
}

// Pending returns a snapshot of the queued actions, for a status/replay endpoint.
func (a *Approvals) Pending() []PendingAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PendingAction, 0, len(a.pending))
	for _, act := range a.pending {
		out = append(out, act)
	}
	return out
}

// take removes and returns a queued action by id; ok is false if it was already
// resolved (a duplicate or late decision) or never existed.
func (a *Approvals) take(id int) (PendingAction, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	act, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	return act, ok
}

// takeAll removes and returns every queued action — used to auto-deny the
// remainder when the wait times out.
func (a *Approvals) takeAll() []PendingAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PendingAction, 0, len(a.pending))
	for id, act := range a.pending {
		out = append(out, act)
		delete(a.pending, id)
	}
	return out
}
