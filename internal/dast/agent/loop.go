package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/greybox"
)

// The agent loop (docs/agentic-dast.md §3.2). The loop lives here, in the Go
// CLI; each reasoning turn is one Transport call. The loop executes the tool
// calls Claude requests against the Phase-3 Toolbox (safe-mode + caps enforced
// there), feeds results back, and repeats until the agent finishes, the
// conversation ends, or a cap trips. No model runs in this process — only tool
// execution and bookkeeping.

// Tool names — the contract shared with the edge function's tool definitions.
const (
	toolGetCrawlMap   = "get_crawl_map"
	toolHTTPProbe     = "http_probe"
	toolNoteFinding   = "note_finding"
	toolReadSource    = "read_source"
	toolRememberFact  = "remember_fact"
	toolDiffResponses = "diff_responses"
	toolFinish        = "finish"
)

// EventType classifies a progress event streamed during a run (§10.2 live view).
type EventType string

const (
	EventStep       EventType = "step"        // a new reasoning turn began
	EventText       EventType = "text"        // the agent said something (hypothesis)
	EventToolUse    EventType = "tool_use"    // the agent invoked a tool
	EventToolResult EventType = "tool_result" // a tool returned
	EventFinding    EventType = "finding"     // a candidate vuln was recorded
	EventGraph      EventType = "graph"       // an attack-graph node/edge delta (§9)
	EventStopped    EventType = "stopped"     // a cap tripped — run bounded early
	EventFinish     EventType = "finish"      // the agent called finish / ended cleanly
	// EventApprovalRequest — a state-changing action was gated and awaits an
	// operator decision (§8). Payload.Approval carries the card data.
	EventApprovalRequest EventType = "approval_request"
	// EventApprovalResolved — a gated action was approved (and executed) or denied.
	EventApprovalResolved EventType = "approval_resolved"
)

// GreyBoxSummary is the structural read of a handler, flattened for the wire so
// the narrative can render it as chips (§6.6 / §9.1). Mirrors
// greybox.StructuralSummary without importing it into the server.
type GreyBoxSummary struct {
	HasAuthCheck   bool `json:"has_auth_check"`
	SanitizesInput bool `json:"sanitizes_input"`
	RawQuery       bool `json:"raw_query"`
	ReflectsInput  bool `json:"reflects_input"`
}

// EventPayload carries the structured data that lets the two-surface UI render
// chips, a live graph, and the source↔runtime proof split instead of parsing
// strings (§9.1/§9.3). Every field is optional; which are set depends on
// Event.Type.
type EventPayload struct {
	Node    *GraphNode      `json:"node,omitempty"`    // graph delta (EventGraph)
	Edge    *GraphEdge      `json:"edge,omitempty"`    // graph delta (EventGraph)
	Source  *HandlerRef     `json:"source,omitempty"`  // grey-box handler (read_source / finding)
	Summary *GreyBoxSummary `json:"summary,omitempty"` // grey-box chips (read_source)
	Mode    string          `json:"mode,omitempty"`    // read_source mode: endpoint|symbol|query
	// Approval carries the gated action for an EventApprovalRequest so the UI can
	// render the approval card (§8.4); on EventApprovalResolved it identifies which.
	Approval *PendingAction `json:"approval,omitempty"`
	Approved bool           `json:"approved,omitempty"` // EventApprovalResolved: the decision
}

// Event is one streamed progress update. OnEvent is called synchronously in
// loop order, so a UI/CLI sees actions as they happen.
type Event struct {
	Type    EventType
	Step    int
	Tool    string
	Detail  string
	Payload *EventPayload // structured data for rich UI rendering (§9); optional
}

// RunOptions configures a single agentic run.
type RunOptions struct {
	// Task seeds the conversation — the goal plus any context (crawl summary,
	// Nuclei pre-pass findings). The agent can also call get_crawl_map itself.
	Task string
	// MaxRunTokens is a cumulative token ceiling across all turns (the $ cost
	// cap). 0 = rely solely on the step/request/wall-clock caps in the Budget.
	MaxRunTokens int
	// OnEvent receives progress events in order; may be nil.
	OnEvent func(Event)
	// Checkpoint, when non-nil, enables resumption. The caller pre-fills the
	// run-shape fields (target, crawl, tier, limits, RoE); the loop fills in
	// live state and saves after EVERY turn, so nothing is lost to a crash, a
	// closed laptop, or an exhausted token balance.
	//
	// If it already carries Messages, this is a RESUME: the conversation
	// continues from them instead of being seeded fresh from Task.
	Checkpoint *Checkpoint
}

// RunResult is the outcome of a run.
type RunResult struct {
	Findings   []Candidate
	Summary    string
	StopReason StopReason // populated when a Budget cap ended the run
	EndedBy    EventType  // EventFinish or EventStopped
	Steps      int
	Usage      Usage // cumulative across all turns
}

// StopTokenBudget is the reason surfaced when the cumulative token ceiling trips.
const StopTokenBudget StopReason = "token budget reached"

// StopInsufficientTokens ends a run whose Trojan Token balance ran out. Unlike
// every other StopReason this one is RESUMABLE: the checkpoint is kept, and the
// run continues from the same conversation once the user tops up.
const StopInsufficientTokens StopReason = "out of Trojan Tokens"

// DefaultMaxRunTokens disables the per-run cumulative-token ceiling by default
// (0 = off). We removed the hard cap because it was cutting runs off mid-proof —
// e.g. right as a grey-box → credential → auth-bypass chain was being recorded —
// and because token *usage* is moving to the metered, token-based pricing model,
// where the user pays for what a run consumes rather than the run being killed at
// an arbitrary ceiling. The run is still bounded by the real safety caps in
// Limits (steps, requests, wall-clock), so this is not unbounded. The mechanism
// is retained: pass --max-run-tokens <n> to re-impose a ceiling for a given run.
const DefaultMaxRunTokens = 0

// Run drives the agent loop against a prepared Toolbox and Transport.
func Run(ctx context.Context, tb *Toolbox, tr Transport, opts RunOptions) (*RunResult, error) {
	emit := opts.OnEvent
	if emit == nil {
		emit = func(Event) {}
	}

	// Resume picks up the exact conversation the previous attempt ended on.
	// Replaying it verbatim matters: Claude requires assistant turns, including
	// thinking blocks, echoed back byte-for-byte, which is why Message.Content
	// stays json.RawMessage end to end.
	messages := []Message{userTextMessage(opts.Task)}
	var cum Usage
	if cp := opts.Checkpoint; cp != nil && len(cp.Messages) > 0 {
		messages = cp.Messages
		cum = cp.Usage
	}
	result := &RunResult{}

	// save persists the run so far. Failures are logged through the event
	// stream rather than aborting: losing the ability to resume is bad, but
	// killing a live engagement over a disk error is worse.
	save := func(reason StopReason, resumable bool) {
		cp := opts.Checkpoint
		// No id yet means turn 1 has not returned. The file is named by run id,
		// so there is nothing addressable to write until the server mints one.
		if cp == nil || cp.RunID == "" {
			return
		}
		cp.Messages = messages
		cp.Usage = cum
		cp.Findings = tb.Findings()
		cp.Facts = tb.Facts()
		if g := tb.Graph(); g != nil {
			cp.GraphNodes, cp.GraphEdges = g.Snapshot()
		}
		cp.Steps, cp.Requests, cp.Elapsed = tb.Budget().Stats()
		cp.StopReason = reason
		cp.Resumable = resumable
		if err := SaveCheckpoint(cp); err != nil {
			emit(Event{Type: EventStep, Detail: "checkpoint failed: " + err.Error()})
		}
	}

	// Emit the initial attack-graph snapshot (endpoints seeded from the crawl)
	// so a viewer sees the coverage map before the first probe (§9.2).
	if g := tb.Graph(); g != nil {
		nodes, edges := g.Snapshot()
		for _, n := range nodes {
			emit(graphNodeEvent(0, n))
		}
		for _, e := range edges {
			emit(graphEdgeEvent(0, e))
		}
	}

	for {
		// Reserve a reasoning turn. A tripped cap ends the run — visibly.
		if err := tb.Budget().BeginStep(); err != nil {
			_, reason := tb.Budget().Stopped()
			// A tripped step/request/wall-clock cap is a real end, not a pause:
			// resuming would hand back the same exhausted budget. Recorded
			// non-resumable so the UI offers "start a new run", not "continue".
			save(reason, false)
			return finish(result, tb, cum, EventStopped, reason, emit), nil
		}
		step, _, _ := tb.Budget().Stats()
		result.Steps = step
		emit(Event{Type: EventStep, Step: step})

		turn, err := tr.Turn(ctx, messages)
		if err != nil {
			// Out of Trojan Tokens is not a failure -- it is a pause. The work
			// done so far is already paid for, so it is checkpointed and the run
			// ends resumably rather than being thrown away.
			if errors.Is(err, ErrInsufficientTokens) {
				save(StopInsufficientTokens, true)
				return finish(result, tb, cum, EventStopped, StopInsufficientTokens, emit), nil
			}
			// Any other transport error still checkpoints, so a network blip or a
			// crash does not cost the user the whole engagement.
			save("", true)
			return nil, err
		}
		// The run id is minted server-side on turn 1. Latch it the first time we
		// see it so the checkpoint has a stable filename for the rest of the run.
		if cp := opts.Checkpoint; cp != nil && cp.RunID == "" && turn.RunID != "" {
			cp.RunID = turn.RunID
		}

		cum.add(turn.Usage)

		// Cumulative cost ceiling — the $ bound, checked after each turn.
		if opts.MaxRunTokens > 0 && cum.Total() > opts.MaxRunTokens {
			messages = append(messages, Message{Role: "assistant", Content: turn.Content})
			return finish(result, tb, cum, EventStopped, StopTokenBudget, emit), nil
		}

		// Append the assistant turn verbatim (preserves thinking blocks).
		messages = append(messages, Message{Role: "assistant", Content: turn.Content})

		// Checkpoint the turn before executing its tools: the assistant message is
		// already billed, so it must survive even if a probe panics below.
		save("", true)

		toolResults, finished := dispatchBlocks(ctx, tb, turn.Content, step, emit)

		// The agent wants to end when it called finish, or stopped requesting tools
		// (end_turn, refusal, max_tokens, …).
		wantEnd := finished || turn.StopReason != "tool_use" || len(toolResults) == 0

		// §8 Model A: pull in any operator decisions and feed the executed/denied
		// outcomes back. If the agent is trying to end while actions are still
		// queued, block (bounded by the approval timeout) so we never conclude an
		// engagement with an approval left dangling; otherwise just drain what has
		// arrived and keep the agent moving (non-blocking).
		outcomes := tb.resolveApprovals(ctx, step, emit, wantEnd)

		if len(toolResults) > 0 || len(outcomes) > 0 {
			messages = append(messages, followupMessage(toolResults, outcomes))
		}

		// End only when the agent is done AND nothing was just resolved that it
		// should get a turn to react to.
		if wantEnd && len(outcomes) == 0 {
			// Finished for good: drop the checkpoint so completed runs don't
			// accumulate on disk holding captured response bodies.
			if cp := opts.Checkpoint; cp != nil {
				_ = DeleteCheckpoint(cp.RunID)
			}
			return finish(result, tb, cum, EventFinish, "", emit), nil
		}
	}
}

// dispatchBlocks walks an assistant turn's content, executing each tool_use
// against the Toolbox and returning the tool_result blocks plus whether the
// agent called finish.
func dispatchBlocks(ctx context.Context, tb *Toolbox, content []json.RawMessage, step int, emit func(Event)) ([]toolResultBlock, bool) {
	var results []toolResultBlock
	finished := false

	for _, raw := range content {
		var b blockPeek
		if err := json.Unmarshal(raw, &b); err != nil {
			continue
		}
		switch b.Type {
		case "text":
			if b.Text != "" {
				emit(Event{Type: EventText, Step: step, Detail: b.Text})
			}
		case "tool_use":
			emit(Event{Type: EventToolUse, Step: step, Tool: b.Name, Detail: string(b.Input)})
			out, isErr, done := executeTool(ctx, tb, b, step, emit)
			if done {
				finished = true
			}
			results = append(results, toolResultBlock{ToolUseID: b.ID, Content: out, IsError: isErr})
		}
	}
	return results, finished
}

// executeTool runs one tool call and returns (result string, isError, finished).
func executeTool(ctx context.Context, tb *Toolbox, b blockPeek, step int, emit func(Event)) (string, bool, bool) {
	switch b.Name {
	case toolGetCrawlMap:
		return marshalResult(tb.GetCrawlMap()), false, false

	case toolHTTPProbe:
		var pr ProbeRequest
		if err := json.Unmarshal(b.Input, &pr); err != nil {
			return fmt.Sprintf("invalid http_probe input: %v", err), true, false
		}
		// §8 human-in-the-loop gate (only when enabled): classify the action.
		// Block → tool error; Approve → queue it and hand back PENDING (the agent
		// defers and explores elsewhere); Auto → fall through to execute.
		if tb.approvals != nil {
			switch disp := tb.Envelope().Classify(pr.Method, pr.URL, len(pr.Body)); disp.Action {
			case ActionBlock:
				emit(Event{Type: EventToolResult, Step: step, Tool: toolHTTPProbe, Detail: "blocked: " + disp.Reason})
				return "blocked by rules of engagement: " + disp.Reason, true, false
			case ActionApprove:
				act := tb.approvals.Request(PendingAction{
					Tool: toolHTTPProbe, Method: pr.Method, URL: pr.URL,
					Body: pr.Body, Identity: pr.Identity, Reason: disp.Reason, Step: step,
				})
				emit(Event{Type: EventApprovalRequest, Step: step, Tool: toolHTTPProbe,
					Detail:  fmt.Sprintf("approval #%d: %s %s — %s", act.ID, act.Method, act.URL, disp.Reason),
					Payload: &EventPayload{Approval: &act}})
				return fmt.Sprintf("PENDING_APPROVAL#%d: %s. This state-changing action needs operator approval and has been queued. Do NOT retry it — continue testing other hypotheses; you'll be given the result once the operator decides.", act.ID, disp.Reason), false, false
			}
		}
		res, err := tb.HTTPProbe(ctx, pr)
		if err != nil {
			// Safe-mode rejections and tripped caps come back as tool errors so
			// the agent can adapt (or the loop ends on the next BeginStep).
			emit(Event{Type: EventToolResult, Step: step, Tool: toolHTTPProbe, Detail: "error: " + err.Error()})
			return err.Error(), true, false
		}
		emit(Event{Type: EventToolResult, Step: step, Tool: toolHTTPProbe, Detail: fmt.Sprintf("%d %s", res.Status, pr.URL)})
		onProbe(tb, pr.Method, pr.URL, step, emit)
		return marshalResult(res), false, false

	case toolNoteFinding:
		var c Candidate
		if err := json.Unmarshal(b.Input, &c); err != nil {
			return fmt.Sprintf("invalid note_finding input: %v", err), true, false
		}
		tb.NoteFinding(c)
		handler := onFinding(tb, c, step, emit)
		emit(Event{Type: EventFinding, Step: step, Detail: c.Title, Payload: &EventPayload{Source: handler}})
		return `{"ok":true}`, false, false

	case toolReadSource:
		var rs greybox.ReadSourceRequest
		if err := json.Unmarshal(b.Input, &rs); err != nil {
			return fmt.Sprintf("invalid read_source input: %v", err), true, false
		}
		res, err := tb.ReadSource(rs)
		if err != nil {
			return err.Error(), true, false
		}
		payload := onReadSource(tb, rs, res, step, emit)
		emit(Event{Type: EventToolResult, Step: step, Tool: toolReadSource, Detail: readSourceDetail(rs, res), Payload: payload})
		return marshalResult(res), false, false

	case toolRememberFact:
		var f Fact
		if err := json.Unmarshal(b.Input, &f); err != nil || f.Summary == "" {
			return "invalid remember_fact input: need at least a summary", true, false
		}
		facts := tb.RememberFact(f)
		onRememberFact(tb, f, step, emit)
		emit(Event{Type: EventText, Step: step, Detail: "🧠 " + f.Summary})
		return marshalResult(map[string]any{"ok": true, "facts": facts}), false, false

	case toolDiffResponses:
		var d struct {
			A int `json:"a"`
			B int `json:"b"`
		}
		if err := json.Unmarshal(b.Input, &d); err != nil {
			return fmt.Sprintf("invalid diff_responses input: %v", err), true, false
		}
		res, err := tb.DiffResponses(d.A, d.B)
		if err != nil {
			emit(Event{Type: EventToolResult, Step: step, Tool: toolDiffResponses, Detail: "error: " + err.Error()})
			return err.Error(), true, false
		}
		emit(Event{Type: EventToolResult, Step: step, Tool: toolDiffResponses, Detail: diffDetail(res)})
		return marshalResult(res), false, false

	case toolFinish:
		var f struct {
			Summary string `json:"summary"`
		}
		_ = json.Unmarshal(b.Input, &f)
		// Diligence gate: decline an early finish while coverage is thin and
		// budget remains, nudging the agent to keep testing. Capped so its
		// judgment eventually wins and the step/time budget still bounds the run.
		if nudge, done := tb.ConsiderFinish(f.Summary); !done {
			emit(Event{Type: EventStep, Step: step, Detail: "finish deferred: coverage still thin, keep testing"})
			return nudge, false, false
		}
		return `{"ok":true}`, false, true

	default:
		return fmt.Sprintf("unknown tool %q", b.Name), true, false
	}
}

// resolveApprovals turns operator decisions into conversation outcomes (§8, Model
// A). Non-blocking, it drains decisions that have already arrived. Blocking (used
// when the agent is trying to end), it waits for every queued action to be decided
// — bounded by the approval timeout, after which the remainder auto-denies (the
// safe default; never auto-approve, §8.4). Returns the outcome text blocks to feed
// back to the agent. No-op (nil) when HITL is off or nothing is pending.
func (t *Toolbox) resolveApprovals(ctx context.Context, step int, emit func(Event), blocking bool) []string {
	a := t.approvals
	if a == nil || !a.HasPending() {
		return nil
	}
	var outcomes []string
	if !blocking {
		for {
			select {
			case d := <-a.ch:
				if o := t.applyDecision(ctx, d, step, emit); o != "" {
					outcomes = append(outcomes, o)
				}
			default:
				return outcomes
			}
		}
	}
	timer := time.NewTimer(a.timeout)
	defer timer.Stop()
	for a.HasPending() {
		select {
		case d := <-a.ch:
			if o := t.applyDecision(ctx, d, step, emit); o != "" {
				outcomes = append(outcomes, o)
			}
		case <-ctx.Done():
			return append(outcomes, t.autoDenyRemaining(step, emit, "run cancelled")...)
		case <-timer.C:
			return append(outcomes, t.autoDenyRemaining(step, emit, fmt.Sprintf("no operator response within %s", a.timeout))...)
		}
	}
	return outcomes
}

// applyDecision resolves one operator decision. On approval it executes the EXACT
// queued action (Model A — the request runs as the operator saw it) and returns
// the result; on denial it returns a do-not-retry note. Empty string if the id was
// already resolved (a late or duplicate decision).
func (t *Toolbox) applyDecision(ctx context.Context, d ApprovalDecision, step int, emit func(Event)) string {
	act, ok := t.approvals.take(d.ID)
	if !ok {
		return ""
	}
	if !d.Approve {
		emit(Event{Type: EventApprovalResolved, Step: step, Tool: act.Tool,
			Detail:  fmt.Sprintf("approval #%d denied", act.ID),
			Payload: &EventPayload{Approval: &act, Approved: false}})
		note := ""
		if d.Note != "" {
			note = " (" + d.Note + ")"
		}
		return fmt.Sprintf("APPROVAL #%d DENIED by the operator%s. Do not retry %s %s; treat it as out of scope for this engagement.", act.ID, note, act.Method, act.URL)
	}
	res, err := t.HTTPProbe(ctx, ProbeRequest{Method: act.Method, URL: act.URL, Body: act.Body, Identity: act.Identity})
	emit(Event{Type: EventApprovalResolved, Step: step, Tool: act.Tool,
		Detail:  fmt.Sprintf("approval #%d granted", act.ID),
		Payload: &EventPayload{Approval: &act, Approved: true}})
	if err != nil {
		return fmt.Sprintf("APPROVAL #%d GRANTED — but executing %s %s failed: %v", act.ID, act.Method, act.URL, err)
	}
	onProbe(t, act.Method, act.URL, step, emit)
	ident := ""
	if act.Identity != "" {
		ident = " as " + act.Identity
	}
	return fmt.Sprintf("APPROVAL #%d GRANTED — executed %s %s%s → HTTP %d. Response: %s", act.ID, act.Method, act.URL, ident, res.Status, marshalResult(res))
}

// autoDenyRemaining resolves every still-pending action as a safe deny, used when
// the wait times out or the run is cancelled.
func (t *Toolbox) autoDenyRemaining(step int, emit func(Event), reason string) []string {
	var out []string
	for _, act := range t.approvals.takeAll() {
		emit(Event{Type: EventApprovalResolved, Step: step, Tool: act.Tool,
			Detail:  fmt.Sprintf("approval #%d auto-denied (%s)", act.ID, reason),
			Payload: &EventPayload{Approval: &act, Approved: false}})
		out = append(out, fmt.Sprintf("APPROVAL #%d AUTO-DENIED — %s; the action was NOT performed (safe default). Do not retry %s %s.", act.ID, reason, act.Method, act.URL))
	}
	return out
}

// diffDetail renders a compact one-line summary of a diff_responses result for
// the progress stream — the signal plus how the two sides compared.
func diffDetail(d *DiffResult) string {
	detail := fmt.Sprintf("#%d (%d) vs #%d (%d) → %s", d.A.ProbeID, d.A.Status, d.B.ProbeID, d.B.Status, d.Signal)
	if d.JSON && len(d.FieldDiffs) > 0 {
		detail += fmt.Sprintf(", %d field diff(s)", len(d.FieldDiffs))
	} else {
		detail += fmt.Sprintf(", %.0f%% similar", d.Similarity*100)
	}
	return detail
}

// readSourceDetail renders a compact one-line summary of a read_source result
// for the progress stream.
func readSourceDetail(req greybox.ReadSourceRequest, res greybox.ReadSourceResult) string {
	var mode string
	switch {
	case req.Endpoint != nil:
		mode = req.Endpoint.Method + " " + req.Endpoint.Path
	case req.Symbol != "":
		mode = "symbol " + req.Symbol
	case req.Query != "":
		mode = "query " + req.Query
	}
	if res.Note != "" && len(res.Chunks) == 0 {
		return mode + " — " + res.Note
	}
	detail := fmt.Sprintf("%s — %d chunk(s)", mode, len(res.Chunks))
	if res.Summary != nil {
		detail += fmt.Sprintf(" [auth=%v raw_query=%v reflects=%v]",
			res.Summary.HasAuthCheck, res.Summary.RawQuery, res.Summary.ReflectsInput)
	}
	return detail
}

// ── attack-graph delta helpers (§9) ──

func graphNodeEvent(step int, n GraphNode) Event {
	return Event{Type: EventGraph, Step: step, Payload: &EventPayload{Node: &n}}
}

func graphEdgeEvent(step int, e GraphEdge) Event {
	return Event{Type: EventGraph, Step: step, Payload: &EventPayload{Edge: &e}}
}

// pathOf extracts the path from a URL for use as an endpoint node's identity.
func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return rawURL
	}
	return u.Path
}

// onProbe marks the probed endpoint as under test and emits any graph delta.
func onProbe(tb *Toolbox, method, rawURL string, step int, emit func(Event)) {
	g := tb.Graph()
	if g == nil {
		return
	}
	path := pathOf(rawURL)
	if n, created := g.UpsertEndpoint(method, path); created {
		emit(graphNodeEvent(step, n))
	}
	if n, changed := g.SetStatus(EndpointID(method, path), StatusTesting); changed {
		emit(graphNodeEvent(step, n))
	}
}

// onFinding marks the endpoint vulnerable, adds a finding node + edge, and emits
// the deltas. Returns the grey-box handler on the endpoint (if any) so the
// narrative row can show the source↔runtime proof badge.
func onFinding(tb *Toolbox, c Candidate, step int, emit func(Event)) *HandlerRef {
	g := tb.Graph()
	if g == nil {
		return nil
	}
	path := pathOf(c.URL)
	var handler *HandlerRef
	for _, n := range g.MarkVulnerableByPath(path, c.Severity, c.Title, c.Evidence) {
		emit(graphNodeEvent(step, n))
		if n.Handler != nil {
			handler = n.Handler
		}
	}
	fid := fmt.Sprintf("%d-%s", step, c.Title)
	if fn, changed := g.AddFinding(fid, c.Title, c.Severity, c.Title, c.Evidence, handler); changed {
		emit(graphNodeEvent(step, fn))
		if path != "" {
			if e, isNew := g.AddEdge(fn.ID, EndpointID("", path), EdgeChain, true, "finding confirmed here"); isNew {
				emit(graphEdgeEvent(step, e))
			}
		}
	}
	return handler
}

// onReadSource attaches the grey-box handler to the endpoint node and returns the
// payload (source + chips) for the narrative tool_result row.
func onReadSource(tb *Toolbox, req greybox.ReadSourceRequest, res greybox.ReadSourceResult, step int, emit func(Event)) *EventPayload {
	p := &EventPayload{}
	if req.Endpoint != nil {
		p.Mode = "endpoint"
	} else if req.Symbol != "" {
		p.Mode = "symbol"
	} else if req.Query != "" {
		p.Mode = "query"
	}
	if len(res.Chunks) > 0 {
		c := res.Chunks[0]
		p.Source = &HandlerRef{File: c.File, Line: c.Line, Symbol: c.Symbol}
	}
	if res.Summary != nil {
		p.Summary = &GreyBoxSummary{
			HasAuthCheck:   res.Summary.HasAuthCheck,
			SanitizesInput: res.Summary.SanitizesInput,
			RawQuery:       res.Summary.RawQuery,
			ReflectsInput:  res.Summary.ReflectsInput,
		}
	}
	// Attach the handler to the endpoint node so the graph detail panel can show
	// the source↔runtime split.
	if g := tb.Graph(); g != nil && req.Endpoint != nil && p.Source != nil {
		for _, n := range g.AttachHandlerByPath(pathOf(req.Endpoint.Path), *p.Source) {
			emit(graphNodeEvent(step, n))
		}
	}
	return p
}

// onRememberFact renders a chaining fact into the attack graph: captured
// credentials/tokens become credential nodes (with a dataflow edge from the
// endpoint that leaked them), and a fact that links one endpoint to another
// becomes a chain edge — the kill-chain the graph visualizes (§9). Facts that
// don't map to known nodes are still remembered; they just don't draw an edge.
func onRememberFact(tb *Toolbox, f Fact, step int, emit func(Event)) {
	g := tb.Graph()
	if g == nil {
		return
	}
	fromID, fromOK := "", false
	if f.From != "" {
		fromID, fromOK = g.EndpointNodeByPath(pathOf(f.From))
	}

	// Captured credential/token -> a credential node, fed by its source endpoint.
	if f.Kind == "credential" || f.Kind == "token" {
		if n, created := g.AddCredentialNode(f.Summary, f.Summary, NodeCredential); created {
			emit(graphNodeEvent(step, n))
			if fromOK {
				if e, isNew := g.AddEdge(fromID, n.ID, EdgeDataflow, true, "leaked "+f.Kind); isNew {
					emit(graphEdgeEvent(step, e))
				}
			}
		}
	}

	// A fact linking one endpoint to another is a chain step.
	if f.From != "" && f.Enables != "" && fromOK {
		if toID, toOK := g.EndpointNodeByPath(pathOf(f.Enables)); toOK {
			if e, isNew := g.AddEdge(fromID, toID, EdgeChain, true, f.Summary); isNew {
				emit(graphEdgeEvent(step, e))
			}
		}
	}
}

func marshalResult(v any) string {
	j, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("could not serialize tool result: %v", err)
	}
	return string(j)
}

// finish assembles the RunResult and emits the terminal event.
func finish(r *RunResult, tb *Toolbox, cum Usage, ended EventType, reason StopReason, emit func(Event)) *RunResult {
	r.Findings = tb.Findings()
	_, r.Summary = tb.Finished()
	r.Usage = cum
	r.EndedBy = ended
	r.StopReason = reason
	if ended == EventStopped {
		emit(Event{Type: EventStopped, Step: r.Steps, Detail: string(reason)})
	} else {
		emit(Event{Type: EventFinish, Step: r.Steps, Detail: r.Summary})
	}
	return r
}

// ── High-level entrypoint ────────────────────────────────────────────────────

// Config is everything RunAgentic needs to stand up and drive a run. It is the
// single entrypoint the CLI / desktop run-view (Phase 5) calls.
type Config struct {
	TargetURL         string
	AccessToken       string
	Crawl             dast.CrawlResult
	Tier              Tier
	Env               Environment
	AcceptSideEffects bool
	Limits            Limits
	MaxRunTokens      int
	Task              string
	OnEvent           func(Event)
	// Source enables the grey-box read_source tool (§6.6). Nil = black-box only.
	Source SourceReader
	// Identities are named auth sessions the agent may probe as, for IDOR/BOLA
	// testing (§6.5 #2). Empty = single-identity (current behaviour).
	Identities []Identity
	// RoE is the §8.1 rules of engagement layered on the safety envelope (endpoint
	// allow/denylist, auto-avoid). Zero value = the safe default.
	RoE RoE
	// Approvals enables §8 human-in-the-loop: state-changing / out-of-scope actions
	// are gated for operator approval instead of auto-executing. Nil = HITL off.
	Approvals *Approvals
	// AttackTemplate is the selected Attack Market playbook (§9.4), folded into the
	// task as RoE-subordinate guidance. Nil = no template (free-form pen test).
	AttackTemplate *AttackTemplate
}

// RunAgentic wires a safety envelope, budget, toolbox, and edge transport from
// Config and runs the loop. The target host is derived from TargetURL and is
// the same-host scope every probe is bound to.
func RunAgentic(ctx context.Context, cfg Config) (*RunResult, error) {
	host, err := dast.NormalizeHost(cfg.TargetURL)
	if err != nil {
		return nil, err
	}
	env, err := NewEnvelope(cfg.Tier, cfg.Env, host, cfg.AcceptSideEffects)
	if err != nil {
		return nil, err
	}
	env.SetRoE(cfg.RoE)
	if cfg.AccessToken == "" {
		return nil, errors.New("agentic DAST requires a Pro access token")
	}

	limits := cfg.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	budget := NewBudget(limits, nil)
	tb := NewToolbox(env, budget, limits, cfg.Crawl)
	if cfg.Source != nil {
		tb.SetSource(cfg.Source)
	}
	if len(cfg.Identities) > 0 {
		tb.SetIdentities(cfg.Identities)
	}
	if cfg.Approvals != nil {
		tb.SetApprovals(cfg.Approvals)
	}
	tr := NewEdgeTransport(cfg.AccessToken)

	// Fold the selected Attack Market playbook into the seed task as RoE-subordinate
	// guidance (§9.4). The envelope/RoE still governs every probe it inspires.
	task := cfg.Task
	if hint := attackTemplateHint(cfg.AttackTemplate); hint != "" {
		task += "\n\n" + hint
	}

	// Checkpoint template. The run-shape fields are filled here, where the
	// Config is in scope; the loop adds live state and saves after every turn.
	// RunID is left empty deliberately -- it is minted server-side on turn 1 and
	// latched by the loop.
	cp := &Checkpoint{
		TargetURL:         cfg.TargetURL,
		Task:              task,
		Crawl:             cfg.Crawl,
		Tier:              cfg.Tier,
		Env:               cfg.Env,
		AcceptSideEffects: cfg.AcceptSideEffects,
		Limits:            limits,
		MaxRunTokens:      cfg.MaxRunTokens,
		RoE:               cfg.RoE,
		Identities:        cfg.Identities,
	}

	return Run(ctx, tb, tr, RunOptions{
		Task:         task,
		MaxRunTokens: cfg.MaxRunTokens,
		OnEvent:      cfg.OnEvent,
		Checkpoint:   cp,
	})
}

// ResumeOptions carries the live objects a checkpoint cannot hold: the Pro
// access token (a credential, deliberately never written to disk), the event
// sink, and the optional grey-box reader and approval queue.
type ResumeOptions struct {
	AccessToken string
	OnEvent     func(Event)
	Source      SourceReader
	Approvals   *Approvals
}

// ResumeAgentic continues a previously checkpointed run.
//
// The engagement picks up on the exact conversation it stopped on, with its
// findings, fact memory, attack graph and consumed budget intact -- so an agent
// that had already established (say) an admin token via SQLi does not have to
// rediscover it, and does not get a fresh step budget to burn.
//
// The safety envelope is rebuilt from the checkpoint rather than trusted from
// it: tier, environment and RoE go back through NewEnvelope and SetRoE exactly
// as on a fresh run, so a hand-edited checkpoint cannot widen what the agent is
// permitted to do.
func ResumeAgentic(ctx context.Context, cp *Checkpoint, opts ResumeOptions) (*RunResult, error) {
	if cp == nil {
		return nil, errors.New("nil checkpoint")
	}
	if !cp.Resumable {
		return nil, fmt.Errorf("run %s is not resumable (%s)", cp.RunID, cp.StopReason)
	}
	if opts.AccessToken == "" {
		return nil, errors.New("agentic DAST requires a Pro access token")
	}

	host, err := dast.NormalizeHost(cp.TargetURL)
	if err != nil {
		return nil, err
	}
	env, err := NewEnvelope(cp.Tier, cp.Env, host, cp.AcceptSideEffects)
	if err != nil {
		return nil, err
	}
	env.SetRoE(cp.RoE)

	limits := cp.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}

	budget := NewBudget(limits, nil)
	budget.Restore(cp.Steps, cp.Requests, cp.Elapsed)

	tb := NewToolbox(env, budget, limits, cp.Crawl)
	tb.RestoreState(cp.Findings, cp.Facts)
	if g := tb.Graph(); g != nil {
		g.Restore(cp.GraphNodes, cp.GraphEdges)
	}
	if opts.Source != nil {
		tb.SetSource(opts.Source)
	}
	if len(cp.Identities) > 0 {
		tb.SetIdentities(cp.Identities)
	}
	if opts.Approvals != nil {
		tb.SetApprovals(opts.Approvals)
	}

	tr := NewEdgeTransport(opts.AccessToken)
	// Re-attach to the same server-side run so resumed turns keep aggregating to
	// one run in the usage ledger instead of opening a second one.
	tr.SetRunID(cp.RunID)

	return Run(ctx, tb, tr, RunOptions{
		Task:         cp.Task,
		MaxRunTokens: cp.MaxRunTokens,
		OnEvent:      opts.OnEvent,
		Checkpoint:   cp,
	})
}
