package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

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
	toolGetCrawlMap = "get_crawl_map"
	toolHTTPProbe   = "http_probe"
	toolNoteFinding = "note_finding"
	toolReadSource  = "read_source"
	toolFinish      = "finish"
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

// DefaultMaxRunTokens is the shipping default for RunOptions.MaxRunTokens — a
// hard cumulative-token ceiling so a run's cost is always bounded, not just its
// step/request/time budget. It's a safety net, deliberately set well above a
// normal run: small/medium runs land around 150k–400k tokens and even a large
// legitimate target is ~1M, so this only trips a pathological blow-up. Total()
// counts cache-read tokens at face value (they bill at ~0.1x), so the real-dollar
// ceiling is lower than the raw number implies — i.e. this errs toward finishing.
// Pass --max-run-tokens 0 to disable; retune once per-run telemetry is in hand.
const DefaultMaxRunTokens = 1_500_000

// Run drives the agent loop against a prepared Toolbox and Transport.
func Run(ctx context.Context, tb *Toolbox, tr Transport, opts RunOptions) (*RunResult, error) {
	emit := opts.OnEvent
	if emit == nil {
		emit = func(Event) {}
	}

	messages := []Message{userTextMessage(opts.Task)}
	var cum Usage
	result := &RunResult{}

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
			return finish(result, tb, cum, EventStopped, reason, emit), nil
		}
		step, _, _ := tb.Budget().Stats()
		result.Steps = step
		emit(Event{Type: EventStep, Step: step})

		turn, err := tr.Turn(ctx, messages)
		if err != nil {
			return nil, err
		}
		cum.add(turn.Usage)

		// Cumulative cost ceiling — the $ bound, checked after each turn.
		if opts.MaxRunTokens > 0 && cum.Total() > opts.MaxRunTokens {
			messages = append(messages, Message{Role: "assistant", Content: turn.Content})
			return finish(result, tb, cum, EventStopped, StopTokenBudget, emit), nil
		}

		// Append the assistant turn verbatim (preserves thinking blocks).
		messages = append(messages, Message{Role: "assistant", Content: turn.Content})

		toolResults, finished := dispatchBlocks(ctx, tb, turn.Content, step, emit)

		if finished {
			return finish(result, tb, cum, EventFinish, "", emit), nil
		}
		// The agent stopped requesting tools (end_turn, refusal, max_tokens, …):
		// treat the run as complete rather than looping forever.
		if turn.StopReason != "tool_use" || len(toolResults) == 0 {
			return finish(result, tb, cum, EventFinish, "", emit), nil
		}

		messages = append(messages, toolResultMessage(toolResults))
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

	case toolFinish:
		var f struct {
			Summary string `json:"summary"`
		}
		_ = json.Unmarshal(b.Input, &f)
		tb.Finish(f.Summary)
		return `{"ok":true}`, false, true

	default:
		return fmt.Sprintf("unknown tool %q", b.Name), true, false
	}
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
	tr := NewEdgeTransport(cfg.AccessToken)

	return Run(ctx, tb, tr, RunOptions{
		Task:         cfg.Task,
		MaxRunTokens: cfg.MaxRunTokens,
		OnEvent:      cfg.OnEvent,
	})
}
