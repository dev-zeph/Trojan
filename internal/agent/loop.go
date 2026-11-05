package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The white-box hypothesis loop. It lives here, in the CLI; each reasoning turn
// is one stateless Transport call to the whitebox-agent edge function, which
// holds the system prompt and the tool definitions. The loop executes the tool
// calls the model requests against the local Toolbox, feeds the results back,
// and repeats until the model finishes or a budget trips. No model and no
// prompt live in this process: only tool execution and bookkeeping.

// Tool names: the contract shared with the edge function's tool definitions.
const (
	toolListEntrypoints = "list_entrypoints"
	toolGetDataflow     = "get_dataflow"
	toolReadContext     = "read_context"
	toolGetPIINodes     = "get_pii_nodes"
	toolNeighbors       = "neighbors"
	toolUnguardedPaths  = "unguarded_paths"
	toolClientExposures = "client_exposures"
	toolReadSource      = "read_source"
	toolSecurityHistory = "get_security_history"
	toolEmitHypothesis  = "emit_hypothesis"
	toolFinish          = "finish"
)

// StopReason says why a run ended.
type StopReason string

const (
	StopFinished           StopReason = "finished"            // finish tool or end of turn
	StopTurnBudget         StopReason = "turn budget reached" // MaxTurns spent
	StopTokenBudget        StopReason = "token budget reached"
	StopInsufficientTokens StopReason = "out of Trojan Tokens"
)

// Options bounds one run. Zero values take the defaults.
type Options struct {
	// MaxTurns caps reasoning turns (each one is billed). Default 12.
	MaxTurns int
	// MaxTokens is a cumulative LLM-token ceiling across turns. 0 = off.
	MaxTokens int
	// MaxHypotheses caps how many hypotheses are kept. Default 8.
	MaxHypotheses int
	// Logf, if set, receives one-line progress (tool calls, hypotheses).
	Logf func(format string, args ...any)
}

func (o Options) maxTurns() int {
	if o.MaxTurns > 0 {
		return o.MaxTurns
	}
	return 12
}

func (o Options) maxHypotheses() int {
	if o.MaxHypotheses > 0 {
		return o.MaxHypotheses
	}
	return 8
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Result is the outcome of a run. On a transport error it still carries the
// hypotheses emitted before the failure.
type Result struct {
	Hypotheses []Hypothesis
	Summary    string
	StopReason StopReason
	Turns      int
	Usage      Usage
	RunID      string
}

// SeedInput is the project data the first user turn carries. It is facts about
// the project only; how to reason over them is the server's business.
type SeedInput struct {
	Project     string
	OrgContext  string   // org context YAML, "" if none
	EndpointMap []string // grey-box "METHOD /path -> file#handler" lines
	Nodes       int
	Unguarded   int
	Exposures   int
}

// Seed caps.
const (
	seedOrgContextCap = 3000
	seedMaxEndpoints  = 30
)

// BuildSeed renders the first user message.
func BuildSeed(in SeedInput, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PROJECT: %s\n", in.Project)
	fmt.Fprintf(&b, "GRAPH: %d nodes, %d unguarded entrypoint(s), %d client exposure(s)\n", in.Nodes, in.Unguarded, in.Exposures)
	fmt.Fprintf(&b, "BUDGET: at most %d hypotheses, %d turns\n", opts.maxHypotheses(), opts.maxTurns())
	if oc := strings.TrimSpace(in.OrgContext); oc != "" {
		if len(oc) > seedOrgContextCap {
			oc = strings.ToValidUTF8(oc[:seedOrgContextCap], "") + "\n..."
		}
		b.WriteString("\nORG CONTEXT (authored by the owner):\n" + oc + "\n")
	}
	if len(in.EndpointMap) > 0 {
		eps := in.EndpointMap
		more := 0
		if len(eps) > seedMaxEndpoints {
			more = len(eps) - seedMaxEndpoints
			eps = eps[:seedMaxEndpoints]
		}
		b.WriteString("\nENDPOINT MAP (live route -> handler):\n" + strings.Join(eps, "\n") + "\n")
		if more > 0 {
			fmt.Fprintf(&b, "...and %d more\n", more)
		}
	}
	return b.String()
}

// Run drives the loop: seed is the first user message (see BuildSeed).
func Run(ctx context.Context, tb *Toolbox, tr Transport, seed string, opts Options) (*Result, error) {
	res := &Result{}
	messages := []Message{userTextMessage(seed)}
	seen := map[string]bool{}

	for res.Turns < opts.maxTurns() {
		res.Turns++
		turn, err := tr.Turn(ctx, messages)
		if err != nil {
			if errors.Is(err, ErrInsufficientTokens) {
				res.StopReason = StopInsufficientTokens
			}
			return res, fmt.Errorf("white-box turn %d: %w", res.Turns, err)
		}
		if res.RunID == "" {
			res.RunID = turn.RunID
		}
		res.Usage.add(turn.Usage)

		// Replay the assistant turn verbatim (thinking blocks included).
		messages = append(messages, Message{Role: "assistant", Content: turn.Content})

		results, finished := dispatch(tb, turn.Content, res, seen, opts)

		// Hypotheses in this turn are already paid for, so they were kept above
		// before the ceiling is checked.
		if opts.MaxTokens > 0 && res.Usage.Total() > opts.MaxTokens {
			res.StopReason = StopTokenBudget
			return res, nil
		}
		if finished || turn.StopReason != "tool_use" || len(results) == 0 {
			res.StopReason = StopFinished
			return res, nil
		}
		messages = append(messages, toolResultsMessage(results))
	}
	res.StopReason = StopTurnBudget
	return res, nil
}

// dispatch executes every tool_use block in one assistant turn and returns the
// tool results, and whether the model called finish.
func dispatch(tb *Toolbox, content []json.RawMessage, res *Result, seen map[string]bool, opts Options) ([]toolResultBlock, bool) {
	var out []toolResultBlock
	finished := false
	for _, raw := range content {
		var b blockPeek
		if json.Unmarshal(raw, &b) != nil {
			continue
		}
		switch b.Type {
		case "text":
			if t := strings.TrimSpace(b.Text); t != "" {
				opts.logf("agent: %s", oneLine(t, 200))
			}
		case "tool_use":
			r := toolResultBlock{ToolUseID: b.ID}
			switch b.Name {
			case toolEmitHypothesis:
				r.Content, r.IsError = emit(tb, b.Input, res, seen, opts)
			case toolFinish:
				var in struct {
					Summary string `json:"summary"`
				}
				_ = json.Unmarshal(b.Input, &in)
				res.Summary = strings.TrimSpace(in.Summary)
				finished = true
				r.Content = "ok"
			default:
				opts.logf("tool: %s %s", b.Name, oneLine(string(b.Input), 120))
				s, err := tb.Dispatch(b.Name, b.Input)
				if err != nil {
					r.Content, r.IsError = err.Error(), true
				} else {
					r.Content = s
				}
			}
			out = append(out, r)
		}
	}
	return out, finished
}

// emit validates and records one hypothesis. Errors go back to the model so it
// can correct itself; they never abort the run.
func emit(tb *Toolbox, input json.RawMessage, res *Result, seen map[string]bool, opts Options) (string, bool) {
	if len(res.Hypotheses) >= opts.maxHypotheses() {
		return "hypothesis limit reached; call finish", true
	}
	h, err := parseHypothesis(input)
	if err != nil {
		return "invalid emit_hypothesis: " + err.Error(), true
	}
	var unknown []string
	for _, k := range h.NodeKeys {
		if !tb.HasKey(k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return "unknown node key(s): " + strings.Join(unknown, ", ") + "; use keys exactly as the tools returned them", true
	}
	dedup := h.Class + "|" + h.Endpoint()
	if seen[dedup] {
		return "duplicate: already recorded " + h.Class + " at " + h.Endpoint(), true
	}
	seen[dedup] = true
	h.ID = fmt.Sprintf("H%d", len(res.Hypotheses)+1)
	res.Hypotheses = append(res.Hypotheses, h)
	opts.logf("hypothesis %s [%s] %s at %s", h.ID, h.Confidence, h.Class, h.Endpoint())
	return "recorded " + h.ID, false
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "..."
	}
	return s
}
