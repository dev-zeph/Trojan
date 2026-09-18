package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// DefaultModel is the model the loop targets when Config.Model is empty. It is a
// current Claude Opus id and is overridable per run (Config.Model) or, in the
// demo, via the TROJAN_AGENT_MODEL env var, so upgrading the model is a config
// change, not a code change.
const DefaultModel = "claude-opus-4-8"

// ErrNoAPIKey means the live loop was asked to run without a resolvable
// Anthropic key. It is the gate the task requires: the deterministic tool layer
// needs no key, and callers can detect this case (errors.Is) to print a clear
// message and exit cleanly rather than crashing or hanging.
var ErrNoAPIKey = errors.New("agent: no ANTHROPIC_API_KEY set; live hypothesis loop is disabled")

// ErrNoFinding means the model ended its turn without emitting a finding (it ran
// out of turns, or decided there was nothing to report). Not a failure of the
// harness.
var ErrNoFinding = errors.New("agent: model finished without emitting a finding")

// Config controls one run of the hypothesis loop.
type Config struct {
	// Model is the Claude model id. Empty uses DefaultModel.
	Model string
	// APIKey is the Anthropic key. Empty falls back to the ANTHROPIC_API_KEY
	// environment variable; if both are empty the loop returns ErrNoAPIKey.
	APIKey string
	// OrgContext is free-form organisation context the model may fold into its
	// reasoning (what the app does, which data is sensitive, prior incidents).
	// It composes with whatever an org-context workstream produces without a
	// hard dependency on it. Optional.
	OrgContext string
	// MaxTurns caps the tool-calling rounds so a confused model cannot loop
	// forever (and spend). Zero means the default (8).
	MaxTurns int
	// Logf, if set, receives human-readable progress lines (tool calls, model
	// text). Nil is silent.
	Logf func(format string, args ...any)
}

func (c Config) model() string {
	if strings.TrimSpace(c.Model) != "" {
		return c.Model
	}
	return DefaultModel
}

func (c Config) maxTurns() int {
	if c.MaxTurns > 0 {
		return c.MaxTurns
	}
	return 8
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// resolveKey returns the API key to use, honouring the explicit Config.APIKey
// first and the ANTHROPIC_API_KEY env var second. An empty result means the
// caller must not make a live call.
func (c Config) resolveKey() string {
	if strings.TrimSpace(c.APIKey) != "" {
		return c.APIKey
	}
	return strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
}

// emitFindingSchema is the terminal tool: the model calls it to deliver the
// structured Finding. Defined here (not in ToolSpecs) because it is the loop's
// control-flow signal, not a graph query.
func emitFindingSchema() ToolSpec {
	return ToolSpec{
		Name:        "emit_finding",
		Description: "Report your single best attack hypothesis and stop. Call this exactly once, only after you have used the other tools to ground it in the graph.",
		Properties: map[string]any{
			"hypothesis": map[string]any{"type": "string", "description": "the attack in one or two sentences: what the attacker feeds in, where it lands, what it achieves"},
			"severity":   map[string]any{"type": "string", "enum": []string{"high", "medium", "low"}, "description": "justify against the sink severity and whether the path touches PII"},
			"path":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "the node chain from entrypoint to sink, e.g. [\"api.loginHandler\", \"db.Query\"]"},
			"rationale":  map[string]any{"type": "string", "description": "why it holds, citing the file:line anchors the tools returned"},
			"source_id":  map[string]any{"type": "integer", "description": "graph node id of the source entrypoint"},
			"sink_id":    map[string]any{"type": "integer", "description": "graph node id of the sink"},
		},
		Required: []string{"hypothesis", "severity", "path", "rationale"},
	}
}

// specToTool converts an SDK-agnostic ToolSpec into an Anthropic tool param.
func specToTool(s ToolSpec) anthropic.ToolUnionParam {
	props := s.Properties
	if props == nil {
		props = map[string]any{}
	}
	tp := anthropic.ToolParam{
		Name:        s.Name,
		Description: anthropic.String(s.Description),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: props,
			Required:   s.Required,
		},
	}
	return anthropic.ToolUnionParam{OfTool: &tp}
}

// systemPrompt frames the model as a pen-tester reasoning over a local graph,
// and encodes the privacy stance: this is the user's own code, audited locally.
func systemPrompt(orgContext string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(`
You are a security analyst auditing the user's OWN codebase, locally, with their
consent. You reason over a Code Property Graph through tools: nodes are functions
and dangerous sinks, edges are calls and containment, and some nodes are tagged as
untrusted entrypoints (sources) or as touching PII/PHI.

Work like a pen-tester reading their notes:
1. list_entrypoints to find where untrusted input enters.
2. For an entrypoint, use neighbors(edge_kind="contains") to see its sinks and
   neighbors(edge_kind="calls") to follow the call chain deeper.
3. get_dataflow(source_id, sink_id) to confirm a route actually connects them.
4. read_context to resolve any name to a file:line, and get_pii_nodes to see if the
   route touches sensitive data (which raises severity).
5. Form ONE concrete, graph-grounded attack hypothesis and call emit_finding once.

Ground every claim in what the tools return. Cite file:line anchors. Do not invent
nodes, routes, or code you were not shown. If nothing is exploitable, still call
emit_finding with a low-severity, honestly-reasoned result.`))
	if strings.TrimSpace(orgContext) != "" {
		b.WriteString("\n\nOrganisation context provided by the user:\n")
		b.WriteString(strings.TrimSpace(orgContext))
	}
	return b.String()
}

// RunHypothesisLoop drives Claude over the graph tools to produce one grounded
// Finding. The live model call is gated: with no resolvable key it returns
// ErrNoAPIKey immediately, having done no network I/O, so builds and tests never
// require a key or spend. When a key is present it runs a manual tool-use loop
// (define tools, call the model, execute tool calls, feed results back) until
// the model calls emit_finding or the turn budget is spent.
func RunHypothesisLoop(ctx context.Context, tb *Toolbox, cfg Config) (*Finding, error) {
	key := cfg.resolveKey()
	if key == "" {
		return nil, ErrNoAPIKey
	}

	client := anthropic.NewClient(option.WithAPIKey(key))

	// Tools: the five graph tools plus the terminal emit_finding.
	specs := ToolSpecs()
	tools := make([]anthropic.ToolUnionParam, 0, len(specs)+1)
	for _, s := range specs {
		tools = append(tools, specToTool(s))
	}
	tools = append(tools, specToTool(emitFindingSchema()))

	system := []anthropic.TextBlockParam{{Text: systemPrompt(cfg.OrgContext)}}
	adaptive := anthropic.ThinkingConfigAdaptiveParam{Display: anthropic.ThinkingConfigAdaptiveDisplaySummarized}

	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(
			"Audit this codebase. Pick one entrypoint, trace it to a dangerous sink, and report your single best attack hypothesis via emit_finding.")),
	}

	for turn := 0; turn < cfg.maxTurns(); turn++ {
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(cfg.model()),
			MaxTokens: 16000,
			System:    system,
			Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &adaptive},
			Tools:     tools,
			Messages:  messages,
		})
		if err != nil {
			return nil, fmt.Errorf("agent: claude turn failed: %w", err)
		}

		// Record the assistant turn (including any thinking blocks) before we
		// act on the tool calls, so the conversation replays correctly.
		messages = append(messages, resp.ToParam())

		var toolResults []anthropic.ContentBlockParamUnion
		var finding *Finding

		for _, block := range resp.Content {
			switch v := block.AsAny().(type) {
			case anthropic.TextBlock:
				if txt := strings.TrimSpace(v.Text); txt != "" {
					cfg.logf("model: %s", txt)
				}
			case anthropic.ToolUseBlock:
				if v.Name == "emit_finding" {
					f, ferr := parseFinding(v.Input)
					if ferr != nil {
						// Hand the error back so the model can correct itself.
						toolResults = append(toolResults,
							anthropic.NewToolResultBlock(v.ID, "invalid emit_finding: "+ferr.Error(), true))
						continue
					}
					finding = f
					cfg.logf("finding: [%s] %s", f.Severity, f.Hypothesis)
					toolResults = append(toolResults,
						anthropic.NewToolResultBlock(v.ID, "recorded", false))
					continue
				}
				cfg.logf("tool: %s %s", v.Name, string(v.Input))
				out, terr := tb.Dispatch(v.Name, v.Input)
				if terr != nil {
					toolResults = append(toolResults,
						anthropic.NewToolResultBlock(v.ID, terr.Error(), true))
					continue
				}
				toolResults = append(toolResults,
					anthropic.NewToolResultBlock(v.ID, out, false))
			}
		}

		if finding != nil {
			return finding, nil
		}

		// No tools requested and no finding: the model is done, but emptily.
		if resp.StopReason != anthropic.StopReasonToolUse {
			return nil, ErrNoFinding
		}

		messages = append(messages, anthropic.NewUserMessage(toolResults...))
	}

	return nil, fmt.Errorf("agent: %w (turn budget of %d exhausted)", ErrNoFinding, cfg.maxTurns())
}

// parseFinding decodes an emit_finding tool input into a Finding, tolerating the
// model's JSON escaping quirks by going through the standard decoder.
func parseFinding(raw json.RawMessage) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if strings.TrimSpace(f.Hypothesis) == "" {
		return nil, errors.New("hypothesis is empty")
	}
	if strings.TrimSpace(f.Severity) == "" {
		f.Severity = "low"
	}
	return &f, nil
}
