package agent

import "strings"

// roe.go implements the §8 human-in-the-loop governance layer's deterministic
// core: the Rules of Engagement (§8.1) and the runtime action classifier (§8.2).
// It sits between the consent gate ("authorized for this host at all?") and the
// safety Envelope ("is this probe within the tier/host floor?"), answering the
// new question: "may the agent perform THIS specific action without a human OK?"
//
// The classifier is DELIBERATELY RULE-BASED, never an LLM (§8.6 pullback #1): for
// a tool that fires state-changing requests, the approve/block boundary must be a
// deterministic property of the request, not a model's judgement. The edge brain
// proposes; this local gate disposes.

// Action is the disposition of a proposed tool action.
type Action int

const (
	// ActionAuto — in scope and non-state-changing; execute immediately, no prompt.
	ActionAuto Action = iota
	// ActionApprove — state-changing or outside the declared allowlist; hold the
	// action and require a human OK before it runs (§8.3 non-blocking: the agent
	// defers this hypothesis and explores others while it waits).
	ActionApprove
	// ActionBlock — off the safety floor, denylisted, or a dangerous pattern; refuse
	// outright. The agent adapts, or the user must widen the RoE.
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionAuto:
		return "auto"
	case ActionApprove:
		return "approve"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Disposition is a classification result: what to do, and a human-readable reason
// surfaced on the approval card (approve) or the tool error (block).
type Disposition struct {
	Action Action
	Reason string
}

// RoE is the per-engagement Rules of Engagement (§8.1) — a signed, logged contract
// for what the agent may do to an in-scope host. All fields are optional; the zero
// value means "no explicit allow/denylist, auto-avoid active", which is the safe
// default. Path patterns match a request's URL path and support a single trailing
// '*' as a prefix wildcard (e.g. "/api/orders/*"); everything else is an exact,
// case-insensitive path match.
type RoE struct {
	// EndpointAllowlist scopes the engagement. Empty = no allowlist constraint. When
	// non-empty, an in-floor action to a path NOT matched is gated (ActionApprove),
	// or blocked outright if LimitToAllowlist is set.
	EndpointAllowlist []string
	// LimitToAllowlist makes the allowlist a hard boundary: anything outside it is
	// blocked rather than merely gated (§8.1 "limit to listed endpoints" toggle).
	LimitToAllowlist bool
	// EndpointDenylist names paths the agent must never touch — always blocked.
	EndpointDenylist []string
	// AllowDangerous opts in to the auto-avoid patterns below. Default false: actions
	// whose path looks like account deletion, credential change, or payment are
	// blocked even if otherwise in scope (§8.1 auto-avoid, default-ON).
	AllowDangerous bool
}

// dangerousPatterns are action shapes an offensive agent must never fire without
// an explicit opt-in — irreversible or high-blast-radius operations. Matched as
// substrings of the lowercased request path (§8.1 auto-avoid).
var dangerousPatterns = []string{
	"delete", "remove", "destroy", "purge", "wipe",
	"password", "passwd", "credential", "reset",
	"payment", "billing", "invoice", "charge", "refund", "checkout", "card",
}

// Classify decides whether a proposed probe runs automatically, needs a human OK,
// or is refused. It first re-applies the Envelope's hard safety floor (a probe the
// floor rejects can never be approved at this RoE — it's a block), then layers the
// engagement's denylist, auto-avoid, and allowlist rules, and finally gates any
// state-changing method. Pure and deterministic — no network, no model.
func (e *Envelope) Classify(method, rawURL string, bodyLen int) Disposition {
	// Hard floor: destructive verbs, off-host, oversize, and tier/ack violations are
	// blocks — the agent adapts or the user widens the engagement.
	if err := e.ValidateProbe(method, rawURL, bodyLen); err != nil {
		return Disposition{ActionBlock, err.Error()}
	}

	path := strings.ToLower(probePath(rawURL))

	// Denylist wins over everything else that passed the floor.
	if pat, ok := matchAnyGlob(e.roe.EndpointDenylist, path); ok {
		return Disposition{ActionBlock, "endpoint is on the RoE denylist (" + pat + ")"}
	}

	// Auto-avoid: dangerous-looking actions are blocked unless explicitly permitted.
	if !e.roe.AllowDangerous {
		if pat, ok := containsAny(path, dangerousPatterns); ok {
			return Disposition{ActionBlock, "dangerous action pattern (\"" + pat + "\") — blocked by auto-avoid; enable AllowDangerous in the RoE to permit"}
		}
	}

	// Allowlist scoping: outside the list is gated, or blocked when the list is hard.
	if len(e.roe.EndpointAllowlist) > 0 {
		if _, ok := matchAnyGlob(e.roe.EndpointAllowlist, path); !ok {
			if e.roe.LimitToAllowlist {
				return Disposition{ActionBlock, "endpoint is outside the RoE allowlist (limit-to-allowlist is on)"}
			}
			return Disposition{ActionApprove, "endpoint is outside the declared allowlist"}
		}
	}

	// A state-changing request needs a human OK even when in scope (§8.2). Only the
	// always-safe read methods reach the target without a prompt.
	m := strings.ToUpper(strings.TrimSpace(method))
	if !alwaysSafeMethods[m] {
		return Disposition{ActionApprove, "state-changing request (" + m + ")"}
	}
	return Disposition{ActionAuto, "in scope, read-only"}
}

// probePath extracts the URL path (lowercased by the caller). Falls back to the
// raw string so a malformed URL can still be matched conservatively.
func probePath(rawURL string) string {
	if _, rest, ok := strings.Cut(rawURL, "://"); ok {
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			p := rest[slash:]
			if q := strings.IndexAny(p, "?#"); q >= 0 {
				return p[:q]
			}
			return p
		}
		return "/"
	}
	return rawURL
}

// matchAnyGlob reports the first pattern in the list that matches path, using a
// single trailing '*' as a prefix wildcard; otherwise an exact match.
func matchAnyGlob(patterns []string, path string) (string, bool) {
	for _, pat := range patterns {
		if pathGlob(pat, path) {
			return pat, true
		}
	}
	return "", false
}

func pathGlob(pattern, path string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// containsAny reports the first substring found in s.
func containsAny(s string, subs []string) (string, bool) {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return sub, true
		}
	}
	return "", false
}
