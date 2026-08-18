package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// diff.go implements response diffing (§6.5 #3): a deterministic, structural
// comparison of two captured probe responses. It exists so the agent proves an
// authorization difference (IDOR / BOLA) structurally instead of eyeballing two
// bodies in its own reasoning — the latter is non-deterministic, token-heavy, and
// yields "looks different to me" rather than "response B for bob contains alice's
// email field". Pairs with multi-identity auth (§6.5 #2): fetch a resource as one
// identity, request the SAME resource as another, then diff the two probes.

// Signal is a conservative heuristic verdict about what a diff implies for
// authorization. It is a HINT to prioritize the agent's next move and to seed
// downstream triage — never proof on its own. The FieldDiffs are the evidence.
const (
	// SignalAuthzEnforced: one side was allowed (2xx) and the other was blocked
	// (401/403). The boundary appears to work — usually NOT a vulnerability.
	SignalAuthzEnforced = "authz_enforced"
	// SignalPossibleBOLA: both sides succeeded and returned near-identical bodies
	// despite different identities — the second identity may be reading the first
	// one's resource (broken object-level authorization).
	SignalPossibleBOLA = "possible_bola"
	// SignalDivergent: both succeeded but returned materially different data —
	// expected when each identity legitimately sees its own resource.
	SignalDivergent = "divergent"
	// SignalIdentical: the two responses are byte-identical.
	SignalIdentical = "identical"
)

// FieldDiff is one structural difference between two JSON responses. Path is a
// dotted/bracketed locator (e.g. "user.email", "items[2].id"). Change is one of
// added (only in B), removed (only in A), or changed (present in both, different).
type FieldDiff struct {
	Path   string `json:"path"`
	Change string `json:"change"` // added | removed | changed
	A      string `json:"a,omitempty"`
	B      string `json:"b,omitempty"`
}

// ProbeRef identifies one side of a diff — enough for the agent to reason about
// what was compared without re-sending the bodies.
type ProbeRef struct {
	ProbeID  int    `json:"probe_id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Identity string `json:"identity,omitempty"`
	Status   int    `json:"status"`
}

// DiffResult is the deterministic comparison of two captured probes handed back
// to the agent. Structural (FieldDiffs) when both bodies are JSON; otherwise the
// scalar signals (Similarity, LengthDelta) still apply.
type DiffResult struct {
	A             ProbeRef    `json:"a"`
	B             ProbeRef    `json:"b"`
	StatusChanged bool        `json:"status_changed"`
	LengthDelta   int         `json:"length_delta"` // len(B.body) - len(A.body), bytes
	Similarity    float64     `json:"similarity"`   // 0..1, line-level overlap
	JSON          bool        `json:"json"`         // both bodies parsed as JSON
	FieldDiffs    []FieldDiff `json:"field_diffs,omitempty"`
	Truncated     bool        `json:"truncated,omitempty"` // FieldDiffs capped
	Signal        string      `json:"signal"`
	Note          string      `json:"note,omitempty"`
}

const (
	maxFieldDiffs   = 50  // cap structural diffs so tool output stays token-bounded
	maxDiffValueLen = 160 // per-value truncation in a FieldDiff
	// similarityIdentical is the line-overlap floor above which two 2xx bodies of
	// different identities are treated as "same resource served twice" (BOLA hint).
	similarityIdentical = 0.9
)

// diffResponses compares two captured probes and returns a structural verdict.
// It is pure: no network, no shared state. capturedProbe carries the request meta
// so the result is self-describing.
func diffResponses(a, b capturedProbe) DiffResult {
	res := DiffResult{
		A:             a.ref(),
		B:             b.ref(),
		StatusChanged: a.status != b.status,
		LengthDelta:   len(b.body) - len(a.body),
	}

	if a.body == b.body && a.status == b.status {
		res.Similarity = 1
		res.Signal = SignalIdentical
		res.Note = "responses are byte-identical."
		res.markBOLAIfCrossIdentity(a, b)
		return res
	}

	res.Similarity = lineSimilarity(a.body, b.body)

	// Structural diff when both bodies are JSON — this is the high-signal path for
	// object-level authorization: it names exactly which fields leaked or changed.
	var av, bv any
	aJSON := json.Unmarshal([]byte(a.body), &av) == nil
	bJSON := json.Unmarshal([]byte(b.body), &bv) == nil
	if aJSON && bJSON {
		res.JSON = true
		diffs := make([]FieldDiff, 0, 16)
		diffs, res.Truncated = jsonDiff("", av, bv, diffs)
		res.FieldDiffs = diffs
	}

	res.Signal = classify(a, b, res.Similarity)
	return res
}

// classify assigns a conservative authorization signal. Order matters: an
// allow/block asymmetry is the clearest read; a near-identical body across
// identities is the BOLA hint; everything else is divergent.
func classify(a, b capturedProbe, similarity float64) string {
	aOK := a.status >= 200 && a.status < 300
	bOK := b.status >= 200 && b.status < 300
	aBlocked := a.status == 401 || a.status == 403
	bBlocked := b.status == 401 || b.status == 403

	if (aOK && bBlocked) || (bOK && aBlocked) {
		return SignalAuthzEnforced
	}
	if aOK && bOK && similarity >= similarityIdentical && crossIdentity(a, b) {
		return SignalPossibleBOLA
	}
	return SignalDivergent
}

// markBOLAIfCrossIdentity upgrades an identical-body result to a BOLA hint when
// the two probes were sent as different identities to the same resource.
func (r *DiffResult) markBOLAIfCrossIdentity(a, b capturedProbe) {
	if crossIdentity(a, b) && a.status >= 200 && a.status < 300 {
		r.Signal = SignalPossibleBOLA
		r.Note = "identical response served to two different identities for the same request — object-level authorization may be missing."
	}
}

// crossIdentity reports whether the two probes were sent as distinct identities
// against the same method+URL (the shape of an IDOR/BOLA test).
func crossIdentity(a, b capturedProbe) bool {
	return a.identity != b.identity &&
		strings.EqualFold(a.method, b.method) &&
		a.url == b.url
}

// jsonDiff walks two decoded JSON values and appends field-level differences.
// Returns the accumulated diffs and whether the cap was hit (truncated).
func jsonDiff(path string, a, b any, acc []FieldDiff) ([]FieldDiff, bool) {
	if len(acc) >= maxFieldDiffs {
		return acc, true
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return append(acc, FieldDiff{Path: pathOr(path), Change: "changed", A: brief(a), B: brief(b)}), false
		}
		for _, k := range sortedKeys(av, bv) {
			child := joinPath(path, k)
			aChild, aHas := av[k]
			bChild, bHas := bv[k]
			switch {
			case aHas && !bHas:
				acc = append(acc, FieldDiff{Path: child, Change: "removed", A: brief(aChild)})
			case !aHas && bHas:
				acc = append(acc, FieldDiff{Path: child, Change: "added", B: brief(bChild)})
			default:
				var trunc bool
				acc, trunc = jsonDiff(child, aChild, bChild, acc)
				if trunc {
					return acc, true
				}
			}
			if len(acc) >= maxFieldDiffs {
				return acc, true
			}
		}
		return acc, false
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return append(acc, FieldDiff{Path: pathOr(path), Change: "changed", A: brief(a), B: brief(b)}), false
		}
		n := max(len(av), len(bv))
		for i := range n {
			child := fmt.Sprintf("%s[%d]", path, i)
			switch {
			case i >= len(av):
				acc = append(acc, FieldDiff{Path: child, Change: "added", B: brief(bv[i])})
			case i >= len(bv):
				acc = append(acc, FieldDiff{Path: child, Change: "removed", A: brief(av[i])})
			default:
				var trunc bool
				acc, trunc = jsonDiff(child, av[i], bv[i], acc)
				if trunc {
					return acc, true
				}
			}
			if len(acc) >= maxFieldDiffs {
				return acc, true
			}
		}
		return acc, false
	default:
		if !scalarEqual(a, b) {
			acc = append(acc, FieldDiff{Path: pathOr(path), Change: "changed", A: brief(a), B: brief(b)})
		}
		return acc, false
	}
}

func scalarEqual(a, b any) bool { return brief(a) == brief(b) }

func sortedKeys(a, b map[string]any) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

func pathOr(path string) string {
	if path == "" {
		return "(root)"
	}
	return path
}

// brief renders a JSON value compactly and truncates it so a single leaked field
// can't blow the token budget.
func brief(v any) string {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case nil:
		s = "null"
	default:
		if raw, err := json.Marshal(t); err == nil {
			s = string(raw)
		} else {
			s = fmt.Sprintf("%v", t)
		}
	}
	if len(s) > maxDiffValueLen {
		return s[:maxDiffValueLen] + "…"
	}
	return s
}

// lineSimilarity is a cheap 0..1 overlap ratio over the two bodies' unique lines
// (Jaccard). It is bounded and good enough as a hint; it is not an edit distance.
func lineSimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	as := lineSet(a)
	bs := lineSet(b)
	if len(as) == 0 && len(bs) == 0 {
		return 1
	}
	inter := 0
	for l := range as {
		if _, ok := bs[l]; ok {
			inter++
		}
	}
	union := len(as) + len(bs) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

func lineSet(s string) map[string]struct{} {
	set := map[string]struct{}{}
	for l := range strings.SplitSeq(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			set[l] = struct{}{}
		}
	}
	return set
}
