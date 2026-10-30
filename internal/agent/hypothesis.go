package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HypothesesPath is where a white-box run's output is saved, relative to the
// project root. The pen-test agent's seed reads it from here.
const HypothesesPath = ".trojan/hypotheses.json"

// Hypothesis is one concrete, testable claim the white-box agent formed from
// the code graph: which nodes are involved, what class of flaw it is, which
// live endpoint would prove it, and what a successful exploit would show. It
// is a claim to verify, never a finding: the pen test proves or refutes it.
type Hypothesis struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// NodeKeys are stable graph.Node keys (e.g. "app/api/orders/route.ts#POST",
	// "datastore:orders"). The loop rejects keys the graph does not contain.
	NodeKeys []string `json:"node_keys"`
	// Class is the vulnerability class, e.g. "missing-auth", "idor",
	// "sql-injection", "client-exposure".
	Class string `json:"class"`
	// Method and Path are the live endpoint to test ("POST", "/api/orders").
	Method string `json:"method,omitempty"`
	Path   string `json:"path"`
	// ExpectedEvidence is what a successful exploit would observably show.
	ExpectedEvidence string `json:"expected_evidence"`
	// Preconditions is what the test needs, e.g. "two accounts".
	Preconditions string `json:"preconditions,omitempty"`
	// TestIdea is a non-destructive way to prove it within the pen-test tiers.
	TestIdea string `json:"test_idea,omitempty"`
	// Confidence is "high" | "medium" | "low".
	Confidence string `json:"confidence"`
	// Impact is one plain-language sentence for a non-technical founder.
	Impact    string `json:"impact,omitempty"`
	Rationale string `json:"rationale,omitempty"`
}

// Endpoint renders "METHOD /path" (or just the path when no method is set).
func (h Hypothesis) Endpoint() string {
	if h.Method == "" {
		return h.Path
	}
	return h.Method + " " + h.Path
}

// HypothesisFile is the on-disk shape of .trojan/hypotheses.json.
type HypothesisFile struct {
	GeneratedAt time.Time    `json:"generated_at"`
	RunID       string       `json:"run_id,omitempty"`
	Hypotheses  []Hypothesis `json:"hypotheses"`
}

// SaveHypotheses writes the file under root/.trojan/, creating the directory.
func SaveHypotheses(root string, f HypothesisFile) error {
	path := filepath.Join(root, filepath.FromSlash(HypothesesPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadHypotheses reads root/.trojan/hypotheses.json. A missing file returns
// (nil, nil) so callers can treat "never run" as "nothing to prove".
func LoadHypotheses(root string) (*HypothesisFile, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(HypothesesPath)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f HypothesisFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", HypothesesPath, err)
	}
	return &f, nil
}

// parseHypothesis decodes and normalizes an emit_hypothesis tool input. Node
// keys are checked against the graph by the caller, which knows the graph.
func parseHypothesis(raw json.RawMessage) (Hypothesis, error) {
	var h Hypothesis
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, err
	}
	h.Title = strings.TrimSpace(h.Title)
	h.Class = strings.ToLower(strings.TrimSpace(h.Class))
	h.Method = strings.ToUpper(strings.TrimSpace(h.Method))
	h.Path = strings.TrimSpace(h.Path)
	h.ExpectedEvidence = strings.TrimSpace(h.ExpectedEvidence)
	h.Confidence = strings.ToLower(strings.TrimSpace(h.Confidence))
	h.Preconditions = strings.TrimSpace(h.Preconditions)
	h.TestIdea = strings.TrimSpace(h.TestIdea)
	// Impact is shown to founders: keep it free of em dashes.
	h.Impact = strings.ReplaceAll(strings.TrimSpace(h.Impact), "—", ",")
	keys := h.NodeKeys[:0]
	for _, k := range h.NodeKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	h.NodeKeys = keys

	switch {
	case len(h.NodeKeys) == 0:
		return h, errors.New("node_keys is empty: name the graph nodes involved")
	case h.Class == "":
		return h, errors.New("class is empty")
	case h.Path == "":
		return h, errors.New("path is empty: name the live endpoint to test")
	case h.ExpectedEvidence == "":
		return h, errors.New("expected_evidence is empty: say what a successful exploit would show")
	}
	switch h.Confidence {
	case "high", "medium", "low":
	default:
		h.Confidence = "low"
	}
	if h.Title == "" {
		h.Title = h.Class + " at " + h.Endpoint()
	}
	return h, nil
}
