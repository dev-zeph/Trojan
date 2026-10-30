package ai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// triageURL is a var (not const) so tests can point TriageFindings at an
// httptest server instead of the real edge function.
var triageURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/triage"

const triageBatchSize = 40 // must match MAX_FINDINGS in the triage edge function

// noVerdictRationale is what a finding gets when the model returned no usable
// verdict for it. It is deliberately generic and never copied from another
// finding, so a dropped verdict can't borrow a neighbour's explanation.
const noVerdictRationale = "No verdict was returned for this finding; flagged for manual review."

// Verdict is the adversarial false-positive triage result for one finding
// (agentic DAST Phase 1 — docs/agentic-dast.md §7).
type Verdict struct {
	ID         string  `json:"id"`
	Verdict    string  `json:"verdict"` // "confirmed" | "likely_fp" | "needs_manual"
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
	// Missing marks the local placeholder a finding gets when the model
	// returned nothing usable for it. Never sent by the server; escalation uses
	// it so a placeholder never overwrites a real first-pass verdict.
	Missing bool `json:"-"`
}

type triageFindingWire struct {
	// ID is a short positional key ("f1", "f2", ...) for this batch, not the
	// finding's real ID. Asking the model to echo long opaque IDs is what let
	// verdicts land on the wrong finding; short keys are echoed reliably and
	// are mapped back to the real finding by position on our side.
	ID              string `json:"id"`
	Title           string `json:"title"`
	Severity        string `json:"severity"`
	Category        string `json:"category,omitempty"`
	RuleID          string `json:"ruleId,omitempty"`
	MatchedAt       string `json:"matchedAt,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	ResponseSnippet string `json:"responseSnippet,omitempty"`

	// Rationale is the reporter's own reasoning (the agent's note_finding
	// rationale, or the scanner's message) when it adds to Evidence. Before,
	// only one of evidence/message was sent, so the model often lacked what it
	// needed to confirm an agent finding.
	Rationale string `json:"rationale,omitempty"`
	// SourceFile/SourceLine place a website finding in the project's code
	// (grey-box), so the model can tie the live evidence to the handler.
	SourceFile string `json:"sourceFile,omitempty"`
	SourceLine int    `json:"sourceLine,omitempty"`

	// AgreedScanners lists every engine that independently reported this finding
	// (from cross-scanner dedup — internal/normalizer/dedup.go). More than one is
	// corroboration the edge prompt weights toward "confirmed" (A2).
	AgreedScanners []string `json:"agreedScanners,omitempty"`
}

// TriageFindings asks the backend to adversarially verify each finding against
// its own evidence and returns a verdict keyed by finding ID. Findings are sent
// in batches and base64-wrapped ({ "encoded": ... }) so Cloudflare's WAF doesn't
// 403 on the attack signatures the findings contain; the triage edge function
// unwraps via _shared/body.ts. On a batch error the verdicts gathered so far are
// still returned alongside the error, so a partial failure never loses results.
//
// Every finding in a successful batch gets exactly one verdict: its own. A
// finding the model skipped (or whose key it garbled) is retried once in a
// smaller batch, and if it still has no verdict it gets a needs_manual
// placeholder with Missing set, never another finding's text. Callers should
// give findings unique IDs (normalizer.EnsureUniqueIDs); findings sharing an ID
// would share a map entry.
func TriageFindings(findings []normalizer.Finding, accessToken string) (map[string]Verdict, error) {
	out := make(map[string]Verdict, len(findings))
	for start := 0; start < len(findings); start += triageBatchSize {
		end := min(start+triageBatchSize, len(findings))
		batch := findings[start:end]
		got, err := triageBatch(batch, accessToken)
		if err != nil {
			return out, err
		}

		// One retry for anything the model dropped, in its own batch so it
		// isn't crowded out again.
		var missing []int
		for i := range batch {
			if _, ok := got[i]; !ok {
				missing = append(missing, i)
			}
		}
		if len(missing) > 0 && len(missing) < len(batch) {
			retry := make([]normalizer.Finding, len(missing))
			for j, i := range missing {
				retry[j] = batch[i]
			}
			if again, rerr := triageBatch(retry, accessToken); rerr == nil {
				for j, i := range missing {
					if v, ok := again[j]; ok {
						got[i] = v
					}
				}
			}
		}

		for i, f := range batch {
			v, ok := got[i]
			if !ok {
				v = Verdict{Verdict: "needs_manual", Rationale: noVerdictRationale, Missing: true}
			}
			v.ID = f.ID
			if _, dup := out[f.ID]; !dup { // first finding with an ID wins
				out[f.ID] = v
			}
		}
	}
	return out, nil
}

// batchKey is the positional key the model sees for the i-th finding.
func batchKey(i int) string { return "f" + strconv.Itoa(i+1) }

// parseBatchKey maps a key echoed by the model back to a batch index. It also
// accepts "#3"/"F3"/" f3 " so small formatting slips don't drop a verdict.
func parseBatchKey(key string, n int) (int, bool) {
	k := strings.TrimSpace(strings.ToLower(key))
	k = strings.TrimPrefix(strings.TrimPrefix(k, "#"), "f")
	i, err := strconv.Atoi(k)
	if err != nil || i < 1 || i > n {
		return 0, false
	}
	return i - 1, true
}

// buildTriageWire converts a batch to the wire format with positional keys.
func buildTriageWire(findings []normalizer.Finding) []triageFindingWire {
	wire := make([]triageFindingWire, len(findings))
	for i, f := range findings {
		evidence := f.CodeSnippet
		rationale := ""
		if evidence == "" {
			evidence = f.RawMessage
		} else if f.RawMessage != "" && f.RawMessage != evidence {
			rationale = f.RawMessage
		}
		matchedAt := f.URL
		if matchedAt == "" {
			matchedAt = f.FilePath // holds MatchedAt for DAST findings, file for SAST
			if f.LineNumber > 0 {
				matchedAt += ":" + strconv.Itoa(f.LineNumber)
			}
		}
		wire[i] = triageFindingWire{
			ID:              batchKey(i),
			Title:           f.Title,
			Severity:        string(f.Severity),
			Category:        f.Category,
			RuleID:          f.RuleID,
			MatchedAt:       matchedAt,
			Evidence:        evidence,
			ResponseSnippet: f.SurroundingCode,
			Rationale:       rationale,
			SourceFile:      f.SourceFile,
			SourceLine:      f.SourceLine,
			AgreedScanners:  f.AgreedScanners,
		}
	}
	return wire
}

// assignVerdicts maps the model's verdicts back to batch positions. Only valid
// verdicts with a key that names a finding in this batch count; if the model
// emits the same key twice, the FIRST one is kept (the old edge function kept
// the last, which is how one finding ended up with its neighbour's rationale).
func assignVerdicts(vs []Verdict, n int) map[int]Verdict {
	got := make(map[int]Verdict, n)
	for _, v := range vs {
		i, ok := parseBatchKey(v.ID, n)
		if !ok {
			continue
		}
		switch v.Verdict {
		case "confirmed", "likely_fp", "needs_manual":
		default:
			continue
		}
		if _, dup := got[i]; dup {
			continue
		}
		got[i] = v
	}
	return got
}

// triageBatch sends one batch and returns verdicts keyed by batch index.
func triageBatch(findings []normalizer.Finding, accessToken string) (map[int]Verdict, error) {
	inner, err := json.Marshal(map[string]any{"findings": buildTriageWire(findings)})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"encoded": base64.StdEncoding.EncodeToString(inner)})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, triageURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("triage request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate_limit_exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("triage failed (status %d)", resp.StatusCode)
	}

	var result struct {
		Verdicts []Verdict `json:"verdicts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	got := assignVerdicts(result.Verdicts, len(findings))
	// The edge function fills dropped findings with a "No verdict returned"
	// placeholder at confidence 0. Treat that as missing so it is retried and
	// marked, rather than trusted as a real verdict.
	for i, v := range got {
		if v.Confidence == 0 && strings.HasPrefix(v.Rationale, "No verdict returned") {
			delete(got, i)
		}
	}
	return got, nil
}
