package ai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

const (
	triageURL       = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/triage"
	triageBatchSize = 40 // must match MAX_FINDINGS in the triage edge function
)

// Verdict is the adversarial false-positive triage result for one finding
// (agentic DAST Phase 1 — docs/agentic-dast.md §7).
type Verdict struct {
	ID         string  `json:"id"`
	Verdict    string  `json:"verdict"` // "confirmed" | "likely_fp" | "needs_manual"
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

type triageFindingWire struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Severity        string `json:"severity"`
	Category        string `json:"category,omitempty"`
	RuleID          string `json:"ruleId,omitempty"`
	MatchedAt       string `json:"matchedAt,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	ResponseSnippet string `json:"responseSnippet,omitempty"`

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
func TriageFindings(findings []normalizer.Finding, accessToken string) (map[string]Verdict, error) {
	out := make(map[string]Verdict, len(findings))
	for start := 0; start < len(findings); start += triageBatchSize {
		end := min(start+triageBatchSize, len(findings))
		verdicts, err := triageBatch(findings[start:end], accessToken)
		if err != nil {
			return out, err
		}
		for _, v := range verdicts {
			out[v.ID] = v
		}
	}
	return out, nil
}

func triageBatch(findings []normalizer.Finding, accessToken string) ([]Verdict, error) {
	wire := make([]triageFindingWire, len(findings))
	for i, f := range findings {
		evidence := f.CodeSnippet
		if evidence == "" {
			evidence = f.RawMessage
		}
		wire[i] = triageFindingWire{
			ID:              f.ID,
			Title:           f.Title,
			Severity:        string(f.Severity),
			Category:        f.Category,
			RuleID:          f.RuleID,
			MatchedAt:       f.FilePath, // holds MatchedAt for DAST findings
			Evidence:        evidence,
			ResponseSnippet: f.SurroundingCode,
			AgreedScanners:  f.AgreedScanners,
		}
	}

	inner, err := json.Marshal(map[string]any{"findings": wire})
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
	return result.Verdicts, nil
}
