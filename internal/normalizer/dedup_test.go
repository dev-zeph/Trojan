package normalizer

import (
	"reflect"
	"testing"
)

func TestDedup(t *testing.T) {
	tests := []struct {
		name      string
		in        []Finding
		wantIDs   []string            // IDs of surviving representatives, in order
		wantAgree map[string][]string // repID -> sorted AgreedScanners
	}{
		{
			name: "two scanners, same sink, same CWE -> merged",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityMedium, FilePath: "main.go", LineNumber: 42, CWEIDs: []string{"CWE-89"}},
				{ID: "bearer-0", Scanner: "bearer", Category: "sast", Severity: SeverityHigh, FilePath: "main.go", LineNumber: 42, CWEIDs: []string{"CWE-89"}},
			},
			wantIDs:   []string{"bearer-0"}, // higher severity wins as representative
			wantAgree: map[string][]string{"bearer-0": {"bearer", "semgrep"}},
		},
		{
			name: "same line, different CWE -> not merged",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityMedium, FilePath: "main.go", LineNumber: 42, CWEIDs: []string{"CWE-89"}},
				{ID: "semgrep-1", Scanner: "semgrep", Category: "sast", Severity: SeverityMedium, FilePath: "main.go", LineNumber: 42, CWEIDs: []string{"CWE-79"}},
			},
			wantIDs: []string{"semgrep-0", "semgrep-1"},
		},
		{
			name: "lines within span -> merged; equal severity keeps input order",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityHigh, FilePath: "app/x.go", LineNumber: 10, CWEIDs: []string{"CWE-89"}},
				{ID: "bearer-0", Scanner: "bearer", Category: "sast", Severity: SeverityHigh, FilePath: "app/x.go", LineNumber: 12, CWEIDs: []string{"CWE-89"}},
			},
			wantIDs:   []string{"semgrep-0"},
			wantAgree: map[string][]string{"semgrep-0": {"bearer", "semgrep"}},
		},
		{
			name: "lines beyond span -> not merged",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityHigh, FilePath: "app/x.go", LineNumber: 10, CWEIDs: []string{"CWE-89"}},
				{ID: "bearer-0", Scanner: "bearer", Category: "sast", Severity: SeverityHigh, FilePath: "app/x.go", LineNumber: 20, CWEIDs: []string{"CWE-89"}},
			},
			wantIDs: []string{"semgrep-0", "bearer-0"},
		},
		{
			name: "path normalization: ./main.go == main.go",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityLow, FilePath: "./main.go", LineNumber: 5, CWEIDs: []string{"CWE-22"}},
				{ID: "trivy-0", Scanner: "trivy", Category: "sast", Severity: SeverityCritical, FilePath: "main.go", LineNumber: 5, CWEIDs: []string{"CWE-22"}},
			},
			wantIDs:   []string{"trivy-0"}, // critical wins
			wantAgree: map[string][]string{"trivy-0": {"semgrep", "trivy"}},
		},
		{
			name: "line-less findings pass through untouched (no over-merge of SCA)",
			in: []Finding{
				{ID: "trivy-0", Scanner: "trivy", Category: "sca", Severity: SeverityHigh, FilePath: "go.mod", LineNumber: 0, CWEIDs: []string{"CWE-400"}},
				{ID: "trivy-1", Scanner: "trivy", Category: "sca", Severity: SeverityHigh, FilePath: "go.mod", LineNumber: 0, CWEIDs: []string{"CWE-400"}},
			},
			wantIDs: []string{"trivy-0", "trivy-1"},
		},
		{
			name: "three-way cluster across contiguous lines",
			in: []Finding{
				{ID: "semgrep-0", Scanner: "semgrep", Category: "sast", Severity: SeverityMedium, FilePath: "a.go", LineNumber: 100, CWEIDs: []string{"CWE-89"}},
				{ID: "bearer-0", Scanner: "bearer", Category: "sast", Severity: SeverityMedium, FilePath: "a.go", LineNumber: 101, CWEIDs: []string{"CWE-89"}},
				{ID: "semgrep-1", Scanner: "semgrep", Category: "sast", Severity: SeverityCritical, FilePath: "a.go", LineNumber: 102, CWEIDs: []string{"CWE-89"}},
			},
			wantIDs:   []string{"semgrep-1"},
			wantAgree: map[string][]string{"semgrep-1": {"bearer", "semgrep"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dedup(tt.in)
			gotIDs := make([]string, len(got))
			for i, f := range got {
				gotIDs[i] = f.ID
			}
			if !reflect.DeepEqual(gotIDs, tt.wantIDs) {
				t.Fatalf("survivor IDs = %v, want %v", gotIDs, tt.wantIDs)
			}
			for _, f := range got {
				if want, ok := tt.wantAgree[f.ID]; ok {
					if !reflect.DeepEqual(f.AgreedScanners, want) {
						t.Errorf("%s AgreedScanners = %v, want %v", f.ID, f.AgreedScanners, want)
					}
				}
			}
		})
	}
}

func TestDedupEmptyAndSingle(t *testing.T) {
	if got := Dedup(nil); got != nil {
		t.Errorf("Dedup(nil) = %v, want nil", got)
	}
	single := []Finding{{ID: "semgrep-0", Scanner: "semgrep", FilePath: "a.go", LineNumber: 1}}
	got := Dedup(single)
	if len(got) != 1 || !reflect.DeepEqual(got[0].AgreedScanners, []string{"semgrep"}) {
		t.Errorf("single finding: got %+v, want AgreedScanners=[semgrep]", got)
	}
}

func TestDedupSecretsRequireRuleAndValue(t *testing.T) {
	stripe := "sk_" + "live_" + "DedupStripeKeyValue001"
	github := "gh" + "p_" + "DedupGithubKeyValue00000000000000001"
	in := []Finding{
		{ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", Severity: SeverityHigh, FilePath: "config.ts", LineNumber: 1, RuleID: "stripe-access-token", CodeSnippet: stripe},
		{ID: "gitleaks-1", Scanner: "gitleaks", Category: "secrets", Severity: SeverityHigh, FilePath: "config.ts", LineNumber: 2, RuleID: "github-pat", CodeSnippet: github},
	}
	got := Dedup(in)
	if len(got) != 2 {
		t.Fatalf("Stripe+GitHub on consecutive lines: got %d findings, want 2", len(got))
	}

	var keys []Finding
	for i := 1; i <= 10; i++ {
		keys = append(keys, Finding{
			ID: "gitleaks-" + itoa(i), Scanner: "gitleaks", Category: "secrets",
			Severity: SeverityHigh, FilePath: "config.ts", LineNumber: i,
			RuleID: "generic-api-key", CodeSnippet: "keyval" + itoa(i) + "Zx9Q",
		})
	}
	got = Dedup(keys)
	if len(got) != 10 {
		t.Fatalf("10 consecutive keys: got %d findings, want 10", len(got))
	}

	// Same rule and same value within the span still merge.
	dup := []Finding{
		{ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", Severity: SeverityHigh, FilePath: "config.ts", LineNumber: 1, RuleID: "stripe-access-token", CodeSnippet: stripe},
		{ID: "gitleaks-1", Scanner: "gitleaks", Category: "secrets", Severity: SeverityHigh, FilePath: "config.ts", LineNumber: 2, RuleID: "stripe-access-token", CodeSnippet: stripe},
	}
	got = Dedup(dup)
	if len(got) != 1 {
		t.Fatalf("same secret two lines apart should merge, got %d", len(got))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
