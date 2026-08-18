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
