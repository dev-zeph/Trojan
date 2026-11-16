package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func parseLines(t *testing.T, out string) []progressLine {
	t.Helper()
	var res []progressLine
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		if !strings.HasPrefix(l, "PROGRESS ") {
			t.Fatalf("line without PROGRESS prefix: %q", l)
		}
		var p progressLine
		if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "PROGRESS ")), &p); err != nil {
			t.Fatalf("bad json %q: %v", l, err)
		}
		res = append(res, p)
	}
	return res
}

func TestProgressSilentOutsideDesktop(t *testing.T) {
	var buf bytes.Buffer
	p := newCodeScanProgress(false, 3, true)
	p.r.w = &buf
	p.Preparing()
	p.ScannerEvent("semgrep", false, 0, nil)
	p.ScannerEvent("semgrep", true, 1, nil)
	p.DoubleCheck()
	p.BuildingReport()
	pt := newPenTestProgress(false)
	pt.w = &buf
	pt.Phase("x", "y")
	pt.Probe()
	if buf.Len() != 0 {
		t.Fatalf("expected no output outside desktop mode, got %q", buf.String())
	}
}

func TestProgressParallelScannersMonotonicEndsAtTotal(t *testing.T) {
	names := []string{"semgrep", "bearer", "trivy", "gitleaks", "checkov", "syft", "trojan"}
	for _, withAI := range []bool{true, false} {
		var buf bytes.Buffer
		p := newCodeScanProgress(true, len(names), withAI)
		p.r.w = &buf
		p.Preparing()
		var wg sync.WaitGroup
		for _, n := range names {
			wg.Add(1)
			go func(n string) {
				defer wg.Done()
				p.ScannerEvent(n, false, 0, nil)
				p.ScannerEvent(n, true, 2, nil)
			}(n)
		}
		wg.Wait()
		p.DoubleCheck()
		p.BuildingReport()

		lines := parseLines(t, buf.String())
		wantTotal := len(names) + 2
		if withAI {
			wantTotal++
		}
		prev := 0
		for _, l := range lines {
			if l.Total != wantTotal {
				t.Fatalf("total=%d want %d", l.Total, wantTotal)
			}
			if l.Step < prev {
				t.Fatalf("step went backwards: %d after %d", l.Step, prev)
			}
			if l.Step < 1 || l.Step > l.Total {
				t.Fatalf("step %d out of range", l.Step)
			}
			if l.Label == "" {
				t.Fatalf("empty label for %+v", l)
			}
			prev = l.Step
		}
		last := lines[len(lines)-1]
		if last.Step != last.Total || last.Key != "report" {
			t.Fatalf("last line should be the report at total, got %+v", last)
		}
		if !withAI {
			for _, l := range lines {
				if l.Key == "triage" {
					t.Fatal("no AI step expected when not signed in")
				}
			}
		}
	}
}

func TestScannerLabelsArePlain(t *testing.T) {
	for _, n := range []string{"semgrep", "bearer", "trivy", "gitleaks", "checkov", "syft", "trojan", "unknown"} {
		l := scannerLabel(n)
		if l == "" {
			t.Fatalf("no label for %s", n)
		}
		if strings.ContainsAny(l, "—–") {
			t.Fatalf("label has a dash character: %q", l)
		}
		if n != "unknown" && strings.Contains(strings.ToLower(l), n) && n != "trojan" {
			t.Fatalf("label leaks tool name %q: %q", n, l)
		}
	}
}

func TestPenTestProgressOpenEnded(t *testing.T) {
	var buf bytes.Buffer
	p := newPenTestProgress(true)
	p.w = &buf
	p.Phase("crawl", "Exploring the pages of your site")
	p.Probe()
	p.Probe()
	lines := parseLines(t, buf.String())
	if len(lines) != 3 {
		t.Fatalf("got %d lines", len(lines))
	}
	if lines[0].Total != 0 || lines[2].Count != 2 || lines[2].Unit != "checks" {
		t.Fatalf("unexpected: %+v", lines)
	}
}

func TestDastStepsMonotonic(t *testing.T) {
	var buf bytes.Buffer
	r := newDastProgress(true)
	r.w = &buf
	for i := 1; i <= dastSteps; i++ {
		dastStep(r, i)
	}
	lines := parseLines(t, buf.String())
	if len(lines) != dastSteps || lines[dastSteps-1].Step != dastSteps {
		t.Fatalf("unexpected lines: %+v", lines)
	}
}
