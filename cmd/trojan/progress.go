package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/dev-zeph/trojan/internal/config"
)

// signedInForProgress reports whether the AI check step will run (it needs a
// signed-in account), so the step total is right from the first line.
func signedInForProgress() bool {
	cfg, err := config.LoadConfig()
	return err == nil && cfg.AccessToken != ""
}

// Step progress for the desktop app.
//
// In --desktop mode the sidecar prints one machine-readable line per step:
//
//	PROGRESS {"step":3,"total":6,"key":"gitleaks","label":"Checking for leaked passwords and keys"}
//
// The desktop turns these into a "Step 3 of 6" indicator. There is deliberately
// no percentage and no time estimate. An open-ended phase (the pen test) sends
// total 0 and, optionally, a running count:
//
//	PROGRESS {"step":0,"total":0,"key":"testing","label":"Testing your site","count":14,"unit":"checks"}
//
// Outside desktop mode nothing is printed, so CLI output is unchanged.

// progressLine is the JSON payload after the PROGRESS prefix.
type progressLine struct {
	Step  int    `json:"step"`
	Total int    `json:"total"`
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count,omitempty"`
	Unit  string `json:"unit,omitempty"`
}

// stepReporter emits PROGRESS lines. It is safe for concurrent use. The step
// number never goes backwards, even when parallel scanners report out of order.
type stepReporter struct {
	mu      sync.Mutex
	w       io.Writer
	enabled bool
	total   int
	last    int
}

func newStepReporter(enabled bool, total int) *stepReporter {
	return &stepReporter{w: os.Stdout, enabled: enabled, total: total}
}

// Emit prints a step line. step is clamped to [1, total]; a step lower than the
// previously reported one is dropped.
func (r *stepReporter) Emit(step int, key, label string) {
	if r == nil || !r.enabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if step > r.total {
		step = r.total
	}
	if step < 1 {
		step = 1
	}
	if step < r.last {
		return
	}
	r.last = step
	writeProgress(r.w, progressLine{Step: step, Total: r.total, Key: key, Label: label})
}

func writeProgress(w io.Writer, p progressLine) {
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "PROGRESS %s\n", b)
}

// ---- code scan ----

// scannerLabels are the plain-language activity names, one per scanner.
var scannerLabels = map[string]string{
	"semgrep":  "Reading your code for common mistakes",
	"bearer":   "Checking how your code handles personal data",
	"trivy":    "Checking the libraries you use for known problems",
	"gitleaks": "Checking for leaked passwords and keys",
	"checkov":  "Checking your cloud and server setup files",
	"syft":     "Listing everything your app is built from",
	"trojan":   "Looking for ways attackers could chain issues together",
}

func scannerLabel(name string) string {
	if l, ok := scannerLabels[name]; ok {
		return l
	}
	return "Running more security checks"
}

// codeScanProgress tracks a code scan: Preparing, one step per scanner, an
// optional AI double-check, then Building the report.
type codeScanProgress struct {
	r        *stepReporter
	scanners int
	hasAI    bool

	mu       sync.Mutex
	finished int
	running  []string // started, not yet finished, in start order
}

// newCodeScanProgress: total = 1 (prepare) + scanners + (AI check) + 1 (report).
func newCodeScanProgress(enabled bool, scannerCount int, withAI bool) *codeScanProgress {
	total := 1 + scannerCount + 1
	if withAI {
		total++
	}
	return &codeScanProgress{r: newStepReporter(enabled, total), scanners: scannerCount, hasAI: withAI}
}

// Preparing is step 1.
func (p *codeScanProgress) Preparing() {
	p.r.Emit(1, "prepare", "Getting your project ready")
}

// ScannerEvent is the scanners.RunAll callback. Scanners run in parallel, so the
// step is "scanners finished, plus the preparing step, plus the one in flight".
// The label names a scanner that is still running.
func (p *codeScanProgress) ScannerEvent(name string, done bool, _ int, _ error) {
	p.mu.Lock()
	if done {
		p.finished++
		for i, n := range p.running {
			if n == name {
				p.running = append(p.running[:i], p.running[i+1:]...)
				break
			}
		}
	} else {
		p.running = append(p.running, name)
	}
	step := p.finished + 2
	if step > 1+p.scanners {
		step = 1 + p.scanners
	}
	key := name
	if len(p.running) > 0 {
		key = p.running[0]
	}
	p.mu.Unlock()
	p.r.Emit(step, key, scannerLabel(key))
}

// DoubleCheck is the hook for the AI check of findings. Call it right before
// that work starts. It is a no-op unless the scan was created withAI.
func (p *codeScanProgress) DoubleCheck() {
	if p == nil || !p.hasAI {
		return
	}
	p.r.Emit(1+p.scanners+1, "triage", "Double-checking findings")
}

// BuildingReport is the last step.
func (p *codeScanProgress) BuildingReport() {
	if p == nil {
		return
	}
	p.r.Emit(p.r.total, "report", "Building your report")
}

// ---- classic DAST ----

const dastSteps = 6

func newDastProgress(enabled bool) *stepReporter { return newStepReporter(enabled, dastSteps) }

var dastStepLabels = []struct{ key, label string }{
	{"reach", "Checking your site is reachable"},
	{"crawl", "Exploring the pages of your site"},
	{"templates", "Writing custom tests for your site"},
	{"nuclei", "Testing your site for known weaknesses"},
	{"review", "Double-checking and explaining what was found"},
	{"report", "Building your report"},
}

func dastStep(r *stepReporter, step int) {
	if step < 1 || step > len(dastStepLabels) {
		return
	}
	r.Emit(step, dastStepLabels[step-1].key, dastStepLabels[step-1].label)
}

// ---- agentic pen test (open-ended) ----

// penTestProgress reports a phase name, and while the agent works a running
// count of checks, instead of "step N of M".
type penTestProgress struct {
	mu      sync.Mutex
	w       io.Writer
	enabled bool
	probes  int
}

func newPenTestProgress(enabled bool) *penTestProgress {
	return &penTestProgress{w: os.Stdout, enabled: enabled}
}

func (p *penTestProgress) Phase(key, label string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	writeProgress(p.w, progressLine{Key: key, Label: label})
}

// Probe counts one request the agent sent and reports the running total.
func (p *penTestProgress) Probe() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probes++
	writeProgress(p.w, progressLine{Key: "testing", Label: "Testing your site", Count: p.probes, Unit: "checks"})
}
