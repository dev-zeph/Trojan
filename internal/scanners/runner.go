package scanners

import (
	"sync"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ScannerResult holds the output from a single scanner run.
type ScannerResult struct {
	Scanner  string
	Findings []normalizer.Finding
	Err      error
}

// RunAll executes the given scanners in parallel and returns all findings,
// plus the per-scanner ScannerResult for every scanner (success or failure).
// The onProgress callback is called when each scanner starts (done=false, count=0)
// and finishes (done=true, count=number of findings from that scanner).
//
// Callers that only need findings can discard the second return value with
// `_`; callers that need to distinguish "clean" from "this scanner didn't
// run" (e.g. because Trivy hit a fatal DB error) should inspect ScannerResult.Err
// for each entry — RunAll itself still drops findings from failed scanners out
// of the aggregated slice, since a failed scanner produced no reliable findings.
func RunAll(projectPath string, scanners []Scanner, onProgress func(name string, done bool, count int, err error)) ([]normalizer.Finding, []ScannerResult) {
	results := make(chan ScannerResult, len(scanners))
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			if onProgress != nil {
				onProgress(s.Name(), false, 0, nil) // scanner starting
			}

			findings, err := s.Run(projectPath)

			if onProgress != nil {
				onProgress(s.Name(), true, len(findings), err) // scanner done
			}

			results <- ScannerResult{
				Scanner:  s.Name(),
				Findings: findings,
				Err:      err,
			}
		}(s)
	}

	// Close channel once all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all findings, plus every scanner's result (success or failure)
	// so callers can tell a clean run apart from one where a scanner didn't run.
	all := []normalizer.Finding{}
	perScanner := make([]ScannerResult, 0, len(scanners))
	for result := range results {
		if result.Err == nil {
			all = append(all, result.Findings...)
		}
		perScanner = append(perScanner, result)
	}

	return all, perScanner
}

// DefaultScanners returns all available scanners that are installed on the system.
func DefaultScanners() []Scanner {
	candidates := []Scanner{
		Semgrep{},
		Bearer{},
		&Trivy{},
		Gitleaks{},
		Checkov{},
		&Syft{},
	}

	available := []Scanner{}
	for _, s := range candidates {
		if s.IsAvailable() {
			available = append(available, s)
		}
	}

	return available
}
