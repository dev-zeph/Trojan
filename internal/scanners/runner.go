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

// RunAll executes the given scanners in parallel and returns all findings.
// The onProgress callback is called when each scanner starts and finishes —
// this is what the spinner in Phase 2 will hook into.
func RunAll(projectPath string, scanners []Scanner, onProgress func(name string, done bool, err error)) []normalizer.Finding {
	results := make(chan ScannerResult, len(scanners))
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			if onProgress != nil {
				onProgress(s.Name(), false, nil) // scanner starting
			}

			findings, err := s.Run(projectPath)

			if onProgress != nil {
				onProgress(s.Name(), true, err) // scanner done
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

	// Collect all findings
	all := []normalizer.Finding{}
	for result := range results {
		if result.Err == nil {
			all = append(all, result.Findings...)
		}
	}

	return all
}

// DefaultScanners returns all available scanners that are installed on the system.
func DefaultScanners() []Scanner {
	candidates := []Scanner{
		Semgrep{},
		Trivy{},
		Gitleaks{},
		Checkov{},
		Syft{},
	}

	available := []Scanner{}
	for _, s := range candidates {
		if s.IsAvailable() {
			available = append(available, s)
		}
	}

	return available
}
