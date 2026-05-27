package scanners

import (
	"sync"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// DastScanner is the interface for dynamic application security testing.
// Unlike Scanner, it targets a running URL rather than a file system path.
type DastScanner interface {
	Name() string
	Category() string
	Run(targetURL string) ([]normalizer.Finding, error)
	IsAvailable() bool
}

// DastResult holds the output from a single DAST scanner run.
type DastResult struct {
	Scanner  string
	Findings []normalizer.Finding
	Err      error
}

// RunDast executes the given DAST scanners in parallel against the target URL.
// onProgress mirrors the same contract as RunAll — called when each scanner starts and finishes.
func RunDast(targetURL string, dastScanners []DastScanner, onProgress func(name string, done bool, err error)) []normalizer.Finding {
	results := make(chan DastResult, len(dastScanners))
	var wg sync.WaitGroup

	for _, s := range dastScanners {
		wg.Add(1)
		go func(s DastScanner) {
			defer wg.Done()

			if onProgress != nil {
				onProgress(s.Name(), false, nil)
			}

			findings, err := s.Run(targetURL)

			if onProgress != nil {
				onProgress(s.Name(), true, err)
			}

			results <- DastResult{
				Scanner:  s.Name(),
				Findings: findings,
				Err:      err,
			}
		}(s)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	all := []normalizer.Finding{}
	for result := range results {
		if result.Err == nil {
			all = append(all, result.Findings...)
		}
	}

	return all
}

// DefaultDastScanners returns all available DAST scanners that are installed.
func DefaultDastScanners() []DastScanner {
	candidates := []DastScanner{
		Nuclei{},
	}

	available := []DastScanner{}
	for _, s := range candidates {
		if s.IsAvailable() {
			available = append(available, s)
		}
	}

	return available
}
