package normalizer

// ReduceStats reports what the deterministic noise-reduction pass removed, so it
// can be surfaced to the user rather than silently dropping findings.
type ReduceStats struct {
	DroppedNonShipping int // findings removed for living in dep/build/test/generated code
	MergedDuplicates   int // findings collapsed into a cross-scanner representative
}

// Any reports whether the pass changed anything.
func (s ReduceStats) Any() bool { return s.DroppedNonShipping > 0 || s.MergedDuplicates > 0 }

// Reduce runs the deterministic false-positive/noise reduction pass over raw
// scanner output: it drops findings in non-shipping code (dependencies, build
// output, generated, and test files — A3) and collapses cross-scanner duplicates
// into a single representative that records which engines agreed (A1). No LLM,
// no network — this is the free floor beneath AI triage.
//
// Path filtering runs first so duplicate-merging only considers findings that
// survive. The returned stats describe what was removed.
func Reduce(findings []Finding) ([]Finding, ReduceStats) {
	kept, dropped := FilterPaths(findings)
	before := len(kept)
	kept = Dedup(kept)
	return kept, ReduceStats{
		DroppedNonShipping: dropped,
		MergedDuplicates:   before - len(kept),
	}
}
