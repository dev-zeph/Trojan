package normalizer

import (
	"path/filepath"
	"sort"
)

// dedupLineSpan is how many lines apart two findings on the same file and issue
// class may be before they're still treated as the same issue. Cross-scanner
// engines often report the same sink one or two lines apart (e.g. the call vs.
// the argument line), so a small span merges those without collapsing genuinely
// distinct issues in the same function.
const dedupLineSpan = 2

// Dedup collapses cross-scanner duplicate findings. Trojan runs several SAST
// engines plus Nuclei, so the dominant noise source is two scanners flagging the
// same sink (e.g. Semgrep and Bearer both reporting CWE-89 at main.go:42). Those
// collapse deterministically here — no embeddings, no LLM.
//
// Scope is deliberately conservative:
//   - Only line-anchored findings (LineNumber > 0) are considered. Line-less
//     findings (SCA/DAST/secrets reported at file scope) pass through untouched,
//     so we never merge distinct CVEs that happen to share a manifest and class.
//   - Two findings merge only when they share the same normalized file AND the
//     same issue class (primary CWE if present, else coarse Category) AND their
//     lines fall within dedupLineSpan of each other.
//
// The surviving representative is the highest-severity finding in the cluster
// (ties broken by input order for determinism). Its AgreedScanners records every
// scanner that reported the cluster — a corroboration signal fed into triage (A2).
// Output preserves the input order of the representatives.
func Dedup(findings []Finding) []Finding {
	if len(findings) < 2 {
		if len(findings) == 1 {
			findings[0].AgreedScanners = mergeScanners(nil, findings[0])
		}
		return findings
	}

	// Group anchored findings by (file, class), preserving input order within
	// each group. Line-less findings are never grouped.
	groups := map[string][]int{}
	for i, f := range findings {
		if f.LineNumber <= 0 {
			continue
		}
		k := dedupKey(f)
		groups[k] = append(groups[k], i)
	}

	absorbed := make(map[int]bool)  // indices merged away into a representative
	merged := make(map[int][]string) // rep index -> unioned scanner set

	for _, idxs := range groups {
		// Sort by line, then input order, so clustering is deterministic.
		sort.SliceStable(idxs, func(a, b int) bool {
			return findings[idxs[a]].LineNumber < findings[idxs[b]].LineNumber
		})

		c := 0
		for c < len(idxs) {
			anchor := idxs[c]
			anchorLine := findings[anchor].LineNumber
			cluster := []int{anchor}
			j := c + 1
			for j < len(idxs) && findings[idxs[j]].LineNumber-anchorLine <= dedupLineSpan {
				cluster = append(cluster, idxs[j])
				j++
			}
			c = j

			// Representative = highest severity; ties → smallest input index.
			rep := cluster[0]
			for _, idx := range cluster[1:] {
				if severityRank(findings[idx].Severity) > severityRank(findings[rep].Severity) ||
					(severityRank(findings[idx].Severity) == severityRank(findings[rep].Severity) && idx < rep) {
					rep = idx
				}
			}

			scanners := []string{}
			for _, idx := range cluster {
				scanners = mergeScanners(scanners, findings[idx])
				if idx != rep {
					absorbed[idx] = true
				}
			}
			sort.Strings(scanners)
			merged[rep] = scanners
		}
	}

	out := make([]Finding, 0, len(findings))
	for i, f := range findings {
		if absorbed[i] {
			continue
		}
		if s, ok := merged[i]; ok {
			f.AgreedScanners = s
		} else {
			f.AgreedScanners = mergeScanners(nil, f)
		}
		out = append(out, f)
	}
	return out
}

// dedupKey groups findings that could be the same issue: same normalized file
// and same issue class. Primary CWE is preferred (precise, and shared across
// engines that report the same vulnerability class); Category is the fallback
// for findings without a CWE.
func dedupKey(f Finding) string {
	class := f.Category
	if len(f.CWEIDs) > 0 {
		class = f.CWEIDs[0]
	}
	return normPath(f.FilePath) + "\x00" + class
}

func normPath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// mergeScanners returns the union of the given scanner set with a finding's own
// Scanner and any AgreedScanners it already carries, de-duplicated.
func mergeScanners(existing []string, f Finding) []string {
	seen := map[string]bool{}
	for _, s := range existing {
		seen[s] = true
	}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			existing = append(existing, s)
		}
	}
	add(f.Scanner)
	for _, s := range f.AgreedScanners {
		add(s)
	}
	return existing
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	}
	return 0
}
