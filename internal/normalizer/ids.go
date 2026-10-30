package normalizer

import "strconv"

// EnsureUniqueIDs gives every finding a distinct, non-empty ID, in place.
// Triage verdicts are keyed by finding ID, so two findings sharing an ID (or
// both having none) would receive the same verdict. The first occurrence keeps
// its ID; later duplicates get a "-2", "-3", ... suffix, and an empty ID becomes
// "finding-<index>". Returns how many IDs were changed.
func EnsureUniqueIDs(findings []Finding) int {
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			seen[f.ID] = false // reserve every original ID before renaming
		}
	}
	taken := make(map[string]bool, len(findings))
	changed := 0
	for i := range findings {
		id := findings[i].ID
		if id == "" {
			id = "finding-" + strconv.Itoa(i)
		}
		base := id
		for n := 2; taken[id] || (id != findings[i].ID && hasKey(seen, id)); n++ {
			id = base + "-" + strconv.Itoa(n)
		}
		if id != findings[i].ID {
			findings[i].ID = id
			changed++
		}
		taken[id] = true
	}
	return changed
}

func hasKey(m map[string]bool, k string) bool {
	_, ok := m[k]
	return ok
}
