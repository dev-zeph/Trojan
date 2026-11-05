package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// SnapshotRelPath is where the fingerprint taken when the context was last
// saved lives, relative to the project root.
const SnapshotRelPath = ".trojan/fingerprint.json"

// SnapshotPath returns the snapshot path for a project root.
func SnapshotPath(root string) string { return filepath.Join(root, SnapshotRelPath) }

// SaveSnapshot writes fp as the baseline later changes are compared against.
func SaveSnapshot(root string, fp Fingerprint) error {
	p := SnapshotPath(root)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// LoadSnapshot reads the saved baseline. ok is false when none exists or it
// cannot be read.
func LoadSnapshot(root string) (fp Fingerprint, ok bool) {
	data, err := os.ReadFile(SnapshotPath(root))
	if err != nil {
		return Fingerprint{}, false
	}
	if err := json.Unmarshal(data, &fp); err != nil {
		return Fingerprint{}, false
	}
	return fp, true
}

// Changes is what is new or gone in a project since the snapshot.
type Changes struct {
	RoutesAdded       []string `json:"routes_added"`
	RoutesRemoved     []string `json:"routes_removed"`
	DataStoresAdded   []string `json:"data_stores_added"`
	DataStoresRemoved []string `json:"data_stores_removed"`
	ServicesAdded     []string `json:"services_added"`
	ServicesRemoved   []string `json:"services_removed"`
}

// Empty reports whether nothing meaningful changed.
func (c Changes) Empty() bool {
	return len(c.RoutesAdded)+len(c.RoutesRemoved)+len(c.DataStoresAdded)+
		len(c.DataStoresRemoved)+len(c.ServicesAdded)+len(c.ServicesRemoved) == 0
}

// Diff compares a saved baseline to the current fingerprint. Only routes, data
// stores and outside services count; dependency churn alone is not meaningful.
func Diff(old, cur Fingerprint) Changes {
	routeKeys := func(fp Fingerprint) []string {
		out := make([]string, 0, len(fp.Routes))
		for _, r := range fp.Routes {
			out = append(out, r.Method+" "+r.Path)
		}
		return out
	}
	var c Changes
	c.RoutesAdded, c.RoutesRemoved = setDiff(routeKeys(old), routeKeys(cur))
	c.DataStoresAdded, c.DataStoresRemoved = setDiff(old.DataStores, cur.DataStores)
	c.ServicesAdded, c.ServicesRemoved = setDiff(old.ThirdParty, cur.ThirdParty)
	return c
}

// setDiff returns (in cur not old, in old not cur), sorted, never nil.
func setDiff(old, cur []string) (added, removed []string) {
	o := map[string]bool{}
	for _, s := range old {
		o[s] = true
	}
	n := map[string]bool{}
	for _, s := range cur {
		n[s] = true
	}
	added, removed = []string{}, []string{}
	for s := range n {
		if !o[s] {
			added = append(added, s)
		}
	}
	for s := range o {
		if !n[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
