package intel

import (
	"sort"
	"strings"
)

// MatchAdvisories decides, locally and by exact installed version, which
// packages each advisory applies to. It is pure (no I/O) so callers can
// re-check a single package after an upgrade. Advisories are matched to
// packages by ecosystem and normalized name; the same advisory can match
// several installed versions of one package. Results are sorted by
// severity (critical first), then malicious before other kinds, then direct
// before transitive, then package name and advisory ID.
func MatchAdvisories(pkgs []Package, advs []Advisory) []Match {
	byPkg := map[string][]int{}
	for i, a := range advs {
		k := normEcosystem(a.Ecosystem) + "\x00" + normName(a.Ecosystem, a.Package)
		byPkg[k] = append(byPkg[k], i)
	}
	seen := map[string]bool{}
	var out []Match
	for _, p := range pkgs {
		eco := normEcosystem(p.Ecosystem)
		for _, i := range byPkg[eco+"\x00"+normName(eco, p.Name)] {
			a := advs[i]
			ok, fix := a.AffectsVersion(p.Version)
			if !ok {
				continue
			}
			id := MatchID(a.ID, eco, p.Name, p.Version)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, Match{
				ID:               id,
				Package:          p.Name,
				InstalledVersion: p.Version,
				Ecosystem:        eco,
				Lockfile:         p.Lockfile,
				Lockfiles:        p.Lockfiles,
				Direct:           p.Direct,
				Advisory:         a,
				FixedVersion:     fix,
				Severity:         normSeverity(a.Severity),
				Kind:             strings.ToLower(a.Kind),
				ProofAvailable:   a.PlaybookID != nil && *a.PlaybookID != "",
				Status:           StatusMatchedUnproven,
			})
		}
	}
	SortMatches(out)
	return out
}

// SortMatches orders matches critical→low, malicious first, direct first.
func SortMatches(ms []Match) {
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if ma, mb := a.Kind == "malicious", b.Kind == "malicious"; ma != mb {
			return ma
		}
		if a.Direct != b.Direct {
			return a.Direct
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.InstalledVersion != b.InstalledVersion {
			return a.InstalledVersion < b.InstalledVersion
		}
		return a.Advisory.ID < b.Advisory.ID
	})
}

// normSeverity lowercases and folds GHSA's "moderate" into "medium".
func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "moderate" {
		return "medium"
	}
	return s
}

func severityRank(s string) int {
	switch normSeverity(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
