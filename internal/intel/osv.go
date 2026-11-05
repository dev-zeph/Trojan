package intel

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// Range is one OSV affected range: {"type": "SEMVER"|"ECOSYSTEM"|"GIT",
// "events": [...]}.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one OSV range event. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

func (e Event) version() string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// Ranges is a list of OSV ranges. It unmarshals leniently: null, a single
// range object, or an array are all accepted.
type Ranges []Range

func (r *Ranges) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*r = nil
		return nil
	}
	if b[0] == '{' {
		var one Range
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*r = Ranges{one}
		return nil
	}
	var many []Range
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*r = many
	return nil
}

// versionCmp compares two versions of one ecosystem. ok=false when either
// version can't be parsed.
type versionCmp func(a, b string) (c int, ok bool)

// comparatorFor returns the version ordering for an ecosystem: SemVer for npm,
// PEP 440 for PyPI. Unknown ecosystems try SemVer.
func comparatorFor(ecosystem string) versionCmp {
	if normEcosystem(ecosystem) == EcosystemPyPI {
		return func(a, b string) (int, bool) {
			x, err1 := parsePEP440(a)
			y, err2 := parsePEP440(b)
			if err1 != nil || err2 != nil {
				return 0, false
			}
			return comparePEP440(x, y), true
		}
	}
	return func(a, b string) (int, bool) {
		x, err1 := parseSemver(a)
		y, err2 := parseSemver(b)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return compareSemver(x, y), true
	}
}

// CompareVersions orders two versions of the given ecosystem ("npm" uses
// SemVer 2.0 precedence, "pypi" uses PEP 440). ok is false if either version
// doesn't parse. The prove path uses it to check installed >= fixed.
func CompareVersions(ecosystem, a, b string) (c int, ok bool) {
	return comparatorFor(ecosystem)(a, b)
}

// rangeAffects evaluates one OSV range against version and reports whether it
// is affected and, if so, the fixed version that closes the matching interval
// ("" when the interval is open-ended or closed by last_affected).
//
// Semantics follow the OSV spec's reference algorithm: events are sorted by
// version ("introduced: 0" first) and walked in order; introduced <= v opens
// an affected interval, fixed <= v closes it, last_affected < v closes it.
// Two deliberate leniencies, both biased toward not missing a vulnerability:
//   - a range with fixed/last_affected events but no introduced event is
//     treated as if it started with introduced "0";
//   - if any event version fails to parse, the events are walked in their
//     original order and unparseable events are skipped.
//
// GIT ranges (commit hashes) can't be evaluated against an installed version
// and never match.
func rangeAffects(r Range, version string, cmp versionCmp) (affected bool, fixed string) {
	if strings.EqualFold(r.Type, "GIT") || len(r.Events) == 0 {
		return false, ""
	}
	evs := make([]Event, 0, len(r.Events)+1)
	hasIntro := false
	for _, e := range r.Events {
		if e.Introduced != "" {
			hasIntro = true
		}
		if e.version() == "" || (e.Limit != "" && e.Introduced == "" && e.Fixed == "" && e.LastAffected == "") {
			continue // limit events only bound GIT ranges
		}
		evs = append(evs, e)
	}
	if len(evs) == 0 {
		return false, ""
	}
	if !hasIntro {
		evs = append([]Event{{Introduced: "0"}}, evs...)
	}

	sortable := true
	for _, e := range evs {
		if e.Introduced == "0" {
			continue
		}
		if _, ok := cmp(e.version(), e.version()); !ok {
			sortable = false
			break
		}
	}
	if sortable {
		sort.SliceStable(evs, func(i, j int) bool {
			a, b := evs[i], evs[j]
			if a.Introduced == "0" || b.Introduced == "0" {
				return a.Introduced == "0" && b.Introduced != "0"
			}
			c, _ := cmp(a.version(), b.version())
			return c < 0
		})
	}

	affected = false
	pendingFix := ""
	for i, e := range evs {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" {
				affected = true
			} else if c, ok := cmp(version, e.Introduced); ok && c >= 0 {
				affected = true
			} else {
				continue
			}
			pendingFix = nextFixed(evs[i+1:])
		case e.Fixed != "":
			if c, ok := cmp(version, e.Fixed); ok && c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if c, ok := cmp(version, e.LastAffected); ok && c > 0 {
				affected = false
			}
		}
	}
	if !affected {
		return false, ""
	}
	return true, pendingFix
}

// nextFixed returns the first fixed event before the next introduced event.
func nextFixed(evs []Event) string {
	for _, e := range evs {
		if e.Introduced != "" {
			return ""
		}
		if e.Fixed != "" {
			return e.Fixed
		}
		if e.LastAffected != "" {
			return ""
		}
	}
	return ""
}

// AffectsVersion reports whether the advisory applies to version, and the
// fixed version for that installed line ("" if unknown or not fixed yet).
//
// Order of evidence: an exact hit in affected_versions; then the OSV ranges;
// then, if the advisory has neither ranges nor versions, "version < fixed_version"
// when a fixed version exists. An advisory with no version data never matches.
func (a Advisory) AffectsVersion(version string) (bool, string) {
	cmp := comparatorFor(a.Ecosystem)
	fallbackFix := ""
	if a.FixedVersion != nil {
		fallbackFix = *a.FixedVersion
	}

	for _, av := range a.AffectedVersions {
		if versionsEqual(cmp, av, version) {
			if f := a.fixForVersion(version, cmp); f != "" {
				return true, f
			}
			return true, fallbackFix
		}
	}
	for _, r := range a.AffectedRanges {
		if ok, fix := rangeAffects(r, version, cmp); ok {
			if fix == "" {
				fix = fallbackFix
			}
			return true, fix
		}
	}
	if len(a.AffectedRanges) == 0 && len(a.AffectedVersions) == 0 {
		if fallbackFix != "" {
			if c, ok := cmp(version, fallbackFix); ok && c < 0 {
				return true, fallbackFix
			}
			return false, ""
		}
		// No version data at all: never assume a hit. Telling a user a package
		// is malicious on no evidence is the false positive intel must avoid.
		// A wholly malicious package (typosquat) is ingested as an OSV range
		// introduced "0", which the range loop above already matches.
	}
	return false, ""
}

// fixForVersion finds the range-specific fix for a version hit via
// affected_versions (ranges may also cover it).
func (a Advisory) fixForVersion(version string, cmp versionCmp) string {
	for _, r := range a.AffectedRanges {
		if ok, fix := rangeAffects(r, version, cmp); ok && fix != "" {
			return fix
		}
	}
	return ""
}

func versionsEqual(cmp versionCmp, a, b string) bool {
	if c, ok := cmp(a, b); ok {
		return c == 0
	}
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}
