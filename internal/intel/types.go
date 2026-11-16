package intel

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// Ecosystem identifiers (always lowercase on our side; the server may send
// OSV spellings like "PyPI", which normEcosystem folds).
const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "pypi"
)

// StatusMatchedUnproven is the only status the matcher assigns: the installed
// version falls in an advisory's affected range, but nothing has shown the
// vulnerable code is reachable or exploitable yet.
const StatusMatchedUnproven = "matched_unproven"

// Package is one installed package version found in a lockfile.
type Package struct {
	Ecosystem string `json:"ecosystem"` // "npm" | "pypi"
	Name      string `json:"name"`      // npm: as published; pypi: PEP 503 normalized
	Version   string `json:"version"`   // exact installed version
	Lockfile  string `json:"lockfile"`  // first lockfile it was found in, relative to the project root (slash-separated)
	// Lockfiles lists every lockfile containing this exact version (monorepos).
	Lockfiles []string `json:"lockfiles,omitempty"`
	// Direct is true when a manifest/importer depends on it directly (not only
	// transitively). OR'd across lockfiles.
	Direct bool `json:"direct"`
}

func (p Package) key() string { return p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version }

// Advisory is one advisory row returned by the intel edge function, scoped to
// a single (ecosystem, package).
type Advisory struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"` // e.g. "osv", "ghsa"
	Kind             string   `json:"kind"`   // e.g. "vulnerability", "malicious"
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	AffectedRanges   Ranges   `json:"affected_ranges"`
	AffectedVersions []string `json:"affected_versions"`
	FixedVersion     *string  `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Summary          string   `json:"summary"`
	Details          *string  `json:"details"`
	Aliases          []string `json:"aliases"`
	Refs             Refs     `json:"refs"`
	PublishedAt      string   `json:"published_at"`
	UpdatedAt        string   `json:"updated_at"`
	// PlaybookID is the Attack Market template slug that can prove this
	// advisory against the running app; nil when no proof exists yet.
	PlaybookID *string `json:"playbook_id"`
}

// Ref is an advisory reference link.
type Ref struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// Refs unmarshals leniently: an array of {type,url} objects, an array of URL
// strings, or null.
type Refs []Ref

func (r *Refs) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*r = nil
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := make(Refs, 0, len(raw))
	for _, item := range raw {
		var s string
		if json.Unmarshal(item, &s) == nil {
			out = append(out, Ref{URL: s})
			continue
		}
		var ref Ref
		if err := json.Unmarshal(item, &ref); err != nil {
			return err
		}
		out = append(out, ref)
	}
	*r = out
	return nil
}

// Match is one installed package version that falls inside an advisory.
type Match struct {
	// ID is stable across runs: advisoryID|ecosystem|name@version.
	ID               string   `json:"id"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	Ecosystem        string   `json:"ecosystem"`
	Lockfile         string   `json:"lockfile"`
	Lockfiles        []string `json:"lockfiles,omitempty"`
	Direct           bool     `json:"direct"`
	Advisory         Advisory `json:"advisory"`
	// FixedVersion is the fix for the installed release line when the ranges
	// say so (e.g. 14.2.25 for a 14.x install), else the advisory's
	// fixed_version; "" when no fix is known.
	FixedVersion string `json:"fixed_version"`
	Severity     string `json:"severity"`
	Kind         string `json:"kind"`
	// ProofAvailable is true when an Attack Market playbook can prove it.
	ProofAvailable bool   `json:"proof_available"`
	Status         string `json:"status"`
}

// MatchID builds the stable Match.ID.
func MatchID(advisoryID, ecosystem, name, version string) string {
	return advisoryID + "|" + ecosystem + "|" + name + "@" + version
}

var pep503Sep = regexp.MustCompile(`[-_.]+`)

// NormalizePyPIName applies PEP 503 name normalization ("Foo_Bar.baz" -> "foo-bar-baz").
func NormalizePyPIName(name string) string {
	return pep503Sep.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

func normEcosystem(e string) string {
	switch strings.ToLower(strings.TrimSpace(e)) {
	case "pypi", "pip", "python":
		return EcosystemPyPI
	case "npm", "node", "javascript":
		return EcosystemNPM
	}
	return strings.ToLower(strings.TrimSpace(e))
}

// normName normalizes a package name for matching in an ecosystem.
func normName(ecosystem, name string) string {
	if normEcosystem(ecosystem) == EcosystemPyPI {
		return NormalizePyPIName(name)
	}
	return strings.ToLower(strings.TrimSpace(name))
}
