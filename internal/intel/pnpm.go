package intel

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmPkgEntry struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Packages        map[string]pnpmPkgEntry `yaml:"packages"`
	Snapshots       map[string]yaml.Node    `yaml:"snapshots"`

	// Single-project lockfiles (pre-v9, no workspace) keep importer fields at
	// the top level.
	pnpmImporter `yaml:",inline"`
}

// pnpmImporter's dependency maps hold either "1.2.3" (v5) or
// {specifier, version} (v6+), so they are decoded as raw nodes.
type pnpmImporter struct {
	Dependencies         map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
}

// directVersions returns name -> resolved version (peer suffix stripped).
func (im pnpmImporter) directVersions(into map[string]map[string]bool) {
	for _, block := range []map[string]yaml.Node{im.Dependencies, im.DevDependencies, im.OptionalDependencies} {
		for name, n := range block {
			var v string
			switch n.Kind {
			case yaml.ScalarNode:
				v = n.Value
			case yaml.MappingNode:
				var obj struct {
					Version string `yaml:"version"`
				}
				if n.Decode(&obj) == nil {
					v = obj.Version
				}
			}
			v = stripPNPMPeers(v)
			if into[name] == nil {
				into[name] = map[string]bool{}
			}
			into[name][v] = true
		}
	}
}

// stripPNPMPeers removes peer-dependency suffixes: "1.0.0(react@18.2.0)"
// (v6+) and "1.0.0_react@18.2.0" (v5).
func stripPNPMPeers(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '_'); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// parsePNPMKey extracts name and version from a pnpm packages/snapshots key:
//
//	v5:  /name/1.0.0, /@scope/name/1.0.0_peer@1
//	v6:  /name@1.0.0, /@scope/name@1.0.0(peer@1)
//	v9:  name@1.0.0,  @scope/name@1.0.0(peer@1)
func parsePNPMKey(key string, slashFormat bool) (name, version string) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(k, '('); i >= 0 {
		k = k[:i]
	}
	if slashFormat {
		if i := strings.IndexByte(k, '_'); i >= 0 {
			k = k[:i]
		}
		i := strings.LastIndexByte(k, '/')
		if i <= 0 {
			return "", ""
		}
		return k[:i], k[i+1:]
	}
	return splitNameVersion(k)
}

// parsePNPMLock handles pnpm-lock.yaml v5 through v9. Importers (or the
// top-level dependency blocks of single-project lockfiles) mark direct deps.
func parsePNPMLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	major := 0
	switch v := lock.LockfileVersion.(type) {
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		major = int(f)
	case int:
		major = v
	case float64:
		major = int(v)
	}
	slashFormat := major > 0 && major < 6

	direct := map[string]map[string]bool{}
	lock.pnpmImporter.directVersions(direct)
	for _, im := range lock.Importers {
		im.directVersions(direct)
	}

	var out []Package
	add := func(key, name, version string) {
		if name == "" || version == "" {
			n, v := parsePNPMKey(key, slashFormat)
			if name == "" {
				name = n
			}
			if version == "" {
				version = v
			}
		}
		if p, ok := newPkg(EcosystemNPM, name, version, rel, direct[name][version]); ok {
			out = append(out, p)
		}
	}
	for key, e := range lock.Packages {
		add(key, e.Name, e.Version)
	}
	if len(lock.Packages) == 0 {
		for key := range lock.Snapshots {
			add(key, "", "")
		}
	}
	return out, nil
}
