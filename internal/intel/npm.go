package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// manifestDeps is the dependency block shape shared by package.json, npm
// lockfile v2 "packages" entries and bun workspaces.
type manifestDeps struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// specs returns name -> requested range across every dependency block.
func (m manifestDeps) specs() map[string]string {
	out := map[string]string{}
	for _, block := range []map[string]string{m.PeerDependencies, m.OptionalDependencies, m.DevDependencies, m.Dependencies} {
		for k, v := range block {
			out[k] = v
		}
	}
	return out
}

// readPackageJSONDeps reads the direct dependency specs of the package.json
// next to a lockfile. Missing or broken package.json yields an empty map.
func readPackageJSONDeps(dir string) map[string]string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return map[string]string{}
	}
	var m manifestDeps
	if json.Unmarshal(data, &m) != nil {
		return map[string]string{}
	}
	return m.specs()
}

type npmLockV2Entry struct {
	manifestDeps
	Name    string `json:"name"`
	Version string `json:"version"`
	Link    bool   `json:"link"`
}

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Bundled      bool                    `json:"bundled"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockV2Entry `json:"packages"`
	Dependencies    map[string]npmLockV1Dep   `json:"dependencies"`
}

// parseNPMLock handles package-lock.json / npm-shrinkwrap.json v1, v2 and v3.
// v2/v3 use the flat "packages" map (keys are install paths such as
// "node_modules/@scope/a/node_modules/b"); v1 uses the nested "dependencies"
// tree. Direct deps are the root's (and workspaces') declared dependencies
// installed at the top level of node_modules.
func parseNPMLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var out []Package

	if len(lock.Packages) > 0 {
		direct := map[string]bool{}
		for key, e := range lock.Packages {
			// The root ("") and workspace members (keys outside node_modules)
			// declare the project's direct dependencies.
			if key == "" || !strings.Contains(key, "node_modules/") {
				for name := range e.specs() {
					direct[name] = true
				}
			}
		}
		for key, e := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || e.Link {
				continue // root, workspace member, or symlink to one
			}
			installName := key[i+len("node_modules/"):]
			name := installName
			if e.Name != "" {
				name = e.Name // aliased install: "node_modules/foo" -> real package
			}
			topLevel := i == 0 || strings.HasSuffix(key[:i], "/") && !strings.Contains(key[:i], "node_modules/")
			p, ok := newPkg(EcosystemNPM, name, e.Version, rel, topLevel && direct[installName])
			if ok {
				out = append(out, p)
			}
		}
		return out, nil
	}

	// v1: nested dependencies tree.
	direct := readPackageJSONDeps(filepath.Dir(path))
	var walk func(deps map[string]npmLockV1Dep, top bool)
	walk = func(deps map[string]npmLockV1Dep, top bool) {
		for installName, d := range deps {
			name, version := installName, d.Version
			if strings.HasPrefix(version, "npm:") { // alias: "npm:real@1.2.3"
				name, version = splitNameVersion(strings.TrimPrefix(version, "npm:"))
			}
			_, isDirect := direct[installName]
			if p, ok := newPkg(EcosystemNPM, name, version, rel, top && isDirect); ok {
				out = append(out, p)
			}
			walk(d.Dependencies, false)
		}
	}
	walk(lock.Dependencies, true)
	return out, nil
}

// splitNameVersion splits "name@1.2.3" / "@scope/name@1.2.3" at the last '@'
// that isn't the scope marker.
func splitNameVersion(s string) (name, version string) {
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}
