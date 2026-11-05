package intel

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseYarnLock handles yarn.lock in both the classic v1 text format and
// the yarn berry (v2+) YAML format. Direct deps are entries whose header
// includes the exact "name@range" requested by the sibling package.json.
func parseYarnLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	direct := readPackageJSONDeps(filepath.Dir(path))
	if bytes.Contains(data, []byte("\n__metadata:")) || bytes.HasPrefix(data, []byte("__metadata:")) {
		return parseYarnBerry(data, rel, direct)
	}
	return parseYarnClassic(data, rel, direct), nil
}

// yarnSpecIsDirect reports whether a header spec ("name@^1", "name@npm:^1")
// is the exact range package.json asks for.
func yarnSpecIsDirect(spec string, direct map[string]string) bool {
	name, rng := splitYarnSpec(spec)
	want, ok := direct[name]
	if !ok {
		return false
	}
	return rng == want || rng == "npm:"+want || strings.TrimPrefix(rng, "npm:") == strings.TrimPrefix(want, "npm:")
}

// splitYarnSpec splits "name@range" at the first '@' after a scope marker;
// the range itself may contain '@' ("foo@npm:bar@^1").
func splitYarnSpec(spec string) (name, rng string) {
	if len(spec) < 2 {
		return spec, ""
	}
	i := strings.IndexByte(spec[1:], '@')
	if i < 0 {
		return spec, ""
	}
	return spec[:i+1], spec[i+2:]
}

// isNonRegistryRange reports whether a requested range points at code that
// isn't a registry package (git, tarball URL, local path, workspace).
func isNonRegistryRange(rng string) bool {
	if strings.Contains(rng, "://") {
		return true
	}
	for _, p := range []string{"git", "github:", "gitlab:", "bitbucket:", "file:", "link:", "workspace:", "portal:", "./", "../", "/"} {
		if strings.HasPrefix(rng, p) {
			return true
		}
	}
	return false
}

func splitYarnHeader(h string) []string {
	h = strings.TrimSuffix(strings.TrimSpace(h), ":")
	var specs []string
	for _, s := range strings.Split(h, ",") {
		s = strings.Trim(strings.TrimSpace(s), `"`)
		if s != "" {
			specs = append(specs, s)
		}
	}
	return specs
}

// parseYarnClassic parses the v1 format:
//
//	"@babel/core@^7.0.0", "@babel/core@^7.1.0":
//	  version "7.1.2"
func parseYarnClassic(data []byte, rel string, direct map[string]string) []Package {
	var out []Package
	var specs []string
	flush := func(version string) {
		if len(specs) == 0 || version == "" {
			return
		}
		name, rng := splitYarnSpec(specs[0])
		if isNonRegistryRange(rng) {
			return
		}
		isDirect := false
		for _, s := range specs {
			if yarnSpecIsDirect(s, direct) {
				isDirect = true
			}
		}
		// Alias header: "foo@npm:bar@^1" installs bar.
		if strings.HasPrefix(rng, "npm:") && strings.LastIndex(rng, "@") > 4 {
			name, _ = splitNameVersion(rng[4:])
		}
		if p, ok := newPkg(EcosystemNPM, name, version, rel, isDirect); ok {
			out = append(out, p)
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	gotVersion := false
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			specs = splitYarnHeader(line)
			gotVersion = false
			continue
		}
		// Only the entry's own two-space-indented "version" line counts, not
		// one nested under dependencies.
		if !gotVersion && strings.HasPrefix(line, "  version ") && !strings.HasPrefix(line, "   ") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "  version ")), `"`)
			flush(v)
			gotVersion = true
		}
	}
	return out
}

type yarnBerryEntry struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
}

// parseYarnBerry parses the v2+ format:
//
//	"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
//	  version: 4.17.21
//	  resolution: "lodash@npm:4.17.21"
//
// Only registry packages ("@npm:" resolutions, and "@patch:" of them) are
// kept; workspace:, link:, portal:, file: and git resolutions are local code.
func parseYarnBerry(data []byte, rel string, direct map[string]string) ([]Package, error) {
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid yarn berry lockfile: %w", err)
	}
	var out []Package
	for header, node := range doc {
		if header == "__metadata" {
			continue
		}
		var e yarnBerryEntry
		if node.Decode(&e) != nil || e.Version == "" {
			continue
		}
		var name string
		switch {
		case strings.Contains(e.Resolution, "@npm:"):
			name = e.Resolution[:strings.Index(e.Resolution[1:], "@npm:")+1]
		case strings.Contains(e.Resolution, "@patch:"):
			name = e.Resolution[:strings.Index(e.Resolution[1:], "@patch:")+1]
			if !strings.Contains(e.Resolution, "npm%3A") {
				continue
			}
		default:
			continue
		}
		isDirect := false
		for _, s := range splitYarnHeader(header) {
			if yarnSpecIsDirect(s, direct) {
				isDirect = true
			}
		}
		if p, ok := newPkg(EcosystemNPM, name, e.Version, rel, isDirect); ok {
			out = append(out, p)
		}
	}
	return out, nil
}
