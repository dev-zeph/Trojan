package intel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var pep508Name = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// reqName extracts the normalized project name from a PEP 508 requirement
// ("Flask[async]>=2.0; python_version>'3.8'" -> "flask").
func reqName(req string) string {
	m := pep508Name.FindStringSubmatch(req)
	if m == nil {
		return ""
	}
	return NormalizePyPIName(m[1])
}

// readPyprojectDirect returns the normalized names a pyproject.toml declares
// directly: PEP 621 [project] dependencies and optional-dependencies, PEP 735
// [dependency-groups], uv dev-dependencies, and poetry dependency tables.
func readPyprojectDirect(dir string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return out
	}
	for _, st := range readTOML(data) {
		switch {
		case st.Table == "project" && st.Key == "dependencies",
			st.Table == "project.optional-dependencies",
			st.Table == "dependency-groups",
			st.Table == "tool.uv" && st.Key == "dev-dependencies":
			for _, s := range tomlStrings(st.Raw) {
				if n := reqName(s); n != "" {
					out[n] = true
				}
			}
		case st.Table == "tool.poetry.dependencies",
			st.Table == "tool.poetry.dev-dependencies",
			strings.HasPrefix(st.Table, "tool.poetry.group.") && strings.HasSuffix(st.Table, ".dependencies"):
			if n := NormalizePyPIName(st.Key); n != "python" {
				out[n] = true
			}
		}
	}
	return out
}

// tomlLockPackage collects name/version (and source hints) of one
// [[package]] table in poetry.lock or uv.lock.
type tomlLockPackage struct {
	name, version string
	skip          bool
}

func parseTOMLPackages(data []byte, isUV bool) []tomlLockPackage {
	var out []tomlLockPackage
	cur := -1
	lastIdx := -1
	localSource := regexp.MustCompile(`\b(editable|virtual|directory|path|git)\s*=`)
	for _, st := range readTOML(data) {
		if st.Table == "package" && st.ArrayTable && st.TableIdx != lastIdx {
			out = append(out, tomlLockPackage{})
			cur = len(out) - 1
			lastIdx = st.TableIdx
		}
		if cur < 0 {
			continue
		}
		switch {
		case st.Table == "package" && st.TableIdx == lastIdx:
			switch st.Key {
			case "name":
				out[cur].name = tomlString(st.Raw)
			case "version":
				out[cur].version = tomlString(st.Raw)
			case "source":
				if isUV && localSource.MatchString(st.Raw) {
					out[cur].skip = true
				}
			}
		case st.Table == "package.source" && st.Key == "type":
			// poetry: local checkouts are the project's own code, not PyPI.
			switch tomlString(st.Raw) {
			case "directory", "git":
				out[cur].skip = true
			}
		}
	}
	return out
}

func parseTOMLLock(path, rel string, isUV bool) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(data, []byte("[[package]]")) {
		return nil, fmt.Errorf("no [[package]] tables found")
	}
	direct := readPyprojectDirect(filepath.Dir(path))
	var out []Package
	for _, lp := range parseTOMLPackages(data, isUV) {
		if lp.skip {
			continue
		}
		if p, ok := newPkg(EcosystemPyPI, lp.name, lp.version, rel, direct[NormalizePyPIName(lp.name)]); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// parsePoetryLock handles poetry.lock ([[package]] name/version).
func parsePoetryLock(path, rel string) ([]Package, error) { return parseTOMLLock(path, rel, false) }

// parseUVLock handles uv.lock ([[package]] name/version; the project itself
// and other editable/virtual/path sources are skipped).
func parseUVLock(path, rel string) ([]Package, error) { return parseTOMLLock(path, rel, true) }

// parsePipfileLock handles Pipfile.lock: {"default": {name: {"version":
// "==x"}}, "develop": {...}}. Direct deps come from the sibling Pipfile.
func parsePipfileLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	direct := map[string]bool{}
	if pf, err := os.ReadFile(filepath.Join(filepath.Dir(path), "Pipfile")); err == nil {
		for _, st := range readTOML(pf) {
			if st.Table == "packages" || st.Table == "dev-packages" {
				direct[NormalizePyPIName(st.Key)] = true
			}
		}
	}
	var out []Package
	for _, section := range []string{"default", "develop"} {
		raw, ok := lock[section]
		if !ok {
			continue
		}
		var entries map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("invalid %q section: %w", section, err)
		}
		for name, e := range entries {
			v := strings.TrimSpace(e.Version)
			if !strings.HasPrefix(v, "==") {
				continue // git/path entries have no pinned version
			}
			v = strings.TrimPrefix(strings.TrimPrefix(v, "=="), "=")
			if p, ok := newPkg(EcosystemPyPI, name, v, rel, direct[NormalizePyPIName(name)]); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

var reqPinRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)\s*$`)

// parseRequirements handles requirements*.txt. Only exact pins
// ("name==1.2.3", "name[extra]==1.2.3 ; marker", "name===1.2.3") are kept;
// ranges, URLs, VCS links, -e/-r/-c options and wildcards ("==1.*") are
// ignored. A pin is direct unless pip-compile's "# via" annotation names
// only other packages (via "-r file" or no annotation means direct).
func parseRequirements(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type pin struct {
		name, version string
		via           []string
	}
	var pins []pin
	inVia := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	cont := false
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		wasCont := cont
		cont = strings.HasSuffix(line, `\`)
		if wasCont {
			continue // --hash continuation lines
		}
		if strings.HasPrefix(line, "#") {
			c := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if len(pins) > 0 && (raw != line) { // indented comment under a pin
				switch {
				case strings.HasPrefix(c, "via "):
					pins[len(pins)-1].via = append(pins[len(pins)-1].via, strings.TrimSpace(c[4:]))
					inVia = true
				case c == "via":
					inVia = true
				case inVia && c != "":
					pins[len(pins)-1].via = append(pins[len(pins)-1].via, c)
				}
			}
			continue
		}
		inVia = false
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, `\`))
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i]) // environment marker
		}
		// Drop trailing options such as --hash=... on the same line.
		if i := strings.Index(line, " --"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := reqPinRe.FindStringSubmatch(line)
		if m == nil || strings.Contains(m[2], "*") {
			continue
		}
		pins = append(pins, pin{name: m[1], version: m[2]})
	}
	var out []Package
	for _, p := range pins {
		direct := len(p.via) == 0
		for _, v := range p.via {
			if strings.HasPrefix(v, "-r ") {
				direct = true
			}
		}
		if pk, ok := newPkg(EcosystemPyPI, p.name, p.version, rel, direct); ok {
			out = append(out, pk)
		}
	}
	return out, nil
}
