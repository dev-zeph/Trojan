package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type bunLock struct {
	Workspaces map[string]manifestDeps      `json:"workspaces"`
	Packages   map[string][]json.RawMessage `json:"packages"`
}

// parseBunLock handles the text bun.lock (Bun >= 1.2): JSONC with trailing
// commas. Each "packages" value is an array whose first element is the
// resolved "name@version". Keys are install paths: "react" is top-level,
// "parent/child" is nested. The binary bun.lockb is not supported.
func parseBunLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock bunLock
	if err := json.Unmarshal(jsoncToJSON(data), &lock); err != nil {
		return nil, fmt.Errorf("invalid bun.lock: %w", err)
	}
	direct := map[string]bool{}
	for _, ws := range lock.Workspaces {
		for name := range ws.specs() {
			direct[name] = true
		}
	}
	var out []Package
	for key, arr := range lock.Packages {
		if len(arr) == 0 {
			continue
		}
		var ident string
		if json.Unmarshal(arr[0], &ident) != nil {
			continue
		}
		name, version := splitNameVersion(ident)
		if strings.HasPrefix(version, "npm:") { // alias form
			name, version = splitNameVersion(strings.TrimPrefix(version, "npm:"))
		}
		isDirect := direct[key] && !isNestedBunKey(key)
		if p, ok := newPkg(EcosystemNPM, name, version, rel, isDirect); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// isNestedBunKey reports whether a bun.lock package key is a nested install
// ("parent/child", "@s/parent/child") rather than a top-level name.
func isNestedBunKey(key string) bool {
	n := strings.Count(key, "/")
	if strings.HasPrefix(key, "@") {
		return n > 1
	}
	return n > 0
}

// jsoncToJSON strips // and /* */ comments and trailing commas outside of
// strings, turning JSONC into strict JSON.
func jsoncToJSON(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			// Drop the comma if the next significant byte closes a container.
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
