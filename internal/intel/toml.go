package intel

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// tomlStmt is one key/value statement from a TOML file, tagged with the
// table it belongs to. This is a deliberately small reader for the shapes
// poetry.lock, uv.lock, pyproject.toml and Pipfile use; it is not a general
// TOML parser (no dotted-key expansion, values are kept raw).
type tomlStmt struct {
	Table      string // e.g. "package", "tool.poetry.dependencies"
	ArrayTable bool   // the table header was [[...]]
	TableIdx   int    // increments on every table header (separates [[package]] entries)
	Key        string // unquoted
	Raw        string // raw value text, possibly spanning lines
}

// readTOML splits TOML into statements. Multi-line arrays, inline tables and
// triple-quoted strings are folded into a single statement's Raw value.
func readTOML(data []byte) []tomlStmt {
	var out []tomlStmt
	table, arrayTable, idx := "", false, 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var pending *tomlStmt
	depth := 0
	triple := ""
	for sc.Scan() {
		line := sc.Text()
		if pending != nil {
			pending.Raw += "\n" + line
			if triple != "" {
				if strings.Contains(line, triple) {
					triple = ""
					out = append(out, *pending)
					pending = nil
				}
				continue
			}
			depth += bracketDelta(line)
			if depth <= 0 {
				out = append(out, *pending)
				pending = nil
				depth = 0
			}
			continue
		}
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") {
			arrayTable = strings.HasPrefix(t, "[[")
			h := strings.TrimSpace(stripTOMLComment(t))
			h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
			if arrayTable {
				h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
			}
			table = unquoteTOMLKey(strings.TrimSpace(h))
			idx++
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		st := tomlStmt{Table: table, ArrayTable: arrayTable, TableIdx: idx,
			Key: unquoteTOMLKey(strings.TrimSpace(t[:eq])), Raw: strings.TrimSpace(t[eq+1:])}
		for _, q := range []string{`"""`, `'''`} {
			if strings.HasPrefix(st.Raw, q) && strings.Count(st.Raw, q) == 1 {
				triple = q
			}
		}
		if triple != "" {
			pending = &st
			continue
		}
		if d := bracketDelta(st.Raw); d > 0 {
			depth = d
			pending = &st
			continue
		}
		out = append(out, st)
	}
	if pending != nil {
		out = append(out, *pending)
	}
	return out
}

// bracketDelta counts [ and { minus ] and } outside strings and comments.
func bracketDelta(s string) int {
	d := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			q = c
		case '#':
			return d
		case '[', '{':
			d++
		case ']', '}':
			d--
		}
	}
	return d
}

func stripTOMLComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == q {
				q = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			q = c
		} else if c == '#' {
			return s[:i]
		}
	}
	return s
}

func unquoteTOMLKey(k string) string {
	if len(k) >= 2 && (k[0] == '"' && k[len(k)-1] == '"' || k[0] == '\'' && k[len(k)-1] == '\'') {
		return k[1 : len(k)-1]
	}
	// quoted segments inside dotted table names: tool.poetry."group".x
	return strings.ReplaceAll(strings.ReplaceAll(k, `"`, ""), `'`, "")
}

var tomlStringRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'`)

// tomlString returns the first string literal in a raw value.
func tomlString(raw string) string {
	m := tomlStringRe.FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return strings.ReplaceAll(m[1], `\"`, `"`)
	}
	return m[2]
}

// tomlStrings returns every string literal in a raw value (array elements).
func tomlStrings(raw string) []string {
	var out []string
	for _, m := range tomlStringRe.FindAllStringSubmatch(stripArrayComments(raw), -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

func stripArrayComments(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		lines[i] = stripTOMLComment(l)
	}
	return strings.Join(lines, "\n")
}
