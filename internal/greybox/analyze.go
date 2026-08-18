package greybox

import (
	"regexp"
	"sort"
	"strings"
)

// The structural analysis is deliberately heuristic (regex over source text) —
// its job is to PRIME the agent's hypotheses cheaply, not to be a static
// analyzer. Every signal the agent acts on is runtime-verified against the live
// target, so a false read costs a probe, not a wrong finding (§6.6 honest limits).
// These are case-insensitive substring signals (prefix tokens like "sanitiz"
// intentionally match "sanitize"/"sanitizer"), not anchored words — heuristics,
// not a parser.
var (
	authRe = regexp.MustCompile(`(?i)(require[_]?auth|is[_]?admin|login_required|get_?session|verify_?token|current_?user|req\.user|ctx\.user|authoriz|authenticat|\bjwt\b|\bbearer\b|has[_]?permission|check[_]?role)`)

	sanitizeRe = regexp.MustCompile(`(?i)(sanitiz|escape|bleach|validat|parameteriz|prepared|bind[_]?param|placeholder|\bzod\b|\bjoi\b|pydantic|htmlspecialchars)`)

	// A SQL verb near string concatenation / interpolation — the raw-query smell.
	sqlVerbRe = regexp.MustCompile(`(?i)\b(select|insert|update|delete|drop)\b`)
	concatRe  = regexp.MustCompile("(\\+\\s*['\"`])|(['\"`]\\s*\\+)|(\\$\\{)|(%s|%d)|(f['\"])|(\\.format\\()|(\\|\\|)")

	reflectRe = regexp.MustCompile(`(?i)(res\.send|res\.write|res\.end|innerhtml|dangerouslysetinnerhtml|\.write\(|document\.write|render_template_string)`)

	callRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_.]*)\s*\(`)
	// defNameRe captures names being DEFINED, so they aren't listed as calls.
	defNameRe = regexp.MustCompile(`(?:\b(?:func|function|def|class)\s+|\b(?:const|let|var)\s+)([A-Za-z_]\w*)`)
)

// callKeywords are control-flow / declaration tokens that look like calls but
// aren't worth surfacing.
var callKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "return": true,
	"func": true, "function": true, "def": true, "catch": true, "await": true,
	"async": true, "and": true, "or": true, "not": true, "in": true, "with": true,
	"typeof": true, "new": true, "class": true, "else": true, "elif": true,
}

// analyze produces the heuristic structural summary of a code region. guards are
// the middleware/decorator chain the resolver already found (authoritative for
// has_auth_check); the body text is scanned for the rest.
func analyze(code string, guards []string) StructuralSummary {
	s := StructuralSummary{
		HasAuthCheck:   len(guards) > 0 || authRe.MatchString(code),
		SanitizesInput: sanitizeRe.MatchString(code),
		RawQuery:       sqlVerbRe.MatchString(code) && concatRe.MatchString(code),
		ReflectsInput:  reflectRe.MatchString(code),
		Calls:          extractCalls(code),
	}
	return s
}

// extractCalls lists distinct function calls in the code, minus keywords, capped
// so the summary stays compact.
func extractCalls(code string) []string {
	// Names being defined here are not calls (a def line `function getUser(` would
	// otherwise register getUser as a call to itself).
	defined := map[string]bool{}
	for _, m := range defNameRe.FindAllStringSubmatch(code, -1) {
		defined[m[1]] = true
	}

	seen := map[string]bool{}
	var calls []string
	for _, m := range callRe.FindAllStringSubmatch(code, -1) {
		name := m[1]
		if defined[name] {
			continue
		}
		// Keep the last dotted component for readability (obj.method -> method).
		if i := strings.LastIndex(name, "."); i >= 0 && i < len(name)-1 {
			name = name[i+1:]
		}
		if name == "" || callKeywords[name] || seen[name] {
			continue
		}
		seen[name] = true
		calls = append(calls, name)
		if len(calls) >= 20 {
			break
		}
	}
	sort.Strings(calls)
	return calls
}

// symbolDefRegex matches a definition of `name` across the common languages:
// Go func, JS/TS function/const/let/var, Python def/class.
func symbolDefRegex(name string) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	return regexp.MustCompile(`(?:\b(?:func|function|def|class|const|let|var)\s+` + q + `\b)|(?:\b` + q + `\s*[:=]\s*(?:async\s+)?(?:function\b|\())`)
}
