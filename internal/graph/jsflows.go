package graph

import (
	"context"
	"regexp"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// Sink rules shared by the builders and the detectors in detect.go.
const (
	// RuleSQLConcat is a SQL call whose statement is built by string
	// concatenation or interpolation from values the builder could not tie to
	// the request (a constant column list, a config value, ...).
	RuleSQLConcat = "SQL query built with string concatenation (injection)"
	// RuleSQLFromInput is a SQL call whose statement interpolates a value
	// read from the request in the same function: the classic injection.
	RuleSQLFromInput = "SQL query built from request input (SQL injection)"
	// RuleRawHTML is markup rendered without escaping (React's
	// dangerouslySetInnerHTML with a non-constant, unsanitized value).
	RuleRawHTML = "raw HTML rendered with dangerouslySetInnerHTML (XSS)"
)

// requestMarkers are source-text fragments that mean "this value comes from
// the HTTP request": Request/NextRequest bodies and URLs, Express/Koa req
// fields, route params, form data and headers.
var requestMarkers = []string{
	"req.", "request.", "searchParams", "formData", "ctx.request", "ctx.query", "ctx.params",
	"event.body", "event.queryStringParameters", "headers.get(", "cookies.get(",
}

// paramsRe matches a reference to the Next.js route `params` object
// (`params.id`, `await params`, `const { id } = params`).
var paramsRe = regexp.MustCompile(`\bparams\b`)

// declRe matches a JS/TS variable declaration: LHS (identifier or a
// destructuring pattern) and the initializer up to the end of the line or
// statement.
var declRe = regexp.MustCompile(`(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]+)?=\s*([^;\n]+)`)

var identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

func mentionsRequest(s string) bool {
	for _, m := range requestMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return paramsRe.MatchString(s)
}

// requestTainted returns the local names in body that hold request data:
// declared from a request expression, or from another such name.
func requestTainted(body string) map[string]bool {
	tainted := map[string]bool{}
	decls := declRe.FindAllStringSubmatch(body, -1)
	// Two passes so `const body = await req.json(); const { email } = body`
	// taints email too.
	for pass := 0; pass < 2; pass++ {
		for _, d := range decls {
			rhs := d[2]
			hit := mentionsRequest(rhs)
			if !hit {
				for _, id := range identRe.FindAllString(rhs, -1) {
					if tainted[id] {
						hit = true
						break
					}
				}
			}
			if !hit {
				continue
			}
			for _, id := range identRe.FindAllString(d[1], -1) {
				tainted[id] = true
			}
		}
	}
	return tainted
}

// sqlFromRequest reports whether the dynamic parts of a SQL call's
// arguments (the identifiers inside ${} or "+" operands; string text holds
// no identifiers) come from the request: directly (req.query.q) or through a
// local declared from it in the enclosing function.
func (b *jsBuilder) sqlFromRequest(ctx context.Context, fnID int, args []tswasm.Node) bool {
	var refs []string
	for _, a := range args {
		collectRefs(ctx, b.f, a, &refs, 0)
	}
	if len(refs) == 0 {
		return false
	}
	var tainted map[string]bool
	if r, ok := b.fnRange[fnID]; ok && int(r[1]) <= len(b.f.src) && r[0] <= r[1] {
		tainted = requestTainted(string(b.f.src[r[0]:r[1]]))
	}
	for _, ref := range refs {
		if mentionsRequest(ref) {
			return true
		}
		if tainted[ref] {
			return true
		}
	}
	return false
}

// collectRefs appends the text of identifiers and member expressions under n,
// skipping tagged templates (their values are bound, not concatenated).
func collectRefs(ctx context.Context, f *tsFile, n tswasm.Node, out *[]string, depth int) {
	if depth > 40 {
		return
	}
	k, err := n.Kind(ctx)
	if err != nil {
		return
	}
	switch k {
	case "identifier":
		*out = append(*out, f.text(ctx, n))
		return
	case "member_expression":
		*out = append(*out, strings.Join(strings.Fields(f.text(ctx, n)), ""))
	case "call_expression":
		if isTaggedTemplate(ctx, n) {
			return
		}
	}
	nc, err := namedChildren(ctx, n)
	if err != nil {
		return
	}
	for _, c := range nc {
		collectRefs(ctx, f, c, out, depth+1)
	}
}

// rawHTMLRe finds React's raw-HTML prop, as JSX (dangerouslySetInnerHTML={{
// __html: x }}) or as a createElement props object.
var rawHTMLRe = regexp.MustCompile(`dangerouslySetInnerHTML\s*[=:]\s*\{\s*\{?\s*__html\s*:`)

// rawHTMLSafeHints mark a value that was sanitized or serialized on the way
// in, which is the normal, safe use of the prop.
var rawHTMLSafeHints = []string{"sanitize", "dompurify", "purify", "escapehtml", "escape(", "xss(", "json.stringify", "serialize"}

// scanRawHTML adds a sink for every dangerouslySetInnerHTML whose value is
// not a constant and not visibly sanitized. It works on source text because
// the TypeScript grammar has no TSX dialect: JSX attributes usually arrive as
// ERROR nodes, but the functions around them still have byte ranges.
func (b *jsBuilder) scanRawHTML() {
	src := b.f.src
	for _, m := range rawHTMLRe.FindAllIndex(src, -1) {
		expr := rawHTMLExpr(src[m[1]:])
		if rawHTMLIsSafe(expr) {
			continue
		}
		owner := b.innermostFunc(uint32(m[0]))
		if owner < 0 {
			continue
		}
		b.addSinkAt(b.f.line(uint32(m[0])), owner, "dangerouslySetInnerHTML", RuleRawHTML, "medium")
	}
}

// rawHTMLExpr returns the __html value expression: text up to the first ","
// or closing brace at nesting depth zero, capped.
func rawHTMLExpr(rest []byte) string {
	depth := 0
	for i, c := range rest {
		if i > 400 {
			return string(rest[:i])
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']':
			depth--
		case '}':
			if depth == 0 {
				return string(rest[:i])
			}
			depth--
		case ',':
			if depth == 0 {
				return string(rest[:i])
			}
		}
	}
	return string(rest)
}

func rawHTMLIsSafe(expr string) bool {
	e := strings.TrimSpace(expr)
	if e == "" {
		return true
	}
	// a plain string constant
	if len(e) >= 2 && (e[0] == '"' || e[0] == '\'' || e[0] == '`') && e[len(e)-1] == e[0] && !strings.Contains(e, "${") {
		return true
	}
	low := strings.ToLower(e)
	for _, h := range rawHTMLSafeHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// innermostFunc returns the function of this file whose source range holds
// pos most tightly, or -1.
func (b *jsBuilder) innermostFunc(pos uint32) int {
	best, span := -1, ^uint32(0)
	for _, id := range b.funcs {
		r, ok := b.fnRange[id]
		if !ok || pos < r[0] || pos >= r[1] {
			continue
		}
		if s := r[1] - r[0]; s < span {
			best, span = id, s
		}
	}
	return best
}
