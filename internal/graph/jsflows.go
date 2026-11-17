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

// placeholderJoinRe matches a value built as a list of "?" placeholders joined
// into a string: ids.map(() => "?").join(",") or Array(n).fill("?").join(", ").
// The result is a constant parameter list (?,?,?), not attacker data, even when
// the array it was derived from came from the request — the real values are
// passed separately to .all(...)/.run(...) and bound as parameters. Without
// this, WHERE id IN (${marks}) looks like request-interpolated SQL and is
// reported as a false-positive injection.
var placeholderJoinRe = regexp.MustCompile(
	"(?:\\.map\\(\\s*(?:\\([^)]*\\)|[\\w$]+)?\\s*=>\\s*[\"'`]\\?[\"'`]\\s*\\)|\\.fill\\(\\s*[\"'`]\\?[\"'`]\\s*\\))\\s*\\.join\\(")

// forOfRe matches a for...of loop that binds loop variables:
// for (const [k, v] of EXPR) or for (const x of EXPR). The iterable EXPR stops
// at the first ")", which still captures enough to spot a request source such
// as Object.entries(req.query).
var forOfRe = regexp.MustCompile(
	`for\s*\(\s*(?:const|let|var)\s+(\[[^\]]*\]|[A-Za-z_$][\w$]*)\s+of\s+([^)]+)`)

// pushRe matches arr.push(ARG): a mutation that carries ARG's taint into the
// array, so a tainted clause pushed onto an array and later join()ed into SQL
// is tracked. ARG runs to the end of the statement/line.
var pushRe = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\.\s*push\(([^;\n]*)`)

func mentionsRequest(s string) bool {
	for _, m := range requestMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return paramsRe.MatchString(s)
}

// requestTainted returns the local names in body that hold request data:
// declared from a request expression, bound by a for...of over one, or carried
// into an array by a push of a tainted value. Taint flows through several hops
// (a loop variable taints a destructured name, which taints a pushed clause,
// which taints the array a later statement join()s into SQL), so it iterates to
// a fixpoint rather than a fixed number of passes.
func requestTainted(body string) map[string]bool {
	tainted := map[string]bool{}
	decls := declRe.FindAllStringSubmatch(body, -1)
	forOfs := forOfRe.FindAllStringSubmatch(body, -1)
	pushes := pushRe.FindAllStringSubmatch(body, -1)

	// refsTainted: the expression reads the request directly or references a
	// name already known to be tainted.
	refsTainted := func(expr string) bool {
		if mentionsRequest(expr) {
			return true
		}
		for _, id := range identRe.FindAllString(expr, -1) {
			if tainted[id] {
				return true
			}
		}
		return false
	}

	for i := 0; i < 8; i++ {
		changed := false
		mark := func(names string) {
			for _, id := range identRe.FindAllString(names, -1) {
				if !tainted[id] {
					tainted[id] = true
					changed = true
				}
			}
		}
		for _, d := range decls {
			lhs, rhs := d[1], d[2]
			// A list of "?" placeholders is a constant parameter list, not
			// attacker data, even when built from a request-sourced array.
			if placeholderJoinRe.MatchString(rhs) {
				continue
			}
			if refsTainted(rhs) {
				mark(lhs)
			}
		}
		for _, fo := range forOfs {
			lhs, iterable := fo[1], fo[2]
			if refsTainted(iterable) {
				mark(lhs)
			}
		}
		for _, p := range pushes {
			arr, arg := p[1], p[2]
			if placeholderJoinRe.MatchString(arg) {
				continue
			}
			if refsTainted(arg) {
				mark(arr)
			}
		}
		if !changed {
			break
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
