package graph

import (
	"go/ast"
	"strings"
)

// knownSinks maps an exact "pkg.Func" callee to why it's dangerous and a coarse
// severity. These fire regardless of package aliasing being resolved because the
// callee is matched textually.
var knownSinks = map[string]struct {
	rule string
	sev  string
}{
	"exec.Command":        {"OS command execution", "high"},
	"exec.CommandContext": {"OS command execution", "high"},
	"os.WriteFile":        {"file write (path traversal)", "medium"},
	"os.ReadFile":         {"file read (path traversal)", "medium"},
	"ioutil.WriteFile":    {"file write (path traversal)", "medium"},
	"template.HTML":       {"unescaped HTML (XSS)", "high"},
}

// sqlMethods are receiver methods that execute SQL. They're matched by method
// name (the receiver is a variable, not a package, so we can't qualify it).
var sqlMethods = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true,
	"QueryContext": true, "QueryRowContext": true, "ExecContext": true,
}

// logMethods are print/log calls that can leak sensitive data into logs/stdout.
var logMethods = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Fatal": true, "Fatalf": true, "Fatalln": true,
}

// matchSink reports whether a call is a dangerous sink, with a human rule and a
// severity. SQL calls with a string-concatenated argument are escalated to high
// (that's the classic injection shape).
func matchSink(call *ast.CallExpr) (rule, sev string, ok bool) {
	callee := calleeString(call.Fun)
	if s, found := knownSinks[callee]; found {
		return s.rule, s.sev, true
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	method := sel.Sel.Name
	if sqlMethods[method] && !looksNonSQLReceiver(sel.X) {
		if hasStringConcat(call.Args) {
			return "SQL query built with string concatenation (injection)", "high", true
		}
		return "SQL query execution", "medium", true
	}
	if logMethods[method] {
		if x, ok := sel.X.(*ast.Ident); ok && (x.Name == "log" || x.Name == "fmt") {
			return "possible sensitive data written to logs/stdout", "medium", true
		}
	}
	return "", "", false
}

// nonSQLReceivers are receiver expressions whose ".Query"/".Exec" methods are
// not SQL (url.Values.Query, template exec, …). Without type resolution we can
// only guard by name; the production build resolves the receiver's type and
// drops this heuristic entirely.
var nonSQLReceivers = []string{".URL", "url.", ".Form", "tmpl", "template", ".T."}

// looksNonSQLReceiver reports whether a rendered receiver is a known non-SQL
// source of a Query/Exec method, to suppress the obvious false positives.
func looksNonSQLReceiver(x ast.Expr) bool {
	r := calleeString(x)
	for _, hint := range nonSQLReceivers {
		if strings.Contains(r, hint) {
			return true
		}
	}
	return false
}

// hasStringConcat reports whether any argument is a "+" expression with a
// non-literal operand — the signature of an interpolated query/command.
func hasStringConcat(args []ast.Expr) bool {
	for _, a := range args {
		found := false
		ast.Inspect(a, func(n ast.Node) bool {
			b, ok := n.(*ast.BinaryExpr)
			if !ok || b.Op.String() != "+" {
				return true
			}
			if !isBasicLit(b.X) || !isBasicLit(b.Y) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func isBasicLit(e ast.Expr) bool {
	_, ok := e.(*ast.BasicLit)
	return ok
}

// piiHints are identifier substrings that suggest personal / sensitive data.
var piiHints = []string{
	"password", "passwd", "secret", "token", "apikey", "ssn", "email",
	"phone", "dob", "birth", "address", "creditcard", "cardnumber", "cvv",
	"medical", "diagnosis", "patient", "phi",
}

// looksLikePII reports whether an identifier name suggests it holds PII/PHI.
func looksLikePII(name string) bool {
	lower := strings.ToLower(name)
	for _, h := range piiHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// calleeString renders a call target as source text: "exec.Command", "db.Query",
// "log.Printf", or a bare "helper". Good enough for matching and reports.
func calleeString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return calleeString(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}

// typeString renders a type expression as source-like text, e.g. "*http.Request".
func typeString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return "*" + typeString(v.X)
	case *ast.SelectorExpr:
		return typeString(v.X) + "." + v.Sel.Name
	case *ast.ArrayType:
		return "[]" + typeString(v.Elt)
	default:
		return ""
	}
}

// AttackPath is a reachable route from an untrusted entrypoint (source) to a
// dangerous sink — the concrete hypothesis an agent would try to prove.
type AttackPath struct {
	Source   Node   // the entrypoint function
	Sink     Node   // the dangerous call
	Via      []Node // function chain from source to the function holding the sink (inclusive)
	Severity string
	TouchPII bool // any function along the path touches PII/PHI
}

// Paths returns every source->sink route in the graph, discovered by walking the
// call edges out of each entrypoint (BFS) until a function that contains a sink
// is reached. This is the report the demo prints and, in production, the seed
// set the agent loop reasons over.
func (g *Graph) Paths() []AttackPath {
	// adjacency over call edges; sinks contained per function.
	calls := make(map[int][]int)
	contains := make(map[int][]int)
	for _, e := range g.Edges {
		switch e.Kind {
		case EdgeCalls:
			calls[e.Src] = append(calls[e.Src], e.Dst)
		case EdgeContains:
			contains[e.Src] = append(contains[e.Src], e.Dst)
		}
	}

	var paths []AttackPath
	for _, n := range g.Nodes {
		if n.Kind != KindFunc || !n.Source {
			continue
		}
		// BFS from this source, tracking predecessors to rebuild the chain.
		prev := map[int]int{n.ID: -1}
		queue := []int{n.ID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, sinkID := range contains[cur] {
				chain := g.rebuild(prev, cur)
				sink := g.Nodes[sinkID]
				paths = append(paths, AttackPath{
					Source:   n,
					Sink:     sink,
					Via:      chain,
					Severity: sink.Severity,
					TouchPII: g.chainTouchesPII(chain),
				})
			}
			for _, next := range calls[cur] {
				if _, seen := prev[next]; !seen {
					prev[next] = cur
					queue = append(queue, next)
				}
			}
		}
	}
	return paths
}

// rebuild reconstructs the function chain from the BFS source to node id.
func (g *Graph) rebuild(prev map[int]int, id int) []Node {
	var ids []int
	for id != -1 {
		ids = append(ids, id)
		id = prev[id]
	}
	// reverse into source->…->holder order.
	chain := make([]Node, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		chain = append(chain, g.Nodes[ids[i]])
	}
	return chain
}

func (g *Graph) chainTouchesPII(chain []Node) bool {
	for _, n := range chain {
		if n.PII {
			return true
		}
	}
	return false
}
