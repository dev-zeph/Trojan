package graph

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/dev-zeph/trojan/internal/graph/tswasm"
)

// chainStep is one call in a fluent method chain such as
// supabase.from("orders").insert(body).select(): method is the called name
// ("from"), args its argument nodes.
type chainStep struct {
	method string
	args   []tswasm.Node
	start  uint32 // start byte of this step's call node (dedupe key)
}

// flattenCallChain unwinds a fluent call chain into its steps, innermost
// call first, plus the receiver text the chain starts from ("supabase",
// "supabase.storage", "prisma.user"). It understands both grammars' shapes:
// JS call_expression/member_expression and Python call/attribute (both put
// the callee first and the accessed name last).
func flattenCallChain(ctx context.Context, f *tsFile, call tswasm.Node) (steps []chainStep, root string) {
	cur := call
	for i := 0; i < 32; i++ {
		kind, _ := cur.Kind(ctx)
		if kind != "call_expression" && kind != "call" {
			break
		}
		nc, err := namedChildren(ctx, cur)
		if err != nil || len(nc) == 0 {
			break
		}
		callee := nc[0]
		var args []tswasm.Node
		if len(nc) > 1 {
			args, _ = namedChildren(ctx, nc[1])
		}
		start, _ := cur.StartByte(ctx)
		ck, _ := callee.Kind(ctx)
		switch ck {
		case "member_expression", "attribute":
			cc, err := namedChildren(ctx, callee)
			if err != nil || len(cc) < 2 {
				return reverseSteps(steps), ""
			}
			steps = append(steps, chainStep{method: f.text(ctx, cc[len(cc)-1]), args: args, start: start})
			cur = cc[0]
			continue
		case "identifier":
			steps = append(steps, chainStep{method: f.text(ctx, callee), args: args, start: start})
			return reverseSteps(steps), ""
		}
		return reverseSteps(steps), ""
	}
	return reverseSteps(steps), strings.TrimSuffix(strings.TrimSpace(f.text(ctx, cur)), "!")
}

func reverseSteps(s []chainStep) []chainStep {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// literalString returns the content of a plain (non-interpolated) string
// literal node, or "" if n is anything else.
func literalString(ctx context.Context, f *tsFile, n tswasm.Node) (string, bool) {
	kind, _ := n.Kind(ctx)
	if kind != "string" && kind != "template_string" {
		return "", false
	}
	if hasInterpolation(ctx, n) {
		return "", false
	}
	t := f.text(ctx, n)
	t = strings.TrimLeft(t, "rRbBuU")
	for _, q := range []string{`"""`, `'''`, `"`, `'`, "`"} {
		if strings.HasPrefix(t, q) && strings.HasSuffix(t, q) && len(t) >= 2*len(q) {
			return t[len(q) : len(t)-len(q)], true
		}
	}
	return "", false
}

var (
	supabaseWriteOps = map[string]bool{"insert": true, "update": true, "upsert": true, "delete": true}
	supabaseReadOps  = map[string]bool{"select": true}
	storageWriteOps  = map[string]bool{"upload": true, "update": true, "remove": true, "move": true, "copy": true}
	storageReadOps   = map[string]bool{"download": true, "list": true, "createSignedUrl": true, "createSignedUrls": true, "getPublicUrl": true, "create_signed_url": true, "get_public_url": true}
	prismaWriteOps   = map[string]bool{"create": true, "createMany": true, "update": true, "updateMany": true, "upsert": true, "delete": true, "deleteMany": true}
	prismaReadOps    = map[string]bool{"findMany": true, "findUnique": true, "findFirst": true, "findUniqueOrThrow": true, "findFirstOrThrow": true, "count": true, "aggregate": true, "groupBy": true}
)

// dataAccess is one datastore touch found in a call chain.
type dataAccess struct {
	store string   // datastore name: "orders", "rpc:fn", "storage:avatars"
	kind  EdgeKind // EdgeReads or EdgeWrites
	key   uint32   // start byte of the call that names the store (dedupe)
}

// matchDataAccess recognizes datastore access in a call chain:
//
//	supabase.from("orders").insert(...)      -> writes orders
//	supabase.table("items").select("*")      -> reads items (Python)
//	supabase.rpc("fn", ...)                  -> writes rpc:fn
//	supabase.storage.from("b").upload(...)   -> writes storage:b
//	prisma.user.findMany()                   -> reads user
//
// A bare .from("x") with no known operation counts only when the receiver
// is plainly a Supabase client, so Buffer.from("...") and Array.from(...)
// never become tables.
func matchDataAccess(ctx context.Context, f *tsFile, steps []chainStep, root string) (dataAccess, bool) {
	for i, s := range steps {
		switch s.method {
		case "from", "table":
			if len(s.args) == 0 {
				continue
			}
			name, ok := literalString(ctx, f, s.args[0])
			if !ok || name == "" {
				continue
			}
			storage := i == 0 && (root == "storage" || strings.HasSuffix(root, ".storage"))
			if i > 0 && steps[i-1].method == "storage" { // Python: supabase.storage.from_(...)
				storage = true
			}
			writeOps, readOps := supabaseWriteOps, supabaseReadOps
			store := name
			if storage {
				writeOps, readOps = storageWriteOps, storageReadOps
				store = "storage:" + name
			}
			kind := EdgeKind("")
			for _, later := range steps[i+1:] {
				if writeOps[later.method] {
					kind = EdgeWrites
					break
				}
				if readOps[later.method] {
					kind = EdgeReads
				}
			}
			if kind == "" {
				if !strings.Contains(strings.ToLower(root), "supabase") && !storage {
					continue
				}
				kind = EdgeReads
			}
			return dataAccess{store: store, kind: kind, key: s.start}, true
		case "from_": // supabase-py storage: supabase.storage.from_("b")
			if len(s.args) == 0 {
				continue
			}
			name, ok := literalString(ctx, f, s.args[0])
			if !ok {
				continue
			}
			kind := EdgeReads
			for _, later := range steps[i+1:] {
				if storageWriteOps[later.method] {
					kind = EdgeWrites
				}
			}
			return dataAccess{store: "storage:" + name, kind: kind, key: s.start}, true
		case "rpc":
			if len(s.args) == 0 {
				continue
			}
			if name, ok := literalString(ctx, f, s.args[0]); ok && name != "" {
				return dataAccess{store: "rpc:" + name, kind: EdgeWrites, key: s.start}, true
			}
		}
	}
	// Prisma: <client>.<model>.<op>(...), the op being the innermost step.
	if len(steps) > 0 && root != "" {
		if dot := strings.LastIndex(root, "."); dot > 0 {
			client, model := strings.ToLower(root[:dot]), root[dot+1:]
			if strings.HasSuffix(client, "prisma") || client == "db" || strings.HasSuffix(client, ".db") {
				op := steps[0].method
				if prismaWriteOps[op] {
					return dataAccess{store: lowerFirst(model), kind: EdgeWrites, key: steps[0].start}, true
				}
				if prismaReadOps[op] {
					return dataAccess{store: lowerFirst(model), kind: EdgeReads, key: steps[0].start}, true
				}
			}
		}
	}
	return dataAccess{}, false
}

// chainHasDataStep reports whether a chain is a Supabase query builder, used
// to keep supabase-py's terminal .execute() from being mistaken for a DB-API
// cursor.execute() SQL sink.
func chainHasDataStep(steps []chainStep) bool {
	for _, s := range steps {
		switch s.method {
		case "from", "from_", "table", "rpc":
			return true
		}
	}
	return false
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// storeTracker dedupes datastore nodes and access edges inside one builder's
// graph slice: one node per store name, one edge per (func, store, kind).
type storeTracker struct {
	g      *Graph
	nodes  map[string]int
	edges  map[[3]int]bool
	byCall map[string]bool // file + call start byte, so nested chain calls count once
}

func newStoreTracker(g *Graph) *storeTracker {
	return &storeTracker{g: g, nodes: map[string]int{}, edges: map[[3]int]bool{}, byCall: map[string]bool{}}
}

// add records that fnID accesses the store described by a. Datastore nodes
// carry no File/Line: they are project-wide, keyed "datastore:<name>".
func (t *storeTracker) add(file string, fnID int, a dataAccess) {
	ck := file + "#" + strconv.Itoa(int(a.key)) + "#" + a.store
	if t.byCall[ck] {
		return
	}
	t.byCall[ck] = true
	id, ok := t.nodes[a.store]
	if !ok {
		id = t.g.addNode(Node{Kind: KindDataStore, Name: a.store})
		t.nodes[a.store] = id
	}
	kindN := 0
	if a.kind == EdgeWrites {
		kindN = 1
	}
	k := [3]int{fnID, id, kindN}
	if t.edges[k] {
		return
	}
	t.edges[k] = true
	t.g.addEdge(fnID, id, a.kind)
}

// isServiceRoleClient reports whether a call creates a Supabase client with
// the service-role key: createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)
// or create_client(url, os.environ["SUPABASE_SERVICE_ROLE_KEY"]). Only the
// argument *text* (an env var name) is inspected, never a value.
func isServiceRoleClient(callee, argsText string) bool {
	last := callee
	if i := strings.LastIndex(callee, "."); i >= 0 {
		last = callee[i+1:]
	}
	switch last {
	case "createClient", "createServerClient", "create_client", "Client", "createAdminClient":
	default:
		return false
	}
	a := strings.ToLower(argsText)
	return strings.Contains(a, "service_role") || strings.Contains(a, "servicerole") || strings.Contains(a, "service_key")
}

// sinkName renders a callee for Node.Name: whitespace collapsed and capped,
// so a sink is named by what it calls ("pool.query"), never by its argument
// text (which can hold literals the graph must not carry).
func sinkName(callee string) string {
	// drop everything inside call parentheses: getConn().cursor().execute
	var b strings.Builder
	depth := 0
	for _, r := range callee {
		switch {
		case r == '(':
			if depth == 0 {
				b.WriteRune(r)
			}
			depth++
		case r == ')':
			depth--
			if depth == 0 {
				b.WriteRune(r)
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	callee = strings.Join(strings.Fields(b.String()), "")
	if len(callee) > 80 {
		callee = callee[:80]
	}
	return callee
}

var (
	sqlVerbRe  = regexp.MustCompile(`(?i)\b(select|insert|update|delete|upsert|merge)\b`)
	sqlTableRe = regexp.MustCompile("(?i)\\b(insert\\s+into|update|delete\\s+from|from|join|into)\\s+[\"`\\[]?([A-Za-z_][\\w]*(?:\\.[A-Za-z_][\\w]*)?)")
)

// sqlTables extracts the tables a raw SQL statement touches, so code that
// talks to Postgres/SQLite directly gets datastore nodes too:
// "SELECT * FROM invoices" reads invoices, "INSERT INTO bookings" writes
// bookings. Only the statement text is read; nothing is executed.
func sqlTables(sql string) []dataAccess {
	if !sqlVerbRe.MatchString(sql) {
		return nil
	}
	write := false
	switch strings.ToLower(sqlVerbRe.FindString(sql)) {
	case "insert", "update", "delete", "upsert", "merge":
		write = true
	}
	var out []dataAccess
	seen := map[string]bool{}
	for _, m := range sqlTableRe.FindAllStringSubmatch(sql, -1) {
		verb := strings.ToLower(strings.Join(strings.Fields(m[1]), " "))
		name := m[2]
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:] // public.orders -> orders
		}
		low := strings.ToLower(name)
		if seen[low] || sqlNotTables[low] {
			continue
		}
		seen[low] = true
		kind := EdgeReads
		if write && (verb == "insert into" || verb == "update" || verb == "delete from" || verb == "into") {
			kind = EdgeWrites
		}
		out = append(out, dataAccess{store: low, kind: kind})
	}
	return out
}

// sqlNotTables are words the table regex can catch that are not tables
// ("DELETE FROM ... WHERE id IN (SELECT ... FROM ...)", "SELECT ... FROM
// unnest(...)", "UPDATE ... SET").
var sqlNotTables = map[string]bool{"select": true, "set": true, "where": true, "unnest": true, "lateral": true, "dual": true, "values": true}
