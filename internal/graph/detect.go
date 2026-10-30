package graph

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Detection is a code flaw the graph can show end to end, precise enough to
// report as a finding on its own (see scanners.GraphChecks): not "this
// function runs SQL" but "request input is built into this SQL string".
type Detection struct {
	// Rule is a stable id: DetectSQLInjection or DetectStoredXSS.
	Rule     string
	Severity string // "critical" | "high"
	Title    string
	Message  string
	// Sink is the node the finding is anchored on (its File/Line/Key).
	Sink Node
	// Entry is the entrypoint that reaches the sink (SQL injection) or
	// writes the stored data (stored XSS); zero when none was found.
	Entry Node
	// Unguarded is true when Entry is reachable with no auth check.
	Unguarded bool
	// Store is the datastore a stored-XSS chain goes through.
	Store string
	// Readers are the routes that serve that data to the rendering code.
	Readers []Node
}

// Detection rule ids.
const (
	DetectSQLInjection = "trojan.sql-injection"
	DetectStoredXSS    = "trojan.stored-xss"
)

// Detect runs the graph-level detectors:
//
//   - SQL injection: a SQL sink whose statement interpolates request input
//     (RuleSQLFromInput). Critical when an unauthenticated entrypoint reaches
//     it, high otherwise.
//   - Stored XSS: a dangerouslySetInnerHTML sink (RuleRawHTML) rendering a
//     datastore that an unauthenticated entrypoint writes. The rendered data
//     is linked to the store either through the reads of the rendering
//     function itself (a server component) or through the same-origin API
//     routes the rendering file fetches ("/api/admin/messages" -> the route
//     handler -> datastore:messages).
//
// root is the project root, used to read the rendering files for their
// fetch() URLs; node files may be absolute or relative to it.
func Detect(g *Graph, root string) []Detection {
	var out []Detection
	out = append(out, detectSQLInjection(g)...)
	out = append(out, detectStoredXSS(g, root)...)
	rank := map[string]int{"critical": 0, "high": 1}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

func detectSQLInjection(g *Graph) []Detection {
	// best entrypoint per sink: prefer an unguarded one.
	type hit struct {
		entry     Node
		unguarded bool
		found     bool
	}
	best := map[int]hit{}
	for _, p := range g.Paths() {
		if p.Sink.Kind != KindSink || p.Sink.SinkRule != RuleSQLFromInput {
			continue
		}
		h := best[p.Sink.ID]
		if !h.found || (!h.unguarded && !p.Guarded) {
			best[p.Sink.ID] = hit{entry: p.Source, unguarded: !p.Guarded, found: true}
		}
	}
	var out []Detection
	for _, n := range g.Nodes {
		if n.Kind != KindSink || n.SinkRule != RuleSQLFromInput {
			continue
		}
		h := best[n.ID]
		d := Detection{
			Rule:     DetectSQLInjection,
			Severity: "high",
			Title:    "SQL injection: request input is built into a SQL query",
			Sink:     n,
			Entry:    h.entry,
		}
		msg := "The SQL statement passed to " + n.Name + " is built with string interpolation or concatenation from a value taken from the request, so an attacker can change the query itself (for example `' OR '1'='1`). Use a parameterized query (placeholders like ? or $1 with the values passed separately, or a tagged sql`` template)."
		if h.found {
			if h.unguarded {
				d.Severity = "critical"
				d.Unguarded = true
				msg = "Anyone can reach this without logging in: " + entryLabel(h.entry) + ". " + msg
			} else {
				msg = "Reached from " + entryLabel(h.entry) + " (behind a login check). " + msg
			}
		}
		d.Message = msg
		out = append(out, d)
	}
	return out
}

func detectStoredXSS(g *Graph, root string) []Detection {
	calls := map[int][]int{}
	reads := map[int][]int{} // func -> datastores it reads
	holder := map[int]int{}  // sink -> function containing it
	for _, e := range g.Edges {
		switch e.Kind {
		case EdgeCalls:
			calls[e.Src] = append(calls[e.Src], e.Dst)
		case EdgeReads:
			reads[e.Src] = append(reads[e.Src], e.Dst)
		case EdgeContains:
			holder[e.Dst] = e.Src
		}
	}
	// datastores reachable (read) from a function through calls.
	readsFrom := func(start int) map[int]bool {
		got := map[int]bool{}
		seen := map[int]bool{start: true}
		queue := []int{start}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, s := range reads[cur] {
				got[s] = true
			}
			for _, nx := range calls[cur] {
				if !seen[nx] {
					seen[nx] = true
					queue = append(queue, nx)
				}
			}
		}
		return got
	}

	// unauthenticated writers per datastore, ignoring lazy schema/seed
	// helpers (a getDb() that seeds tables on first use would otherwise make
	// every public route a "writer" of every table).
	writers := map[int]AttackPath{}
	for _, p := range g.UnguardedPaths() {
		if p.Access != EdgeWrites || p.Sink.Kind != KindDataStore {
			continue
		}
		if len(p.Via) == 0 || isSetupFunc(p.Via[len(p.Via)-1]) {
			continue
		}
		if cur, ok := writers[p.Sink.ID]; !ok || len(p.Via) < len(cur.Via) {
			writers[p.Sink.ID] = p
		}
	}
	if len(writers) == 0 {
		return nil
	}

	routes := routeIndex(g)
	fileURLs := map[string][]string{}
	var out []Detection
	for _, n := range g.Nodes {
		if n.Kind != KindSink || n.SinkRule != RuleRawHTML {
			continue
		}
		h, ok := holder[n.ID]
		if !ok {
			continue
		}
		stores := readsFrom(h)
		readersOf := map[int][]Node{}
		for s := range stores {
			readersOf[s] = append(readersOf[s], g.Nodes[h])
		}
		file := nodeFile(n, root)
		urls, cached := fileURLs[file]
		if !cached {
			urls = sameOriginURLs(file)
			fileURLs[file] = urls
		}
		for _, u := range urls {
			for _, r := range routes.match(u) {
				if r.method != "GET" && r.method != "" {
					continue
				}
				for s := range readsFrom(r.id) {
					stores[s] = true
					readersOf[s] = append(readersOf[s], g.Nodes[r.id])
				}
			}
		}
		// deterministic order; when the code just above the sink names some
		// of the candidate stores (messages.map((m) => ...)), only those are
		// considered, so a page that fetches several APIs is tied to the data
		// it actually renders at this spot.
		ids := make([]int, 0, len(stores))
		for s := range stores {
			ids = append(ids, s)
		}
		sort.Ints(ids)
		ids = narrowToMentioned(g, ids, linesBefore(file, n.Line, 20))
		for _, s := range ids {
			w, ok := writers[s]
			if !ok {
				continue
			}
			store := g.Nodes[s].Name
			readers := readersOf[s]
			via := ""
			if len(readers) > 0 {
				via = " (served by " + entryLabel(readers[0]) + ")"
			}
			out = append(out, Detection{
				Rule:      DetectStoredXSS,
				Severity:  "high",
				Title:     "Stored XSS: data anyone can submit is rendered as raw HTML",
				Message:   "Anyone can write to `" + store + "` without logging in through " + entryLabel(w.Source) + ", and this page renders that data with dangerouslySetInnerHTML" + via + ". A submitted <img src=x onerror=...> runs as script in the browser of whoever views it, often an admin. Render it as text (no dangerouslySetInnerHTML), or sanitize it with DOMPurify first.",
				Sink:      n,
				Entry:     w.Source,
				Unguarded: true,
				Store:     store,
				Readers:   readers,
			})
			break // one finding per sink
		}
	}
	return out
}

// isSetupFunc reports whether a function looks like schema setup or seeding
// (seed, migrate, bootstrap, setup, init) rather than request work. Only the
// symbol is checked (from the node key, else the name minus its file
// prefix), so a file called seed.ts does not make its handlers "setup".
func isSetupFunc(n Node) bool {
	sym := n.Name
	if i := strings.Index(n.Key, "#"); i >= 0 {
		sym = n.Key[i+1:]
	} else if i := strings.Index(sym, "."); i >= 0 {
		// Name is "<file base>.<symbol>"; drop the base and its extension.
		if j := strings.Index(sym[i+1:], "."); j >= 0 {
			sym = sym[i+1+j+1:]
		}
	}
	for _, part := range strings.FieldsFunc(sym, func(r rune) bool { return r == '.' || r == '#' }) {
		w := strings.ToLower(part)
		if w == "init" {
			return true
		}
		for _, k := range []string{"seed", "migrate", "migration", "bootstrap", "setup", "initdb", "init_db", "createtables", "ensureschema"} {
			if strings.HasPrefix(w, k) {
				return true
			}
		}
	}
	return false
}

// entryLabel renders an entrypoint as "METHOD /path" when it is a route,
// else its key or name.
func entryLabel(n Node) string {
	if m, p, ok := routeOf(n); ok {
		if m == "" {
			return p
		}
		return m + " " + p
	}
	if n.Key != "" {
		return n.Key
	}
	return n.Name
}

type routeEntry struct {
	id     int
	method string
	segs   []string
}

type routeTable []routeEntry

// routeIndex lists every source function that serves an HTTP route.
func routeIndex(g *Graph) routeTable {
	var t routeTable
	for _, n := range g.Nodes {
		if n.Kind != KindFunc || !n.Source {
			continue
		}
		m, p, ok := routeOf(n)
		if !ok {
			continue
		}
		t = append(t, routeEntry{id: n.ID, method: m, segs: splitURL(p)})
	}
	return t
}

// match returns the routes whose pattern matches a same-origin URL; "{x}"
// pattern segments and "*" URL segments (from ${...}) match anything.
func (t routeTable) match(url string) []routeEntry {
	segs := splitURL(url)
	var out []routeEntry
	for _, r := range t {
		if len(r.segs) != len(segs) {
			continue
		}
		ok := true
		for i := range segs {
			if segs[i] == "*" || (strings.HasPrefix(r.segs[i], "{") && strings.HasSuffix(r.segs[i], "}")) {
				continue
			}
			if segs[i] != r.segs[i] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, r)
		}
	}
	return out
}

func splitURL(u string) []string {
	var out []string
	for _, s := range strings.Split(strings.Trim(u, "/"), "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

var expressRouteNameRe = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|ALL) (/\S*?)(#\d+)?$`)

// routeOf derives an entrypoint's HTTP method and URL pattern: Next.js
// app/**/route.ts exports and pages/api files from the node key's path,
// Express-style handlers from their "METHOD /path" name.
func routeOf(n Node) (method, url string, ok bool) {
	rel := n.Key
	sym := ""
	if i := strings.Index(rel, "#"); i >= 0 {
		rel, sym = rel[:i], rel[i+1:]
	}
	if rel != "" {
		stem := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
		for _, appDir := range []string{"app/", "src/app/"} {
			if strings.HasPrefix(rel, appDir) && stem == "route" {
				if u, ok := nextURLPath(path.Dir(strings.TrimPrefix(rel, appDir))); ok {
					return strings.ToUpper(sym), u, true
				}
			}
		}
		for _, pagesAPI := range []string{"pages/api/", "src/pages/api/"} {
			if strings.HasPrefix(rel, pagesAPI) {
				sub := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(rel, "src/"), "pages/"), path.Ext(rel))
				sub = strings.TrimSuffix(strings.TrimSuffix(sub, "/index"), "index")
				u, _ := nextURLPath(sub)
				return "", u, true
			}
		}
	}
	name := n.Name
	if i := strings.Index(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if m := expressRouteNameRe.FindStringSubmatch(name); m != nil {
		return m[1], m[2], true
	}
	return "", "", false
}

// sameOriginRe finds same-origin request URLs in client code:
// fetch("/api/x"), axios.get(`/api/y/${id}`), useSWR("/api/z").
var sameOriginRe = regexp.MustCompile("(?:fetch|axios(?:\\.\\w+)?|useSWR|useQuery|ky(?:\\.\\w+)?|\\$fetch|get|post)\\(\\s*[\"'`](/[^\"'`\\s]*)")

var templateExprRe = regexp.MustCompile(`\$\{[^}]*\}`)

// sameOriginURLs returns the relative URLs a file requests, with query
// strings dropped and ${...} parts turned into "*" segments.
func sameOriginURLs(file string) []string {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range sameOriginRe.FindAllSubmatch(src, -1) {
		u := templateExprRe.ReplaceAllString(string(m[1]), "*")
		if i := strings.IndexAny(u, "?#"); i >= 0 {
			u = u[:i]
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// nodeFile resolves a node's source file: an absolute File as is, else the
// key's project-relative path under root, else File as given.
func nodeFile(n Node, root string) string {
	if filepath.IsAbs(n.File) {
		return n.File
	}
	if i := strings.Index(n.Key, "#"); i >= 0 && root != "" {
		return filepath.Join(root, filepath.FromSlash(n.Key[:i]))
	}
	return n.File
}

// linesBefore returns up to n source lines ending at line (1-based).
func linesBefore(file string, line, n int) string {
	src, err := os.ReadFile(file)
	if err != nil || line <= 0 {
		return ""
	}
	lines := strings.Split(string(src), "\n")
	if line > len(lines) {
		line = len(lines)
	}
	start := line - n
	if start < 0 {
		start = 0
	}
	return strings.Join(lines[start:line], "\n")
}

// narrowToMentioned keeps the datastore whose name (or its singular) occurs
// as a word closest to the end of text, i.e. nearest above the sink, or all
// of them when none occurs.
func narrowToMentioned(g *Graph, ids []int, text string) []int {
	if text == "" {
		return ids
	}
	low := strings.ToLower(text)
	best, bestPos := []int(nil), -1
	for _, id := range ids {
		name := strings.ToLower(g.Nodes[id].Name)
		pos := -1
		for _, w := range []string{name, strings.TrimSuffix(name, "s")} {
			if w == "" {
				continue
			}
			for _, m := range regexp.MustCompile(`\b`+regexp.QuoteMeta(w)+`\b`).FindAllStringIndex(low, -1) {
				if m[0] > pos {
					pos = m[0]
				}
			}
		}
		switch {
		case pos < 0:
		case pos > bestPos:
			best, bestPos = []int{id}, pos
		case pos == bestPos:
			best = append(best, id)
		}
	}
	if best == nil {
		return ids
	}
	return best
}
