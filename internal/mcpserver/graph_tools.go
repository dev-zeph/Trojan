package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/orgcontext"
	"github.com/dev-zeph/trojan/internal/rag"
	"github.com/dev-zeph/trojan/internal/reach"
)

// ── Security brain tools ─────────────────────────────────────────────────────
//
// These give the AI tool what it can't get by reading files one at a time:
// Trojan's persistent code graph (every entrypoint, call chain and datastore
// access across the project), the project's context and its memory of past
// findings. Everything runs locally; the graph is refreshed incrementally on
// each call, so answers match the code on disk.
//
// Responses are compact JSON, ranked most urgent first, carry file:line on
// every item and stay under maxResponseBytes (lists are shortened to fit).

// maxResponseBytes caps every brain tool response so it never floods the AI
// tool's context window.
const maxResponseBytes = 7800

// graphToolNames don't need a prior scan: they build the graph on demand, so
// resolveProject accepts any project folder for them.
var graphToolNames = map[string]bool{
	"get_attack_surface": true, "get_attack_paths": true, "trace_dataflow": true,
	"what_touches": true, "get_security_rules": true, "get_security_history": true,
	"search_code_security": true,
}

func registerGraphTools(s *server.MCPServer, tool func(string, ...mcp.ToolOption) mcp.Tool, project projectFunc) {
	s.AddTool(
		tool("get_attack_surface",
			mcp.WithDescription("Every public entrypoint in the project (API routes, server actions, Express/FastAPI/Flask handlers) from Trojan's code graph: whether each checks login, and which database tables and dangerous calls it reaches. "+
				"Call this when you need an overview of what an attacker can hit, before reviewing or changing routes. Ranked: unprotected routes that write data first."),
		),
		handleAttackSurface(project),
	)
	s.AddTool(
		tool("get_attack_paths",
			mcp.WithDescription("Concrete attack paths from Trojan's code graph: public routes that reach a database write or read, or a dangerous call (raw SQL, shell), with no login check on the way, plus browser code that reaches secrets or the admin database client. "+
				"Call this after finishing a feature or when asked which routes are unprotected. Each path has file:line for the route and the call chain."),
		),
		handleAttackPaths(project),
	)
	s.AddTool(
		tool("trace_dataflow",
			mcp.WithDescription("Follow one route or function through the code graph: who reaches it (and whether they check login), every function it calls across files, the tables it reads and writes, and the dangerous calls on the way. "+
				"Call this before changing a route or function, or to understand what a finding's code can affect."),
			mcp.WithString("target", mcp.Required(), mcp.Description(`A route ("/api/orders" or "POST /api/orders"), a function name ("deletePost"), or a node key from another Trojan tool.`)),
		),
		handleTraceDataflow(project),
	)
	s.AddTool(
		tool("what_touches",
			mcp.WithDescription("Everything in the code that reads or writes a datastore (e.g. \"orders\") or touches a sensitive data category from the project context (e.g. \"payments\", \"PII\"), with whether each is reachable without login. "+
				"Call this before changing a table, its schema or its access rules, or when asked where some kind of data is used."),
			mcp.WithString("target", mcp.Required(), mcp.Description(`A table or collection name, or a sensitive data category.`)),
		),
		handleWhatTouches(project),
	)
	s.AddTool(
		tool("get_security_rules",
			mcp.WithDescription("The security rules this specific project must follow, worked out from its stack (e.g. Supabase, Next.js, Express, FastAPI, Flask, Stripe), its project context and what Trojan has learned, with the places in the code that currently break each rule. "+
				"Call this BEFORE writing auth, database or API code, and follow the rules in what you write."),
			mcp.WithString("area", mcp.Description(`"auth", "database", "api", "client", "payments" or "all" (default).`)),
		),
		handleSecurityRules(project),
	)
	s.AddTool(
		tool("get_security_history",
			mcp.WithDescription("What Trojan remembers about this project: findings confirmed real, dismissed as false alarms, accepted as risks or fixed, and facts learned during tests. "+
				"Call this before working on a file or fixing a finding, so you don't redo or undo past decisions. Filter by file, node key or rule, or omit all for the latest events."),
			mcp.WithString("file", mcp.Description("Project-relative file path.")),
			mcp.WithString("node_key", mcp.Description("A graph node key from another Trojan tool.")),
			mcp.WithString("rule", mcp.Description("A scanner rule id.")),
		),
		handleSecurityHistory(project),
	)
	s.AddTool(
		tool("search_code_security",
			mcp.WithDescription("Search the project's code by meaning (e.g. \"where are passwords hashed\", \"stripe webhook handler\") using Trojan's semantic index, returning file:line ranges. "+
				"Call this when you need to find security-relevant code you can't locate by name. Needs `trojan index` to have been run for the project."),
			mcp.WithString("query", mcp.Required(), mcp.Description("What you're looking for, in plain words.")),
			mcp.WithNumber("limit", mcp.Description("Maximum results (default 6, at most 10).")),
		),
		handleSearchCodeSecurity(project),
	)
}

// --- shared helpers ---

// brain is one project's freshly refreshed graph plus its context.
type brain struct {
	root string
	a    *reach.Analyzer
	ctx  *orgcontext.OrgContext
}

func loadBrain(projectPath string) (*brain, error) {
	g, ctx, err := reach.LoadGraph(projectPath)
	if err != nil {
		return nil, fmt.Errorf("could not build the code graph for %s: %w", projectPath, err)
	}
	return &brain{root: projectPath, a: reach.New(g, projectPath), ctx: ctx}, nil
}

// withBrain resolves the project, loads its graph and runs fn.
func withBrain(project projectFunc, fn func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, err := loadBrain(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return fn(b, req), nil
	}
}

// fitJSON marshals build(n) compactly, shrinking n until the result fits in
// maxResponseBytes. build must report truncation itself (it knows its totals).
func fitJSON(n int, build func(n int) any) *mcp.CallToolResult {
	for {
		// No HTML escaping: routes like "/delete/<id>" must read as written.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(build(n)); err != nil {
			return mcp.NewToolResultError("failed to serialize result")
		}
		out := bytes.TrimSpace(buf.Bytes())
		if len(out) <= maxResponseBytes || n <= 1 {
			return mcp.NewToolResultText(string(out))
		}
		n = n * 2 / 3
	}
}

func capN[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// funcLabel is a function's route label for entrypoints, else its symbol.
func (b *brain) funcLabel(n graph.Node) string {
	if n.Source {
		return b.a.Label(n)
	}
	return reach.Symbol(n)
}

// via renders a call chain as "symbol (file:line)" hops, eliding the middle
// of long chains.
func (b *brain) via(chain []graph.Node) []string {
	var out []string
	for i, n := range chain {
		if len(chain) > 5 && i == 2 {
			out = append(out, fmt.Sprintf("... %d more ...", len(chain)-4))
		}
		if len(chain) > 5 && i >= 2 && i < len(chain)-2 {
			continue
		}
		out = append(out, fmt.Sprintf("%s (%s)", reach.Symbol(n), b.a.Loc(n)))
	}
	return out
}

// sinkView is a dangerous call reached.
type sinkView struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity,omitempty"`
	At       string `json:"at"`
}

func (b *brain) sinks(ids []int, n int) []sinkView {
	sort.SliceStable(ids, func(i, j int) bool {
		return b.a.G.Nodes[ids[i]].Severity == "high" && b.a.G.Nodes[ids[j]].Severity != "high"
	})
	var out []sinkView
	for _, id := range capN(ids, n) {
		s := b.a.G.Nodes[id]
		out = append(out, sinkView{Rule: s.SinkRule, Severity: s.Severity, At: b.a.Loc(s)})
	}
	return out
}

// --- get_attack_surface ---

type surfaceEntry struct {
	Route      string     `json:"route"`
	At         string     `json:"at"`
	LoginCheck bool       `json:"login_check"`
	Writes     []string   `json:"writes,omitempty"`
	Reads      []string   `json:"reads,omitempty"`
	Sinks      []sinkView `json:"dangerous_calls,omitempty"`
	Sensitive  bool       `json:"sensitive,omitempty"`
	Key        string     `json:"node_key"`
	rank       int
}

func handleAttackSurface(project projectFunc) server.ToolHandlerFunc {
	return withBrain(project, func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult {
		var entries []surfaceEntry
		unguarded := 0
		stores := map[string]bool{}
		for _, n := range b.a.G.Nodes {
			if n.Kind == graph.KindDataStore {
				stores[n.Name] = true
			}
			if n.Kind != graph.KindFunc || !n.Source {
				continue
			}
			d := b.a.Downstream(n.ID)
			e := surfaceEntry{
				Route: b.a.Label(n), At: b.a.Loc(n), LoginCheck: n.Guarded,
				Writes: d.Writes, Reads: d.Reads, Sinks: b.sinks(d.Sinks, 3), Sensitive: d.Sensitive, Key: n.Key,
			}
			if !n.Guarded {
				unguarded++
				e.rank = 8
			}
			switch {
			case len(d.Writes) > 0:
				e.rank += 4
			case len(d.Sinks) > 0:
				e.rank += 3
			case len(d.Reads) > 0:
				e.rank += 2
			}
			if d.Sensitive {
				e.rank++
			}
			entries = append(entries, e)
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].rank > entries[j].rank })
		return fitJSON(40, func(n int) any {
			out := map[string]any{
				"entrypoints":       len(entries),
				"without_login":     unguarded,
				"datastores":        capN(sortedSet(stores), 30),
				"items":             capN(entries, n),
				"note":              "login_check=false means Trojan found no auth check in the handler or a middleware covering it.",
				"next":              "Use get_attack_paths for the unprotected paths, trace_dataflow for one route.",
				"client_code_risks": len(b.a.G.ClientExposures()),
			}
			if len(entries) > n {
				out["truncated"] = fmt.Sprintf("showing %d of %d, most urgent first", n, len(entries))
			}
			return out
		})
	})
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- get_attack_paths ---

type pathView struct {
	Route     string   `json:"route"`
	Entry     string   `json:"entry"`
	Reaches   string   `json:"reaches"`
	At        string   `json:"at"`
	Severity  string   `json:"severity"`
	Sensitive bool     `json:"sensitive,omitempty"`
	Via       []string `json:"via,omitempty"`
	Key       string   `json:"node_key"`
	rank      int
}

type exposureView struct {
	Client  string   `json:"browser_code"`
	Reaches string   `json:"reaches"`
	At      string   `json:"at"`
	Via     []string `json:"via,omitempty"`
}

func handleAttackPaths(project projectFunc) server.ToolHandlerFunc {
	return withBrain(project, func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult {
		paths, exposures := b.attackPaths()
		flaws := b.codeFlaws()
		return fitJSON(25, func(n int) any {
			out := map[string]any{
				"code_flaws":        capN(flaws, n),
				"unprotected_paths": capN(paths, n),
				"browser_exposures": capN(exposures, n),
				"total":             len(flaws) + len(paths) + len(exposures),
				"meaning":           "Each code flaw is a vulnerability the code graph traced end to end (request input built into SQL, public input stored and rendered as raw HTML). Each unprotected path is a public route that reaches the listed data or call with no login check on the way. Each browser exposure ships a secret or privileged client to users' browsers.",
				"next":              "Fix by checking the signed-in user at the route (see get_security_rules), then run_scan or verify_fix.",
			}
			if len(paths) > n || len(exposures) > n {
				out["truncated"] = fmt.Sprintf("showing up to %d of each, most urgent first", n)
			}
			return out
		})
	})
}

// attackPaths returns the graph's unguarded paths and client exposures,
// deduplicated and ranked.
func (b *brain) attackPaths() ([]pathView, []exposureView) {
	type dk struct {
		src, dst int
		kind     graph.EdgeKind
	}
	seen := map[dk]bool{}
	paths := []pathView{}
	for _, p := range b.a.G.UnguardedPaths() {
		k := dk{p.Source.ID, p.Sink.ID, p.Access}
		if seen[k] {
			continue
		}
		seen[k] = true
		holder := p.Via[len(p.Via)-1]
		v := pathView{
			Route: b.a.Label(p.Source), Entry: b.a.Loc(p.Source), Severity: p.Severity,
			Sensitive: p.TouchPII || p.Sink.PII, Via: b.via(p.Via), Key: p.Source.Key,
		}
		switch p.Access {
		case graph.EdgeWrites:
			v.Reaches, v.At, v.rank = "writes "+p.Sink.Name, b.a.Loc(holder), 6
		case graph.EdgeReads:
			v.Reaches, v.At, v.rank = "reads "+p.Sink.Name, b.a.Loc(holder), 3
		default:
			v.Reaches, v.At, v.rank = p.Sink.SinkRule, b.a.Loc(p.Sink), 2
			if p.Severity == "high" {
				v.rank = 5
			}
		}
		if v.Sensitive {
			v.rank++
		}
		paths = append(paths, v)
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].rank > paths[j].rank })

	exposures := []exposureView{}
	for _, e := range b.a.G.ClientExposures() {
		exposures = append(exposures, exposureView{
			Client:  fmt.Sprintf("%s (%s)", reach.Symbol(e.Client), b.a.Loc(e.Client)),
			Reaches: e.Reached.SinkRule, At: b.a.Loc(e.Reached), Via: b.via(e.Via),
		})
	}
	return paths, exposures
}

type flawView struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	At       string `json:"at"`
	Entry    string `json:"entry,omitempty"`
	Store    string `json:"store,omitempty"`
	Detail   string `json:"detail"`
	Key      string `json:"node_key"`
}

// codeFlaws returns the graph's end-to-end detections (graph.Detect).
func (b *brain) codeFlaws() []flawView {
	out := []flawView{}
	for _, d := range graph.Detect(b.a.G, b.a.Root) {
		v := flawView{
			Rule: d.Rule, Severity: d.Severity, Title: d.Title, At: b.a.Loc(d.Sink),
			Store: d.Store, Detail: d.Message, Key: d.Sink.Key,
		}
		if d.Entry.Kind != "" {
			v.Entry = b.a.Label(d.Entry)
		}
		out = append(out, v)
	}
	return out
}

// --- trace_dataflow ---

type accessView struct {
	Store  string `json:"store"`
	Access string `json:"access"`
	At     string `json:"at"`
}

type traceView struct {
	Function   string       `json:"function"`
	At         string       `json:"at"`
	Key        string       `json:"node_key"`
	Entrypoint bool         `json:"entrypoint"`
	LoginCheck bool         `json:"login_check"`
	Exposed    bool         `json:"reachable_without_login"`
	ClientSide bool         `json:"client_side,omitempty"`
	Sensitive  bool         `json:"sensitive,omitempty"`
	Categories []string     `json:"categories,omitempty"`
	ReachedBy  []string     `json:"reached_from,omitempty"`
	Calls      []string     `json:"calls,omitempty"`
	Data       []accessView `json:"data,omitempty"`
	Sinks      []sinkView   `json:"dangerous_calls,omitempty"`
}

func handleTraceDataflow(project projectFunc) server.ToolHandlerFunc {
	return withBrain(project, func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult {
		target := strings.TrimSpace(req.GetString("target", ""))
		if target == "" {
			return mcp.NewToolResultError("missing required parameter: target")
		}
		ids := b.resolveFuncs(target)
		if len(ids) == 0 {
			if b.storeNode(target) >= 0 {
				return mcp.NewToolResultText(fmt.Sprintf("%q is a datastore, not a function. Use what_touches to see the code that reads and writes it.", target))
			}
			return mcp.NewToolResultText(fmt.Sprintf("No route or function matching %q in the code graph. Use get_attack_surface to list routes.", target))
		}
		return fitJSON(15, func(n int) any {
			var views []traceView
			for _, id := range capN(ids, 3) {
				views = append(views, b.trace(id, n))
			}
			out := map[string]any{"matches": len(ids), "results": views}
			if len(ids) > 3 {
				out["note"] = "more than 3 matches; pass a route or node key to narrow it"
			}
			return out
		})
	})
}

func (b *brain) trace(id, n int) traceView {
	node := b.a.G.Nodes[id]
	d := b.a.Downstream(id)
	info := b.a.ForNode(id)
	v := traceView{
		Function: b.funcLabel(node), At: b.a.Loc(node), Key: node.Key,
		Entrypoint: node.Source, LoginCheck: node.Guarded || info.Guarded,
		Exposed: b.a.Exposed(id), ClientSide: info.ClientSide,
		Sensitive: d.Sensitive, Categories: d.Categories, ReachedBy: info.Entrypoints,
	}
	for _, f := range d.Funcs {
		fn := b.a.G.Nodes[f]
		if f != id && len(v.Calls) < n {
			v.Calls = append(v.Calls, fmt.Sprintf("%s (%s)", reach.Symbol(fn), b.a.Loc(fn)))
		}
		for _, e := range b.a.Accesses(f) {
			if e.Kind == graph.EdgeContains || len(v.Data) >= n {
				continue
			}
			v.Data = append(v.Data, accessView{Store: b.a.G.Nodes[e.Dst].Name, Access: string(e.Kind), At: b.a.Loc(fn)})
		}
	}
	v.Sinks = b.sinks(d.Sinks, n/2+1)
	return v
}

// resolveFuncs finds function nodes for a node key, a route, or a name.
func (b *brain) resolveFuncs(target string) []int {
	g := b.a.G
	var exact, routes, partial []int
	lower := strings.ToLower(target)
	routeLike := strings.Contains(target, "/")
	for _, n := range g.Nodes {
		if n.Kind != graph.KindFunc {
			continue
		}
		if n.Key == target {
			return []int{n.ID}
		}
		if routeLike && n.Source {
			l := b.a.Label(n)
			if strings.EqualFold(l, target) || strings.HasSuffix(strings.ToLower(l), " "+lower) {
				routes = append(routes, n.ID)
			}
			continue
		}
		sym := reach.Symbol(n)
		switch {
		case sym == target || n.Name == target:
			exact = append(exact, n.ID)
		case strings.Contains(strings.ToLower(n.Name), lower):
			partial = append(partial, n.ID)
		}
	}
	for _, list := range [][]int{routes, exact, partial} {
		if len(list) > 0 {
			return list
		}
	}
	return nil
}

func (b *brain) storeNode(name string) int {
	for _, n := range b.a.G.Nodes {
		if n.Kind == graph.KindDataStore && (strings.EqualFold(n.Name, name) || n.Key == name) {
			return n.ID
		}
	}
	return -1
}

// --- what_touches ---

type toucherView struct {
	Function   string   `json:"function"`
	At         string   `json:"at"`
	Touches    string   `json:"touches"`
	Exposed    bool     `json:"reachable_without_login"`
	ClientSide bool     `json:"client_side,omitempty"`
	ReachedBy  []string `json:"reached_from,omitempty"`
	Key        string   `json:"node_key"`
	rank       int
}

func handleWhatTouches(project projectFunc) server.ToolHandlerFunc {
	return withBrain(project, func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult {
		target := strings.TrimSpace(req.GetString("target", ""))
		if target == "" {
			return mcp.NewToolResultError("missing required parameter: target")
		}
		g := b.a.G
		stores := map[int]bool{}
		for _, n := range g.Nodes {
			if n.Kind == graph.KindDataStore && nameMatches(n.Name, target) {
				stores[n.ID] = true
			}
		}
		cats := b.matchCategories(target)

		var items []toucherView
		seen := map[string]bool{}
		add := func(fid int, touches string) {
			fn := g.Nodes[fid]
			if seen[fn.Key+touches] {
				return
			}
			seen[fn.Key+touches] = true
			info := b.a.ForNode(fid)
			v := toucherView{
				Function: b.funcLabel(fn), At: b.a.Loc(fn), Touches: touches,
				Exposed: b.a.Exposed(fid), ClientSide: info.ClientSide, ReachedBy: capN(info.Entrypoints, 2), Key: fn.Key,
			}
			if v.Exposed || v.ClientSide {
				v.rank += 4
			}
			if strings.HasPrefix(touches, "writes") {
				v.rank += 2
			}
			items = append(items, v)
		}
		for _, e := range g.Edges {
			if (e.Kind == graph.EdgeReads || e.Kind == graph.EdgeWrites) && stores[e.Dst] {
				add(e.Src, string(e.Kind)+" "+g.Nodes[e.Dst].Name)
			}
		}
		for _, n := range g.Nodes {
			if n.Kind != graph.KindFunc {
				continue
			}
			tagged := strings.Split(n.Tags[orgcontext.TagSensitiveCategory], ",")
			for _, c := range cats {
				for _, t := range tagged {
					if strings.EqualFold(t, c) {
						add(n.ID, "category "+c)
					}
				}
			}
			if len(cats) == 0 && isPIIQuery(target) && n.PII {
				add(n.ID, "personal data")
			}
		}
		if len(items) == 0 {
			var names []string
			for _, n := range g.Nodes {
				if n.Kind == graph.KindDataStore {
					names = append(names, n.Name)
				}
			}
			var catNames []string
			if b.ctx != nil {
				for _, c := range b.ctx.SensitiveData {
					catNames = append(catNames, c.Category)
				}
			}
			out, _ := json.Marshal(map[string]any{
				"matches":              0,
				"note":                 fmt.Sprintf("Nothing in the code graph touches %q.", target),
				"known_datastores":     capN(names, 40),
				"sensitive_categories": catNames,
				"hint":                 "Pass one of the names above. Add sensitive data categories with update_project_context.",
			})
			return mcp.NewToolResultText(string(out))
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].rank > items[j].rank })
		return fitJSON(30, func(n int) any {
			out := map[string]any{"target": target, "matches": len(items), "items": capN(items, n)}
			if len(items) > n {
				out["truncated"] = fmt.Sprintf("showing %d of %d, exposed first", n, len(items))
			}
			return out
		})
	})
}

// nameMatches compares datastore names loosely: case and a plural "s".
func nameMatches(name, target string) bool {
	a, b := strings.ToLower(name), strings.ToLower(target)
	return a == b || strings.TrimSuffix(a, "s") == strings.TrimSuffix(b, "s")
}

func isPIIQuery(t string) bool {
	switch strings.ToLower(t) {
	case "pii", "personal", "personal data", "personal information":
		return true
	}
	return false
}

// matchCategories returns the context's sensitive categories matching target.
func (b *brain) matchCategories(target string) []string {
	if b.ctx == nil {
		return nil
	}
	var out []string
	for _, c := range b.ctx.SensitiveData {
		if nameMatches(c.Category, target) || strings.Contains(strings.ToLower(c.Category), strings.ToLower(target)) {
			out = append(out, c.Category)
		}
	}
	return out
}

// --- get_security_history ---

func handleSecurityHistory(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if !hasMemory(projectPath) {
			return mcp.NewToolResultText("Trojan has no history for this project yet. It records one when findings are fixed, verified, dismissed or confirmed."), nil
		}
		store, err := memory.Open(projectPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		defer store.Close()

		var events []memory.Event
		filter := "latest"
		switch {
		case req.GetString("node_key", "") != "":
			filter = "node_key"
			events, err = store.ForKey(req.GetString("node_key", ""))
		case req.GetString("file", "") != "":
			filter = "file"
			events, err = store.ForFile(relPath(projectPath, req.GetString("file", "")))
		case req.GetString("rule", "") != "":
			filter = "rule"
			events, err = store.ByRule(req.GetString("rule", ""))
		default:
			events, err = store.All()
		}
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		type ev struct {
			Kind     string `json:"kind"`
			Title    string `json:"title"`
			File     string `json:"file,omitempty"`
			Rule     string `json:"rule,omitempty"`
			Key      string `json:"node_key,omitempty"`
			Evidence string `json:"evidence,omitempty"`
			Source   string `json:"source"`
			When     string `json:"when"`
		}
		var rows []ev
		for i := len(events) - 1; i >= 0; i-- { // newest first
			e := events[i]
			evid := e.Evidence
			if len(evid) > 200 {
				evid = evid[:200] + "..."
			}
			rows = append(rows, ev{string(e.Kind), e.Title, e.File, e.RuleID, e.NodeKey, evid, string(e.Source), e.At.Format("2006-01-02")})
		}
		return fitJSON(30, func(n int) any {
			out := map[string]any{"filter": filter, "total": len(rows), "events": capN(rows, n)}
			if len(rows) > n {
				out["truncated"] = fmt.Sprintf("showing the newest %d of %d", n, len(rows))
			}
			return out
		}), nil
	}
}

func hasMemory(projectPath string) bool {
	_, err := os.Stat(filepath.Join(projectPath, filepath.FromSlash(memory.DefaultDBPath)))
	return err == nil
}

// --- search_code_security ---

// newEmbedder builds the embedder for semantic search. A variable so tests
// can swap in a fake (tests make no network calls).
var newEmbedder = func(accessToken string) rag.Embedder { return ai.NewEmbedder(accessToken) }

func handleSearchCodeSecurity(project projectFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectPath, err := project(ctx, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		query := strings.TrimSpace(req.GetString("query", ""))
		if query == "" {
			return mcp.NewToolResultError("missing required parameter: query"), nil
		}
		if !rag.ProjectHasIndex(projectPath) {
			return mcp.NewToolResultText("This project has no semantic index yet, so search by meaning isn't available. " +
				"The user can build one with `trojan index` in the project folder. Meanwhile, use trace_dataflow or what_touches to find code by route, function or table."), nil
		}
		token := ""
		if cfg, err := config.LoadConfig(); err == nil {
			token = cfg.AccessToken
		}
		if token == "" {
			return mcp.NewToolResultText("Semantic search needs a signed-in Trojan account. Use trace_dataflow or what_touches instead."), nil
		}
		r, err := rag.NewRetriever(projectPath, newEmbedder(token))
		if err != nil {
			return mcp.NewToolResultError("could not load the semantic index: " + err.Error()), nil
		}
		limit := int(req.GetFloat("limit", 6))
		if limit < 1 || limit > 10 {
			limit = 6
		}
		results, err := r.Retrieve(query, limit)
		if err != nil {
			return mcp.NewToolResultError("search failed: " + err.Error()), nil
		}
		type hit struct {
			At      string  `json:"at"`
			Symbol  string  `json:"symbol,omitempty"`
			Score   float64 `json:"score"`
			Snippet string  `json:"snippet"`
		}
		var hits []hit
		for _, res := range results {
			snip := res.Chunk.Text
			if len(snip) > 500 {
				snip = snip[:500] + "..."
			}
			hits = append(hits, hit{
				At:     fmt.Sprintf("%s:%d-%d", res.Chunk.FilePath, res.Chunk.StartLine, res.Chunk.EndLine),
				Symbol: res.Chunk.Symbol, Score: float64(int(res.Score*1000)) / 1000, Snippet: snip,
			})
		}
		return fitJSON(len(hits), func(n int) any {
			return map[string]any{"query": query, "results": capN(hits, n)}
		}), nil
	}
}
