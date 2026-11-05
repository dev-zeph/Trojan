package mcpserver

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/fingerprint"
	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/memory"
)

// ── get_security_rules ───────────────────────────────────────────────────────
//
// Deterministic (no AI) invariants for one project, assembled from what its
// stack is (fingerprint), what the user told Trojan (context.yaml), what
// Trojan learned (memory facts) and where the code graph shows each rule is
// already broken. The AI tool calls this before writing auth, database or API
// code, so new code follows the project's rules instead of generic advice.

// securityRule is one invariant, with the code that currently breaks it.
type securityRule struct {
	Area     string   `json:"area"`
	Rule     string   `json:"rule"`
	Why      string   `json:"why,omitempty"`
	BrokenAt []string `json:"broken_at,omitempty"`
	From     string   `json:"from"`
}

var ruleAreas = map[string]bool{"auth": true, "database": true, "api": true, "client": true, "payments": true, "all": true}

func handleSecurityRules(project projectFunc) server.ToolHandlerFunc {
	return withBrain(project, func(b *brain, req mcp.CallToolRequest) *mcp.CallToolResult {
		area := strings.ToLower(strings.TrimSpace(req.GetString("area", "all")))
		if area == "" {
			area = "all"
		}
		if !ruleAreas[area] {
			return mcp.NewToolResultError(`area must be "auth", "database", "api", "client", "payments" or "all"`)
		}
		fp, _ := fingerprint.Collect(b.root)
		rules := b.securityRules(fp)
		var picked []securityRule
		for _, r := range rules {
			if area == "all" || r.Area == area || r.Area == "general" {
				picked = append(picked, r)
			}
		}
		stack := detectStack(fp)
		return fitJSON(8, func(n int) any {
			out := make([]securityRule, len(picked))
			for i, r := range picked {
				r.BrokenAt = capN(r.BrokenAt, n)
				out[i] = r
			}
			return map[string]any{
				"stack": stack.names(),
				"area":  area,
				"rules": out,
				"note":  "Follow these in new code. broken_at lists existing code that breaks the rule today.",
			}
		})
	})
}

// stack is what the project is built with, as the rules care about it.
type stack struct {
	next, express, fastapi, flask, supabase, stripe, pgNode, pyPG, prisma, mongo bool
}

func (s stack) names() []string {
	var out []string
	for _, x := range []struct {
		on   bool
		name string
	}{{s.next, "nextjs"}, {s.express, "express"}, {s.fastapi, "fastapi"}, {s.flask, "flask"}, {s.supabase, "supabase"},
		{s.stripe, "stripe"}, {s.pgNode || s.pyPG, "postgres"}, {s.prisma, "prisma"}, {s.mongo, "mongodb"}} {
		if x.on {
			out = append(out, x.name)
		}
	}
	return out
}

func detectStack(fp fingerprint.Fingerprint) stack {
	deps := map[string]bool{}
	for _, d := range fp.Dependencies {
		deps[strings.ToLower(d)] = true
	}
	third := map[string]bool{}
	for _, t := range fp.ThirdParty {
		third[t] = true
	}
	return stack{
		next:     fp.Framework == "nextjs" || deps["next"],
		express:  fp.Framework == "express" || deps["express"],
		fastapi:  fp.Framework == "fastapi" || deps["fastapi"],
		flask:    fp.Framework == "flask" || deps["flask"],
		supabase: third["supabase"],
		stripe:   third["stripe"],
		pgNode:   deps["pg"] || deps["postgres"],
		pyPG:     deps["psycopg2"] || deps["psycopg2-binary"] || deps["psycopg"] || deps["asyncpg"],
		prisma:   third["prisma"],
		mongo:    third["mongodb"],
	}
}

// openRoute is a public entrypoint without a login check that touches data
// or a dangerous call: what the auth rules flag as broken.
type openRoute struct {
	label, at, file string
}

func (b *brain) openRoutes() []openRoute {
	var out []openRoute
	for _, n := range b.a.G.Nodes {
		if n.Kind != graph.KindFunc || !n.Source || n.Guarded {
			continue
		}
		d := b.a.Downstream(n.ID)
		if len(d.Reads)+len(d.Writes)+len(d.Sinks) == 0 {
			continue
		}
		var touches []string
		for _, w := range d.Writes {
			touches = append(touches, "writes "+w)
		}
		for _, r := range d.Reads {
			touches = append(touches, "reads "+r)
		}
		desc := b.a.Label(n)
		if len(touches) > 0 {
			desc += ", " + strings.Join(capN(touches, 2), ", ")
		}
		out = append(out, openRoute{label: desc, at: b.a.Loc(n), file: b.a.Rel(n.File)})
	}
	return out
}

func (b *brain) securityRules(fp fingerprint.Fingerprint) []securityRule {
	st := detectStack(fp)
	open := b.openRoutes()
	var rules []securityRule
	add := func(area, from, rule, why string, broken []string) {
		rules = append(rules, securityRule{Area: area, Rule: rule, Why: why, BrokenAt: broken, From: from})
	}
	fileText := map[string]string{}
	textOf := func(rel string) string {
		if t, ok := fileText[rel]; ok {
			return t
		}
		data, _ := os.ReadFile(filepath.Join(b.root, rel))
		fileText[rel] = strings.ToLower(string(data))
		return fileText[rel]
	}
	brokenWhere := func(keep func(openRoute) bool) []string {
		var out []string
		for _, r := range open {
			if keep(r) {
				out = append(out, fmt.Sprintf("%s (%s)", r.label, r.at))
			}
		}
		return out
	}
	isJS := func(r openRoute) bool { return isJSFile(r.file) }
	isPy := func(r openRoute) bool { return strings.HasSuffix(r.file, ".py") }

	var tables []string
	for _, n := range b.a.G.Nodes {
		if n.Kind == graph.KindDataStore {
			tables = append(tables, n.Name)
		}
	}
	var exposures, sqlConcat []string
	for _, e := range b.a.G.ClientExposures() {
		exposures = append(exposures, fmt.Sprintf("%s reaches %s (%s)", path.Base(b.a.Rel(e.Client.File)), e.Reached.SinkRule, b.a.Loc(e.Reached)))
	}
	for _, n := range b.a.G.Nodes {
		if n.Kind == graph.KindSink && n.Severity == "high" && strings.Contains(n.SinkRule, "SQL") {
			sqlConcat = append(sqlConcat, b.a.Loc(n))
		}
	}

	// ── Supabase ──
	if st.supabase {
		why := "Supabase tables are reachable from the browser with the public anon key; RLS is the only thing stopping anyone reading or changing every row."
		if len(tables) > 0 {
			why += " Tables found: " + strings.Join(capN(tables, 12), ", ") + "."
		}
		add("database", "supabase", "Enable Row Level Security on every table and add policies that limit rows to their owner (auth.uid() = user_id) before shipping.", why, nil)
		add("database", "supabase", "When reading or writing user rows, also filter by the signed-in user's id (e.g. .eq(\"user_id\", user.id)); never take the user id from the request body.", "", nil)
		add("client", "supabase", "Never import the service-role client (SUPABASE_SERVICE_ROLE_KEY) in 'use client' files or anything they import. Only server code may create it, and only for admin work.",
			"The service-role key bypasses RLS; anything a client component imports ships to every visitor's browser.", exposures)
		if st.next {
			add("auth", "supabase+nextjs", "In every route handler and server action that reads or writes user data, call supabase.auth.getUser() and return 401 (or redirect) when there is no user. Don't trust getSession() on the server.",
				"getUser() verifies the token with Supabase; getSession() only reads the cookie, which the user controls.", brokenWhere(isJS))
		} else {
			add("auth", "supabase", "Verify the caller with supabase.auth.getUser(token) on the server before any read or write of user data.", "", nil)
		}
	}

	// ── Next.js ──
	if st.next {
		add("auth", "nextjs", "middleware.ts only protects the paths its matcher lists. Check auth inside each /api route handler and server action too; don't rely on middleware alone.", "", nil)
		add("api", "nextjs", "Every 'use server' function is a public POST endpoint anyone can call: validate its input and check the signed-in user (and their role for admin actions) inside it.", "", nil)
		var leaked []string
		for _, e := range fp.EnvVarNames {
			u := strings.ToUpper(e)
			if strings.HasPrefix(u, "NEXT_PUBLIC_") && (strings.Contains(u, "SECRET") || strings.Contains(u, "SERVICE_ROLE") || strings.Contains(u, "PRIVATE")) {
				leaked = append(leaked, e)
			}
		}
		add("client", "nextjs", "Only NEXT_PUBLIC_ env vars reach the browser. Never give a secret (service-role key, Stripe secret, database URL) a NEXT_PUBLIC_ name.", "", leaked)
	}

	// ── Express ──
	if st.express {
		add("auth", "express", "Put auth middleware on every route that reads or writes data: app.delete(\"/x\", requireAuth, handler), or router.use(requireAuth) before mounting a router.",
			"Express routes are public unless a middleware in front of them rejects the request.",
			brokenWhere(func(r openRoute) bool { return isJS(r) && expressRoute(r.label) }))
		add("api", "express", "Use helmet() and a rate limiter (express-rate-limit), and validate req.body, req.params and req.query (zod, joi) before using them.", "", nil)
	}

	// ── FastAPI / Flask ──
	if st.fastapi {
		add("auth", "fastapi", "Add user=Depends(get_current_user) to every route that reads or writes data, or set dependencies=[Depends(get_current_user)] on the APIRouter.", "",
			brokenWhere(func(r openRoute) bool { return isPy(r) && strings.Contains(textOf(r.file), "fastapi") }))
		add("api", "fastapi", "Declare request bodies as Pydantic models instead of reading request.json() directly, so FastAPI validates them.", "", nil)
	}
	if st.flask {
		add("auth", "flask", "Decorate every route that reads or writes data with @login_required (directly under @app.route), and check the user's role for admin routes.", "",
			brokenWhere(func(r openRoute) bool { return isPy(r) && strings.Contains(textOf(r.file), "flask") }))
		add("api", "flask", "Enable CSRF protection (Flask-WTF CSRFProtect) for form posts, and set SESSION_COOKIE_SECURE and SESSION_COOKIE_HTTPONLY.", "", nil)
	}

	// ── SQL ──
	if st.pgNode || st.pyPG || len(sqlConcat) > 0 {
		r := "Use parameterized queries: pool.query(\"... WHERE id = $1\", [id]) in Node, cursor.execute(\"... WHERE id = %s\", (id,)) in Python. Never build SQL with +, template strings or f-strings."
		add("database", "sql", r, "String-built SQL lets a request rewrite the query (SQL injection).", sqlConcat)
	}
	if st.prisma {
		add("database", "prisma", "Avoid $queryRawUnsafe and $executeRawUnsafe with request input; use the $queryRaw tagged template.", "", nil)
	}
	if st.mongo {
		add("database", "mongodb", "Never pass req.body or req.query objects straight into a MongoDB filter; pick and type the fields (operator injection).", "", nil)
	}

	// ── Stripe ──
	if st.stripe {
		add("payments", "stripe", "Keep STRIPE_SECRET_KEY on the server only. Compute prices and amounts on the server from your own data; never trust an amount or price id sent by the client.", "", nil)
		add("payments", "stripe", "Verify every webhook with stripe.webhooks.constructEvent(rawBody, signature, secret) before acting on it, and fulfil orders from the webhook, not the success page.", "", nil)
	}

	// ── Always ──
	add("api", "general", "Never build SQL, shell commands or file paths from request input, and never return stack traces or raw errors to the client.", "", nil)
	if len(open) > 0 && !st.next && !st.express && !st.fastapi && !st.flask {
		add("auth", "general", "Check the signed-in user in every public handler that reads or writes data.", "", brokenWhere(func(openRoute) bool { return true }))
	}

	// ── Project context ──
	if b.ctx != nil {
		for _, c := range b.ctx.SensitiveData {
			desc := c.Category
			if c.Description != "" {
				desc += " (" + c.Description + ")"
			}
			area := "database"
			if strings.Contains(strings.ToLower(c.Category), "pay") {
				area = "payments"
			}
			add(area, "project context", fmt.Sprintf("Treat %s as sensitive: only the signed-in owner (or an admin) may read or change it, never log it, and never send more of it to the browser than the page needs.", desc), "", nil)
		}
		if am := b.ctx.AuthModel; am != nil {
			if len(am.Roles) > 0 || am.AdminArea {
				roles := strings.Join(am.Roles, ", ")
				if roles == "" {
					roles = "admin"
				}
				add("auth", "project context", fmt.Sprintf("This app has roles (%s): check the user's role on the server before any admin or role-restricted action, never only in the UI.", roles), "", nil)
			}
		}
		for _, l := range capN(b.ctx.Learned, 5) {
			add("general", "project context", l.Fact, l.Evidence, nil)
		}
	}

	// ── Memory ──
	if hasMemory(b.root) {
		if store, err := memory.Open(b.root); err == nil {
			events, _ := store.All()
			store.Close()
			n := 0
			for i := len(events) - 1; i >= 0 && n < 5; i-- {
				e := events[i]
				switch e.Kind {
				case memory.KindFact:
					add("general", "trojan memory", e.Title, e.Evidence, nil)
					n++
				case memory.KindAcceptedRisk:
					add("general", "trojan memory", "Accepted risk, don't re-raise: "+e.Title, e.File, nil)
					n++
				}
			}
		}
	}
	return rules
}

func isJSFile(f string) bool {
	switch path.Ext(f) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// expressRoute reports whether an entrypoint label is an Express route
// ("DELETE /api/notes/:id, writes notes").
func expressRoute(label string) bool {
	sp := strings.IndexByte(label, ' ')
	return sp > 0 && sp+1 < len(label) && label[sp+1] == '/' && strings.ToUpper(label[:sp]) == label[:sp] && label[:sp] != "ANY"
}
