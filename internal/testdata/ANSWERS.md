# Fixture answer key

Three small apps with planted security issues. Used by graph, fingerprint, reachability and MCP tests, and by the final end-to-end check.

Rule for tests: every FLAG must be detected; every SAFE must NOT be reported as an unauthenticated path. The canary value `TROJAN_CANARY_DO_NOT_LEAK_7731` (vibeapp/.env) must never appear in any Trojan output, graph node, fingerprint, or edge payload.

## vibeapp (Next.js + Supabase)

| ID | File | Expectation |
|---|---|---|
| 1 | app/api/orders/route.ts POST | FLAG: public route writes datastore `orders`, no auth check. Reached through cross-file helper lib/supabase/server.ts. |
| 2 | app/api/profile/route.ts GET | SAFE: calls supabase.auth.getUser() and returns 401 if no user. Reads `profiles`. |
| 3 | components/AdminPanel.tsx | FLAG: "use client" file imports the service-role client (lib/supabase/admin.ts) and deletes from `profiles`. ClientSide = true. |
| 4 | app/actions.ts deletePost | FLAG: "use server" action (an entrypoint) deletes from `posts`, no auth check. |
| 5 | app/api/export/route.ts GET | FLAG: raw SQL built by string concat from a query param (pg pool.query). |
| - | middleware.ts | Matcher covers only /dashboard/:path*, so it does NOT guard /api routes. |

Datastores (from supabase/migrations): orders, profiles, posts, invoices.
Env var names: NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY, DATABASE_URL.
Third party: supabase, stripe. Framework: nextjs.

## expressapp (Express + Supabase + pg)

| ID | File | Expectation |
|---|---|---|
| E1 | server.js POST /api/notes | SAFE: requireAuth middleware on the route. Writes `notes`. |
| E2 | server.js DELETE /api/notes/:id | FLAG: deletes from `notes`, no auth. |
| E3 | server.js GET /api/search | FLAG: raw SQL from req.query via pool.query concat. |
| E4 | routes/users.js GET /api/users/:id | FLAG: cross-file router mounted in server.js; reads `users` by id, no auth. |
| - | GET /health | Public, touches nothing. Not a finding. |

lib/db.js creates a service-role Supabase client on the server (fine on the server; only a problem if reached from client code).

## storeapp (Next.js + better-sqlite3, end-to-end code flaws)

Exercises graph.Detect / the `trojan` scanner (scanners.GraphChecks) and get_attack_paths `code_flaws`. Modeled on a real miss: login SQL built with a template literal, and a public contact form rendered as raw HTML on the admin page.

| ID | File | Expectation |
|---|---|---|
| S1 | app/api/auth/login/route.ts POST | FLAG (critical, `trojan.sql-injection`): `prepare(\`... '${email}' ...\`)` with email from `req.json()`, no auth. |
| S2 | app/api/auth/login-safe/route.ts POST | SAFE: bound `?` parameter. Not concat, not request-input SQL. |
| S3 | app/api/search/route.ts GET | SAFE: postgres.js tagged template `sql\`... ${q}\``. No SQL sink flagged. |
| S4 | app/api/stats/route.ts GET | SAFE: @vercel/postgres `sql\`\`` and `db.execute(sql\`...\`)`. Plain "SQL query execution" sink only. |
| S5 | app/api/report/route.ts GET | SAFE as a finding: interpolates a constant column list. Kept as a concat sink (graph fact), never request-input SQL. |
| S6 | app/admin/page.tsx | FLAG (high, `trojan.stored-xss`): fetches `/api/admin/messages` (guarded GET reading `messages`) and renders `m.body` with dangerouslySetInnerHTML; `messages` is written by the public POST /api/contact. |
| S7 | app/notes/page.tsx | SAFE as a finding: raw-HTML sink, but `notes` is only written by a logged-in route. |
| S8 | app/inbox/page.tsx | SAFE: value passed through DOMPurify.sanitize, so not a sink. |
| - | lib/db.ts seed() | getDb() seeds users/notes/messages on first use; these writes must not count as public routes writing those tables. |

Exactly 2 findings: S1 and S6. Fixing S1 (bound parameters) and S6 (render as text) leaves 0. vibeapp #5 (export) is also reported as `trojan.sql-injection`; no other fixture produces code flaws.

## pyapp (FastAPI + Flask + Supabase + psycopg2)

| ID | File | Expectation |
|---|---|---|
| P1 | main.py POST /items | FLAG: writes `items`, no auth. |
| P2 | main.py GET /me | SAFE: Depends(get_current_user). Reads `profiles`. |
| P3 | main.py GET /search | FLAG: raw SQL f-string from query param into cursor.execute (via cross-file db.get_conn). |
| P4 | flask_app.py POST /admin/delete/<item_id> | FLAG: deletes from `items`, no login_required. |
| P5 | flask_app.py GET /account | SAFE: @login_required. Reads `profiles`. |
