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

## pyapp (FastAPI + Flask + Supabase + psycopg2)

| ID | File | Expectation |
|---|---|---|
| P1 | main.py POST /items | FLAG: writes `items`, no auth. |
| P2 | main.py GET /me | SAFE: Depends(get_current_user). Reads `profiles`. |
| P3 | main.py GET /search | FLAG: raw SQL f-string from query param into cursor.execute (via cross-file db.get_conn). |
| P4 | flask_app.py POST /admin/delete/<item_id> | FLAG: deletes from `items`, no login_required. |
| P5 | flask_app.py GET /account | SAFE: @login_required. Reads `profiles`. |
