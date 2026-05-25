# Trojan — Build Progress

## Completed

### Phase 0 — Repo Setup
- Go module initialised, monorepo structure (`cmd/`, `internal/`, `ui/`, `docs/`)
- First binary compiles and runs

### Phase 1 — Semgrep Scanner MVP
- Semgrep scanner integrated as subprocess
- Terminal output with findings summary
- Results persisted to `.trojan/` directory

### Phase 2 — All 5 Scanners
- Trivy (SCA), Gitleaks (secrets), Checkov (IaC), Syft (SBOM) added
- All scanners run in parallel goroutines with `sync.WaitGroup`
- Finding deduplication and progress bar

### Phase 3 — Local Web UI
- React + Vite + TypeScript + Tailwind + shadcn/ui built and embedded in the Go binary via `embed.FS`
- HTTP API at `localhost:7878` serves the report
- Editorial aesthetic, dark mode, findings preview, Pro placeholders
- VS Code deep links, export support

### Phase 4 — Distribution
- goreleaser config for multi-platform builds (macOS arm64/amd64, Linux)
- Homebrew tap formula
- `install.sh` one-line install script
- `trojan update` command for self-update
- Auto-installs scanners on first run

### Phase 5 — Paid Tier Backend
- Supabase Edge Functions (Deno runtime):
  - `synthesize` — calls Claude Haiku, caches AI output per finding
  - `checkout` — creates Stripe checkout session for Pro/Team
  - `stripe-webhook` — handles subscription lifecycle events
  - `license` — returns `{ isPro, subscriptionStatus, email }` for CLI auth check
- GitHub OAuth via Supabase Auth
- Stripe sandbox wired with webhook secret
- Local AI cache at `~/.trojan/cache/[ruleID]-[scanner].json`
- `trojan login` triggers OAuth, fetches license, stores `IsPro` in local config
- UI banner: "Log in" for unauthenticated users, "Upgrade to Pro" for free-tier users
- FindingDetail shows real AI content (Simply + Actions) for Pro, locked placeholder for free

### Phase 6 (partial) — Developer Workflow Features
- `trojan ci` — CI mode outputting SARIF 2.1.0 to stdout/file, exits 1 on findings above severity threshold
  - `--output <file>` flag writes SARIF to file instead of stdout
  - `--severity <level>` flag sets exit threshold (default: high)
  - Compatible with GitHub Code Scanning (`github/codeql-action/upload-sarif`)
- `trojan hook install` — writes `# trojan`-marked pre-commit hook to `.git/hooks/pre-commit`
- `trojan hook uninstall` — removes only Trojan-owned hooks, leaves custom ones untouched
- `trojan scan --pre-commit` — silent scan, no browser/UI, exits 1 on Critical/High findings
- `trojan mcp install` — auto-configures Claude Code, Cursor, and Codex CLI
  - Pro-gated: checks JWT claims, returns clear upgrade error for free users
  - Terminal output says "vulnerability findings" consistently
- `internal/ci/sarif.go` — `BuildSARIF()` / `MarshalSARIF()` with SARIF 2.1.0 spec
- `internal/hook/hook.go` — `Install()` / `Uninstall()` with ownership marker

### Phase 8 (partial) — Marketing Website
Work started early since the site supports the Phase 5 upgrade flow.

- `trojan-web/frontend` — Next.js 16 App Router, React 19, Tailwind v4, Montserrat font
- **Homepage** (`/`) — waves hero, typing animation, terminal preview, scanner features table, "Why Trojan" (6 items), MCP section, tech logo loop, reviews carousel, CTA
- **Pricing** (`/pricing`) — 3-tier cards (Free / Pro $15 / Team $99), FAQ, hatch-pattern side decoration
  - Free: up to 5 low & medium reports; critical/high locked
  - Pro: full reports, AI explanations, MCP integration
- **Docs** (`/docs`) — full standard docs layout with sticky sidebar nav
  - Sections: Installation, First scan, Commands, CI integration, Pre-commit hook, AI features, MCP integration
  - All new CLI commands documented (`hook`, `ci`, `scan --pre-commit`, `mcp install`)
  - CI section includes GitHub Actions SARIF example
- **Supabase auth** — server-side session with `@supabase/ssr`, resilient to missing env vars
- **Vercel deployment** — middleware (`proxy.ts`) guards session refresh, gracefully degrades when env vars absent
- **Mobile responsiveness** (full pass, May 2026):
  - Fixed `LogoLoop` track overflow — primary cause of horizontal scroll
  - Fixed scanner table `grid-cols-[80px_140px_1fr]` — stacked on mobile, 3-column on sm+
  - Responsive hero heading (`text-3xl sm:text-4xl lg:text-5xl`)
  - Hatch panels hidden on mobile (`hidden lg:block`) to prevent overflow bleed
  - `border-x` on pricing main scoped to `lg:` only
  - Hard `<br />` in MCP section h2 removed
  - Nav logo `shrink-0`, reduced height on mobile (`h-10 sm:h-14`), tighter button gap
  - Explicit `viewport` export in `app/layout.tsx` (`width=device-width, initialScale=1, maximumScale=1`)
  - All section paddings converted to `px-4 sm:px-8` and `py-16 sm:py-24`

---

## Up Next

### Phase 6 (completed) — Developer Workflow Features
All Phase 6 work is done. See the Phase 6 (partial) entry above for the earlier items.

- `trojan scan --watch` — `fsnotify` recursive watcher, 1.5s debounce, re-runs all scanners on change
  - Ignores `.git/`, `.trojan/`, `node_modules/`, `vendor/`, binary extensions
  - Dynamically adds newly created directories to the watch set
  - Calls `srv.UpdateScan()` after each re-scan to swap data atomically
  - Browser report updates automatically via SSE (no reload needed)
- SSE endpoint `/api/events` in `internal/server/server.go`
  - Pure stdlib — no additional Go dependency
  - 25s keepalive ping prevents proxy timeouts
  - `UpdateScan()` notifies all connected clients in a non-blocking send
- UI (`ui/src/App.tsx` + `api.ts`) subscribes on mount via `EventSource`
  - Shows "Rescanning…" pulse badge in header during re-scan
  - Cleans up `EventSource` on unmount
- `internal/watcher/watcher.go` — standalone package, `New(dir, onChange)` + `Stop()`

### Phase 7 — Public Launch
- Polish GitHub repo: README screenshots/GIFs, CONTRIBUTING.md, issue templates, SECURITY.md
- Test on 10+ real open-source projects, fix edge cases and false positive rates
- Beta test with 5-10 friendly developers
- Hacker News "Show HN" post
- Product Hunt launch
- /r/programming, /r/devops, /r/golang posts
- Tweet thread with demo video

### Phase 8 (remaining) — Marketing Site & Dashboard
- `/privacy` and `/terms` legal pages (required before public launch)
- Customer dashboard — subscription status, billing portal, team seat management
- Blog / changelog pages
- Analytics (PostHog for product, Plausible for marketing)
- Error monitoring (Sentry)
- Status page (status.trojan.dev)
