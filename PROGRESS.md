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
- Auth callback page redesigned with Montserrat font and pulse animation

### Phase 8 (partial) — Marketing Website
Work started early since the site supports the Phase 5 upgrade flow.

- `trojan-web/frontend` — Next.js 16 App Router, React 19, Tailwind v4, Montserrat font
- **Homepage** (`/`) — waves hero, typing animation, terminal preview, scanner features table, tech logo loop, reviews carousel, CTA
- **Pricing** (`/pricing`) — 3-tier cards (Free / Pro $15 / Team $99), FAQ, slanted line side decoration
- **Docs** (`/docs`) — Getting Started page with installation methods, commands table, AI features section, slanted line side decoration
- Shared components: `Nav`, `Footer`, `DrawnButton`, `WavesHero`, `WhyTrojan`, `TypingText`, `TechLoop`, `Reviews`

---

## Up Next

### Phase 6 — Developer Workflow Features
- `trojan scan --watch` — file watcher with fsnotify + WebSocket push to UI
- Pre-commit hook: `trojan hook install` blocks commits with Critical/High findings
- CI mode: `trojan ci` — exits non-zero on findings, outputs SARIF for GitHub Code Scanning

### Phase 7 — Public Launch
- Hacker News "Show HN" post
- Product Hunt launch
- Beta user onboarding and feedback loop

### Phase 8 (remaining) — Marketing Site & Dashboard
- Deploy `trojan-web` to Vercel at `trojan.dev`
- Customer dashboard (view subscription, manage seats, billing portal)
- `/privacy` and `/terms` pages
- Blog / changelog
