# Trojan

**A developer-first security CLI. Catch vulnerabilities before they ship.**

Trojan is a command-line tool that scans your codebase for security issues — vulnerable dependencies, leaked secrets, code-level vulnerabilities, and infrastructure misconfigurations — and opens a rich local web UI to walk you through every finding in plain English. Built in Go for single-binary distribution. Open-source core. Runs entirely on your machine. AI-powered explanations available as a paid tier.

> *"The trojan horse you actually want — one that finds the weaknesses before someone else does."*

---

## 1. The pitch

You're a developer shipping fast. AI tools (Cursor, Claude, v0, Lovable) have made it possible to build production apps in days. Security tooling has not kept up.

Existing tools (Snyk, Aikido, Sonar) require uploading your code to the cloud, are priced for enterprise teams, and produce reports written for security engineers — not the developers actually shipping the code.

Trojan is different:

- **Runs locally.** Your code never leaves your machine.
- **Single binary.** `brew install trojan` and you're done. No Node, no Python, no runtime required.
- **One command.** `trojan scan` and you're scanning.
- **Rich UI in your browser.** Not a wall of terminal text — a proper report at `localhost:7878`.
- **Plain-English explanations.** Not "CWE-89 detected at line 142." Real explanations of what's wrong, why it matters, and how to fix it.
- **Open source.** MIT-licensed core. Audit the code. Run it anywhere.
- **Multi-engine.** Wraps the best open-source scanners (Semgrep, Trivy, Gitleaks, Checkov, Syft) so you don't have to chain them yourself.
- **Pre-commit ready.** Stop vulnerabilities from ever hitting your repo.

For developers who care about security but don't have time to become security engineers.

---

## 2. Why this exists

**Three problems with the current market:**

1. **Cloud security tools are non-starters for many teams.** Regulated industries (fintech, healthtech, gov contractors, Canadian privacy-sensitive sectors) can't or won't upload proprietary code to a third-party cloud scanner. Local-first scanning is a hard requirement they're not being served on.

2. **Existing tools are built for security teams, not developers.** Snyk, Aikido, Sonar all assume the user is a security engineer who knows CWE classifications. The developer shipping a Next.js app at 11pm doesn't. They need explanations, not classifications.

3. **The setup tax kills adoption.** A serious developer who wants to lock down their project has to install and configure Semgrep, Trivy, Gitleaks, Checkov, Syft separately. Each has its own config file, output format, and quirks. Most devs don't bother. Trojan is the meta-tool that orchestrates all of them with one command.

**Trojan's structural advantage:** local execution + single-binary distribution + open-source core + AI synthesis layer is a combination no incumbent can easily match. Snyk and Aikido are structurally cloud-based — their business models depend on it. They can't pivot to local-first without rebuilding their entire stack.

---

## 3. How it works

### The user experience

**Install:**
```bash
brew install trojan
# or
curl -fsSL https://trojan.dev/install.sh | sh
# or for Go users
go install github.com/trojan/trojan@latest
```

One static binary. ~15MB. No runtime dependencies.

**First-time setup:**
```bash
$ trojan init
✓ Detected project: Next.js + TypeScript
✓ Installing scanners (Semgrep, Trivy, Gitleaks, Checkov, Syft)...
  This will use ~400MB of disk space. Continue? (y/n) y
✓ Scanners ready.
✓ Added .trojan/ to .gitignore
```

**Run a scan:**
```bash
$ trojan scan
  
  Scanning your project...
  
  [✓] Static analysis      (847 files, 12 findings)
  [✓] Dependencies          (247 packages, 3 vulnerabilities)
  [✓] Secrets               (full git history scanned, 1 leak)
  [✓] Infrastructure        (3 config files, 2 misconfigs)
  [✓] SBOM generated        (saved to .trojan/sbom.json)
  
  18 total findings — 2 critical, 4 high, 7 medium, 5 low
  
  → Report ready at http://localhost:7878
  → Press Ctrl+C to close
```

A browser tab opens automatically with the report.

**Common workflows:**

```bash
trojan scan --watch          # Re-scan on file save, live update UI
trojan scan --pre-commit     # Fast scan, fails on Critical/High
trojan ci                    # CI mode, outputs SARIF, no UI
trojan monitor               # Background daemon, alerts on new CVEs
trojan login                 # Authenticate for AI tier features
trojan update                # Update Trojan + scanner rule databases
```

### The local web UI

When `trojan scan` finishes, Trojan spins up an HTTP server on `127.0.0.1:7878` and opens the browser. The UI is a React app embedded inside the Go binary using Go's `embed` package — it ships as part of the binary, no separate files.

What it shows:

- **Dashboard:** severity breakdown, scan duration, project summary, trend vs last scan
- **Findings list:** filterable by severity, scanner, file, category, status
- **Finding detail view:**
  - Plain-English title and explanation (AI-generated for paid tier)
  - Vulnerable code snippet with the offending line highlighted
  - "Open in VS Code" button (uses `vscode://` URL protocol)
  - Real-world breach analog ("Same root cause as the MOVEit breach, 2023")
  - Suggested fix with diff preview
  - Buttons: "Mark resolved" / "Suppress this rule" / "Add exception"
- **SBOM viewer:** searchable, exportable inventory of all dependencies and licenses
- **Diff mode:** "3 new findings since last scan, 2 resolved"
- **Export:** PDF report, JSON, SARIF (for GitHub Code Scanning), HTML

The server only lives while the CLI process is running. Closing the terminal closes the server.

### What gets scanned

| Engine | Tool | Catches |
|--------|------|---------|
| **SAST** | Semgrep | Injection (SQL, command, LDAP), XSS, insecure crypto, path traversal, insecure deserialization |
| **SCA** | Trivy | Known CVEs in dependencies (npm, pip, gem, maven, go.mod, etc.), container vulns |
| **Secrets** | Gitleaks | Hardcoded API keys, tokens, passwords (current code + full git history) |
| **IaC** | Checkov | Terraform, Kubernetes, Dockerfile, CloudFormation misconfigurations |
| **SBOM** | Syft | Full software bill of materials, license compliance |

Each scanner runs in parallel as a goroutine spawning a subprocess. Output is normalized into a common schema. Duplicates are deduped.

### The AI synthesis layer (paid tier)

Raw scanner output is noise. The differentiator is the layer on top:

- **Plain-English explanations:** Claude rewrites each finding for the actual developer, not a security engineer.
- **Breach storytelling:** Findings tie to a curated database of real-world breaches with the same root cause.
- **Severity reassessment:** Adjusts severity based on the location of the finding and the project's context.
- **Fix suggestions:** Generated code diffs the user can apply directly.

Two delivery options:
1. **Trojan-hosted:** subscription includes API calls, you don't manage keys.
2. **Bring-your-own-key:** user provides their Anthropic API key, lower subscription cost.

---

## 4. Technical architecture

### Stack

**CLI core:**
- **Go** for the orchestrator, scanner wrappers, HTTP server
- Single static binary, cross-compiled for macOS (Intel + ARM), Linux, Windows
- Distributed via Homebrew, install script, Go install, direct download
- Embeds UI assets using Go's `embed` package

**Local server:**
- Go's standard library `net/http` (no framework needed)
- Binds to `127.0.0.1` only (never 0.0.0.0)
- Random high port (default 7878, auto-increments if taken)
- WebSocket support for `--watch` mode live updates

**Local UI:**
- React + Vite + TypeScript + Tailwind + shadcn/ui
- Built to static assets, embedded in Go binary
- Reads scan results via HTTP API endpoints served by the Go binary
- No external network calls (except for paid-tier AI calls, proxied through your backend)

**Scanners (subprocess wrappers):**
- Semgrep, Trivy, Gitleaks, Checkov, Syft
- Each invoked via Go's `os/exec`
- JSON output parsed and normalized
- Installed via `trojan init` on first run (not bundled — too large)

**Cloud backend (paid tier only):**
- Node.js + Fastify + Postgres + Stripe + Claude API
- Hosted on Railway or Fly.io initially
- Handles: auth, subscriptions, AI proxy, license validation
- Minimal — most logic stays in the CLI

**Local storage:**
- Scan results: `.trojan/scans/[timestamp].json` in the user's repo
- Config: `~/.trojan/config.json` (auth tokens, preferences)
- Cache: `~/.trojan/cache/` (LLM responses, scanner rule snapshots)

### Why Go over Node

- **Single static binary distribution.** Brew install works cleanly. No Node runtime required on user's machine.
- **Zero npm supply chain warnings.** Critical for a security tool — `npm audit` warnings on a security product is a credibility-killer.
- **Native concurrency.** Goroutines are perfect for parallel scanner orchestration.
- **Performance.** Faster cold start, lower memory, no JIT warmup. Matters for `--watch` mode and pre-commit hooks.
- **Ecosystem fit.** Trivy and Gitleaks are written in Go. Most modern security tooling is Go.
- **Cross-compilation.** `GOOS=darwin GOARCH=arm64 go build` produces a Mac ARM binary from any platform.

The TypeScript/React UI is embedded in the Go binary using `embed.FS`. Two languages, one binary, clean separation.

### Scan pipeline

```
User runs `trojan scan`
        ↓
┌─────────────────────────┐
│  Go CLI starts          │
│  Detect project type    │
│  Determine scanners     │
└──────────┬──────────────┘
           ↓
┌─────────────────────────────────────────────┐
│  Parallel goroutines, each spawning a       │
│  subprocess for one scanner                 │
│                                             │
│  ┌──────┐  ┌──────┐  ┌────────┐  ┌──────┐ │
│  │ SAST │  │ SCA  │  │Secrets │  │ IaC  │ │
│  └───┬──┘  └──┬───┘  └───┬────┘  └───┬──┘ │
│      │       │           │           │     │
│      └───────┴─────┬─────┴───────────┘     │
└────────────────────┼────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│  Normalize findings into common schema      │
│  Deduplicate across scanners                │
│  Assign severity_adjusted                   │
└────────────────────┬────────────────────────┘
                     ↓
            ┌────────┴────────┐
            │  Paid tier?     │
            └────────┬────────┘
              No  ↙   ↘  Yes
                 │     │
                 │     ↓
                 │   ┌──────────────────────────┐
                 │   │  AI synthesis (backend)  │
                 │   │  - Claude API per finding│
                 │   │  - Breach DB lookup      │
                 │   │  - Cache to local        │
                 │   └────────┬─────────────────┘
                 │            │
                 └────┬───────┘
                      ↓
            ┌────────────────────┐
            │  Save to .trojan/  │
            └─────────┬──────────┘
                      ↓
            ┌────────────────────┐
            │  Start net/http    │
            │  Open browser      │
            └────────────────────┘
```

---

## 5. Development phases

Each phase is independently shippable. Each phase ends with a concrete deliverable you can demo. Resist the urge to skip ahead — each phase de-risks the next.

---

### Phase 0 — Foundation and language ramp (week 1)

**Goal:** You're comfortable writing Go. The repo exists. The first commit is made.

**What this phase accomplishes:**
- Removes "I haven't started" anxiety
- Builds your Go muscle on a throwaway project before touching Trojan
- Sets up the repo, tooling, and CI so you can ship cleanly from Phase 1 onward

**Tasks:**
- Read "A Tour of Go" (golang.org/tour) — about 4 hours
- Build a throwaway Go CLI: a Markdown word counter, a TODO tracker, or a port scanner. Anything small. Goal is to feel the language, not produce something useful.
- Read "Effective Go" — the standard idioms doc
- Skim "Go by Example" for patterns (gobyexample.com)
- Create the Trojan repo: `github.com/yourname/trojan` (or whatever username)
- Set up Go module: `go mod init github.com/yourname/trojan`
- Add MIT license, basic README, .gitignore
- Set up GitHub Actions CI: build on every push, run tests
- Set up monorepo structure:
  ```
  trojan/
  ├── cmd/trojan/          # CLI entry point
  ├── internal/
  │   ├── scanners/        # Scanner wrappers
  │   ├── normalizer/      # Finding normalization
  │   ├── server/          # Local HTTP server
  │   └── config/          # Config management
  ├── ui/                  # React + Vite (separate package)
  ├── docs/
  ├── .github/workflows/
  └── README.md
  ```
- First commit: README with the pitch from this blueprint
- Build a Go binary that prints "trojan v0.0.1" and exits

**Definition of done:** `go build && ./trojan` prints version info. You feel like you can write basic Go without constantly checking syntax.

**Time estimate:** 1 week of focused evening work (10-15 hours).

---

### Phase 1 — Single scanner MVP (weeks 2-3)

**Goal:** Trojan runs Semgrep on a real codebase and outputs findings to the terminal.

**What this phase accomplishes:**
- Validates the core technical pattern: spawn a subprocess, parse JSON, normalize output
- Gives you something to demo: "look, my tool runs a real security scan"
- Sets the schema for all future scanners

**Tasks:**
- Add a Cobra-based CLI structure (`github.com/spf13/cobra`) — the standard Go CLI framework
- Implement `trojan --help`, `trojan version`, `trojan scan` commands
- Implement `trojan init` that detects Semgrep installation, installs it if missing (call pip or download binary)
- Implement scanner wrapper for Semgrep:
  - Spawn subprocess: `semgrep --config=auto --json <path>`
  - Capture stdout, parse JSON
  - Handle errors (Semgrep not installed, scan failed, malformed output)
- Define the normalized Finding struct:
  ```go
  type Finding struct {
      ID              string
      Scanner         string
      Category        string
      Severity        Severity
      Title           string
      RawMessage      string
      FilePath        string
      LineNumber      int
      CodeSnippet     string
      Status          Status
  }
  ```
- Implement normalization: Semgrep JSON → Finding structs
- Output to terminal:
  - Summary line: "X findings: N critical, N high, ..."
  - Grouped list by severity
  - Color-coded output (use `github.com/fatih/color`)
- Save scan results to `.trojan/scans/[timestamp].json`
- Write basic unit tests for normalization
- Update README with install instructions and screenshots

**Definition of done:** You can clone any open-source project, run `trojan scan`, and see real Semgrep findings printed to terminal. Saved to disk. Works on Mac and Linux.

**Time estimate:** 2 weeks (20-30 hours).

---

### Phase 2 — Full scanner pipeline (weeks 3-5)

**Goal:** All five scanners run in parallel, findings are deduplicated, output is unified.

**What this phase accomplishes:**
- The product is now genuinely useful as a free CLI
- Performance optimization through parallel goroutines
- Foundation for the UI in Phase 3

**Tasks:**
- Implement scanner wrappers for:
  - Trivy (SCA + container scanning)
  - Gitleaks (secrets + git history scanning)
  - Checkov (IaC)
  - Syft (SBOM)
- For each: subprocess spawn, JSON parse, normalize to Finding struct
- Implement parallel execution using goroutines and `sync.WaitGroup`:
  ```go
  var wg sync.WaitGroup
  for _, scanner := range scanners {
      wg.Add(1)
      go func(s Scanner) {
          defer wg.Done()
          results := s.Run(projectPath)
          // ...
      }(scanner)
  }
  wg.Wait()
  ```
- Implement project type detection:
  - Look for `package.json`, `requirements.txt`, `go.mod`, `Gemfile`, etc.
  - Look for IaC files (Terraform, K8s manifests, Dockerfile)
  - Skip scanners that don't apply (no IaC files = skip Checkov)
- Implement finding deduplication:
  - Same vuln caught by multiple scanners → merge into one finding with multiple sources
  - Hash-based dedup using file path + line number + rule ID
- Implement severity normalization across scanner conventions
- Implement progress reporting in terminal — a spinner/animation per scanner showing which scan is currently running, so users aren't waiting with no feedback. Each scanner should show its name and status (running → done/failed) in real time.
- Implement `--scanner=sast,sca` flag to run only specific scanners
- Implement `--exclude` flag for file/directory exclusions
- Implement `.trojan/config.yaml` for per-project configuration
- Add comprehensive integration tests with real test repos

**Definition of done:** Running `trojan scan` on a real project executes all 5 scanners in parallel in under 2 minutes, produces a normalized findings list, saves results to `.trojan/`.

**Time estimate:** 2 weeks (25-35 hours).

---

### Phase 3 — Local web UI (weeks 5-7)

**Goal:** After scanning, browser opens to a beautiful local report at localhost:7878.

**What this phase accomplishes:**
- The product becomes genuinely delightful, not just functional
- The differentiator vs. raw scanner CLIs is now visible
- The "wow" moment exists

**Tasks:**
- Build the React + Vite + Tailwind + shadcn UI in `ui/` subdirectory
- Design and build UI screens:
  - Dashboard: severity stats, scan summary, project overview
  - Findings list: filterable table with severity, scanner, file, category columns
  - Finding detail page: full description, code snippet, fix suggestions, breach analogs
  - SBOM viewer: searchable dependency list
  - Settings/exclusions page
- Use `monaco-editor` or `prismjs` for syntax-highlighted code snippets
- Implement HTTP API in Go using `net/http`:
  - `GET /api/scans/latest` — most recent scan
  - `GET /api/scans/:id` — specific scan
  - `GET /api/findings/:id` — finding detail
  - `POST /api/findings/:id/resolve` — mark resolved
  - `POST /api/findings/:id/suppress` — add to suppression list
  - `GET /api/sbom` — SBOM data
- Embed UI assets in Go binary using `embed.FS`:
  ```go
  //go:embed all:ui/dist
  var uiAssets embed.FS
  ```
- Server lifecycle: start on scan completion, kill on Ctrl+C, find available port if 7878 taken
- Auto-open browser using `github.com/pkg/browser`
- Implement "Open in VS Code" via `vscode://file/path:line` URLs
- Implement export buttons: PDF (use `github.com/chromedp/chromedp` to render HTML to PDF), JSON, SARIF
- Polish: empty states, loading states, error states, responsive design

**Definition of done:** After scan, browser opens automatically to a polished report. Devs see this and say "oh, this is nice."

**Time estimate:** 2-3 weeks (30-40 hours).

---

### Phase 4 — Distribution and packaging (weeks 7-8)

**Goal:** Anyone can install Trojan with one command on any platform.

**What this phase accomplishes:**
- The product is publicly installable, not just runnable from source
- Distribution channels in place for launch
- Auto-update mechanism so users get rule database updates

**Tasks:**
- Set up release pipeline with `goreleaser`:
  - Cross-compile for macOS (Intel + ARM), Linux (amd64 + arm64), Windows
  - Generate checksums and signatures
  - Auto-publish releases to GitHub Releases
- Create Homebrew formula:
  - Set up `homebrew-trojan` tap repository
  - Formula that downloads the binary from GitHub Releases
  - Test: `brew install yourname/trojan/trojan`
- Create install script (`install.sh`):
  - Detect OS and architecture
  - Download appropriate binary
  - Place in `/usr/local/bin/`
  - Tested on macOS + Linux
- Set up Scoop manifest for Windows
- Configure `go install github.com/yourname/trojan@latest` to work
- Implement `trojan update` command:
  - Check GitHub Releases for newer version
  - Download and replace binary
  - Update scanner rule databases (semgrep --update, trivy db update, etc.)
- Set up auto-update notification (non-intrusive)
- Code signing for macOS binaries (Apple Developer cert)
- Write installation docs in README
- Test installation on fresh Mac, fresh Linux VM, fresh Windows machine

**Definition of done:** A stranger can run `brew install trojan` on their Mac and have it working in under 30 seconds. Same for Linux via install script.

**Time estimate:** 1-2 weeks (15-25 hours).

---

### Phase 5 — Paid tier backend (weeks 8-11)

**Goal:** AI explanations are live. Users can subscribe and unlock the synthesis layer.

**What this phase accomplishes:**
- Revenue starts flowing
- The product moat (AI synthesis) is live
- Authentication and licensing model proven

**Tasks:**
- Build minimal backend: Node.js + Fastify + Postgres
  - Endpoints: `/auth/login`, `/auth/callback`, `/api/synthesize`, `/api/subscriptions`
- Deploy backend to Railway or Fly.io
- Implement `trojan login` flow:
  - Opens browser to OAuth (GitHub OAuth via your backend)
  - Backend returns API token
  - Token stored in `~/.trojan/config.json`
- Integrate Stripe:
  - Subscription plans (Pro $15/mo, Team $99/mo)
  - Webhook handlers for subscription lifecycle
  - Customer portal for self-service management
- Implement AI synthesis pipeline:
  - CLI sends findings to backend (only metadata, never source code — privacy promise)
  - Backend calls Claude API with finding + minimal context
  - Returns: plain-English explanation, business impact, breach analog ID, fix suggestion
  - CLI caches responses locally to avoid re-calling for same findings
- Build breach database:
  - Hand-curate 50 real-world breach entries
  - Each entry: company, year, root cause (mapped to CWE), business impact, scanner category
  - Store as JSON in repo, lookup in backend
- Implement BYOK (bring-your-own-key):
  - User provides their own Anthropic API key
  - Stored locally, CLI calls Claude directly
  - Lower subscription tier ($5/mo for non-AI features)
- License validation in CLI:
  - On `trojan login`, fetch subscription status
  - Gate AI features behind active subscription
  - Cache license check (refresh weekly)
- Implement graceful degradation:
  - No subscription? Show raw findings without AI synthesis
  - Network down? Use cached responses

**Definition of done:** A user can sign up, subscribe, run a scan, and see AI-powered explanations of findings. Payment flows work end to end.

**Time estimate:** 3 weeks (40-50 hours).

---

### Phase 6 — Watch mode and monitoring (weeks 11-13)

**Goal:** Trojan can run continuously and notify devs of new issues.

**What this phase accomplishes:**
- Becomes part of the daily workflow, not just a one-shot tool
- Stickiness increases (background process = higher retention)
- Enables pre-commit and CI integrations

**Tasks:**
- Implement `trojan scan --watch`:
  - Use `github.com/fsnotify/fsnotify` to watch file changes
  - Debounce events (avoid scanning during git operations)
  - Re-run affected scanners on file save
  - Push live updates to UI via WebSocket
- Implement `trojan monitor` daemon:
  - Run as background process
  - Periodically check CVE database for new vulns affecting tracked deps
  - Native OS notifications (use `github.com/gen2brain/beeep`)
  - Optional: install as system service (launchd on macOS, systemd on Linux)
- Implement pre-commit hook:
  - `trojan install-hooks` adds `.git/hooks/pre-commit`
  - Hook runs `trojan scan --pre-commit --fast`
  - Fails commit if Critical/High findings introduced
  - Configurable severity threshold
- Implement CI mode (`trojan ci`):
  - No browser, no UI
  - Outputs SARIF to stdout or file
  - Compatible with GitHub Code Scanning, GitLab Security Dashboard
  - Exit codes signal severity for CI pipeline gating
- Document GitHub Actions integration with example workflow
- Document GitLab CI integration
- Implement MCP (Model Context Protocol) server in Trojan:
  - Expose findings as MCP resources so AI agents (Claude, Cursor, Copilot, etc.) can read them directly
  - Tools to expose via MCP:
    - `get_findings` — returns all current findings with severity, file, line, message
    - `get_finding_detail` — returns full detail for a specific finding ID
    - `resolve_finding` — marks a finding as resolved
    - `suppress_finding` — suppresses a finding by rule ID
    - `run_scan` — triggers a fresh scan from within the AI agent
  - MCP server runs alongside the existing local HTTP server on a separate port (default 7879)
  - `trojan mcp` command starts the MCP server standalone (for AI IDE integrations)
  - Document how to connect Claude Code, Cursor, and other MCP-compatible tools to Trojan
  - This allows AI agents to see your security findings and suggest/apply fixes in context

**Definition of done:** A dev can install Trojan, set up the pre-commit hook, and have it block commits with critical issues. CI integration works. Watch mode updates UI live. AI agents can connect via MCP and read/act on findings.

**Time estimate:** 2 weeks (25-30 hours).

---

### Phase 7 — Public launch (weeks 13-15)

**Goal:** Trojan launches to the world. First wave of real users.

**What this phase accomplishes:**
- Validation: do developers actually want this?
- First wave of feedback for iteration
- First paying customers
- GitHub stars + community begins

**Tasks:**
- Polish the GitHub repo:
  - Compelling README with screenshots and animated GIFs
  - Detailed CONTRIBUTING.md
  - GitHub issue templates
  - Code of Conduct
  - Security policy (SECURITY.md)
- Set up trojan.dev landing page (build in Phase 8):
  - Marketing site with install instructions
  - Documentation site
  - Pricing page
- Pre-launch checklist:
  - Test on 10+ real open-source projects (Next.js apps, Python projects, Go services, etc.)
  - Fix any crashes, false positives, edge cases
  - Performance test: 1GB repo scan should complete in under 10 min
  - Security review of own codebase (eat your own dog food)
  - Beta test with 5-10 friendly developers
- Launch sequence:
  - Show HN post: "Trojan — local-first security CLI for developers"
  - Product Hunt launch
  - Post to /r/programming, /r/devops, /r/golang, /r/javascript
  - Tweet thread with demo video
  - Write launch blog post on dev.to or Hashnode
- Monitor and respond:
  - Watch GitHub issues, respond within 24 hours
  - Engage with HN/Reddit comments
  - Fix critical bugs in real-time
  - Collect user feedback systematically

**Definition of done:** Trojan is publicly available. First 100 users. First 5 paying customers. Front page of HN at least once (stretch goal). Real feedback is flowing in.

**Time estimate:** 2 weeks (30-40 hours).

---

### Phase 8 — Marketing site, payments, and completion (weeks 15-17)

**Goal:** Trojan has a real home on the internet. Payment flows are polished. The product is "complete" as a v1.

**What this phase accomplishes:**
- Closes the loop from "tool exists" to "real business"
- Professional presence that justifies pricing
- Self-serve onboarding works end-to-end without your involvement

**Tasks:**

**Build the marketing site (trojan.dev or similar):**
- Stack: Next.js + Tailwind + shadcn (you know this well)
- Host on Vercel
- Pages:
  - **Homepage:** hero (install command + animated demo), feature breakdown, social proof, CTA
  - **Why Trojan:** comparison vs Snyk/Aikido/Sonar, privacy positioning
  - **Features:** detailed pages on SAST, SCA, secrets, IaC, AI synthesis, watch mode
  - **Pricing:** clear tier breakdown, FAQ
  - **Docs:** full installation, usage, integration guides
  - **Blog:** technical articles, security writeups, breach analyses
  - **Open source:** GitHub link, contribution guide
  - **About:** Trojan Software Solutions story, you, the mission
  - **Privacy / Terms / Security:** legal pages
- Embed Stripe checkout for Pro and Team tiers
- Implement customer dashboard:
  - Subscription status
  - Billing history
  - API key management (BYOK)
  - Team management (Team tier)
  - Account settings

**Pricing page tiers:**

| Tier | Price | Includes |
|------|-------|----------|
| **Free** | $0 | Full CLI, all 5 scanners, local web UI, pre-commit hooks, basic findings list, CI integration, MIT licensed |
| **Pro (BYOK)** | $5/mo | Everything in Free + AI explanations using your own Anthropic key |
| **Pro** | $15/mo | Everything in Pro BYOK + AI calls included, breach storytelling, fix suggestions, PDF export, priority support |
| **Team** | $99/mo (10 seats) | Everything in Pro + team dashboard, shared suppressions, Slack/Discord notifications, cloud sync (optional), $9 per additional seat |
| **Enterprise** | Custom | Everything in Team + SSO, SCIM, audit logs, on-prem AI option, compliance modules, SLA, dedicated support |

**Payment plan implementation:**
- Stripe Checkout for self-serve Pro/Team signup
- Stripe Customer Portal for self-service management
- Webhook handlers for: subscription created, updated, cancelled, payment failed
- Automated email flows (use Resend or Postmark):
  - Welcome email after signup
  - Payment receipt
  - Subscription renewal reminder
  - Payment failure notice
- Trial: 14-day free trial of Pro for new users
- Annual discount: 2 months free for annual billing

**Final polish:**
- Comprehensive documentation:
  - Getting started
  - Configuration reference
  - All commands and flags
  - CI/CD integration guides
  - VS Code integration
  - Pre-commit hook setup
  - Suppression rule reference
- API reference for the backend (if you eventually let teams self-host)
- Status page (status.trojan.dev)
- Public roadmap (use GitHub Projects)
- Analytics setup (PostHog for product, Plausible for marketing)
- Error monitoring (Sentry)

**Definition of done:** A complete stranger can land on trojan.dev, understand what Trojan is in 30 seconds, install it, pay for a subscription, and get value without ever talking to you. The product is a real business, not just a project.

**Time estimate:** 2-3 weeks (30-40 hours).

---

### Summary of phase timeline

| Phase | Weeks | Hours | Goal |
|-------|-------|-------|------|
| 0 | 1 | 10-15 | Foundation, Go ramp |
| 1 | 2-3 | 20-30 | Single scanner MVP |
| 2 | 3-5 | 25-35 | Full scanner pipeline |
| 3 | 5-7 | 30-40 | Local web UI |
| 4 | 7-8 | 15-25 | Distribution |
| 5 | 8-11 | 40-50 | Paid tier backend |
| 6 | 11-13 | 25-30 | Watch mode & monitoring |
| 7 | 13-15 | 30-40 | Public launch |
| 8 | 15-17 | 30-40 | Marketing site & completion |

**Total: ~17 weeks (4 months) of focused part-time work (15-25 hours/week) alongside a job hunt.**

If full-time, halve the timeline (2 months).
If significantly less than 15 hours/week, expect 6-8 months.

---

## 6. Distribution and growth

### Phase 1: Open-source launch (months 1-3)
- Ship CLI to brew + GitHub Releases
- Show HN, Product Hunt, /r/programming, /r/devops, /r/golang
- Goal: 1,000 GitHub stars, 5,000 installs, 50 Pro signups

### Phase 2: Community + content (months 3-6)
- One technical blog post per month on trojan.dev/blog
- Open-source contributions back to scanner ecosystems
- Halifax tech meetups, local conference talks
- Guest posts on dev.to, Hacker Noon
- Goal: 100 paying Pro subscribers, 5 Team accounts, $2K MRR

### Phase 3: Vertical wedges (months 6-12)
- Identify which verticals adopt fastest (likely AI startups, fintech, healthtech)
- Build vertical-specific rulesets and breach intel
- Partner with bootcamps for educational use
- Goal: $10K MRR

### Phase 4: SaaS expansion (year 2)
- Team dashboard becomes prominent
- Cloud-only features (DAST, monitoring, compliance) drive enterprise upsell
- Goal: $50K MRR, first enterprise contracts

---

## 7. Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Devs use the free tier forever, never upgrade | Make AI tier genuinely 10x better than raw findings. BYOK option for cost-sensitive users. |
| Open-source clones | Moat is AI synthesis backend + breach database + brand. Forks won't have those. |
| Semgrep/Aikido releases meta-CLI | Already happened (Opengrep). Differentiation is UX, AI layer, breach storytelling. |
| Snyk/Aikido add local CLI mode | Possible. Trojan's open-source license is the structural advantage. |
| Scanner false-positive rates erode trust | Smart suppression UX, learning from "wontfix" decisions, AI flags low-confidence findings. |
| LLM costs eat margins | BYOK option, aggressive local caching, possible local LLM mode (Ollama). |
| Cross-platform pain (Windows) | Prioritize macOS + Linux. Windows via WSL initially, native later. |
| Solo founder bandwidth | Open-source community helps with scanner integrations, rule tuning, docs. |
| GitHub releases own version | Likely eventually. Trojan's edge: open-source, local-first, dev-UX-focused. |

---

## 8. Success metrics

**Phase 1-3 (months 1-3)**
- 1,000 GitHub stars
- 5,000 installs
- 50 Pro signups
- HN front page

**Phase 4-6 (months 3-6)**
- 100 paying Pro subscribers
- 5 Team accounts
- $2K MRR
- Mentioned in a major dev newsletter

**Phase 7-8 (months 6-12)**
- $10K MRR
- 500+ paying customers
- 5,000 GitHub stars
- VS Code extension shipped

**Year 2**
- $50K MRR
- First enterprise contract
- Team of 2-3

---

## 9. Why this works

Three structural advantages:

1. **Local-first is a real moat.** Snyk, Aikido, Sonar all require cloud uploads. Entire markets (regulated industries, security-sensitive companies, privacy-conscious devs) are structurally unserved. Trojan owns that segment by default.

2. **Open-source is a real distribution engine.** GitHub stars, community PRs, organic mentions, free SEO. Marketing that doesn't require performing.

3. **AI synthesis is a real product layer.** Wrapping scanners is commoditized. Translating their output into plain English with breach analogs is genuinely novel.

Built right, Trojan becomes "the security CLI" the way Cursor became "the AI editor."

---

*Maintained by Chizulu under Trojan Software Solutions. Last updated: May 2026.*