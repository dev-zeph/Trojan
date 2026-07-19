# Trojan — Changelog

---

## v0.1.0 — May 2026

### CLI Core

**Parallel AI explanation generation**
- Replaced sequential AI synthesis loop with an 8-goroutine worker pool using a buffered channel semaphore (`make(chan struct{}, 8)`)
- Scan time for a full AI synthesis pass dropped from ~2 minutes to ~15–20 seconds for a 64-finding report
- Progress counter (`X / Y complete`) updates in real time with `\r` overwrite
- Post-synthesis message: "Preparing actionable fix recommendations..." before opening the browser

**`var version` fix for GoReleaser ldflags**
- Changed `const version = "0.0.1"` to `var version = "0.0.1"` in `cmd/trojan/main.go`
- Go compiler rejects ldflags injection into `const` — changing to `var` allows `goreleaser` to correctly stamp the version at build time
- Without this, every release binary reports `v0.0.0` regardless of the tag

**Update check hardening (`internal/config/update.go`)**
- Added HTTP status code check: non-200 responses now return an error instead of silently succeeding
- Added empty tag guard: an empty `tag_name` field from the GitHub API no longer causes a false "update available" result

### Local Web UI (`ui/`)

**Dark mode toggle removed**
- Removed `useDarkMode` hook and manual toggle button entirely
- Replaced with `useEffect` that reads `window.matchMedia('(prefers-color-scheme: dark)')` and listens for OS-level changes
- UI theme now tracks system preference automatically with no user friction

**Resolved and suppressed findings hidden**
- `FindingsList.tsx`: added `const openFindings = findings.filter(f => f.Status === 'open')` pre-filter; all subsequent filtering operates on open findings only
- `Dashboard.tsx`: preview panel now counts and renders only open findings
- `App.tsx`: tab badge count shows open findings only: `scan.findings.filter(f => f.Status === 'open').length`
- Users no longer wade through already-resolved findings on every scan

### Distribution & Release Pipeline

**GoReleaser fixes**
- Removed trailing slash from `main: ./cmd/trojan/` → `./cmd/trojan` (goreleaser path resolution bug)
- Removed `brews`/`homebrew` section (removed from goreleaser v2 free tier) — replaced with custom shell script step
- Removed `signs` section (GPG deferred — see Blueprint.md)
- Removed windows build target temporarily (WSL path complexity)
- Removed `extra_files` from release section

**GitHub Actions — release.yml**
- Replaced `actions/setup-go@v5` (CDN failures) with direct Go install via curl
- Upgraded `actions/checkout@v4` → `@v5` (Node.js 20 deprecation enforced by GitHub)
- Upgraded `actions/setup-node@v4` → `@v5`
- Upgraded `goreleaser/goreleaser-action@v6` → `@v7`
- Removed SLSA provenance step (`actions/attest-build-provenance@v2`) — CDN failures, deferred (see Blueprint)
- Removed GPG import and binary checksum steps (deferred)
- Added custom Homebrew tap update step: shell script that generates `Formula/trojan.rb` and pushes to `homebrew-trojan` tap repo

**`.gitignore` anchoring fix**
- Changed `trojan` → `/trojan` and `trojan.exe` → `/trojan.exe`
- Unanchored `trojan` matched `cmd/trojan/` directory, hiding the CLI entry point from git entirely
- Root-anchored `/trojan` correctly matches only the built binary at the repo root

### Homebrew Distribution

**Custom tap (pre-Homebrew-core acceptance)**
- Install command: `brew install dev-zeph/trojan/trojan`
- Single command — no separate `brew tap` step when the formula path is fully qualified
- Homebrew core acceptance requires significant download numbers; tap is the standard interim approach

### `install.sh` — One-line Installer

New script at `trojancli.com/install.sh` (served from `trojan-web/frontend/public/install.sh`):
- Detects OS (`darwin`/`linux`) and architecture (`amd64`/`arm64`)
- Queries GitHub API for latest release tag
- Constructs correct filename: `trojan_{VERSION}_{OS}_{ARCH}.tar.gz`
- Downloads from GitHub Releases with error handling
- Installs to the first available path in order of preference:
  1. `/usr/local/bin` — standard on Intel Macs and Linux
  2. `/opt/homebrew/bin` — standard on Apple Silicon with Homebrew
  3. `~/.local/bin` — fallback, directory created automatically
- Uses `sudo` only for system directories; skips it for user-owned paths
- Prints install path and PATH warning if the install dir is not on PATH

---

## Security Implementation Status

| Feature | Status |
|---|---|
| GPG binary signing | ⏸ Deferred — `SIGNING_KEY` secret is configured in GitHub, implementation removed from workflow |
| SLSA provenance | ⏸ Deferred — CDN failures with `actions/attest-build-provenance@v2`, re-enable when stable |
| macOS code signing | 🔲 Not started — requires Apple Developer account |
| Windows build | ⏸ Deferred — stripped from goreleaser temporarily |

---

*Last updated: May 2026*
