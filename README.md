# Trojan

**A developer-first security CLI. Catch vulnerabilities before they ship.**

Trojan scans your codebase for security issues — vulnerable dependencies, leaked secrets, code-level vulnerabilities, and infrastructure misconfigurations — and opens a rich local web UI to walk you through every finding in plain English.

---

## Why Trojan

- **Runs locally.** Your code never leaves your machine.
- **Single binary.** One install command and you're scanning.
- **One command.** `trojan scan` does everything.
- **Rich UI in your browser.** A proper report — not a wall of terminal text.
- **Plain-English explanations.** Not "CWE-89 at line 142." Real explanations of what's wrong, why it matters, and exactly how to fix it.
- **Multi-engine.** Wraps Semgrep, Trivy, Gitleaks, Checkov, and Syft so you don't have to chain them yourself.
- **Pre-commit ready.** Block vulnerabilities from ever hitting your repo.
- **Watch mode.** `trojan scan --watch` re-scans on every file save and pushes updates to the open report.
- **CI-native.** `trojan ci` outputs SARIF 2.1.0 for GitHub Code Scanning, GitLab, and any SARIF-compatible pipeline.

---

## Install

**macOS (Homebrew)**
```bash
brew tap dev-zeph/trojan
brew install trojan
```

**Linux / macOS (curl)**
```bash
curl -fsSL https://trojan.dev/install.sh | sh
```

---

## Quick start

```bash
trojan init          # Install scanners (~30 seconds, first time only)
trojan scan          # Scan the current project, open report in browser
```

Log in for AI-powered explanations and fix suggestions:

```bash
trojan login         # Sign in or create a free account
trojan scan          # Now includes plain-English summaries for every finding
```

---

## Commands

| Command | Description |
|---|---|
| `trojan init` | Install pinned scanner versions to `~/.trojan/bin/` |
| `trojan scan` | Scan project, open local report at `localhost:7878` |
| `trojan scan --watch` | Re-scan on file changes, live-update the open report (Pro) |
| `trojan ci` | Silent scan, SARIF 2.1.0 output to stdout, exits 1 on findings |
| `trojan login` | Authenticate for AI explanations and Pro features |
| `trojan pro` | Check subscription status |
| `trojan hook install` | Install a pre-commit hook that blocks critical/high findings |
| `trojan mcp install` | Wire Trojan into Claude Code, Cursor, and Codex CLI via MCP |
| `trojan verify` | Verify the binary's SHA256 and GPG signature |
| `trojan version` | Print the installed version |

---

## Scanners

Trojan manages its own pinned, SHA256-verified scanner versions in `~/.trojan/bin/` — independent of your system packages.

| Scanner | What it catches |
|---|---|
| [Semgrep](https://semgrep.dev) | Code-level vulnerabilities, injection flaws, insecure patterns |
| [Trivy](https://trivy.dev) | Dependency CVEs, container image vulns, secrets |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Leaked secrets and credentials in git history |
| [Checkov](https://checkov.io) | Infrastructure-as-code misconfigurations (Terraform, Docker, k8s) |
| [Syft](https://github.com/anchore/syft) | Software Bill of Materials (SBOM) generation |

---

## CI integration

```yaml
# GitHub Actions
- name: Security scan
  run: trojan ci --output trojan.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trojan.sarif
```

---

## Pre-commit hook

```bash
trojan hook install   # Blocks commits that have critical or high findings
trojan hook uninstall
```

---

## AI editor integration (MCP)

```bash
trojan mcp install    # Auto-configures Claude Code, Cursor, and Codex CLI
```

After installing, your AI editor can query Trojan for scan results, ask about specific findings, and suggest fixes — directly in your editor.

---

## Security

Trojan takes supply chain security seriously:

- Every release binary is **SHA256 verified** and **GPG signed**.
- Release provenance is published to the **Sigstore transparency log** via SLSA.
- Scanner versions are **pinned and SHA256-verified** on install — not pulled from package managers.
- Your code and findings **never leave your machine** unless you opt in to AI explanations (Pro).

Verify your binary:
```bash
trojan verify
```

See [SECURITY.md](SECURITY.md) for the full security policy and GPG public key.

---

## License

Source available under the [Business Source License 1.1](LICENSE).
Free for personal, educational, and open-source use.
Commercial use requires a license — see [trojan.dev](https://trojan.dev).
