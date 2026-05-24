# Trojan

**A developer-first security CLI. Catch vulnerabilities before they ship.**

Trojan scans your codebase for security issues — vulnerable dependencies, leaked secrets, code-level vulnerabilities, and infrastructure misconfigurations — and opens a rich local web UI to walk you through every finding in plain English.

> *"The trojan horse you actually want — one that finds the weaknesses before someone else does."*

---

## Why Trojan

- **Runs locally.** Your code never leaves your machine.
- **Single binary.** `brew install trojan` and you're done. No Node, no Python, no runtime required.
- **One command.** `trojan scan` and you're scanning.
- **Rich UI in your browser.** A proper report at `localhost:7878` — not a wall of terminal text.
- **Plain-English explanations.** Not "CWE-89 detected at line 142." Real explanations of what's wrong, why it matters, and how to fix it.
- **Multi-engine.** Wraps Semgrep, Trivy, Gitleaks, Checkov, and Syft so you don't have to chain them yourself.
- **Pre-commit ready.** Stop vulnerabilities from ever hitting your repo.

---

## Install

```bash
brew install trojan
# or
curl -fsSL https://trojan.dev/install.sh | sh
```

## Usage

```bash
trojan init    # First-time setup, installs scanners
trojan scan    # Scan your project, open report in browser
trojan ci      # CI mode, outputs SARIF, no UI
```

---

## License

Source available under the [Business Source License 1.1](LICENSE).  
Free for personal, educational, and open-source use.  
Commercial use requires a license — see [trojan.dev](https://trojan.dev).
