package orgcontext

import (
	"fmt"
	"os"
	"path/filepath"
)

// scaffoldTemplate is the starter .trojan/context.yaml written by
// WriteScaffold. It is authored as literal, commented YAML (rather than
// marshaled from OrgContext) so the prompts guiding the user survive being
// written to disk and edited, and so an empty schema still reads as an
// onboarding walkthrough rather than a blank file.
const scaffoldTemplate = `# Trojan org context
#
# This file tells Trojan what your app actually does, so it can test more
# intentionally instead of only applying generic heuristics. It is the
# highest-leverage input you can give the tool: a few honest sentences here
# focus every scan on what actually matters for YOUR app, instead of a
# generic OWASP checklist.
#
# Location: .trojan/context.yaml (project-local; .trojan/ is gitignored by
# default, so this stays local unless you choose to commit it for your team).

app:
  name: ""
  # One paragraph: what does this app do, who uses it, and why does it exist?
  # Example:
  #   "Billing API for a B2B SaaS product. Handles subscription plans,
  #   invoicing, and stored payment methods for roughly 500 enterprise
  #   customers, each with multiple users and role-based access."
  description: ""

# List every category of sensitive data your app handles. For each one, give
# patterns that locate it in code: file/path globs (supporting * and **, e.g.
# "internal/billing/**") and regexes matched against function or symbol names
# (e.g. "(?i)creditcard"). Trojan's generic heuristics already guess at PII
# from variable names; this section lets you correct and extend those guesses
# with what you actually know about your own data model.
sensitive_data: []
# sensitive_data:
#   - category: PII
#     description: "Customer names, emails, phone numbers"
#     file_patterns:
#       - "internal/customers/**"
#     symbol_patterns:
#       - "(?i)email"
#       - "(?i)phone"
#   - category: payment
#     description: "Card numbers and stored payment method tokens"
#     file_patterns:
#       - "internal/billing/**"
#     symbol_patterns:
#       - "(?i)card"
#       - "(?i)payment"
#   - category: credentials
#     description: "Passwords, API keys, session tokens"
#     symbol_patterns:
#       - "(?i)password"
#       - "(?i)apikey"
#       - "(?i)session"

# Name the trust boundaries in your system: places where data crosses from
# one level of trust to another (the public internet into your API, one
# tenant's data into another's, a regular user into an admin-only surface).
# Trojan uses these to reason about which paths matter most and to explain
# findings in terms your team already uses internally.
trust_boundaries: []
# trust_boundaries:
#   - name: "public API"
#     description: "Internet-facing HTTP handlers, no auth assumed"
#     file_patterns:
#       - "internal/api/**"
#     symbol_patterns:
#       - "(?i)^Handle"
#   - name: "internal admin"
#     description: "Admin-only surface, requires an elevated role"
#     file_patterns:
#       - "internal/admin/**"

# Who are you actually defending against? Naming your threat actors sharpens
# what Trojan treats as a real finding versus noise. "targets" (optional)
# lists the trust_boundaries[].name values that actor is assumed to reach.
threat_actors: []
# threat_actors:
#   - name: "external attacker"
#     description: "Unauthenticated internet user probing the public API"
#     targets: ["public API"]
#   - name: "malicious tenant"
#     description: "Authenticated customer trying to reach another tenant's data"
#     targets: ["public API"]
#   - name: "insider"
#     description: "Employee or contractor misusing internal admin access"
#     targets: ["internal admin"]
`

// GenerateScaffold returns the starter .trojan/context.yaml content: a
// commented walkthrough guiding the user through describing their app,
// sensitive data, trust boundaries, and threat actors.
func GenerateScaffold() []byte {
	return []byte(scaffoldTemplate)
}

// WriteScaffold writes the starter context.yaml to .trojan/context.yaml under
// root, creating .trojan/ if needed. It refuses to overwrite an existing file
// unless force is true, so re-running onboarding never silently clobbers
// context the user already authored. It returns the path written.
func WriteScaffold(root string, force bool) (string, error) {
	path := Path(root)
	if !force && Exists(path) {
		return path, fmt.Errorf("orgcontext: %s already exists (pass force to overwrite)", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("orgcontext: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, GenerateScaffold(), 0o644); err != nil {
		return "", fmt.Errorf("orgcontext: write %s: %w", path, err)
	}
	return path, nil
}
