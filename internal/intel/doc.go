// Package intel is Trojan's dependency-intel matcher: it turns a project's
// lockfiles into an exact installed-package inventory, asks the hosted
// intel edge function (functions/v1/intel) for advisories about those
// packages, and decides hits locally by exact installed version.
//
// The server only narrows advisories to package names; whether an installed
// version is affected is always decided here, against OSV-style ranges, so a
// match never depends on the server's range logic.
//
// # Pipeline
//
//	pkgs, lockfiles, err := intel.ParseProject(dir)   // 1. inventory
//	resp, err := intel.NewClient().Fetch(ctx, pkgs)    // 2. intel
//	matches := intel.MatchAdvisories(pkgs, resp.Advisories) // 3. local decision
//
// Check does all three, caches the response under
// <project>/.trojan/intel/advisories.json and falls back to that cache when
// the server is unreachable (Result.FromCache, Result.FetchedAt).
//
// # Lockfiles
//
// npm: package-lock.json / npm-shrinkwrap.json (v1 tree and v2/v3 packages
// map), pnpm-lock.yaml (v5-v9), yarn.lock (classic v1 and berry), bun.lock
// (text, Bun >= 1.2; bun.lockb is not read). PyPI: poetry.lock, uv.lock,
// Pipfile.lock, requirements*.txt (exact == pins only). Lockfiles are found
// anywhere up to 6 directories deep (monorepos), skipping node_modules, .git,
// .trojan, vendor, virtualenvs and build output. Non-registry entries (git,
// file:, link:, workspace:, editable) are dropped. PyPI names are PEP 503
// normalized. Packages are deduplicated on (ecosystem, name, version); every
// distinct installed version is kept and matched separately.
//
// # Matching semantics
//
// Versions compare with SemVer 2.0 precedence for npm and PEP 440 for PyPI
// (CompareVersions). An advisory applies to an installed version when the
// version appears in affected_versions, or falls in one of the OSV
// affected_ranges (events sorted, introduced "0" = from the start, affected
// from introduced until the next fixed (exclusive) or last_affected
// (inclusive)). A range with no introduced event is treated as starting at
// "0". With no range data at all, version < fixed_version decides, and a
// malicious-package advisory with nothing else applies to every version.
// Match.FixedVersion is the fix for the installed release line when the
// ranges give one, else the advisory's fixed_version.
//
// Every Match has Status "matched_unproven": the version is in range, but
// nothing has shown the vulnerable code is reached. ProofAvailable says an
// Attack Market playbook (Advisory.PlaybookID, a template slug) can try to
// prove it. Match.ID is stable across runs (advisoryID|ecosystem|name@version)
// so a later proof step can refer back to it.
//
// To prove a fix after an upgrade, re-run ParseProject (or ParseLockfile) and
// either MatchAdvisories against the same advisories (the match disappears)
// or CompareVersions(eco, installed, fixed) >= 0.
//
// # Auth and wire format
//
// Requests use the signed-in user's Supabase access token from
// ~/.trojan/config.json (config.LoadConfig, the same source as the other
// hosted-function callers; override with Client.Token). Bodies are sent
// base64-wrapped as {"encoded": "<base64 JSON>"} like the other Go callers,
// because Cloudflare's WAF 403s raw payloads. 401 maps to ErrNotSignedIn and
// 402 to *SubscriptionRequiredError (errors.Is ErrSubscriptionRequired);
// other non-200 replies are *StatusError.
package intel
