// Regression guard for the Pro-subscription -> Trojan Tokens migration
// (commit b12b5733). That migration added a token-balance gate to every AI
// edge function but left the OLD `if (!await isPro(user)) return json({
// error: 'Pro subscription required' }, 403)` gate sitting above it, so the
// Pro check always fired first and the token gate was dead code. The rule
// going forward: local work is free and ungated, server-side AI work is
// bounded by the user's Trojan Token balance enforced at the edge function,
// and nothing is hidden behind a subscription tier. This test reads the
// actual function source off disk (not a mock) so a future PR cannot
// reintroduce an isPro(...) authorization gate without failing CI.
//
// Run without Deno installed:
//   node --experimental-strip-types supabase/functions/_shared/gating.test.ts
//
// Or, with Deno:
//   deno test --allow-read supabase/functions/_shared/gating.test.ts

import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const FUNCTIONS_DIR = fileURLToPath(new URL("..", import.meta.url))

function readFunctionSource(name: string): string {
  return readFileSync(FUNCTIONS_DIR + name + "/index.ts", "utf8")
}

// Functions that do real, metered AI work server-side. Each MUST still have
// its Trojan Token balance gate (402 insufficient_tokens) -- that is the
// actual paywall now -- but MUST NOT have an isPro(...) gate above it.
const METERED_FUNCTIONS = [
  "synthesize",
  "triage",
  "dast-templates",
  "agentic-dast",
  "threat-lab",
  "compliance-lab",
  "pentest-report",
]

// Functions with no token gate: cheap (embed) or a read-only catalog
// (attack-templates). These are correctly sign-in-only -- they must still
// reject unauthenticated requests (401), but must not require Pro or tokens.
const SIGNIN_ONLY_FUNCTIONS = [
  "attack-templates",
  "embed",
]

let pass = 0, fail = 0
function check(name: string, got: unknown, want: unknown) {
  const ok = JSON.stringify(got) === JSON.stringify(want)
  console.log(`${ok ? "  PASS" : "  FAIL"}  ${name}${ok ? "" : `\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`}`)
  ok ? pass++ : fail++
}

for (const name of [...METERED_FUNCTIONS, ...SIGNIN_ONLY_FUNCTIONS]) {
  const src = readFunctionSource(name)

  // The old gate, in any form -- import or call -- must be gone. Checking the
  // bare substring "isPro" (not just the call) also catches a leftover,
  // now-unused import, which is itself a lint/dead-code smell we want to
  // avoid reintroducing.
  check(`${name}: no isPro(...) gate`, /isPro\s*\(/.test(src), false)
  check(`${name}: no isPro import`, /\bisPro\b/.test(src), false)
  check(`${name}: no stale "Pro subscription required" error`, src.includes("Pro subscription required"), false)

  // Every function in this list must still refuse unauthenticated callers.
  check(`${name}: still checks for missing/invalid token (401)`, /401\)/.test(src), true)
}

for (const name of METERED_FUNCTIONS) {
  const src = readFunctionSource(name)
  // The real paywall: insufficient balance -> 402 insufficient_tokens. This
  // must survive the isPro removal untouched, or metered AI work becomes free.
  check(`${name}: still has insufficient_tokens gate`, src.includes("insufficient_tokens"), true)
  check(`${name}: insufficient_tokens gate returns 402`, /402\)/.test(src), true)
}

console.log(`\n  ${pass} passed, ${fail} failed`)
if (fail > 0) throw new Error(`${fail} gating test(s) failed`)
