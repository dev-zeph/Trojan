import { validateToken, corsHeaders } from '../_shared/auth.ts'
import { supabase } from '../_shared/supabase.ts'

// attack-templates — the Attack Market catalog (§9.4 / §13). Serves the curated,
// FIRST-PARTY breach-derived attack playbooks the desktop browses and the agent
// runs (one at a time). Author-only: templates live in the TEMPLATES array below;
// you add a breach by appending an entry and redeploying this function. The
// community never uploads here — they can only star (a separate table, phase 2)
// or email hi@trojancli.com to suggest one you then research and author.
//
// Two fields, by design:
//   - breach_story : the human-readable narrative (what really happened). This is
//     the transparency surface the user reads before running it.
//   - prompt_body  : the GENERALIZED "what to test" the agent runs against the
//     user's OWN app. It is a technique pattern abstracted from the breach, NOT a
//     literal "attack <company>". It is injected into the run as RoE-subordinate
//     content — it never widens scope; the rules of engagement stay fixed.
//
// Free to browse for any signed-in user -- it's a read-only catalog, not the
// metered AI work, so there's no token cost to look. Running a template's
// prompt_body through the agent is what spends tokens, gated at agentic-dast
// itself. Read-only (GET) here; star counts are joined in a later phase.

interface AttackTemplate {
  slug: string
  title: string
  technique: string[] // ATT&CK-flavored tags, for the browse filter + badges
  min_tier: 'passive' | 'safe-active' | 'aggressive'
  breach_story: string
  prompt_body: string
  star_count: number
  starred?: boolean // whether the requesting user has starred it (set per-request)
}

const TEMPLATES: AttackTemplate[] = [
  {
    slug: 'client-bundle-secret-to-account-takeover',
    // SAMPLE template — replace/extend with researched real-world breaches
    // (e.g. "Samsung 2026 Password Data Breach"). Kept generalized so it runs
    // against any target, not a specific company.
    title: 'Client-Bundle Secret → Account Takeover',
    technique: ['secrets-exposure', 'broken-authentication', 'broken-access-control'],
    min_tier: 'safe-active',
    breach_story:
      'A recurring real-world breach pattern. A web app ships secrets in its ' +
      'client-side JavaScript bundle (hardcoded admin credentials, an API key, ' +
      'or a token) because the build inlines environment variables meant for the ' +
      'server. An attacker downloads the public bundle, extracts the secret, and ' +
      'reuses it against the login or admin surface. Often the admin gate turns ' +
      'out to be enforced only in the browser (a sessionStorage/localStorage flag) ' +
      'with no server-side check, so the reused credential, or simply flipping the ' +
      'flag, lands full admin access. Root cause: trusting the client with secrets ' +
      'and with authorization decisions.',
    prompt_body:
      'Goal: determine whether this application leaks a secret to the client and ' +
      'whether that secret (or a client-only auth gate) leads to account takeover.\n' +
      'Steps:\n' +
      '1. Read the served JavaScript/HTML bundle and inlined env config. Look for ' +
      'hardcoded credentials, API keys, tokens, or admin emails/passwords.\n' +
      '2. If source is available, use read_source to confirm how auth and any admin ' +
      'gate are enforced: specifically whether the admin check is client-side only ' +
      '(a sessionStorage/localStorage/cookie flag) with no server verification.\n' +
      '3. If a credential is found, remember_fact it, then attempt a single ' +
      'authentication with it against the login endpoint to prove reuse (non-' +
      'destructive; one attempt, no brute force).\n' +
      '4. If an admin gate looks client-only, probe an admin route directly to prove ' +
      'the server does not enforce authorization.\n' +
      '5. Report the proven chain (leak, then reuse/bypass, then privileged access) ' +
      'as a single high-severity finding with the concrete evidence at each step.',
    star_count: 0,
  },
  {
    slug: 'capital-one-2019-ssrf-cloud-metadata',
    title: 'Capital One 2019: SSRF to Cloud Metadata',
    technique: ['ssrf', 'cloud-metadata', 'credential-theft'],
    min_tier: 'safe-active',
    breach_story:
      "In 2019 an attacker pulled over 100 million credit applications out of Capital One's AWS environment. A misconfigured web application firewall was vulnerable to server-side request forgery (SSRF): it was tricked into requesting the cloud instance metadata service (169.254.169.254), which handed back temporary IAM credentials for the firewall's over-privileged role. Those credentials unlocked sensitive S3 buckets. Root cause: an SSRF-able server component plus an IAM role with far more access than it needed.",
    prompt_body:
      'Goal: find whether any endpoint can be coerced into making server-side requests (SSRF), and whether that reaches internal or cloud-metadata targets.\n' +
      'Steps:\n' +
      '1. Enumerate parameters, headers, and JSON fields that take a URL, hostname, path, or file reference (webhooks, image/pdf fetchers, link previews, imports, redirects).\n' +
      '2. If source is available, read_source the handler to confirm user input flows into an outbound request with no allow-list.\n' +
      '3. Point one such parameter at a benign internal-style target and at the cloud metadata address, and observe status, timing, or a response body that differs from an external URL as proof the server made the request. Do not exfiltrate credentials.\n' +
      '4. remember_fact any confirmed SSRF sink and whether it reached an internal or metadata endpoint.\n' +
      '5. Report a single finding with the SSRF-able parameter, the evidence it reached an internal target, and the blast radius.',
    star_count: 0,
  },
  {
    slug: 'equifax-2017-unpatched-component',
    title: 'Equifax 2017: Unpatched Framework Component',
    technique: ['outdated-component', 'known-cve', 'rce'],
    min_tier: 'passive',
    breach_story:
      'The 2017 Equifax breach exposed personal data on roughly 147 million people. The entry point was a known, already-patched remote-code-execution flaw in the Apache Struts web framework (CVE-2017-5638) that Equifax never updated. Crafted requests were executed by the vulnerable component, giving attackers a foothold they widened over months. Root cause: a public web app running a component with a known critical vulnerability that was left unpatched.',
    prompt_body:
      'Goal: determine whether the app exposes components with known, unpatched vulnerabilities.\n' +
      'Steps:\n' +
      '1. Fingerprint the stack from responses: Server and X-Powered-By headers, framework cookies, error pages, JS libraries and their versions, and any exposed build info.\n' +
      '2. If source is available, read the dependency manifests (package.json, requirements.txt, go.mod, pom.xml) and note components and versions.\n' +
      '3. Cross-reference discovered versions against known-vulnerable ranges (the Nuclei pre-pass results are the breadth signal here).\n' +
      '4. For anything that looks outdated, send one non-destructive probe that confirms the version or the presence of the known issue, without running an exploit payload.\n' +
      '5. Report each outdated or known-vulnerable component with the observed version, the class of risk, and the fixed version.',
    star_count: 0,
  },
  {
    slug: 'log4shell-2021-injection-sink',
    title: 'Log4Shell 2021: Input Reaches an Injection Sink',
    technique: ['injection', 'rce', 'input-validation'],
    min_tier: 'safe-active',
    breach_story:
      'In late 2021 Log4Shell (CVE-2021-44228) affected countless applications. A widely used logging library evaluated special lookup syntax inside strings it logged, so any attacker-controlled value that got logged (a username, a User-Agent, a search term) could trigger a server-side request and remote code execution. The lesson generalizes: untrusted input reaching a powerful sink (logger, template engine, expression evaluator, command) without sanitization is dangerous. Root cause: attacker input flowing unsanitized into a component that interprets it.',
    prompt_body:
      'Goal: find places where untrusted input reaches a sink that interprets it (template, expression, logger, command, query).\n' +
      'Steps:\n' +
      '1. Map inputs that are reflected, stored, logged, or processed: form fields, query params, headers (User-Agent, Referer, X-Forwarded-For), JSON values, file names.\n' +
      '2. If source is available, read_source the handlers to see whether inputs reach a template renderer, an eval/expression, a logging call, or a shell command without sanitization.\n' +
      '3. Inject a safe, marked, non-executing probe (a unique benign marker, or a harmless expression that only renders differently if interpreted) and observe whether the input was interpreted rather than treated as literal text.\n' +
      '4. Keep it report-only: prove interpretability with a benign marker, never run a real command or callback.\n' +
      '5. Report each confirmed injection sink with the input, location, and class (template, expression, or command injection).',
    star_count: 0,
  },
  {
    slug: 'moveit-2023-sql-injection',
    title: 'MOVEit 2023: SQL Injection in a Web App',
    technique: ['sql-injection', 'injection'],
    min_tier: 'safe-active',
    breach_story:
      'In 2023 a SQL injection flaw in the MOVEit Transfer web application (CVE-2023-34362) was exploited at scale, leading to data theft from thousands of organizations. Unauthenticated requests carried input the application concatenated into SQL queries without proper validation, letting attackers read and manipulate the database and ultimately plant a web shell. Root cause: user input reaching SQL queries without parameterization.',
    prompt_body:
      'Goal: determine whether any parameter reaches a SQL query unsafely.\n' +
      'Steps:\n' +
      '1. Identify inputs that likely touch the database: search, filters, ids, login, sort/order params, JSON fields.\n' +
      '2. If source is available, read_source the handler to confirm whether input is concatenated into a raw query (raw_query true, sanitizes_input false) versus parameterized.\n' +
      '3. Send boolean-based and time-based probes (a true condition versus a false one, or a short safe delay) and compare with diff_responses to prove the input changes query logic. One proof is enough.\n' +
      '4. Do not dump tables, extract at volume, or alter data. A single confirmation of injectability is the deliverable.\n' +
      '5. Report the injectable parameter with the boolean/timing evidence and the endpoint.',
    star_count: 0,
  },
  {
    slug: 'optus-2022-unauthenticated-api',
    title: 'Optus 2022: Unauthenticated Public API',
    technique: ['missing-authentication', 'api', 'enumeration'],
    min_tier: 'passive',
    breach_story:
      'In 2022 the telecom Optus exposed around 10 million customer records. An internet-facing API endpoint that returned customer details required no authentication and keyed on sequential customer identifiers, so anyone could script requests that incremented the id and pull the entire dataset. It had been left reachable on a secondary domain that missed an access-control fix applied elsewhere. Root cause: a sensitive API exposed to the internet with no authentication and predictable identifiers.',
    prompt_body:
      'Goal: find sensitive endpoints reachable without authentication, especially those keyed on guessable identifiers.\n' +
      'Steps:\n' +
      '1. Enumerate API routes from the crawl, any API schema, and source. Flag ones that return user or record data.\n' +
      '2. Request each candidate with NO credentials (no identity) and see whether it returns real data instead of 401/403.\n' +
      '3. For any unauthenticated endpoint that takes an id, request two adjacent ids and compare with diff_responses to show it returns different real records. Fetch only what proves the issue, never the whole set.\n' +
      '4. remember_fact any endpoint that leaks data without auth.\n' +
      '5. Report each unauthenticated sensitive endpoint with the evidence, and flag predictable-identifier enumeration where present.',
    star_count: 0,
  },
  {
    slug: 'first-american-2019-idor',
    title: 'First American 2019: Increment-the-ID Document Access',
    technique: ['idor', 'broken-object-level-authorization'],
    min_tier: 'safe-active',
    breach_story:
      "In 2019 First American Financial left roughly 885 million sensitive documents (bank statements, Social Security numbers, mortgage records) reachable through its website. Each document was addressed by a sequential number in the URL with no login or ownership check, so changing the number in a valid link returned someone else's document. Root cause: direct object references with no authorization check, a textbook IDOR / broken object-level authorization flaw.",
    prompt_body:
      "Goal: prove whether one user can reach another user's object by manipulating an identifier (IDOR / BOLA).\n" +
      'Steps:\n' +
      '1. Find endpoints that reference an object by id in the path, query, or body (documents, orders, profiles, messages, invoices).\n' +
      '2. If two identities are provided, fetch a resource as its owner (identity A), then request the SAME id as a different user (identity B). If no identities are given, fetch an object you own, then request an adjacent id.\n' +
      "3. Call diff_responses on the two probes. A near-identical successful body across different identities (possible_bola), or another user's private fields in your response, is the proof. A 401/403 for the second request means authorization is holding.\n" +
      '4. Fetch only one adjacent object to prove the issue; never enumerate the range.\n' +
      '5. Report the IDOR/BOLA with the endpoint, the two responses, and the leaked fields.',
    star_count: 0,
  },
  {
    slug: 'github-2012-mass-assignment',
    title: 'GitHub 2012: Mass Assignment Privilege Escalation',
    technique: ['mass-assignment', 'privilege-escalation', 'broken-access-control'],
    min_tier: 'safe-active',
    breach_story:
      'In 2012 a researcher demonstrated a mass-assignment flaw against GitHub, then a Ruby on Rails app. A create/update form bound request parameters straight onto the database model, so adding an extra field the form never showed (an owner id, an admin flag) let the attacker set protected attributes and, in the demo, push a commit as if authorized. Root cause: unfiltered request parameters binding to sensitive model fields the user should not control.',
    prompt_body:
      'Goal: determine whether create/update endpoints accept extra fields that set protected attributes (mass assignment).\n' +
      'Steps:\n' +
      '1. Find state-changing endpoints (registration, profile update, create/edit resources) and note the fields their forms normally submit.\n' +
      '2. If source is available, read_source the handler/model to see whether the body is bound wholesale (a spread/merge of the request body) versus an explicit field allow-list.\n' +
      '3. Submit the request with one extra plausible privileged field added (role: admin, is_admin: true, owner_id, verified: true, price), staying within the safe-active tier.\n' +
      '4. Confirm via the response or a follow-up read whether the extra field was accepted and changed state. One benign proof only; do not escalate further or persist damage.\n' +
      '5. Report the endpoint, the accepted extra field, and the privilege or integrity impact.',
    star_count: 0,
  },
  {
    slug: 'british-airways-2018-magecart-skimming',
    title: 'British Airways 2018: Payment-Page Script Skimming',
    technique: ['xss', 'third-party-script', 'csp', 'client-side'],
    min_tier: 'safe-active',
    breach_story:
      'In 2018 the Magecart group stole card details from about 400,000 British Airways customers. Attackers altered a JavaScript file the site loaded (an old, modified Modernizr script) so it serialized the payment form and sent the data to a look-alike domain. The page had no Content Security Policy or Subresource Integrity to stop a tampered script from reading the form and exfiltrating it. Root cause: sensitive pages trusting third-party or injectable scripts with no integrity or content-security controls, a client-side skimming risk closely tied to cross-site scripting.',
    prompt_body:
      'Goal: find whether sensitive pages can run attacker-controlled script or load unvetted third-party script that could read form data.\n' +
      'Steps:\n' +
      '1. Load pages that handle sensitive input (login, checkout, payment) and inventory every script they include and the origins those scripts come from.\n' +
      '2. Check for a Content-Security-Policy and Subresource-Integrity on those scripts; note their absence, which is what let a tampered script run in this breach.\n' +
      '3. Probe reflected inputs on these flows with a unique benign marker and confirm whether it is rendered unescaped (reflected XSS), which would let an attacker inject a skimmer. Prove reflection only; do not fire a live payload.\n' +
      '4. If source is available, read_source to confirm whether output encoding is applied where input is reflected.\n' +
      '5. Report missing CSP/SRI on sensitive pages, unvetted third-party scripts, and any confirmed reflected-XSS sink, framed as a client-side data-theft risk.',
    star_count: 0,
  },
  {
    slug: 'myspace-2005-samy-stored-xss',
    title: 'MySpace 2005: The Samy Stored-XSS Worm',
    technique: ['stored-xss', 'xss'],
    min_tier: 'aggressive',
    breach_story:
      "In 2005 the Samy worm spread across MySpace in under a day. A profile allowed HTML and JavaScript that was stored and then executed in the browser of everyone who viewed it, so the payload added the author as a friend and copied itself onto each viewer's profile, growing exponentially. Root cause: user-supplied content stored and later rendered without sanitization, a persistent (stored) cross-site scripting flaw.",
    prompt_body:
      'Goal: find whether user-supplied content is stored and later rendered without sanitization (stored XSS). This tier is staging-only because it persists a test artifact.\n' +
      'Steps:\n' +
      '1. Identify fields whose content is saved and shown to the same or other users later (profile fields, comments, names, notes, support messages).\n' +
      '2. Submit a uniquely marked, benign, non-executing test string (a harmless tagged marker), staying within the aggressive/staging tier and using a clearly labeled test value.\n' +
      '3. Re-load the pages where that content is displayed and confirm whether the marker is rendered as active markup rather than escaped text.\n' +
      '4. If source is available, read_source the render path to confirm missing output encoding.\n' +
      '5. Report the stored-XSS sink with the input field, the display location, and evidence the marker was rendered unescaped. Note the persisted test value so it can be cleaned up.',
    star_count: 0,
  },
  {
    slug: 'uber-2016-exposed-secrets',
    title: 'Uber 2016: Secrets Left in Reachable Code',
    technique: ['secrets-exposure', 'sensitive-files', 'information-disclosure'],
    min_tier: 'passive',
    breach_story:
      'In 2016 attackers reached data on about 57 million Uber users and drivers after finding cloud access keys left in code they could reach. The keys unlocked cloud storage full of personal data. The lesson generalizes to the whole surface a web app exposes: secrets and sensitive artifacts often leak through served JavaScript, source maps, config endpoints, backup files, and exposed version-control metadata. Root cause: credentials and sensitive files reachable by someone who should not have them.',
    prompt_body:
      'Goal: find secrets and sensitive artifacts the running app or its surface exposes.\n' +
      'Steps:\n' +
      '1. Fetch and scan served JavaScript, HTML, and any source maps for hardcoded secrets: API keys, tokens, cloud access keys, passwords, private endpoints, admin emails.\n' +
      '2. Probe for commonly exposed sensitive paths (/.env, /.git/config, /config.json, backup or .bak files, /debug or /actuator style endpoints) and note any that return real content.\n' +
      '3. If source is available, read_source config and environment handling to see which secrets are meant to be server-only yet appear client-side.\n' +
      '4. remember_fact any live secret discovered, and only if safe and non-destructive, note what it would unlock without actually using it at volume.\n' +
      '5. Report each exposed secret or sensitive file with its location and the access it would grant. Keep everything read-only.',
    star_count: 0,
  },
]

function json(data: unknown, status = 200): Response {
  return new Response(data === null ? null : JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return json(null, 200)

  const token = req.headers.get('authorization')?.replace('Bearer ', '')
  if (!token) return json({ error: 'Unauthorized' }, 401)
  const user = await validateToken(token)
  if (!user) return json({ error: 'Unauthorized' }, 401)
  if (req.method === 'GET') return catalog(user.id)
  if (req.method === 'POST') return toggleStar(req, user.id)
  return json({ error: 'Method not allowed' }, 405)
})

// catalog returns the browse grid + run playbooks, merged with live star data:
// star_count (community popularity) from the aggregate view, and `starred` (has
// THIS user starred it). prompt_body is included so the desktop can hand the
// selected template to the sidecar without a second call — the desktop is the
// user's own trusted app, not a public web surface.
async function catalog(userId: string): Promise<Response> {
  const counts = new Map<string, number>()
  const { data: countRows } = await supabase
    .from('template_star_counts')
    .select('template_slug, star_count')
  for (const r of countRows ?? []) counts.set(r.template_slug, r.star_count)

  const mine = new Set<string>()
  const { data: myRows } = await supabase
    .from('template_stars')
    .select('template_slug')
    .eq('user_id', userId)
  for (const r of myRows ?? []) mine.add(r.template_slug)

  const templates = TEMPLATES.map((t) => ({
    ...t,
    star_count: counts.get(t.slug) ?? 0,
    starred: mine.has(t.slug),
  }))
  return json({ templates })
}

// toggleStar stars or unstars a template for the requesting user. The slug must be
// a known first-party template — we never persist a star for an arbitrary slug.
async function toggleStar(req: Request, userId: string): Promise<Response> {
  let body: { slug?: string; star?: boolean }
  try {
    body = await req.json()
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }
  const slug = body.slug
  if (!slug || !TEMPLATES.some((t) => t.slug === slug)) {
    return json({ error: 'unknown template' }, 400)
  }

  if (body.star === false) {
    await supabase.from('template_stars').delete().eq('user_id', userId).eq('template_slug', slug)
  } else {
    // Idempotent: the (user_id, template_slug) primary key makes a repeat star a
    // no-op rather than a duplicate.
    await supabase.from('template_stars').upsert(
      { user_id: userId, template_slug: slug },
      { onConflict: 'user_id,template_slug', ignoreDuplicates: true },
    )
  }

  const { count } = await supabase
    .from('template_stars')
    .select('*', { count: 'exact', head: true })
    .eq('template_slug', slug)
  return json({ ok: true, slug, star_count: count ?? 0, starred: body.star !== false })
}
