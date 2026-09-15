# Crash analytics SDK — research & technical plan

Status: research, not yet scoped for build. Branch `research/crash-analytics-sdk`.

## The ask

Add a Sentry-style crash/error monitoring SDK to Trojan: a developer drops a package
into their app, and when it throws/panics in production, Trojan captures the event,
groups it with past occurrences of the same bug, and surfaces it — with AI triage —
on the dashboard. Framed as "20% of what Sentry does well," not a full APM
competitor. A DDoS-detection angle was also raised; treated as a separate concern
below, since it isn't actually part of what Sentry does either.

Positioning: this is meant to round out Trojan's "security + crash team before you
hire one" pitch for early-stage teams — SAST/SCA/secrets scanning, pen-testing, and
now "what broke in prod last night," in one product.

---

## 1. How this actually works, technically

Every crash-reporting product — Sentry, Bugsnag, Rollbar, Honeybadger, GlitchTip —
is the same five-stage pipeline. The client SDK does stage 1; everything else is
Trojan's backend.

1. **Capture.** The SDK hooks the runtime's error surface and, on an unhandled
   error, collects: exception type/message, full stack trace, breadcrumbs (recent
   log lines / HTTP calls / DB queries in the preceding window), request context
   (route, headers minus secrets, user id if the app provides one), environment
   (release version, deploy id, runtime version), and — for compiled/minified code —
   enough to reverse the trace back to source later (source maps for JS, debug
   symbols for Go).
2. **Transmit.** Serialize to JSON, POST it to Trojan's ingestion endpoint over
   HTTPS, async and non-blocking so a reporting failure never becomes a second
   crash. Batched/rate-limited client-side so an error loop doesn't self-DDoS the
   ingestion endpoint.
3. **Ingest.** A public, always-on endpoint validates the project API key,
   rate-limits per project, and writes the raw event.
4. **Group (fingerprint).** Hash a normalized signature — exception type + the
   first few in-app stack frames, with file paths and line numbers kept but
   variable data (memory addresses, UUIDs, timestamps) stripped — into a
   fingerprint. New fingerprint → new "issue." Matching fingerprint → increment
   the existing issue's count and update its "last seen."  This is what turns
   50,000 raw events from one bug into "1 issue, seen 50,000 times" instead of a
   wall of noise.
5. **Symbolicate & surface.** Map minified/compiled frames back to real source
   (via uploaded source maps or debug symbols), then show the issue list: title,
   count, first/last seen, trend, affected release.

None of this is exotic — it's a well-worn pattern. The genuinely hard parts are
operational: ingesting reliably at spiky volume (a bad deploy can produce
thousands of identical events per second), storing it cheaply enough to keep
90 days of history, and not leaking customer PII in the process.

### Where Trojan could actually be better than Sentry, not just cheaper

Sentry has no idea your codebase also went through a SAST scan. Trojan does. The
one real differentiator here: when a new issue is created, hand the AI triage
pipeline (`internal/ai/triage.go` — this already exists, built for finding
triage) the stack trace plus:
- the SAST/SCA findings Trojan already has on file for that exact file/line,
- recent `git blame` on the frames in the trace,
- the dependency's advisory data if the crashing frame is in a vendored package.

The output isn't just "here's a stack trace," it's "this crash is in the same
function your last scan flagged as a possible unhandled-input issue" or "this
panic is in lodash 4.17.15, which you're still running despite the SCA finding
from three weeks ago telling you to upgrade it." That's a correlation no
Sentry/GlitchTip/Bugsnag installation can make, because none of them see your
scan history. It's also the one piece of this that's genuinely worth building
from scratch — the capture/ingest/group pipeline is not.

---

## 2. Buy vs. build (this changes the estimate a lot)

I checked the current landscape rather than assuming Trojan has to write a wire
protocol and ingestion pipeline from zero:

- **GlitchTip** — open-source, **Sentry-SDK-API-compatible**. Existing Sentry
  client SDKs (JS, Python, Go, dozens more, all already mature, already handle
  breadcrumbs/source-maps/framework integrations) point at a GlitchTip endpoint
  with a one-line config change. Self-hosts on Django + Celery + Redis +
  Postgres, one `docker-compose up`. Reported to deliver roughly 80% of Sentry's
  functionality at a fraction of the resources.
- **Bugsink** — even lighter: a single Docker container, ~512MB RAM, Sentry-SDK
  compatible, ~5 minutes to stand up.
- Building a competing wire protocol and a family of client SDKs from scratch
  (fingerprinting, breadcrumb capture, source-map upload/resolution, rate
  limiting, retry/backoff) is 3–6 engineer-months of work *before* any AI triage
  gets built — and it duplicates two OSS projects that already do it well.

**Recommendation:** don't build a capture protocol or client SDKs from scratch.
Run GlitchTip (or Bugsink) as Trojan's ingestion backend, let customers use the
existing, battle-tested Sentry SDKs pointed at Trojan's endpoint (or ship a thin
Trojan-branded wrapper around them that just sets the DSN and adds a Trojan
project token), and put 100% of the actual engineering effort into the one part
that's genuinely differentiated: the AI correlation/triage layer on top. This is
the single biggest lever on both cost and time-to-value.

---

## 3. Proposed architecture (if pursued)

```
customer's app (prod)
  └─ Sentry-compatible SDK (existing OSS SDK, Trojan DSN)
       │  HTTPS, async, batched
       ▼
Ingestion endpoint (GlitchTip, self-hosted; Trojan-branded)
       │  writes raw event, computes fingerprint, upserts issue
       ▼
Postgres (issue/event storage — GlitchTip's own schema)
       │  on *new* issue only (not every event — controls AI spend)
       ▼
Trigger → triage job  ──┐
                         │  reuses internal/ai/triage.go patterns:
                         │  - pull SAST/SCA findings for the crashing file
                         │  - pull recent git blame on the frames
                         │  - ask Claude for root-cause + fix suggestion
                         ▼
                  crash_verdicts table (Supabase Postgres, alongside
                  existing scan data — this is where Trojan's own DB
                  starts, not GlitchTip's)
       │
       ▼
Desktop app — new "Crashes" tab (same nav pattern as the existing
Reports tabs): issue list, sparkline, AI verdict, link to the file/line,
cross-link to the original SAST finding when there is one.
```

Token/billing hook: meter AI-verdict generation the same way `threat-lab`/
`compliance-lab` already meter Claude calls — this slots into the existing
token system instead of needing a new billing model.

### DDoS detection — scoped out of v1, and here's why

Sentry doesn't do this either, for a reason: meaningful DDoS detection needs
network-layer visibility (request volume, source IP distribution, TLS handshake
patterns) that an in-app SDK sitting *inside* the request handler doesn't have —
by the time your app code runs, the network layer already absorbed or passed the
flood. That's Cloudflare/AWS Shield/a WAF's job, not an APM SDK's. The one thing
worth doing here: a cheap heuristic where a sudden spike in *identical* crash
events (same fingerprint, unusual rate) gets flagged as "possible attack pattern,
not organic," since a real DDoS or exploit attempt often does manifest as an error
spike. That's a small addition on top of the grouping pipeline above, not a
separate system. True DDoS mitigation is out of scope and out of Trojan's
current infra reach.

### On "agents and \[an\] orchestrator"

Read this as: a background job runs per new issue, calls the AI triage agent,
writes a verdict, and (optionally) notifies. For an MVP a simple Postgres-backed
job queue (Supabase already gives us this) is enough — this is a low-frequency,
non-latency-sensitive job (one per *new* issue, not per event). If durability/
retry semantics become a real concern at scale, a proper workflow engine
(Inngest, Trigger.dev, Temporal) is worth revisiting then, not up front. If a
specific tool was meant by "Standard," let me know and I'll fold it in — I
couldn't place that as a proper noun in this space.

---

## 4. Pros

- **Real differentiator, not just a cheaper Sentry.** The scan-history ↔
  crash correlation is something no competitor can do without also owning your
  SAST/SCA data. That's Trojan's actual moat here.
- **Reuses existing infra.** AI triage pipeline, token metering, desktop nav
  pattern, Supabase backend — this isn't a green-field system, it's an
  extension of things already built.
- **Fits the buyer.** Exactly the audience already being pitched ("your
  security team until you hire one") — pre-seed/seed teams who'd otherwise
  skip Sentry to save $26/mo and 20 minutes of setup.
- **Stickier than a CLI scan.** Once the SDK is wired into a production
  deploy, switching cost is real — this is a meaningfully different retention
  profile than "run `trojan scan` when you remember to."
- **Buy-vs-build path is cheap.** Adopting GlitchTip's protocol/backend
  turns this from a multi-month SDK-family build into weeks of integration
  work plus the triage layer.

## 5. Cons / risks

- **Direct tension with Trojan's core pitch.** The marketing site's entire
  premise is "your code never leaves your machine, 0 bytes sent to our
  servers." A crash SDK is the opposite trust model by design — it ships live
  production runtime data (stack traces, request context, potentially PII) to
  Trojan's servers continuously. This needs very deliberate positioning
  ("scanning is local-first and always will be; crash monitoring is a
  separate, explicitly opt-in cloud feature") or it muddies the thing Trojan
  is currently known for. This is the risk I'd want a real answer to before
  building anything.
- **New always-on operational commitment.** A CLI tool that's briefly down
  costs a re-run. An ingestion endpoint that's down *loses production crash
  data permanently*. That's a different reliability bar — uptime expectations,
  on-call, incident response — for a small team pre-launch.
- **PII/compliance surface.** Stack traces and request context routinely
  contain PII. Needs scrubbing (Sentry invests heavily here), a privacy-policy
  update, and probably DPA language — non-trivial for a two-person-ish team.
- **Cost at scale.** A popular customer app having a bad night can produce
  thousands of events/second. GlitchTip handles this better than
  hand-rolled Postgres, but it's still a cost and capacity-planning problem
  Trojan doesn't currently have.
- **The bar to switch is high.** Sentry's free tier is generous, and
  GlitchTip/Bugsink are free, 5-minute self-hosted, drop-in replacements
  today. Without the AI-correlation angle actually landing, there's limited
  reason for a customer to route crashes through Trojan instead.
- **Focus risk.** Phase 7 (public launch) is still pending per the project's
  own roadmap. Crash monitoring is a second, more crowded, more
  operationally demanding market (Sentry, Datadog, Honeybadger, Bugsnag,
  Rollbar are all well-funded incumbents). Worth a deliberate check that this
  doesn't pull focus from shipping the core product's launch.

---

## 6. Recommended path, if this moves forward

**Phase 0 — validate, cheaply (days, not months).** Stand up GlitchTip
self-hosted, wrap it behind a Trojan-branded onboarding flow (issue a DSN as
part of a project, point customers at the existing JS Sentry SDK). No AI
layer yet. Ship this to a handful of existing customers and see if anyone
actually wires it in. This tests demand before any real engineering
investment.

**Phase 1 — the actual differentiator.** Build the triage job: new issue →
Claude agent with SAST/SCA/git-blame context → verdict → desktop "Crashes"
tab. This is where Trojan's angle either proves itself or doesn't.

**Phase 2 — expand, only if 0 and 1 land.** Python/Go SDK wrappers, alerting
(Slack/email on new issue), the crash-rate-spike heuristic, retention tuning.

**Before Phase 0:** get an explicit answer on the local-first positioning
tension above — that's a product/brand decision, not an engineering one, and
it should be made on purpose rather than discovered after the feature ships.

---

## Sources

- [Top 7 Sentry Alternatives for Error Tracking in 2025/2026 — Uptrace](https://uptrace.dev/comparisons/sentry-alternatives)
- [Sentry Open Source Alternative: Best Tools for 2026 — CubeAPM](https://cubeapm.com/faqs/sentry-open-source-alternatives/)
- [Best Open Source Alternatives to Sentry in 2026 — OSSAlt](https://ossalt.com/guides/best-open-source-alternatives-to-sentry-2026)
- [Self-Host Sentry or GlitchTip: Open-Source Error Tracking Alternatives (2026) — DanubeData](https://danubedata.ro/blog/self-host-sentry-glitchtip-error-tracking-2026)
- [Bugsink alternatives — AlternativeTo](https://alternativeto.net/software/bugsink)
- [Sentry SDK — Better Stack Documentation](https://betterstack.com/docs/errors/collecting-errors/sentry-sdk/)
- [Mastering Sentry: A Deep Dive into Modern Error Monitoring and Observability](https://martinuke0.github.io/posts/2026-03-30-mastering-sentry-a-deep-dive-into-modern-error-monitoring-and-observability/)
