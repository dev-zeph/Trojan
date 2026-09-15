# Crash analytics SDK — research & technical plan

Status: research, not yet scoped for build. Branch `research/crash-analytics-sdk`.

## The ask

Add a Sentry-style crash/error monitoring SDK to Trojan: a developer drops a package
into their app, and when it throws/panics in production, Trojan captures the event,
groups it with past occurrences of the same bug, and surfaces it on the dashboard.
Framed as "20% of what Sentry does well," not a full APM competitor. A
DDoS-detection angle was also raised; treated as a separate concern below, since
it isn't actually part of what Sentry does either.

Positioning: this rounds out the product with something founders want day-to-day
(error visibility), alongside the security scanning — but it is **not** a
security feature and should not be framed, sold, or technically coupled to one.

### Decisions from review (scope is locked to this)

- **Not security-framed.** No SAST/SCA correlation, no security branding, no
  place in the security nav. This is its own standalone "Errors" surface.
  (I'd originally proposed AI-correlating crashes with scan findings as the
  differentiator — explicitly cut. Kept as a documented future idea in §7 in
  case it's worth revisiting later, but it is not in scope now.)
- **Adopt an existing open-source crash logger, don't build one.** Confirms
  the buy-vs-build call in §2 below — GlitchTip (or Bugsink), self-hosted.
  Trojan's job is the integration guide, the onboarding flow, and the
  dashboard surface, not a new ingestion protocol.
- **Trust model is resolved, not open.** The concern I raised about tension
  with "your code never leaves your machine" is addressed by the shape of
  the feature itself: this never touches source code. The customer explicitly
  opts in by adding an SDK to their *running app*; what comes back is runtime
  error events (stack trace, message, request context), not a copy of their
  codebase. Different category from scanning, and should read as an
  obviously-separate, clearly-labeled feature in the product — but not a
  blocker.
- **New requirement: mute during agentic DAST.** When Trojan's own pen-test
  agent is actively attacking a target, it will legitimately throw errors —
  that's the point of pen-testing. Those need to not show up as "your app is
  broken" noise. Design in §3a below.

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
project token), and spend the actual engineering effort on the guide, the
onboarding flow, and the dashboard surface — the parts customers touch. This is
the single biggest lever on both cost and time-to-value, and it's what keeps
this a days-to-weeks feature instead of a months-long one.

**GlitchTip vs. Bugsink, concretely:** lean GlitchTip as the default —
more mature, more framework integrations documented, and its Django/Celery
stack is a known quantity to run. Bugsink is worth a second look if the
single-container/~512MB footprint matters more than feature depth at this
stage; it's a smaller operational surface to own. Either is a config change
away from the other since both speak the Sentry protocol, so this isn't a
one-way door.

---

## 3. Proposed architecture (v1 — the locked scope)

```
customer's app (prod)
  └─ Sentry-compatible SDK (existing OSS SDK, Trojan DSN)
       │  HTTPS, async, batched
       ▼
Trojan ingestion shim (thin — auth bridge + DAST-mute check, see §3a)
       │
       ▼
GlitchTip (self-hosted; Trojan-branded, not customer-visible)
       │  writes raw event, computes fingerprint, upserts issue
       ▼
Postgres (issue/event storage — GlitchTip's own schema)
       │
       ▼
Desktop app / web dashboard — new, standalone "Errors" tab (its own
nav entry, not nested under Security or the scan Reports): issue list,
count, first/last seen, trend, stack trace, link to the file/line.
```

The one piece of custom code this genuinely requires, even at minimum scope:
a **thin ingestion shim** in front of GlitchTip rather than pointing customer
SDKs straight at it. It does two jobs: (1) maps a Trojan project/API key to
the right GlitchTip project, so customers auth against Trojan, not a
GlitchTip account they never see; (2) the DAST-mute check below. Small
surface — a handful of routes — not a rebuild of anything GlitchTip already
does.

No AI step, no token metering, no correlation with scan data in this scope —
the whole point of the simplification is that this doesn't touch the AI/
billing infrastructure at all. Straight capture → group → display.

### 3a. Muting during agentic DAST runs

Trojan's DAST orchestrator (`internal/dast`) already knows the start/end of a
pen-test run against a given target. Two options, and I'd pick the second:

- **Drop events during the run.** Simple, but if a real, unrelated production
  bug happens to fire during that window, it's lost — not acceptable for a
  feature whose entire value proposition is "never miss an error."
- **Tag, don't drop.** The shim checks an `active_dast_run_id` flag on the
  project (set by the orchestrator at run start, cleared at run end via the
  same two calls it already makes to start/stop a scan) and stamps matching
  events `source: dast_run` instead of `source: production`. The dashboard
  filters `dast_run`-tagged events out of the default "Errors" view but
  doesn't discard them — visible under a "during pen-test" filter if someone
  wants to check. Real bugs never silently disappear; pen-test noise never
  shows up as "your app is down" by default.

This is a small, mechanical addition to the shim (one flag lookup per
event) and a one-line addition to the DAST orchestrator's existing
run-start/run-end hooks — not a new subsystem.

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

With the AI-correlation idea deferred (§7), there's no agent/job pipeline in
v1's scope — GlitchTip does capture, grouping, and display on its own, no
background job needed. This section is kept for when/if §7 gets revisited:
short version, a background job per *new* issue (not per event) calling an
agent is a low-frequency, non-latency-sensitive workload a simple
Postgres-backed queue handles fine; a proper workflow engine (Inngest,
Trigger.dev, Temporal) would only be worth it at real scale. If a specific
tool was meant by "Standard," let me know and I'll fold it in — I couldn't
place that as a proper noun in this space.

---

## 4. Pros

- **Cheap to build, at this scope.** No new SDKs, no new wire protocol, no
  AI/billing integration. GlitchTip does capture, grouping, and storage;
  Trojan builds a thin auth/mute shim, a setup guide, and a dashboard tab.
  Realistically days-to-weeks, not months.
- **Fits the buyer.** Exactly the audience already being pitched ("your
  security team until you hire one") — pre-seed/seed teams who'd otherwise
  skip Sentry to save $26/mo and 20 minutes of setup, and who'd rather have
  one dashboard than five.
- **Stickier than a CLI scan.** Once the SDK is wired into a production
  deploy, switching cost is real — a meaningfully different retention
  profile than "run `trojan scan` when you remember to."
- **Doesn't touch source code, and doesn't need to be positioned as if it
  does.** It's runtime telemetry the customer explicitly opts into by adding
  an SDK to their running app — a clean, easy story, separate from scanning.
- **Low one-way-door risk.** GlitchTip and Bugsink both speak the Sentry
  protocol, so the backend choice isn't permanent, and customers are on
  standard Sentry SDKs — nothing proprietary to migrate away from later.

## 5. Cons / risks

- **New always-on operational commitment.** A CLI tool that's briefly down
  costs a re-run. An ingestion endpoint that's down *loses production crash
  data permanently*. That's a different reliability bar — uptime
  expectations, on-call, incident response — for a small team pre-launch.
- **PII/compliance surface.** Stack traces and request context routinely
  contain PII. Needs scrubbing (Sentry invests heavily here), a privacy-policy
  update, and probably DPA language — non-trivial for a small team, and worth
  doing before the first real customer sends production data through it.
- **Cost at scale.** A popular customer app having a bad night can produce
  thousands of events/second. GlitchTip handles this better than
  hand-rolled Postgres, but it's still a cost and capacity-planning problem
  Trojan doesn't currently have.
- **The bar to switch is genuinely high.** Sentry's free tier is generous,
  and GlitchTip/Bugsink are themselves free, 5-minute self-hosted, drop-in
  replacements today. At this locked-down scope the pitch to a customer is
  "one dashboard instead of two," not a capability gap — real value, but a
  quieter one than "we do something Sentry can't."
- **Focus risk.** Phase 7 (public launch) is still pending per the project's
  own roadmap. Even at minimal scope, this is a new always-on service to
  operate while that launch is still the priority — worth a deliberate
  check that it doesn't pull focus.

---

## 6. Recommended path

This is now small enough that there's really one phase, not a staged rollout:

1. Stand up GlitchTip (or Bugsink) self-hosted.
2. Build the thin ingestion shim: Trojan project token → GlitchTip project
   mapping, plus the DAST-mute check (§3a).
3. Write the setup guide: pick a language/framework, copy a snippet (this is
   just the existing Sentry SDK docs, re-pointed at a Trojan DSN — not new
   content to invent from scratch, mostly curation).
4. Add the "Errors" tab to the desktop app / dashboard, reading from
   GlitchTip's issue API.
5. Ship to a handful of existing customers, see if it gets wired in.

No separate "validate first" step needed the way the original AI-correlation
version warranted — the cost of building this at all is low enough that
shipping it *is* the validation.

---

## 7. Deferred idea, not in scope: AI correlation with scan history

Recorded here in case it's worth revisiting once plain error logging is live
and proven. Sentry has no visibility into a codebase's SAST/SCA scan history;
Trojan does. A later phase could, on a new GlitchTip issue, hand the stack
trace to the existing triage pipeline (`internal/ai/triage.go`) along with
the SAST/SCA findings on file for that file/line and recent git blame, and
surface "this crash is in the function your last scan flagged" instead of
just a stack trace. Deliberately cut from v1 because it re-introduces the
security framing this feature is explicitly not supposed to have, and it
brings in the AI/token-billing infrastructure a plain error-logging feature
doesn't need. Worth another look only if the plain version proves people
want this inside Trojan at all.

---

## Sources

- [Top 7 Sentry Alternatives for Error Tracking in 2025/2026 — Uptrace](https://uptrace.dev/comparisons/sentry-alternatives)
- [Sentry Open Source Alternative: Best Tools for 2026 — CubeAPM](https://cubeapm.com/faqs/sentry-open-source-alternatives/)
- [Best Open Source Alternatives to Sentry in 2026 — OSSAlt](https://ossalt.com/guides/best-open-source-alternatives-to-sentry-2026)
- [Self-Host Sentry or GlitchTip: Open-Source Error Tracking Alternatives (2026) — DanubeData](https://danubedata.ro/blog/self-host-sentry-glitchtip-error-tracking-2026)
- [Bugsink alternatives — AlternativeTo](https://alternativeto.net/software/bugsink)
- [Sentry SDK — Better Stack Documentation](https://betterstack.com/docs/errors/collecting-errors/sentry-sdk/)
- [Mastering Sentry: A Deep Dive into Modern Error Monitoring and Observability](https://martinuke0.github.io/posts/2026-03-30-mastering-sentry-a-deep-dive-into-modern-error-monitoring-and-observability/)
