# Sample app: "Checkout Service"

A deliberately breakable Node.js service. It stands in for a customer's running
app so you can demo Trojan Errors without needing a real customer.

It is wired to Trojan exactly the way `crash-analytics/SETUP.md` tells a real
founder to wire theirs: the genuine `@sentry/node` SDK pointed at a Trojan DSN.
Nothing about it is special-cased. If this works, a customer's app works.

- Port: `3003`
- Release: `checkout-demo@1.4.2`
- Environment: `production`
- Reports to: whatever DSN the Trojan Errors shim hands out at `:3002`

## Run it

The normal way, as part of the whole stack:

```bash
./crash-analytics/start.sh
open http://localhost:3003
```

On its own, with the shim already up:

```bash
cd crash-analytics/sample-app
npm install          # only needed once
node index.js
```

It discovers its DSN at boot from `http://127.0.0.1:3002/api/errors/config`.
Override anything with env vars:

```bash
PORT=3010 \
TROJAN_RELEASE="checkout-demo@1.5.0" \
TROJAN_ENVIRONMENT="staging" \
TROJAN_DSN="http://<key>@localhost:3002/1" \
node index.js
```

If it cannot find a DSN it refuses to boot and tells you how to fix it. An app
that silently reports nowhere is worse than one that will not start.

## Drive it

Open <http://localhost:3003> and click the buttons. Each one fires the real
request and prints the response inline, so the whole demo is clickable.

Everything is also a plain curl:

```bash
curl -s http://localhost:3003/boom
curl -s http://localhost:3003/boom/db
curl -s http://localhost:3003/boom/async
curl -s "http://localhost:3003/boom/repeat?n=5"
curl -s -X POST http://localhost:3003/boom/pii
```

Then read the errors back out of Trojan:

```bash
curl -s "http://127.0.0.1:3002/api/errors/issues?filter=all"
```

## Endpoints

| Method | Path | Status | What breaks |
|--------|------|--------|-------------|
| GET  | `/` | 200 | The clickable console. Not instrumented. |
| GET  | `/api/checkout` | 200 | Nothing. Completes an order for a customer who is in the cache. |
| GET  | `/healthz` | 200 | Nothing. Echoes release, environment, and the DSN with the key masked. |
| GET  | `/config` | 200 | Nothing. Shows where the DSN came from and the SDK version. |
| GET  | `/boom` | 500 | `TypeError`. `loadCustomer()` misses the cache and returns `undefined`, so `applyDiscount()` reads `.discountRate` off nothing, two call frames deep. The stack trace is the point. |
| GET  | `/boom/db` | 500 | `DatabaseError`. A custom error class with its own message, so it groups separately from the TypeErrors. |
| GET  | `/boom/async` | 202 | Unhandled promise rejection. `settlePayment()` is called with no `await` and no `.catch()`, rejects about 10ms later, and is reported by the process-level `unhandledRejection` handler. The route has already answered 202 by then. |
| GET  | `/boom/repeat?n=5` | 500 | The same cart-badge `TypeError`, fired N times (1 to 25, default 5). This is the grouping demo: Trojan must show **one** issue with a count of N, not N issues. |
| POST | `/boom/pii` | 500 | `TypeError`, with an `Authorization: Bearer` header, an `x-api-key`, and a body holding an email, a password, a card number, and a session token. This is the scrubbing demo: all of it must be stored as `[redacted]` and listed in the issue's `scrubbed` array. |

`/boom/pii` also works from a bare `curl` with no body or headers. It synthesizes
a canned secret-looking payload so the demo never falls flat.

## Why it stays up

Sentry's default `OnUncaughtException` and `OnUnhandledRejection` integrations
are removed in `index.js` and replaced with handlers that report and then keep
serving. A demo box you have to restart after every button is useless. Real apps
should leave the defaults alone.

Each failing route also flushes to Trojan before it answers, so "click the
button, then look at the Errors tab" has no race in it. Real apps should not
block a response on their error reporting.

## Files

| File | What it is |
|------|------------|
| `index.js` | Entrypoint. `Sentry.init()` runs first, then `./server` is required. |
| `server.js` | The HTTP server and all the routes. Serves `index.html` at `/`. |
| `checkout.js` | Fake business logic. Every function is buggy in a different way. |
| `index.html` | The clickable console. Plain HTML, no build step, no CDN. `server.js` substitutes `{{RELEASE}}`, `{{ENVIRONMENT}}`, and `{{DSN}}` at request time. |
