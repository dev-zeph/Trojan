# Send your app's errors to Trojan

Five minutes, three steps. Your app keeps running the whole time.

Trojan Errors speaks the Sentry wire protocol, so you install the standard
`@sentry/node` SDK and point it at a Trojan DSN. No Trojan SDK, no vendor
library, nothing to rip out later.

---

## 1. Get your DSN

Open the Trojan desktop app, go to the **Errors** tab, and copy the DSN from the
setup panel. It looks like this:

```
http://f5112336bc67c060193d7e22f82e6cf5@localhost:3002/1
```

Same thing from a terminal:

```bash
curl -s http://127.0.0.1:3002/api/errors/config
```

Treat the DSN as config, not as a constant. Read it from an env var:

```bash
# .env
TROJAN_DSN="http://f5112336bc67c060193d7e22f82e6cf5@localhost:3002/1"
```

---

## 2. Install and initialize

```bash
npm install @sentry/node
```

Create `instrument.js` next to your entrypoint:

```js
// instrument.js
const Sentry = require('@sentry/node');

Sentry.init({
  dsn: process.env.TROJAN_DSN,

  // Shown on every issue in the Errors tab. Feed these from your deploy
  // pipeline so you can tell which build broke.
  release: process.env.GIT_SHA || 'my-api@1.0.0',
  environment: process.env.NODE_ENV || 'production',

  // Trojan only indexes error events. Leave tracing off.
  tracesSampleRate: 0,
});
```

Load it as the **very first line** of your entrypoint, before anything else:

```js
// index.js
require('./instrument');            // must be first

const express = require('express');
const Sentry = require('@sentry/node');

const app = express();

app.get('/', (req, res) => res.send('ok'));

app.get('/debug-trojan', () => {
  throw new Error('Trojan Errors test error');
});

// After your routes, before any other error middleware.
Sentry.setupExpressErrorHandler(app);

app.listen(3000);
```

ESM version:

```js
// instrument.mjs
import * as Sentry from '@sentry/node';

Sentry.init({
  dsn: process.env.TROJAN_DSN,
  release: process.env.GIT_SHA || 'my-api@1.0.0',
  environment: process.env.NODE_ENV || 'production',
  tracesSampleRate: 0,
});
```

```bash
node --import ./instrument.mjs index.mjs
```

### Why the ordering matters

The SDK works by patching `http`, `express`, your database driver and so on as
they load. Anything already imported when `Sentry.init()` runs is never patched,
so its errors arrive with no request attached, or do not arrive at all. First
line, every time. With ESM, `--import` is the only way to get in early enough.

---

## 3. Verify

Start your app and hit the test route:

```bash
curl -s localhost:3000/debug-trojan
```

It should appear in the Trojan desktop app under **Errors** within a second or
two. From a terminal:

```bash
curl -s "http://127.0.0.1:3002/api/errors/issues?filter=all"
```

Look for `"value": "Trojan Errors test error"`.

Nothing showed up? Check these in order:

```bash
# 1. Is Trojan Errors actually running?
curl -s http://127.0.0.1:3002/api/errors/health
# -> {"ok":true,...,"backendReachable":true,"projectConfigured":true}

# 2. Is your app reading the DSN you think it is?
node -e 'console.log(process.env.TROJAN_DSN)'

# 3. Watch the SDK's own transport logging.
SENTRY_DEBUG=1 node index.js
```

A DSN with a non-numeric project id will make the SDK throw `BadDsn` at startup.
Copy the DSN exactly as Trojan gives it to you.

Delete `/debug-trojan` once you have seen it work.

---

## Release and environment

These two fields are what make the Errors tab useful instead of just noisy. Set
them from your deploy pipeline:

```js
Sentry.init({
  dsn: process.env.TROJAN_DSN,
  release: process.env.VERCEL_GIT_COMMIT_SHA || process.env.GIT_SHA,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 0,
});
```

```bash
# Docker, CI, wherever you build
GIT_SHA=$(git rev-parse --short HEAD)
```

With those set you can answer "did my deploy cause this" by looking, rather than
by guessing.

---

## Python

```bash
pip install sentry-sdk
```

```python
# instrument.py
import os
import sentry_sdk

sentry_sdk.init(
    dsn=os.environ["TROJAN_DSN"],
    release=os.environ.get("GIT_SHA", "my-worker@1.0.0"),
    environment=os.environ.get("APP_ENV", "production"),
    traces_sample_rate=0,
)
```

Import it first, before Flask, Django, your ORM, or anything else:

```python
# app.py
import instrument  # must be first

from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

@app.route("/debug-trojan")
def debug_trojan():
    raise ValueError("Trojan Errors test error")
```

The SDK auto-detects Flask, Django, FastAPI, Celery and friends, so there is no
framework-specific wiring to add. Unhandled exceptions are reported for you.

To report something you already caught:

```python
try:
    charge_card(order)
except PaymentError:
    sentry_sdk.capture_exception()
    raise
```

Same in Node:

```js
try {
  await chargeCard(order);
} catch (err) {
  Sentry.captureException(err);
  throw err;
}
```

---

## What Trojan stores, and what it scrubs

**Trojan Errors never touches your source code.** This is runtime telemetry sent
by your running app: an error happened, here is its type, message, and stack. No
repository access, no file upload, no build artifacts, no source maps. Trojan
only ever sees the few lines of context your own SDK chose to attach to a crash.

### Stored

- Error type, message, and stack trace, including the source lines the SDK
  attached as context around each frame
- The grouping fingerprint, first seen, last seen, and event count
- `release`, `environment`, server name, and runtime version
- Request method, URL, and headers, after scrubbing
- The `extra` context and breadcrumbs you attached, after scrubbing

### Scrubbed before storage

Scrubbing runs in Trojan's ingest path **before** anything is written to disk.
The storage layer never sees the original value. Redacted values are replaced
with `[redacted]` and the field path is recorded on the event, so the UI can
tell you exactly what was dropped rather than quietly hiding it.

**Headers dropped by name, whatever the value:**
`authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`.
Request cookies are dropped wholesale.

**Keys dropped by name**, anywhere in request data, `extra`, `user`,
breadcrumbs, or stack-frame local variables. A key is treated as a secret if its
name contains any of:

```
pass   secret   token   auth   key   cred   session
```

That catches `password`, `api_key`, `access_token`, `session_id`,
`aws_secret_access_key`, `credentials`, and so on, in any casing.

**Values redacted by shape**, even under an innocent-looking key name, in
messages, exception messages, `extra`, `user`, breadcrumbs, and frame locals:

| Pattern | Example |
|---------|---------|
| Email addresses | `ada@example.com` |
| Card-shaped digit runs, 13 to 19 digits | `4242 4242 4242 4242` |
| `Bearer` / `Token` / `Basic` prefixed credentials | `Bearer sk_live_...` |
| Long opaque tokens, 32+ chars | `cst_9f2b41ac8e77d0135aab99ee31...` |

### Seeing it work

Open any issue in the Errors tab. Redacted fields read `[redacted]`, and the
issue lists every path it scrubbed. For an error that carried an auth header and
a password body, you get something like:

```json
{
  "scrubbed": [
    "extra.checkout_session_token",
    "extra.customer_email",
    "request.data.card_number",
    "request.data.email",
    "request.data.password",
    "request.headers.authorization",
    "request.headers.x-api-key"
  ],
  "request": {
    "method": "POST",
    "url": "http://localhost:3003/boom/pii",
    "headers": {
      "content-type": "application/json",
      "authorization": "[redacted]",
      "x-api-key": "[redacted]"
    }
  }
}
```

You can see this yourself against the bundled demo service:

```bash
./crash-analytics/start.sh
curl -s -X POST http://localhost:3003/boom/pii
curl -s "http://127.0.0.1:3002/api/errors/issues?filter=all"
```

Scrubbing is belt and braces, not a substitute for judgement. If your app puts a
secret in an error message under a field called `colour`, nothing can save you.
Do not log secrets.

---

## Pen-test runs

When you run a Trojan pen test against your own app, the errors it provokes are
tagged as pen-test traffic rather than thrown away. The Errors tab hides them by
default and a filter chip brings them back.

An issue is only ever hidden if **every** recorded event for it happened during
a pen test. One real production event and the whole issue is treated as
production. A genuine bug can never be buried under pen-test noise.

---

## Reference

| Thing | Where |
|-------|-------|
| Your DSN | Errors tab, or `GET http://127.0.0.1:3002/api/errors/config` |
| Health check | `GET http://127.0.0.1:3002/api/errors/health` |
| Issue list | `GET http://127.0.0.1:3002/api/errors/issues?filter=production\|dast\|all` |
| Start the stack | `./crash-analytics/start.sh` |
| Stop the stack | `./crash-analytics/stop.sh` |
| Working example | `crash-analytics/sample-app/` |
