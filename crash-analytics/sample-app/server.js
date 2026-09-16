/**
 * The demo HTTP server. Required by index.js *after* Sentry.init().
 *
 * Every route that throws does so behind a try/catch at the request boundary,
 * reports to Sentry, flushes, and then answers with a 500. The process stays up
 * so you can hit several break buttons in a row.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const Sentry = require('@sentry/node');

const checkout = require('./checkout');

const INDEX_HTML = path.join(__dirname, 'index.html');

let BOOT = { dsn: '', via: '', release: '', environment: '' };

function log(msg) {
  process.stdout.write(`[sample-app] ${msg}\n`);
}

/**
 * Attach the real request (method, url, headers, body) to the event.
 *
 * Done explicitly rather than leaning on auto-instrumentation so the demo is
 * deterministic: /boom/pii must reliably carry an Authorization header and a
 * password field into Trojan, otherwise there is nothing to prove Trojan
 * scrubbed.
 */
function captureWithRequest(err, req, body, extra) {
  return new Promise((resolve) => {
    Sentry.withScope((scope) => {
      scope.addEventProcessor((event) => {
        event.request = {
          method: req.method,
          url: `http://localhost:${BOOT.port}${req.url}`,
          headers: { ...req.headers },
          ...(body ? { data: body } : {}),
        };
        return event;
      });
      if (extra) {
        for (const [k, v] of Object.entries(extra)) scope.setExtra(k, v);
      }
      Sentry.captureException(err);
    });
    // Flush before answering so "click button, then look at Trojan" works with
    // no race. A real app would NOT block its response on this.
    Sentry.flush(3000).then(() => resolve(), () => resolve());
  });
}

function json(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size <= 64 * 1024) chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

// ── routes ────────────────────────────────────────────────────────────────

const ROUTES = {
  /** A TypeError thrown two call frames deep, so the stack trace is worth reading. */
  async '/boom'(req, res) {
    const order = { orderId: 'ord_88213', customerId: 'cus_9999', total: 149.0 };
    try {
      const receipt = checkout.completeCheckout(order);
      return json(res, 200, receipt);
    } catch (err) {
      await captureWithRequest(err, req, null, { order });
      return json(res, 500, {
        broke: 'TypeError',
        detail: err.message,
        where: 'checkout.js applyDiscount() -> loadCustomer() cache miss',
        sentTo: 'Trojan Errors',
      });
    }
  },

  /** A thrown custom DatabaseError with a distinct message. */
  async '/boom/db'(req, res) {
    try {
      checkout.reserveInventory('SKU-4471');
      return json(res, 200, { reserved: true });
    } catch (err) {
      await captureWithRequest(err, req, null, { sku: 'SKU-4471' });
      return json(res, 500, {
        broke: 'DatabaseError',
        detail: err.message,
        sentTo: 'Trojan Errors',
      });
    }
  },

  /**
   * An unhandled promise rejection. Nothing catches this; the process-level
   * handler in index.js reports it and the server keeps serving.
   */
  async '/boom/async'(req, res) {
    checkout.settlePayment('ord_77104'); // no await, no .catch() -- that is the bug
    return json(res, 202, {
      broke: 'unhandled promise rejection',
      detail: 'settlePayment() rejects in ~10ms with nothing attached to catch it',
      note: 'reported by the process-level unhandledRejection handler, then the server keeps running',
      sentTo: 'Trojan Errors',
    });
  },

  /**
   * Fires the SAME error N times. In Trojan this collapses into ONE issue with
   * a count of N. This is the grouping demo.
   */
  async '/boom/repeat'(req, res, url) {
    const requested = Number(url.searchParams.get('n') || 5);
    const n = Number.isFinite(requested) ? Math.min(Math.max(Math.trunc(requested), 1), 25) : 5;

    let message = '';
    for (let i = 0; i < n; i++) {
      try {
        checkout.renderCartBadge({ sessionId: 'sess_2f10' });
      } catch (err) {
        message = err.message;
        Sentry.captureException(err);
      }
    }
    await Sentry.flush(5000).catch(() => {});

    return json(res, 500, {
      broke: 'TypeError',
      detail: message,
      firedEvents: n,
      expectInTrojan: `1 issue with a count of ${n}, not ${n} issues`,
      sentTo: 'Trojan Errors',
    });
  },

  /**
   * An error whose request carries an Authorization: Bearer header and a
   * password-ish body. Trojan scrubs both before anything is stored -- check the
   * issue detail in the Errors tab and you should see [redacted].
   */
  async '/boom/pii'(req, res) {
    const raw = await readBody(req);

    // A plain `curl http://localhost:3003/boom/pii` with no body still needs to
    // demo something, so fall back to a canned payload.
    let body;
    try {
      body = raw ? JSON.parse(raw) : null;
    } catch {
      body = { _unparsed: raw };
    }
    if (!body) {
      body = {
        email: 'ada@example.com',
        password: 'hunter2-correct-horse',
        card_number: '4242424242424242',
      };
    }

    // If the caller did not send one, synthesize the auth header so the demo
    // works from a bare curl too.
    if (!req.headers.authorization) {
      req.headers.authorization = 'Bearer demo-auth-token-not-a-real-secret';
    }

    try {
      checkout.auditPaymentAttempt({ orderId: 'ord_31337', payment: {} });
      return json(res, 200, { audited: true });
    } catch (err) {
      await captureWithRequest(err, req, body, {
        checkout_session_token: 'cst_9f2b41ac8e77d0135aab99ee31',
        customer_email: 'ada@example.com',
      });
      return json(res, 500, {
        broke: 'TypeError',
        detail: err.message,
        carried: {
          header: 'Authorization: Bearer ...',
          bodyFields: Object.keys(body),
          extraFields: ['checkout_session_token', 'customer_email'],
        },
        expectInTrojan: 'all of the above stored as [redacted], listed under trojan_scrubbed',
        sentTo: 'Trojan Errors',
      });
    }
  },

  /** A route that actually works, so the demo is not 100% fire. */
  async '/api/checkout'(req, res) {
    const receipt = checkout.completeCheckout({
      orderId: 'ord_10022',
      customerId: 'cus_1001',
      total: 149.0,
    });
    return json(res, 200, receipt);
  },

  async '/healthz'(req, res) {
    return json(res, 200, {
      ok: true,
      service: 'trojan-errors-sample-app',
      release: BOOT.release,
      environment: BOOT.environment,
      reportingTo: BOOT.dsn.replace(/\/\/[^@]+@/, '//<key>@'),
    });
  },

  async '/config'(req, res) {
    return json(res, 200, {
      dsn: BOOT.dsn.replace(/\/\/[^@]+@/, '//<key>@'),
      dsnResolvedFrom: BOOT.via,
      release: BOOT.release,
      environment: BOOT.environment,
      sdk: `@sentry/node ${require('@sentry/node/package.json').version}`,
    });
  },
};

function start(port, boot) {
  BOOT = { ...boot, port };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);

    if (url.pathname === '/') {
      let html;
      try {
        html = fs.readFileSync(INDEX_HTML, 'utf8');
      } catch {
        html = '<h1>index.html is missing</h1>';
      }
      html = html
        .replace('{{RELEASE}}', BOOT.release)
        .replace('{{ENVIRONMENT}}', BOOT.environment)
        .replace('{{DSN}}', BOOT.dsn.replace(/\/\/[^@]+@/, '//&lt;key&gt;@'));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(html);
    }

    const handler = ROUTES[url.pathname];
    if (!handler) {
      return json(res, 404, { error: 'not found', try: Object.keys(ROUTES) });
    }

    // The request boundary. Anything a handler throws synchronously or async is
    // reported here and turned into a 500 -- the server never falls over.
    Promise.resolve(handler(req, res, url)).catch(async (err) => {
      log(`unexpected handler error on ${url.pathname}: ${err && err.message}`);
      await captureWithRequest(err, req, null, null);
      if (!res.headersSent) json(res, 500, { error: String(err && err.message) });
    });
  });

  server.listen(port, () => {
    log(`listening on http://localhost:${port}`);
    log(`release=${BOOT.release} environment=${BOOT.environment}`);
    log(`reporting to ${BOOT.dsn.replace(/\/\/[^@]+@/, '//<key>@')} (via ${BOOT.via})`);
    log('open http://localhost:' + port + ' to click the break buttons');
  });

  const shutdown = () => {
    log('shutting down');
    server.close(() => {
      Sentry.close(2000).then(() => process.exit(0), () => process.exit(0));
    });
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}

module.exports = { start };
