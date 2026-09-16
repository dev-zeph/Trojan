#!/usr/bin/env node
/**
 * Trojan Errors sample app -- entrypoint.
 *
 * This file stands in for a customer's running deployed service. It is wired to
 * Trojan exactly the way crash-analytics/SETUP.md tells a real customer to wire
 * theirs: the genuine `@sentry/node` SDK, pointed at a Trojan DSN.
 *
 * Ordering matters. Sentry.init() has to run before the modules it instruments
 * (http, fetch, ...) are loaded, which is why ./server is require()'d lazily
 * *after* init rather than at the top of this file.
 */
'use strict';

const Sentry = require('@sentry/node');

const PORT = Number(process.env.PORT || 3003);
const RELEASE = process.env.TROJAN_RELEASE || 'checkout-demo@1.4.2';
const ENVIRONMENT = process.env.TROJAN_ENVIRONMENT || 'production';
const CONFIG_URL = process.env.TROJAN_CONFIG_URL || 'http://127.0.0.1:3002/api/errors/config';

function log(msg) {
  process.stdout.write(`[sample-app] ${msg}\n`);
}

/**
 * Resolve the Trojan DSN.
 *   1. $TROJAN_DSN
 *   2. the Trojan Errors shim's own config endpoint (what the desktop app shows
 *      in the Errors tab setup panel)
 * Anything else is a hard, actionable failure -- an app that silently reports
 * nowhere is worse than one that refuses to boot.
 */
async function resolveDsn() {
  if (process.env.TROJAN_DSN && process.env.TROJAN_DSN.trim()) {
    return { dsn: process.env.TROJAN_DSN.trim(), via: 'TROJAN_DSN env var' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(CONFIG_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const cfg = await res.json();
    if (!cfg || !cfg.dsn) throw new Error('response had no "dsn" field');
    return { dsn: cfg.dsn, via: CONFIG_URL };
  } catch (err) {
    const reason = err && err.name === 'AbortError' ? 'timed out' : String((err && err.message) || err);

    process.stderr.write(
      [
        '',
        'ERROR: could not work out where to send errors.',
        '',
        `  $TROJAN_DSN is not set, and fetching ${CONFIG_URL}`,
        `  failed (${reason}).`,
        '',
        'Fix it with either of these:',
        '',
        '  1. Start the Trojan Errors shim so this app can discover the DSN itself:',
        '         ./crash-analytics/start.sh',
        '',
        '  2. Or pass the DSN in directly:',
        '         TROJAN_DSN="http://<key>@localhost:3002/<projectId>" node index.js',
        '',
        '     Find that DSN in the Trojan desktop app under the Errors tab, or run:',
        '         curl http://127.0.0.1:3002/api/errors/config',
        '',
        '     To demo against the storage backend alone (no shim), use the',
        '     "backendDsn" value from crash-analytics/runtime.json.',
        '',
      ].join('\n')
    );
    process.exit(1);
  }
}

async function main() {
  const { dsn, via } = await resolveDsn();

  Sentry.init({
    dsn,

    // These two are what the Trojan Errors UI displays per issue. Real apps
    // should feed them from their build/deploy pipeline.
    release: RELEASE,
    environment: ENVIRONMENT,

    // Deliberately ON in this demo so /boom/pii actually ships a secret-looking
    // header at Trojan and we can prove Trojan redacts it before storing.
    // Real apps can leave this off; Trojan scrubs either way.
    sendDefaultPii: true,

    // No performance tracing. Trojan Errors only indexes error events.
    tracesSampleRate: 0,

    // Trojan is local (http, not https) in dev, so keep the SDK quiet about it.
    // Flip on SENTRY_DEBUG=1 to see the SDK's own transport logging.
    debug: process.env.SENTRY_DEBUG === '1',

    // We take over the two process-level handlers so a demo crash never kills
    // the demo. See below.
    integrations(defaults) {
      return defaults.filter(
        (i) => i.name !== 'OnUncaughtException' && i.name !== 'OnUnhandledRejection'
      );
    },
  });

  // --- Stay alive -------------------------------------------------------
  // Report, then keep serving. Sentry's own handlers exit the process by
  // default; a demo box you have to restart after every button is useless.
  process.on('uncaughtException', (err) => {
    log(`uncaughtException: ${err && err.message}`);
    Sentry.captureException(err);
    Sentry.flush(2000).catch(() => {});
  });

  process.on('unhandledRejection', (reason) => {
    const err = reason instanceof Error ? reason : new Error(`Unhandled rejection: ${String(reason)}`);
    log(`unhandledRejection: ${err.message}`);
    Sentry.captureException(err, { tags: { unhandled_rejection: 'true' } });
    Sentry.flush(2000).catch(() => {});
  });

  // Required *after* Sentry.init so the http module gets instrumented.
  const { start } = require('./server');

  start(PORT, { dsn, via, release: RELEASE, environment: ENVIRONMENT });
}

main();
