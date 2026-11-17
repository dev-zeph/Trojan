// Case-sensitive dangerous-scheme checks that an attacker can bypass with a
// different casing (JavaScript:, JAVASCRIPT:) or a scheme the filter forgot.

function renderLink(url) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  const href = /^javascript:/.test(url) ? "#" : url;
  return `<a href="${href}">link</a>`;
}

function blockData(url) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  if (/^data:/.test(url)) return "#";
  return url;
}

function sanitizeHref(href) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  return href.replace(/^vbscript:/, "");
}

function matchScheme(link) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  return link.match(/^javascript:/) ? "#" : link;
}

function startsWithScheme(href) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  if (href.startsWith("javascript:")) return "#";
  return href;
}

function exactScheme(url) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  return url === "data:text/html" ? "#" : url;
}

function indexOfScheme(redirect) {
  // ruleid: trojan-js-case-sensitive-scheme-filter
  if (redirect.indexOf("javascript:") === 0) return "/";
  return redirect;
}

// A case-insensitive regex (i flag) cannot be bypassed by casing.
function renderLinkSafe(url) {
  // ok: trojan-js-case-sensitive-scheme-filter
  const href = /^javascript:/i.test(url) ? "#" : url;
  return `<a href="${href}">link</a>`;
}

// The URL is lower-cased before the comparison.
function startsWithSafe(href) {
  // ok: trojan-js-case-sensitive-scheme-filter
  if (href.toLowerCase().startsWith("javascript:")) return "#";
  return href;
}

function exactSchemeSafe(url) {
  // ok: trojan-js-case-sensitive-scheme-filter
  return url.toLowerCase() === "data:text/html" ? "#" : url;
}

// Matching a safe scheme (allow-list style) is not the bug.
function isHttp(url) {
  // ok: trojan-js-case-sensitive-scheme-filter
  return /^https?:/.test(url);
}

// Not a URL value (the variable is plain text), so the check is out of scope.
function parseHeading(text) {
  // ok: trojan-js-case-sensitive-scheme-filter
  return /^data:/.test(text) ? null : text;
}
