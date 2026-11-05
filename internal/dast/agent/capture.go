package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// maxCapturedIdentities bounds how many sessions one run may auto-register, so a
// chatty login endpoint can't fill memory with near-duplicate identities. Past
// the cap, the agent keeps the ones it has and can still probe as them.
const maxCapturedIdentities = 8

// minSecretLen is the shortest value we treat as a session secret. Below this a
// cookie/token value is almost certainly a flag or a short code, not a usable
// session, and redacting it would mangle ordinary report text.
const minSecretLen = 8

// sessionCookieHints are substrings that mark a Set-Cookie as an authentication
// session rather than an analytics/consent/CSRF cookie. Matched case-insensitively
// against the cookie NAME. Kept conservative on purpose: a false positive would
// register a useless identity, and CSRF tokens are deliberately excluded because
// they are not, on their own, an authenticated session.
var sessionCookieHints = []string{
	"session", "sess", "sid", "auth", "token", "jwt", "login",
	"phpsessid", "jsessionid", "connect.sid", "_session", "access",
}

// tokenBodyFields are JSON response fields whose string value is, by convention,
// a bearer token the client is meant to send back as Authorization.
var tokenBodyFields = []string{
	"token", "access_token", "accesstoken", "jwt", "id_token", "idtoken",
	"auth_token", "authtoken", "bearer", "authorization",
}

// autoCaptureFromResponse inspects a probe response for a session the agent can
// reuse and registers it as a named identity. It looks at cookies (session/auth
// cookies) first, then a bearer token in a JSON body. Returns the new identity's
// name and a short source label, or "" if nothing capturable was found or it was a
// duplicate. No secret ever appears in the returned label.
//
// jarCookies are the cookies the probe's per-request jar accumulated across the
// whole redirect chain; they are preferred over the final response's headers
// because a login often sets its session cookie on a 302 that the last hop no
// longer carries. header is still consulted as a fallback for responses handled
// without the jar (e.g. tests).
func (t *Toolbox) autoCaptureFromResponse(method, url string, header http.Header, jarCookies []*http.Cookie, body string) (string, string) {
	where := strings.ToUpper(strings.TrimSpace(method)) + " " + pathOf(url)

	// 1) Cookies: collect every cookie the exchange set, and register them as one
	// Cookie header when at least one looks like an auth session. A real session
	// often spans more than one cookie, so we replay them together.
	cookies := jarCookies
	if len(cookies) == 0 {
		cookies = (&http.Response{Header: header}).Cookies()
	}
	if len(cookies) > 0 {
		var pairs []string
		authy := false
		for _, c := range cookies {
			if c.Value == "" {
				continue
			}
			pairs = append(pairs, c.Name+"="+c.Value)
			if looksLikeSessionCookie(c.Name) && len(c.Value) >= minSecretLen {
				authy = true
			}
		}
		if authy && len(pairs) > 0 {
			headers := map[string]string{"Cookie": strings.Join(pairs, "; ")}
			if name, ok := t.registerCapturedIdentity(headers, "session cookie from "+where); ok {
				return name, "session cookie from " + where
			}
			return "", "" // found a session but it was a duplicate — don't re-announce
		}
	}

	// 2) Bearer token in a JSON body (a login/refresh endpoint handing one back).
	if tok := bearerTokenFromBody(body); tok != "" {
		headers := map[string]string{"Authorization": "Bearer " + tok}
		if name, ok := t.registerCapturedIdentity(headers, "bearer token from "+where); ok {
			return name, "bearer token from " + where
		}
	}
	return "", ""
}

// CaptureFromFact registers a session from a remembered credential/token fact, so
// a token the agent chose to remember (rather than one we spotted in a response)
// is also replayable by name. Returns the identity name and source label, or "".
func (t *Toolbox) CaptureFromFact(f Fact) (string, string) {
	kind := strings.ToLower(strings.TrimSpace(f.Kind))
	val := strings.TrimSpace(f.Value)
	if val == "" || (kind != "credential" && kind != "token") || len(val) < minSecretLen {
		return "", ""
	}
	var headers map[string]string
	switch {
	case strings.HasPrefix(strings.ToLower(val), "bearer "):
		headers = map[string]string{"Authorization": val}
	case looksLikeCookiePair(val):
		headers = map[string]string{"Cookie": val}
	case strings.Count(val, ".") == 2 || kind == "token":
		// A JWT (header.payload.signature) or an explicit token → Authorization.
		headers = map[string]string{"Authorization": "Bearer " + val}
	default:
		// A credential we can't shape into a usable header (e.g. "user:pass") is
		// left as a fact only; forcing it into a header would send garbage auth.
		return "", ""
	}
	label := "remembered " + kind
	if f.From != "" {
		label += " from " + f.From
	}
	if name, ok := t.registerCapturedIdentity(headers, label); ok {
		return name, label
	}
	return "", ""
}

// registerCapturedIdentity adds a captured session as "captured-N". It dedupes by
// header signature (against both captured and user-supplied identities), is bounded
// by maxCapturedIdentities, and is safe for concurrent use. Returns the new name
// and true, or "" and false when nothing new was registered.
func (t *Toolbox) registerCapturedIdentity(headers map[string]string, source string) (string, bool) {
	if len(headers) == 0 {
		return "", false
	}
	sig := identitySignature(headers)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.identities == nil {
		t.identities = make(map[string]Identity)
	}
	if t.capturedSeen == nil {
		t.capturedSeen = make(map[string]bool)
	}
	if t.capturedSeen[sig] {
		return "", false
	}
	// Never duplicate a session we already hold under any name (incl. user logins).
	for _, id := range t.identities {
		if identitySignature(id.Headers) == sig {
			t.capturedSeen[sig] = true
			return "", false
		}
	}
	if t.capturedSeq >= maxCapturedIdentities {
		return "", false
	}
	t.capturedSeq++
	name := fmt.Sprintf("captured-%d", t.capturedSeq)
	// Extremely unlikely, but make sure we never clobber a user identity named
	// "captured-N".
	for {
		if _, clash := t.identities[name]; !clash {
			break
		}
		t.capturedSeq++
		name = fmt.Sprintf("captured-%d", t.capturedSeq)
	}
	t.identities[name] = Identity{Name: name, Headers: cloneHeaders(headers), Source: source}
	t.identOrder = append(t.identOrder, name)
	t.capturedSeen[sig] = true
	return name, true
}

// looksLikeSessionCookie reports whether a cookie name reads like an auth session.
func looksLikeSessionCookie(name string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "csrf") || strings.Contains(n, "xsrf") {
		return false // a CSRF token is not, by itself, a session
	}
	for _, h := range sessionCookieHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

// looksLikeCookiePair reports whether a value looks like "name=value" cookie data.
func looksLikeCookiePair(v string) bool {
	eq := strings.IndexByte(v, '=')
	return eq > 0 && eq < len(v)-1 && !strings.Contains(v, " ")
}

// bearerTokenFromBody pulls a bearer token out of a JSON object body, if one of
// the conventional token fields holds a plausible string value. Non-JSON bodies
// and short values return "".
func bearerTokenFromBody(body string) string {
	body = strings.TrimSpace(body)
	if body == "" || body[0] != '{' {
		return ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return ""
	}
	// Case-insensitive field lookup.
	lower := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		lower[strings.ToLower(k)] = v
	}
	for _, field := range tokenBodyFields {
		raw, ok := lower[field]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		s = strings.TrimSpace(strings.TrimPrefix(s, "Bearer "))
		s = strings.TrimPrefix(s, "bearer ")
		if len(s) >= minSecretLen {
			return s
		}
	}
	return ""
}

// identitySignature is a stable fingerprint of a header set, for dedupe.
func identitySignature(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(strings.ToLower(k))
		b.WriteByte('=')
		b.WriteString(headers[k])
		b.WriteByte('\n')
	}
	return b.String()
}

func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// ── Redaction ────────────────────────────────────────────────────────────────
//
// Identity secrets (user-supplied and captured) must not land in an artifact that
// can be shared or committed. checkpoint.go already keeps the full checkpoint out
// of git (~/.trojan, 0600) and never writes the access token; this does the same
// for identity secrets in the two structured artifacts that DO travel: the report
// (RunResult.Findings, which persistScan writes and the brain learns) and the
// findings/facts copied into a checkpoint. The raw conversation is relied on to
// stay under the 0600 checkpoint handling, since Claude needs it replayed verbatim.

// secretValues returns the sensitive substrings to scrub: each identity header
// value, plus the token/cookie value inside a "Bearer x" or "k=v" so the secret is
// caught even when quoted without its header name. Short values are skipped.
func (t *Toolbox) secretValues() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < minSecretLen || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, id := range t.identities {
		for k, v := range id.Headers {
			add(v)
			if strings.EqualFold(k, "authorization") {
				add(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer ")))
			}
			if strings.EqualFold(k, "cookie") {
				for _, pair := range strings.Split(v, ";") {
					if _, val, ok := strings.Cut(pair, "="); ok {
						add(val)
					}
				}
			}
		}
	}
	// Longest-first so a token is scrubbed before its own prefix.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

const redactedMark = "[redacted-identity-secret]"

// redactSecrets replaces every known secret substring in s with a placeholder.
func redactSecrets(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, redactedMark)
		}
	}
	return s
}

// RedactCandidates returns a copy of the findings with identity secrets scrubbed
// from every free-text field. A no-op when no identities carry a secret.
func (t *Toolbox) RedactCandidates(in []Candidate) []Candidate {
	secrets := t.secretValues()
	if len(secrets) == 0 {
		return in
	}
	out := make([]Candidate, len(in))
	for i, c := range in {
		c.Title = redactSecrets(c.Title, secrets)
		c.URL = redactSecrets(c.URL, secrets)
		c.Evidence = redactSecrets(c.Evidence, secrets)
		c.Rationale = redactSecrets(c.Rationale, secrets)
		out[i] = c
	}
	return out
}

// RedactFacts returns a copy of the facts with identity secrets scrubbed. The
// Value field is where a captured token most often sits, so it is scrubbed too;
// the agent reuses sessions by `identity` name now, not by pasting the raw value.
func (t *Toolbox) RedactFacts(in []Fact) []Fact {
	secrets := t.secretValues()
	if len(secrets) == 0 {
		return in
	}
	out := make([]Fact, len(in))
	for i, f := range in {
		f.Summary = redactSecrets(f.Summary, secrets)
		f.Value = redactSecrets(f.Value, secrets)
		f.From = redactSecrets(f.From, secrets)
		f.Enables = redactSecrets(f.Enables, secrets)
		out[i] = f
	}
	return out
}
