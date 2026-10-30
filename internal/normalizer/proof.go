package normalizer

import (
	"net/url"
	"regexp"
	"strings"
)

// Proof is a structured, replayable record of what made a website / DAST
// finding true: the exact request Trojan sent and the decisive signal in the
// response. It lets Trojan re-check (retest) just that one endpoint in seconds
// instead of rerunning a whole website test. Secret values (auth tokens,
// cookies, API keys) are redacted to RedactedValue; the header names and the
// identity used are kept so a retest knows which credentials to restore.
//
// Proof is optional: older findings and code findings have none. A retest of a
// finding without a Proof is inconclusive by design — there is nothing to
// replay, so a full test is the honest answer.
type Proof struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"` // secret values redacted to RedactedValue
	RequestBody     string            `json:"request_body,omitempty"`
	Identity        string            `json:"identity,omitempty"` // named identity the request was sent as, if any
	OrigStatus      int               `json:"orig_status"`
	Signal          ProofSignal       `json:"signal"`
	ResponseExcerpt string            `json:"response_excerpt,omitempty"` // first chars of the response body, for context
}

// ProofSignal is the decisive observation a retest re-checks. Kind drives the
// deterministic comparison; Marker is the concrete thing to look for (a
// reflected payload, a redirect target, a header name); Detail carries the
// finding's free-text evidence for a human reading the result.
type ProofSignal struct {
	Kind   string `json:"kind"`
	Marker string `json:"marker,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Signal kinds. Anything a retest does not recognize is treated as unknown and
// returns inconclusive — forward-compatible with a newer capturer.
const (
	SignalStatus        = "status"         // the finding is about the response status (e.g. 200 where auth was expected)
	SignalReflection    = "reflection"     // an injected payload was echoed back in the body (reflected XSS)
	SignalRedirect      = "redirect"       // the endpoint issued a redirect (open redirect)
	SignalMissingHeader = "missing_header" // a security header was absent
	SignalUnknown       = "unknown"        // no signal could be derived
)

// RedactedValue replaces a secret header's value in a stored Proof so proofs are
// safe to persist to disk and show to the model.
const RedactedValue = "[redacted]"

// secretHeaderNames are request headers whose values are credentials and must be
// redacted from a stored Proof (matched case-insensitively).
var secretHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
}

// IsSecretHeader reports whether a header carries credentials that must be
// redacted from a stored Proof (and restored from an identity to replay).
func IsSecretHeader(name string) bool {
	return secretHeaderNames[strings.ToLower(strings.TrimSpace(name))]
}

// RedactHeaders returns a copy of h with every secret header's value replaced by
// RedactedValue. Keys are preserved so a retest knows auth was present.
func RedactHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if IsSecretHeader(k) {
			out[k] = RedactedValue
		} else {
			out[k] = v
		}
	}
	return out
}

var reflectTokenRE = regexp.MustCompile(`[^\s&=]{8,}`)

// DeriveSignal classifies, deterministically, what made a response a finding so
// a retest can re-check it without the model. Priority: a reflected payload
// (reflected XSS) first, then a redirect, then the response status; otherwise
// unknown. It is pure — no network — and shared by the capturer and the tests.
func DeriveSignal(method, rawURL, reqBody string, status int, respHeaders map[string]string, respBody string) ProofSignal {
	if tok := reflectedToken(rawURL, reqBody, respBody); tok != "" {
		return ProofSignal{Kind: SignalReflection, Marker: tok}
	}
	if status >= 300 && status < 400 {
		if loc := headerGet(respHeaders, "Location"); loc != "" {
			return ProofSignal{Kind: SignalRedirect, Marker: loc}
		}
	}
	// A 2xx (resource served) or a 5xx (triggered a server error) is a signal we
	// can re-check by replaying and comparing the status; a 4xx that isn't a
	// redirect carries no clear "still vulnerable" meaning on its own.
	if (status >= 200 && status < 300) || status >= 500 {
		return ProofSignal{Kind: SignalStatus}
	}
	return ProofSignal{Kind: SignalUnknown}
}

// reflectedToken returns the longest request-supplied token (length >= 8) that
// appears verbatim in the response body, or "" when nothing is reflected.
func reflectedToken(rawURL, reqBody, respBody string) string {
	if respBody == "" {
		return ""
	}
	cands := map[string]struct{}{}
	addFormValues := func(s string) {
		for _, pair := range strings.Split(s, "&") {
			if _, v, ok := strings.Cut(pair, "="); ok {
				cands[v] = struct{}{}
				if dec, err := url.QueryUnescape(v); err == nil {
					cands[dec] = struct{}{}
				}
			}
		}
	}
	if u, err := url.Parse(rawURL); err == nil {
		addFormValues(u.RawQuery)
	}
	addFormValues(reqBody)
	for _, m := range reflectTokenRE.FindAllString(reqBody, -1) {
		cands[m] = struct{}{}
	}
	best := ""
	for c := range cands {
		c = strings.TrimSpace(c)
		if len(c) >= 8 && len(c) > len(best) && strings.Contains(respBody, c) {
			best = c
		}
	}
	return best
}

// headerGet looks up a header by name, case-insensitively, in a plain map.
func headerGet(h map[string]string, name string) string {
	if v, ok := h[name]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
