package dast

import (
	"net/url"
	"strings"

	"github.com/dev-zeph/trojan/internal/redact"
)

// Sensitive query and fragment parameter names. Values are masked; names and
// the rest of the URL shape are kept so template generation still sees the
// route and which parameters exist.
var sensitiveQueryNames = map[string]bool{
	"api_key": true, "api-key": true, "apikey": true, "key": true,
	"secret": true, "client_secret": true, "client-secret": true,
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"sig": true, "signature": true,
	"x-amz-signature": true, "x-amz-credential": true, "x-amz-security-token": true,
	"code": true, "private_token": true, "private-token": true,
	"token": true, "access_token": true, "access-token": true,
	"refresh_token": true, "refresh-token": true, "id_token": true, "id-token": true,
	"jwt": true, "session": true, "auth": true,
	"access_key": true, "access-key": true, "accesskey": true,
	"bearer": true, "otp": true,
}

// RedactTemplateRequest returns a copy of req whose TargetURL and every
// Endpoint.URL have been rewritten for the dast-templates call: param names
// and path shape are kept, secret values and high-entropy path segments are
// replaced with AI descriptors, and userinfo is stripped or labelled.
func RedactTemplateRequest(req TemplateRequest) TemplateRequest {
	out := req
	out.TargetURL = RedactURL(req.TargetURL)
	if req.Endpoints == nil {
		return out
	}
	out.Endpoints = make([]Endpoint, len(req.Endpoints))
	for i, e := range req.Endpoints {
		e.URL = RedactURL(e.URL)
		out.Endpoints[i] = e
	}
	return out
}

// RedactURL masks secrets in a single URL string while keeping its structure.
// Unparseable input falls back to the general redactor.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return redact.Text(raw)
	}

	if u.User != nil {
		u.User = redactUserinfo(u.User)
	}

	if u.Path != "" {
		u.Path = redactPath(u.Path)
		// url.Parse puts an escaped path in Opaque/Path; keep RawPath empty so
		// String() uses the already-redacted Path.
		u.RawPath = ""
	}

	if u.RawQuery != "" {
		u.RawQuery = redactQuery(u.RawQuery)
	}
	if u.Fragment != "" {
		if strings.Contains(u.Fragment, "=") {
			u.Fragment = redactQuery(u.Fragment)
			u.RawFragment = ""
		} else if shouldMaskSegment(u.Fragment) {
			u.Fragment = maskValue(u.Fragment, "url_fragment")
			u.RawFragment = ""
		}
	}

	// Assemble the URL ourselves so labels are not percent-encoded. Do not
	// run redact.Text over the result: labels would be treated as new secrets.
	return formatRedactedURL(u)
}

func formatRedactedURL(u *url.URL) string {
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString("://")
	}
	if u.User != nil {
		b.WriteString(u.User.Username())
		if pass, ok := u.User.Password(); ok {
			b.WriteByte(':')
			b.WriteString(pass)
		}
		b.WriteByte('@')
	}
	b.WriteString(u.Host)
	if u.Path != "" {
		b.WriteString(u.Path)
	}
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	} else if u.ForceQuery {
		b.WriteByte('?')
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.Fragment)
	}
	return b.String()
}

func redactUserinfo(user *url.Userinfo) *url.Userinfo {
	name := user.Username()
	pass, hasPass := user.Password()
	if hasPass {
		pass = maskValue(pass, "url_password")
	}
	if name != "" && shouldMaskSegment(name) {
		name = maskValue(name, "url_username")
	}
	if hasPass {
		return url.UserPassword(name, pass)
	}
	if name != "" && shouldMaskSegment(user.Username()) {
		return url.User(name)
	}
	if name == "" && hasPass {
		return url.UserPassword("", pass)
	}
	return user
}

func redactPath(path string) string {
	if path == "" || path == "/" {
		return path
	}
	leading := strings.HasPrefix(path, "/")
	trailing := strings.HasSuffix(path, "/") && len(path) > 1
	parts := strings.Split(path, "/")
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			decoded = seg
		}
		if hits := redact.Find(decoded); len(hits) > 0 {
			parts[i] = maskValue(decoded, hits[0].Type)
			continue
		}
		if i > 0 && isSensitivePathKey(parts[i-1]) && len(decoded) >= 4 {
			parts[i] = maskValue(decoded, "url_path")
			continue
		}
		if shouldMaskSegment(decoded) {
			parts[i] = maskValue(decoded, "url_path")
		}
	}
	out := strings.Join(parts, "/")
	if leading && !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	if trailing && !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

func redactQuery(raw string) string {
	// Preserve parameter order and repeated keys; only rewrite values.
	var b strings.Builder
	start := 0
	for start <= len(raw) {
		if start == len(raw) {
			break
		}
		amp := strings.IndexByte(raw[start:], '&')
		var part string
		if amp < 0 {
			part = raw[start:]
			start = len(raw)
		} else {
			part = raw[start : start+amp]
			start = start + amp + 1
		}
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(redactQueryPair(part))
		if amp < 0 {
			break
		}
	}
	return b.String()
}

func redactQueryPair(part string) string {
	eq := strings.IndexByte(part, '=')
	if eq < 0 {
		if shouldMaskSegment(part) {
			return maskValue(part, "url_query")
		}
		return part
	}
	key, val := part[:eq], part[eq+1:]
	decoded, err := url.QueryUnescape(val)
	if err != nil {
		decoded = val
	}
	name := strings.ToLower(key)
	sensitive := sensitiveQueryNames[name]
	if !sensitive {
		if hits := redact.Find(decoded); len(hits) > 0 {
			return key + "=" + maskValue(decoded, hits[0].Type)
		}
		if shouldMaskSegment(decoded) {
			return key + "=" + maskValue(decoded, "url_query")
		}
		return part
	}
	if decoded == "" {
		return part
	}
	return key + "=" + maskValue(decoded, "url_query")
}

// shouldMaskSegment reports whether a path segment or similarly isolated
// token should be labelled. Short numeric IDs and ordinary slugs stay visible
// so templates still target the route.
func shouldMaskSegment(seg string) bool {
	if len(seg) < 16 {
		return false
	}
	if len(redact.Find(seg)) > 0 {
		return true
	}
	if isOrdinarySlug(seg) {
		return false
	}
	e := redact.Entropy(seg)
	if len(seg) >= 22 && e >= 3.5 {
		return true
	}
	return len(seg) >= 16 && e >= 4.0
}

func isOrdinarySlug(s string) bool {
	// UUIDs, numeric IDs, and kebab/snake words are route shape, not secrets.
	hexish := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-':
			hexish++
		}
	}
	if hexish == len(s) && strings.Count(s, "-") >= 4 {
		return true // UUID-shaped
	}
	allNum := true
	for _, r := range s {
		if r < '0' || r > '9' {
			allNum = false
			break
		}
	}
	if allNum {
		return true
	}
	return !strings.ContainsAny(s, "+/=_") && strings.IndexFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.')
	}) < 0
}

func maskValue(v, typ string) string {
	return redact.Descriptor(redact.Secret{Value: v, Type: typ}, "", "")
}

func isSensitivePathKey(seg string) bool {
	n := strings.ToLower(seg)
	switch n {
	case "api_key", "api-key", "apikey", "access_key", "access-key", "accesskey",
		"access_token", "access-token", "token", "secret", "auth", "jwt",
		"password", "bearer", "key", "otp":
		return true
	}
	return false
}
