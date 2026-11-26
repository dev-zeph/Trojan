package redact

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// sensitiveStems are the path-segment / identifier tokens that mark a
// query parameter, form field, header-style key, or assignment name as
// carrying a secret. Matching is token-based, not substring-based, so
// ordinary words such as "keyboard", "monkey", "author", "sidebar" and
// "designation" are left alone. See SensitiveParamName.
//
// jwt, bearer and otp are kept from earlier URL/header coverage; they
// do not collide with the false-positive names above.
var sensitiveStems = map[string]bool{
	"token": true, "secret": true, "key": true,
	"sid": true, "session": true, "auth": true,
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"sig": true, "signature": true, "signing": true,
	"ticket": true, "credential": true, "credentials": true,
	"jwt": true, "bearer": true, "otp": true,
	"sess": true, "jsessionid": true, "phpsessid": true,
	"code":  true, // OAuth / verification codes; wordy values are rejected later
	"oauth": true, "verifier": true,
	"authorization": true, "authentication": true,
}

// paramAllowlist is names that look a bit like the stems (for example
// "id") but are ordinary query fields, not secrets.
var paramAllowlist = map[string]bool{
	"state": true, "nonce": true, "hash": true, "page": true,
	"id": true, "sort": true, "client": true,
	"client_id": true, "client-id": true, "clientid": true,
}

// SensitiveParamName reports whether a query, path, header or assignment
// name should have its value redacted.
//
// The name is split on "_", "-" and camelCase boundaries (apiToken,
// session-token, secret_key). A name is sensitive only when one of those
// tokens equals a stem, or a longer stem such as "session" or "password"
// is a prefix of a glued token ("sessionid"). Short stems (key, sid, sig,
// auth, pass, pwd, code) must be a whole token: they are not matched as a
// prefix or infix of a longer lowercase word, which is what keeps
// "keyboard", "monkey", "author", "sidebar" and "designation" out.
func SensitiveParamName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if paramAllowlist[lower] {
		return false
	}
	for _, tok := range splitIdent(name) {
		t := strings.ToLower(tok)
		if paramAllowlist[t] {
			continue
		}
		if sensitiveStems[t] {
			return true
		}
		if longStemPrefix(t) {
			return true
		}
		if compactCompound(t) {
			return true
		}
	}
	if compactCompound(lower) {
		return true
	}
	return false
}

// longStems may appear glued to a short, known suffix without a separator
// ("sessionid", "sessiontoken"). A single-letter plural ("sessions",
// "tokens") is not enough; that is how path segments like /sessions/ stay
// visible.
var longStems = []string{
	"session", "token", "secret", "password", "passwd", "credential",
	"bearer", "ticket", "signature", "signing",
}

var allowedGlue = map[string]bool{
	"id": true, "token": true, "key": true, "secret": true,
	"val": true, "value": true, "phrase": true, "word": true,
	"hash": true, "auth": true, "code": true, "pass": true, "pwd": true,
}

func longStemPrefix(token string) bool {
	for _, s := range longStems {
		if token == s {
			return true
		}
		if strings.HasPrefix(token, s) && len(token) > len(s) {
			if allowedGlue[token[len(s):]] {
				return true
			}
		}
	}
	return false
}

// compactPrefixes + a trailing stem catch unsuffixed compounds such as
// "apikey" and "appsecret" that do not split on a separator or camelCase.
var compactPrefixes = map[string]bool{
	"api": true, "app": true, "auth": true, "private": true, "priv": true,
	"access": true, "client": true, "jwt": true, "session": true,
	"webhook": true, "oauth": true, "refresh": true, "signing": true,
	"crypto": true, "ssh": true, "rsa": true, "hmac": true,
	"aws": true, "gcp": true, "azure": true, "db": true, "database": true,
	"secret": true, "pub": true, "public": true, "master": true, "service": true,
}

var compactStems = []string{
	"token", "secret", "key", "password", "passwd", "session",
	"credential", "credentials", "ticket", "sid",
}

func compactCompound(token string) bool {
	for _, stem := range compactStems {
		if len(token) > len(stem) && strings.HasSuffix(token, stem) {
			if compactPrefixes[token[:len(token)-len(stem)]] {
				return true
			}
		}
	}
	return false
}

// splitIdent breaks name into tokens on "_", "-", "." and camelCase
// boundaries (apiToken -> "api", "Token"; oauth_token -> "oauth", "token").
func splitIdent(name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	prev, prevSize := rune(0), 0
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == '_' || r == '-' || r == '.' {
			flush()
			prev, prevSize = 0, 0
			i += size
			continue
		}
		if prev != 0 && unicode.IsLower(prev) && unicode.IsUpper(r) {
			flush()
		} else if prev != 0 && unicode.IsUpper(prev) && unicode.IsUpper(r) && i+size < len(name) {
			// XMLHttp -> XML, Http: split before the last capital of a
			// run when the next rune is lowercase.
			next, _ := utf8.DecodeRuneInString(name[i+size:])
			if unicode.IsLower(next) {
				flush()
			}
		} else if prev != 0 && unicode.IsLetter(prev) != unicode.IsLetter(r) {
			flush()
		}
		b.WriteString(name[i : i+size])
		prev, prevSize = r, size
		_ = prevSize
		i += size
	}
	flush()
	return out
}

// isSessionCookieName is narrower than SensitiveParamName: JWT_SECRET and
// api_key assignments are secrets but not cookies. Only session / sess /
// sid style names (including jsessionid and sessionid) take this type.
func isSessionCookieName(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "jsessionid" || lower == "phpsessid" || lower == "sid" || lower == "sess" || lower == "session" || lower == "sessionid" {
		return true
	}
	for _, tok := range splitIdent(name) {
		switch strings.ToLower(tok) {
		case "session", "sess", "sid", "jsessionid", "phpsessid":
			return true
		}
		t := strings.ToLower(tok)
		if strings.HasPrefix(t, "session") && longStemPrefix(t) {
			return true
		}
	}
	return false
}

func isPathIdentByte(c byte) bool {
	return c == '_' || c == '-' || c == '.' ||
		(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isPathValueStop(c byte) bool {
	return c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' ||
		c == '<' || c == '>' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// findNamedPathValues walks every "/" in text and redacts the following
// segment when the preceding segment is a secret-named path key. A regexp
// cannot do this: overlapping /name/value/name/value paths would hide the
// real key (https://x.com/api_key/VALUE would match x.com/api_key first).
func findNamedPathValues(text string, taken func(s, e int) bool) []Secret {
	if text == "" {
		return nil
	}
	var out []Secret
	for i := 0; i < len(text); i++ {
		if text[i] != '/' {
			continue
		}
		ns := i + 1
		ne := ns
		for ne < len(text) && isPathIdentByte(text[ne]) {
			ne++
		}
		if ne == ns || ne >= len(text) || text[ne] != '/' {
			continue
		}
		if !SensitiveParamName(text[ns:ne]) {
			continue
		}
		vs := ne + 1
		ve := vs
		for ve < len(text) && !isPathValueStop(text[ve]) {
			ve++
		}
		if ve-vs < 3 {
			continue
		}
		if taken != nil && taken(vs, ve) {
			continue
		}
		v := text[vs:ve]
		if !urlQueryValueOK(v) {
			continue
		}
		out = append(out, Secret{Start: vs, End: ve, Value: v, Type: "url_path"})
	}
	return out
}
