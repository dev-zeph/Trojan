package redact

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

var (
	reShortWord = regexp.MustCompile(`^[a-z_]{1,24}$`)
	reAlg       = regexp.MustCompile(`^[A-Za-z0-9]{2,10}$`)
)

// jwtInfo describes a JWT without revealing it: the signing alg, the claim
// NAMES (never their values), and the role claim when it is a short
// lower-case word (e.g. Supabase "anon" vs "service_role"), which is what
// triage needs to tell a public client key from a server key.
func jwtInfo(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return ""
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	var claims map[string]json.RawMessage
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "=")); err == nil {
		_ = json.Unmarshal(b, &hdr)
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
		_ = json.Unmarshal(b, &claims)
	}
	var out []string
	if reAlg.MatchString(hdr.Alg) {
		out = append(out, "jwt_alg="+hdr.Alg)
	}
	if len(claims) > 0 {
		keys := make([]string, 0, len(claims))
		for k := range claims {
			if reShortWord.MatchString(strings.ToLower(k)) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) > 12 {
			keys = keys[:12]
		}
		if len(keys) > 0 {
			out = append(out, "claims="+strings.Join(keys, "|"))
		}
		var role string
		if json.Unmarshal(claims["role"], &role) == nil && reShortWord.MatchString(role) {
			out = append(out, "role="+role)
		}
	}
	return strings.Join(out, ", ")
}
