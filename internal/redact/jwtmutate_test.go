package redact

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var jb64 = base64.RawURLEncoding

// makeJWT builds a compact JWT from header/claims JSON and a raw signature.
func makeJWT(t *testing.T, hdr, claims map[string]any, sig string) string {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	return jb64.EncodeToString(hb) + "." + jb64.EncodeToString(cb) + "." + sig
}

// decodeJWT returns header and claims maps from a token (for assertions).
func decodeJWT(t *testing.T, tok string) (map[string]any, map[string]any, string) {
	t.Helper()
	h, p, s, err := SplitJWT(tok)
	if err != nil {
		t.Fatalf("SplitJWT(%q): %v", tok, err)
	}
	hb, err := jb64.DecodeString(strings.TrimRight(h, "="))
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	pb, err := jb64.DecodeString(strings.TrimRight(p, "="))
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var hm, pm map[string]any
	if err := json.Unmarshal(hb, &hm); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
	if err := json.Unmarshal(pb, &pm); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	return hm, pm, s
}

func TestMutateJWT_AlgNoneIsValid(t *testing.T) {
	tok := makeJWT(t, map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "u-123", "role": "user", "exp": 1800000000}, "originalsig")
	res, err := MutateJWT(tok, JWTMutation{SetAlg: "none", SetClaims: map[string]any{"role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	// alg=none ⇒ empty signature; the result parses as a valid 3-part JWT.
	if strings.Count(res.Token, ".") != 2 || !strings.HasSuffix(res.Token, ".") {
		t.Fatalf("alg=none token should end with an empty signature: %q", res.Token)
	}
	hm, pm, sig := decodeJWT(t, res.Token)
	if hm["alg"] != "none" {
		t.Fatalf("alg not set to none: %v", hm["alg"])
	}
	if pm["role"] != "admin" {
		t.Fatalf("role not changed: %v", pm["role"])
	}
	if sig != "" {
		t.Fatalf("alg=none must have empty signature, got %q", sig)
	}
	// Original identifier survives but is never surfaced as a safe value.
	if pm["sub"] != "u-123" {
		t.Fatalf("sub should be preserved locally: %v", pm["sub"])
	}
	if _, bad := res.SafeValues["c.sub"]; bad {
		t.Fatal("sub must never be returned as a safe value")
	}
	if res.SafeValues["c.role"] != "admin" || res.SafeValues["h.alg"] != "none" {
		t.Fatalf("expected role/alg in safe values: %v", res.SafeValues)
	}
}

func TestMutateJWT_SafeValuesAllowlist(t *testing.T) {
	tok := makeJWT(t, map[string]any{"alg": "HS256", "kid": "key-sekret-99"},
		map[string]any{"sub": "u-1", "email": "x@y.z", "role": "editor", "exp": 1700000000, "session": "AK" + "IA" + "IOSFODNN7EXAMPLE"}, "sig")
	res, err := MutateJWT(tok, JWTMutation{})
	if err != nil {
		t.Fatal(err)
	}
	// Non-secret metadata is allowed.
	if res.SafeValues["c.role"] != "editor" {
		t.Fatalf("role should be a safe value: %v", res.SafeValues)
	}
	if _, ok := res.SafeValues["h.alg"]; !ok {
		t.Fatal("alg should be a safe value")
	}
	// Identifiers, kid and anything secret-looking must be withheld.
	for _, bad := range []string{"c.sub", "c.email", "h.kid", "c.session"} {
		if _, present := res.SafeValues[bad]; present {
			t.Fatalf("%s must not be a safe value: %v", bad, res.SafeValues)
		}
	}
	// Names are always surfaced.
	if !contains(res.ClaimNames, "sub") || !contains(res.ClaimNames, "email") {
		t.Fatalf("claim names missing: %v", res.ClaimNames)
	}
	if !contains(res.HeaderNames, "kid") {
		t.Fatalf("header names missing kid: %v", res.HeaderNames)
	}
}

func TestMutateJWT_DeleteClaimAndStripSignature(t *testing.T) {
	tok := makeJWT(t, map[string]any{"alg": "HS256"},
		map[string]any{"sub": "1", "exp": 1700000000, "role": "user"}, "abc")
	res, err := MutateJWT(tok, JWTMutation{DeleteClaims: []string{"exp"}, Signature: "strip", SetClaims: map[string]any{"role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	// strip ⇒ header.payload, no trailing dot.
	if strings.Count(res.Token, ".") != 1 {
		t.Fatalf("stripped token should have a single dot: %q", res.Token)
	}
	if contains(res.ClaimNames, "exp") {
		t.Fatalf("exp should be deleted: %v", res.ClaimNames)
	}
}

func TestMutateJWT_ResignWeakKey(t *testing.T) {
	// Forge an HS256 token actually signed with a weak key from the local list.
	hdr := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{"sub": "7", "role": "user"}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	si := jb64.EncodeToString(hb) + "." + jb64.EncodeToString(cb)
	tok := si + "." + signHMAC("HS256", "secret", si)

	res, err := MutateJWT(tok, JWTMutation{SetClaims: map[string]any{"role": "admin"}, Signature: "resign_weak"})
	if err != nil {
		t.Fatalf("resign_weak should succeed for a weak-key token: %v", err)
	}
	if !res.WeakKeyFound {
		t.Fatal("weak key should have been found")
	}
	_, pm, sig := decodeJWT(t, res.Token)
	if pm["role"] != "admin" {
		t.Fatalf("role not changed: %v", pm["role"])
	}
	// The re-signed token verifies under the same weak key.
	nh, np, _, _ := SplitJWT(res.Token)
	if sig != signHMAC("HS256", "secret", nh+"."+np) {
		t.Fatal("re-signed signature does not verify under the recovered weak key")
	}
}

func TestMutateJWT_ResignWeakKeyRejectsStrongKey(t *testing.T) {
	hdr := map[string]any{"alg": "HS256"}
	claims := map[string]any{"sub": "7"}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	si := jb64.EncodeToString(hb) + "." + jb64.EncodeToString(cb)
	tok := si + "." + signHMAC("HS256", "a-very-strong-unguessable-key-9Xp", si)
	_, err := MutateJWT(tok, JWTMutation{Signature: "resign_weak"})
	if err == nil {
		t.Fatal("resign_weak must fail when no local weak key verifies the signature")
	}
}

func TestMutateJWT_NotAJWTErrorsCleanly(t *testing.T) {
	for _, bad := range []string{"", "not.a.jwt.at.all", "onlyonepart", "aaa.bbb", "!!!.@@@.###"} {
		if _, err := MutateJWT(bad, JWTMutation{SetAlg: "none"}); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestInspectJWT(t *testing.T) {
	tok := makeJWT(t, map[string]any{"alg": "RS256"}, map[string]any{"sub": "1", "role": "admin"}, "x")
	res, err := InspectJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if res.SafeValues["c.role"] != "admin" || res.SafeValues["h.alg"] != "RS256" {
		t.Fatalf("unexpected safe values: %v", res.SafeValues)
	}
}

func TestParseRef(t *testing.T) {
	cases := map[string]string{
		"S1":                                "S1",
		"ref=S42":                           "S42",
		"<SECRET: ref=S7, type=jwt, len=9>": "S7",
		"not a ref":                         "",
		"":                                  "",
	}
	for in, want := range cases {
		if got := ParseRef(in); got != want {
			t.Fatalf("ParseRef(%q)=%q want %q", in, got, want)
		}
	}
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func TestVaultRememberLookup(t *testing.T) {
	v := NewVault()
	ref, label := v.Remember("jwt_forged", "aaa.bbb.ccc")
	if ref == "" || !strings.Contains(label, "ref="+ref) {
		t.Fatalf("Remember: ref=%q label=%q", ref, label)
	}
	got, ok := v.Lookup(ref)
	if !ok || got != "aaa.bbb.ccc" {
		t.Fatalf("Lookup: %q %v", got, ok)
	}
	if _, ok := v.Lookup("S999"); ok {
		t.Fatal("unknown ref should miss")
	}
	// Remembering the same value returns the same ref.
	ref2, _ := v.Remember("jwt_forged", "aaa.bbb.ccc")
	if ref2 != ref {
		t.Fatalf("stable ref: %q vs %q", ref, ref2)
	}
	// Redaction picks up the remembered value.
	red := v.Redact("token=aaa.bbb.ccc")
	if strings.Contains(red, "aaa.bbb.ccc") || !strings.Contains(red, "ref="+ref) {
		t.Fatalf("Remembered value not redacted: %s", red)
	}
}
