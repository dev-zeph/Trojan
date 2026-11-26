package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

// mixedTok is a detectable non-wordy value built at runtime.
func mixedTok() string { return "6Yzk" + "Qp2n" + "R8wL" + "t4xH" + "b9cV" + "m1sF" + "d3aE" + "u7gK" }

func TestRound5ParamNamesAreMasked(t *testing.T) {
	val := mixedTok()
	names := []string{
		"secret_key", "auth_token", "sid", "session_token", "sessionid",
		"oauth_token", "oauth_verifier", "jwt_token", "apiToken",
		"app_secret", "signing_key", "private_key", "ticket",
	}
	for _, name := range names {
		in := "https://x.com/a?" + name + "=" + val
		got := Text(in)
		if strings.Contains(got, val) {
			t.Errorf("%s query leaked: %s", name, got)
		}
		if !strings.Contains(got, "SECRET removed by Trojan") {
			t.Errorf("%s query not labelled: %s", name, got)
		}
		line := name + "=" + val
		got = Text(line)
		if strings.Contains(got, val) {
			t.Errorf("%s line leaked: %s", name, got)
		}
	}
	// Bare assignment as in the repro, no URL wrapper.
	in := "auth_token=" + val
	got := Text(in)
	if strings.Contains(got, val) {
		t.Fatalf("bare auth_token leaked: %s", got)
	}
}

func TestRound5HarmlessParamNamesAreUntouched(t *testing.T) {
	val := mixedTok()
	for _, name := range []string{"keyboard", "monkey", "author", "sidebar", "designation"} {
		in := "https://x.com/a?" + name + "=" + val
		if got := Text(in); got != in {
			t.Errorf("false positive on %s: %s", name, got)
		}
		line := name + "=" + val
		if got := Text(line); got != line {
			t.Errorf("false positive assignment %s: %s", name, got)
		}
	}
}

func TestRound5LongValuesAreFullyMasked(t *testing.T) {
	// 1,200 and 12,000 character values must not leak a prefix or a tail.
	for _, n := range []int{1200, 12000} {
		// Mixed hex so genericValueOK does not reject it as wordy.
		chunk := "a1b2c3d4e5f6"
		val := strings.Repeat(chunk, (n+len(chunk)-1)/len(chunk))[:n]
		for _, in := range []string{
			`password="` + val + `"`,
			`API_KEY=` + val,
			`postgres://app:` + val + `@db.internal:5432/app`,
		} {
			got := Text(in)
			if strings.Contains(got, val) {
				t.Errorf("len %d fully leaked in %s", n, brief(got))
			}
			// A 32-char window from the middle and from the tail must be gone.
			if strings.Contains(got, val[len(val)/2:len(val)/2+32]) {
				t.Errorf("len %d mid leaked in %s", n, brief(got))
			}
			if strings.Contains(got, val[len(val)-32:]) {
				t.Errorf("len %d tail leaked in %s", n, brief(got))
			}
			if !strings.Contains(got, "SECRET removed by Trojan") {
				t.Errorf("len %d not labelled: %s", n, brief(got))
			}
		}
	}
}

func TestRound5MinifiedJSForms(t *testing.T) {
	val := mixedTok()
	// JSON.parse("{\"apiKey\":\"VALUE\"}") as it appears in minified source.
	jsonParse := "JSON.parse(\"" + "{\\\"apiKey\\\":\\\"" + val + "\\\"}" + "\")"
	inputs := []string{
		jsonParse,
		`const x=process.env.X||"` + val + `"`,
		`const y=process.env.X??"` + val + `"`,
		"`Bearer " + val + "`",
		`var password=` + val + `;`,
		`Api_Key=` + val,
	}
	for _, in := range inputs {
		got := Text(in)
		if strings.Contains(got, val) {
			t.Errorf("leaked in %q -> %s", in, got)
		}
		if !strings.Contains(got, "SECRET removed by Trojan") {
			t.Errorf("no label for %q -> %s", in, got)
		}
	}
}

func TestRound5HexEscapeAndShortPassword(t *testing.T) {
	val := mixedTok()
	// \x22-escaped quotes around a named key.
	in := `api_key=\x22` + val + `\x22`
	got := Text(in)
	if strings.Contains(got, val) {
		t.Fatalf(`\x22 form leaked: %s`, got)
	}
	// 3-character password (the LB4-style leftover). 1-2 remain a documented limit.
	pw := "LB" + "4"
	in = `var password=` + pw + `;`
	got = Text(in)
	if strings.Contains(got, pw) {
		t.Fatalf("3-char password leaked: %s", got)
	}
	// 1-2 character leftovers stay visible.
	for _, short := range []string{"x", "ab"} {
		in = `var password=` + short + `;`
		if got = Text(in); !strings.Contains(got, short) {
			t.Errorf("1-2 char leftover should stay visible: %s", got)
		}
	}
}

func TestRound5Base64WrappedKey(t *testing.T) {
	inner := fakeStripe
	blob := base64.StdEncoding.EncodeToString([]byte(inner))
	in := "const packed = \"" + blob + "\""
	got := Text(in)
	if strings.Contains(got, blob) || strings.Contains(got, inner) {
		t.Fatalf("base64-wrapped key leaked: %s", got)
	}
	if !strings.Contains(got, "SECRET removed by Trojan") {
		t.Fatalf("base64-wrapped key not labelled: %s", got)
	}
	// A random base64 blob that does not decode to a secret stays put.
	noise := base64.StdEncoding.EncodeToString([]byte("hello world, not a key!!"))
	plain := "const packed = \"" + noise + "\""
	if got = Text(plain); got != plain {
		t.Fatalf("harmless base64 was redacted: %s", got)
	}
}

func TestRound5DigitGluedVendorPrefix(t *testing.T) {
	in := "x=1" + fakeStripe
	got := Text(in)
	if strings.Contains(got, fakeStripe) {
		t.Fatalf("digit-glued stripe leaked: %s", got)
	}
}

func TestTryBase64Decode(t *testing.T) {
	raw := "sk_" + "live_" + "wrappedExampleKey99"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	if got := tryBase64Decode(enc); got != raw {
		t.Fatalf("std decode=%q want %q", got, raw)
	}
	urlEnc := base64.RawURLEncoding.EncodeToString([]byte(raw))
	if got := tryBase64Decode(urlEnc); got != raw {
		t.Fatalf("url decode=%q want %q", got, raw)
	}
	if got := tryBase64Decode("@@@not-base64@@@___________"); got != "" {
		t.Fatalf("garbage decoded as %q", got)
	}
}

func brief(s string) string {
	if len(s) > 180 {
		return s[:180] + "..."
	}
	return s
}
