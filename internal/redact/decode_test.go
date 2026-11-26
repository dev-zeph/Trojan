package redact

import (
	"net/url"
	"strings"
	"testing"
)

func TestDecodeShadowPercentAndJSON(t *testing.T) {
	// {"key": "VALUE"} URL-encoded, with VALUE standing in for a later secret.
	inner := `{"key":"hello"}`
	enc := url.QueryEscape(inner)
	src := "https://x.com/a?data=" + enc
	dec, m := decodeShadow(src)
	if !strings.Contains(dec, inner) {
		t.Fatalf("decoded %q does not contain %q", dec, inner)
	}
	i := strings.Index(dec, "hello")
	if i < 0 {
		t.Fatal("expected hello in decoded")
	}
	os, oe := mapDecodedSpan(m, i, i+len("hello"))
	if src[os:oe] != "hello" {
		t.Fatalf("mapped span %q, want hello (src=%q offsets %d:%d)", src[os:oe], src, os, oe)
	}
}

func TestDecodeShadowUnicodeAndAmp(t *testing.T) {
	src := `x\u0022sk_live` + `_abc&amp;api_key=1`
	dec, m := decodeShadow(src)
	if !strings.Contains(dec, `"sk_live_abc&api_key=1`) {
		t.Fatalf("decoded=%q", dec)
	}
	i := strings.Index(dec, "sk_live_abc")
	os, oe := mapDecodedSpan(m, i, i+len("sk_live_abc"))
	if src[os:oe] != "sk_live_abc" {
		t.Fatalf("mapped %q", src[os:oe])
	}
	j := strings.Index(dec, "&api_key")
	os, oe = mapDecodedSpan(m, j, j+1)
	if src[os:oe] != "&amp;" {
		t.Fatalf("amp mapped to %q", src[os:oe])
	}
}

func TestIncludeDanglingQuote(t *testing.T) {
	// Snippet is the secret plus a trailing quote, no opener.
	s := `eyJhbGciOiJub25lIn0."`
	//                  ^^^^ not a real jwt; just the quote rule
	if !includeDanglingQuote(s, 0, len(s)-1) {
		t.Fatal("expected dangling quote to be consumed")
	}
	wrapped := `"eyJhbGciOiJub25lIn0."`
	if includeDanglingQuote(wrapped, 1, len(wrapped)-1) {
		t.Fatal("wrapping quotes should be left in place")
	}
}

func TestExtendRun(t *testing.T) {
	s := "abcXYZ end"
	if got := extendRun(s, 3, " \t", 100); got != 6 {
		t.Fatalf("extendRun=%d want 6", got)
	}
}

func TestDecodeShadowSlashEscapes(t *testing.T) {
	src := `{"apiKey":\"` + `VALUE` + `\"}`
	dec, _ := decodeShadow(src)
	if !strings.Contains(dec, `{"apiKey":"VALUE"}`) && !strings.Contains(dec, `"apiKey":"VALUE"`) {
		t.Fatalf("backslash-quote decode=%q", dec)
	}
	src = `api_key=\x22VALUE\x22`
	dec, m := decodeShadow(src)
	if !strings.Contains(dec, `api_key="VALUE"`) {
		t.Fatalf(`\x22 decode=%q`, dec)
	}
	i := strings.Index(dec, "VALUE")
	os, oe := mapDecodedSpan(m, i, i+len("VALUE"))
	if src[os:oe] != "VALUE" {
		t.Fatalf("mapped %q", src[os:oe])
	}
}

func TestExtendRunUnbounded(t *testing.T) {
	s := "abc" + strings.Repeat("Z", 20000) + " end"
	if got := extendRun(s, 3, " \t", 0); got != 20003 {
		t.Fatalf("unbounded extendRun=%d want 20003", got)
	}
	if got := extendRun(s, 3, " \t", 10); got != 13 {
		t.Fatalf("capped extendRun=%d want 13", got)
	}
}
