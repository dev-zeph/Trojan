package main

import (
	"strings"
	"testing"
)

// R4-P3-2: the signed-out trojan dast message names a website test (not
// "Agentic DAST", which is wrong for the classic scan), says how to sign in,
// and has no em dash.
func TestDastLoginMessage(t *testing.T) {
	got := dastLoginMessage("http://127.0.0.1:8799")
	for _, want := range []string{
		"Sign in to run a website test. Every account gets 500 free tokens a month.",
		"Run trojan login, or sign in from the Trojan desktop app, then try again.",
		"http://127.0.0.1:8799",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	for _, bad := range []string{"Agentic", "DAST", "penetration", "\u2014", "`"} {
		if strings.Contains(got, bad) {
			t.Errorf("contains %q: %q", bad, got)
		}
	}
}
