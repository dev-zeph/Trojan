package main

import "testing"

func TestParseIdentities(t *testing.T) {
	got, err := parseIdentities([]string{
		"alice=Authorization: Bearer alice.jwt.token=",
		"alice=Cookie: session=abc123",
		"bob=Authorization: Bearer bob-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(got))
	}
	// Order preserved: alice first, bob second.
	if got[0].Name != "alice" || got[1].Name != "bob" {
		t.Errorf("order = [%s %s], want [alice bob]", got[0].Name, got[1].Name)
	}
	// Alice accumulated two headers; the bearer value keeps its trailing '=' (only
	// the first '=' separates name from header line, first ':' separates key/value).
	if got[0].Headers["Authorization"] != "Bearer alice.jwt.token=" {
		t.Errorf("alice Authorization = %q", got[0].Headers["Authorization"])
	}
	if got[0].Headers["Cookie"] != "session=abc123" {
		t.Errorf("alice Cookie = %q", got[0].Headers["Cookie"])
	}
}

func TestParseIdentitiesErrors(t *testing.T) {
	for _, bad := range []string{
		"noequals",
		"=Authorization: x",       // empty name
		"alice=NoColonHeader",     // header without ':'
		"alice=Authorization: ",   // empty value
	} {
		if _, err := parseIdentities([]string{bad}); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	// Empty input is valid (no identities).
	if got, err := parseIdentities(nil); err != nil || len(got) != 0 {
		t.Errorf("nil input should yield no identities, got %v err %v", got, err)
	}
}
