package redact

import "testing"

func TestSensitiveParamNameLeaks(t *testing.T) {
	// Every name from the round-4 regression, plus earlier URL forms.
	names := []string{
		"secret_key", "auth_token", "sid", "session_token", "sessionid",
		"oauth_token", "oauth_verifier", "jwt_token", "apiToken",
		"app_secret", "signing_key", "private_key", "ticket",
		"api_key", "apikey", "apiKey", "API_KEY", "access_key", "accessKey",
		"token", "access_token", "refresh_token", "id_token",
		"session", "auth", "password", "passwd", "pwd", "pass",
		"sig", "signature", "bearer", "otp", "credential", "credentials",
		"client_secret", "private_token", "session-token", "sessionToken",
		"jwt", "code",
	}
	for _, n := range names {
		if !SensitiveParamName(n) {
			t.Errorf("SensitiveParamName(%q) = false, want true", n)
		}
	}
}

func TestSensitiveParamNameFalsePositives(t *testing.T) {
	// These contain a stem as a substring of a larger English word, or are
	// ordinary query fields. Token-level matching must leave them alone.
	names := []string{
		"keyboard", "monkey", "author", "sidebar", "designation",
		"state", "nonce", "client_id", "clientId", "hash", "page", "id", "sort",
		"theme", "locale", "format", "callback", "redirect",
		"sessions", "tokens", "secrets", "keyboarding",
	}
	for _, n := range names {
		if SensitiveParamName(n) {
			t.Errorf("SensitiveParamName(%q) = true, want false", n)
		}
	}
}

func TestSplitIdent(t *testing.T) {
	cases := map[string][]string{
		"apiToken":      {"api", "Token"},
		"secret_key":    {"secret", "key"},
		"session-token": {"session", "token"},
		"sid":           {"sid"},
		"oauth_token":   {"oauth", "token"},
	}
	for in, want := range cases {
		got := splitIdent(in)
		if len(got) != len(want) {
			t.Errorf("splitIdent(%q)=%v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitIdent(%q)=%v, want %v", in, got, want)
				break
			}
		}
	}
}

func TestIsSessionCookieName(t *testing.T) {
	yes := []string{"sid", "session", "sessionid", "session_id", "JSESSIONID", "PHPSESSID", "sess"}
	no := []string{"JWT_SECRET", "api_key", "sidebar", "keyboard", "auth_token"}
	for _, n := range yes {
		if !isSessionCookieName(n) {
			t.Errorf("isSessionCookieName(%q)=false", n)
		}
	}
	for _, n := range no {
		if isSessionCookieName(n) {
			t.Errorf("isSessionCookieName(%q)=true", n)
		}
	}
}

func TestFindNamedPathValues(t *testing.T) {
	val := "Fclb" + "thHV8fa56vORRwkgLcLsbMTrRvHX"
	in := "https://x.com/api_key/" + val + "/items"
	hits := findNamedPathValues(in, nil)
	if len(hits) != 1 || hits[0].Value != val || hits[0].Type != "url_path" {
		t.Fatalf("hits=%+v", hits)
	}
	// /sessions/<id> is a route, not a secret-named key.
	in = "https://x.com/sessions/" + val + "/edit"
	hits = findNamedPathValues(in, nil)
	if len(hits) != 0 {
		t.Fatalf("sessions path should be ignored, got %+v", hits)
	}
}
