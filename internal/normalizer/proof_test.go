package normalizer

import "testing"

func TestDeriveSignalReflection(t *testing.T) {
	// A query payload echoed back in the body is a reflection signal.
	sig := DeriveSignal("GET", "https://x.test/search?q=trojanXSS12345", "", 200, nil,
		`<h1>Results for trojanXSS12345</h1>`)
	if sig.Kind != SignalReflection {
		t.Fatalf("kind = %q, want reflection", sig.Kind)
	}
	if sig.Marker != "trojanXSS12345" {
		t.Errorf("marker = %q, want trojanXSS12345", sig.Marker)
	}
}

func TestDeriveSignalReflectionFromBody(t *testing.T) {
	sig := DeriveSignal("POST", "https://x.test/comment", "comment=<script>uniqMarker999</script>", 200, nil,
		`saved: <script>uniqMarker999</script>`)
	if sig.Kind != SignalReflection {
		t.Fatalf("kind = %q, want reflection", sig.Kind)
	}
}

func TestDeriveSignalRedirect(t *testing.T) {
	sig := DeriveSignal("GET", "https://x.test/go?url=http://evil.test", "", 302,
		map[string]string{"Location": "http://evil.test"}, "")
	if sig.Kind != SignalRedirect || sig.Marker != "http://evil.test" {
		t.Fatalf("got %+v, want redirect to evil.test", sig)
	}
}

func TestDeriveSignalStatus(t *testing.T) {
	// A 200 with nothing reflected and no redirect is a status signal.
	sig := DeriveSignal("GET", "https://x.test/admin", "", 200, nil, "<h1>Admin panel</h1>")
	if sig.Kind != SignalStatus {
		t.Fatalf("kind = %q, want status", sig.Kind)
	}
}

func TestDeriveSignalUnknown(t *testing.T) {
	// A bare 404 with no reflection/redirect can't be classified.
	sig := DeriveSignal("GET", "https://x.test/missing", "", 404, nil, "not found")
	if sig.Kind != SignalUnknown {
		t.Fatalf("kind = %q, want unknown", sig.Kind)
	}
}

func TestRedactHeaders(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer secret-token",
		"Cookie":        "session=abc",
		"X-Api-Key":     "k",
		"Content-Type":  "application/json",
		"X-Request-Id":  "visible",
	}
	out := RedactHeaders(in)
	for _, secret := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if out[secret] != RedactedValue {
			t.Errorf("%s = %q, want redacted", secret, out[secret])
		}
	}
	if out["Content-Type"] != "application/json" || out["X-Request-Id"] != "visible" {
		t.Errorf("non-secret headers were altered: %+v", out)
	}
	// The original map must not be mutated.
	if in["Authorization"] != "Bearer secret-token" {
		t.Error("RedactHeaders mutated its input")
	}
}

func TestIsSecretHeaderCaseInsensitive(t *testing.T) {
	if !IsSecretHeader("authorization") || !IsSecretHeader("AUTHORIZATION") || !IsSecretHeader("Cookie") {
		t.Error("expected secret headers to match case-insensitively")
	}
	if IsSecretHeader("Content-Type") {
		t.Error("Content-Type is not a secret header")
	}
}
