package dast

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestVerifyFileAndMetaOverHTTP drives the real fetch + match path against a
// live server, covering the well-known-file and homepage-meta methods.
func TestVerifyFileAndMetaOverHTTP(t *testing.T) {
	const token = "live-token-abcdef123456"
	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, TXTPrefix+token+"\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><head><meta name="%s" content="%s"></head><body>hi</body>`, MetaName, token)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if err := verifyFile(srv.URL, token); err != nil {
		t.Errorf("verifyFile over HTTP failed: %v", err)
	}
	if err := verifyMeta(srv.URL, token); err != nil {
		t.Errorf("verifyMeta over HTTP failed: %v", err)
	}
	// Wrong token must fail both.
	if err := verifyFile(srv.URL, "wrong"); err == nil {
		t.Error("verifyFile should fail for a wrong token")
	}
	if err := verifyMeta(srv.URL, "wrong"); err == nil {
		t.Error("verifyMeta should fail for a wrong token")
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"http://localhost:3000", "localhost", false},
		{"https://Example.COM/path?q=1", "example.com", false},
		{"https://app.example.com:8443/x", "app.example.com", false},
		{"http://127.0.0.1:7878", "127.0.0.1", false},
		{"ftp://example.com", "", true},   // wrong scheme
		{"example.com", "", true},         // no scheme
		{"http://", "", true},             // no host
	}
	for _, c := range cases {
		got, err := NormalizeHost(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeHost(%q) expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeHost(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsLocalHost(t *testing.T) {
	local := []string{
		"localhost", "foo.localhost", "myapp.local", "svc.internal",
		"127.0.0.1", "127.0.0.53", "::1",
		"10.0.0.5", "192.168.1.10", "172.16.4.4", "169.254.1.1",
		"0.0.0.0",
	}
	for _, h := range local {
		if !IsLocalHost(h) {
			t.Errorf("IsLocalHost(%q) = false, want true", h)
		}
	}
	// Public literal IPs must gate. (Hostnames like example.com are skipped
	// here because IsLocalHost resolves them, which needs network.)
	public := []string{"8.8.8.8", "1.1.1.1"}
	for _, h := range public {
		if IsLocalHost(h) {
			t.Errorf("IsLocalHost(%q) = true, want false", h)
		}
	}
}

func TestMatchTXT(t *testing.T) {
	tok := "abc123"
	yes := [][]string{
		{"trojan-verify=abc123"},
		{"v=spf1 -all", "trojan-verify=abc123"},
		{`  trojan-verify=abc123  `},
		{"trojan-verify=abc123 extra=stuff"},
	}
	for _, recs := range yes {
		if !matchTXT(recs, tok) {
			t.Errorf("matchTXT(%v, %q) = false, want true", recs, tok)
		}
	}
	no := [][]string{
		{"trojan-verify=nope"},
		{"abc123"}, // missing prefix
		{},
		{"v=spf1 -all"},
	}
	for _, recs := range no {
		if matchTXT(recs, tok) {
			t.Errorf("matchTXT(%v, %q) = true, want false", recs, tok)
		}
	}
}

func TestMatchMeta(t *testing.T) {
	tok := "tok-XYZ_789"
	yes := []string{
		`<meta name="trojan-site-verification" content="tok-XYZ_789">`,
		`<META CONTENT='tok-XYZ_789' NAME='trojan-site-verification'/>`, // reordered, single-quoted, uppercase
		`<head><meta charset="utf-8"><meta name="trojan-site-verification" content="tok-XYZ_789"></head>`,
		"<meta\n  name=\"trojan-site-verification\"\n  content=\"tok-XYZ_789\">", // multiline
	}
	for _, h := range yes {
		if !matchMeta(h, tok) {
			t.Errorf("matchMeta(%q) = false, want true", h)
		}
	}
	no := []string{
		`<meta name="trojan-site-verification" content="wrong">`,
		`<meta name="other" content="tok-XYZ_789">`,
		`<div>tok-XYZ_789</div>`, // token present but not in a meta tag
		``,
	}
	for _, h := range no {
		if matchMeta(h, tok) {
			t.Errorf("matchMeta(%q) = true, want false", h)
		}
	}
}

func TestMatchToken(t *testing.T) {
	if !matchToken("  deadbeef\n", "deadbeef") {
		t.Error("matchToken should match a trimmed body")
	}
	if !matchToken("trojan-verify=deadbeef", "deadbeef") {
		t.Error("matchToken should match token embedded with prefix")
	}
	if matchToken("cafebabe", "deadbeef") {
		t.Error("matchToken should not match a different token")
	}
}

func TestNewTokenUnique(t *testing.T) {
	a, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("newToken produced identical tokens")
	}
	if len(a) != tokenBytes*2 {
		t.Errorf("token length = %d, want %d", len(a), tokenBytes*2)
	}
}

func TestConsentStoreRoundTrip(t *testing.T) {
	// Redirect the store to a temp HOME so we don't touch the real config.
	t.Setenv("HOME", t.TempDir())

	s := &consentStore{}
	s.Pending = append(s.Pending, pendingToken{Domain: "example.com", UserEmail: "u@x.com", Token: "t1"})
	s.upsertVerified(ConsentRecord{Domain: "example.com", UserEmail: "u@x.com", Method: MethodDNS, Token: "t1"})
	if err := saveConsentStore(s); err != nil {
		t.Fatal(err)
	}

	got, err := loadConsentStore()
	if err != nil {
		t.Fatal(err)
	}
	if r := got.findVerified("example.com", "u@x.com"); r == nil || r.Method != MethodDNS {
		t.Errorf("findVerified after round trip = %+v", r)
	}
	// A different user must not see another user's verification.
	if r := got.findVerified("example.com", "other@x.com"); r != nil {
		t.Error("findVerified leaked a record across users")
	}

	got.removePending("example.com", "u@x.com")
	if p := got.findPending("example.com", "u@x.com"); p != nil {
		t.Error("removePending did not remove the token")
	}
}
