package ai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// A finding from an older scan can carry an absolute path. The synthesize
// request still never contains the home folder.
func TestSynthesizeRequestHasNoHomePath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	t.Setenv("HOME", home)
	var sent string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sent = string(b)
		w.Write([]byte(`{"simply":"This is a serious security problem.","actions":["Rotate the key."]}`)) //nolint:errcheck
	}))
	defer stub.Close()
	old := synthesizeURL
	synthesizeURL = stub.URL
	defer func() { synthesizeURL = old }()

	f := normalizer.Finding{ID: "f1", Scanner: "gitleaks", RuleID: "stripe-access-token", Title: "Leaked Stripe access token",
		FilePath: filepath.Join(home, "clients", "acme-shop", "src", "config.ts"), CodeSnippet: "const k = process.env.K"}
	if _, err := SynthesizeFinding(f, "tok", 0, ""); err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	if sent == "" || strings.Contains(sent, home) {
		t.Fatalf("request has the home folder: %s", sent)
	}
	if !strings.Contains(sent, `"filePath":"~/clients/acme-shop/src/config.ts"`) {
		t.Errorf("filePath not scrubbed as expected: %s", sent)
	}
}
