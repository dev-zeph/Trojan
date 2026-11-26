package mcpserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Assembled at runtime; not a real key.
var reportAWSKey = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK"

// Report uploads (threat-lab) keep exact locations and code but mask secret
// values to prefix…last4.
func TestSecurityReportUploadMasksSecrets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".trojan"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".trojan", "config.json"), []byte(`{"access_token":"tok","familiarity":0}`), 0o600)

	var sent string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Encoded string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		inner, _ := base64.StdEncoding.DecodeString(body.Encoded)
		sent = string(inner)
		_, _ = w.Write([]byte(`{"threat_index":10,"grade":"B","verdict":"ok"}`))
	}))
	defer stub.Close()
	old := edgeBase
	edgeBase = stub.URL + "/"
	defer func() { edgeBase = old }()

	scan := &normalizer.ScanResult{ProjectPath: "/p", Findings: []normalizer.Finding{{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "aws-access-token",
		Title: "Leaked AWS", FilePath: "src/aws.ts", LineNumber: 4,
		CodeSnippet:     `accessKeyId: "` + reportAWSKey + `"`,
		SurroundingCode: "const cfg = {\n  accessKeyId: \"" + reportAWSKey + "\",\n}\n",
	}}}
	if _, err := securityReport("/p", scan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sent, reportAWSKey) {
		t.Fatal("raw secret uploaded")
	}
	for _, want := range []string{`"FilePath":"src/aws.ts"`, `"LineNumber":4`, `accessKeyId: \"AKIA…VQXK\"`, `const cfg = {`} {
		if !strings.Contains(sent, want) {
			t.Errorf("upload missing %s: %s", want, sent)
		}
	}
	if !strings.Contains(scan.Findings[0].CodeSnippet, reportAWSKey) {
		t.Fatal("local scan must keep the raw value")
	}
}
