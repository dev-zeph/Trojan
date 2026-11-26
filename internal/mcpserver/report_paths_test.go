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

// threat-lab and compliance-lab get the project's folder name, not its
// absolute path, and findings with project-relative files. The home folder
// (which names the user) never reaches the server.
func TestLabReportsSendNoAbsolutePaths(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".trojan"), 0o700)                                                                   //nolint:errcheck
	os.WriteFile(filepath.Join(home, ".trojan", "config.json"), []byte(`{"access_token":"tok","familiarity":1}`), 0o600) //nolint:errcheck
	proj := filepath.Join(home, "clients", "acme-shop")

	bodies := map[string]string{}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Encoded string }
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		inner, _ := base64.StdEncoding.DecodeString(body.Encoded)
		bodies[strings.TrimPrefix(r.URL.Path, "/")] = string(inner)
		w.Write([]byte(`{"threat_index":10,"grade":"A","verdict":"ok","executive_summary":"ok"}`)) //nolint:errcheck
	}))
	defer stub.Close()
	old := edgeBase
	edgeBase = stub.URL + "/"
	defer func() { edgeBase = old }()

	scan := &normalizer.ScanResult{ProjectPath: proj, Findings: []normalizer.Finding{
		{ID: "f1", Title: "Leaked Stripe access token", Scanner: "gitleaks", Severity: normalizer.SeverityCritical,
			FilePath: filepath.Join(proj, "src", "config.ts"), LineNumber: 3},
		{ID: "f2", Title: "XSS", Scanner: "trojan", Severity: normalizer.SeverityHigh,
			FilePath: "src/app.js", SourceFile: filepath.Join(proj, "api", "h.go")},
	}}
	if _, err := securityReport(proj, scan); err != nil {
		t.Fatalf("security report: %v", err)
	}
	if _, err := complianceReport(proj, scan); err != nil {
		t.Fatalf("compliance report: %v", err)
	}
	for _, fn := range []string{"threat-lab", "compliance-lab"} {
		b, ok := bodies[fn]
		if !ok {
			t.Fatalf("%s not called", fn)
		}
		if strings.Contains(b, home) || strings.Contains(b, filepath.Dir(home)) {
			t.Errorf("%s body has an absolute path: %s", fn, b)
		}
		var m map[string]any
		json.Unmarshal([]byte(b), &m) //nolint:errcheck
		if m["project_path"] != "acme-shop" {
			t.Errorf("%s project_path = %v", fn, m["project_path"])
		}
	}
	if b := bodies["threat-lab"]; !strings.Contains(b, `"FilePath":"src/config.ts"`) || !strings.Contains(b, `"source_file":"api/h.go"`) {
		t.Errorf("threat-lab findings not project-relative: %s", b)
	}
	if scan.Findings[0].FilePath != filepath.Join(proj, "src", "config.ts") {
		t.Error("the saved scan was changed")
	}
}
