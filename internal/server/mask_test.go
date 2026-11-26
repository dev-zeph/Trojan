package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

var serverAWSKey = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK" // assembled at runtime; not real

// The local UI gets the full value; the ?mask=secrets copy the desktop uploads
// for reports gets prefix…last4 with the same location.
func TestLatestScanMaskForUpload(t *testing.T) {
	scan := &normalizer.ScanResult{ProjectPath: t.TempDir(), Findings: []normalizer.Finding{{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", FilePath: "src/aws.ts", LineNumber: 4,
		CodeSnippet: `accessKeyId: "` + serverAWSKey + `"`, Status: normalizer.StatusOpen,
	}}}
	s := New(scan, nil)
	get := func(path string) scanResponse {
		rec := httptest.NewRecorder()
		s.handleLatestScan(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var resp scanResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	local := get("/api/scans/latest")
	if !strings.Contains(local.Findings[0].CodeSnippet, serverAWSKey) {
		t.Fatal("local UI must show the full value")
	}
	up := get("/api/scans/latest?mask=secrets")
	f := up.Findings[0]
	if strings.Contains(f.CodeSnippet, serverAWSKey) || f.CodeSnippet != `accessKeyId: "AKIA…VQXK"` {
		t.Fatalf("upload copy not masked: %q", f.CodeSnippet)
	}
	if f.FilePath != "src/aws.ts" || f.LineNumber != 4 {
		t.Fatal("location changed")
	}
}
