package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// runScan's explanation path (synthesizeConcurrently -> ai.SynthesizeFinding)
// must not send a gitleaks match's raw value, while the local finding keeps it.
func TestScanExplainPathRedactsSecrets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	raw := "AK" + "IA" + "Q7Z3M2PL9WNBVQXK" // assembled at runtime; not real
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"simply":"rotate the key","actions":["rotate"]}`))
	}))
	defer srv.Close()
	defer ai.OverrideSynthesizeURL(srv.URL)()

	findings := []normalizer.Finding{{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "aws-access-token",
		FilePath: "src/aws.ts", LineNumber: 4, CodeSnippet: `accessKeyId: "` + raw + `"`,
		SurroundingCode: "const cfg = {\n  accessKeyId: \"" + raw + "\",\n}\n",
	}}
	res := synthesizeConcurrently(findings, []int{0}, "token", 1, "")
	if res.completed != 1 || len(bodies) != 1 {
		t.Fatalf("completed=%d calls=%d", res.completed, len(bodies))
	}
	if strings.Contains(bodies[0], raw) || !strings.Contains(bodies[0], "type=aws_access_key") {
		t.Fatalf("explain payload not redacted: %s", bodies[0])
	}
	if !strings.Contains(findings[0].CodeSnippet, raw) {
		t.Fatal("local finding must keep the raw value")
	}
}
