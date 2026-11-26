package ai

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Assembled at runtime so no key-shaped literal sits in the repo. Not real.
var (
	wireAWSKey = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK"
	wireStripe = "sk_" + "live_" + "51HxQe2LkF9aZ0rT7wYbN3mVvC8dPq"
	wireOpaque = "q8Rw2Lm9Vx7Np3Kt" // a gitleaks match no pattern knows
)

func secretFindings() []normalizer.Finding {
	return []normalizer.Finding{
		{
			ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "aws-access-token",
			Title: "Leaked AWS", RawMessage: "Secret found in the project files", FilePath: "src/aws.ts", LineNumber: 4,
			CodeSnippet:     `accessKeyId: "` + wireAWSKey + `"`,
			SurroundingCode: "import S3 from 's3'\nconst cfg = {\n  region: 'us-east-1',\n  accessKeyId: \"" + wireAWSKey + "\",\n}\n",
		},
		{
			ID: "gitleaks-1", Scanner: "gitleaks", Category: "secrets", RuleID: "generic-api-key",
			Title: "Leaked Generic API Key", FilePath: "src/internal.ts", LineNumber: 2,
			CodeSnippet:     `internalKey = "` + wireOpaque + `"`,
			SurroundingCode: "// call the billing service\ninternalKey = \"" + wireOpaque + "\"\nfetch(url, { headers: { k: internalKey } })\n",
		},
		{
			ID: "semgrep-0", Scanner: "semgrep", Category: "sast", RuleID: "hardcoded-stripe",
			Title: "Hard-coded Stripe key", RawMessage: "Stripe key " + wireStripe + " in code", FilePath: "src/pay.ts", LineNumber: 9,
			CodeSnippet: `const stripe = new Stripe("` + wireStripe + `")`,
		},
		{
			ID: "semgrep-1", Scanner: "semgrep", Category: "sast", RuleID: "sqli",
			Title: "SQL injection", FilePath: "src/db.ts", LineNumber: 12,
			CodeSnippet: "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
		},
	}
}

func assertNoRawSecret(t *testing.T, where, payload string) {
	t.Helper()
	for _, raw := range []string{wireAWSKey, wireStripe, wireOpaque} {
		if strings.Contains(payload, raw) {
			t.Fatalf("%s payload contains a raw secret value (%.4s…)", where, raw)
		}
	}
}

func decodeEncoded(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Encoded string `json:"encoded"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Encoded == "" {
		return string(body)
	}
	inner, err := base64.StdEncoding.DecodeString(env.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(inner)
}

func TestTriageWireCarriesNoRawSecret(t *testing.T) {
	var mu sync.Mutex
	var payloads []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		payloads = append(payloads, decodeEncoded(t, b))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"verdicts":[{"id":"f1","verdict":"confirmed","confidence":0.9,"rationale":"ok"}]}`))
	}))
	defer srv.Close()
	orig := triageURL
	triageURL = srv.URL
	defer func() { triageURL = orig }()

	fs := secretFindings()
	if _, err := TriageFindings(fs, "tok"); err != nil {
		t.Fatal(err)
	}
	if len(payloads) == 0 {
		t.Fatal("no triage call")
	}
	for _, p := range payloads {
		assertNoRawSecret(t, "triage", p)
	}
	var wire struct {
		Findings []triageFindingWire `json:"findings"`
	}
	if err := json.Unmarshal([]byte(payloads[0]), &wire); err != nil {
		t.Fatal(err)
	}
	aws := wire.Findings[0]
	if aws.MatchedAt != "src/aws.ts:4" || !strings.Contains(aws.Evidence, "<SECRET removed by Trojan: type=aws_access_key, len=20, prefix=AKIA") {
		t.Fatalf("location/descriptor wrong: %+v", aws)
	}
	if !strings.Contains(aws.ResponseSnippet, "import S3 from 's3'\nconst cfg = {\n  region: 'us-east-1',\n  accessKeyId: \"<SECRET") {
		t.Fatalf("surrounding code must be kept: %q", aws.ResponseSnippet)
	}
	if !strings.Contains(wire.Findings[2].Evidence, "prefix=sk_live_") {
		t.Fatalf("live/test prefix must reach triage: %q", wire.Findings[2].Evidence)
	}
	if wire.Findings[3].Evidence != fs[3].CodeSnippet {
		t.Fatalf("non-secret code must be untouched: %q", wire.Findings[3].Evidence)
	}
	// Local findings keep the raw value for the UI.
	if !strings.Contains(fs[0].CodeSnippet, wireAWSKey) {
		t.Fatal("local finding was modified")
	}
}

func TestSynthesizeWireCarriesNoRawSecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // keep the explanation cache out of the real home
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte(`{"simply":"rotate it","actions":["rotate"]}`))
	}))
	defer srv.Close()
	defer OverrideSynthesizeURL(srv.URL)()

	for _, f := range secretFindings() {
		if _, err := SynthesizeFinding(f, "tok", 1, "my staging key is "+wireStripe); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 4 {
		t.Fatalf("calls = %d", len(got))
	}
	for _, p := range got {
		assertNoRawSecret(t, "synthesize", p)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(got[0]), &p)
	if p["filePath"] != "src/aws.ts" || !strings.Contains(p["codeSnippet"].(string), "<SECRET removed by Trojan: type=aws_access_key") {
		t.Fatalf("payload: %v", p)
	}
}

func TestEmbedWireCarriesNoRawSecret(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, decodeEncoded(t, b))
		_, _ = w.Write([]byte(`{"embeddings":[[0.1],[0.2]]}`))
	}))
	defer srv.Close()
	orig := embedURLForTest
	embedURLForTest = srv.URL
	defer func() { embedURLForTest = orig }()

	// An index chunk and an escalation retrieval query (escalate.go:retrievalQuery).
	q := retrievalQuery(secretFindings()[2])
	if _, err := EmbedTexts([]string{"const k = \"" + wireAWSKey + "\"\nexport default k", q}, EmbedDocument, "tok"); err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		assertNoRawSecret(t, "embed", p)
	}
	if !strings.Contains(got[0], `export default k`) {
		t.Fatal("chunk code must be kept")
	}
}
