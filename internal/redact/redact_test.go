package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Golden: one line of code per secret type -> exact redacted line.
func TestRedactGoldenPerType(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"aws_access_key", `const id = "` + fakeAWSKey + `"`,
			`const id = "<SECRET: type=aws_access_key, len=20, prefix=AKIA, entropy=4.0, class=likely_real>"`},
		{"aws_secret_key", `aws_secret_access_key = ` + fakeAWSSecret,
			`aws_secret_access_key = <SECRET: type=aws_secret_key, len=40, prefix=Zq8t, entropy=5.2, class=likely_real>`},
		{"github_token_checksum_ok", `token: ` + fakeGitHub(),
			`token: <SECRET: type=github_token, len=40, prefix=ghp_, entropy=4.7, class=likely_real, checks=checksum_ok>`},
		{"github_token_checksum_bad", `token: ` + fakeGitHubBadChecksum(),
			`token: <SECRET: type=github_token, len=40, prefix=ghp_, entropy=4.6, class=likely_placeholder, checks=checksum_invalid>`},
		{"npm_token", `//registry.npmjs.org/:_authToken=` + fakeNPM(),
			`//registry.npmjs.org/:_authToken=<SECRET: type=npm_token, len=40, prefix=npm_, entropy=4.8, class=likely_real, checks=checksum_ok>`},
		{"stripe_live", `stripe(` + `"` + fakeStripe + `")`,
			`stripe("<SECRET: type=stripe_secret_key, len=38, prefix=sk_live_, entropy=5.0, class=likely_real>")`},
		{"slack", `SLACK=` + fakeSlack,
			`SLACK=<SECRET: type=slack_token, len=50, prefix=xoxb-, entropy=4.7, class=likely_real>`},
		{"google", `key=` + fakeGoogle,
			`key=<SECRET: type=google_api_key, len=39, prefix=AIza, entropy=5.2, class=likely_real>`},
		{"anthropic", `new Anthropic({ apiKey: "` + fakeAnthropic + `" })`,
			`new Anthropic({ apiKey: "<SECRET: type=anthropic_api_key, len=43, prefix=sk-ant-api03-, entropy=5.0, class=likely_real>" })`},
		{"openai", `OPENAI_API_KEY=` + fakeOpenAI,
			`OPENAI_API_KEY=<SECRET: type=openai_api_key, len=40, prefix=sk-proj-, entropy=5.1, class=likely_real>`},
		{"sendgrid", `sg.setApiKey("` + fakeSendgrid + `")`,
			`sg.setApiKey("<SECRET: type=sendgrid_api_key, len=69, prefix=SG., entropy=5.3, class=likely_real>")`},
		{"jwt_with_role", `const k = "` + fakeJWT + `"`,
			`const k = "<SECRET: type=jwt, len=120, prefix=eyJ, entropy=5.0, class=likely_real, jwt_alg=HS256, claims=iss|role, role=service_role>"`},
		{"url_password", `DATABASE_URL=postgres://app:S3cr3tPa55w0rd@db.internal:5432/app`,
			`DATABASE_URL=postgres://app:<SECRET: type=url_password, len=14, prefix=S3, entropy=3.4, class=likely_real>@db.internal:5432/app`},
		{"bearer_header", `Authorization: Bearer Zk9xLm3Qp7Rt2Vw8Yb4Nc6`,
			`Authorization: Bearer <SECRET: type=authorization_header, len=22, prefix=Zk9x, entropy=4.5, class=likely_real>`},
		{"generic_quoted", `const dbPassword = "Tr0ub4dor&3xyz"`,
			`const dbPassword = "<SECRET: type=generic_secret, len=14, prefix=Tr, entropy=3.7, class=likely_real>"`},
		{"generic_placeholder", `API_KEY=changeme123`,
			`API_KEY=<SECRET: type=generic_secret, len=11, prefix=ch, entropy=3.3, class=likely_placeholder, checks=placeholder_pattern>`},
		{"aws_docs_example", `aws_access_key_id = AK` + `IAIOSFODNN7EXAMPLE`,
			`aws_access_key_id = <SECRET: type=aws_access_key, len=20, prefix=AKIA, entropy=3.7, class=likely_placeholder, checks=provider_docs_example>`},
		{"low_variety", `API_TOKEN=aaaaaaaaaaaa1`,
			`API_TOKEN=<SECRET: type=generic_secret, len=13, prefix=aa, entropy=0.4, class=likely_placeholder, checks=low_entropy>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Text(c.in)
			if got != c.want {
				t.Fatalf("\n got: %s\nwant: %s", got, c.want)
			}
		})
	}
}

func TestPrivateKeyBlockIsRedactedWhole(t *testing.T) {
	in := "const key = `" + fakePEM() + "`\nconsole.log('ok')"
	got := Text(in)
	if strings.Contains(got, fakePEMBody[:20]) || strings.Contains(got, "PRIVATE KEY-----") {
		t.Fatalf("PEM body or armor leaked: %s", got)
	}
	if !strings.Contains(got, "<SECRET: type=private_key") || !strings.HasSuffix(got, "`\nconsole.log('ok')") {
		t.Fatalf("surrounding code changed: %q", got)
	}
	m := Mask(in)
	if strings.Contains(m, fakePEMBody[:20]) || !strings.Contains(m, "-----BEGIN RSA PRIV"+"ATE KEY-----…[private key,") {
		t.Fatalf("mask: %q", m)
	}
}

// Ordinary code that only talks about secrets must pass through untouched.
func TestNormalCodeIsUntouched(t *testing.T) {
	cases := []string{
		`const password = req.body.password`,
		`password: string;`,
		`labels = { password: "Password", email: "Email address" }`,
		`token := os.Getenv("GITHUB_TOKEN")`,
		`const apiKey = process.env.STRIPE_SECRET_KEY`,
		`secretName = "my-app-secrets"`,
		`api_key = "your_api_key_here"`,
		`if token == "" { return errMissingToken }`,
		`const tokenType = "Bearer"`,
		`headers: { Authorization: ` + "`Bearer ${token}`" + ` }`,
		`password_hash = bcrypt.hash(password, 12)`,
		`SECRET_KEY = os.environ["SECRET_KEY"]`,
		`DATABASE_URL=postgres://localhost:5432/app`,
		`const sha = "3f786850e387550fdab836ed7e6dc881de23001b"`,
		`id: "550e8400-e29b-41d4-a716-446655440000"`,
		`fetch("https://api.example.com/v1/users?page=2")`,
		`import { createClient } from "@supabase/supabase-js"`,
		`- name: token\n  in: header\n  required: true`,
		`func (t *Token) Secret() string { return t.secret }`,
		"password: ${{ secrets.DB_PASSWORD }}",
	}
	for _, in := range cases {
		if got := Text(in); got != in {
			t.Errorf("over-redacted:\n in: %s\nout: %s", in, got)
		}
		if got := Mask(in); got != in {
			t.Errorf("over-masked:\n in: %s\nout: %s", in, got)
		}
	}
}

func TestMaskPrefixLast4(t *testing.T) {
	cases := map[string]string{
		`id = "` + fakeAWSKey + `"`:       `id = "AKIA…VQXK"`,
		`k = "` + fakeStripe + `"`:        `k = "sk_live_…8dPq"`,
		`token: ` + fakeGitHub():          `token: ghp_…` + fakeGitHub()[36:],
		`DB_PASSWORD=Tr0ub4dor3xy`:        `DB_PASSWORD=Tr…xy`,
		`API_KEY=short9x`:                 `API_KEY=[masked, 7 chars]`,
		`postgres://u:S3cr3tPa55w0rd@h/d`: `postgres://u:S3…rd@h/d`,
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestClassifyPreChecks(t *testing.T) {
	cases := []struct {
		value, typ, path string
		want             Class
		check            string
	}{
		{fakeGitHub(), "github_token", "src/app.ts", LikelyReal, "checksum_ok"},
		{fakeGitHub(), "github_token", "test/fixtures/a.ts", LikelyReal, "test_path"}, // checksum beats path
		{fakeGitHubBadChecksum(), "github_token", "", LikelyPlaceholder, "checksum_invalid"},
		{fakeNPM(), "npm_token", "", LikelyReal, "checksum_ok"},
		{"sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc", "stripe_secret_key", "", LikelyPlaceholder, "provider_docs_example"},
		{"sk_" + "test_" + "Hk3Lp9Qm2Wn7Xb4Zc8Vd1Fg6", "stripe_secret_key", "src/pay.ts", LikelyReal, ""}, // a test key is still a real key
		{"xxxxxxxxxxxxxxxx", "generic_secret", "", LikelyPlaceholder, "placeholder_pattern"},
		{"<your-token>", "generic_secret", "", LikelyPlaceholder, "placeholder_pattern"},
		{"dummy-secret-123", "generic_secret", "", LikelyPlaceholder, "placeholder_pattern"},
		{"Tr0ub4dor&3", "generic_secret", ".env.example", LikelyPlaceholder, "test_path"},
		{"Tr0ub4dor&3", "generic_secret", "config/prod.env", LikelyReal, ""},
		{"Zk9xLm3Qp7Rt2Vw8Yb4Nc6Hj0Ks5TyQe2LkF9", "generic_secret", "spec/fixtures/keys.yml", LikelyReal, "test_path"}, // high entropy survives a test path
	}
	for _, c := range cases {
		a := Classify(c.value, c.typ, c.path)
		if a.Class != c.want {
			t.Errorf("Classify(%s, %s): %s (%v), want %s", c.typ, c.path, a.Class, a.Checks, c.want)
		}
		if c.check != "" && !strings.Contains(strings.Join(a.Checks, "+"), c.check) {
			t.Errorf("Classify(%s, %s): checks %v missing %s", c.typ, c.path, a.Checks, c.check)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	for _, p := range []string{"test/a.go", "src/__tests__/x.ts", "pkg/foo_test.go", "a.spec.ts", "fixtures/k.json", "testdata/x", ".env.example", "config.sample.yml", "examples/demo.js"} {
		if !IsTestPath(p) {
			t.Errorf("%s should be a test path", p)
		}
	}
	for _, p := range []string{"src/app.ts", "internal/contest/x.go", "latest/a.go", ".env", "config/prod.yml"} {
		if IsTestPath(p) {
			t.Errorf("%s should not be a test path", p)
		}
	}
}

func TestEntropy(t *testing.T) {
	if e := Entropy("aaaa"); e != 0 {
		t.Fatal(e)
	}
	if e := Entropy("abcd"); e != 2 {
		t.Fatal(e)
	}
}

func TestKnownValueIsRedactedEvenWithoutPattern(t *testing.T) {
	f := &Finder{}
	f.Known("session_credential", "plainlookingsessionvalue")
	got := f.Redact(`{"user":"bob","note":"plainlookingsessionvalue"}`)
	if strings.Contains(got, "plainlookingsessionvalue") || !strings.Contains(got, "type=session_credential") {
		t.Fatal(got)
	}
}

func TestVaultRefsAreStableAndRestorable(t *testing.T) {
	v := NewVault()
	a := v.Redact("first " + fakeAWSKey + " and " + fakeJWT)
	b := v.Redact("again " + fakeJWT)
	if strings.Contains(a+b, fakeAWSKey) || strings.Contains(a+b, fakeJWT) {
		t.Fatal("raw value on the wire")
	}
	if !strings.Contains(a, "ref=S1") || !strings.Contains(a, "ref=S2") || !strings.Contains(b, "ref=S2") {
		t.Fatalf("refs not stable: %s | %s", a, b)
	}
	// The model hands a descriptor back (even a shortened one): restored locally.
	in := json.RawMessage(`{"headers":{"Authorization":"Bearer <SECRET: ref=S2, type=jwt>"},"note":"<SECRET: ref=S9>"}`)
	out := string(v.RestoreJSON(in))
	if !strings.Contains(out, "Bearer "+fakeJWT) {
		t.Fatalf("not restored: %s", out)
	}
	if !strings.Contains(out, "<SECRET: ref=S9>") {
		t.Fatalf("unknown ref must be left alone: %s", out)
	}
}

func TestRedactBlocksOnlyTouchesTextAndToolResults(t *testing.T) {
	v := NewVault()
	text, _ := json.Marshal(map[string]any{"type": "text", "text": "key " + fakeAWSKey})
	tr, _ := json.Marshal(map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": `{"body":"{\"token\":\"` + fakeJWT + `\"}"}`})
	nested, _ := json.Marshal(map[string]any{"type": "tool_result", "tool_use_id": "t2", "content": []any{map[string]any{"type": "text", "text": fakeStripe}}})
	img := json.RawMessage(`{"type":"image","source":{"data":"` + fakeAWSKey + `"}}`)
	out := v.RedactBlocks([]json.RawMessage{text, tr, nested, img})
	for i := 0; i < 3; i++ {
		s := string(out[i])
		if strings.Contains(s, fakeAWSKey) || strings.Contains(s, fakeJWT) || strings.Contains(s, fakeStripe) {
			t.Fatalf("block %d leaked: %s", i, s)
		}
	}
	if string(out[3]) != string(img) {
		t.Fatal("non-text block must pass through byte-for-byte")
	}
	plain, _ := json.Marshal(map[string]any{"type": "text", "text": "nothing secret here"})
	if got := v.RedactBlocks([]json.RawMessage{plain}); string(got[0]) != string(plain) {
		t.Fatal("unchanged block must be byte-identical")
	}
}

func gitleaksFinding(match, surrounding string) normalizer.Finding {
	return normalizer.Finding{
		ID: "gitleaks-0", Scanner: "gitleaks", Category: "secrets", RuleID: "generic-api-key",
		Title: "Leaked Generic API Key", RawMessage: "Secret found in the project files",
		FilePath: "src/config.ts", LineNumber: 3, CodeSnippet: match, SurroundingCode: surrounding,
	}
}

// A gitleaks match whose value no pattern knows is still redacted, everywhere
// it appears in the finding, and the location is unchanged.
func TestForAIRedactsScannerMatchEverywhere(t *testing.T) {
	val := "q8Rw2" + "Lm9Vx" + "7Np3Kt"
	match := `internalKey = "` + val + `"`
	sur := "import x from 'y'\n// key below\n" + match + "\nexport default internalKey\n"
	f := gitleaksFinding(match, sur)
	got := ForAI(f)
	if strings.Contains(got.CodeSnippet+got.SurroundingCode, val) {
		t.Fatalf("raw value leaked: %+v", got)
	}
	if got.FilePath != f.FilePath || got.LineNumber != f.LineNumber || got.RuleID != f.RuleID {
		t.Fatal("location changed")
	}
	if !strings.Contains(got.SurroundingCode, "import x from 'y'\n// key below\ninternalKey = \"<SECRET: type=secret_generic-api-key, len=16, prefix=q8Rw") ||
		!strings.HasSuffix(got.SurroundingCode, "\nexport default internalKey\n") {
		t.Fatalf("surrounding code not kept: %q", got.SurroundingCode)
	}
	if f.CodeSnippet != match {
		t.Fatal("input finding was modified (local UI must keep the raw value)")
	}
}

func TestValuesFromMatch(t *testing.T) {
	generic := "q8Rw2" + "Lm9Vx" + "7Np3Kt"
	cases := map[string]string{
		`key = "` + generic + `";`:   generic,
		`PASSWORD: hunter22hunter`:   "hunter22hunter",
		fakeAWSKey:                   fakeAWSKey,
		`"token": "` + fakeJWT + `"`: fakeJWT,
	}
	for in, want := range cases {
		got := ValuesFromMatch(in)
		if len(got) == 0 || got[0] != want {
			t.Errorf("ValuesFromMatch(%q) = %q", in, got)
		}
	}
}

func TestForUploadMasksButKeepsLocationAndCode(t *testing.T) {
	val := "q8Rw2" + "Lm9Vx" + "7Np3Kt"
	match := `internalKey = "` + val + `"`
	f := gitleaksFinding(match, "a()\n"+match+"\nb()\n")
	f.Proof = &normalizer.Proof{Method: "GET", URL: "https://app.test/api", ResponseExcerpt: `{"token":"` + fakeJWT + `"}`}
	got := ForUpload(f)
	if got.CodeSnippet != `internalKey = "q8Rw…p3Kt"` {
		t.Fatalf("snippet mask: %q", got.CodeSnippet)
	}
	if got.SurroundingCode != "a()\ninternalKey = \"q8Rw…p3Kt\"\nb()\n" {
		t.Fatalf("surrounding: %q", got.SurroundingCode)
	}
	if strings.Contains(got.Proof.ResponseExcerpt, fakeJWT) || !strings.Contains(got.Proof.ResponseExcerpt, "eyJ…") {
		t.Fatalf("proof excerpt: %q", got.Proof.ResponseExcerpt)
	}
	if got.FilePath != f.FilePath || got.LineNumber != f.LineNumber || got.ID != f.ID || got.Proof.URL != f.Proof.URL {
		t.Fatal("location changed")
	}
	b, _ := json.Marshal(ForUploadAll([]normalizer.Finding{f}))
	if strings.Contains(string(b), val) || strings.Contains(string(b), fakeJWT) {
		t.Fatal("raw value in upload JSON")
	}
	if f.CodeSnippet != match {
		t.Fatal("input finding modified")
	}
}
