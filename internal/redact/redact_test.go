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
			`const id = "<SECRET removed by Trojan: type=aws_access_key, len=20, prefix=AKIA, looks=real>"`},
		{"aws_secret_key", `aws_secret_access_key = ` + fakeAWSSecret,
			`aws_secret_access_key = <SECRET removed by Trojan: type=aws_secret_key, len=40, looks=real>`},
		{"github_token_checksum_ok", `token: ` + fakeGitHub(),
			`token: <SECRET removed by Trojan: type=github_token, len=40, prefix=ghp_, looks=real, why=checksum_ok>`},
		{"github_token_checksum_bad", `token: ` + fakeGitHubBadChecksum(),
			`token: <SECRET removed by Trojan: type=github_token, len=40, prefix=ghp_, looks=placeholder, why=checksum_invalid>`},
		{"npm_token", `//registry.npmjs.org/:_authToken=` + fakeNPM(),
			`//registry.npmjs.org/:_authToken=<SECRET removed by Trojan: type=npm_token, len=40, prefix=npm_, looks=real, why=checksum_ok>`},
		{"stripe_live", `stripe(` + `"` + fakeStripe + `")`,
			`stripe("<SECRET removed by Trojan: type=stripe_secret_key, len=38, prefix=sk_live_, looks=real>")`},
		{"slack", `SLACK=` + fakeSlack,
			`SLACK=<SECRET removed by Trojan: type=slack_token, len=50, prefix=xoxb-, looks=real>`},
		{"google", `key=` + fakeGoogle,
			`key=<SECRET removed by Trojan: type=google_api_key, len=39, prefix=AIza, looks=real>`},
		{"anthropic", `new Anthropic({ apiKey: "` + fakeAnthropic + `" })`,
			`new Anthropic({ apiKey: "<SECRET removed by Trojan: type=anthropic_api_key, len=43, prefix=sk-ant-api03-, looks=real>" })`},
		{"openai", `OPENAI_API_KEY=` + fakeOpenAI,
			`OPENAI_API_KEY=<SECRET removed by Trojan: type=openai_api_key, len=40, prefix=sk-proj-, looks=real>`},
		{"sendgrid", `sg.setApiKey("` + fakeSendgrid + `")`,
			`sg.setApiKey("<SECRET removed by Trojan: type=sendgrid_api_key, len=69, prefix=SG., looks=real>")`},
		{"jwt_with_role", `const k = "` + fakeJWT + `"`,
			`const k = "<SECRET removed by Trojan: type=jwt, len=120, prefix=eyJ, looks=real, jwt_alg=HS256, claims=iss|role, role=service_role>"`},
		{"url_password", `DATABASE_URL=postgres://app:S3cr3tPa55w0rd@db.internal:5432/app`,
			`DATABASE_URL=postgres://app:<SECRET removed by Trojan: type=url_password, len=14, looks=real>@db.internal:5432/app`},
		{"bearer_header", `Authorization: Bearer Zk9xLm3Qp7Rt2Vw8Yb4Nc6`,
			`Authorization: Bearer <SECRET removed by Trojan: type=authorization_header, len=22, looks=real>`},
		{"generic_quoted", `const dbPassword = "Tr0ub4dor&3xyz"`,
			`const dbPassword = "<SECRET removed by Trojan: type=generic_secret, len=14, looks=real>"`},
		{"generic_placeholder", `API_KEY=changeme123`,
			`API_KEY=<SECRET removed by Trojan: type=generic_secret, len=11, looks=placeholder, why=placeholder_pattern>`},
		{"aws_docs_example", `aws_access_key_id = AK` + `IAIOSFODNN7EXAMPLE`,
			`aws_access_key_id = <SECRET removed by Trojan: type=aws_access_key, len=20, prefix=AKIA, looks=placeholder, why=provider_docs_example>`},
		{"low_variety", `API_TOKEN=aaaaaaaaaaaa1`,
			`API_TOKEN=<SECRET removed by Trojan: type=generic_secret, len=13, looks=placeholder, why=low_entropy>`},
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
	if !strings.Contains(got, "<SECRET removed by Trojan: type=private_key") || !strings.HasSuffix(got, "`\nconsole.log('ok')") {
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

func TestMaskVendorPrefixLast4OrHidden(t *testing.T) {
	cases := map[string]string{
		`id = "` + fakeAWSKey + `"`:       `id = "AKIA…VQXK"`,
		`k = "` + fakeStripe + `"`:        `k = "sk_live_…8dPq"`,
		`token: ` + fakeGitHub():          `token: ghp_…` + fakeGitHub()[36:],
		`DB_PASSWORD=Tr0ub4dor3xy`:        `DB_PASSWORD=[hidden, 12 chars]`,
		`API_KEY=short9x`:                 `API_KEY=[hidden, 7 chars]`,
		`postgres://u:S3cr3tPa55w0rd@h/d`: `postgres://u:[hidden, 14 chars]@h/d`,
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
		{"Tr0ub4dor&3", "generic_secret", ".env.example", LikelyReal, "test_path"}, // test_path does not flip looks
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
	if !strings.Contains(got.SurroundingCode, "import x from 'y'\n// key below\ninternalKey = \"<SECRET removed by Trojan:") ||
		!strings.Contains(got.SurroundingCode, "len=16") ||
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
	if got.CodeSnippet != `internalKey = "[hidden, 16 chars]"` {
		t.Fatalf("snippet mask: %q", got.CodeSnippet)
	}
	if got.SurroundingCode != "a()\ninternalKey = \"[hidden, 16 chars]\"\nb()\n" {
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

// UX Lead failing cases (2026-11-26 MCP usability test): URL query params,
// x-api-key headers, short unquoted passwords, and redis://:password@host.
func TestUXLeadURLQueryAndHeaderRedaction(t *testing.T) {
	apiKey := "IfuK" + "P6oZZjAvJV3UEdmKtwgFxg9KGWWc"
	header := "3nIs" + "HSiCqHU5G1FYlewUGcE5LCAfFlMm"
	amz := "anAm" + "zSignatureExampleValue0001"
	in := "fetch('https://api.example.com/v1/data?api_key=" + apiKey + "&user=1')"
	got := Text(in)
	if strings.Contains(got, apiKey) {
		t.Fatalf("api_key query leaked: %s", got)
	}
	if !strings.Contains(got, "user=1") || !strings.Contains(got, "type=url_query") {
		t.Fatalf("should keep param names and user=1: %s", got)
	}
	up := Mask(in)
	if strings.Contains(up, apiKey) {
		t.Fatalf("api_key leaked in upload: %s", up)
	}

	hdr := "curl -H 'x-api-key: " + header + "' https://api.x.com"
	got = Text(hdr)
	if strings.Contains(got, header) {
		t.Fatalf("x-api-key leaked: %s", got)
	}
	if strings.Contains(Mask(hdr), header) {
		t.Fatalf("x-api-key leaked in upload: %s", Mask(hdr))
	}

	// Other secret-named query params from the report must also be masked.
	names := []string{"apikey", "key", "secret", "client_secret", "password", "pwd", "sig", "signature", "code", "X-Amz-Signature", "token", "access_token"}
	for _, name := range names {
		line := "https://ex.test/v1?user=1&" + name + "=" + amz + "&ok=true"
		got := Text(line)
		if strings.Contains(got, amz) {
			t.Errorf("%s query leaked: %s", name, got)
		}
		if !strings.Contains(got, "user=1") || !strings.Contains(got, "ok=true") {
			t.Errorf("%s should keep non-secret params: %s", name, got)
		}
	}
}

func TestUXLeadPasswordAndRedisURL(t *testing.T) {
	if got := Text("password=hunter2"); strings.Contains(got, "hunter2") || !strings.Contains(got, "type=password") {
		t.Fatalf("password=hunter2: %s", got)
	}
	if got := Text("pass: 6DciK"); strings.Contains(got, "6DciK") {
		t.Fatalf("pass: 6DciK leaked: %s", got)
	}
	redisPW := "k6zc" + "bWUsNNA2l7xErhJM"
	in := "redis://:" + redisPW + "@cache:6379"
	got := Text(in)
	if strings.Contains(got, redisPW) {
		t.Fatalf("redis empty-user password leaked: %s", got)
	}
	if !strings.Contains(got, "type=url_password") {
		t.Fatalf("expected url_password: %s", got)
	}
}

func TestGenericPrefixIsNotSecretCharacters(t *testing.T) {
	// Generic password: AI label must not show leading characters, upload is fully hidden.
	in := `password = "Tr0ub4dor&8BiK"`
	got := Text(in)
	if strings.Contains(got, "prefix=Tr0u") || strings.Contains(got, "Tr0u") {
		t.Fatalf("generic prefix leaked to AI: %s", got)
	}
	if !strings.Contains(got, "looks=real") || !strings.Contains(got, "len=14") {
		t.Fatalf("label missing length/looks: %s", got)
	}
	up := Mask(in)
	if strings.Contains(up, "Tr0u") || strings.Contains(up, "8BiK") || !strings.Contains(up, "[hidden, 14 chars]") {
		t.Fatalf("upload should fully hide generic password: %s", up)
	}
}

func TestVendorPrefixOnlyOnKnownPrefixes(t *testing.T) {
	s := Secret{Value: fakeStripe, Type: "stripe_secret_key"}
	if SafePrefixFor(s) != "sk_live_" {
		t.Fatalf("stripe prefix: %q", SafePrefixFor(s))
	}
	s = Secret{Value: "Tr0ub4dor&8BiK", Type: "password"}
	if SafePrefixFor(s) != "" {
		t.Fatalf("generic must have empty prefix, got %q", SafePrefixFor(s))
	}
}

func TestEncodedVendorKeysAreDetected(t *testing.T) {
	body := fakeStripe
	cases := []struct {
		name, text string
	}{
		{"url_json", "https://x.com/a?data=%7B%22key%22%3A%20%22" + body + "%22%7D"},
		{"pct_eq", "x%3D" + body},
		{"pct_space", "x%20" + body},
		{"json_u", `x\u0022` + body},
		{"underscore", "pref_" + body},
		{"token_ghp", "token%3D" + fakeGitHub()},
	}
	for _, c := range cases {
		hits := Find(c.text)
		if len(hits) == 0 {
			t.Errorf("%s: detected nothing in %q", c.name, c.text)
			continue
		}
		red := Text(c.text)
		if strings.Contains(red, body) || strings.Contains(red, fakeGitHub()) {
			t.Errorf("%s: raw value survived: %s", c.name, red)
		}
		if !strings.Contains(red, "SECRET removed by Trojan") {
			t.Errorf("%s: missing label: %s", c.name, red)
		}
	}
}

func TestLongValuesAreFullyMasked(t *testing.T) {
	long := strings.Repeat("Ab1", 133) + "Z" // 400 chars, not a vendor key
	if len(long) != 400 {
		t.Fatalf("len=%d", len(long))
	}
	env := "API_KEY=" + long
	red := Text(env)
	if strings.Contains(red, long) || strings.Contains(red, long[256:]) {
		t.Fatalf("400-char env leaked: %s", red)
	}
	if !strings.Contains(red, "len=400") {
		t.Fatalf("expected len=400, got %s", red)
	}

	quoted := `api_key: "` + long + `x"` // 401 inside quotes
	red = Text(quoted)
	if strings.Contains(red, long) {
		t.Fatalf("quoted long value leaked: %s", red)
	}

	pw := strings.Repeat("Cd2", 85) // 255
	u := "postgres://u:" + pw + "@h/db"
	red = Text(u)
	if strings.Contains(red, pw) {
		t.Fatalf("long url password leaked: %s", red)
	}
}

func TestAWSKeyInExampleStaysReal(t *testing.T) {
	k := "AKIA" + "ABCDEFGHIJKLMNOP" // 20-char access key shape; fake
	a := Classify(k, "aws_access_key", ".env.example")
	if a.Class != LikelyReal {
		t.Fatalf("looks=%s checks=%v, want real", a.Class, a.Checks)
	}
	if !strings.Contains(strings.Join(a.Checks, "+"), "test_path") {
		t.Fatalf("expected why=test_path, got %v", a.Checks)
	}
	lab := Descriptor(Secret{Value: k, Type: "aws_access_key"}, ".env.example", "")
	if !strings.Contains(lab, "looks=real") || !strings.Contains(lab, "why=test_path") {
		t.Fatalf("label=%s", lab)
	}
}

func TestTypeNamesForEnvAndURL(t *testing.T) {
	hex := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
	hits := Find("JWT_SECRET=" + hex)
	if len(hits) == 0 || hits[0].Type == "session_cookie" {
		t.Fatalf("JWT_SECRET should not be session_cookie: %+v", hits)
	}
	hits = Find("https://x.com/?token=" + hex)
	if len(hits) == 0 || hits[0].Type != "url_query" {
		t.Fatalf("?token= should be url_query: %+v", hits)
	}
	rk := "rk_" + "live_" + "ABCDEFGH12"
	hits = Find("k=" + rk)
	// may need surrounding word boundary; also as raw
	hits = Find(rk + " ")
	if len(hits) == 0 || hits[0].Type != "stripe_restricted_key" {
		t.Fatalf("rk_live_ should be stripe_restricted_key: %+v", hits)
	}
	secretVal := "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab"
	hits = Find("SECRET_KEY='" + secretVal + "'")
	if len(hits) == 0 || hits[0].Type == "password" {
		t.Fatalf("SECRET_KEY should not be password: %+v", hits)
	}
}

func TestP2FormsAreMasked(t *testing.T) {
	val := "Fclb" + "thHV8fa56vORRwkgLcLsbMTrRvHX"
	user := "ad" + "min"
	curlUser := func(flag string) string {
		return "curl " + flag + " " + user + ":" + val + " https://example.com"
	}
	cases := []string{
		"https://x.com/?access_key=" + val + "&a=1",
		"https://x.com/?accessKey=" + val,
		curlUser("-u"),
		curlUser("--user"),
		"https://x.com/?x=1&amp;api_key=" + val,
		"https://x.com/?bearer=" + val,
		"Authorization: " + val,
		"Ocp-Apim-Subscription-Key: " + val,
		"https://x.com/api_key/" + val + "/items",
	}
	for _, c := range cases {
		red := Text(c)
		if strings.Contains(red, val) {
			t.Errorf("leaked in %q -> %s", c, red)
		}
		if !strings.Contains(red, "SECRET removed by Trojan") {
			t.Errorf("no label for %q -> %s", c, red)
		}
	}
}

func TestJWTDanglingQuoteIsRemoved(t *testing.T) {
	tok := fakeJWT
	// A gitleaks-style snippet that includes only the trailing quote.
	in := tok + `"`
	out := Text(in)
	if strings.HasSuffix(out, `>"`) || strings.HasSuffix(out, `"`) && !strings.HasSuffix(out, `>`) {
		t.Fatalf("dangling quote left: %s", out)
	}
	if strings.Contains(out, tok) {
		t.Fatalf("jwt leaked: %s", out)
	}
}
