package dast

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Fake values, built at run time so nothing token-shaped is committed.
func fakeTok() string { return strings.Repeat("Qz7", 11) + "k" }
func fakeHex() string { return strings.Repeat("c0ffee", 6) }
func fakeJWT() string {
	return "eyJ" + strings.Repeat("hb9", 6) + "." + "eyJ" + strings.Repeat("pl4", 6) + "." + strings.Repeat("sg2", 8)
}

func fakeLet20() string { return strings.Repeat("hQkZpLmWtR", 2) }
func fakeLow16() string { return strings.Repeat("qwhzk", 3) + "x" }
func fakeMix11() string { return "aB3" + "dE6" + "gH9" + "jK" }
func fakeDig10() string { return "a1" + "b2" + "c3" + "d4" + "e5" }

func expand(s string) string {
	return strings.NewReplacer("<TOK>", fakeTok(), "<HEX>", fakeHex(), "<JWT>", fakeJWT(),
		"<LET20>", fakeLet20(), "<LOW16>", fakeLow16(), "<MIX11>", fakeMix11(), "<DIG10>", fakeDig10()).Replace(s)
}

type scrubVectors struct {
	URLs []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"urls"`
	Request struct {
		In  json.RawMessage `json:"in"`
		Out json.RawMessage `json:"out"`
		Key string          `json:"digest"`
	} `json:"request"`
}

func loadVectors(t *testing.T) scrubVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "crawl_scrub_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v scrubVectors
	if err := json.Unmarshal([]byte(expand(string(raw))), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestScrubURLVectors(t *testing.T) {
	for _, c := range loadVectors(t).URLs {
		if got := ScrubURL(c.In); got != c.Out {
			t.Errorf("ScrubURL(%q)\n got %q\nwant %q", c.In, got, c.Out)
		}
	}
}

func TestScrubURLNeverKeepsFakeValues(t *testing.T) {
	for _, c := range loadVectors(t).URLs {
		got := ScrubURL(c.In)
		for _, v := range []string{fakeTok(), fakeHex(), fakeJWT(), fakeLet20(), fakeLow16(), fakeMix11(), fakeDig10(), "Pw", "frag", "jane", "zephaniah", "@"} {
			if strings.Contains(got, v) {
				t.Errorf("ScrubURL(%q) kept %q: %q", c.In, v, got)
			}
		}
	}
}

func TestScrubSegment(t *testing.T) {
	cases := map[string]string{
		"123": "123", "orders": "orders", "v2": "v2", "": "",
		"550e8400-e29b-41d4-a716-446655440000": "{uuid}",
		"1234567890":                           "{num}", "123456789": "123456789",
		fakeTok(): "{token}", fakeHex(): "{token}", fakeJWT(): "{token}",
		"how-to-reset-password-2024": "how-to-reset-password-2024",
		"a1b2c3d4e5f6g7":             "{token}",
	}
	for in, want := range cases {
		if got := ScrubSegment(in); got != want {
			t.Errorf("ScrubSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeToken(t *testing.T) {
	yes := []string{fakeTok(), fakeHex(), fakeJWT(), strings.Repeat("a", 40), "abc%2Fdef%3Dxyz", strings.Repeat("word", 6)}
	no := []string{"login", "account-settings", "v1", "2024", "my_profile", "index.html", "terms-of-service"}
	for _, s := range yes {
		if !LooksLikeToken(s) {
			t.Errorf("LooksLikeToken(%q) = false", s)
		}
	}
	for _, s := range no {
		if LooksLikeToken(s) {
			t.Errorf("LooksLikeToken(%q) = true", s)
		}
	}
}

func TestScrubNames(t *testing.T) {
	got := ScrubNames([]string{"b", "a", "a", " c ", "", "bad name", fakeTok(), strings.Repeat("n", 65), "user[email]"})
	want := []string{"a", "b", "c", "user[email]"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScrubNames = %v, want %v", got, want)
	}
	many := make([]string, 80)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i%40) + string(rune('a'+i%26))
	}
	if n := len(ScrubNames(many)); n > maxScrubNames {
		t.Errorf("ScrubNames kept %d names, cap is %d", n, maxScrubNames)
	}
}

func TestScrubTemplateRequestVector(t *testing.T) {
	v := loadVectors(t)
	var in, want TemplateRequest
	if err := json.Unmarshal(v.Request.In, &in); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(v.Request.Out, &want); err != nil {
		t.Fatal(err)
	}
	got := ScrubTemplateRequest(in)
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Errorf("ScrubTemplateRequest\n got %s\nwant %s", g, w)
	}
	if k := CrawlKey(in); k != v.Request.Key {
		t.Errorf("CrawlKey = %s, want %s (shared with the server tests)", k, v.Request.Key)
	}
	body, _ := json.Marshal(got)
	for _, s := range []string{fakeTok(), fakeHex(), "me:pw", "/account", "/cart"} {
		if strings.Contains(string(body), s) {
			t.Errorf("scrubbed request still contains %q", s)
		}
	}
}

func TestScrubTemplateRequestCapsEndpoints(t *testing.T) {
	req := TemplateRequest{TargetURL: "https://example.com"}
	for i := 0; i < 500; i++ {
		req.Endpoints = append(req.Endpoints, Endpoint{URL: "https://example.com/p" + strings.Repeat("x", i%50) + "/" + string(rune('a'+i%26)), Method: "GET"})
	}
	if n := len(ScrubTemplateRequest(req).Endpoints); n > maxScrubEndpoints {
		t.Errorf("kept %d endpoints, cap is %d", n, maxScrubEndpoints)
	}
}

func TestCrawlKey(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	base := TemplateRequest{
		TargetURL: "https://example.com/?a=1",
		Endpoints: []Endpoint{{URL: "https://example.com/login?sid=" + fakeHex(), Method: "GET", QueryParams: []string{"sid"}}},
		TechHints: []string{"react"},
	}
	k := CrawlKey(base)
	if !hex64.MatchString(k) {
		t.Fatalf("CrawlKey = %q, want 64 hex chars", k)
	}
	// Different query values, a fragment and a user:password@ give the same key:
	// they were never part of what's sent.
	same := base
	same.TargetURL = "https://u:p@example.com/?a=2#x"
	same.Endpoints = []Endpoint{{URL: "https://example.com/login?sid=" + fakeTok(), Method: "get", QueryParams: []string{"sid"}}}
	if CrawlKey(same) != k {
		t.Error("CrawlKey changed with query values only")
	}
	// Anything that changes the prompt changes the key.
	for name, mut := range map[string]func(*TemplateRequest){
		"path": func(r *TemplateRequest) { r.Endpoints = []Endpoint{{URL: "https://example.com/signin", Method: "GET"}} },
		"host": func(r *TemplateRequest) { r.TargetURL = "https://other.example.com" },
		"fields": func(r *TemplateRequest) {
			r.Endpoints = []Endpoint{{URL: "https://example.com/login", Method: "GET", FormFields: []string{"otp"}, QueryParams: []string{"sid"}}}
		},
		"hints": func(r *TemplateRequest) { r.TechHints = []string{"django"} },
		"max":   func(r *TemplateRequest) { r.MaxTemplates = 3 },
	} {
		r := base
		mut(&r)
		if CrawlKey(r) == k {
			t.Errorf("CrawlKey ignored a change to %s", name)
		}
	}
}

// GenerateTemplates must send only the scrubbed request.
func TestGenerateTemplatesSendsScrubbedRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		body = buf[:n]
		w.Write([]byte(`{"templates":["id: x\nhttp:\n"],"rationale":"r"}`)) //nolint:errcheck
	}))
	defer srv.Close()
	old := dastTemplatesEndpoint
	dastTemplatesEndpoint = srv.URL
	defer func() { dastTemplatesEndpoint = old }()

	req := TemplateRequest{
		TargetURL: "https://me:pw@example.com/?k=" + fakeTok(),
		Endpoints: []Endpoint{{URL: "https://example.com/reset/" + fakeTok() + "?t=" + fakeHex(), Method: "GET"}},
	}
	if _, err := GenerateTemplates(req, "test-access"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fakeTok(), fakeHex(), "me:pw"} {
		if strings.Contains(string(body), s) {
			t.Errorf("request body contains %q", s)
		}
	}
	if !strings.Contains(string(body), `https://example.com/reset/{token}?t=`) {
		t.Errorf("request body missing the scrubbed URL: %s", body)
	}
}

func TestLooksLikeEmail(t *testing.T) {
	for _, s := range []string{"jane.doe@example.com", "jane+news@example.com", "jane@example", "@janedoe"} {
		if !LooksLikeEmail(s) {
			t.Errorf("LooksLikeEmail(%q) = false", s)
		}
	}
	for _, s := range []string{"jane.doe", "orders", "example.com", ""} {
		if LooksLikeEmail(s) {
			t.Errorf("LooksLikeEmail(%q) = true", s)
		}
	}
}

func TestIsPersonParent(t *testing.T) {
	for _, s := range []string{"users", "U", "profile", "Members", "authors", "customers"} {
		if !IsPersonParent(s) {
			t.Errorf("IsPersonParent(%q) = false", s)
		}
	}
	for _, s := range []string{"orders", "docs", "contact", "account", ""} {
		if IsPersonParent(s) {
			t.Errorf("IsPersonParent(%q) = true", s)
		}
	}
}

func TestLooksLikePersonName(t *testing.T) {
	for _, s := range []string{"zephaniah-chizulu", "Jane_Doe", "jdoe", "acme-corp"} {
		if !LooksLikePersonName(s) {
			t.Errorf("LooksLikePersonName(%q) = false", s)
		}
	}
	for _, s := range []string{"123", "{uuid}", "new", "me", "Settings", "sign-in", ""} {
		if LooksLikePersonName(s) {
			t.Errorf("LooksLikePersonName(%q) = true", s)
		}
	}
}

func TestScrubPath(t *testing.T) {
	cases := []struct{ in, want []string }{
		{[]string{"", "users", "jane-doe", "orders"}, []string{"users", "{name}", "orders"}},
		{[]string{"users", "123", "orders"}, []string{"users", "123", "orders"}},
		{[]string{"users", "new"}, []string{"users", "new"}},
		{[]string{"u", "jane@example.com"}, []string{"u", "{email}"}},
		{[]string{"p;jsessionid=x", ".", "..", "x"}, []string{"p", "x"}},
		{[]string{"docs", "getting-started"}, []string{"docs", "getting-started"}},
		{[]string{"users", fakeTok()}, []string{"users", "{token}"}},
	}
	for _, c := range cases {
		if got := ScrubPath(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ScrubPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRandomLetters(t *testing.T) {
	for _, s := range []string{fakeLet20(), fakeLow16(), "ZxCv" + "BnMq" + "WeRtYuIoPa"} {
		if !RandomLetters(s) {
			t.Errorf("RandomLetters(%q) = false", s)
		}
	}
	for _, s := range []string{"internationalization", "getUserProfileSettings", "troubleshootingguide", "dashboard", "gettingstarted", "Supercalifragilistic", fakeLet20()[:15], "abc123defghijklmnop"} {
		if RandomLetters(s) {
			t.Errorf("RandomLetters(%q) = true", s)
		}
	}
}

func TestShortMixedToken(t *testing.T) {
	for _, s := range []string{fakeMix11(), fakeDig10(), "Z9y8X7w6"} {
		if !ShortMixedToken(s) {
			t.Errorf("ShortMixedToken(%q) = false", s)
		}
	}
	for _, s := range []string{"iPhone15Pro", "abc123def", "v2", "dashboard", "a1-b2-c3-d4", "release2024", "aB3dE6g", strings.Repeat("a1", 6)} {
		if ShortMixedToken(s) {
			t.Errorf("ShortMixedToken(%q) = true", s)
		}
	}
}

func TestHasUnsafeRune(t *testing.T) {
	for _, s := range []string{"https://a.example\\@b/x", "https://a.example/x\ty", "https://a.example/\n", "x\x7f"} {
		if !hasUnsafeRune(s) {
			t.Errorf("hasUnsafeRune(%q) = false", s)
		}
	}
	if hasUnsafeRune("https://a.example/caf\u00e9?q=1") {
		t.Error("hasUnsafeRune flagged a normal URL")
	}
}

func TestCharClass(t *testing.T) {
	for in, want := range map[rune]int{'a': 0, 'Z': 1, '7': 2, '-': 3, '\u00e9': 3} {
		if got := charClass(in); got != want {
			t.Errorf("charClass(%q) = %d, want %d", in, got, want)
		}
	}
	if !isVowel('E') || isVowel('k') {
		t.Error("isVowel")
	}
}
