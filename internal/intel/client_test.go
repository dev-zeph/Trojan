package intel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeIntel is a stand-in for the intel edge function. It decodes the
// {"encoded": base64} wrapper and answers with advisories for the requested
// package names.
type fakeIntel struct {
	t          *testing.T
	advisories []Advisory
	status     int
	body       string
	calls      atomic.Int32
	lastPkgs   []wirePackage
}

func (f *fakeIntel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		io.WriteString(w, f.body)
		return
	}
	var wrap struct {
		Encoded string `json:"encoded"`
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &wrap); err != nil || wrap.Encoded == "" {
		f.t.Errorf("body not base64-wrapped: %s", raw)
	}
	inner, err := base64.StdEncoding.DecodeString(wrap.Encoded)
	if err != nil {
		f.t.Errorf("bad base64: %v", err)
	}
	var req struct {
		Packages []wirePackage `json:"packages"`
	}
	if err := json.Unmarshal(inner, &req); err != nil {
		f.t.Errorf("bad inner json: %v", err)
	}
	f.lastPkgs = req.Packages
	names := map[string]bool{}
	for _, p := range req.Packages {
		names[p.Ecosystem+"/"+p.Name] = true
	}
	out := []Advisory{}
	for _, a := range f.advisories {
		if names[normEcosystem(a.Ecosystem)+"/"+normName(a.Ecosystem, a.Package)] {
			out = append(out, a)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"advisories": out, "generated_at": "2026-11-05T00:00:00Z"})
}

func testClient(url string) *Client {
	return &Client{URL: url, Token: func() (string, error) { return "tok", nil }}
}

func TestClientFetchOK(t *testing.T) {
	f := &fakeIntel{t: t, advisories: []Advisory{{ID: "GHSA-1", Ecosystem: "npm", Package: "next"}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	pkgs := []Package{
		{Ecosystem: "npm", Name: "next", Version: "14.1.0"},
		{Ecosystem: "npm", Name: "next", Version: "14.1.0"}, // duplicate is sent once
		{Ecosystem: "pypi", Name: "django", Version: "4.2.7"},
	}
	resp, err := testClient(srv.URL).Fetch(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Advisories) != 1 || resp.GeneratedAt == "" {
		t.Errorf("resp = %+v", resp)
	}
	if len(f.lastPkgs) != 2 {
		t.Errorf("sent %d packages, want 2", len(f.lastPkgs))
	}
}

func TestClientChunks(t *testing.T) {
	f := &fakeIntel{t: t, advisories: []Advisory{{ID: "A", Ecosystem: "npm", Package: "p0"}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	var pkgs []Package
	for i := 0; i < MaxPackagesPerRequest+10; i++ {
		pkgs = append(pkgs, Package{Ecosystem: "npm", Name: "p0", Version: "1.0." + itoa(i)})
	}
	resp, err := testClient(srv.URL).Fetch(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 2 || len(resp.Advisories) != 1 {
		t.Errorf("calls=%d advisories=%d", f.calls.Load(), len(resp.Advisories))
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestClientErrors(t *testing.T) {
	pkgs := []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}}
	tests := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"401", 401, `{"error":"unauthorized"}`, func(err error) bool { return errors.Is(err, ErrNotSignedIn) }},
		{"402", 402, `{"error":"subscription_required","message":"Intel needs Trojan Pro."}`, func(err error) bool {
			var se *SubscriptionRequiredError
			return errors.Is(err, ErrSubscriptionRequired) && errors.As(err, &se) && se.Message == "Intel needs Trojan Pro." &&
				err.Error() == "Intel needs Trojan Pro."
		}},
		{"500", 500, `{"error":"boom"}`, func(err error) bool {
			var se *StatusError
			return errors.As(err, &se) && se.Code == 500 && strings.Contains(err.Error(), "boom")
		}},
		{"malformed 200", 200, `{"advisories": [`, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "malformed")
		}},
		{"200 without advisories", 200, `{"generated_at":"x"}`, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "missing advisories")
		}},
		{"200 wrong type", 200, `{"advisories": {"id": 1}}`, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "malformed")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(&fakeIntel{t: t, status: tt.status, body: tt.body})
			defer srv.Close()
			_, err := testClient(srv.URL).Fetch(context.Background(), pkgs)
			if !tt.check(err) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	// No token: fails locally, no request.
	f := &fakeIntel{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: func() (string, error) { return "", nil }}
	if _, err := c.Fetch(context.Background(), pkgs); !errors.Is(err, ErrNotSignedIn) || f.calls.Load() != 0 {
		t.Errorf("empty token: err=%v calls=%d", err, f.calls.Load())
	}
	// Wrong token -> server 401.
	c = &Client{URL: srv.URL, Token: func() (string, error) { return "nope", nil }}
	if _, err := c.Fetch(context.Background(), pkgs); !errors.Is(err, ErrNotSignedIn) {
		t.Errorf("bad token: %v", err)
	}
}

func TestClientDefaultTokenFromConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := &fakeIntel{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	old := intelURL
	intelURL = srv.URL
	defer func() { intelURL = old }()

	pkgs := []Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}}
	if _, err := NewClient().Fetch(context.Background(), pkgs); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("no config: %v", err)
	}
	os.MkdirAll(filepath.Join(home, ".trojan"), 0o700)
	os.WriteFile(filepath.Join(home, ".trojan", "config.json"), []byte(`{"access_token":"tok"}`), 0o600)
	if _, err := NewClient().Fetch(context.Background(), pkgs); err != nil {
		t.Fatalf("with config: %v", err)
	}
}

func TestCheckEndToEnd(t *testing.T) {
	// Copy the fixture project so the cache write doesn't touch testdata.
	root := t.TempDir()
	copyTree(t, filepath.Join("testdata", "project"), root)

	f := &fakeIntel{t: t, advisories: []Advisory{
		{ID: "GHSA-next", Kind: "vulnerability", Ecosystem: "npm", Package: "next", Severity: "critical",
			AffectedRanges: ranges(t, `[{"type":"SEMVER","events":[{"introduced":"14.0.0"},{"fixed":"14.2.25"},{"introduced":"15.0.0"},{"fixed":"15.2.3"}]}]`),
			FixedVersion:   strp("15.2.3"), PlaybookID: strp("nextjs-middleware-bypass")},
		{ID: "GHSA-semver", Kind: "vulnerability", Ecosystem: "npm", Package: "semver", Severity: "moderate",
			AffectedRanges: ranges(t, `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.7.2"},{"introduced":"6.0.0"},{"fixed":"6.3.1"},{"introduced":"7.0.0"},{"fixed":"7.5.2"}]}]`)},
		{ID: "MAL-event-stream", Kind: "malicious", Ecosystem: "npm", Package: "event-stream", Severity: "critical",
			AffectedVersions: []string{"3.3.6"}},
		{ID: "PYSEC-django", Kind: "vulnerability", Ecosystem: "PyPI", Package: "Django", Severity: "HIGH",
			AffectedRanges: ranges(t, `[{"type":"ECOSYSTEM","events":[{"introduced":"4.2"},{"fixed":"4.2.8"}]}]`)},
		{ID: "PYSEC-requests-old", Ecosystem: "pypi", Package: "requests", Severity: "medium",
			AffectedRanges: ranges(t, `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.20.0"}]}]`)},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	res, err := Check(context.Background(), root, Options{Client: testClient(srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range res.Matches {
		ids = append(ids, m.ID)
		if m.Status != StatusMatchedUnproven {
			t.Errorf("%s status %q", m.ID, m.Status)
		}
	}
	want := []string{
		"MAL-event-stream|npm|event-stream@3.3.6", // critical + malicious
		"GHSA-next|npm|next@14.1.0",               // critical, direct
		"PYSEC-django|pypi|django@4.2.7",          // high
		"GHSA-semver|npm|semver@5.7.1",            // medium (moderate)
		"GHSA-semver|npm|semver@7.5.1",
	}
	if strings.Join(ids, "\n") != strings.Join(want, "\n") {
		t.Errorf("matches:\n%s\nwant:\n%s", strings.Join(ids, "\n"), strings.Join(want, "\n"))
	}
	next := res.Matches[1]
	if next.FixedVersion != "14.2.25" || !next.ProofAvailable || !next.Direct || next.Lockfile != "package-lock.json" {
		t.Errorf("next match = %+v", next)
	}
	if res.Matches[3].FixedVersion != "5.7.2" || res.Matches[4].FixedVersion != "7.5.2" {
		t.Errorf("semver fixes = %q %q", res.Matches[3].FixedVersion, res.Matches[4].FixedVersion)
	}
	if res.Matches[2].Lockfile != "services/api/requirements.txt" || res.Matches[2].Severity != "high" {
		t.Errorf("django = %+v", res.Matches[2])
	}
	if res.PackagesScanned != 6 || len(res.Lockfiles) != 2 || res.FromCache || res.IntelGeneratedAt == "" {
		t.Errorf("result = %+v", res)
	}

	// Cache was written; an offline run uses it.
	if _, err := os.Stat(filepath.Join(root, ".trojan", "intel", "advisories.json")); err != nil {
		t.Fatal(err)
	}
	off, err := Check(context.Background(), root, Options{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !off.FromCache || len(off.Matches) != len(res.Matches) || off.FetchedAt.IsZero() || off.UncoveredPackages != 0 {
		t.Errorf("offline = %+v", off)
	}

	// Server down -> cache fallback with a warning; new package counted as uncovered.
	os.WriteFile(filepath.Join(root, "services", "api", "requirements.txt"), []byte("Django==4.2.7\nrequests==2.31.0\nflask==3.0.0\n"), 0o644)
	down := httptest.NewServer(&fakeIntel{t: t, status: 503, body: `{"error":"unavailable"}`})
	defer down.Close()
	fb, err := Check(context.Background(), root, Options{Client: testClient(down.URL)})
	if err != nil {
		t.Fatal(err)
	}
	if !fb.FromCache || fb.UncoveredPackages != 1 || len(fb.Warnings) == 0 {
		t.Errorf("fallback = %+v", fb)
	}

	// 402 is never masked by the cache.
	pay := httptest.NewServer(&fakeIntel{t: t, status: 402, body: `{"error":"subscription_required","message":"upgrade"}`})
	defer pay.Close()
	if _, err := Check(context.Background(), root, Options{Client: testClient(pay.URL)}); !errors.Is(err, ErrSubscriptionRequired) {
		t.Errorf("402: %v", err)
	}

	// Upgrading next to the fixed version makes its match disappear (prove path).
	os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"next":"14.2.25"}},"node_modules/next":{"version":"14.2.25"}}}`), 0o644)
	pkgs, _, err := ParseProject(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range MatchAdvisories(pkgs, f.advisories) {
		if m.Package == "next" {
			t.Errorf("next still matched after upgrade: %s", m.ID)
		}
	}
	if c, ok := CompareVersions("npm", "14.2.25", next.FixedVersion); !ok || c < 0 {
		t.Errorf("installed should be >= fixed")
	}
}

func TestCheckNoPackagesSkipsNetwork(t *testing.T) {
	f := &fakeIntel{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	res, err := Check(context.Background(), t.TempDir(), Options{Client: testClient(srv.URL)})
	if err != nil || f.calls.Load() != 0 || len(res.Matches) != 0 || res.Matches == nil {
		t.Errorf("res=%+v err=%v calls=%d", res, err, f.calls.Load())
	}
}

func TestCheckOfflineWithoutCache(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644)
	if _, err := Check(context.Background(), root, Options{Offline: true}); err == nil {
		t.Error("want error with no cache")
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
