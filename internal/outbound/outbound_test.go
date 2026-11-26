package outbound

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

func TestFolderName(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"/":                              "",
		"/Users/alice/clients/acme-shop": "acme-shop",
		"/Users/alice/acme-shop/":        "acme-shop",
		`C:\Users\alice\acme-shop`:       "acme-shop",
		`C:\`:                            "",
		"acme-shop":                      "acme-shop",
		"  /tmp/app  ":                   "app",
	}
	for in, want := range cases {
		if got := FolderName(in); got != want {
			t.Errorf("FolderName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRelPath(t *testing.T) {
	root := "/Users/alice/acme-shop"
	cases := map[string]string{
		"":                                "",
		"src/a.ts":                        "src/a.ts",
		root:                              ".",
		root + "/src/a.ts":                "src/a.ts",
		"/Users/alice/acme-shop2/x.ts":    "x.ts",
		"/Users/alice/.ssh/id_rsa":        "id_rsa",
		"https://shop.example/login":      "https://shop.example/login",
		`C:\Users\alice\other\secret.env`: "secret.env",
	}
	for in, want := range cases {
		if got := RelPath(root, in); got != want {
			t.Errorf("RelPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RelPath("", "/Users/alice/acme-shop/a.ts"); got != "a.ts" {
		t.Errorf("no root: %q", got)
	}
	if got := RelPath(`C:\Users\alice\shop`, `C:\Users\alice\shop\src\a.ts`); got != "src/a.ts" {
		t.Errorf("windows root: %q", got)
	}
}

func TestFindingsCopiesAndRelativizes(t *testing.T) {
	root := "/Users/alice/acme-shop"
	in := []normalizer.Finding{
		{ID: "a", FilePath: root + "/src/a.ts", SourceFile: root + "/api/h.go"},
		{ID: "b", FilePath: "https://shop.example/x"},
		{ID: "c", FilePath: root},
	}
	out := Findings(root, in)
	if out[0].FilePath != "src/a.ts" || out[0].SourceFile != "api/h.go" || out[1].FilePath != "https://shop.example/x" || out[2].FilePath != "." {
		t.Errorf("got %+v", out)
	}
	if in[0].FilePath != root+"/src/a.ts" {
		t.Error("input slice was changed")
	}
}

func withHome(t *testing.T, h string) {
	t.Helper()
	orig := homeDir
	homeDir = func() string { return h }
	t.Cleanup(func() { homeDir = orig })
}

func TestScrubJSON(t *testing.T) {
	withHome(t, "/Users/alice")
	body, _ := json.Marshal(map[string]any{
		"project_path": "/Users/alice/acme-shop",
		"file":         "/Users/alice/acme-shop/src/a.ts",
		"other":        "/Users/alice/notes/todo.md",
		"home":         "/Users/alice",
		"sibling":      "/Users/alice/acme-shop2/b.ts",
		"longer":       "/Users/alicea/x",
		"text":         "see /Users/alice/acme-shop/src/a.ts:3 and /Users/alice.",
	})
	got := string(ScrubJSON(body, "/Users/alice/acme-shop"))
	var m map[string]string
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("not JSON any more: %v\n%s", err, got)
	}
	want := map[string]string{
		"project_path": ".",
		"file":         "src/a.ts",
		"other":        "~/notes/todo.md",
		"home":         "~",
		"sibling":      "~/acme-shop2/b.ts",
		"longer":       "/Users/alicea/x",
		"text":         "see src/a.ts:3 and ~.",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	if strings.Contains(got, "alice/") {
		t.Errorf("home path left: %s", got)
	}
}

func TestScrubJSONWindowsAndShortDirs(t *testing.T) {
	withHome(t, `C:\Users\alice`)
	body, _ := json.Marshal(map[string]string{"f": `C:\Users\alice\shop\a.ts`, "g": `C:\Users\alice\other\b.ts`})
	var m map[string]string
	if err := json.Unmarshal(ScrubJSON(body, `C:\Users\alice\shop`), &m); err != nil {
		t.Fatal(err)
	}
	if m["f"] != "a.ts" || m["g"] != `~\other\b.ts` {
		t.Errorf("got %+v", m)
	}
	withHome(t, "/")
	in := []byte(`{"a":"/etc/x"}`)
	if got := string(ScrubJSON(in, "/")); got != string(in) {
		t.Errorf("short dirs rewrote the body: %s", got)
	}
}
