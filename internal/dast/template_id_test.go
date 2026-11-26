package dast

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var onlyCustomID = regexp.MustCompile(`(?m)^id: trojan-custom-\d{3}$`)

// topLevelIDs returns every top-level id line, in any of the spellings nuclei
// (YAML) accepts.
func topLevelIDs(t string) []string {
	return regexp.MustCompile(`(?m)^\x{FEFF}?(?:"id"|'id'|id)[ \t]*:.*$`).FindAllString(t, -1)
}

func TestSetTemplateID(t *testing.T) {
	in := "id: alphapets-loyalty-api-idor\n\ninfo:\n  name: Alpha Pets loyalty API\n  metadata:\n    id: keep-nested\nhttp:\n  - method: GET\n"
	got, ok := SetTemplateID(in, 7)
	if !ok || !strings.HasPrefix(got, "id: trojan-custom-007\n") {
		t.Fatalf("id not rewritten: %q", got)
	}
	if strings.Contains(got, "alphapets") {
		t.Errorf("site name left in id: %q", got)
	}
	if !strings.Contains(got, "    id: keep-nested") {
		t.Errorf("nested id changed: %q", got)
	}
	if got, _ := SetTemplateID("info:\n  name: x\n", 12); got != "id: trojan-custom-012\ninfo:\n  name: x\n" {
		t.Errorf("missing id not added: %q", got)
	}
	if got, _ := SetTemplateID("# c\nid: \"quoted-id\"\ninfo: {}\n", 1); got != "# c\nid: trojan-custom-001\ninfo: {}\n" {
		t.Errorf("quoted value: %q", got)
	}
}

// The UX Lead's round 3 edge cases (R3-P3-1): every spelling of the key is
// replaced, a BOM is dropped, and flow-style templates are rejected.
func TestSetTemplateIDEdgeCases(t *testing.T) {
	cases := map[string]string{
		"quotedKey":        "\"id\": alphapets-x\ninfo: {}\n",
		"singleQuotedKey":  "'id': alphapets-x\ninfo: {}\n",
		"spaceBeforeColon": "id : alphapets-x\ninfo: {}\n",
		"tabBeforeColon":   "id\t: alphapets-x\ninfo: {}\n",
		"bom":              "\uFEFFid: alphapets-x\ninfo: {}\n",
		"bomQuoted":        "\uFEFF\"id\" : alphapets-x\ninfo: {}\n",
		"lastLineNoNL":     "info: {}\nid: alphapets-x",
		"crlf":             "id: alphapets-x\r\ninfo: {}\r\n",
		"duplicateIDs":     "id: alphapets-x\ninfo: {}\nid: alphapets-y\n",
		"docMarker":        "---\nid: alphapets-x\ninfo: {}\n",
	}
	for name, in := range cases {
		out, ok := SetTemplateID(in, 3)
		if !ok {
			t.Errorf("%s: rejected", name)
			continue
		}
		if strings.Contains(out, "alphapets") {
			t.Errorf("%s: site id still present: %q", name, out)
		}
		ids := topLevelIDs(out)
		if len(ids) != 1 || ids[0] != "id: trojan-custom-003" {
			t.Errorf("%s: top-level ids %q in %q", name, ids, out)
		}
		if strings.HasPrefix(out, "\uFEFF") {
			t.Errorf("%s: BOM kept", name)
		}
	}
	for _, flow := range []string{"--- {id: alphapets-x}", "---\t{id: alphapets-x, info: {}}\n", "# c\n--- {id: alphapets-x}\n", "{id: alphapets-x}", "# c\n{id: alphapets-x, info: {name: y}}\n", "  {\"id\": \"alphapets-x\"}"} {
		if out, ok := SetTemplateID(flow, 1); ok {
			t.Errorf("flow-style template accepted: %q -> %q", flow, out)
		}
	}
}

func TestIsFlowStyleTemplate(t *testing.T) {
	cases := map[string]bool{
		"{id: x}":                   true,
		"\n# comment\n---\n{id: x}": true,
		"id: x\ninfo: {name: y}\n":  false,
		"--- {id: x}":               true,
		"--- # doc\nid: x\n":        false,
		"---\nid: x\n":              false,
		"":                          false,
	}
	for in, want := range cases {
		if got := isFlowStyleTemplate(in); got != want {
			t.Errorf("isFlowStyleTemplate(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWriteTemplatesToDirRewritesIDs(t *testing.T) {
	dir := t.TempDir()
	resp := &TemplateResponse{Templates: []string{"id: acme-a\ninfo: {}\n", "{id: acme-flow}", "\"id\": acme-b\ninfo: {}\n"}}
	if err := WriteTemplatesToDir(resp, dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if len(files) != 2 {
		t.Fatalf("want 2 templates written (flow-style skipped), got %v", files)
	}
	for i, f := range []string{"template_000.yaml", "template_001.yaml"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		ids := onlyCustomID.FindAllString(string(b), -1)
		if len(ids) != 1 || ids[0] != []string{"id: trojan-custom-001", "id: trojan-custom-002"}[i] || strings.Contains(string(b), "acme") {
			t.Errorf("%s: %q", f, b)
		}
	}
}
