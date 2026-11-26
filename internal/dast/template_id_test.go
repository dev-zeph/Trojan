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

// R4-P3-1 leftovers: block scalar ids lose their continuation lines, and
// anchors, aliases, explicit keys and indented top levels are rejected.
func TestSetTemplateIDBlockScalarsAndRejections(t *testing.T) {
	rewritten := map[string]string{
		"foldedBlock":   "id: >-\n  alphapets-x\n  more\ninfo: {}\n",
		"literalBlock":  "id: |\n  alphapets-x\n\n  tail\ninfo: {}\n",
		"plainWrapped":  "id: alphapets\n  -x\ninfo: {}\n",
		"emptyThenTab":  "id:\n\talphapets-x\ninfo: {}\n",
		"secondBlockId": "id: a\ninfo: {}\nid: >\n  alphapets-y\nhttp: []\n",
	}
	for name, in := range rewritten {
		out, ok := SetTemplateID(in, 1)
		if !ok {
			t.Errorf("%s: rejected", name)
			continue
		}
		if strings.Contains(out, "alphapets") || strings.Contains(out, "more") || strings.Contains(out, "tail") {
			t.Errorf("%s: old id text left: %q", name, out)
		}
		if ids := topLevelIDs(out); len(ids) != 1 || ids[0] != "id: trojan-custom-001" {
			t.Errorf("%s: ids %q in %q", name, ids, out)
		}
		if !strings.Contains(out, "info: {}") {
			t.Errorf("%s: other keys lost: %q", name, out)
		}
	}
	if out, _ := SetTemplateID("id: >-\n  alphapets-x\ninfo:\n  name: y\n", 2); out != "id: trojan-custom-002\ninfo:\n  name: y\n" {
		t.Errorf("block scalar: %q", out)
	}
	rejected := map[string]string{
		"anchor":               "id: &a alphapets-x\ninfo:\n  name: *a\n",
		"alias":                "base: &a alphapets-x\nid: *a\n",
		"quotedAnchor":         "\"id\" : &site alphapets-x\n",
		"explicitKey":          "? id\n: alphapets-x\ninfo: {}\n",
		"explicitKeyTab":       "info: {}\n?\tid\n: alphapets-x\n",
		"explicitBare":         "?\n  id\n: alphapets-x\n",
		"indentedTop":          "  id: alphapets-x\n  info: {}\n",
		"indentedAfterComment": "# c\n\n    id: alphapets-x\n",
		"indentedAfterMarker":  "---\n  id: alphapets-x\n",
	}
	for name, in := range rejected {
		if out, ok := SetTemplateID(in, 1); ok {
			t.Errorf("%s: accepted: %q", name, out)
		}
		if unsafeTemplate(strings.TrimPrefix(in, "\uFEFF")) == "" {
			t.Errorf("%s: unsafeTemplate gave no reason", name)
		}
	}
}

func TestUnsafeTemplateAllowsNormalTemplates(t *testing.T) {
	for _, ok := range []string{
		"id: x\ninfo:\n  name: y\n  tags: a,b\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/?q=1\"\n",
		"# comment\n---\nid: x\nvariables:\n  a: &anc 1\n  b: *anc\n",
		"info: {name: y}\nid: x\n",
	} {
		if r := unsafeTemplate(ok); r != "" {
			t.Errorf("rejected (%s): %q", r, ok)
		}
	}
}

func TestIsIndented(t *testing.T) {
	cases := map[string]bool{"  x": true, "\tx": true, "x": false, "   ": false, "": false}
	for in, want := range cases {
		if got := isIndented(in); got != want {
			t.Errorf("isIndented(%q) = %v", in, got)
		}
	}
}
