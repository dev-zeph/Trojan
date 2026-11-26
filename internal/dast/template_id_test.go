package dast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetTemplateID(t *testing.T) {
	in := "id: alphapets-loyalty-api-idor\n\ninfo:\n  name: Alpha Pets loyalty API\n  metadata:\n    id: keep-nested\nhttp:\n  - method: GET\n"
	got := SetTemplateID(in, 7)
	if !strings.HasPrefix(got, "id: trojan-custom-007\n") {
		t.Fatalf("id not rewritten: %q", got)
	}
	if strings.Contains(got, "alphapets") {
		t.Errorf("site name left in id: %q", got)
	}
	if !strings.Contains(got, "    id: keep-nested") {
		t.Errorf("nested id changed: %q", got)
	}
	if got := SetTemplateID("info:\n  name: x\n", 12); !strings.HasPrefix(got, "id: trojan-custom-012\ninfo:") {
		t.Errorf("missing id not added: %q", got)
	}
	if got := SetTemplateID("# c\nid: \"quoted-id\"\ninfo: {}\n", 1); got != "# c\nid: trojan-custom-001\ninfo: {}\n" {
		t.Errorf("quoted id: %q", got)
	}
}

func TestWriteTemplatesToDirRewritesIDs(t *testing.T) {
	dir := t.TempDir()
	resp := &TemplateResponse{Templates: []string{"id: acme-a\ninfo: {}\n", "id: acme-b\ninfo: {}\n"}}
	if err := WriteTemplatesToDir(resp, dir); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"id: trojan-custom-001", "id: trojan-custom-002"} {
		b, err := os.ReadFile(filepath.Join(dir, "template_00"+string(rune('0'+i))+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(b), want+"\n") {
			t.Errorf("template %d: %q", i, b)
		}
	}
}
