package normalizer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodePreviewOrPlaceholder(t *testing.T) {
	got := CodePreviewOrPlaceholder("requires login", "src/config.ts", 2)
	want := "Code preview not available for this finding. See src/config.ts line 2."
	if got != want {
		t.Fatalf("got %q", got)
	}
	if CodePreviewOrPlaceholder("const x = 1", "src/config.ts", 2) != "const x = 1" {
		t.Fatal("real snippet was rewritten")
	}
}

func TestRelToProjectFromParentFolder(t *testing.T) {
	parent := t.TempDir()
	proj := filepath.Join(parent, "leaky-app")
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "src", "config.ts"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := RelToProject(proj, "leaky-app/src/config.ts"); got != "src/config.ts" {
		t.Fatalf("got %q", got)
	}
	if got := RelToProject(proj, "src/config.ts"); got != "src/config.ts" {
		t.Fatalf("already-relative path: %q", got)
	}
	if got := RelToProject(proj, "https://example.com/login"); got != "https://example.com/login" {
		t.Fatalf("URL rewritten: %q", got)
	}
}
