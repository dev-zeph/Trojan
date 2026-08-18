package routes

import (
	"os"
	"path/filepath"
	"testing"
)

func classifyFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		content string
		want    Framework
	}{
		{"next before react", "package.json", `{"dependencies":{"react":"18","next":"14"}}`, FrameworkNextjs},
		{"nest before express", "package.json", `{"dependencies":{"@nestjs/core":"10","express":"4"}}`, FrameworkNestjs},
		{"express", "package.json", `{"dependencies":{"express":"4"}}`, FrameworkExpress},
		{"gin", "go.mod", "module x\nrequire github.com/gin-gonic/gin v1.9.0", FrameworkGin},
		{"chi", "go.mod", "module x\nrequire github.com/go-chi/chi/v5 v5.0.0", FrameworkChi},
		{"fastapi", "requirements.txt", "fastapi==0.110\nuvicorn", FrameworkFastAPI},
		{"django", "requirements.txt", "Django==5.0", FrameworkDjango},
		{"flask", "pyproject.toml", "[project]\ndependencies = [\"Flask>=3\"]", FrameworkFlask},
		{"unknown", "package.json", `{"dependencies":{"lodash":"4"}}`, FrameworkUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := classifyFixture(t, tt.file, tt.content)
			if got := Classify(dir); got != tt.want {
				t.Errorf("Classify = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyEmptyDir(t *testing.T) {
	if got := Classify(t.TempDir()); got != FrameworkUnknown {
		t.Errorf("empty project should be unknown, got %q", got)
	}
}
