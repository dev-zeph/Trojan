package intel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pkgSet renders packages as sorted "name@version[*]" strings, * = direct.
func pkgSet(pkgs []Package) []string {
	var out []string
	for _, p := range pkgs {
		s := p.Name + "@" + p.Version
		if p.Direct {
			s += "*"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestParseLockfiles(t *testing.T) {
	tests := []struct {
		file string
		eco  string
		want []string
	}{
		{"npm-v3/package-lock.json", EcosystemNPM, []string{
			"@scope/util@2.3.1*", "next@14.1.0*", "react@18.2.0*", "react@18.3.0-canary-1*",
			"semver@5.7.1", "semver@7.5.4", "strip-ansi@6.0.1*", "typescript@5.3.3*",
		}},
		{"npm-v1/package-lock.json", EcosystemNPM, []string{
			"left-pad@1.3.0*", "lodash@3.10.1", "lodash@4.17.15*", "minimist@1.2.0",
		}},
		{"pnpm-v5/pnpm-lock.yaml", EcosystemNPM, []string{
			"@babel/core@7.12.3*", "axios@0.21.1*", "follow-redirects@1.14.0",
		}},
		{"pnpm-v6/pnpm-lock.yaml", EcosystemNPM, []string{
			"@types/node@20.11.5*", "loose-envify@1.4.0", "next@14.1.0*", "react@18.2.0*",
			"semver@6.3.1", "semver@7.5.4",
		}},
		{"pnpm-v9/pnpm-lock.yaml", EcosystemNPM, []string{
			"@remix-run/node@2.5.0*", "@types/node@20.11.5", "body-parser@1.20.1",
			"express@4.18.2*", "typescript@5.3.3", "vitest@1.2.0*",
		}},
		{"yarn-v1/yarn.lock", EcosystemNPM, []string{
			"@babel/core@7.12.3*", "chalk@4.1.2*", "lodash@3.10.1", "lodash@4.17.20*",
		}},
		{"yarn-berry/yarn.lock", EcosystemNPM, []string{
			"@types/node@20.11.5", "lodash@4.17.21*", "resolve@1.22.8*",
		}},
		{"bun/bun.lock", EcosystemNPM, []string{
			"@types/bun@1.1.0*", "@types/node@20.12.7", "bun-types@1.1.0", "hono@4.0.5*",
		}},
		{"poetry/poetry.lock", EcosystemPyPI, []string{
			"asgiref@3.7.2", "django@4.2.7*", "pytest@7.4.3*", "requests@2.31.0*", "zope-interface@6.1",
		}},
		{"uv/uv.lock", EcosystemPyPI, []string{
			"fastapi@0.110.0*", "jinja2@3.1.2*", "pydantic@2.6.0b1", "ruff@0.4.1*", "starlette@0.36.3",
		}},
		{"pipenv/Pipfile.lock", EcosystemPyPI, []string{
			"black@23.1.0*", "flask@2.0.1*", "pyyaml@5.3*", "werkzeug@2.0.2",
		}},
		{"requirements/requirements.txt", EcosystemPyPI, []string{
			"flask@2.0.1*", "jinja2@3.0.1", "pillow@9.0.0*", "requests@2.25.1*", "urllib3@1.26.4",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			pkgs, err := ParseLockfile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got := pkgSet(pkgs)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("got  %v\nwant %v", got, tt.want)
			}
			for _, p := range pkgs {
				if p.Ecosystem != tt.eco {
					t.Errorf("%s: ecosystem %q, want %q", p.Name, p.Ecosystem, tt.eco)
				}
				if p.Lockfile != filepath.Base(tt.file) {
					t.Errorf("%s: lockfile %q", p.Name, p.Lockfile)
				}
			}
		})
	}
}

func TestParseProjectWalk(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "flask==2.0.1\n")
	write("apps/api/requirements.txt", "flask==2.0.1\nDjango==4.2.7\n")
	write("apps/api/requirements-dev.txt", "pytest==7.0.0\n")
	write("node_modules/x/requirements.txt", "evil==1.0.0\n")
	write(".venv/lib/requirements.txt", "evil==1.0.0\n")
	write(".trojan/requirements.txt", "evil==1.0.0\n")
	write("dist/requirements.txt", "evil==1.0.0\n")
	write("a/b/c/d/e/requirements.txt", "deep-ok==1.0.0\n")      // depth 5 dir
	write("a/b/c/d/e/f/g/requirements.txt", "too-deep==1.0.0\n") // depth 7 dir
	write("broken/package-lock.json", "{not json")

	pkgs, files, warnings, err := ParseProjectWithWarnings(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(pkgSet(pkgs), " ")
	want := "deep-ok@1.0.0* django@4.2.7* flask@2.0.1* pytest@7.0.0*"
	if got != want {
		t.Errorf("packages = %s, want %s", got, want)
	}
	wantFiles := "a/b/c/d/e/requirements.txt apps/api/requirements-dev.txt apps/api/requirements.txt requirements.txt"
	if strings.Join(files, " ") != wantFiles {
		t.Errorf("lockfiles = %v", files)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "broken/package-lock.json") {
		t.Errorf("warnings = %v", warnings)
	}
	for _, p := range pkgs {
		if p.Name == "flask" && strings.Join(p.Lockfiles, ",") != "apps/api/requirements.txt,requirements.txt" {
			t.Errorf("flask lockfiles = %v", p.Lockfiles)
		}
	}
}

func TestParseProjectErrors(t *testing.T) {
	if _, _, err := ParseProject(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing dir: want error")
	}
	if _, err := ParseLockfile("testdata/npm-v3/package.json"); err == nil {
		t.Error("package.json is not a lockfile: want error")
	}
	pkgs, files, err := ParseProject(t.TempDir())
	if err != nil || len(pkgs) != 0 || len(files) != 0 {
		t.Errorf("empty dir: %v %v %v", pkgs, files, err)
	}
}

func TestDedupeKeepsDistinctVersions(t *testing.T) {
	in := []Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0", Lockfile: "x"},
		{Ecosystem: "npm", Name: "a", Version: "1.0.0", Lockfile: "y", Direct: true},
		{Ecosystem: "npm", Name: "a", Version: "2.0.0", Lockfile: "x"},
	}
	out := Dedupe(in)
	if len(out) != 2 || !out[0].Direct || len(out[0].Lockfiles) != 2 || out[0].Lockfile != "x" {
		t.Errorf("dedupe = %+v", out)
	}
}

func TestNormalizePyPIName(t *testing.T) {
	for in, want := range map[string]string{
		"Django": "django", "Zope.Interface": "zope-interface", "foo__bar-.baz": "foo-bar-baz", "PyYAML": "pyyaml",
	} {
		if got := NormalizePyPIName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
