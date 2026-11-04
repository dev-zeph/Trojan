package routes

import (
	"sort"
	"strings"
	"testing"
)

func TestExtractFlask(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "requirements.txt", "Flask==3.0.0\n")
	mkfile(t, dir, "app.py", `
from flask import Flask
from admin import bp

app = Flask(__name__)
app.register_blueprint(bp, url_prefix="/staff")

@app.route("/")
def home():
    pass

@app.route("/login", methods=["GET", "POST"])
def login():
    pass

@app.route("/customer/<int:cid>")
@login_required
def customer(cid):
    pass

@app.route(
    "/import",
    methods=["POST"],
)
@login_required
@limiter.limit("5/minute")
def import_prefs():
    pass

@app.get("/files/<path:p>")
def files(p):
    pass
`)
	mkfile(t, dir, "admin.py", `
from flask import Blueprint
bp = Blueprint("admin", __name__, url_prefix="/admin")

@bp.route("/users/<uid>")
@auth.login_required
def user(uid):
    pass
`)

	if fw := Classify(dir); fw != FrameworkFlask {
		t.Fatalf("Classify = %q, want flask", fw)
	}
	got := NewResolver(dir).Routes()
	byKey := map[string]Route{}
	var keys []string
	for _, r := range got {
		k := r.Method + " " + r.PathPattern
		byKey[k] = r
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{
		"GET /",
		"GET /customer/{cid}",
		"GET /files/{p...}",
		"GET /login",
		"GET /staff/users/{uid}", // register_blueprint prefix overrides the Blueprint's
		"POST /import",           // methods= on a wrapped line
		"POST /login",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("flask routes:\n got: %v\nwant: %v", keys, want)
	}
	if r := byKey["GET /customer/{cid}"]; r.HandlerSymbol != "customer" || r.HandlerFile != "app.py" || r.HandlerLine != 16 ||
		len(r.Guards) != 1 || r.Guards[0] != "login_required" {
		t.Errorf("customer route = %+v", r)
	}
	if r := byKey["POST /import"]; r.HandlerSymbol != "import_prefs" || len(r.Guards) != 2 {
		t.Errorf("import route = %+v", r)
	}
	if r := byKey["GET /staff/users/{uid}"]; r.HandlerFile != "admin.py" || len(r.Guards) != 1 || r.Guards[0] != "auth.login_required" {
		t.Errorf("blueprint route = %+v", r)
	}
	if r := byKey["GET /login"]; len(r.Guards) != 0 {
		t.Errorf("login should have no guards: %+v", r)
	}
	if r, ok := NewResolver(dir).Resolve("GET", "/customer/7"); !ok || r.HandlerSymbol != "customer" {
		t.Errorf("Resolve(/customer/7) = %+v, %v", r, ok)
	}
}

func TestExtractPHP(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "index.php", "<?php echo 'hi';")
	mkfile(t, dir, "admin.php", "<?php echo 'admin';")
	mkfile(t, dir, "api/index.php", "<?php echo '[]';")
	mkfile(t, dir, "vendor/lib/x.php", "<?php // dependency, not a route")

	if fw := Classify(dir); fw != FrameworkPHP {
		t.Fatalf("Classify = %q, want php", fw)
	}
	res := NewResolver(dir)
	for path, wantFile := range map[string]string{
		"/":          "index.php",
		"/admin.php": "admin.php",
		"/api":       "api/index.php",
	} {
		r, ok := res.Resolve("POST", path)
		if !ok || r.HandlerFile != wantFile {
			t.Errorf("Resolve(%s) = %+v, %v; want %s", path, r, ok, wantFile)
		}
	}
	if _, ok := res.Resolve("GET", "/vendor/lib/x.php"); ok {
		t.Error("vendor files must not be routes")
	}
}

func TestClassifyPHP_FrameworkRouterStaysUnknown(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "composer.json", `{"require": {"laravel/framework": "^11.0"}}`)
	mkfile(t, dir, "index.php", "<?php require 'vendor/autoload.php';")
	if fw := Classify(dir); fw != FrameworkUnknown {
		t.Errorf("Classify = %q, want unknown for a Laravel app", fw)
	}
}
