package routes

import (
	"sort"
	"strings"
	"testing"
)

func TestExtractExpress(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"express":"4"}}`)
	mkfile(t, dir, "server.js", `
const express = require('express');
const app = express();
const router = express.Router();

app.get('/health', (req, res) => res.send('ok'));
router.get('/:id', getUser);
router.post('/', createUser);
app.use('/api/users', router);
app.all('/webhook', handleHook);
`)

	got := extractExpress(dir)
	var keys []string
	for _, r := range got {
		m := r.Method
		if m == "" {
			m = "ANY"
		}
		keys = append(keys, m+" "+r.PathPattern)
	}
	sort.Strings(keys)
	want := []string{
		"ANY /webhook",
		"GET /api/users/{id}",  // router mounted at /api/users, :id -> {id}
		"GET /health",
		"POST /api/users",      // router POST '/' mounted at /api/users
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("express routes:\n got: %v\nwant: %v", keys, want)
	}

	// Confidence + handler symbol captured.
	for _, r := range got {
		if r.Confidence != 0.7 || r.Source != "static" {
			t.Errorf("expected 0.7/static, got %.2f/%s", r.Confidence, r.Source)
		}
		if r.PathPattern == "/health" && r.HandlerLine == 0 {
			t.Errorf("expected a handler line for /health")
		}
	}
}

func TestExtractExpressResolvesViaResolver(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "package.json", `{"dependencies":{"express":"4"}}`)
	mkfile(t, dir, "app.js", `
const app = express();
app.get('/users/:id', getUser);
`)
	r := NewResolver(dir)
	if r.Framework() != FrameworkExpress {
		t.Fatalf("framework = %q, want express", r.Framework())
	}
	got, ok := r.Resolve("GET", "/users/99")
	if !ok || got.PathPattern != "/users/{id}" {
		t.Errorf("resolve GET /users/99 -> %q (ok=%v), want /users/{id}", got.PathPattern, ok)
	}
}
