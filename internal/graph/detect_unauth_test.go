package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnauthSensitiveDataDetector mirrors the ashgrove-portal bug: a report
// export router mounted with no auth middleware exposes a financial table to
// the public, while an auth route reading the users table and a public contact
// form writing a non-sensitive table must NOT be flagged.
func TestUnauthSensitiveDataDetector(t *testing.T) {
	src := `const express = require("express");
const app = express();

function requireLogin(req, res, next) { if (req.user) return next(); return res.status(401).end(); }

const reports = express.Router();
reports.get("/revenue.csv", (req, res) => {
  const rows = db.prepare("SELECT c.name, c.contact_email, i.amount, i.bank_ref FROM invoices i JOIN clients c ON c.id = i.client_id").all();
  res.type("text/csv").send(rows);
});

const portal = express.Router();
portal.get("/invoices", (req, res) => {
  const rows = db.prepare("SELECT id, amount FROM invoices").all();
  res.json(rows);
});

// Mounted with NO auth middleware (the bug); the sibling /portal is guarded.
app.use("/admin/reports", reports);
app.use("/portal", requireLogin, portal);

// Auth route: reading users without a session is this route's job.
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT id, email, password_hash FROM users WHERE email = ?").get(email);
  res.json({ ok: true });
});

// Public contact form writing a non-sensitive table: public by design.
app.post("/contact", (req, res) => {
  const { name, body } = req.body;
  db.prepare("INSERT INTO messages (name, body) VALUES (?, ?)").run(name, body);
  res.json({ ok: true });
});
`
	dir := t.TempDir()
	f := filepath.Join(dir, "server.js")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	ds := detectUnauthSensitiveData(g, nil)

	for _, d := range ds {
		if strings.Contains(entryLabel(d.Entry), "login") {
			t.Errorf("auth route must not be flagged: %+v", d)
		}
		if strings.Contains(entryLabel(d.Entry), "contact") {
			t.Errorf("public contact form (non-sensitive write) must not be flagged: %+v", d)
		}
		if strings.Contains(entryLabel(d.Entry), "portal") {
			t.Errorf("guarded route must not be flagged: %+v", d)
		}
	}

	var gotReports bool
	for _, d := range ds {
		if strings.Contains(entryLabel(d.Entry), "/admin/reports/revenue.csv") {
			gotReports = true
			if d.Rule != DetectUnauthSensitiveData {
				t.Errorf("wrong rule: %q", d.Rule)
			}
			if !strings.Contains(d.Store, "invoices") {
				t.Errorf("store should name invoices: %q", d.Store)
			}
			if !strings.HasSuffix(d.Sink.File, "server.js") {
				t.Errorf("finding should be anchored on the route file, got %q", d.Sink.File)
			}
		}
	}
	if !gotReports {
		t.Fatalf("the unauthenticated /admin/reports export was not flagged; got %+v", ds)
	}
}
