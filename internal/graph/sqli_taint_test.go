package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// sinkRulesInFile returns the sink rules present on a built file, keyed by the
// 1-based line of the sink.
func sinkRulesByLine(t *testing.T, src string) map[int]string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "api.js")
	if err := os.WriteFile(f, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := BuildFromFiles([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]string{}
	for _, n := range g.Nodes {
		if n.Kind == KindSink && (n.SinkRule == RuleSQLFromInput || n.SinkRule == RuleSQLConcat) {
			out[n.Line] = n.SinkRule
		}
	}
	return out
}

// TestSQLiPlaceholderJoinIsSafe mirrors ashgrove-portal routes/api.js:59: a
// WHERE ... IN (${marks}) where marks is a ?-placeholder list joined from a
// request-derived array, with the real values bound through .all(...ids). This
// is parameterized and must NOT be reported as request-input SQL injection.
func TestSQLiPlaceholderJoinIsSafe(t *testing.T) {
	src := "const express = require(\"express\");\n" +
		"const router = express.Router();\n" +
		"router.post(\"/export\", (req, res) => {\n" +
		"  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(Number).filter(Number.isInteger);\n" +
		"  const marks = ids.map(() => \"?\").join(\",\");\n" +
		"  const rows = db.prepare(`SELECT number FROM invoices WHERE id IN (${marks})`).all(...ids);\n" +
		"  res.json(rows);\n" +
		"});\n"
	rules := sinkRulesByLine(t, src)
	for line, rule := range rules {
		if rule == RuleSQLFromInput {
			t.Errorf("line %d: placeholder-join IN clause flagged as request-input SQLi (false positive)", line)
		}
	}
}

// TestSQLiOperatorInterpolationIsInjection mirrors ashgrove-portal
// routes/api.js:30: a request-query key is split into an operator, and
// OPERATORS[op] || op concatenates the raw attacker string into a WHERE clause
// that is pushed onto an array, join()ed, and interpolated into the query. This
// is a real injection and MUST be reported as request-input SQL injection.
func TestSQLiOperatorInterpolationIsInjection(t *testing.T) {
	src := "const express = require(\"express\");\n" +
		"const router = express.Router();\n" +
		"const OPERATORS = { eq: \"=\", gt: \">\" };\n" +
		"const FILTERABLE = [\"status\", \"budget\"];\n" +
		"router.get(\"/engagements\", (req, res) => {\n" +
		"  const clauses = [];\n" +
		"  const params = [];\n" +
		"  for (const [key, value] of Object.entries(req.query)) {\n" +
		"    const [column, op = \"eq\"] = key.split(\":\");\n" +
		"    if (!FILTERABLE.includes(column)) continue;\n" +
		"    clauses.push(`${column} ${OPERATORS[op] || op} ?`);\n" +
		"    params.push(String(value));\n" +
		"  }\n" +
		"  const where = clauses.length ? `WHERE ${clauses.join(\" AND \")}` : \"\";\n" +
		"  const rows = db.prepare(`SELECT id FROM engagements ${where}`).all(...params);\n" +
		"  res.json(rows);\n" +
		"});\n"
	rules := sinkRulesByLine(t, src)
	var found bool
	for _, rule := range rules {
		if rule == RuleSQLFromInput {
			found = true
		}
	}
	if !found {
		t.Errorf("the OPERATORS[op] || op injection was not flagged as request-input SQLi; sinks=%v", rules)
	}
}

// TestRequestTainted_PlaceholderJoinNotTainted is a unit check on the taint
// engine: a ?-placeholder join is not tainted, while a for-of over the request
// and a push of the resulting value are.
func TestRequestTainted_Flows(t *testing.T) {
	body := `
  const ids = req.body.ids.map(Number);
  const marks = ids.map(() => "?").join(",");
  for (const [key, value] of Object.entries(req.query)) {
    const [column, op = "eq"] = key.split(":");
    clauses.push(` + "`${OPERATORS[op] || op}`" + `);
  }
  const where = ` + "`WHERE ${clauses.join(\" AND \")}`" + `;
`
	tainted := requestTainted(body)
	if tainted["marks"] {
		t.Error("marks (a ?-placeholder join) must not be tainted")
	}
	for _, want := range []string{"ids", "key", "value", "op", "column", "clauses", "where"} {
		if !tainted[want] {
			t.Errorf("%q should be request-tainted; tainted=%v", want, tainted)
		}
	}
}
