package agent

import (
	"encoding/json"
	"testing"
)

func TestCandidateUnmarshal_SourceLocationIsTolerant(t *testing.T) {
	cases := []struct {
		in   string
		file string
		line int
	}{
		{`{"title":"t","file":"app/api/x/route.ts","line":12}`, "app/api/x/route.ts", 12},
		{`{"title":"t","file":"app/api/x/route.ts","line":"12"}`, "app/api/x/route.ts", 12},
		{`{"title":"t","file":"app/api/x/route.ts:7"}`, "app/api/x/route.ts", 7},
		{`{"title":"t","file":"lib/auth.ts#L3"}`, "lib/auth.ts", 3},
		{`{"title":"t","file":"lib/auth.ts","line":"near the top"}`, "lib/auth.ts", 0},
		{`{"title":"t","line":-4}`, "", 0},
		{`{"title":"t","severity":"high","url":"http://x","evidence":"e","rationale":"r"}`, "", 0},
	}
	for _, c := range cases {
		var got Candidate
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got.Title != "t" || got.File != c.file || got.Line != c.line {
			t.Errorf("%s -> %+v, want file=%q line=%d", c.in, got, c.file, c.line)
		}
	}
	var full Candidate
	json.Unmarshal([]byte(`{"title":"t","severity":"high","url":"http://x","evidence":"e","rationale":"r"}`), &full) //nolint:errcheck
	if full.Severity != "high" || full.URL != "http://x" || full.Evidence != "e" || full.Rationale != "r" {
		t.Errorf("core fields lost: %+v", full)
	}
}

func TestCandidateWithHandler(t *testing.T) {
	h := &HandlerRef{File: "app/api/admin/customers/route.ts", Line: 5}
	if c := (Candidate{Title: "t"}).withHandler(h); c.File != h.File || c.Line != 5 {
		t.Errorf("handler not applied: %+v", c)
	}
	own := Candidate{Title: "t", File: "lib/db.ts", Line: 40}
	if c := own.withHandler(h); c.File != "lib/db.ts" || c.Line != 40 {
		t.Errorf("agent's own location overwritten: %+v", c)
	}
	if c := (Candidate{Title: "t"}).withHandler(nil); c.File != "" {
		t.Errorf("nil handler set a file: %+v", c)
	}
}
