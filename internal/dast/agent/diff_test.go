package agent

import (
	"context"
	"net/http"
	"testing"
)

// cp is a test helper for building a capturedProbe inline.
func cp(id int, method, url, identity string, status int, body string) capturedProbe {
	return capturedProbe{id: id, method: method, url: url, identity: identity, status: status, body: body}
}

func TestDiffIdenticalBodies(t *testing.T) {
	a := cp(1, "GET", "/api/orders/7", "alice", 200, `{"id":7,"total":42}`)
	b := cp(2, "GET", "/api/orders/7", "alice", 200, `{"id":7,"total":42}`)
	d := diffResponses(a, b)
	if d.Signal != SignalIdentical {
		t.Fatalf("want identical, got %q", d.Signal)
	}
	if d.Similarity != 1 || d.StatusChanged {
		t.Errorf("identical should be similarity=1, no status change; got sim=%v changed=%v", d.Similarity, d.StatusChanged)
	}
}

func TestDiffPossibleBOLA(t *testing.T) {
	// Same request, two DIFFERENT identities, identical successful body → the
	// second identity read the first one's resource. The headline IDOR/BOLA case.
	a := cp(1, "GET", "/api/orders/7", "alice", 200, `{"id":7,"owner":"alice","total":42}`)
	b := cp(2, "GET", "/api/orders/7", "bob", 200, `{"id":7,"owner":"alice","total":42}`)
	d := diffResponses(a, b)
	if d.Signal != SignalPossibleBOLA {
		t.Fatalf("want possible_bola, got %q (note=%q)", d.Signal, d.Note)
	}
}

func TestDiffAuthzEnforced(t *testing.T) {
	a := cp(1, "GET", "/api/orders/7", "alice", 200, `{"id":7}`)
	b := cp(2, "GET", "/api/orders/7", "bob", 403, `{"error":"forbidden"}`)
	d := diffResponses(a, b)
	if d.Signal != SignalAuthzEnforced {
		t.Fatalf("want authz_enforced, got %q", d.Signal)
	}
	if !d.StatusChanged {
		t.Error("status change should be flagged")
	}
}

func TestDiffDivergentWithFieldDiffs(t *testing.T) {
	// Each identity sees its own record — expected, divergent. But the structural
	// diff must still name exactly which fields differ.
	a := cp(1, "GET", "/api/me", "alice", 200, `{"id":1,"email":"alice@x.com","role":"user"}`)
	b := cp(2, "GET", "/api/me", "bob", 200, `{"id":2,"email":"bob@x.com","role":"admin","team":"ops"}`)
	d := diffResponses(a, b)
	if d.Signal != SignalDivergent {
		t.Fatalf("want divergent, got %q", d.Signal)
	}
	if !d.JSON {
		t.Fatal("both bodies are JSON; JSON flag should be set")
	}
	changes := map[string]FieldDiff{}
	for _, fd := range d.FieldDiffs {
		changes[fd.Path] = fd
	}
	if changes["email"].Change != "changed" {
		t.Errorf("email should be changed, got %+v", changes["email"])
	}
	if changes["role"].Change != "changed" {
		t.Errorf("role should be changed, got %+v", changes["role"])
	}
	if changes["team"].Change != "added" {
		t.Errorf("team should be added (only in B), got %+v", changes["team"])
	}
}

func TestDiffNonJSONFallback(t *testing.T) {
	a := cp(1, "GET", "/page", "", 200, "line one\nline two\nline three")
	b := cp(2, "GET", "/page", "", 200, "line one\nline two\nline four")
	d := diffResponses(a, b)
	if d.JSON {
		t.Error("non-JSON bodies should not set JSON flag")
	}
	if d.Similarity <= 0 || d.Similarity >= 1 {
		t.Errorf("expected partial similarity, got %v", d.Similarity)
	}
}

func TestDiffFieldCap(t *testing.T) {
	// Build two large objects that differ in every key past the cap.
	build := func(offset int) map[string]any {
		m := map[string]any{}
		for i := range maxFieldDiffs + 20 {
			m[itoa(i)] = i + offset
		}
		return m
	}
	acc, trunc := jsonDiff("", build(0), build(1), nil)
	if !trunc {
		t.Error("expected truncation when diffs exceed the cap")
	}
	if len(acc) > maxFieldDiffs {
		t.Errorf("diffs should be capped at %d, got %d", maxFieldDiffs, len(acc))
	}
}

// itoa avoids importing strconv just for the test helper above.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ── toolbox integration: capture + diff by id ──

func TestDiffResponsesByID(t *testing.T) {
	mux := http.NewServeMux()
	// Broken object-level auth: returns alice's record regardless of caller.
	mux.HandleFunc("/api/orders/7", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"owner":"alice","total":42}`))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)
	tb.SetIdentities([]Identity{
		{Name: "alice", Headers: map[string]string{"Authorization": "Bearer alice"}},
		{Name: "bob", Headers: map[string]string{"Authorization": "Bearer bob"}},
	})

	ra, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/api/orders/7", Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	rb, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/api/orders/7", Identity: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if ra.ProbeID == 0 || rb.ProbeID == 0 || ra.ProbeID == rb.ProbeID {
		t.Fatalf("probes should get distinct nonzero ids: %d, %d", ra.ProbeID, rb.ProbeID)
	}

	d, err := tb.DiffResponses(ra.ProbeID, rb.ProbeID)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if d.Signal != SignalPossibleBOLA {
		t.Errorf("bob reading alice's order should read as possible_bola, got %q", d.Signal)
	}
	if d.A.Identity != "alice" || d.B.Identity != "bob" {
		t.Errorf("diff should record the identities: %+v / %+v", d.A, d.B)
	}
}

func TestDiffResponsesErrors(t *testing.T) {
	tb, base := newTestbox(t, DefaultLimits(), http.NewServeMux())
	r, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.DiffResponses(r.ProbeID, r.ProbeID); err == nil {
		t.Error("diffing a probe against itself should error")
	}
	if _, err := tb.DiffResponses(r.ProbeID, 9999); err == nil {
		t.Error("diffing against a missing id should error")
	}
}

func TestProbeCaptureEviction(t *testing.T) {
	tb, base := newTestbox(t, DefaultLimits(), http.NewServeMux())
	var firstID int
	for i := range maxRetainedProbes + 5 {
		r, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstID = r.ProbeID
		}
	}
	// The oldest capture must have been evicted; referencing it is a clean error.
	if _, err := tb.DiffResponses(firstID, tb.probeSeq); err == nil {
		t.Errorf("probe #%d should have been evicted after %d newer captures", firstID, maxRetainedProbes)
	}
}
