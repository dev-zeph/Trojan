package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestHTTPProbeAsIdentity proves the multi-identity mechanic: the same request
// sent "as alice" and "as bob" carries each identity's auth, so the agent can
// compare responses to detect broken object-level authorization (IDOR/BOLA).
func TestHTTPProbeAsIdentity(t *testing.T) {
	// A toy "orders" endpoint that only returns the order to its owner, keyed by
	// the bearer token. Alice owns order 1; Bob owns nothing.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer alice-token":
			_, _ = w.Write([]byte(`{"id":1,"owner":"alice","total":42}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		}
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)
	tb.SetIdentities([]Identity{
		{Name: "alice", Headers: map[string]string{"Authorization": "Bearer alice-token"}},
		{Name: "bob", Headers: map[string]string{"Authorization": "Bearer bob-token"}},
	})

	if got := tb.IdentityNames(); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("IdentityNames = %v, want [alice bob]", got)
	}

	// As alice (owner) -> 200 with her data.
	asAlice, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/api/orders/1", Identity: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if asAlice.Status != 200 || !strings.Contains(asAlice.Body, `"owner":"alice"`) {
		t.Errorf("as alice: got %d %q, want 200 with her order", asAlice.Status, asAlice.Body)
	}

	// As bob (not owner) -> 403. (This app is correctly authorized; a vulnerable
	// one would return alice's data here — that difference is the IDOR signal.)
	asBob, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/api/orders/1", Identity: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if asBob.Status != 403 {
		t.Errorf("as bob: got %d, want 403", asBob.Status)
	}

	// Two probes, two identities, both counted against the request budget.
	if _, reqs, _ := tb.Budget().Stats(); reqs != 2 {
		t.Errorf("expected 2 probe requests, got %d", reqs)
	}
}

func TestHTTPProbeUnknownIdentity(t *testing.T) {
	tb, base := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	tb.SetIdentities([]Identity{{Name: "alice", Headers: map[string]string{"Authorization": "x"}}})

	_, err := tb.HTTPProbe(context.Background(), ProbeRequest{Method: "GET", URL: base + "/", Identity: "mallory"})
	if err == nil || !strings.Contains(err.Error(), "unknown identity") {
		t.Fatalf("expected unknown-identity error, got %v", err)
	}
	// A rejected identity must not spend the request budget.
	if _, reqs, _ := tb.Budget().Stats(); reqs != 0 {
		t.Errorf("unknown identity should cost 0 requests, got %d", reqs)
	}
}

func TestHTTPProbeExplicitHeaderOverridesIdentity(t *testing.T) {
	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") })
	tb, base := newTestbox(t, DefaultLimits(), mux)
	tb.SetIdentities([]Identity{{Name: "alice", Headers: map[string]string{"Authorization": "Bearer alice-token"}}})

	_, err := tb.HTTPProbe(context.Background(), ProbeRequest{
		Method: "GET", URL: base + "/", Identity: "alice",
		Headers: map[string]string{"Authorization": "Bearer override"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer override" {
		t.Errorf("explicit header should override identity; server saw %q", seen)
	}
}
