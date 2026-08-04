package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

func newTestServer() *Server {
	return New(&normalizer.ScanResult{}, nil)
}

// writeProConfig points config at a temp HOME with a logged-in Pro user.
func writeProConfig(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if err := config.SaveConfig(&config.TrojanConfig{
		AccessToken: "test-token",
		UserEmail:   "u@example.com",
		IsPro:       true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAgenticStatusReflectsBroadcast(t *testing.T) {
	s := newTestServer()
	s.ResetAgenticRun()
	s.BroadcastAgentEvent(AgentEvent{Type: "step", Step: 1})
	s.BroadcastAgentEvent(AgentEvent{Type: "run", Status: "complete"})

	rec := httptest.NewRecorder()
	s.handleAgenticStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dast/agentic/status", nil))

	var got struct {
		Status string `json:"status"`
		Events int    `json:"events"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "complete" {
		t.Errorf("status = %q, want complete", got.Status)
	}
	if got.Events != 2 {
		t.Errorf("events = %d, want 2", got.Events)
	}
}

func TestAgenticEventsReplayAndLive(t *testing.T) {
	s := newTestServer()
	s.ResetAgenticRun()
	// Buffered before any client connects — must be replayed on connect.
	s.BroadcastAgentEvent(AgentEvent{Type: "step", Step: 1})

	srv := httptest.NewServer(http.HandlerFunc(s.handleAgenticEvents))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The client is registered and the replay has been written by the time the
	// response headers arrive, so a live event now is guaranteed to be tailed.
	s.BroadcastAgentEvent(AgentEvent{Type: "finding", Detail: "Exposed /ftp"})

	var payloads []string
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				payloads = append(payloads, strings.TrimPrefix(line, "data: "))
				if len(payloads) >= 2 {
					close(done)
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out; got %d payloads: %v", len(payloads), payloads)
	}
	if !strings.Contains(payloads[0], `"step":1`) {
		t.Errorf("first payload should be the replayed step: %s", payloads[0])
	}
	if !strings.Contains(payloads[1], "Exposed /ftp") {
		t.Errorf("second payload should be the live finding: %s", payloads[1])
	}
}

func TestConsentEndpointsRequireLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no config → not logged in
	s := newTestServer()

	rec := httptest.NewRecorder()
	s.handleConsentStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dast/consent/status?url=http://localhost:3000", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when not logged in", rec.Code)
	}
}

func TestConsentStatusLocalhostBypass(t *testing.T) {
	writeProConfig(t)
	s := newTestServer()

	// Missing url → 400.
	rec := httptest.NewRecorder()
	s.handleConsentStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dast/consent/status", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing url: status = %d, want 400", rec.Code)
	}

	// localhost target bypasses the ownership gate (no network).
	rec = httptest.NewRecorder()
	s.handleConsentStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dast/consent/status?url=http://localhost:3000", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("localhost status = %d, want 200", rec.Code)
	}
	var got struct {
		Allowed bool `json:"allowed"`
		IsLocal bool `json:"isLocal"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Allowed || !got.IsLocal {
		t.Errorf("localhost should be allowed+local, got %+v", got)
	}
}

func TestConsentMintMethodGuard(t *testing.T) {
	writeProConfig(t)
	s := newTestServer()
	rec := httptest.NewRecorder()
	// GET on a POST-only endpoint.
	s.handleConsentMint(rec, httptest.NewRequest(http.MethodGet, "/api/dast/consent/mint", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
