package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// edgeAt points an EdgeTransport at a local httptest server (loopback only;
// no real network, no tokens).
func edgeAt(url string) *EdgeTransport {
	t := NewEdgeTransport("tok-123")
	t.url = url
	return t
}

func TestEdgeTransport_402IsInsufficientTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":"insufficient_tokens"}`))
	}))
	defer srv.Close()

	_, err := edgeAt(srv.URL).Turn(context.Background(), []Message{userTextMessage("seed")})
	if !errors.Is(err, ErrInsufficientTokens) {
		t.Fatalf("402 must map to ErrInsufficientTokens, got %v", err)
	}

	// And the loop surfaces it as a resumable out-of-tokens stop.
	res, err := Run(context.Background(), vibeToolbox(t), edgeAt(srv.URL), "seed", Options{})
	if !errors.Is(err, ErrInsufficientTokens) || res.StopReason != StopInsufficientTokens {
		t.Fatalf("loop: want ErrInsufficientTokens + out-of-tokens stop, got %v / %q", err, res.StopReason)
	}
}

func TestEdgeTransport_WireFormatAndRunID(t *testing.T) {
	var gotAuth string
	var gotRunIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var wrap struct {
			Encoded string `json:"encoded"`
		}
		if err := json.NewDecoder(r.Body).Decode(&wrap); err != nil || wrap.Encoded == "" {
			t.Errorf("body not base64-wrapped: %v", err)
		}
		raw, _ := base64.StdEncoding.DecodeString(wrap.Encoded)
		var inner struct {
			Messages []Message `json:"messages"`
			RunID    string    `json:"runId"`
		}
		_ = json.Unmarshal(raw, &inner)
		gotRunIDs = append(gotRunIDs, inner.RunID)
		_ = json.NewEncoder(w).Encode(TurnResult{StopReason: "end_turn", RunID: "run-abc"})
	}))
	defer srv.Close()

	tr := edgeAt(srv.URL)
	for i := 0; i < 2; i++ {
		if _, err := tr.Turn(context.Background(), []Message{userTextMessage("seed")}); err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	// Turn 1 sends no run id; turn 2 echoes the server-minted one.
	if len(gotRunIDs) != 2 || gotRunIDs[0] != "" || gotRunIDs[1] != "run-abc" {
		t.Fatalf("run ids sent = %v, want [\"\" run-abc]", gotRunIDs)
	}
}

func TestEdgeTransport_StatusMapping(t *testing.T) {
	for code, want := range map[int]error{
		http.StatusUnauthorized:    ErrUnauthorized,
		http.StatusTooManyRequests: ErrRateLimited,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		_, err := edgeAt(srv.URL).Turn(context.Background(), []Message{userTextMessage("s")})
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("status %d: want %v, got %v", code, want, err)
		}
	}
}
