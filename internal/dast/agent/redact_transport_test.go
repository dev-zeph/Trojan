package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Assembled at runtime; not real credentials.
var (
	agentJWT    = "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0." + "Qw7Er8Ty9Ui0Op1As2Df3Gh4Jk5"
	agentCookie = "Zk9xLm3Qp7Rt2Vw8Yb4Nc6Hj0Ks5TyQe2L"
	agentAWS    = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK"
)

// recordingTransport lets each scripted turn look at what the model was sent
// (so it can hand a descriptor back, as the model would).
type recordingTransport struct {
	mu       sync.Mutex
	received [][]Message
	script   []func(seen string) *TurnResult
}

func (r *recordingTransport) Turn(_ context.Context, msgs []Message) (*TurnResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := make([]Message, len(msgs))
	copy(snap, msgs)
	r.received = append(r.received, snap)
	i := len(r.received) - 1
	if i >= len(r.script) {
		return &TurnResult{StopReason: "end_turn"}, nil
	}
	b, _ := json.Marshal(msgs)
	seen := strings.NewReplacer(`\u003c`, "<", `\u003e`, ">").Replace(string(b))
	return r.script[i](seen), nil
}

var reRef = regexp.MustCompile(`<SECRET(?: removed by Trojan)?: ref=(S\d+), type=jwt[^>]*>`)

func TestAgentWireNeverCarriesRawSecrets(t *testing.T) {
	var echoed sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: agentCookie, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"` + agentJWT + `","debug":"aws ` + agentAWS + `"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		echoed.Store("auth", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"id":42,"echo":"` + r.Header.Get("Authorization") + `"}`))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	var jwtDescriptor string
	tr := &recordingTransport{script: []func(string) *TurnResult{
		func(string) *TurnResult {
			return turn("tool_use", toolUseBlock("t1", toolHTTPProbe, map[string]any{"method": "POST", "url": base + "/login", "body": "{}"}))
		},
		func(seen string) *TurnResult {
			// The model only has the descriptor; it remembers it and replays it.
			jwtDescriptor = reRef.FindString(seen)
			return turn("tool_use",
				thinkingBlock("the login returned "+jwtDescriptor),
				toolUseBlock("t2", toolRememberFact, map[string]any{"kind": "token", "summary": "user JWT", "value": jwtDescriptor, "from": "/login"}),
				toolUseBlock("t3", toolHTTPProbe, map[string]any{"method": "GET", "url": base + "/me", "headers": map[string]string{"Authorization": "Bearer " + jwtDescriptor}}),
			)
		},
		func(string) *TurnResult {
			return turn("tool_use", toolUseBlock("t4", toolFinish, map[string]any{"summary": "done"}))
		},
	}}

	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "test " + base}); err != nil {
		t.Fatal(err)
	}
	if jwtDescriptor == "" {
		t.Fatal("model never saw a JWT descriptor")
	}
	// 1. Nothing raw ever went on the wire, on any turn.
	for i, msgs := range tr.received {
		b, _ := json.Marshal(msgs)
		for _, raw := range []string{agentJWT, agentCookie, agentAWS} {
			if strings.Contains(string(b), raw) {
				t.Fatalf("turn %d carried a raw secret (%.4s…)", i+1, raw)
			}
		}
	}
	// 2. The descriptor was mapped back locally: the probe sent the real token,
	//    and the remembered fact holds the real value.
	if v, _ := echoed.Load("auth"); v != "Bearer "+agentJWT {
		t.Fatalf("probe did not get the restored token: %v", v)
	}
	facts := tb.Facts()
	if len(facts) != 1 || facts[0].Value != agentJWT {
		t.Fatalf("fact not restored locally: %+v", facts)
	}
	// 3. The assistant turn (with its thinking block) is replayed byte-for-byte.
	last := tr.received[len(tr.received)-1]
	var foundThinking bool
	for _, m := range last {
		if m.Role == "assistant" {
			for _, c := range m.Content {
				if strings.Contains(string(c), `"thinking"`) {
					foundThinking = true
					var blk struct{ Thinking string }
					_ = json.Unmarshal(c, &blk)
					if blk.Thinking != "the login returned "+jwtDescriptor {
						t.Fatal("assistant turn altered")
					}
				}
			}
		}
	}
	if !foundThinking {
		t.Fatal("thinking block missing from replay")
	}
}

func TestRedactingTransportIsIdempotentAndStable(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	inner := &fakeTransport{}
	tr := redactingTransport(redactingTransport(inner, tb), tb)
	if _, ok := tr.(*secretRedactingTransport); !ok {
		t.Fatal("not wrapped")
	}
	msgs := []Message{userTextMessage("found " + agentAWS)}
	_, _ = tr.Turn(context.Background(), msgs)
	_, _ = tr.Turn(context.Background(), msgs)
	a, _ := json.Marshal(inner.received[0])
	b, _ := json.Marshal(inner.received[1])
	if string(a) != string(b) || strings.Contains(string(a), agentAWS) {
		t.Fatalf("redaction must be stable across turns and hide the key: %s", a)
	}
	if !strings.Contains(string(msgs[0].Content[0]), agentAWS) {
		t.Fatal("local history must keep the raw value")
	}
}
