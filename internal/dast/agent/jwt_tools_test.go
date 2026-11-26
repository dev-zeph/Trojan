package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var reForgedRef = regexp.MustCompile(`<SECRET: ref=(S\d+), type=jwt_forged[^>]*>`)

// jwtClaims decodes the payload of a compact JWT (test helper).
func jwtClaims(t *testing.T, tok string) (map[string]any, string) {
	t.Helper()
	tok = strings.TrimPrefix(tok, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		t.Fatalf("not a jwt: %q", tok)
	}
	pb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(pb, &m); err != nil {
		t.Fatalf("payload not json: %v", err)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	var hm map[string]any
	_ = json.Unmarshal(hb, &hm)
	alg, _ := hm["alg"].(string)
	return m, alg
}

// TestJWTMutateForgedTokenNeverOnWire is the headline guarantee: the pen-test
// agent can forge a privilege-escalated token and replay it against the target,
// yet neither the original nor the forged token ever appears in an AI request.
func TestJWTMutateForgedTokenNeverOnWire(t *testing.T) {
	var echoed sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"` + agentJWT + `"}`))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		echoed.Store("auth", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	tb, base := newTestbox(t, DefaultLimits(), mux)

	var jwtLabel, forgedLabel string
	tr := &recordingTransport{script: []func(string) *TurnResult{
		func(string) *TurnResult {
			return turn("tool_use", toolUseBlock("t1", toolHTTPProbe, map[string]any{"method": "POST", "url": base + "/login", "body": "{}"}))
		},
		func(seen string) *TurnResult {
			jwtLabel = reRef.FindString(seen) // <SECRET: ref=S1, type=jwt …>
			return turn("tool_use", toolUseBlock("t2", toolJWTMutate, map[string]any{
				"ref":        jwtLabel,
				"set_alg":    "none",
				"set_claims": map[string]any{"role": "admin"},
			}))
		},
		func(seen string) *TurnResult {
			forgedLabel = reForgedRef.FindString(seen)
			return turn("tool_use", toolUseBlock("t3", toolHTTPProbe, map[string]any{
				"method":  "GET",
				"url":     base + "/admin",
				"headers": map[string]string{"Authorization": "Bearer " + forgedLabel},
			}))
		},
		func(string) *TurnResult {
			return turn("tool_use", toolUseBlock("t4", toolFinish, map[string]any{"summary": "done"}))
		},
	}}

	if _, err := Run(context.Background(), tb, tr, RunOptions{Task: "forge " + base}); err != nil {
		t.Fatal(err)
	}
	if jwtLabel == "" || forgedLabel == "" {
		t.Fatalf("model never saw both labels: orig=%q forged=%q", jwtLabel, forgedLabel)
	}

	// The /admin endpoint received the forged token with alg=none and role=admin.
	v, _ := echoed.Load("auth")
	auth, _ := v.(string)
	claims, alg := jwtClaims(t, auth)
	if alg != "none" {
		t.Fatalf("forged token alg=%q, want none", alg)
	}
	if claims["role"] != "admin" {
		t.Fatalf("forged token role=%v, want admin", claims["role"])
	}
	forged := strings.TrimPrefix(auth, "Bearer ")

	// Nothing raw — original or forged — ever went to the model.
	for i, msgs := range tr.received {
		b, _ := json.Marshal(msgs)
		s := string(b)
		for name, raw := range map[string]string{"original JWT": agentJWT, "forged token": forged} {
			if raw != "" && strings.Contains(s, raw) {
				t.Fatalf("turn %d leaked the %s to the model", i+1, name)
			}
		}
	}
}

func TestJWTMutateUnknownRefErrorsCleanly(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	out, isErr := tb.JWTMutate(json.RawMessage(`{"ref":"S999","set_alg":"none"}`))
	if !isErr {
		t.Fatal("unknown ref should be an error")
	}
	if !strings.Contains(out, "unknown ref") {
		t.Fatalf("error should name the unknown ref: %q", out)
	}
	// And it must not panic or leak anything.
	out2, isErr2 := tb.JWTMutate(json.RawMessage(`{"ref":"not-a-ref"}`))
	if !isErr2 || !strings.Contains(out2, "ref") {
		t.Fatalf("bad ref should error: %q", out2)
	}
}

func TestJWTMutateBadInput(t *testing.T) {
	tb, _ := newTestbox(t, DefaultLimits(), http.NotFoundHandler())
	if _, isErr := tb.JWTMutate(json.RawMessage(`{"ref":`)); !isErr {
		t.Fatal("malformed JSON should error")
	}
}
