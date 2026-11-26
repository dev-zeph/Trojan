package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Tool results can quote absolute paths. The turn sent to the edge function
// (and the model behind it) has the home folder replaced with ~.
func TestTurnScrubsHomeFolder(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	t.Setenv("HOME", home)
	var inner string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Encoded string }
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		b, _ := base64.StdEncoding.DecodeString(body.Encoded)
		inner = string(b)
		w.Write([]byte(`{"content":[],"stop_reason":"end_turn"}`)) //nolint:errcheck
	}))
	defer stub.Close()
	tr := &EdgeTransport{accessToken: "tok", url: stub.URL, client: stub.Client()}
	text, _ := json.Marshal(map[string]string{"type": "text", "text": "handler at " + filepath.Join(home, "shop", "api", "h.go") + ":12"})
	tr.Turn(context.Background(), []Message{{Role: "user", Content: []json.RawMessage{text}}}) //nolint:errcheck
	if inner == "" || strings.Contains(inner, home) || !strings.Contains(inner, "~/shop/api/h.go:12") {
		t.Fatalf("turn body: %s", inner)
	}
}
