package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/dast/agent"
)

// Agentic-DAST server surface (Phase 5 §10). Two concerns live here:
//
//  1. Consent gate (§4, Phase 2) — the pre-run / consent screens call these to
//     mint an ownership token, check verification, and gate scanning of a
//     non-local target. They wrap internal/dast's consent engine.
//  2. Live run stream (§10.2) — the agentic run executes in the CLI process
//     that owns this server (like the one-shot scan does) and broadcasts
//     progress here via BroadcastAgentEvent; the run view subscribes over SSE.
//
// Everything is Pro-gated, matching the rest of the DAST feature.

const agenticBufferCap = 2000 // cap the replay buffer so a long run can't grow unbounded

// AgentEvent is the wire form of one live run event streamed to the UI. It
// mirrors agent.Event plus a run-lifecycle Status for "run" events.
type AgentEvent struct {
	Type   string `json:"type"`             // step|text|tool_use|tool_result|finding|graph|stopped|finish|run
	Step   int    `json:"step,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Detail string `json:"detail,omitempty"`
	Status string `json:"status,omitempty"` // for Type=="run": running|complete|error

	// Structured payload for the two-surface UI (§9): graph deltas, grey-box
	// handler + chips. Optional; set by type. Reuses the agent wire types.
	Node    *agent.GraphNode      `json:"node,omitempty"`
	Edge    *agent.GraphEdge      `json:"edge,omitempty"`
	Source  *agent.HandlerRef     `json:"source,omitempty"`
	Summary *agent.GreyBoxSummary `json:"summary,omitempty"`
	Mode    string                `json:"mode,omitempty"`
}

// ── Live run stream ──────────────────────────────────────────────────────────

// BroadcastAgentEvent records an event in the replay buffer and fans it out to
// every subscribed run-view client. Called by the CLI's agentic loop via the
// OnEvent callback. Safe for concurrent use.
func (s *Server) BroadcastAgentEvent(evt AgentEvent) {
	s.agenticMu.Lock()
	defer s.agenticMu.Unlock()

	if evt.Type == "run" {
		s.agenticStatus = evt.Status
	}
	s.agenticBuffer = append(s.agenticBuffer, evt)
	if len(s.agenticBuffer) > agenticBufferCap {
		// Drop the oldest events; keep the buffer bounded.
		s.agenticBuffer = s.agenticBuffer[len(s.agenticBuffer)-agenticBufferCap:]
	}
	for _, ch := range s.agenticClients {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (s *Server) handleAgenticStatus(w http.ResponseWriter, r *http.Request) {
	s.agenticMu.Lock()
	status := s.agenticStatus
	events := len(s.agenticBuffer)
	s.agenticMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "events": events})
}

// handleAgenticEvents streams run events over SSE. On connect it replays the
// buffer (so a run view that attaches mid-run catches up — the SSE stream has
// no native replay), then tails live events until the run ends or the client
// disconnects.
func (s *Server) handleAgenticEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Register first, then snapshot the buffer, so no event slips through the
	// gap between replay and tail (an event that arrives during replay is also
	// queued on our channel and de-duped by the client on step/index).
	ch := make(chan AgentEvent, 64)
	s.agenticMu.Lock()
	id := s.agenticNextID
	s.agenticNextID++
	s.agenticClients[id] = ch
	replay := make([]AgentEvent, len(s.agenticBuffer))
	copy(replay, s.agenticBuffer)
	s.agenticMu.Unlock()
	defer func() {
		s.agenticMu.Lock()
		delete(s.agenticClients, id)
		s.agenticMu.Unlock()
	}()

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	for _, evt := range replay {
		writeAgentEvent(w, flusher, evt)
	}

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case evt := <-ch:
			writeAgentEvent(w, flusher, evt)
		}
	}
}

func writeAgentEvent(w http.ResponseWriter, flusher http.Flusher, evt AgentEvent) {
	data, _ := json.Marshal(evt)
	fmt.Fprintf(w, "event: agent\ndata: %s\n\n", data)
	flusher.Flush()
}

// ResetAgenticRun clears the stream state for a fresh run. Called by the CLI
// before it starts broadcasting.
func (s *Server) ResetAgenticRun() {
	s.agenticMu.Lock()
	s.agenticBuffer = nil
	s.agenticStatus = "running"
	s.agenticMu.Unlock()
}

// ── Consent gate ─────────────────────────────────────────────────────────────

// currentUser returns the logged-in user's email and Pro status from local
// config. ok is false when not logged in.
func currentUser() (email string, isPro, ok bool) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return "", false, false
	}
	return cfg.UserEmail, cfg.IsPro, true
}

// requirePro writes a 401/403 and returns ("", false) if the caller isn't a
// logged-in Pro user; otherwise returns (email, true).
func requirePro(w http.ResponseWriter) (string, bool) {
	email, isPro, ok := currentUser()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not_logged_in"})
		return "", false
	}
	if !isPro {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pro_required"})
		return "", false
	}
	return email, true
}

func (s *Server) handleConsentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	email, ok := requirePro(w)
	if !ok {
		return
	}
	url := r.URL.Query().Get("url")
	if url == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}
	allowed, isLocal, rec, domain, err := dast.GateStatus(url, email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	resp := map[string]any{
		"allowed":  allowed,
		"isLocal":  isLocal,
		"verified": rec != nil,
		"domain":   domain,
	}
	if rec != nil {
		resp["method"] = string(rec.Method)
		resp["verifiedAt"] = rec.VerifiedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleConsentMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	email, ok := requirePro(w)
	if !ok {
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}
	domain, token, isLocal, err := dast.MintToken(body.URL, email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Hand the UI everything it needs to render the three placement options.
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":        domain,
		"token":         token,
		"isLocal":       isLocal,
		"txtPrefix":     dast.TXTPrefix,
		"wellKnownPath": dast.WellKnownPath,
		"metaName":      dast.MetaName,
	})
}

func (s *Server) handleConsentVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	email, ok := requirePro(w)
	if !ok {
		return
	}
	var body struct {
		URL    string `json:"url"`
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" || body.Method == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url and method required"})
		return
	}
	rec, err := dast.VerifyOwnership(body.URL, dast.VerifyMethod(body.Method), email)
	if err != nil {
		// Verification failure is an expected outcome, not a server error — 200
		// with verified:false so the UI can show the reason and let them retry.
		writeJSON(w, http.StatusOK, map[string]any{"verified": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true,
		"domain":   rec.Domain,
		"method":   string(rec.Method),
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
