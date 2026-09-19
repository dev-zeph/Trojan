package server

import (
	"encoding/json"
	"net/http"

	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// activeProjectRoot returns the project root the desktop app is currently
// pointed at. It mirrors the mechanism handleLatestScan already uses: the
// most recent scan's ProjectPath is the closest thing the server has to a
// notion of "the active project," so context reads and writes target the
// same directory a scan just ran against.
func (s *Server) activeProjectRoot() string {
	s.scanMu.RLock()
	defer s.scanMu.RUnlock()
	if s.scan == nil {
		return "."
	}
	return s.scan.ProjectPath
}

// contextGetResponse is the GET /api/context response shape.
type contextGetResponse struct {
	Exists  bool                   `json:"exists"`
	Context *orgcontext.OrgContext `json:"context"`
}

// contextPostResponse is the POST /api/context response shape.
type contextPostResponse struct {
	OK   bool   `json:"ok"`
	Path string `json:"path"`
}

// handleContext serves the org-context read/write API the desktop app's
// onboarding and settings screens use.
//
//	GET  /api/context -> { "exists": bool, "context": OrgContext|null }
//	POST /api/context -> body is an OrgContext; saves it and returns
//	                     { "ok": true, "path": <absolute path written> }
func (s *Server) handleContext(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleContextGet(w, r)
	case http.MethodPost:
		s.handleContextPost(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleContextGet(w http.ResponseWriter, r *http.Request) {
	root := s.activeProjectRoot()
	path := orgcontext.Path(root)

	if !orgcontext.Exists(path) {
		writeJSON(w, http.StatusOK, contextGetResponse{Exists: false, Context: nil})
		return
	}

	ctx, err := orgcontext.Load(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, contextGetResponse{Exists: true, Context: ctx})
}

func (s *Server) handleContextPost(w http.ResponseWriter, r *http.Request) {
	var ctx orgcontext.OrgContext
	if err := json.NewDecoder(r.Body).Decode(&ctx); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}

	root := s.activeProjectRoot()
	path, err := orgcontext.Save(root, &ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, contextPostResponse{OK: true, Path: path})
}
