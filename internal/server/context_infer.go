package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/fingerprint"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// ContextInferer drafts an org context. The real one calls the infer-context
// edge function; tests inject a fake.
type ContextInferer interface {
	Infer(description string, fp fingerprint.Fingerprint, projectID string, existing *orgcontext.OrgContext, accessToken string) (*ai.InferContextResult, error)
}

type realInferer struct{}

func (realInferer) Infer(d string, fp fingerprint.Fingerprint, pid string, ex *orgcontext.OrgContext, tok string) (*ai.InferContextResult, error) {
	return ai.InferContext(d, fp, pid, ex, tok)
}

func (s *Server) inferer() ContextInferer {
	if s.contextInferer != nil {
		return s.contextInferer
	}
	return realInferer{}
}

// session returns the signed-in user's access token and id.
func (s *Server) session() (token, userID string, ok bool) {
	if s.authSession != nil {
		return s.authSession()
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return "", "", false
	}
	return cfg.AccessToken, jwtSubject(cfg.AccessToken), true
}

// jwtSubject reads the "sub" claim without verifying (the backend verifies).
func jwtSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(payload, &c)
	return c.Sub
}

// projectRoot returns the project the request is about: the project_path query
// parameter when given, otherwise the active project.
func (s *Server) projectRoot(r *http.Request) string {
	if p := r.URL.Query().Get("project_path"); p != "" {
		return p
	}
	return s.activeProjectRoot()
}

func projectID(root, userID string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	sum := sha256.Sum256([]byte(abs + "\x00" + userID))
	return hex.EncodeToString(sum[:])
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

type inferRequest struct {
	ProjectPath string `json:"project_path"`
	Description string `json:"description"`
}

// handleContextInfer serves POST /api/context/infer.
//
//	{project_path, description} -> {draft, questions, mismatches, free}
//
// 401 {error:"not_signed_in"}; 402 {error:"out_of_tokens", message, balance}.
func (s *Server) handleContextInfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req inferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	root := req.ProjectPath
	if root == "" {
		root = s.activeProjectRoot()
	}
	if !isDir(root) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "project_path is not a folder"})
		return
	}
	token, userID, ok := s.session()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not_signed_in", "message": "Please sign in to Trojan first."})
		return
	}
	fp, err := fingerprint.Collect(root)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var existing *orgcontext.OrgContext
	if p := orgcontext.Path(root); orgcontext.Exists(p) {
		if c, err := orgcontext.Load(p); err == nil {
			existing = c
		}
	}
	res, err := s.inferer().Infer(req.Description, fp, projectID(root, userID), existing, token)
	if err != nil {
		var tokErr *ai.InsufficientTokensError
		if errors.As(err, &tokErr) {
			writeJSON(w, http.StatusPaymentRequired, map[string]any{
				"error":   "out_of_tokens",
				"message": "You're out of tokens. Add more to keep Trojan learning about your app.",
				"balance": tokErr.Balance,
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "infer_failed", "message": "Trojan couldn't work out what your app does just now. Please try again."})
		return
	}
	if res.Questions == nil {
		res.Questions = []string{}
	}
	if res.Mismatches == nil {
		res.Mismatches = []ai.ContextMismatch{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"draft":      res.Context,
		"questions":  res.Questions,
		"mismatches": res.Mismatches,
		"free":       res.Free,
	})
}

// handleContextChanges serves GET /api/context/changes?project_path=.
func (s *Server) handleContextChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	root := s.projectRoot(r)
	if !isDir(root) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "project_path is not a folder"})
		return
	}
	old, ok := fingerprint.LoadSnapshot(root)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"has_snapshot": false, "changed": false, "changes": fingerprint.Changes{}})
		return
	}
	cur, err := fingerprint.Collect(root)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	c := fingerprint.Diff(old, cur)
	writeJSON(w, http.StatusOK, map[string]any{"has_snapshot": true, "changed": !c.Empty(), "changes": c})
}
