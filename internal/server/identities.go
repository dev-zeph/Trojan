package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// identitiesDoc is the on-disk shape of <site>/identities.json and the PUT body.
type identitiesDoc struct {
	Identities []agent.Identity `json:"identities"`
}

// wireIdentity is the redacted GET shape: secret field values are blanked and a
// secret_set flag tells the UI a secret is stored without echoing it.
type wireIdentity struct {
	Name    string            `json:"name"`
	Login   *wireLogin        `json:"login,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type wireLogin struct {
	URL       string            `json:"url"`
	Method    string            `json:"method,omitempty"`
	Fields    map[string]string `json:"fields"`
	SecretSet bool              `json:"secret_set"`
}

// handleIdentities reads/writes the test logins used for authenticated DAST of a
// target, keyed by the target URL. GET redacts secrets; PUT saves them 0600 and
// local-only, preserving a stored secret when the client sends that field empty
// (so re-saving without retyping the password is safe).
//
// GET  /api/dast/identities?url=<target>
// PUT  /api/dast/identities?url=<target>   body: {"identities":[...]}
func (s *Server) handleIdentities(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("url"))
	if target == "" {
		http.Error(w, "missing url query parameter", http.StatusBadRequest)
		return
	}
	siteDir, err := normalizer.WebsiteDir(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	path := filepath.Join(siteDir, "identities.json")

	switch r.Method {
	case http.MethodGet:
		writeIdentitiesJSON(w, redactIdentities(loadIdentitiesDoc(path)))
	case http.MethodPut, http.MethodPost:
		var incoming identitiesDoc
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		merged := mergeIdentitySecrets(incoming, loadIdentitiesDoc(path))
		if err := os.MkdirAll(siteDir, 0700); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, _ := json.MarshalIndent(merged, "", "  ")
		if err := os.WriteFile(path, data, 0600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeIdentitiesJSON(w, redactIdentities(merged))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func loadIdentitiesDoc(path string) identitiesDoc {
	var doc identitiesDoc
	data, err := os.ReadFile(path)
	if err != nil {
		return doc
	}
	_ = json.Unmarshal(data, &doc)
	return doc
}

// isSecretKey reports whether a field/header name holds a secret that must be
// redacted on read and preserved on an empty-on-save.
func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"pass", "pwd", "secret", "token", "cookie", "authorization"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func redactIdentities(doc identitiesDoc) map[string]any {
	out := make([]wireIdentity, 0, len(doc.Identities))
	for _, id := range doc.Identities {
		wi := wireIdentity{Name: id.Name}
		if id.Login != nil {
			wl := &wireLogin{URL: id.Login.URL, Method: id.Login.Method, Fields: map[string]string{}}
			for k, v := range id.Login.Fields {
				if isSecretKey(k) {
					if strings.TrimSpace(v) != "" {
						wl.SecretSet = true
					}
					wl.Fields[k] = ""
				} else {
					wl.Fields[k] = v
				}
			}
			wi.Login = wl
		}
		if len(id.Headers) > 0 {
			wi.Headers = map[string]string{}
			for k, v := range id.Headers {
				if isSecretKey(k) {
					if strings.TrimSpace(v) != "" {
						wi.Headers[k] = ""
					}
				} else {
					wi.Headers[k] = v
				}
			}
		}
		out = append(out, wi)
	}
	return map[string]any{"identities": out}
}

// mergeIdentitySecrets keeps a stored secret when the incoming value for that
// field is empty, matching by identity name + field/header key.
func mergeIdentitySecrets(incoming, existing identitiesDoc) identitiesDoc {
	prev := map[string]agent.Identity{}
	for _, id := range existing.Identities {
		prev[id.Name] = id
	}
	for i := range incoming.Identities {
		id := &incoming.Identities[i]
		old, ok := prev[id.Name]
		if !ok {
			continue
		}
		if id.Login != nil && old.Login != nil {
			for k, v := range id.Login.Fields {
				if isSecretKey(k) && strings.TrimSpace(v) == "" {
					if ov, has := old.Login.Fields[k]; has && ov != "" {
						id.Login.Fields[k] = ov
					}
				}
			}
		}
		if len(id.Headers) > 0 {
			for k, v := range id.Headers {
				if isSecretKey(k) && strings.TrimSpace(v) == "" {
					if ov, has := old.Headers[k]; has && ov != "" {
						id.Headers[k] = ov
					}
				}
			}
		}
	}
	return incoming
}

func writeIdentitiesJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
