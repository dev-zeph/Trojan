package ai

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/fingerprint"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

const recordedInferResponse = `{
  "context": {
    "app": {"name": "Corner Shop", "description": "Customers order food and pay by card."},
    "sensitive_data": [{"category": "payment", "file_patterns": ["app/api/orders/**"]}],
    "trust_boundaries": [{"name": "public API", "file_patterns": ["app/api/**"]}],
    "threat_actors": [{"name": "anonymous visitor", "targets": ["public API"]}],
    "data_stores": ["orders", "profiles"],
    "auth_model": {"who_logs_in": "customers", "roles": ["customer"], "admin_area": false},
    "third_party_services": ["stripe", "supabase"]
  },
  "questions": ["Do customers need an account to place an order?", "Is there a page only your staff can open?"],
  "mismatches": [{"said": "Everyone must log in", "found": "Placing an order does not check for a login", "question": "Should anyone be able to place an order without logging in?"}],
  "free": true
}`

func decodeWrapped(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var wrapper map[string]string
	_ = json.NewDecoder(r.Body).Decode(&wrapper)
	raw, err := base64.StdEncoding.DecodeString(wrapper["encoded"])
	if err != nil {
		t.Errorf("body not base64 wrapped: %v", err)
	}
	var inner map[string]any
	_ = json.Unmarshal(raw, &inner)
	return inner
}

func TestInferContext_ParsesRecordedResponse(t *testing.T) {
	var gotAuth string
	var inner map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		inner = decodeWrapped(t, r)
		w.Write([]byte(recordedInferResponse))
	}))
	defer srv.Close()
	defer OverrideInferContextURL(srv.URL)()

	fp := fingerprint.Fingerprint{Framework: "nextjs", DataStores: []string{"orders"}}
	res, err := InferContext("A shop where customers order food", fp, "proj123", nil, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if inner["project_id"] != "proj123" || inner["description"] == "" {
		t.Errorf("payload = %v", inner)
	}
	if _, ok := inner["existing_context"]; ok {
		t.Error("existing_context should be omitted when nil")
	}
	if res.Context.App.Name != "Corner Shop" || len(res.Context.DataStores) != 2 {
		t.Errorf("context = %+v", res.Context)
	}
	if res.Context.AuthModel == nil || res.Context.AuthModel.WhoLogsIn != "customers" {
		t.Errorf("auth model = %+v", res.Context.AuthModel)
	}
	if len(res.Context.SensitiveData) != 1 || res.Context.SensitiveData[0].FilePatterns[0] != "app/api/orders/**" {
		t.Errorf("sensitive = %+v", res.Context.SensitiveData)
	}
	if len(res.Questions) != 2 {
		t.Errorf("questions = %v", res.Questions)
	}
	if len(res.Mismatches) != 1 || !strings.Contains(res.Mismatches[0].Found, "login") || res.Mismatches[0].Question == "" {
		t.Errorf("mismatches = %+v", res.Mismatches)
	}
	if !res.Free {
		t.Error("free flag lost")
	}
}

func TestInferContext_SendsExistingContext(t *testing.T) {
	var inner map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = decodeWrapped(t, r)
		w.Write([]byte(`{"context":{"app":{"name":"x","description":"y"}},"questions":[],"mismatches":[]}`))
	}))
	defer srv.Close()
	defer OverrideInferContextURL(srv.URL)()

	existing := &orgcontext.OrgContext{App: orgcontext.AppInfo{Name: "Old"}}
	if _, err := InferContext("d", fingerprint.Fingerprint{}, "p", existing, "t"); err != nil {
		t.Fatal(err)
	}
	if inner["existing_context"] == nil {
		t.Error("existing_context missing")
	}
}

func TestInferContext_402IsInsufficientTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`{"error":"insufficient_tokens","message":"You are out of Trojan Tokens.","balance":0}`))
	}))
	defer srv.Close()
	defer OverrideInferContextURL(srv.URL)()

	_, err := InferContext("d", fingerprint.Fingerprint{}, "p", nil, "t")
	if !errors.Is(err, ErrInsufficientTokens) {
		t.Fatalf("want ErrInsufficientTokens, got %v", err)
	}
}

func TestInferContext_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	defer OverrideInferContextURL(srv.URL)()
	if _, err := InferContext("d", fingerprint.Fingerprint{}, "p", nil, "t"); err == nil || errors.Is(err, ErrInsufficientTokens) {
		t.Fatalf("want generic error, got %v", err)
	}
}
