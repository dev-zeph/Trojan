package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApprovalMethodGuard(t *testing.T) {
	writeProConfig(t)
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.handleApproval(rec, httptest.NewRequest(http.MethodGet, "/api/dast/approval", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on approval endpoint: status = %d, want 405", rec.Code)
	}
}

func TestApprovalNoActiveRun(t *testing.T) {
	writeProConfig(t)
	s := newTestServer() // no sink installed
	rec := httptest.NewRecorder()
	s.handleApproval(rec, httptest.NewRequest(http.MethodPost, "/api/dast/approval", strings.NewReader(`{"id":1,"approve":true}`)))
	if rec.Code != http.StatusConflict {
		t.Errorf("no active run: status = %d, want 409", rec.Code)
	}
}

func TestApprovalDeliversDecision(t *testing.T) {
	writeProConfig(t)
	s := newTestServer()

	type decision struct {
		id      int
		approve bool
		note    string
	}
	got := make(chan decision, 1)
	s.SetApprovalSink(func(id int, approve bool, note string) {
		got <- decision{id, approve, note}
	})

	rec := httptest.NewRecorder()
	s.handleApproval(rec, httptest.NewRequest(http.MethodPost, "/api/dast/approval",
		strings.NewReader(`{"id":42,"approve":true,"note":"looks safe"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	select {
	case d := <-got:
		if d.id != 42 || !d.approve || d.note != "looks safe" {
			t.Errorf("decision not delivered verbatim: %+v", d)
		}
	default:
		t.Error("decision was not delivered to the sink")
	}

	// A missing id is a 400.
	rec = httptest.NewRecorder()
	s.handleApproval(rec, httptest.NewRequest(http.MethodPost, "/api/dast/approval", strings.NewReader(`{"approve":true}`)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing id: status = %d, want 400", rec.Code)
	}
}
