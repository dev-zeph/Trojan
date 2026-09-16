// Package errmon is the Trojan side of the Errors (crash analytics) feature.
//
// It contains exactly one thing: the hook that tells the Trojan Errors shim
// when a pen-test run is attacking a target, so the errors that run provokes
// don't show up in the customer's Errors tab as "your app is broken."
//
// Per the locked design (CRASH_ANALYTICS_RESEARCH.md 3a) this is tag-don't-drop:
// we only tell the shim a run is in progress. The shim stamps matching events
// as pen-test traffic and the desktop hides them behind a filter. Nothing is
// ever discarded, so a genuine production bug that happens to fire during a
// pen-test window is still recorded and still findable.
//
// Everything here is best-effort and fails silent. The Errors shim is an
// optional, separately-run service; a customer who has never enabled crash
// analytics has nothing listening on that port. Under no circumstances may
// this degrade or delay a pen-test.
package errmon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// DefaultShimURL is where the Trojan Errors shim listens locally.
// Override with TROJAN_ERRORS_URL (for example when the shim is deployed).
const DefaultShimURL = "http://127.0.0.1:3002"

// hookTimeout is deliberately tiny. If the shim isn't there, we want to know
// within a blink and move on with the scan.
const hookTimeout = 750 * time.Millisecond

var (
	mu      sync.Mutex
	current string // run id of the in-flight run, empty when none
)

func shimURL() string {
	if v := os.Getenv("TROJAN_ERRORS_URL"); v != "" {
		return v
	}
	return DefaultShimURL
}

// post fires a request at the shim and swallows everything that goes wrong.
// A missing shim is the expected case, not an error worth surfacing.
func post(path string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, shimURL()+path, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// NotifyRunStart marks the beginning of a pen-test window against target.
// Returns the run id, or "" if the shim isn't reachable (the normal case when
// crash analytics isn't set up). Safe to call unconditionally.
func NotifyRunStart(target string) string {
	runID := fmt.Sprintf("dast-%d", time.Now().UnixNano())

	if !post("/api/errors/dast/start", map[string]string{
		"runId":  runID,
		"target": target,
	}) {
		return ""
	}

	mu.Lock()
	current = runID
	mu.Unlock()

	return runID
}

// NotifyRunEnd closes the pen-test window. Safe to call with an empty run id,
// more than once, or without a matching start.
func NotifyRunEnd(runID string) {
	if runID == "" {
		return
	}

	mu.Lock()
	if current == runID {
		current = ""
	}
	mu.Unlock()

	post("/api/errors/dast/stop", map[string]string{"runId": runID})
}

// EndActiveRun closes whatever run is currently open. This exists for the
// signal path: cancelling a pen-test (desktop Cancel button, or Ctrl+C) must
// un-mute, otherwise a killed run would leave the customer's Errors tab
// filtering out real production errors indefinitely.
func EndActiveRun() {
	mu.Lock()
	runID := current
	current = ""
	mu.Unlock()

	if runID != "" {
		post("/api/errors/dast/stop", map[string]string{"runId": runID})
	}
}
