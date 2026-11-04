package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFinalizeRun covers the core of the website-test honesty fix: the engine
// can exit 0 while its agentic phase failed, so finalizeRun must read the run
// log, not trust the exit code.
func TestFinalizeRun(t *testing.T) {
	cases := []struct {
		name       string
		log        string
		waitErr    error
		exitCode   int
		wantState  string
		reasonHas  string // substring the reason must contain ("" = no reason)
	}{
		{
			name:      "401 with clean exit is a failure, not finished",
			log:       "crawling...\n  Agentic run failed: agentic-dast turn failed (status 401)\nPENTEST_END {\"outcome\":\"error\",\"issues\":0}",
			waitErr:   nil, // engine exited 0 despite the error
			exitCode:  0,
			wantState: "failed",
			reasonHas: "401",
		},
		{
			name:      "unauthorized white-box turn",
			log:       "White-box review skipped: white-box turn 1: unauthorized",
			wantState: "failed",
			reasonHas: "sign in",
		},
		{
			name:      "insufficient tokens",
			log:       "error: insufficient tokens to run the agent",
			wantState: "failed",
			reasonHas: "token balance",
		},
		{
			name:      "engine error outcome without a known cause",
			log:       "PENTEST_END {\"outcome\":\"error\",\"issues\":0}",
			wantState: "failed",
			reasonHas: "reported an error",
		},
		{
			name:      "abnormal process exit",
			log:       "panic: boom",
			waitErr:   os.ErrClosed, // stand-in for a non-nil wait error
			exitCode:  2,
			wantState: "failed",
			reasonHas: "exited abnormally",
		},
		{
			name:      "clean success",
			log:       "PENTEST_END {\"outcome\":\"ok\",\"issues\":3}",
			wantState: "finished",
			reasonHas: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "last-run.log"), []byte(tc.log), 0600); err != nil {
				t.Fatal(err)
			}
			state, reason := finalizeRun(dir, tc.waitErr, tc.exitCode)
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
			if tc.reasonHas == "" && reason != "" {
				t.Errorf("reason = %q, want empty", reason)
			}
			if tc.reasonHas != "" && !strings.Contains(strings.ToLower(reason), strings.ToLower(tc.reasonHas)) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.reasonHas)
			}
		})
	}
}
