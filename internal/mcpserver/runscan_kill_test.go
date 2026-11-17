package mcpserver

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// killedError returns a genuine *exec.ExitError from a process killed by
// SIGKILL, the same shape scan-once produces when the context deadline fires
// or the OS out-of-memory killer steps in.
func killedError(t *testing.T) error {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "kill -9 $$").Run()
	if err == nil {
		t.Fatal("expected the process to be killed")
	}
	return err
}

func TestScanFailureMessage_OOMKill(t *testing.T) {
	// A live (never-cancelled) context: a SIGKILL here was not our deadline,
	// so the message should point at memory, not the time limit.
	msg := scanFailureMessage(killedError(t), context.Background(), t.TempDir(), nil)
	if !strings.Contains(msg, "memory") {
		t.Errorf("OOM kill should mention memory, got: %q", msg)
	}
	if strings.Contains(msg, "signal: killed") {
		t.Errorf("raw 'signal: killed' should not reach the user: %q", msg)
	}
}

func TestScanFailureMessage_DeadlineKill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has passed
	msg := scanFailureMessage(killedError(t), ctx, t.TempDir(), nil)
	if !strings.Contains(msg, "limit") {
		t.Errorf("deadline kill should mention the time limit, got: %q", msg)
	}
}

func TestScanFailureMessage_GenericError(t *testing.T) {
	err := exec.Command("/bin/sh", "-c", "echo boom >&2; exit 3").Run()
	if err == nil {
		t.Fatal("expected a non-zero exit")
	}
	msg := scanFailureMessage(err, context.Background(), t.TempDir(), nil)
	if strings.Contains(msg, "memory") || strings.Contains(msg, "limit") {
		t.Errorf("a plain non-zero exit should not be reported as kill/timeout: %q", msg)
	}
	if !strings.Contains(msg, "did not finish") {
		t.Errorf("want a generic failure message, got: %q", msg)
	}
}
