package agent

import (
	"errors"
	"testing"
	"time"
)

func TestBudgetStepCap(t *testing.T) {
	b := NewBudget(Limits{MaxSteps: 2}, nil)
	if err := b.BeginStep(); err != nil {
		t.Fatalf("step 1: %v", err)
	}
	if err := b.BeginStep(); err != nil {
		t.Fatalf("step 2: %v", err)
	}
	err := b.BeginStep()
	var be *BudgetError
	if !errors.As(err, &be) || be.Reason != StopStepBudget {
		t.Fatalf("step 3 should trip step budget, got %v", err)
	}
	if stopped, reason := b.Stopped(); !stopped || reason != StopStepBudget {
		t.Errorf("Stopped() = %v, %q; want true, %q", stopped, reason, StopStepBudget)
	}
}

func TestBudgetRequestCap(t *testing.T) {
	b := NewBudget(Limits{MaxRequests: 1}, nil)
	if err := b.CountRequest(); err != nil {
		t.Fatalf("request 1: %v", err)
	}
	err := b.CountRequest()
	var be *BudgetError
	if !errors.As(err, &be) || be.Reason != StopRequestBudget {
		t.Fatalf("request 2 should trip request budget, got %v", err)
	}
	// A tripped budget is sticky and reported, never silent.
	if err := b.BeginStep(); err == nil {
		t.Error("BeginStep after trip should still error")
	}
}

func TestBudgetWallClock(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	b := NewBudget(Limits{WallClock: time.Minute}, clock)

	if err := b.BeginStep(); err != nil { // starts the clock at t=0
		t.Fatalf("first step: %v", err)
	}
	now = now.Add(30 * time.Second)
	if err := b.CountRequest(); err != nil {
		t.Fatalf("within window: %v", err)
	}
	now = now.Add(31 * time.Second) // now 61s elapsed
	err := b.CountRequest()
	var be *BudgetError
	if !errors.As(err, &be) || be.Reason != StopWallClock {
		t.Fatalf("should trip wall-clock, got %v", err)
	}
}

func TestBudgetStats(t *testing.T) {
	now := time.Unix(100, 0)
	b := NewBudget(DefaultLimits(), func() time.Time { return now })
	_ = b.BeginStep()
	_ = b.CountRequest()
	_ = b.CountRequest()
	now = now.Add(5 * time.Second)
	steps, reqs, elapsed := b.Stats()
	if steps != 1 || reqs != 2 || elapsed != 5*time.Second {
		t.Errorf("Stats() = %d, %d, %v; want 1, 2, 5s", steps, reqs, elapsed)
	}
}

func TestRateLimiterSpacing(t *testing.T) {
	now := time.Unix(0, 0)
	var slept []time.Duration
	clock := func() time.Time { return now }
	sleep := func(d time.Duration) { slept = append(slept, d); now = now.Add(d) }

	// 5 rps => 200ms minimum interval.
	r := NewRateLimiter(5, clock, sleep)

	r.Wait() // first call: no wait
	if len(slept) != 0 {
		t.Fatalf("first Wait should not sleep, slept=%v", slept)
	}
	r.Wait() // immediate second call: must sleep ~200ms
	if len(slept) != 1 || slept[0] != 200*time.Millisecond {
		t.Fatalf("second Wait should sleep 200ms, slept=%v", slept)
	}

	// After enough real time passes, no sleep needed.
	now = now.Add(500 * time.Millisecond)
	r.Wait()
	if len(slept) != 1 {
		t.Fatalf("third Wait should not sleep, slept=%v", slept)
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	slept := 0
	r := NewRateLimiter(0, func() time.Time { return time.Unix(0, 0) }, func(time.Duration) { slept++ })
	for range 100 {
		r.Wait()
	}
	if slept != 0 {
		t.Errorf("unlimited limiter should never sleep, slept %d times", slept)
	}
}
