package agent

import (
	"sync"
	"time"
)

// StopReason is the human-readable cause surfaced when a cap trips. It is shown
// to the user verbatim ("stopped: <reason>") so a bounded run never looks like
// a clean finish (§11 DoD, §12).
type StopReason string

const (
	StopStepBudget    StopReason = "step budget reached"
	StopRequestBudget StopReason = "request budget reached"
	StopWallClock     StopReason = "time budget reached"
)

// BudgetError is returned by Budget operations once a cap has tripped.
type BudgetError struct{ Reason StopReason }

func (e *BudgetError) Error() string { return "stopped: " + string(e.Reason) }

// Limits are the hard bounds for a run (§8). A zero value on any field disables
// that particular cap.
type Limits struct {
	MaxSteps         int           // max agent reasoning turns
	MaxRequests      int           // max HTTP probes across the whole run
	WallClock        time.Duration // max elapsed wall-clock time
	RequestsPerSec   float64       // global request-rate cap (0 = unlimited)
	MaxResponseBytes int64         // cap on how much of a response body we ingest
	ProbeTimeout     time.Duration // per-probe HTTP timeout
	MaxRedirects     int           // per-probe redirect cap
}

// DefaultLimits are the shipping defaults from §8 (all configurable).
func DefaultLimits() Limits {
	return Limits{
		MaxSteps:         15,
		MaxRequests:      500,
		WallClock:        5 * time.Minute,
		RequestsPerSec:   10,
		MaxResponseBytes: 256 * 1024,
		ProbeTimeout:     15 * time.Second,
		MaxRedirects:     5,
	}
}

// Budget tracks step / request / wall-clock consumption for a run and trips —
// permanently — the moment any cap is exceeded. It is safe for concurrent use
// (parallel probes within a step, §9). The clock is injectable for tests.
type Budget struct {
	mu       sync.Mutex
	lim      Limits
	clock    func() time.Time
	start    time.Time
	started  bool
	steps    int
	requests int
	stopped  bool
	reason   StopReason
}

// NewBudget creates a Budget. Pass nil for clock to use the wall clock.
func NewBudget(lim Limits, clock func() time.Time) *Budget {
	if clock == nil {
		clock = time.Now
	}
	return &Budget{lim: lim, clock: clock}
}

// BeginStep reserves one agent reasoning turn, returning a *BudgetError if the
// step or wall-clock cap is (or has been) reached.
func (b *Budget) BeginStep() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensureStarted()
	if b.stopped {
		return &BudgetError{b.reason}
	}
	if b.overWallClock() {
		return b.trip(StopWallClock)
	}
	if b.lim.MaxSteps > 0 && b.steps >= b.lim.MaxSteps {
		return b.trip(StopStepBudget)
	}
	b.steps++
	return nil
}

// CountRequest reserves one HTTP probe, returning a *BudgetError if the request
// or wall-clock cap is (or has been) reached.
func (b *Budget) CountRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensureStarted()
	if b.stopped {
		return &BudgetError{b.reason}
	}
	if b.overWallClock() {
		return b.trip(StopWallClock)
	}
	if b.lim.MaxRequests > 0 && b.requests >= b.lim.MaxRequests {
		return b.trip(StopRequestBudget)
	}
	b.requests++
	return nil
}

// Stopped reports whether a cap has tripped and, if so, why.
func (b *Budget) Stopped() (bool, StopReason) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped, b.reason
}

// Stats returns consumption so far for progress display / budget meters.
func (b *Budget) Stats() (steps, requests int, elapsed time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		elapsed = b.clock().Sub(b.start)
	}
	return b.steps, b.requests, elapsed
}

func (b *Budget) ensureStarted() {
	if !b.started {
		b.start = b.clock()
		b.started = true
	}
}

func (b *Budget) overWallClock() bool {
	return b.lim.WallClock > 0 && b.clock().Sub(b.start) >= b.lim.WallClock
}

// trip must be called with the lock held.
func (b *Budget) trip(r StopReason) error {
	b.stopped = true
	b.reason = r
	return &BudgetError{r}
}

// RateLimiter enforces a global minimum interval between probes so the agent
// physically cannot burst-DoS a target while probing (§6.2). Serializing on the
// mutex during the wait makes the cap truly global across concurrent probes.
// clock and sleep are injectable for tests.
type RateLimiter struct {
	mu          sync.Mutex
	minInterval time.Duration
	last        time.Time
	clock       func() time.Time
	sleep       func(time.Duration)
}

// NewRateLimiter builds a limiter permitting at most perSec requests per second
// (perSec <= 0 disables limiting). Pass nil clock/sleep to use the wall clock.
func NewRateLimiter(perSec float64, clock func() time.Time, sleep func(time.Duration)) *RateLimiter {
	if clock == nil {
		clock = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	var iv time.Duration
	if perSec > 0 {
		iv = time.Duration(float64(time.Second) / perSec)
	}
	return &RateLimiter{minInterval: iv, clock: clock, sleep: sleep}
}

// Wait blocks until the next probe is permitted under the rate cap.
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.minInterval <= 0 {
		return
	}
	now := r.clock()
	if !r.last.IsZero() {
		if elapsed := now.Sub(r.last); elapsed < r.minInterval {
			d := r.minInterval - elapsed
			r.sleep(d)
			now = now.Add(d)
		}
	}
	r.last = now
}
