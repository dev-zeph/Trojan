package scangate

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dev-zeph/trojan/internal/ai"
)

func fixed(balance int) LicenseFetcher {
	return func(string) (*ai.LicenseInfo, error) { return &ai.LicenseInfo{TokenBalance: balance}, nil }
}

func TestCheck_SignedOutBlocksWithoutCallingServer(t *testing.T) {
	called := false
	r := Check("", func(string) (*ai.LicenseInfo, error) { called = true; return nil, nil })
	if r.Allowed || r.Reason != ReasonSignedOut {
		t.Fatalf("signed out should be blocked, got %+v", r)
	}
	if r.Message != "Sign in to scan. Every account gets 500 free tokens a month." {
		t.Fatalf("unexpected message %q", r.Message)
	}
	if called {
		t.Fatal("no network call is needed to know nobody is signed in")
	}
}

func TestCheck_ExpiredSessionCountsAsSignedOut(t *testing.T) {
	r := Check("tok", func(string) (*ai.LicenseInfo, error) { return nil, ai.ErrLicenseUnauthorized })
	if r.Allowed || r.Reason != ReasonSignedOut || !strings.Contains(r.Message, "Sign in to scan") {
		t.Fatalf("got %+v", r)
	}
}

func TestCheck_BelowMinimumBlocksAndShowsBalance(t *testing.T) {
	r := Check("tok", fixed(MinTokens-1))
	if r.Allowed || r.Reason != ReasonLowTokens || r.Balance != MinTokens-1 {
		t.Fatalf("got %+v", r)
	}
	if !strings.Contains(r.Message, "You have 49") || !strings.Contains(r.Message, "at least 50") {
		t.Fatalf("message should show balance and minimum: %q", r.Message)
	}
}

func TestCheck_AtOrAboveMinimumPasses(t *testing.T) {
	for _, b := range []int{MinTokens, 500, 100000} {
		if r := Check("tok", fixed(b)); !r.Allowed || r.Balance != b {
			t.Fatalf("balance %d should pass, got %+v", b, r)
		}
	}
}

func TestCheck_UnreachableServerAllowsButFlagsUnverified(t *testing.T) {
	r := Check("tok", func(string) (*ai.LicenseInfo, error) { return nil, errors.New("offline") })
	if !r.Allowed || !r.Unverified {
		t.Fatalf("got %+v", r)
	}
}

// The monthly free grant is applied by the license endpoint before it reports
// the balance. This stub grants lazily on first call like the real one, so a
// user whose new month has not been granted yet (balance 0) only passes if
// Check reads the balance through that endpoint.
func TestCheck_ReadsBalanceThroughGrantingEndpoint(t *testing.T) {
	var mu sync.Mutex
	var events []string
	balance := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, "grant")
		if balance == 0 {
			balance = 500 // ensure_monthly_free_tokens
		}
		events = append(events, "read")
		_ = json.NewEncoder(w).Encode(map[string]any{"tokenBalance": balance})
	}))
	defer srv.Close()
	defer ai.OverrideLicenseURL(srv.URL)()

	r := Check("tok", ai.FetchLicense)
	if !r.Allowed || r.Balance != 500 {
		t.Fatalf("new-month user should pass after the grant, got %+v", r)
	}
	if strings.Join(events, ",") != "grant,read" {
		t.Fatalf("grant must come before the balance read: %v", events)
	}
}

func TestOutOfTokensNote(t *testing.T) {
	if got := OutOfTokensNote(3); got != "Out of tokens: 3 findings weren't double-checked." {
		t.Fatal(got)
	}
	if got := OutOfTokensNote(1); got != "Out of tokens: 1 finding wasn't double-checked." {
		t.Fatal(got)
	}
}
