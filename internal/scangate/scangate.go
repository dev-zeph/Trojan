// Package scangate decides whether a code scan may start.
//
// A code scan needs a signed-in account and a small token balance, because the
// AI check after the scanners spends Trojan Tokens. This is the user-facing
// gate (clear message, no wasted run). It is NOT the enforcement: the triage and
// synthesize edge functions authenticate and debit on their own, so a client
// that skips this gate still cannot spend what it does not have.
package scangate

import (
	"errors"
	"fmt"

	"github.com/dev-zeph/trojan/internal/ai"
)

// MinTokens is the balance needed to start a code scan.
//
// A scan's own cost is usage-based: roughly 5 tokens per explained finding and
// about 30 for a batch triage call on Haiku. 50 covers the triage call plus a
// handful of explanations, so a scan that starts can do something useful. It is
// also 10% of the monthly free grant, so a free user is never locked out by it
// until they have genuinely used most of their month. Running out later is not
// fatal: the scan finishes with scanner results and only the AI check stops.
const MinTokens = 50

// SignInMessage is shown to a signed-out user. Keep in step with
// desktop/src/lib/scanGate.ts.
const SignInMessage = "Sign in to scan. Every account gets 500 free tokens a month."

// Reason says why a scan was (or was not) allowed.
type Reason string

const (
	ReasonOK        Reason = "ok"
	ReasonSignedOut Reason = "signed_out"
	ReasonLowTokens Reason = "low_tokens"
)

// Result is the outcome of Check.
type Result struct {
	Allowed bool
	Reason  Reason
	Balance int
	Min     int
	Message string
	// Unverified is true when the balance could not be read (offline, service
	// down) and the scan was allowed anyway. Scanners are free; the server still
	// refuses any AI work the account cannot pay for.
	Unverified bool
}

// LicenseFetcher reads the account's license info. ai.FetchLicense is the
// real one. The license endpoint applies this month's free grant before it
// reports the balance, so a new month's tokens are already counted.
type LicenseFetcher func(accessToken string) (*ai.LicenseInfo, error)

// Check gates a code scan for the given access token ("" means signed out).
func Check(accessToken string, fetch LicenseFetcher) Result {
	if accessToken == "" {
		return Result{Reason: ReasonSignedOut, Min: MinTokens, Message: SignInMessage}
	}
	info, err := fetch(accessToken)
	if err != nil {
		if errors.Is(err, ai.ErrLicenseUnauthorized) {
			return Result{Reason: ReasonSignedOut, Min: MinTokens,
				Message: "Your sign-in has expired. " + SignInMessage}
		}
		return Result{Allowed: true, Reason: ReasonOK, Min: MinTokens, Unverified: true,
			Message: "Could not check your token balance, so scanning anyway. The AI check needs tokens and may be skipped."}
	}
	if info.TokenBalance < MinTokens {
		return Result{Reason: ReasonLowTokens, Balance: info.TokenBalance, Min: MinTokens,
			Message: LowTokensMessage(info.TokenBalance)}
	}
	return Result{Allowed: true, Reason: ReasonOK, Balance: info.TokenBalance, Min: MinTokens}
}

// LowTokensMessage is the plain-words block shown when the balance is too low.
func LowTokensMessage(balance int) string {
	return fmt.Sprintf("Not enough tokens to scan. You have %d and a scan needs at least %d. "+
		"Top up at https://trojancli.com/pricing, or wait for your free 500 tokens next month.", balance, MinTokens)
}

// OutOfTokensNote is the one-line note shown when the balance runs out partway
// through a scan. The scan still finishes with the scanner results.
func OutOfTokensNote(unchecked int) string {
	noun := "findings weren't"
	if unchecked == 1 {
		noun = "finding wasn't"
	}
	return fmt.Sprintf("Out of tokens: %d %s double-checked.", unchecked, noun)
}
