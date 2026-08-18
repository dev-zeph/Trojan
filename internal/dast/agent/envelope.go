package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// Tier is the scan-intensity rung (§6.2). Higher tiers permit more, and are
// gated by environment: aggressive is staging-only, and safe-active POST on
// production additionally requires an explicit side-effect acknowledgement.
type Tier int

const (
	// TierPassive — GET/HEAD/OPTIONS only. Safe anywhere, including production.
	TierPassive Tier = iota
	// TierSafeActive — adds non-destructive POST (boolean/time-based injection
	// confirmation, reflected-XSS markers). No writes, no extraction, no volume.
	TierSafeActive
	// TierAggressive — adds stored-XSS / state-touching probes with labelled
	// benign markers. Staging-only.
	TierAggressive
)

func (t Tier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierSafeActive:
		return "safe-active"
	case TierAggressive:
		return "aggressive"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// ParseTier maps a CLI/UI string to a Tier.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "passive":
		return TierPassive, nil
	case "safe-active", "safeactive", "safe_active":
		return TierSafeActive, nil
	case "aggressive":
		return TierAggressive, nil
	default:
		return TierPassive, fmt.Errorf("unknown tier %q (use passive, safe-active, or aggressive)", s)
	}
}

// Environment declares whether the target is production or staging (§6.2).
type Environment int

const (
	EnvProduction Environment = iota
	EnvStaging
)

func (e Environment) String() string {
	if e == EnvStaging {
		return "staging"
	}
	return "production"
}

// ParseEnvironment maps a CLI/UI string to an Environment. Production is the
// safe default — an unspecified environment is treated as production so the
// stricter rules apply.
func ParseEnvironment(s string) (Environment, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "prod", "production":
		return EnvProduction, nil
	case "staging", "stage", "test":
		return EnvStaging, nil
	default:
		return EnvProduction, fmt.Errorf("unknown environment %q (use production or staging)", s)
	}
}

// Method classification. Destructive verbs are never permitted in report-only
// mode regardless of tier; the always-safe set is read-only.
var (
	alwaysSafeMethods  = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
	destructiveMethods = map[string]bool{"PUT": true, "PATCH": true, "DELETE": true, "TRACE": true, "CONNECT": true}
)

const defaultMaxRequestBody = 64 * 1024 // 64 KiB — a proof, not bulk data

// Envelope is the immutable safety context for a single run. It is the sole
// authority on whether a given probe is permitted.
type Envelope struct {
	Tier              Tier
	Env               Environment
	Host              string // canonical same-host scope (lowercased hostname)
	AcceptSideEffects bool   // required for POST on production (Safe-Active, §6.2)
	MaxRequestBody    int64  // reject probe bodies larger than this

	// roe is the per-engagement Rules of Engagement (§8.1): what the agent may DO
	// to an in-scope host, layered on top of the tier/host floor above. Zero value
	// = no allowlist/denylist and auto-avoid active — the safe default. Set once by
	// the composition root via SetRoE before the run starts.
	roe RoE
}

// SetRoE installs the engagement's Rules of Engagement. Called once at setup,
// before any probe — the Envelope is otherwise treated as immutable during a run.
func (e *Envelope) SetRoE(r RoE) { e.roe = r }

// RoE returns the installed Rules of Engagement (for logging into the scan record).
func (e *Envelope) RoE() RoE { return e.roe }

// NewEnvelope builds an Envelope and enforces the environment-level invariants
// up front: a host scope is required, and the aggressive tier is staging-only.
func NewEnvelope(tier Tier, env Environment, host string, acceptSideEffects bool) (*Envelope, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("envelope requires a same-host scope")
	}
	if tier == TierAggressive && env != EnvStaging {
		return nil, fmt.Errorf("aggressive tier is staging-only (target is %s)", env)
	}
	return &Envelope{
		Tier:              tier,
		Env:               env,
		Host:              host,
		AcceptSideEffects: acceptSideEffects,
		MaxRequestBody:    defaultMaxRequestBody,
	}, nil
}

// ValidateProbe enforces safe-mode on a single probe: method allowlist by tier,
// destructive-verb rejection, same-host scope, and request-body size. It is
// pure (no network) so it is fully unit-testable and cheap to call per probe.
func (e *Envelope) ValidateProbe(method, rawURL string, bodyLen int) error {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		return fmt.Errorf("probe method is empty")
	}

	switch {
	case destructiveMethods[m]:
		return fmt.Errorf("method %s is destructive and never permitted in report-only mode", m)
	case alwaysSafeMethods[m]:
		// permitted at every tier and environment
	case m == "POST":
		if e.Tier < TierSafeActive {
			return fmt.Errorf("POST requires the safe-active tier (current tier: %s)", e.Tier)
		}
		if e.Env == EnvProduction && !e.AcceptSideEffects {
			return fmt.Errorf("POST against production requires explicit side-effect acknowledgement")
		}
	default:
		return fmt.Errorf("method %s is not permitted", m)
	}

	host, err := probeHost(rawURL)
	if err != nil {
		return err
	}
	if host != e.Host {
		return fmt.Errorf("off-host target %q — probes are scoped to %q", host, e.Host)
	}

	if e.MaxRequestBody > 0 && int64(bodyLen) > e.MaxRequestBody {
		return fmt.Errorf("request body of %d bytes exceeds the %d-byte cap", bodyLen, e.MaxRequestBody)
	}
	return nil
}

// probeHost extracts the lowercased hostname from an http/https URL.
func probeHost(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("invalid probe URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("probe URL must be http:// or https://")
	}
	h := u.Hostname()
	if h == "" {
		return "", fmt.Errorf("probe URL has no host")
	}
	return strings.ToLower(h), nil
}
