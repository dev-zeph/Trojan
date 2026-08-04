package dast

// Domain-ownership consent gate (agentic DAST — Phase 2).
//
// Pen-testing a host you don't own is a CFAA-class crime, so no crawl, Nuclei
// run, or agent turn may fire against a non-local target until the user has
// proven they control it. This mirrors the Google Search Console model users
// already understand: mint a token, place it via one of three methods, verify.
//
// Enforcement is local-first: the authoritative consent record lives in
// ~/.trojan/consent.json on the user's machine (the same box that originates
// the traffic), so the gate holds even offline and no scan state leaves the
// host. localhost / private-IP targets skip the gate (no third party is
// involved) but are always labelled as such by callers.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Verification carriers. These strings are user-facing (shown in CLI/UI
// instructions and matched against what the user places), so keep them stable.
const (
	// TXTPrefix is the leading token marker in a DNS TXT record value:
	//   trojan-verify=<token>
	TXTPrefix = "trojan-verify="

	// WellKnownPath is fetched over HTTP(S); the body must contain the token.
	WellKnownPath = "/.well-known/trojan-verify.txt"

	// MetaName is the <meta name="..."> whose content must equal the token.
	MetaName = "trojan-site-verification"

	// tokenBytes is the entropy of a minted token (hex-encoded → 2x chars).
	tokenBytes = 20
)

// VerifyMethod identifies how ownership was (or will be) proven.
type VerifyMethod string

const (
	MethodDNS  VerifyMethod = "dns"
	MethodFile VerifyMethod = "file"
	MethodMeta VerifyMethod = "meta"
)

// ConsentRecord is a persisted proof that a user verified control of a domain.
// It satisfies the Phase-2 DoD: who (UserEmail), which domain, method, when.
type ConsentRecord struct {
	Domain     string       `json:"domain"`      // exact host verified (no scheme/port)
	UserEmail  string       `json:"user_email"`  // who verified (from the local session)
	Method     VerifyMethod `json:"method"`      // dns | file | meta
	Token      string       `json:"token"`       // the token that was matched
	VerifiedAt time.Time    `json:"verified_at"` // when the proof succeeded
}

// pendingToken is a minted-but-not-yet-verified challenge, persisted so that
// re-checking a domain reuses the same token the user already placed.
type pendingToken struct {
	Domain    string    `json:"domain"`
	UserEmail string    `json:"user_email"`
	Token     string    `json:"token"`
	MintedAt  time.Time `json:"minted_at"`
}

// consentStore is the on-disk shape of ~/.trojan/consent.json.
type consentStore struct {
	Verified []ConsentRecord `json:"verified"`
	Pending  []pendingToken  `json:"pending"`
}

// ── Public API ──────────────────────────────────────────────────────────────

// GateStatus reports whether scanning the given URL is permitted for the given
// user. A target is allowed when it is local (loopback / private network — no
// third party) or when a verified consent record exists for its exact host.
func GateStatus(rawURL, userEmail string) (allowed, isLocal bool, rec *ConsentRecord, domain string, err error) {
	host, err := NormalizeHost(rawURL)
	if err != nil {
		return false, false, nil, "", err
	}
	if IsLocalHost(host) {
		return true, true, nil, host, nil
	}
	store, _ := loadConsentStore()
	if r := store.findVerified(host, userEmail); r != nil {
		return true, false, r, host, nil
	}
	return false, false, nil, host, nil
}

// MintToken returns the token the user must place to prove ownership of the
// URL's host. It reuses an existing verified/pending token for the same
// (host, user) so repeated checks are stable, otherwise it mints and persists a
// fresh one. isLocal is true for targets that bypass the gate entirely.
func MintToken(rawURL, userEmail string) (domain, token string, isLocal bool, err error) {
	host, err := NormalizeHost(rawURL)
	if err != nil {
		return "", "", false, err
	}
	if IsLocalHost(host) {
		return host, "", true, nil
	}

	store, _ := loadConsentStore()
	if r := store.findVerified(host, userEmail); r != nil {
		return host, r.Token, false, nil
	}
	if p := store.findPending(host, userEmail); p != nil {
		return host, p.Token, false, nil
	}

	tok, err := newToken()
	if err != nil {
		return "", "", false, err
	}
	store.Pending = append(store.Pending, pendingToken{
		Domain:    host,
		UserEmail: userEmail,
		Token:     tok,
		MintedAt:  time.Now().UTC(),
	})
	if err := saveConsentStore(store); err != nil {
		return "", "", false, err
	}
	return host, tok, false, nil
}

// VerifyOwnership checks that the token minted for the URL's host is present via
// the requested method. On success it persists a ConsentRecord and clears the
// pending token, then returns the record.
func VerifyOwnership(rawURL string, method VerifyMethod, userEmail string) (*ConsentRecord, error) {
	host, err := NormalizeHost(rawURL)
	if err != nil {
		return nil, err
	}
	if IsLocalHost(host) {
		return nil, fmt.Errorf("%s is a local target — no ownership check is required", host)
	}

	store, _ := loadConsentStore()
	p := store.findPending(host, userEmail)
	if p == nil {
		return nil, fmt.Errorf("no pending token for %s — mint one first", host)
	}

	if err := runVerification(rawURL, host, method, p.Token); err != nil {
		return nil, err
	}

	rec := ConsentRecord{
		Domain:     host,
		UserEmail:  userEmail,
		Method:     method,
		Token:      p.Token,
		VerifiedAt: time.Now().UTC(),
	}
	store.upsertVerified(rec)
	store.removePending(host, userEmail)
	if err := saveConsentStore(store); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ── Local-target detection ───────────────────────────────────────────────────

// NormalizeHost extracts the lowercased hostname (no scheme, no port) from a
// URL. It requires an http/https scheme so callers can't accidentally gate a
// bare hostname differently from how the scanner will hit it.
func NormalizeHost(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("URL must start with http:// or https://")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL has no host")
	}
	return strings.ToLower(host), nil
}

// IsLocalHost reports whether a host is a loopback / private-network target that
// does not involve a third party and therefore bypasses the consent gate.
// Cheap literal checks run first; only then does it resolve the name and treat
// it as local if every resolved address is loopback/private (covers dev
// hostnames mapped to 127.0.0.1 or an RFC-1918 address via /etc/hosts or split
// DNS).
func IsLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	// Resolve a hostname; if it resolves entirely to private space, it's local.
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return false // unresolvable → treat as public and gate it
	}
	for _, ip := range addrs {
		if !isPrivateIP(ip) {
			return false
		}
	}
	return true
}

// isPrivateIP covers loopback, RFC-1918 / RFC-4193 private ranges, link-local,
// and the unspecified address.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ── Verification methods ─────────────────────────────────────────────────────

func runVerification(rawURL, host string, method VerifyMethod, token string) error {
	switch method {
	case MethodDNS:
		return verifyDNS(host, token)
	case MethodFile:
		return verifyFile(rawURL, token)
	case MethodMeta:
		return verifyMeta(rawURL, token)
	default:
		return fmt.Errorf("unknown verification method %q (use dns, file, or meta)", method)
	}
}

// verifyDNS looks for a `trojan-verify=<token>` TXT record on the host (and on
// the `_trojan-verify.<host>` label, which some DNS providers prefer for
// challenge records).
func verifyDNS(host, token string) error {
	names := []string{host, "_trojan-verify." + host}
	var all []string
	for _, name := range names {
		if recs, err := net.LookupTXT(name); err == nil {
			all = append(all, recs...)
		}
	}
	if matchTXT(all, token) {
		return nil
	}
	return fmt.Errorf("DNS TXT record %s%s not found on %s (checked %s)",
		TXTPrefix, token, host, strings.Join(names, ", "))
}

// verifyFile fetches scheme://host/.well-known/trojan-verify.txt and checks the
// body contains the token.
func verifyFile(rawURL, token string) error {
	base, err := schemeHost(rawURL)
	if err != nil {
		return err
	}
	target := base + WellKnownPath
	body, err := fetch(target)
	if err != nil {
		return fmt.Errorf("could not fetch %s: %w", target, err)
	}
	if matchToken(body, token) {
		return nil
	}
	return fmt.Errorf("%s did not contain the verification token", target)
}

// verifyMeta fetches the homepage and looks for
// <meta name="trojan-site-verification" content="<token>">.
func verifyMeta(rawURL, token string) error {
	base, err := schemeHost(rawURL)
	if err != nil {
		return err
	}
	target := base + "/"
	body, err := fetch(target)
	if err != nil {
		return fmt.Errorf("could not fetch %s: %w", target, err)
	}
	if matchMeta(body, token) {
		return nil
	}
	return fmt.Errorf(`<meta name="%s" content="%s"> not found on %s`, MetaName, token, target)
}

// ── Pure matchers (unit-tested) ──────────────────────────────────────────────

// matchTXT reports whether any TXT record carries the token, tolerating
// surrounding quotes/whitespace and records concatenated by the resolver.
func matchTXT(records []string, token string) bool {
	want := TXTPrefix + token
	for _, r := range records {
		if strings.Contains(strings.TrimSpace(r), want) {
			return true
		}
	}
	return false
}

// matchToken reports whether the token appears in an arbitrary text body,
// with or without the TXT prefix.
func matchToken(body, token string) bool {
	body = strings.TrimSpace(body)
	return strings.Contains(body, token)
}

var metaTagRE = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
var attrRE = regexp.MustCompile(`(?is)([a-z0-9-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)

// matchMeta parses <meta> tags out of an HTML document and reports whether one
// has name==MetaName and content==token, regardless of attribute order or
// quoting.
func matchMeta(html, token string) bool {
	for _, tag := range metaTagRE.FindAllString(html, -1) {
		var name, content string
		for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
			key := strings.ToLower(m[1])
			val := strings.Trim(m[2], `"'`)
			switch key {
			case "name":
				name = strings.ToLower(val)
			case "content":
				content = val
			}
		}
		if name == MetaName && content == token {
			return true
		}
	}
	return false
}

// ── helpers ──────────────────────────────────────────────────────────────────

func schemeHost(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL must include scheme and host")
	}
	return u.Scheme + "://" + u.Host, nil
}

func fetch(target string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target) //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Cap the read — a verification file/homepage should never be large.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("could not generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ── store persistence ────────────────────────────────────────────────────────

func consentStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trojan", "consent.json")
}

func loadConsentStore() (*consentStore, error) {
	data, err := os.ReadFile(consentStorePath())
	if err != nil {
		return &consentStore{}, err // empty store on first use
	}
	var s consentStore
	if err := json.Unmarshal(data, &s); err != nil {
		return &consentStore{}, err
	}
	return &s, nil
}

func saveConsentStore(s *consentStore) error {
	path := consentStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (s *consentStore) findVerified(host, userEmail string) *ConsentRecord {
	for i := range s.Verified {
		if s.Verified[i].Domain == host && s.Verified[i].UserEmail == userEmail {
			return &s.Verified[i]
		}
	}
	return nil
}

func (s *consentStore) findPending(host, userEmail string) *pendingToken {
	for i := range s.Pending {
		if s.Pending[i].Domain == host && s.Pending[i].UserEmail == userEmail {
			return &s.Pending[i]
		}
	}
	return nil
}

func (s *consentStore) upsertVerified(rec ConsentRecord) {
	for i := range s.Verified {
		if s.Verified[i].Domain == rec.Domain && s.Verified[i].UserEmail == rec.UserEmail {
			s.Verified[i] = rec
			return
		}
	}
	s.Verified = append(s.Verified, rec)
}

func (s *consentStore) removePending(host, userEmail string) {
	out := s.Pending[:0]
	for _, p := range s.Pending {
		if p.Domain == host && p.UserEmail == userEmail {
			continue
		}
		out = append(out, p)
	}
	s.Pending = out
}
