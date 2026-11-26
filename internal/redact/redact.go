// Package redact replaces secret values with descriptive placeholders before
// any text leaves the machine for an AI provider, and masks them in uploaded
// reports.
//
// Scanner output keeps the raw value locally (the local UI shows it); only the
// copies built for the network are rewritten. Three entry points:
//
//   - Text / Finder.Redact: replace every detected secret with a descriptor
//     such as <SECRET: type=aws_access_key, len=20, prefix=AKIA, entropy=3.7,
//     class=likely_real>. File, line and the surrounding code are untouched, so
//     the model can still reason about how the value is used.
//   - Mask: replace every detected secret with prefix…last4 (e.g. AKIA…WXYZ)
//     for report uploads, which keep their exact locations and code.
//   - Vault: the descriptor form plus a stable ref (ref=S1) that the pen-test
//     agents can hand back in tool inputs and that is mapped back to the raw
//     value locally, never on the wire.
//
// Every match is classified by local pre-checks (entropy, placeholder words,
// test/fixture/example paths, provider checksums). Classification only
// annotates the descriptor: redaction applies whatever the class.
package redact

import (
	"fmt"
	"hash/crc32"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Class is the local pre-check verdict on a secret value.
type Class string

const (
	LikelyReal        Class = "likely_real"
	LikelyPlaceholder Class = "likely_placeholder"
)

// Secret is one detected secret value inside a text.
type Secret struct {
	Start, End int    // byte offsets of the value in the text
	Value      string // the raw value (never put this on the wire)
	Type       string // e.g. aws_access_key, github_token, generic_secret
}

// detector finds one secret type. group is the regexp submatch holding the
// value (0 = whole match). check, when set, rejects a candidate value that is
// not secret-like (used by the generic rules so ordinary code is left alone).
type detector struct {
	typ   string
	re    *regexp.Regexp
	group int
	check func(v string) bool
	hints []string // cheap pre-filter: skip the regexp unless one appears (lower-case = case-insensitive)
}

// Provider formats first (most specific), generic assignment rules last. A
// later detector never overrides an overlapping earlier match.
var detectors = []detector{
	{typ: "private_key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\\n]*(?:[A-Za-z0-9+/=]{8,}|[A-Za-z-]+: [^\n]*))+[\s\\n]*(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)?`), hints: []string{"PRIVATE KEY"}},
	{typ: "aws_access_key", re: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16})\b`), group: 1, hints: []string{"AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA"}},
	{typ: "aws_secret_key", re: regexp.MustCompile(`(?i)aws[a-z0-9_.\-]{0,20}?(?:secret|sk)[a-z0-9_.\-]*["']?\s*(?:[:=]|=>)\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`), group: 1, hints: []string{"aws"}},
	{typ: "github_fine_grained_pat", re: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`), group: 1, hints: []string{"github_pat_"}},
	{typ: "github_token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,251})\b`), group: 1, hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
	{typ: "npm_token", re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), group: 1, hints: []string{"npm_"}},
	{typ: "stripe_secret_key", re: regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,247})\b`), group: 1, hints: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}},
	{typ: "stripe_webhook_secret", re: regexp.MustCompile(`\b(whsec_[A-Za-z0-9]{24,})\b`), group: 1, hints: []string{"whsec_"}},
	{typ: "slack_token", re: regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9-]{10,})\b`), group: 1, hints: []string{"xox"}},
	{typ: "slack_webhook", re: regexp.MustCompile(`hooks\.slack\.com/services/(T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,})`), group: 1, hints: []string{"hooks.slack.com"}},
	{typ: "google_api_key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})`), group: 1, hints: []string{"AIza"}},
	{typ: "anthropic_api_key", re: regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_\-]{20,})`), group: 1, hints: []string{"sk-ant-"}},
	{typ: "openai_api_key", re: regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})`), group: 1, hints: []string{"sk-"}},
	{typ: "sendgrid_api_key", re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), group: 1, hints: []string{"SG."}},
	{typ: "twilio_api_key", re: regexp.MustCompile(`\b(SK[0-9a-f]{32})\b`), group: 1, hints: []string{"SK"}},
	{typ: "jwt", re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*)`), group: 1, hints: []string{"eyJ"}},
	{typ: "url_password", re: regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@"'<>]{1,64}:([^\s@/"'<>]{3,128})@`), group: 1, check: notTemplateRef, hints: []string{"://"}},
	{typ: "authorization_header", re: regexp.MustCompile(`(?i)\b(?:authorization|proxy-authorization)["']?\s*[:=]\s*["']?(?:bearer|basic|token|apikey)\s+([A-Za-z0-9._~+/=\-]{8,})`), group: 1, check: notTemplateRef, hints: []string{"authorization"}},
	{typ: "session_cookie", re: regexp.MustCompile(`(?i)\b(?:[a-z0-9_.\-]*(?:session|sess|sid|token|auth|jwt)[a-z0-9_.\-]*)=([A-Za-z0-9%._~+/\-]{16,}={0,2})`), group: 1, check: looksRandom, hints: []string{"session", "sess", "sid", "token", "auth", "jwt"}},
	// Generic: a secret-named key assigned a quoted literal.
	{typ: "generic_secret", re: regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|pwd|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credentials?|bearer)[a-z0-9_\-]*["']?\s*(?:[:=]|=>|:=)\s*["'` + "`" + `]([^"'` + "`" + `\s]{6,256})["'` + "`" + `]`), group: 1, check: genericValueOK, hints: []string{"key", "secret", "token", "passw", "pwd", "credential", "bearer"}},
	// Generic: .env / shell style uppercase NAME=value (unquoted).
	{typ: "generic_secret", re: regexp.MustCompile(`(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|CREDENTIALS?)[A-Z0-9_]*\s*=\s*([^\s"'#]{6,256})`), group: 1, check: genericValueOK, hints: []string{"key", "secret", "token", "pass", "pwd", "credential"}},
	// Generic: YAML style secret-named key with an unquoted scalar.
	{typ: "generic_secret", re: regexp.MustCompile(`(?im)^\s*[a-z0-9_\-]*(?:password|passwd|secret|token|api[_\-]?key|private[_\-]?key|client[_\-]?secret)[a-z0-9_\-]*:[ \t]+([^\s"'#{}\[\]]{8,256})[ \t]*$`), group: 1, check: func(v string) bool { return genericValueOK(v) && looksRandom(v) }, hints: []string{"key", "secret", "token", "passw", "pwd", "credential", "bearer"}},
}

// Find returns every secret detected in text, sorted by position, with no
// overlaps (earlier/more specific detectors win).
func Find(text string) []Secret {
	if text == "" {
		return nil
	}
	var out []Secret
	taken := func(s, e int) bool {
		for _, o := range out {
			if s < o.End && e > o.Start {
				return true
			}
		}
		return false
	}
	lower := strings.ToLower(text)
	for _, d := range detectors {
		if !hinted(text, lower, d.hints) {
			continue
		}
		for _, m := range d.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[2*d.group], m[2*d.group+1]
			if s < 0 || e <= s {
				continue
			}
			v := text[s:e]
			if d.check != nil && !d.check(v) {
				continue
			}
			if taken(s, e) {
				continue
			}
			out = append(out, Secret{Start: s, End: e, Value: v, Type: d.typ})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// hinted reports whether any hint occurs; lower-case hints match
// case-insensitively. No hints = always run.
func hinted(text, lower string, hints []string) bool {
	if len(hints) == 0 {
		return true
	}
	for _, h := range hints {
		if h == strings.ToLower(h) {
			if strings.Contains(lower, h) {
				return true
			}
		} else if strings.Contains(text, h) {
			return true
		}
	}
	return false
}

// ── value checks for the generic rules ───────────────────────────────────────

var (
	reTemplateRef = regexp.MustCompile(`^(?:\$\{?|\{\{|%\(|<%|process\.env|os\.(?:Getenv|environ)|env\(|ENV\[)`)
	reWordy       = regexp.MustCompile(`^[a-z]+(?:[\-_. ][a-z]+)*$|^[A-Z][a-z]+(?:[A-Z][a-z]+)*$|^[A-Z]+(?:_[A-Z]+)*$`)
	reCodeish     = regexp.MustCompile(`[()\[\];]|^https?://|^/|^\./|^\.\./|^[a-z]+\.[a-zA-Z_.]+$`)
)

func notTemplateRef(v string) bool { return !reTemplateRef.MatchString(v) }

// genericValueOK rejects values that are clearly code or prose, not a
// credential: env/template references, function calls, paths, and plain
// words (UI labels like "Password", identifiers like "my-app-secrets",
// slots like "your_api_key"). Those are not secrets, and triage needs to see
// them as they are to call them false alarms. Anything with digits or mixed
// symbols passes and is redacted (then classified, e.g. changeme123 as a
// placeholder).
func genericValueOK(v string) bool {
	if !notTemplateRef(v) || reCodeish.MatchString(v) {
		return false
	}
	return !reWordy.MatchString(v)
}

// looksRandom is a stricter check for unquoted / cookie values: long enough
// and with enough character variety to be a token rather than a word.
func looksRandom(v string) bool {
	if len(v) < 8 || reWordy.MatchString(v) {
		return false
	}
	return Entropy(v) >= 3.0
}

// ── classification (local pre-checks) ────────────────────────────────────────

var rePlaceholder = regexp.MustCompile(`(?i)x{4,}|\*{3,}|\.{3,}|change[_\-]?me|replace[_\-]?(?:me|this)|your[_\-]?(?:own[_\-]?)?(?:api[_\-]?)?(?:key|token|secret|password|pass)|example|dummy|sample|placeholder|insert[_\-]?(?:here|key|token)|fake|foo[_\-]?bar|lorem|redacted|todo|fixme|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|^(?:test|testing|password|passwd|secret|token|admin|root|default)\d*$|^(?:0+|1234567\d*|12345678\d*|abcdef\w*|qwerty\w*)$`)

// knownPublicExamples are documentation keys published by the providers
// themselves (AWS docs, Stripe docs). They are not secrets.
// Split literals keep secret scanners from flagging this file.
var knownPublicExamples = map[string]bool{
	"AKIA" + "IOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY": true,
	"sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc":         true,
	"sk_" + "test_BQokikJOvBiI2HlWgH4olfQ2":         true,
}

var reTestPath = regexp.MustCompile(`(?i)(?:^|[/\\])(?:tests?|__tests__|specs?|fixtures?|testdata|test[_\-]?data|mocks?|__mocks__|examples?|samples?|demo)(?:[/\\]|$)|(?:_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|_spec\.rb|test_[^/\\]*\.py)$|\.(?:example|sample|template|tmpl|dist|defaults?)(?:\.[a-z0-9]+)?$|\.env\.(?:example|sample|template|dist|defaults?)$`)

func isPlaceholder(v string) bool { return rePlaceholder.MatchString(v) || knownPublicExamples[v] }

// IsTestPath reports whether a file path looks like a test, fixture, example
// or template file (where committed keys are usually fake).
func IsTestPath(path string) bool { return path != "" && reTestPath.MatchString(path) }

// Assessment is the result of the local pre-checks on one value.
type Assessment struct {
	Class  Class
	Checks []string // which signals fired, e.g. checksum_ok, placeholder_pattern, test_path
}

// Classify runs the local pre-checks. path may be "" when unknown.
func Classify(value, typ, path string) Assessment {
	var checks []string
	placeholder := false
	real := false

	if knownPublicExamples[value] {
		checks = append(checks, "provider_docs_example")
		placeholder = true
	} else if isPlaceholder(value) {
		checks = append(checks, "placeholder_pattern")
		placeholder = true
	}
	switch ok, applies := providerChecksum(value, typ); {
	case applies && ok:
		checks = append(checks, "checksum_ok")
		real = !placeholder
	case applies && !ok:
		checks = append(checks, "checksum_invalid")
		placeholder = true
	}
	if lowVariety(value) {
		checks = append(checks, "low_entropy")
		placeholder = true
	}
	if IsTestPath(path) {
		checks = append(checks, "test_path")
	}

	class := LikelyReal
	switch {
	case real:
		class = LikelyReal
	case placeholder:
		class = LikelyPlaceholder
	case IsTestPath(path) && Entropy(value) < 4.0:
		// A test/fixture path alone is weak evidence; combined with a value that
		// is not strongly random, call it a placeholder.
		class = LikelyPlaceholder
	}
	return Assessment{Class: class, Checks: checks}
}

// lowVariety flags values made of very few distinct characters (aaaaaaaa,
// 00000000, abababab) — never real generated credentials.
func lowVariety(v string) bool {
	if len(v) < 8 {
		return false
	}
	seen := map[rune]bool{}
	for _, r := range v {
		seen[r] = true
	}
	return len(seen) <= 3 || (len(v) >= 16 && Entropy(v) < 2.0)
}

// providerChecksum validates the built-in checksum of formats that carry one:
// GitHub classic tokens (gh[pousr]_) and npm tokens (npm_) end in base62
// CRC32 of the 30-char random body. applies=false when the format has none.
func providerChecksum(v, typ string) (ok, applies bool) {
	switch typ {
	case "github_token", "npm_token":
	default:
		return false, false
	}
	i := strings.IndexByte(v, '_')
	if i < 0 {
		return false, false
	}
	body := v[i+1:]
	if len(body) != 36 { // only the classic 36-char body carries this checksum
		return false, false
	}
	payload, sum := body[:30], body[30:]
	return base62(crc32.ChecksumIEEE([]byte(payload)), 6) == sum, true
}

const b62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62(n uint32, width int) string {
	var b []byte
	for {
		b = append([]byte{b62[n%62]}, b...)
		n /= 62
		if n == 0 {
			break
		}
	}
	for len(b) < width {
		b = append([]byte{'0'}, b...)
	}
	return string(b)
}

// Entropy is the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// ── descriptor & mask ────────────────────────────────────────────────────────

// visiblePrefix is how much of the value a descriptor may show: 4 chars for
// values of 16+ chars (usually a provider prefix such as AKIA or ghp_), 2 for
// 10-15, none for shorter values, where 4 chars would be a large share of the
// secret. Private keys never show a prefix.
func visiblePrefix(v, typ string) string {
	if typ == "private_key" {
		return ""
	}
	if p := providerPrefix(v); p != "" && len(v) >= 16 {
		return p
	}
	switch {
	case len(v) >= 16:
		return safePrefix(v, 4)
	case len(v) >= 10:
		return safePrefix(v, 2)
	}
	return ""
}

// reProviderPrefix matches the public, fixed part of provider key formats.
// Showing it (sk_live_ vs sk_test_, ghp_, AKIA) is what lets triage tell a
// live key from a test key; it carries no secret entropy.
var reProviderPrefix = regexp.MustCompile(`^(?:(?:sk|rk)_(?:live|test)_|gh[pousr]_|github_pat_|npm_|xox[abposr]-|sk-ant-(?:api\d+-|admin\d+-)?|sk-(?:proj-|svcacct-|admin-)?|SG\.|AIza|whsec_|(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)|eyJ)`)

func providerPrefix(v string) string { return reProviderPrefix.FindString(v) }

// SafePrefixFor returns the public prefix a descriptor would show for a secret
// (the provider prefix when there is one, else a few leading chars). Exported
// so the preview/MCP layer can display it without re-deriving it.
func SafePrefixFor(s Secret) string { return visiblePrefix(s.Value, s.Type) }

func safePrefix(v string, n int) string {
	if len(v) < n {
		return ""
	}
	return strings.ToValidUTF8(v[:n], "")
}

// Descriptor renders the placeholder sent to an AI provider for one value.
// ref is optional (pen-test agents use it to hand the value back by name).
func Descriptor(s Secret, path, ref string) string {
	a := Classify(s.Value, s.Type, path)
	var b strings.Builder
	b.WriteString("<SECRET: ")
	if ref != "" {
		fmt.Fprintf(&b, "ref=%s, ", ref)
	}
	fmt.Fprintf(&b, "type=%s, len=%d", s.Type, len(s.Value))
	if p := visiblePrefix(s.Value, s.Type); p != "" {
		fmt.Fprintf(&b, ", prefix=%s", p)
	}
	fmt.Fprintf(&b, ", entropy=%.1f, class=%s", Entropy(s.Value), a.Class)
	if len(a.Checks) > 0 {
		fmt.Fprintf(&b, ", checks=%s", strings.Join(a.Checks, "+"))
	}
	if s.Type == "jwt" {
		if info := jwtInfo(s.Value); info != "" {
			b.WriteString(", " + info)
		}
	}
	b.WriteString(">")
	return b.String()
}

// MaskValue renders the upload form of one value: prefix…last4 for values of
// 16+ chars, first2…last2 for 10-15, and a length-only mask for anything
// shorter (where prefix+last4 would reveal most of it). Private keys keep
// their BEGIN line only.
func MaskValue(s Secret) string {
	v := s.Value
	if s.Type == "private_key" {
		head := v
		if i := strings.Index(v, "-----\n"); i >= 0 {
			head = v[:i+5]
		} else if j := strings.Index(v[min(len(v), 11):], "-----"); j >= 0 {
			head = v[:11+j+5]
		}
		return fmt.Sprintf("%s…[private key, %d chars masked]", head, len(v))
	}
	switch {
	case len(v) >= 16:
		p := providerPrefix(v)
		if p == "" || len(p) > len(v)-8 {
			p = safePrefix(v, 4)
		}
		return p + "…" + v[len(v)-4:]
	case len(v) >= 10:
		return safePrefix(v, 2) + "…" + v[len(v)-2:]
	}
	return fmt.Sprintf("[masked, %d chars]", len(v))
}

// ── Finder: detection plus exact values known out of band ───────────────────

// Finder detects secrets by pattern and also replaces exact values the caller
// already knows are secret (a gitleaks match, a captured session token).
type Finder struct {
	known []Secret // Value+Type only; offsets unused
	Path  string   // file path, for the test/fixture pre-check
}

// Known registers exact secret values (shortest ones under 4 chars are ignored
// so a stray "a" never blanks a file).
func (f *Finder) Known(typ string, values ...string) {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) < 4 {
			continue
		}
		dup := false
		for _, k := range f.known {
			if k.Value == v {
				dup = true
				break
			}
		}
		if !dup {
			f.known = append(f.known, Secret{Value: v, Type: typ})
		}
	}
}

// find merges pattern hits with occurrences of known values.
func (f *Finder) find(text string) []Secret {
	hits := Find(text)
	if len(f.known) == 0 {
		return hits
	}
	// Longest known values first so a token wins over its own prefix.
	known := append([]Secret(nil), f.known...)
	sort.Slice(known, func(i, j int) bool { return len(known[i].Value) > len(known[j].Value) })
	var extra []Secret
	overlaps := func(s, e int) bool {
		for _, h := range hits {
			if s < h.End && e > h.Start {
				return true
			}
		}
		for _, h := range extra {
			if s < h.End && e > h.Start {
				return true
			}
		}
		return false
	}
	for _, k := range known {
		from := 0
		for {
			i := strings.Index(text[from:], k.Value)
			if i < 0 {
				break
			}
			s, e := from+i, from+i+len(k.Value)
			if !overlaps(s, e) {
				extra = append(extra, Secret{Start: s, End: e, Value: k.Value, Type: k.Type})
			} else {
				// A pattern hit inside a known value (e.g. the token part of a
				// known "Bearer x") is replaced by the wider known span.
				var kept []Secret
				for _, h := range hits {
					// Strictly wider only: a pattern hit on exactly the known
					// value keeps its more specific type (aws_access_key).
					if s <= h.Start && h.End <= e && e-s > h.End-h.Start {
						continue
					}
					kept = append(kept, h)
				}
				if len(kept) != len(hits) && !overlapsAny(kept, s, e) && !overlapsAny(extra, s, e) {
					hits = kept
					extra = append(extra, Secret{Start: s, End: e, Value: k.Value, Type: k.Type})
				}
			}
			from = e
		}
	}
	all := append(hits, extra...)
	sort.Slice(all, func(i, j int) bool { return all[i].Start < all[j].Start })
	return all
}

func overlapsAny(list []Secret, s, e int) bool {
	for _, h := range list {
		if s < h.End && e > h.Start {
			return true
		}
	}
	return false
}

// replace rewrites every secret in text with render(secret).
func (f *Finder) replace(text string, render func(Secret) string) string {
	hits := f.find(text)
	if len(hits) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, h := range hits {
		b.WriteString(text[last:h.Start])
		b.WriteString(render(h))
		last = h.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Redact replaces every secret in text with its AI descriptor.
func (f *Finder) Redact(text string) string {
	return f.replace(text, func(s Secret) string { return Descriptor(s, f.Path, "") })
}

// Mask replaces every secret in text with its upload mask (prefix…last4).
func (f *Finder) Mask(text string) string {
	return f.replace(text, MaskValue)
}

// Text redacts a free-standing text (no known values, no path).
func Text(s string) string { return (&Finder{}).Redact(s) }

// Mask masks a free-standing text for upload.
func Mask(s string) string { return (&Finder{}).Mask(s) }

// Contains reports whether text holds any detectable secret.
func Contains(s string) bool { return len(Find(s)) > 0 }
