package dast

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Crawl scrubbing for the website test template request.
//
// The crawler records full URLs, so a page link or form action can carry query
// values (session ids, reset tokens, signed links) and the target URL can carry
// a user:password@ part or a fragment. None of that helps the model write a
// template, and none of it should reach our server, the model provider or the
// template cache. Before a crawl is hashed, cached or sent, every URL keeps only
// its scheme, host, port and path; query values are dropped (parameter names
// stay), the fragment and any user:password@ are dropped, and path segments
// that look like ids or tokens become placeholders.
//
// The dast-templates edge function applies the same rules again
// (supabase/functions/_shared/crawl_scrub.ts), so an old client can't put raw
// values in the cache either. The two implementations share test vectors.

const (
	// ScrubVersion is mixed into the cache key, so a change to these rules
	// never serves a template built under the old rules.
	ScrubVersion = "crawl-scrub-v1"

	maxScrubEndpoints = 200
	maxScrubNames     = 50
	maxNameLen        = 64
	maxHintLen        = 40
)

var (
	uuidSeg     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitsSeg   = regexp.MustCompile(`^[0-9]+$`)
	hexSeg      = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	hasDigit    = regexp.MustCompile(`[0-9]`)
	lettersOnly = regexp.MustCompile(`^[A-Za-z]+$`)
	camelPiece  = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+`)
	hasLetter   = regexp.MustCompile(`[A-Za-z]`)
	safeName    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)
	safeHint    = regexp.MustCompile(`^[a-z0-9._+-]+$`)
	separatorRe = regexp.MustCompile(`[-_.~]`)
)

// personParents are path segments whose child segment is usually a person's
// handle or name (/users/jane-doe, /u/zephaniah, /@jane).
var personParents = map[string]bool{
	"user": true, "users": true, "u": true, "profile": true, "profiles": true,
	"people": true, "person": true, "member": true, "members": true,
	"author": true, "authors": true, "staff": true, "employee": true,
	"employees": true, "customer": true, "customers": true,
	"contacts": true, "student": true, "students": true, "patient": true,
	"patients": true,
}

// routeWords are common child routes of a person parent that are not names.
var routeWords = map[string]bool{
	"new": true, "me": true, "edit": true, "settings": true, "search": true,
	"list": true, "all": true, "index": true, "create": true, "login": true,
	"logout": true, "signin": true, "signup": true, "register": true,
	"sign_in": true, "sign_up": true, "sign-in": true, "sign-up": true,
	"profile": true, "account": true, "admin": true, "export": true,
	"import": true, "invite": true, "invitations": true, "password": true,
	"reset": true, "verify": true, "confirm": true, "current": true,
	"self": true, "api": true, "v1": true, "v2": true, "v3": true,
}

// LooksLikeEmail reports whether a path segment carries an email address or an
// @handle. Any "@" in a segment counts: real routes don't use it.
func LooksLikeEmail(seg string) bool {
	return strings.Contains(seg, "@")
}

// IsPersonParent reports whether seg is a route like /users or /u whose child
// is usually a person's handle or name.
func IsPersonParent(seg string) bool {
	return personParents[strings.ToLower(seg)]
}

// LooksLikePersonName reports whether seg, found right after a person parent,
// should be treated as a name: anything but a number, a placeholder or a
// common route word.
func LooksLikePersonName(seg string) bool {
	if seg == "" || strings.HasPrefix(seg, "{") || digitsSeg.MatchString(seg) {
		return false
	}
	return !routeWords[strings.ToLower(seg)]
}

// ScrubPath scrubs decoded path segments in order, using the previous
// segment as context for names. Empty, "." and ".." segments are dropped.
func ScrubPath(segs []string) []string {
	out := []string{}
	prev := ""
	for _, seg := range segs {
		if i := strings.IndexByte(seg, ';'); i >= 0 { // ;jsessionid=... path params
			seg = seg[:i]
		}
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		s := ScrubSegment(seg)
		if !strings.HasPrefix(s, "{") && IsPersonParent(prev) && LooksLikePersonName(seg) {
			s = "{name}"
		}
		out = append(out, s)
		prev = seg
	}
	return out
}

// ScrubSegment returns the placeholder for a path segment that looks like an
// email, an id or a token, or the segment itself. Short numeric ids stay,
// because the model uses them to spot IDOR candidates; they're not secrets.
func ScrubSegment(seg string) string {
	if seg == "" {
		return ""
	}
	switch {
	case LooksLikeEmail(seg):
		return "{email}"
	case uuidSeg.MatchString(seg):
		return "{uuid}"
	case digitsSeg.MatchString(seg):
		if len(seg) >= 10 {
			return "{num}"
		}
		return seg
	case LooksLikeToken(seg):
		return "{token}"
	}
	return seg
}

// LooksLikeToken reports whether s looks like a credential, session id or other
// opaque value rather than a word or a slug.
func LooksLikeToken(s string) bool {
	if len(s) >= 40 {
		return true
	}
	if strings.HasPrefix(s, "eyJ") && len(s) >= 16 {
		return true
	}
	if hexSeg.MatchString(s) {
		return true
	}
	if strings.ContainsAny(s, "=+/%") && len(s) >= 12 {
		return true
	}
	// A slug splits into short words; a token is one long run of mixed
	// letters and digits, random letters, or a short dense mix.
	for _, part := range separatorRe.Split(s, -1) {
		if len(part) >= 12 && hasDigit.MatchString(part) && hasLetter.MatchString(part) {
			return true
		}
		if len(part) >= 24 {
			return true
		}
		if RandomLetters(part) || ShortMixedToken(part) {
			return true
		}
	}
	return false
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'y', 'A', 'E', 'I', 'O', 'U', 'Y':
		return true
	}
	return false
}

// RandomLetters reports whether a letters-only string of 16 or more
// characters looks random rather than like a word or camelCase name: its
// camelCase pieces average under 3 letters (hQkZpLmW...), or a long piece has
// almost no vowels or a run of 5 or more consonants (qwhzkxmvbnrtplsd).
// internationalization, getUserProfileSettings and gettingstarted survive.
func RandomLetters(s string) bool {
	if len(s) < 16 || !lettersOnly.MatchString(s) {
		return false
	}
	pieces := camelPiece.FindAllString(s, -1)
	if len(pieces) > 0 && float64(len(s))/float64(len(pieces)) < 3 {
		return true
	}
	for _, p := range pieces {
		if len(p) < 6 {
			continue
		}
		vowels, run, maxRun := 0, 0, 0
		for _, r := range p {
			if isVowel(r) {
				vowels++
				run = 0
			} else {
				run++
				if run > maxRun {
					maxRun = run
				}
			}
		}
		if maxRun >= 5 || float64(vowels)/float64(len(p)) < 0.2 {
			return true
		}
	}
	return false
}

// charClass is 0 for lowercase, 1 for uppercase, 2 for a digit, 3 otherwise.
func charClass(r rune) int {
	switch {
	case r >= 'a' && r <= 'z':
		return 0
	case r >= 'A' && r <= 'Z':
		return 1
	case r >= '0' && r <= '9':
		return 2
	}
	return 3
}

// ShortMixedToken reports whether an 8 to 11 character string mixes letters
// and digits densely enough to be a code (aB3dE6gH9jK, a1b2c3d4e5): 6 or more
// switches between lowercase, uppercase and digits. iPhone15Pro, abc123def
// and OAuth2Callback survive.
func ShortMixedToken(s string) bool {
	if len(s) < 8 || len(s) > 11 || !hasDigit.MatchString(s) || !hasLetter.MatchString(s) {
		return false
	}
	switches, prev := 0, -1
	for _, r := range s {
		c := charClass(r)
		if c == 3 {
			return false
		}
		if prev >= 0 && c != prev {
			switches++
		}
		prev = c
	}
	return switches >= 6
}

// hasUnsafeRune reports a backslash or an ASCII control character, which
// browsers and Go's parser read differently. Such URLs are dropped.
func hasUnsafeRune(s string) bool {
	for _, r := range s {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// scrubName keeps a parameter or form field name if it's an ordinary name.
func scrubName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > maxNameLen || !safeName.MatchString(n) || LooksLikeToken(n) {
		return "", false
	}
	return n, true
}

// ScrubNames cleans, dedupes and sorts a list of parameter or field names.
func ScrubNames(names []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range names {
		if c, ok := scrubName(n); ok && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	if len(out) > maxScrubNames {
		out = out[:maxScrubNames]
	}
	return out
}

// ScrubURL returns the URL with only scheme, host, port, a scrubbed path and
// the query parameter names (no values). It returns "" for anything that isn't
// an absolute http or https URL.
func ScrubURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if hasUnsafeRune(raw) {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
		if !(scheme == "https" && p == "443") && !(scheme == "http" && p == "80") {
			host += ":" + p
		}
	}

	var b strings.Builder
	b.WriteString(scheme + "://" + host)
	// u.Path is decoded, so an encoded slash (%2F) splits segments here; the
	// server does the same.
	for _, s := range ScrubPath(strings.Split(u.Path, "/")) {
		if !strings.HasPrefix(s, "{") {
			s = url.PathEscape(s)
		}
		b.WriteString("/" + s)
	}
	if strings.HasSuffix(u.Path, "/") && u.Path != "/" {
		b.WriteString("/")
	}

	names := []string{}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			k = pair[:i]
		}
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		names = append(names, k)
	}
	if clean := ScrubNames(names); len(clean) > 0 {
		b.WriteString("?" + strings.Join(clean, "=&") + "=")
	}
	return b.String()
}

// ScrubTemplateRequest returns a copy of req that is safe to hash, cache and
// send: scrubbed URLs, clean names and hints, endpoints merged and sorted.
func ScrubTemplateRequest(req TemplateRequest) TemplateRequest {
	type acc struct {
		method        string
		url           string
		query, fields []string
	}
	merged := map[string]*acc{}
	for _, e := range req.Endpoints {
		u := ScrubURL(e.URL)
		if u == "" {
			continue
		}
		m := strings.ToUpper(strings.TrimSpace(e.Method))
		if m != "POST" {
			m = "GET"
		}
		key := m + " " + u
		a, ok := merged[key]
		if !ok {
			a = &acc{method: m, url: u}
			merged[key] = a
		}
		a.query = append(a.query, e.QueryParams...)
		a.fields = append(a.fields, e.FormFields...)
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxScrubEndpoints {
		keys = keys[:maxScrubEndpoints]
	}
	eps := make([]Endpoint, 0, len(keys))
	for _, k := range keys {
		a := merged[k]
		eps = append(eps, Endpoint{URL: a.url, Method: a.method, QueryParams: ScrubNames(a.query), FormFields: ScrubNames(a.fields)})
	}

	hints := []string{}
	seen := map[string]bool{}
	for _, h := range req.TechHints {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && len(h) <= maxHintLen && safeHint.MatchString(h) && !seen[h] {
			seen[h] = true
			hints = append(hints, h)
		}
	}
	sort.Strings(hints)

	max := req.MaxTemplates
	if max <= 0 || max > maxTemplates {
		max = maxTemplates
	}
	return TemplateRequest{TargetURL: ScrubURL(req.TargetURL), Endpoints: eps, TechHints: hints, MaxTemplates: max}
}

// CrawlKey is the cache key for a scrubbed request: sha256 over a canonical
// form of everything the prompt uses. The server computes the same value
// (crawlKey in _shared/crawl_scrub.ts) and scopes it to the signed-in user.
func CrawlKey(req TemplateRequest) string {
	s := ScrubTemplateRequest(req)
	var b strings.Builder
	b.WriteString(ScrubVersion + "\n")
	b.WriteString("target " + s.TargetURL + "\n")
	b.WriteString("max " + strconv.Itoa(s.MaxTemplates) + "\n")
	for _, e := range s.Endpoints {
		b.WriteString("ep " + e.Method + " " + e.URL + " q=" + strings.Join(e.QueryParams, ",") + " f=" + strings.Join(e.FormFields, ",") + "\n")
	}
	b.WriteString("hints " + strings.Join(s.TechHints, ",") + "\n")
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
