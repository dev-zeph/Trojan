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
	hasLetter   = regexp.MustCompile(`[A-Za-z]`)
	safeName    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)
	safeHint    = regexp.MustCompile(`^[a-z0-9._+-]+$`)
	separatorRe = regexp.MustCompile(`[-_.~]`)
)

// ScrubSegment returns the placeholder for a path segment that looks like an id
// or a token, or the segment itself. Short numeric ids stay, because the model
// uses them to spot IDOR candidates; they're not secrets.
func ScrubSegment(seg string) string {
	if seg == "" {
		return ""
	}
	switch {
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
	// letters and digits.
	for _, part := range separatorRe.Split(s, -1) {
		if len(part) >= 12 && hasDigit.MatchString(part) && hasLetter.MatchString(part) {
			return true
		}
		if len(part) >= 24 {
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
	u, err := url.Parse(strings.TrimSpace(raw))
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
	for _, seg := range strings.Split(u.Path, "/") {
		if i := strings.IndexByte(seg, ';'); i >= 0 { // ;jsessionid=... path params
			seg = seg[:i]
		}
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		s := ScrubSegment(seg)
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
