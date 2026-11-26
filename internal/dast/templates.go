package dast

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	dastTemplatesURL = "https://dtmocojzvgsswjdsrmqr.supabase.co/functions/v1/dast-templates"
	templateCacheTTL = 24 * time.Hour
	maxTemplates     = 10
)

// TemplateRequest is sent to the dast-templates edge function.
type TemplateRequest struct {
	TargetURL    string     `json:"targetURL"`
	Endpoints    []Endpoint `json:"endpoints"`
	TechHints    []string   `json:"techHints"`
	MaxTemplates int        `json:"maxTemplates"`
}

// TemplateResponse is returned by the dast-templates edge function.
type TemplateResponse struct {
	Templates []string `json:"templates"` // Nuclei YAML strings
	Rationale string   `json:"rationale"`
}

// GenerateTemplates calls the dast-templates edge function to generate custom
// Nuclei YAML templates for the crawled application. Results are cached locally
// for 24 hours based on the crawl content hash.
func GenerateTemplates(req TemplateRequest, accessToken string) (*TemplateResponse, error) {
	hash := crawlHash(req)

	// Check local cache first.
	if cached := loadTemplateCache(hash); cached != nil {
		return cached, nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, dastTemplatesURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("template generation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck
		if errBody.Error == "rate_limit_exceeded" {
			return nil, fmt.Errorf("rate_limit_exceeded")
		}
		return nil, fmt.Errorf("template generation failed (status %d)", resp.StatusCode)
	}

	var result TemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	saveTemplateCache(hash, &result)
	return &result, nil
}

// WriteTemplatesToDir writes the YAML templates from a TemplateResponse into
// the given directory, creating it if necessary. Returns the directory path.
func WriteTemplatesToDir(resp *TemplateResponse, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	n := 0
	for i, tmpl := range resp.Templates {
		out, ok := SetTemplateID(tmpl, n+1)
		if !ok {
			continue // flow-style: its id can't be rewritten safely
		}
		path := filepath.Join(dir, fmt.Sprintf("template_%03d.yaml", n))
		if err := os.WriteFile(path, []byte(out), 0600); err != nil {
			return fmt.Errorf("writing template %d: %w", i, err)
		}
		n++
	}
	return nil
}

// crawlHash returns a stable hex hash of the crawl content for cache keying.
func crawlHash(req TemplateRequest) string {
	urls := make([]string, len(req.Endpoints))
	for i, e := range req.Endpoints {
		urls[i] = e.Method + ":" + e.URL
	}
	sort.Strings(urls)

	hints := append([]string{}, req.TechHints...)
	sort.Strings(hints)

	raw := req.TargetURL + "|" + fmt.Sprint(urls) + "|" + fmt.Sprint(hints)
	h := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", h)
}

func templateCacheDir(hash string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trojan", "cache", "dast-templates", hash)
}

func loadTemplateCache(hash string) *TemplateResponse {
	dir := templateCacheDir(hash)
	metaPath := filepath.Join(dir, "meta.json")

	info, err := os.Stat(metaPath)
	if err != nil || time.Since(info.ModTime()) > templateCacheTTL {
		return nil
	}

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}

	var resp TemplateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	return &resp
}

func saveTemplateCache(hash string, resp *TemplateResponse) {
	dir := templateCacheDir(hash)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, "meta.json"), data, 0600) //nolint:errcheck
}

// templateIDKey matches a top-level id key in block style, however it is
// written: id:, "id":, 'id': or id : (a top-level key starts in column 0).
// Group 1 is the value after the colon.
var templateIDKey = regexp.MustCompile(`^(?:"id"|'id'|id)[ \t]*:(.*)$`)

// firstContentLine is the template's first line that is not blank, a comment
// or a bare document marker. A marker that shares its line with content
// ("--- {id: x}") gives that content.
func firstContentLine(t string) string {
	for _, line := range strings.Split(t, "\n") {
		l := strings.TrimRight(line, "\r")
		if trimmed := strings.TrimSpace(l); strings.HasPrefix(trimmed, "---") &&
			(len(trimmed) == 3 || trimmed[3] == ' ' || trimmed[3] == '\t') && l == strings.TrimLeft(l, " \t") {
			l = strings.TrimLeft(trimmed[3:], " \t")
		}
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return l
	}
	return ""
}

// isFlowStyleTemplate reports whether the template's top level is a flow
// mapping ({id: x, info: ...}), also after a document marker (--- {id: x}).
func isFlowStyleTemplate(t string) bool {
	return strings.HasPrefix(strings.TrimSpace(firstContentLine(t)), "{")
}

// unsafeTemplate says why a template's id can't be rewritten safely without a
// YAML parser, or "" when it can. Nuclei templates are written as plain block
// mappings, so these are rejected rather than guessed at:
//   - flow style: {id: x} or --- {id: x}
//   - an indented top level ("  id: x" with every key indented): a column 0
//     id would not be part of that mapping
//   - explicit keys ("? id"), which can hide the id key
//   - an id with an anchor or alias (id: &a x, id: *a): renaming would break
//     the alias or keep the old value
func unsafeTemplate(t string) string {
	first := firstContentLine(t)
	switch {
	case strings.HasPrefix(strings.TrimSpace(first), "{"):
		return "flow style"
	case first != "" && (first[0] == ' ' || first[0] == '\t'):
		return "indented top level"
	}
	for _, line := range strings.Split(t, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "?" || strings.HasPrefix(line, "? ") || strings.HasPrefix(line, "?\t") {
			return "explicit key"
		}
		if m := templateIDKey.FindStringSubmatch(line); m != nil {
			if v := strings.TrimSpace(m[1]); strings.HasPrefix(v, "&") || strings.HasPrefix(v, "*") {
				return "anchor or alias on id"
			}
		}
	}
	return ""
}

// SetTemplateID gives an AI-written website test the id trojan-custom-NNN.
// The model names templates after the site ("alphapets-loyalty-api-idor"), and
// nuclei reports that id as the finding's rule id, which would carry the site's
// name into rule-keyed places such as the shared explanation cache. The server
// (dast-templates, _shared/template_id.ts) does the same rewrite, so either side
// alone is enough.
//
// A leading byte order mark is dropped. The first top-level id line is
// replaced in place, later ones are removed, and one is added when there is
// none. An id's value can run onto indented lines (a block scalar such as
// "id: >-" or a plain value that wraps); those lines go with it, so no part of
// the old id survives. ok is false for a template unsafeTemplate rejects,
// which the caller skips.
func SetTemplateID(template string, n int) (out string, ok bool) {
	t := strings.TrimPrefix(template, "\uFEFF")
	if unsafeTemplate(t) != "" {
		return "", false
	}
	id := fmt.Sprintf("id: trojan-custom-%03d", n)
	lines := strings.Split(t, "\n")
	kept := make([]string, 0, len(lines)+1)
	found := false
	for i := 0; i < len(lines); i++ {
		if !templateIDKey.MatchString(strings.TrimRight(lines[i], "\r")) {
			kept = append(kept, lines[i])
			continue
		}
		// Skip the value's continuation: indented lines, and blank lines
		// followed by more indented lines.
		j := i + 1
		for j < len(lines) {
			if isIndented(lines[j]) {
				j++
				continue
			}
			if strings.TrimSpace(lines[j]) == "" {
				k := j
				for k < len(lines) && strings.TrimSpace(lines[k]) == "" {
					k++
				}
				if k < len(lines) && isIndented(lines[k]) {
					j = k
					continue
				}
			}
			break
		}
		if !found {
			kept = append(kept, id) // the first id keeps its place
			found = true
		}
		i = j - 1
	}
	if found {
		return strings.Join(kept, "\n"), true
	}
	if strings.HasPrefix(t, "---\n") {
		return "---\n" + id + "\n" + t[len("---\n"):], true
	}
	return id + "\n" + t, true
}

// isIndented reports whether a line starts with a space or tab and has content.
func isIndented(line string) bool {
	return (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && strings.TrimSpace(line) != ""
}
