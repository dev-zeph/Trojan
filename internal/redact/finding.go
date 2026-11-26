package redact

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// isSecretFinding reports whether a finding's CodeSnippet is, by the scanner's
// own judgement, a leaked secret (gitleaks puts the raw match there).
func isSecretFinding(f normalizer.Finding) bool {
	return f.Scanner == "gitleaks" || strings.EqualFold(f.Category, "secrets")
}

var reAssignedValue = regexp.MustCompile(`(?:[:=]|=>)\s*["'` + "`" + `]?([^"'` + "`" + `\s,;]{4,})["'` + "`" + `]?\s*[,;]?\s*$`)

// ValuesFromMatch extracts the secret value(s) from a secret scanner's match
// text when no pattern recognises them: the value after the last = or :, or
// the whole match when it is a bare token.
func ValuesFromMatch(match string) []string {
	match = strings.TrimSpace(match)
	if match == "" {
		return nil
	}
	if hits := Find(match); len(hits) > 0 {
		out := make([]string, 0, len(hits))
		for _, h := range hits {
			out = append(out, h.Value)
		}
		return out
	}
	if m := reAssignedValue.FindStringSubmatch(match); m != nil {
		return []string{m[1]}
	}
	if !strings.ContainsAny(match, " \t\n") {
		return []string{strings.Trim(match, `"'`+"`")}
	}
	return nil
}

// FinderFor builds a Finder for one finding: pattern detection plus the
// scanner's own match values for secret findings, with the file path for the
// test/fixture pre-check.
func FinderFor(f normalizer.Finding) *Finder {
	fd := &Finder{Path: f.FilePath}
	if f.SourceFile != "" && fd.Path == "" {
		fd.Path = f.SourceFile
	}
	if isSecretFinding(f) {
		typ := "secret_" + strings.ToLower(strings.ReplaceAll(f.RuleID, " ", "_"))
		if f.RuleID == "" {
			typ = "secret"
		}
		fd.Known(typ, ValuesFromMatch(f.CodeSnippet)...)
	}
	return fd
}

// ForAI returns a copy of f whose free-text fields carry descriptors instead
// of secret values. Location (file, line, URL) and all other code are kept.
func ForAI(f normalizer.Finding) normalizer.Finding {
	fd := FinderFor(f)
	f.CodeSnippet = fd.Redact(f.CodeSnippet)
	f.SurroundingCode = fd.Redact(f.SurroundingCode)
	f.RawMessage = fd.Redact(f.RawMessage)
	f.Title = fd.Redact(f.Title)
	return f
}

// ForAIAll applies ForAI to a slice (the input is not modified).
func ForAIAll(in []normalizer.Finding) []normalizer.Finding {
	out := make([]normalizer.Finding, len(in))
	for i, f := range in {
		out[i] = ForAI(f)
	}
	return out
}

// ForUpload returns a copy of f for a report upload: every secret value in
// every string field is masked to prefix…last4. File, line, rule and the
// surrounding code stay exactly as they are.
func ForUpload(f normalizer.Finding) normalizer.Finding {
	fd := FinderFor(f)
	b, err := json.Marshal(f)
	if err != nil {
		return f
	}
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return f
	}
	// Location fields are never secrets; leave them byte-exact.
	keep := map[string]bool{"ID": true, "FilePath": true, "LineNumber": true, "RuleID": true, "Scanner": true, "Category": true, "source_file": true, "url": true}
	if m, ok := doc.(map[string]any); ok {
		for k, v := range m {
			if keep[k] {
				continue
			}
			m[k] = walkStrings(v, fd.Mask)
		}
	}
	b, err = json.Marshal(doc)
	if err != nil {
		return f
	}
	var out normalizer.Finding
	if json.Unmarshal(b, &out) != nil {
		return f
	}
	return out
}

// ForUploadAll applies ForUpload to a slice (the input is not modified).
func ForUploadAll(in []normalizer.Finding) []normalizer.Finding {
	if in == nil {
		return nil
	}
	out := make([]normalizer.Finding, len(in))
	for i, f := range in {
		out[i] = ForUpload(f)
	}
	return out
}
