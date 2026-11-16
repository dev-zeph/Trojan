package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

// ── Code-scan triage with a verdict cache ────────────────────────────────────
//
// Every finding of a code scan gets the AI false-alarm check. To keep rescans
// free, each answer is cached in the project's .trojan/memory.db under a key
// made of the rule, the file and a hash of the flagged code plus the lines
// around it. Unchanged code is a cache hit (no AI call); edited code gets a new
// key and is checked again. Moving code up or down the file keeps its key,
// because the line number is not part of it.

// triageCacheVersion is part of every cache key. Bump it when the triage
// prompt or wire format changes enough that old answers should not be trusted.
const triageCacheVersion = "v1"

// cacheWindowRadius is how many lines either side of the flagged line go into
// the code hash. Small on purpose: an edit far away in the same function
// shouldn't pay for a new check, an edit next to the flagged line should.
const cacheWindowRadius = 3

// hideConfidenceFloor is the lowest confidence at which a likely_fp verdict
// hides a code finding. Below it the finding stays visible as needs_manual:
// hiding a real leaked secret is far worse than showing a false alarm.
const hideConfidenceFloor = 0.6

// VerdictStore is the cache the code-scan triage reads and writes.
// *memory.Store satisfies it.
type VerdictStore interface {
	CachedVerdicts(keys []string) (map[string]memory.CachedVerdict, error)
	PutVerdicts(map[string]memory.CachedVerdict) error
}

// CodeTriageStats says where each verdict came from, for progress output and
// cost tracking.
type CodeTriageStats struct {
	Total   int // findings considered
	Memory  int // resolved by a person's earlier decision (free)
	Cached  int // resolved from the verdict cache (free)
	Checked int // sent to the AI
	Hidden  int // likely false alarms (hidden from the list and the score)
}

// CodeTriageOptions configures TriageCodeScan.
type CodeTriageOptions struct {
	ProjectRoot string           // used to resolve relative file paths for hashing
	AccessToken string           // the signed-in user's token; the edge function bills it
	Retriever   ContextRetriever // RAG context for weak first-pass verdicts; nil without an index
	Memory      FalsePositiveSource
	Cache       VerdictStore // nil disables caching
}

// TriageCodeScan runs the AI false-alarm check over every finding of a code
// scan and writes the verdict onto each finding in place.
//
// Order of precedence for each finding:
//  1. a person's decision in project memory ("this is real" / "not real"),
//  2. a cached verdict for the same rule, file and code,
//  3. the AI (TriageWithContext: batched, with RAG escalation when an index
//     exists).
//
// On an AI error the verdicts gathered so far are still applied and cached,
// every other finding is left without a verdict (so it stays visible), and
// the error is returned for the caller to show as a note. Findings are never
// dropped.
func TriageCodeScan(findings []normalizer.Finding, opts CodeTriageOptions) (CodeTriageStats, error) {
	stats := CodeTriageStats{Total: len(findings)}
	if len(findings) == 0 {
		return stats, nil
	}
	normalizer.EnsureUniqueIDs(findings)

	d := loadMemoryDecisions(opts.Memory)
	keys := make([]string, len(findings))
	for i, f := range findings {
		keys[i] = VerdictCacheKey(f, opts.ProjectRoot)
	}
	var cached map[string]memory.CachedVerdict
	if opts.Cache != nil {
		cached, _ = opts.Cache.CachedVerdicts(keys) // a broken cache only costs money
	}

	var toCheck []normalizer.Finding
	keyByID := make(map[string]string)
	for i := range findings {
		f := &findings[i]
		if v, ok := d.verdictFor(*f); ok {
			applyVerdict(f, v)
			stats.Memory++
			continue
		}
		if c, ok := cached[keys[i]]; ok {
			applyVerdict(f, Verdict{Verdict: c.Verdict, Confidence: c.Confidence, Rationale: c.Rationale})
			stats.Cached++
			continue
		}
		keyByID[f.ID] = keys[i]
		toCheck = append(toCheck, withTriageContext(*f, opts.ProjectRoot))
	}

	var err error
	if len(toCheck) > 0 {
		stats.Checked = len(toCheck)
		var got map[string]Verdict
		got, err = TriageWithContext(toCheck, opts.AccessToken, opts.Retriever)
		fresh := make(map[string]memory.CachedVerdict, len(got))
		for i := range findings {
			f := &findings[i]
			key, sent := keyByID[f.ID]
			if !sent {
				continue
			}
			v, ok := got[f.ID]
			if !ok || v.Missing {
				continue // no answer: leave it visible and ask again next scan
			}
			applyVerdict(f, v)
			fresh[key] = memory.CachedVerdict{Verdict: v.Verdict, Confidence: v.Confidence, Rationale: v.Rationale}
		}
		if opts.Cache != nil {
			_ = opts.Cache.PutVerdicts(fresh)
		}
	}

	for _, f := range findings {
		if f.HiddenAsFalseAlarm() {
			stats.Hidden++
		}
	}
	return stats, err
}

// applyVerdict writes a verdict onto a code finding. A likely_fp the model
// wasn't sure of is shown as needs_manual instead of being hidden.
func applyVerdict(f *normalizer.Finding, v Verdict) {
	verdict := v.Verdict
	if verdict == "likely_fp" && v.Confidence < hideConfidenceFloor {
		verdict = "needs_manual"
	}
	f.Verdict = verdict
	f.VerdictReason = v.Rationale
	f.VerdictConfidence = v.Confidence
}

// VerdictCacheKey identifies a finding for the verdict cache: the rule, the
// project-relative file, and a hash of the flagged code plus the lines around
// it. Findings without a line (dependencies) hash their message instead.
func VerdictCacheKey(f normalizer.Finding, projectRoot string) string {
	file := relFile(projectRoot, f.FilePath)
	window := ""
	if f.LineNumber > 0 {
		window = ExtractSurroundingCode(ResolveFindingFile(projectRoot, f.FilePath), f.LineNumber, cacheWindowRadius)
	}
	if window == "" {
		window = f.Title + "\x00" + f.RawMessage
	}
	h := sha256.New()
	for _, part := range []string{triageCacheVersion, f.Scanner, f.RuleID, file, strings.TrimSpace(f.CodeSnippet), normalizeWindow(window)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeWindow drops trailing whitespace per line so a reformat that only
// touches line endings doesn't pay for a new check.
func normalizeWindow(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return strings.Join(lines, "\n")
}

// ResolveFindingFile turns a scanner's (possibly project-relative) path into one that
// can be opened from the current directory.
func ResolveFindingFile(root, p string) string {
	if p == "" || filepath.IsAbs(p) || root == "" {
		return p
	}
	joined := filepath.Join(root, p)
	if fileExists(joined) {
		return joined
	}
	return p
}

// relFile is p relative to root, with forward slashes, for a stable key.
func relFile(root, p string) string {
	if root != "" && filepath.IsAbs(p) {
		if absRoot, err := filepath.Abs(root); err == nil {
			if rel, err := filepath.Rel(absRoot, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// minTriageContextLines is the least code context a static finding is judged
// on. The enclosing-block finder can stop at a tiny object literal (say, a
// map of form labels); the model then can't see what the value is used for.
const minTriageContextLines = 8

// triageContextRadius is the window used when the enclosing block is too small.
const triageContextRadius = 12

// withTriageContext returns a copy of f whose SurroundingCode is at least a
// useful window of the file around the finding. Only the copy sent to triage
// changes; the finding kept for the report is untouched.
func withTriageContext(f normalizer.Finding, projectRoot string) normalizer.Finding {
	if f.LineNumber <= 0 || strings.Count(f.SurroundingCode, "\n")+1 >= minTriageContextLines {
		return f
	}
	if w := ExtractSurroundingCode(ResolveFindingFile(projectRoot, f.FilePath), f.LineNumber, triageContextRadius); w != "" {
		f.SurroundingCode = w
	}
	return f
}
