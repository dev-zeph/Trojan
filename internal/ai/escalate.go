package ai

import (
	"fmt"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// escalateConfidenceThreshold is the verdict confidence below which a finding is
// re-triaged with retrieved code context. Above it (and not needs_manual) the
// first-pass verdict stands — most findings resolve on structural context alone,
// so only the residual pays for retrieval (docs §3.2 self-gating).
const escalateConfidenceThreshold = 0.5

// RetrievedChunk is a piece of related source returned by a ContextRetriever.
type RetrievedChunk struct {
	FilePath  string
	StartLine int
	EndLine   int
	Text      string
}

// ContextRetriever supplies code chunks semantically related to a query. It is
// satisfied by an adapter over rag.Retriever; ai stays free of a rag import (and
// of any import cycle). A nil retriever disables escalation.
type ContextRetriever interface {
	Retrieve(query string, k int) ([]RetrievedChunk, error)
}

// triageImpl is the triage call, injectable so escalation's gate logic can be
// unit-tested without the network. Production uses the real edge function.
var triageImpl = TriageFindings

// retrievalK is how many chunks to inject per escalated finding.
const retrievalK = 4

// TriageWithContext runs adversarial triage, then applies the §3.2 self-gate: any
// finding the first pass couldn't close (verdict needs_manual, or confidence
// below escalateConfidenceThreshold) is re-triaged with semantically-retrieved
// code context injected — the custom sanitizer or missing guard the scanner's
// local view couldn't see. With a nil retriever (no index built) it degrades to
// a plain triage pass, so callers can always use it.
func TriageWithContext(findings []normalizer.Finding, accessToken string, retriever ContextRetriever) (map[string]Verdict, error) {
	verdicts, err := triageImpl(findings, accessToken)
	if err != nil {
		return verdicts, err
	}
	if retriever == nil {
		return verdicts, nil
	}

	// Build the escalation batch: weak-verdict findings, each with retrieved
	// context appended to its SurroundingCode.
	byID := make(map[string]normalizer.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	var escalated []normalizer.Finding
	for id, v := range verdicts {
		if !shouldEscalate(v) {
			continue
		}
		f, ok := byID[id]
		if !ok {
			continue
		}
		chunks, rerr := retriever.Retrieve(retrievalQuery(f), retrievalK)
		if rerr != nil || len(chunks) == 0 {
			continue // retrieval failed or found nothing new — keep first verdict
		}
		f.SurroundingCode = augmentContext(f.SurroundingCode, chunks)
		escalated = append(escalated, f)
	}
	if len(escalated) == 0 {
		return verdicts, nil
	}

	// Re-triage only the escalated subset; overwrite their verdicts.
	reVerdicts, err := triageImpl(escalated, accessToken)
	if err != nil {
		return verdicts, nil // escalation failed — first-pass verdicts still stand
	}
	for id, v := range reVerdicts {
		verdicts[id] = v
	}
	return verdicts, nil
}

// shouldEscalate reports whether a verdict is too weak to trust without more
// context.
func shouldEscalate(v Verdict) bool {
	return v.Verdict == "needs_manual" || v.Confidence < escalateConfidenceThreshold
}

// retrievalQuery turns a finding into a semantic search query.
func retrievalQuery(f normalizer.Finding) string {
	q := f.Title
	if f.CodeSnippet != "" {
		q += "\n" + f.CodeSnippet
	}
	return q
}

// augmentContext appends retrieved chunks to a finding's existing context under a
// clear header, so the triage prompt can distinguish local from retrieved code.
func augmentContext(existing string, chunks []RetrievedChunk) string {
	var b strings.Builder
	b.WriteString(existing)
	b.WriteString("\n\n// ── Related code retrieved from the repository ──\n")
	for _, c := range chunks {
		fmt.Fprintf(&b, "// %s:%d-%d\n%s\n\n", c.FilePath, c.StartLine, c.EndLine, c.Text)
	}
	return b.String()
}
