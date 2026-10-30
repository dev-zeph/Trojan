package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	whitebox "github.com/dev-zeph/trojan/internal/agent"
	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/graphstore"
	"github.com/dev-zeph/trojan/internal/memory"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/orgcontext"
)

// The "security brain" wiring for the agentic pen-test: what Trojan already
// knows about the app (org context, code graph, per-project memory) is folded
// into the agent's seed task, memory short-circuits triage for findings the
// user already dismissed, and confirmed results are written back so the next
// run starts smarter.

// brainSeedCap bounds the brain section of the seed task, in characters. The
// seed is paid for on every turn of the agent loop, so it stays compact.
const brainSeedCap = 6000

// Per-list caps inside the seed; each list is cut to its cap before the
// overall brainSeedCap trims whatever is left.
const (
	brainMaxExposed  = 12
	brainMaxPaths    = 8
	brainMaxMemory   = 8
	brainMaxFPs      = 8
	brainEvidenceLen = 160
	brainMaxHyps     = 8
)

// buildBrainSeed returns a compact "what we already know" block for the
// pen-test agent's task, or "" when nothing is known about projectRoot. Each
// section (org context, code graph, memory) is dropped on its own when its
// source is missing or unreadable, so a project with only a graph still gets
// the graph part.
func buildBrainSeed(projectRoot string) string {
	return brainSeed(projectRoot, projectRoot)
}

// brainSeed is buildBrainSeed with the memory store located separately: a
// website test with no project folder keeps its memory in the site's
// ~/.trojan/website-tests directory (memRoot) but has no context or graph.
func brainSeed(projectRoot, memRoot string) string {
	var sections []string
	if projectRoot != "" {
		if s := contextSection(projectRoot); s != "" {
			sections = append(sections, s)
		}
		if s := graphSection(projectRoot); s != "" {
			sections = append(sections, s)
		}
	}
	if memRoot != "" {
		if s := memorySection(memRoot); s != "" {
			sections = append(sections, s)
		}
	}
	if projectRoot != "" {
		if s := hypothesesSection(projectRoot); s != "" {
			sections = append(sections, s)
		}
	}
	if len(sections) == 0 {
		return ""
	}
	out := "WHAT TROJAN ALREADY KNOWS ABOUT THIS APP (from the project's own source and past runs; use it to aim your probes, and verify before reporting):\n\n" +
		strings.Join(sections, "\n\n")
	if len(out) > brainSeedCap {
		out = strings.TrimRight(strings.ToValidUTF8(out[:brainSeedCap-3], ""), "\n ") + "…"
	}
	return out
}

func contextSection(root string) string {
	path := orgcontext.Path(root)
	if !orgcontext.Exists(path) {
		return ""
	}
	c, err := orgcontext.Load(path)
	if err != nil || c == nil {
		return ""
	}
	var lines []string
	if c.App.Name != "" || c.App.Description != "" {
		lines = append(lines, "- App: "+strings.TrimSpace(c.App.Name+" "+oneLine(c.App.Description, 400)))
	}
	if len(c.SensitiveData) > 0 {
		names := make([]string, 0, len(c.SensitiveData))
		for _, s := range c.SensitiveData {
			names = append(names, s.Category)
		}
		lines = append(lines, "- Sensitive data: "+strings.Join(names, ", "))
	}
	if a := c.AuthModel; a != nil {
		var parts []string
		if a.WhoLogsIn != "" {
			parts = append(parts, "who logs in: "+oneLine(a.WhoLogsIn, 120))
		}
		if len(a.Roles) > 0 {
			parts = append(parts, "roles: "+strings.Join(a.Roles, ", "))
		}
		if a.AdminArea {
			parts = append(parts, "has an admin area")
		}
		if len(parts) > 0 {
			lines = append(lines, "- Auth: "+strings.Join(parts, "; "))
		}
	}
	if len(c.DataStores) > 0 {
		lines = append(lines, "- Data stores: "+strings.Join(c.DataStores, ", "))
	}
	if len(c.ThirdPartyServices) > 0 {
		lines = append(lines, "- Third parties: "+strings.Join(c.ThirdPartyServices, ", "))
	}
	if len(c.ThreatActors) > 0 {
		names := make([]string, 0, len(c.ThreatActors))
		for _, t := range c.ThreatActors {
			names = append(names, t.Name)
		}
		lines = append(lines, "- Threat actors: "+strings.Join(names, ", "))
	}
	for i, l := range c.Learned {
		if i >= 5 {
			break
		}
		lines = append(lines, "- Learned: "+oneLine(l.Fact, 160))
	}
	if len(lines) == 0 {
		return ""
	}
	return "APP CONTEXT\n" + strings.Join(lines, "\n")
}

func graphSection(root string) string {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return ""
	}
	g, _, err := graphstore.Refresh(root)
	if err != nil || g == nil {
		return ""
	}

	// Unguarded entrypoints, grouped so one route lists everything it reaches.
	var order []string
	reached := map[string][]string{}
	for _, p := range g.UnguardedPaths() {
		src := nodeLabel(p.Source)
		if _, ok := reached[src]; !ok {
			order = append(order, src)
		}
		reached[src] = appendUnique(reached[src], accessLabel(p))
	}
	// Routes reaching a high-severity sink (SQL from request input, ...) go
	// first, and within a row those sinks are listed before plain reads and
	// writes, so the per-row and per-list caps never hide them.
	for _, src := range order {
		sort.SliceStable(reached[src], func(i, j int) bool {
			return strings.Contains(reached[src][i], " [") && !strings.Contains(reached[src][j], " [")
		})
	}
	sort.SliceStable(order, func(i, j int) bool {
		return hasFlagged(reached[order[i]]) && !hasFlagged(reached[order[j]])
	})
	var lines []string
	for i, src := range order {
		if i >= brainMaxExposed {
			lines = append(lines, fmt.Sprintf("- …and %d more unguarded entrypoint(s)", len(order)-i))
			break
		}
		r := reached[src]
		if len(r) > 4 {
			r = append(r[:4:4], fmt.Sprintf("+%d more", len(reached[src])-4))
		}
		lines = append(lines, fmt.Sprintf("- %s [no auth] %s", src, strings.Join(r, ", ")))
	}
	var b strings.Builder
	if ds := graph.Detect(g, root); len(ds) > 0 {
		var dl []string
		for i, d := range ds {
			if i >= brainMaxPaths {
				dl = append(dl, fmt.Sprintf("- …and %d more", len(ds)-i))
				break
			}
			line := fmt.Sprintf("- [%s] %s at %s:%d", d.Severity, d.Title, nodeLabel(d.Sink), d.Sink.Line)
			if d.Entry.Key != "" || d.Entry.Name != "" {
				line += ", via " + nodeLabel(d.Entry)
			}
			if d.Store != "" {
				line += " (stored in " + d.Store + ")"
			}
			dl = append(dl, line)
		}
		b.WriteString("Code flaws the graph traced end to end (prove these first):\n" + strings.Join(dl, "\n"))
	}
	if len(lines) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("Unguarded entrypoints (no auth check on the way to data; test these first):\n" + strings.Join(lines, "\n"))
	}

	if ce := g.ClientExposures(); len(ce) > 0 {
		var cl []string
		for i, e := range ce {
			if i >= brainMaxExposed/2 {
				cl = append(cl, fmt.Sprintf("- …and %d more", len(ce)-i))
				break
			}
			cl = append(cl, fmt.Sprintf("- browser code %s reaches %s", nodeLabel(e.Client), e.Reached.Name))
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("Client exposures (privileged code reachable from the browser; look for leaked keys in served JS):\n" + strings.Join(cl, "\n"))
	}

	// High-severity paths first; identical lines (the same helper reached
	// through several call chains) once.
	all := g.Paths()
	sort.SliceStable(all, func(i, j int) bool { return all[i].Severity == "high" && all[j].Severity != "high" })
	var pl []string
	seenPath := map[string]bool{}
	for _, p := range all {
		if len(pl) >= brainMaxPaths {
			break
		}
		if p.Guarded {
			continue
		}
		what := p.Severity
		if p.Severity == "high" && p.Sink.SinkRule != "" {
			what += ": " + p.Sink.SinkRule
		}
		line := fmt.Sprintf("- %s → %s (%s)", nodeLabel(p.Source), p.Sink.Name, what)
		if seenPath[line] {
			continue
		}
		seenPath[line] = true
		pl = append(pl, line)
	}
	if len(pl) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("Top attack paths (entrypoint to dangerous call):\n" + strings.Join(pl, "\n"))
	}
	if b.Len() == 0 {
		return ""
	}
	return "CODE GRAPH\n" + b.String()
}

func memorySection(memRoot string) string {
	// Reading must not create .trojan/ in a folder that has no memory yet.
	if _, err := os.Stat(filepath.Join(memRoot, filepath.FromSlash(memory.DefaultDBPath))); err != nil {
		return ""
	}
	st, err := memory.Open(memRoot)
	if err != nil {
		return ""
	}
	defer st.Close()
	events, err := st.All()
	if err != nil || len(events) == 0 {
		return ""
	}

	groups := map[memory.Kind][]string{}
	// Newest first, so the caps keep the freshest lessons.
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		line := "- " + oneLine(e.Title, 120)
		if e.File != "" {
			line += " (" + e.File + ")"
		}
		if e.Evidence != "" && e.Kind != memory.KindFalsePositive {
			line += ": " + oneLine(e.Evidence, brainEvidenceLen)
		}
		groups[e.Kind] = append(groups[e.Kind], line)
	}
	var parts []string
	add := func(heading string, kind memory.Kind, max int) {
		ls := groups[kind]
		if len(ls) == 0 {
			return
		}
		if len(ls) > max {
			ls = ls[:max]
		}
		parts = append(parts, heading+"\n"+strings.Join(ls, "\n"))
	}
	add("Previously confirmed issues (re-check whether they are fixed, and look for siblings):", memory.KindConfirmed, brainMaxMemory)
	add("Attack steps that worked before (replay or adapt):", memory.KindAttackStep, brainMaxMemory)
	add("Facts learned:", memory.KindFact, brainMaxMemory)
	add("Known false positives (do NOT report these again):", memory.KindFalsePositive, brainMaxFPs)
	add("Accepted risks (the owner chose to live with these; skip):", memory.KindAcceptedRisk, brainMaxFPs)
	if len(parts) == 0 {
		return ""
	}
	return "MEMORY FROM PAST RUNS\n" + strings.Join(parts, "\n")
}

// hypothesesSection renders the white-box reviewer's saved hypotheses as a
// "HYPOTHESES TO PROVE" block for the pen-test seed, capped. Returns "" when
// there is no .trojan/hypotheses.json or it is empty.
func hypothesesSection(root string) string {
	return hypothesesSectionFrom(loadHypotheses(root))
}

// hypothesesSectionFrom renders an already-loaded set so the dast path can use
// a fresh in-memory run without re-reading the file.
func hypothesesSectionFrom(hyps []whitebox.Hypothesis) string {
	if len(hyps) == 0 {
		return ""
	}
	var lines []string
	for i, h := range hyps {
		if i >= brainMaxHyps {
			lines = append(lines, fmt.Sprintf("- …and %d more", len(hyps)-i))
			break
		}
		line := fmt.Sprintf("- [%s] %s, test %s", h.Confidence, oneLine(h.Title, 100), h.Endpoint())
		if len(h.NodeKeys) > 0 {
			line += " (" + strings.Join(h.NodeKeys, ", ") + ")"
		}
		if h.ExpectedEvidence != "" {
			line += "; proof: " + oneLine(h.ExpectedEvidence, 160)
		}
		lines = append(lines, line)
	}
	return "HYPOTHESES TO PROVE (from Trojan's white-box review of the source; prioritize confirming or refuting each, then report the outcome):\n" + strings.Join(lines, "\n")
}

// loadHypotheses reads .trojan/hypotheses.json, returning nil on any problem.
func loadHypotheses(root string) []whitebox.Hypothesis {
	f, err := whitebox.LoadHypotheses(root)
	if err != nil || f == nil {
		return nil
	}
	return f.Hypotheses
}

// nodeLabel renders a graph node as "file#symbol" for the agent.
func nodeLabel(n graph.Node) string {
	if n.Key != "" {
		return n.Key
	}
	if n.File != "" {
		return n.File + "#" + n.Name
	}
	return n.Name
}

// accessLabel says what an unguarded path ends in: a datastore read/write or a
// dangerous call.
func accessLabel(p graph.AttackPath) string {
	switch p.Access {
	case graph.EdgeWrites:
		return "writes " + p.Sink.Name
	case graph.EdgeReads:
		return "reads " + p.Sink.Name
	}
	if p.Sink.Severity == "high" && p.Sink.SinkRule != "" {
		return "calls " + p.Sink.Name + " [" + p.Sink.SinkRule + "]"
	}
	return "calls " + p.Sink.Name
}

// hasFlagged reports whether any access label names a high-severity rule.
func hasFlagged(labels []string) bool {
	for _, l := range labels {
		if strings.Contains(l, " [") {
			return true
		}
	}
	return false
}

// oneLine collapses whitespace and trims s to max characters.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "…"
	}
	return s
}

// ── Per-run brain session ────────────────────────────────────────────────────

// brainSession ties one agentic run to its memory. projectRoot is the source
// folder when known (grey-box / --project), else "". memRoot is where the
// memory lives: the project, or the target site's folder under
// ~/.trojan/website-tests so repeat tests of the same site learn too.
type brainSession struct {
	projectRoot string
	memRoot     string
	store       *memory.Store // nil if memory couldn't be opened
}

// openBrain resolves where this run's memory lives and opens it. Failures are
// non-fatal: the run proceeds without memory.
func openBrain(projectRoot, targetURL string) *brainSession {
	b := &brainSession{projectRoot: projectRoot, memRoot: projectRoot}
	if b.memRoot == "" {
		if dir, err := normalizer.WebsiteDir(targetURL); err == nil {
			b.memRoot = dir
		}
	}
	if b.memRoot != "" {
		if st, err := memory.Open(b.memRoot); err == nil {
			b.store = st
		}
	}
	return b
}

func (b *brainSession) close() {
	if b != nil && b.store != nil {
		b.store.Close() //nolint:errcheck
	}
}

// seed is the brain block to append to the agent's task ("" when empty).
func (b *brainSession) seed() string {
	if b == nil {
		return ""
	}
	return brainSeed(b.projectRoot, b.memRoot)
}

// triage runs adversarial triage with memory consulted first: known false
// positives are resolved locally and never sent to the AI.
func (b *brainSession) triage(findings []normalizer.Finding, accessToken string, retriever ai.ContextRetriever) (map[string]ai.Verdict, error) {
	var fps ai.FalsePositiveSource
	if b != nil && b.store != nil {
		fps = b.store
	}
	return ai.TriageWithMemory(findings, accessToken, retriever, fps)
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// slug must stay in step with ai.slugTitle.
func slug(s string) string {
	return strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// learn records what a finished agentic run proved: every triage-confirmed
// finding becomes a confirmed event, and each confirmed agent finding also
// becomes an attack_step (the probe URL plus the evidence that proved it) so a
// later run can replay it. Returns how many confirmed events were written.
func (b *brainSession) learn(findings []normalizer.Finding, cands []agent.Candidate) int {
	if b == nil || b.store == nil {
		return 0
	}
	byTitleURL := map[string]agent.Candidate{}
	for _, c := range cands {
		byTitleURL[c.Title+"|"+c.URL] = c
	}
	n := 0
	for _, f := range findings {
		if f.Verdict != "confirmed" {
			continue
		}
		ev := memory.EventFromFinding(f, memory.KindConfirmed, memory.SourceAgent, b.projectRoot)
		if f.RuleID == "agentic" {
			// All agent findings share one rule id; the title keeps them apart.
			ev.RuleID = "agentic:" + slug(f.Title)
		}
		ev.Evidence = oneLine(firstNonEmpty(f.CodeSnippet, f.VerdictReason, f.RawMessage), 400)
		if b.store.Record(ev) == nil {
			n++
		}
		if c, ok := byTitleURL[f.Title+"|"+f.FilePath]; ok && f.Scanner == "agentic-dast" {
			step := ev
			step.Kind = memory.KindAttackStep
			step.Title = "Probe " + c.URL + " proved: " + c.Title
			step.Evidence = oneLine(c.Evidence+" | "+c.Rationale, 400)
			b.store.Record(step) //nolint:errcheck
		}
	}
	return n
}

// recordHypothesisOutcomes writes what the pen test did with each white-box
// hypothesis: a proven one is already captured by learn (confirmed finding +
// replayable attack_step), so here we record only the unproven ones as a fact
// ("tested, not proven", dated), so the next run does not keep chasing a
// hypothesis the live probes could not confirm. No-op without memory.
func (b *brainSession) recordHypothesisOutcomes(hyps []whitebox.Hypothesis, findings []normalizer.Finding) {
	if b == nil || b.store == nil || len(hyps) == 0 {
		return
	}
	date := time.Now().Format("2006-01-02")
	for _, h := range hyps {
		if hypothesisProven(h, findings) {
			continue
		}
		ev := memory.Event{
			Kind:     memory.KindFact,
			Title:    "Tested, not proven: " + oneLine(h.Title, 120),
			Evidence: fmt.Sprintf("White-box %s hypothesis at %s was tested by the pen test on %s and not confirmed.", h.Class, h.Endpoint(), date),
			Source:   memory.SourceAgent,
			RuleID:   "whitebox:" + slug(h.Title),
		}
		if len(h.NodeKeys) > 0 {
			ev.NodeKey = h.NodeKeys[0]
		}
		b.store.Record(ev) //nolint:errcheck
	}
}

// hypothesisProven reports whether a confirmed finding corresponds to the
// hypothesis: same live endpoint path, or a confirmed finding anchored on one
// of the hypothesis's node keys / files.
func hypothesisProven(h whitebox.Hypothesis, findings []normalizer.Finding) bool {
	for _, f := range findings {
		if f.Verdict != "confirmed" {
			continue
		}
		if h.Path != "" && (strings.Contains(f.FilePath, h.Path) || strings.Contains(f.RawMessage, h.Path)) {
			return true
		}
		for _, k := range h.NodeKeys {
			if k != "" && (strings.Contains(f.FilePath, k) || strings.Contains(f.CodeSnippet, k)) {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// resolveBrainRoot picks the project folder for the brain: the explicit
// --project, else the current directory when grey-box is on (the established
// "run from the source dir" contract), else "" (black-box, site-level memory).
func resolveBrainRoot(project string, greyBox bool) string {
	if project == "" && greyBox {
		project = "."
	}
	if project == "" {
		return ""
	}
	if abs, err := filepath.Abs(project); err == nil {
		return abs
	}
	return project
}

// greyBoxRoot is where the grey-box reader and retriever look: the brain's
// project folder, or the current directory as before.
func greyBoxRoot(brainRoot string) string {
	if brainRoot == "" {
		return "."
	}
	return brainRoot
}
