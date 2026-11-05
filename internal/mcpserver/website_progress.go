package mcpserver

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/routes"
)

// ── Progress + coverage for website tests ────────────────────────────────────
//
// The pen-test engine runs as a child process whose stdout/stderr go to
// <site dir>/last-run.log. Its output is line-oriented and stable (see
// printAgentEvent and runAgenticPentest in cmd/trojan), so status can be
// derived from it without a second channel: which phase the run is in, how
// many agent steps and probes it has made, the findings recorded so far, and,
// once done, which URLs it actually reached. That turns "still running" into
// something an agent can reason about, and tells it what the run did NOT cover.

// Run phases, in order.
const (
	phaseStarting     = "starting"
	phaseCrawling     = "crawling"
	phaseBaseline     = "baseline_scan"
	phaseSourceReview = "source_review"
	phaseTesting      = "ai_testing"
	phaseExplaining   = "explaining_findings"
	phaseSaving       = "saving"
	phaseDone         = "done"
)

var phaseLabels = map[string]string{
	phaseStarting:     "starting up",
	phaseCrawling:     "crawling the site to map its pages",
	phaseBaseline:     "running the baseline template scan (Nuclei), usually the longest quiet stretch",
	phaseSourceReview: "reading the project's source to form hypotheses",
	phaseTesting:      "AI agent is probing the site",
	phaseExplaining:   "writing plain-English explanations for the findings",
	phaseSaving:       "saving results",
	phaseDone:         "done",
}

// runProgress is what the run log says about a website test.
type runProgress struct {
	Phase               string   `json:"phase"`
	PhaseLabel          string   `json:"phase_label"`
	PercentEstimate     int      `json:"percent_estimate"` // rough: derived from phase + agent coverage
	EndpointsDiscovered int      `json:"endpoints_discovered"`
	BaselineFindings    int      `json:"baseline_findings"`
	AgentSteps          int      `json:"agent_steps"`
	ProbesSent          int      `json:"probes_sent"`
	ToolCalls           int      `json:"tool_calls"`
	Identities          []string `json:"identities,omitempty"` // test accounts the run logged in as
	Mode                string   `json:"mode,omitempty"`       // "grey-box" (read the source) | "black-box"
	ModeNote            string   `json:"mode_note,omitempty"`
	SourceRoutesMapped  int      `json:"source_routes_mapped,omitempty"`
	FindingsSoFar       []string `json:"findings_so_far"`
	AgentSummary        string   `json:"agent_summary,omitempty"` // the agent's own closing note
	Stopped             string   `json:"stopped,omitempty"`       // why the agent stopped early, if it did
	LatestActivity      string   `json:"latest_activity,omitempty"`

	// reached maps a probed path to the HTTP statuses it returned. Not
	// serialized directly: coverage() turns it into the manifest.
	reached map[string][]int
}

var (
	reDiscovered   = regexp.MustCompile(`Discovered (\d+) endpoint`)
	reBaseline     = regexp.MustCompile(`Baseline: (\d+) finding`)
	reStep         = regexp.MustCompile(`^\[step (\d+)\]`)
	reIdentities   = regexp.MustCompile(`\d+ identities loaded for authorization testing: (.+)$`)
	reGreyMapped   = regexp.MustCompile(`Grey-box: mapped (\d+) endpoint`)
	reProbeResult  = regexp.MustCompile(`^(\d{3}) (https?://\S+)`)
	reToolUse      = regexp.MustCompile(`^→ ([a-z_]+)$`)
	reFindingLine  = regexp.MustCompile(`^✓ finding: (.+)$`)
	reFinishedLine = regexp.MustCompile(`^finished: (.+)$`)
	reStoppedLine  = regexp.MustCompile(`^stopped: (.+)$`)
)

// parseRunLog reads an engine log into a runProgress. It tolerates partial
// output (a run in progress) and unknown lines.
func parseRunLog(log string) runProgress {
	p := runProgress{Phase: phaseStarting, FindingsSoFar: []string{}, reached: map[string][]int{}}
	lastTool := ""
	for _, raw := range strings.Split(log, "\n") {
		line := strings.TrimSpace(ansiRe.ReplaceAllString(raw, ""))
		if line == "" {
			continue
		}
		p.LatestActivity = line
		switch {
		case strings.Contains(line, "Crawling application"):
			p.Phase = phaseCrawling
		case reDiscovered.MatchString(line):
			p.EndpointsDiscovered, _ = strconv.Atoi(reDiscovered.FindStringSubmatch(line)[1])
		case strings.Contains(line, "Running Nuclei baseline"):
			p.Phase = phaseBaseline
		case reBaseline.MatchString(line):
			p.BaselineFindings, _ = strconv.Atoi(reBaseline.FindStringSubmatch(line)[1])
		case reIdentities.MatchString(line):
			for _, n := range strings.Split(reIdentities.FindStringSubmatch(line)[1], ",") {
				if n = strings.TrimSpace(n); n != "" {
					p.Identities = append(p.Identities, n)
				}
			}
		case strings.Contains(line, "White-box review"):
			p.Phase = phaseSourceReview
		case strings.Contains(line, "Grey-box requested but no recognizable source"):
			p.Mode = "black-box"
			p.ModeNote = "project_path was given, but Trojan found no routes it recognizes in that folder, so the test ran without reading the code"
		case reGreyMapped.MatchString(line):
			p.Mode = "grey-box"
			p.SourceRoutesMapped, _ = strconv.Atoi(reGreyMapped.FindStringSubmatch(line)[1])
		case reStep.MatchString(line):
			p.Phase = phaseTesting
			p.AgentSteps, _ = strconv.Atoi(reStep.FindStringSubmatch(line)[1])
		case reToolUse.MatchString(line):
			lastTool = reToolUse.FindStringSubmatch(line)[1]
			p.ToolCalls++
			if lastTool == "http_probe" {
				p.ProbesSent++
			}
		case reProbeResult.MatchString(line) && lastTool == "http_probe":
			m := reProbeResult.FindStringSubmatch(line)
			status, _ := strconv.Atoi(m[1])
			if path := probePath(m[2]); path != "" {
				p.reached[path] = appendStatus(p.reached[path], status)
			}
		case reFindingLine.MatchString(line):
			p.FindingsSoFar = append(p.FindingsSoFar, reFindingLine.FindStringSubmatch(line)[1])
		case reFinishedLine.MatchString(line):
			p.AgentSummary = reFinishedLine.FindStringSubmatch(line)[1]
		case reStoppedLine.MatchString(line):
			p.Stopped = reStoppedLine.FindStringSubmatch(line)[1]
		case strings.Contains(line, "Synthesizing"):
			p.Phase = phaseExplaining
		case strings.HasPrefix(line, "Results saved to"):
			p.Phase = phaseSaving
		case strings.HasPrefix(line, "PENTEST_END"):
			p.Phase = phaseDone
		}
	}
	if len(p.LatestActivity) > 200 {
		p.LatestActivity = p.LatestActivity[:200] + "…"
	}
	if p.Mode == "" && p.Phase != phaseStarting && p.Phase != phaseCrawling && p.Phase != phaseBaseline {
		p.Mode = "black-box"
	}
	p.PhaseLabel = phaseLabels[p.Phase]
	p.PercentEstimate = p.percent()
	return p
}

// percent is a rough progress estimate. Phase sets the floor; during AI
// testing it moves with the share of discovered endpoints probed so far (or
// with steps when there is no endpoint count), and never claims 100 until the
// engine has written its end marker.
func (p runProgress) percent() int {
	switch p.Phase {
	case phaseStarting:
		return 2
	case phaseCrawling:
		return 5
	case phaseBaseline:
		return 15
	case phaseSourceReview:
		return 38
	case phaseTesting:
		frac := float64(p.AgentSteps) / 20
		if p.EndpointsDiscovered > 0 {
			if c := float64(len(p.reached)) / float64(p.EndpointsDiscovered); c > frac {
				frac = c
			}
		}
		if frac > 1 {
			frac = 1
		}
		return 40 + int(frac*48)
	case phaseExplaining:
		return 92
	case phaseSaving:
		return 97
	case phaseDone:
		return 100
	}
	return 0
}

// probePath returns a probed URL's path (no query), "" if unparseable.
func probePath(raw string) string {
	u, err := url.Parse(strings.TrimRight(raw, "…"))
	if err != nil {
		return ""
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func appendStatus(list []int, s int) []int {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// readRunProgress parses the site's run log; ok is false when there is none.
func readRunProgress(siteDir string) (runProgress, bool) {
	data, err := os.ReadFile(filepath.Join(siteDir, "last-run.log"))
	if err != nil {
		return runProgress{}, false
	}
	return parseRunLog(string(data)), true
}

// coverageManifest says what a finished run reached and, when the project's
// source is known, which of its routes the run never touched.
type coverageManifest struct {
	EndpointsDiscovered int              `json:"endpoints_discovered"`
	PathsReached        []reachedPath    `json:"paths_reached"`
	SourceRoutes        int              `json:"source_routes,omitempty"`
	RoutesNotReached    []unreachedRoute `json:"routes_not_reached,omitempty"`
	Note                string           `json:"note"`
}

type reachedPath struct {
	Path     string `json:"path"`
	Statuses []int  `json:"statuses"`
}

type unreachedRoute struct {
	Route   string   `json:"route"` // "GET /tools/ping"
	Handler string   `json:"handler"`
	Guards  []string `json:"guards,omitempty"`
}

// coverage builds the manifest. projectPath may be "": then only what was
// reached is reported.
func (p runProgress) coverage(projectPath string) coverageManifest {
	m := coverageManifest{EndpointsDiscovered: p.EndpointsDiscovered, PathsReached: []reachedPath{}}
	paths := make([]string, 0, len(p.reached))
	for path := range p.reached {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		st := append([]int(nil), p.reached[path]...)
		sort.Ints(st)
		m.PathsReached = append(m.PathsReached, reachedPath{Path: path, Statuses: st})
	}

	if projectPath == "" {
		m.Note = "Only paths the AI agent probed are listed (the baseline scan's requests are not). Pass project_path to also see which routes in the code the test never reached."
		return m
	}
	table := routes.NewResolver(projectPath).Routes()
	if len(table) == 0 {
		m.Note = "Only paths the AI agent probed are listed. Trojan found no routes it recognizes in project_path, so it can't list what was missed."
		return m
	}
	m.SourceRoutes = len(table)
	m.RoutesNotReached = []unreachedRoute{}
	reachedRoute := func(r routes.Route) bool {
		for _, path := range paths {
			if _, ok := routes.Match([]routes.Route{r}, r.Method, path); ok {
				return true
			}
		}
		return false
	}
	// A handler reached through one of its aliases (PHP's /index.php vs /,
	// a Flask view with two @route lines) counts as reached for all of them.
	handlerKey := func(r routes.Route) string { return fmt.Sprintf("%s %s:%d", r.Method, r.HandlerFile, r.HandlerLine) }
	handlerHit := map[string]bool{}
	for _, r := range table {
		if reachedRoute(r) {
			handlerHit[handlerKey(r)] = true
		}
	}
	seen := map[string]bool{}
	for _, r := range table {
		key := r.Method + " " + r.PathPattern
		if handlerHit[handlerKey(r)] || seen[key] {
			continue
		}
		seen[key] = true
		method := r.Method
		if method == "" {
			method = "ANY"
		}
		handler := r.HandlerFile
		if r.HandlerLine > 0 {
			handler += ":" + strconv.Itoa(r.HandlerLine)
		}
		m.RoutesNotReached = append(m.RoutesNotReached, unreachedRoute{Route: method + " " + r.PathPattern, Handler: handler, Guards: r.Guards})
	}
	m.Note = "routes_not_reached are routes in the code that the AI agent never probed: the live test says nothing about them. Check them with the code findings (get_findings), or run another test focused on them."
	if len(m.RoutesNotReached) == 0 {
		m.Note = "The AI agent probed every route Trojan found in the code."
	}
	return m
}

// typicalDuration is the fallback run-time estimate when a site has no
// previous run to go by.
const typicalDuration = "5 to 15 minutes"

// formatDuration renders a duration as "12m 30s".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return d.String()
	}
	m := int(d / time.Minute)
	s := int((d % time.Minute) / time.Second)
	if s == 0 {
		return strconv.Itoa(m) + "m"
	}
	return strconv.Itoa(m) + "m " + strconv.Itoa(s) + "s"
}
