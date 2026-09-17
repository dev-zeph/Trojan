package mcpserver

// MCP tools for Trojan Errors (crash analytics) — the AI-fix flow for
// production crashes, mirroring the security-finding tools in server.go
// exactly: pull-based (the editor calls these when the human asks it to),
// same Pro gate (enforced once at Serve() startup, not per-tool), and the
// same plain-text-detail / JSON-batch / plain-text-confirm shape as
// get_finding_detail / get_fixable_findings / mark_fixed.
//
// Unlike the finding tools, these never touch the local filesystem or
// .trojan/scans — they talk to the Trojan Errors shim over HTTP, the same
// way the desktop app's Errors tab does (see crash-analytics/CONTRACT.md).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/ai"
)

const errorsRequestTimeout = 8 * time.Second

// errorsBaseURL is the Trojan Errors shim's address — fixed at 3002 by
// convention (crash-analytics/CONTRACT.md's port table; same default the
// desktop app's ERRORS_API constant uses), overridable for non-default setups.
func errorsBaseURL() string {
	if v := os.Getenv("TROJAN_ERRORS_API"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:3002"
}

// --- shim wire shapes (mirrors crash-analytics/CONTRACT.md's TrojanIssue/TrojanEvent) ---

type errIssue struct {
	ID          string  `json:"id"`
	ShortID     string  `json:"shortId"`
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Culprit     string  `json:"culprit"`
	Count       int     `json:"count"`
	FirstSeen   string  `json:"firstSeen"`
	LastSeen    string  `json:"lastSeen"`
	Resolved    bool    `json:"resolved"`
	Muted       bool    `json:"muted"`
	Source      string  `json:"source"`
	Release     *string `json:"release"`
	Environment *string `json:"environment"`
}

type errFrame struct {
	Filename    string   `json:"filename"`
	Function    string   `json:"function"`
	Lineno      *int     `json:"lineno"`
	InApp       bool     `json:"inApp"`
	ContextLine *string  `json:"contextLine"`
	PreContext  []string `json:"preContext"`
	PostContext []string `json:"postContext"`
}

type errNamedContext struct {
	Name    string  `json:"name"`
	Version *string `json:"version"`
}

type errRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type errEvent struct {
	EventID    string           `json:"eventId"`
	Timestamp  string           `json:"timestamp"`
	Runtime    *string          `json:"runtime"`
	ServerName *string          `json:"serverName"`
	Browser    *errNamedContext `json:"browser"`
	OS         *errNamedContext `json:"os"`
	Request    *errRequest      `json:"request"`
	Frames     []errFrame       `json:"frames"`
	Scrubbed   []string         `json:"scrubbed"`
}

type errIssueDetail struct {
	Issue       errIssue  `json:"issue"`
	LatestEvent *errEvent `json:"latestEvent"`
}

type errIssuesList struct {
	Issues []errIssue `json:"issues"`
}

// errorsGet performs a GET against the shim and decodes JSON into out. Errors
// are phrased for an AI agent to relay to the human, not raw net/http text —
// the shim being down is an expected, recoverable state, not a bug.
func errorsGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, errorsBaseURL()+path, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: errorsRequestTimeout}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the Trojan Errors service at %s — is it running? Start it with ./crash-analytics/start.sh", errorsBaseURL())
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("errors service returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func errorsPost(ctx context.Context, path string) (*errIssue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, errorsBaseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: errorsRequestTimeout}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the Trojan Errors service at %s — is it running? Start it with ./crash-analytics/start.sh", errorsBaseURL())
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("errors service returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var wrapped struct {
		Issue errIssue `json:"issue"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, err
	}
	return &wrapped.Issue, nil
}

// stackTraceText renders frames the same way the desktop app does: Sentry
// order puts the crashing frame last, so this reverses it to read first,
// and only prints context lines the shim already captured — never reads the
// local filesystem, since the crash may not have happened on this machine.
func stackTraceText(frames []errFrame) string {
	if len(frames) == 0 {
		return "(no stack frames on this event)"
	}
	var b strings.Builder
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		loc := f.Filename
		if f.Lineno != nil {
			loc = fmt.Sprintf("%s:%d", loc, *f.Lineno)
		}
		marker := ""
		if i == len(frames)-1 {
			marker = "  <- CRASHED HERE"
		}
		fmt.Fprintf(&b, "%s in %s%s\n", loc, orAnonymous(f.Function), marker)
		for _, l := range f.PreContext {
			fmt.Fprintf(&b, "    %s\n", l)
		}
		if f.ContextLine != nil {
			fmt.Fprintf(&b, "  > %s\n", *f.ContextLine)
		}
		for _, l := range f.PostContext {
			fmt.Fprintf(&b, "    %s\n", l)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func orAnonymous(fn string) string {
	if fn == "" {
		return "<anonymous>"
	}
	return fn
}

// formatErrorIssue mirrors formatFinding's shape exactly, so an agent reads
// both tool families the same way.
func formatErrorIssue(projectPath string, d errIssueDetail) string {
	is := d.Issue
	var b strings.Builder

	fmt.Fprintf(&b, "ERROR: %s\n", is.ShortID)
	fmt.Fprintf(&b, "Type:    %s\n", is.Type)
	fmt.Fprintf(&b, "Message: %s\n", is.Value)
	if is.Culprit != "" {
		fmt.Fprintf(&b, "Culprit: %s\n", is.Culprit)
	}
	fmt.Fprintf(&b, "Seen:    %d time(s), first %s, last %s\n", is.Count, is.FirstSeen, is.LastSeen)
	if is.Release != nil {
		fmt.Fprintf(&b, "Release: %s\n", *is.Release)
	}
	if is.Environment != nil {
		fmt.Fprintf(&b, "Environment: %s\n", *is.Environment)
	}
	if is.Source == "dast_run" {
		fmt.Fprintf(&b, "Note: every recorded event for this issue happened during a Trojan pen-test run, not real production traffic.\n")
	}
	b.WriteString("\n")

	if d.LatestEvent != nil {
		ev := d.LatestEvent
		if ev.Runtime != nil || ev.OS != nil || ev.Browser != nil {
			fmt.Fprintf(&b, "Where this happened:\n")
			if ev.Runtime != nil {
				fmt.Fprintf(&b, "  Runtime: %s\n", *ev.Runtime)
			}
			if ev.OS != nil {
				fmt.Fprintf(&b, "  OS: %s %s\n", ev.OS.Name, versionOrEmpty(ev.OS.Version))
			}
			if ev.Browser != nil {
				fmt.Fprintf(&b, "  Browser: %s %s\n", ev.Browser.Name, versionOrEmpty(ev.Browser.Version))
			}
			b.WriteString("\n")
		}

		if len(ev.Scrubbed) > 0 {
			fmt.Fprintf(&b, "Trojan redacted %d sensitive field(s) before storing this event: %s\n\n", len(ev.Scrubbed), strings.Join(ev.Scrubbed, ", "))
		}

		fmt.Fprintf(&b, "Stack trace (language: %s):\n%s\n", ai.DetectLanguage(crashingFrameFile(ev.Frames)), stackTraceText(ev.Frames))

		if ev.Request != nil && ev.Request.URL != "" {
			fmt.Fprintf(&b, "Request: %s %s\n\n", ev.Request.Method, ev.Request.URL)
		}
	} else {
		b.WriteString("No event detail available for this issue.\n\n")
	}

	if fw := ai.DetectFramework(projectPath); fw != "" {
		fmt.Fprintf(&b, "Project framework: %s\n", fw)
	}
	if pt := ai.DetectProjectTypeName(projectPath); pt != "" && pt != "unknown" {
		fmt.Fprintf(&b, "Project type: %s\n", pt)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "To mark this fixed after applying a code change, call: mark_error_fixed(id: %q)\n", is.ID)

	return b.String()
}

func versionOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func crashingFrameFile(frames []errFrame) string {
	if len(frames) == 0 {
		return ""
	}
	return frames[len(frames)-1].Filename
}

// --- batch context (mirrors findingContext / get_fixable_findings) ---

type errorContext struct {
	ID          string `json:"id"`
	ShortID     string `json:"short_id"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Culprit     string `json:"culprit"`
	Count       int    `json:"count"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	Release     string `json:"release,omitempty"`
	Environment string `json:"environment,omitempty"`
	Language    string `json:"language,omitempty"`
	Framework   string `json:"framework,omitempty"`
	StackTrace  string `json:"stack_trace,omitempty"`
	RequestURL  string `json:"request_url,omitempty"`
}

func buildErrorContext(projectPath string, d errIssueDetail) errorContext {
	is := d.Issue
	ec := errorContext{
		ID:        is.ID,
		ShortID:   is.ShortID,
		Type:      is.Type,
		Value:     is.Value,
		Culprit:   is.Culprit,
		Count:     is.Count,
		FirstSeen: is.FirstSeen,
		LastSeen:  is.LastSeen,
		Framework: ai.DetectFramework(projectPath),
	}
	if is.Release != nil {
		ec.Release = *is.Release
	}
	if is.Environment != nil {
		ec.Environment = *is.Environment
	}
	if d.LatestEvent != nil {
		ec.StackTrace = stackTraceText(d.LatestEvent.Frames)
		ec.Language = ai.DetectLanguage(crashingFrameFile(d.LatestEvent.Frames))
		if d.LatestEvent.Request != nil {
			ec.RequestURL = d.LatestEvent.Request.URL
		}
	}
	return ec
}

// --- handlers ---

func handleGetFixableErrors(projectPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var list errIssuesList
		if err := errorsGet(ctx, "/api/errors/issues?filter=production&limit=50", &list); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		var results []errorContext
		for _, is := range list.Issues {
			if is.Resolved {
				continue
			}
			var detail errIssueDetail
			if err := errorsGet(ctx, "/api/errors/issues/"+is.ID, &detail); err != nil {
				// One bad issue lookup must not fail the whole batch.
				continue
			}
			results = append(results, buildErrorContext(projectPath, detail))
		}

		summary := struct {
			Total  int            `json:"total"`
			Errors []errorContext `json:"errors"`
		}{Total: len(results), Errors: results}

		out, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize errors"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	}
}

func handleGetErrorDetail(projectPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}

		var detail errIssueDetail
		if err := errorsGet(ctx, "/api/errors/issues/"+id, &detail); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(formatErrorIssue(projectPath, detail)), nil
	}
}

func handleMarkErrorFixed(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := req.RequireString("id")
	if err != nil {
		return mcp.NewToolResultError("missing required parameter: id"), nil
	}

	issue, err := errorsPost(ctx, "/api/errors/issues/"+id+"/resolve")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("error %s marked as resolved", issue.ShortID)), nil
}
