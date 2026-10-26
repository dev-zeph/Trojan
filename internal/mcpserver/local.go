package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/scanners"
)

// ── Local server (desktop app) ───────────────────────────────────────────────
//
// The desktop app runs one MCP server for the whole machine while it is open,
// the way Figma's desktop app does. AI tools (Claude Code, Cursor, Codex)
// connect to it by URL instead of launching a `trojan` binary from PATH, so it
// works without the CLI installed. Findings never leave the machine.
//
// Every request must carry the bearer token from ~/.trojan/mcp-token; the
// installers write that token into each tool's config. Tool calls also need a
// signed-in Trojan account, and each call works out which project it is about
// (see resolveProject).

const (
	LocalAddr = "127.0.0.1:7880"
	LocalURL  = "http://" + LocalAddr + "/mcp"
)

// LocalToken returns the token AI tools must send to the local server,
// creating it on first use. It is readable only by the current user.
//
// Several processes can ask at once (the server starting while the app checks
// status), so creation is atomic: the token is written to a temp file and
// hard-linked into place, which fails if another process got there first, in
// which case that process's token is used.
func LocalToken() (string, error) {
	path, err := trojanFile("mcp-token")
	if err != nil {
		return "", err
	}
	if tok := readToken(path); tok != "" {
		return tok, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "mcp-token-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(hex.EncodeToString(buf) + "\n"); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	os.Link(tmp.Name(), path) //nolint:errcheck // loses the race only if another token is already in place
	if tok := readToken(path); tok != "" {
		return tok, nil
	}
	return "", errors.New("could not create MCP token")
}

func readToken(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ServeLocal runs the local MCP server until it fails. It returns an error at
// once if the port is taken (most likely another Trojan window).
func ServeLocal() error {
	if _, err := LocalToken(); err != nil {
		return fmt.Errorf("could not create MCP token: %w", err)
	}

	importDesktopCache()

	hooks := &server.Hooks{}
	hooks.AddAfterInitialize(func(ctx context.Context, _ any, msg *mcp.InitializeRequest, _ *mcp.InitializeResult) {
		recordActivity(msg.Params.ClientInfo.Name, "")
	})

	s := newServer(resolveProject, true,
		server.WithHooks(hooks),
		server.WithToolHandlerMiddleware(requireSignIn),
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", server.NewStreamableHTTPServer(s))

	ln, err := net.Listen("tcp", LocalAddr)
	if err != nil {
		return fmt.Errorf("port %s is in use (is another Trojan app open?): %w", LocalAddr, err)
	}
	srv := &http.Server{Handler: guard(currentToken, mux), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// currentToken reads the token file on every request, so the server always
// agrees with what the installers wrote into each tool's config.
func currentToken() string {
	tok, _ := LocalToken()
	return tok
}

// guard rejects requests without the token, and requests whose Host isn't the
// loopback address (blocks DNS-rebinding pages that resolve to 127.0.0.1).
func guard(token func() string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		tok := token()
		if tok == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+tok)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSignIn blocks tool calls while nobody is signed in to Trojan. The
// desktop app keeps ~/.trojan/config.json in sync with its session.
func requireSignIn(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if cfg, err := config.LoadConfig(); err != nil || cfg.AccessToken == "" {
			return mcp.NewToolResultError("Trojan: sign in to the Trojan desktop app, then try again."), nil
		}
		return next(ctx, req)
	}
}

// ── Project resolution ───────────────────────────────────────────────────────

// projectFunc works out which project folder a tool call is about.
type projectFunc func(ctx context.Context, req mcp.CallToolRequest) (string, error)

// resolveProject uses the project_path the AI tool passed, falling back to the
// workspace folders ("roots") the tool reports. Either may point at a
// subfolder, so it walks up to the nearest folder holding Trojan scans.
func resolveProject(ctx context.Context, req mcp.CallToolRequest) (string, error) {
	var candidates []string
	if p := strings.TrimSpace(req.GetString("project_path", "")); p != "" {
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		candidates = rootsFromClient(ctx)
	}
	if len(candidates) == 0 {
		return "", errors.New("pass project_path: the absolute path of the project folder you are working in")
	}

	for _, c := range candidates {
		if dir, ok := findScannedProject(expandHome(c)); ok {
			recordActivity(clientName(ctx), dir)
			return dir, nil
		}
	}
	// run_scan is how a never-scanned project gets its first scan.
	if req.Params.Name == "run_scan" {
		if dir := expandHome(candidates[0]); filepath.IsAbs(dir) {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				recordActivity(clientName(ctx), dir)
				return filepath.Clean(dir), nil
			}
		}
	}
	recordActivity(clientName(ctx), "")
	return "", fmt.Errorf("no Trojan scan found for %s. Open the Trojan app, scan this project folder, then try again", candidates[0])
}

// rootsFromClient asks the client for its workspace folders, if it supports
// that. Bounded by a short timeout: not every client answers.
func rootsFromClient(ctx context.Context) []string {
	sess, ok := server.ClientSessionFromContext(ctx).(server.SessionWithClientInfo)
	if !ok || sess.GetClientCapabilities().Roots == nil {
		return nil
	}
	srv := server.ServerFromContext(ctx)
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := srv.RequestRoots(ctx, mcp.ListRootsRequest{})
	if err != nil || res == nil {
		return nil
	}
	var out []string
	for _, r := range res.Roots {
		if u, err := url.Parse(r.URI); err == nil && u.Scheme == "file" {
			out = append(out, u.Path)
		}
	}
	return out
}

// findScannedProject walks up from dir to the nearest folder with
// .trojan/scans, stopping at the home directory.
func findScannedProject(dir string) (string, bool) {
	dir = filepath.Clean(dir)
	home, _ := os.UserHomeDir()
	for {
		if info, err := os.Stat(filepath.Join(dir, ".trojan", "scans")); err == nil && info.IsDir() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir || dir == home {
			return "", false
		}
		dir = parent
	}
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// ── Activity (what the desktop app shows as "last used") ─────────────────────

// ClientActivity is the last time a given AI tool talked to the local server.
type ClientActivity struct {
	Client   string    `json:"client"`
	LastSeen time.Time `json:"last_seen"`
	Project  string    `json:"project,omitempty"`
}

var activityMu sync.Mutex

func clientName(ctx context.Context) string {
	if sess, ok := server.ClientSessionFromContext(ctx).(server.SessionWithClientInfo); ok {
		return sess.GetClientInfo().Name
	}
	return ""
}

// ToolKey maps an MCP client name to the desktop app's key for that tool.
func ToolKey(client string) string {
	c := strings.ToLower(client)
	switch {
	case strings.Contains(c, "claude"):
		return "claude_code"
	case strings.Contains(c, "cursor"):
		return "cursor"
	case strings.Contains(c, "codex"):
		return "codex_cli"
	}
	return c
}

func recordActivity(client, project string) {
	key := ToolKey(client)
	if key == "" {
		return
	}
	activityMu.Lock()
	defer activityMu.Unlock()

	all := LoadActivity()
	prev := all[key]
	if project == "" {
		project = prev.Project
	}
	all[key] = ClientActivity{Client: client, LastSeen: time.Now().UTC(), Project: project}

	path, err := trojanFile("mcp-activity.json")
	if err != nil {
		return
	}
	if data, err := json.MarshalIndent(all, "", "  "); err == nil {
		os.WriteFile(path, data, 0600) //nolint:errcheck // best effort; only feeds a status label
	}
}

// LoadActivity returns the recorded activity keyed by tool (claude_code, ...).
func LoadActivity() map[string]ClientActivity {
	out := map[string]ClientActivity{}
	if path, err := trojanFile("mcp-activity.json"); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			json.Unmarshal(data, &out) //nolint:errcheck
		}
	}
	return out
}

// importDesktopCache copies website-test results that predate the
// website-tests store out of the desktop app's cache (~/.trojan/desktop-cache),
// for any site that has no results in the store yet.
func importDesktopCache() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	files, _ := filepath.Glob(filepath.Join(home, ".trojan", "desktop-cache", "*.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var scan normalizer.ScanResult
		if json.Unmarshal(data, &scan) != nil || len(scan.Findings) == 0 {
			continue
		}
		if !strings.HasPrefix(scan.ProjectPath, "http://") && !strings.HasPrefix(scan.ProjectPath, "https://") {
			continue
		}
		dir, err := normalizer.WebsiteDir(scan.ProjectPath)
		if err != nil || normalizer.LatestScanFile(dir) != "" {
			continue
		}
		normalizer.SaveWebsiteTest(scan.ProjectPath, scan.Findings) //nolint:errcheck // best effort
	}
}

// ── One-off scan (run_scan) ──────────────────────────────────────────────────

// ScanOnce scans a project and saves the result to <project>/.trojan/scans.
// It runs in its own process (`trojan mcp scan-once`) so scanner output can't
// interfere with the MCP connection.
func ScanOnce(projectPath string) (*normalizer.ScanResult, error) {
	if err := config.EnsureScanners(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not install scanners: %s\n", err)
	}
	relevant := scanners.RelevantScanners(scanners.DefaultScanners(), scanners.DetectProject(projectPath))
	findings, _ := scanners.RunAll(projectPath, relevant, nil)
	findings, _ = normalizer.Reduce(findings)
	return normalizer.SaveScanResult(projectPath, findings)
}

func trojanFile(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".trojan")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
