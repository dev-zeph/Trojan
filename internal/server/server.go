package server

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/normalizer"
)

const licenseCacheTTL = 5 * time.Minute

// licenseResult is the in-memory cache entry for a Pro status check.
type licenseResult struct {
	isPro     bool
	fetchedAt time.Time
}

// scanResponse is the API shape returned to the UI — separate from the stored
// ScanResult so we can add view-only fields like locked_count without
// polluting the on-disk format.
type scanResponse struct {
	Timestamp   time.Time          `json:"timestamp"`
	ProjectPath string             `json:"project_path"`
	Findings    []normalizer.Finding `json:"findings"`
	LockedCount int                `json:"locked_count"`
}

// Server holds the scan results and serves the UI + API.
type Server struct {
	scan         *normalizer.ScanResult
	uiAssets     fs.FS
	port         int
	licenseMu    sync.Mutex
	licenseCache *licenseResult
}

// New creates a new server with the given scan result and embedded UI assets.
func New(scan *normalizer.ScanResult, uiAssets fs.FS) *Server {
	return &Server{scan: scan, uiAssets: uiAssets}
}

// Start finds an available port starting from 7878 and starts the HTTP server.
func (s *Server) Start() (string, error) {
	port, err := findAvailablePort(7878)
	if err != nil {
		return "", fmt.Errorf("could not find available port: %w", err)
	}
	s.port = port

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scans/latest", s.handleLatestScan)
	mux.HandleFunc("/api/findings/", s.handleFindingAction)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)

	// Serve embedded UI assets
	uiFS, err := fs.Sub(s.uiAssets, "ui/dist")
	if err != nil {
		return "", fmt.Errorf("could not load UI assets: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(uiFS)))

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	go http.ListenAndServe(addr, mux)

	return fmt.Sprintf("http://%s", addr), nil
}

func (s *Server) handleLatestScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	isPro := s.checkProStatus()

	var resp scanResponse
	resp.Timestamp = s.scan.Timestamp
	resp.ProjectPath = s.scan.ProjectPath

	if isPro {
		resp.Findings = s.scan.Findings
		resp.LockedCount = 0
	} else {
		resp.Findings, resp.LockedCount = markFindingsForFree(s.scan.Findings)
	}

	json.NewEncoder(w).Encode(resp)
}

// checkProStatus validates the user's subscription against the Supabase license
// endpoint. Results are cached in memory for licenseCacheTTL. Fails closed —
// any error (no token, network failure, expired token) returns false.
func (s *Server) checkProStatus() bool {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return false
	}

	s.licenseMu.Lock()
	defer s.licenseMu.Unlock()

	if s.licenseCache != nil && time.Since(s.licenseCache.fetchedAt) < licenseCacheTTL {
		return s.licenseCache.isPro
	}

	info, err := ai.FetchLicense(cfg.AccessToken)
	isPro := err == nil && info != nil && info.IsPro

	s.licenseCache = &licenseResult{isPro: isPro, fetchedAt: time.Now()}
	return isPro
}

// markFindingsForFree returns a copy of all findings with the Locked field set
// for those not accessible on the free plan. Free users get up to 5 low/medium
// findings (medium first); everything else is locked. The original scan slice
// is never mutated.
func markFindingsForFree(findings []normalizer.Finding) (marked []normalizer.Finding, lockedCount int) {
	// Determine which finding IDs get free access: up to 5 low/medium, medium first.
	var medium, low []normalizer.Finding
	for _, f := range findings {
		switch f.Severity {
		case normalizer.SeverityMedium:
			medium = append(medium, f)
		case normalizer.SeverityLow:
			low = append(low, f)
		}
	}
	accessible := append(medium, low...)
	if len(accessible) > 5 {
		accessible = accessible[:5]
	}
	freeIDs := make(map[string]bool, len(accessible))
	for _, f := range accessible {
		freeIDs[f.ID] = true
	}

	// Copy all findings and mark those outside the free set as locked.
	marked = make([]normalizer.Finding, len(findings))
	for i, f := range findings {
		marked[i] = f
		if !freeIDs[f.ID] {
			marked[i].Locked = true
			lockedCount++
		}
	}
	return marked, lockedCount
}

func (s *Server) handleFindingAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse: /api/findings/:id/resolve or /api/findings/:id/suppress
	// path format: /api/findings/{id}/{action}
	path := r.URL.Path // e.g. /api/findings/semgrep-0/resolve
	var id, action string
	fmt.Sscanf(path, "/api/findings/%s", &id)

	// Split id and action
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			id = path[len("/api/findings/"):i]
			action = path[i+1:]
			break
		}
	}

	// Update the finding status in memory
	for i, f := range s.scan.Findings {
		if f.ID == id {
			switch action {
			case "resolve":
				s.scan.Findings[i].Status = normalizer.StatusResolved
			case "suppress":
				s.scan.Findings[i].Status = normalizer.StatusSuppressed
			}
			break
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" || !config.IsLoggedIn() {
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn": false,
			"isPro":    false,
			"plan":     "free",
		})
		return
	}
	plan := config.SubscriptionStatusFromToken(cfg.AccessToken)
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": true,
		"isPro":    plan == "pro" || plan == "team",
		"plan":     plan,
		"email":    cfg.UserEmail,
	})
}

// findAvailablePort returns the first open port starting from the given port.
func findAvailablePort(startPort int) (int, error) {
	for port := startPort; port < startPort+10; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available port found in range %d-%d", startPort, startPort+10)
}
