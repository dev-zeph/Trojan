package server

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

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
	Timestamp   time.Time            `json:"timestamp"`
	ProjectPath string               `json:"project_path"`
	Findings    []normalizer.Finding `json:"findings"`
	LockedCount int                  `json:"locked_count"`
}

// Server holds the scan results and serves the UI + API.
type Server struct {
	uiAssets fs.FS
	port     int

	// Scan data — protected by scanMu so --watch can swap it safely.
	scanMu sync.RWMutex
	scan   *normalizer.ScanResult

	// License cache
	licenseMu    sync.Mutex
	licenseCache *licenseResult

	// SSE — each connected client has a buffered channel that receives a
	// signal when a new scan completes. We track clients by a monotonic ID.
	sseMu     sync.Mutex
	sseNextID int
	sseConns  map[int]chan struct{}
}

// New creates a new server with the given scan result and embedded UI assets.
func New(scan *normalizer.ScanResult, uiAssets fs.FS) *Server {
	return &Server{
		scan:     scan,
		uiAssets: uiAssets,
		sseConns: make(map[int]chan struct{}),
	}
}

// UpdateScan atomically replaces the current scan result and notifies all
// connected SSE clients so the browser refreshes automatically.
func (s *Server) UpdateScan(scan *normalizer.ScanResult) {
	s.scanMu.Lock()
	s.scan = scan
	s.scanMu.Unlock()
	s.notifySSEClients()
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
	mux.HandleFunc("/api/events", s.handleSSE)

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

// handleSSE implements a Server-Sent Events endpoint. The browser connects
// once and receives a "scan_complete" event each time --watch triggers a
// re-scan, at which point it re-fetches /api/scans/latest.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy

	// Register this client.
	ch := make(chan struct{}, 1)
	id := s.registerSSEClient(ch)
	defer s.unregisterSSEClient(id)

	// Initial heartbeat so the browser knows the connection is live.
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// Keepalive ticker — prevents idle proxy timeouts.
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-ch:
			fmt.Fprintf(w, "data: scan_complete\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) registerSSEClient(ch chan struct{}) int {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	id := s.sseNextID
	s.sseNextID++
	s.sseConns[id] = ch
	return id
}

func (s *Server) unregisterSSEClient(id int) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	delete(s.sseConns, id)
}

func (s *Server) notifySSEClients() {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for _, ch := range s.sseConns {
		select {
		case ch <- struct{}{}:
		default:
			// Client channel full — it will pick up the next event.
		}
	}
}

func (s *Server) handleLatestScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	isPro := s.checkProStatus()

	s.scanMu.RLock()
	scan := s.scan
	s.scanMu.RUnlock()

	var resp scanResponse
	resp.Timestamp = scan.Timestamp
	resp.ProjectPath = scan.ProjectPath

	if isPro {
		resp.Findings = scan.Findings
		resp.LockedCount = 0
	} else {
		resp.Findings, resp.LockedCount = markFindingsForFree(scan.Findings)
	}

	json.NewEncoder(w).Encode(resp)
}

// checkProStatus reads the subscription status directly from the local JWT
// claims — same source of truth used by main.go when deciding whether to run
// AI and save results. No network call needed; fails closed on any error.
func (s *Server) checkProStatus() bool {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return false
	}
	return config.IsProFromToken(cfg.AccessToken)
}

// markFindingsForFree returns a copy of all findings with the Locked field set
// for those not accessible on the free plan. Free users get up to 5 low/medium
// findings (medium first); everything else is locked. The original scan slice
// is never mutated.
func markFindingsForFree(findings []normalizer.Finding) (marked []normalizer.Finding, lockedCount int) {
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

	marked = make([]normalizer.Finding, len(findings))
	for i, f := range findings {
		marked[i] = f
		// Never expose AI-generated content to free users — strip cached
		// Simply/Actions regardless of whether the finding is unlocked.
		marked[i].Simply = ""
		marked[i].Actions = nil
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

	path := r.URL.Path
	var id, action string
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			id = path[len("/api/findings/"):i]
			action = path[i+1:]
			break
		}
	}

	s.scanMu.Lock()
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
	s.scanMu.Unlock()

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
