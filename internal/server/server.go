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
	Timestamp   time.Time               `json:"timestamp"`
	ProjectPath string                  `json:"project_path"`
	Findings    []normalizer.Finding    `json:"findings"`
	LockedCount int                     `json:"locked_count"`
	Packages    []normalizer.Package    `json:"packages,omitempty"`
	Privacy     *normalizer.PrivacyReport `json:"privacy,omitempty"`
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

	// Agentic-DAST live run stream (Phase 5 §10.2). The run itself executes in
	// the CLI process that owns this server; it broadcasts progress events here
	// and the "Penetration Testing" run view subscribes over SSE.
	agenticMu      sync.Mutex
	agenticNextID  int
	agenticClients map[int]chan AgentEvent
	agenticBuffer  []AgentEvent // replay buffer for late subscribers
	agenticStatus  string       // "idle" | "running" | "complete" | "error"
}

// New creates a new server with the given scan result and embedded UI assets.
func New(scan *normalizer.ScanResult, uiAssets fs.FS) *Server {
	return &Server{
		scan:           scan,
		uiAssets:       uiAssets,
		sseConns:       make(map[int]chan struct{}),
		agenticClients: make(map[int]chan AgentEvent),
		agenticStatus:  "idle",
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

// Start binds to any available port on loopback and starts the HTTP server.
// Using port 0 lets the OS assign a free port, so stale sidecar processes
// from previous sessions never cause "no available port" errors.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("could not bind to a local port: %w", err)
	}
	s.port = ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scans/latest", s.handleLatestScan)
	mux.HandleFunc("/api/findings/", s.handleFindingAction)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/events", s.handleSSE)
	mux.HandleFunc("/api/install-progress", s.handleInstallProgress)

	// Agentic-DAST (Phase 5): consent gate + live run stream.
	mux.HandleFunc("/api/dast/consent/status", s.handleConsentStatus)
	mux.HandleFunc("/api/dast/consent/mint", s.handleConsentMint)
	mux.HandleFunc("/api/dast/consent/verify", s.handleConsentVerify)
	mux.HandleFunc("/api/dast/agentic/status", s.handleAgenticStatus)
	mux.HandleFunc("/api/dast/agentic/events", s.handleAgenticEvents)

	// Serve embedded UI assets (caller passes an already-subbed fs.FS)
	mux.Handle("/", http.FileServer(http.FS(s.uiAssets)))

	// Wrap with CORS headers so the Tauri desktop webview (localhost:1420 in dev,
	// tauri://localhost in prod) can fetch /api/* endpoints directly.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})
	go http.Serve(ln, handler) //nolint:errcheck

	return fmt.Sprintf("http://127.0.0.1:%d", s.port), nil
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
	resp.Packages = scan.Packages
	resp.Privacy = scan.Privacy

	json.NewEncoder(w).Encode(resp)
}

// checkProStatus reads cfg.IsPro which is set server-side on login/refresh.
// This correctly covers org seat members whose JWT subscription_status is "free".
func (s *Server) checkProStatus() bool {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.AccessToken == "" {
		return false
	}
	return cfg.IsPro
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
	// For org seat members their JWT plan is "free" but cfg.IsPro is true.
	// Show "Pro" so the UI banner displays correctly.
	if cfg.IsPro && plan == "free" {
		plan = "Pro"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": true,
		"isPro":    cfg.IsPro,
		"plan":     plan,
		"email":    cfg.UserEmail,
	})
}

// InstallProgressEvent is emitted by the desktop onboarding screen via SSE.
type InstallProgressEvent struct {
	Scanner string `json:"scanner"`
	Status  string `json:"status"` // "downloading" | "verifying" | "done" | "error"
	Pct     int    `json:"pct"`
	Error   string `json:"error,omitempty"`
}

// installProgressMu guards installProgressClients.
var installProgressMu sync.Mutex
var installProgressClients = map[int]chan InstallProgressEvent{}
var installProgressNextID int

// BroadcastInstallProgress sends a progress event to all connected onboarding
// SSE clients. Called by config.RunInit when running in desktop mode.
func BroadcastInstallProgress(evt InstallProgressEvent) {
	installProgressMu.Lock()
	defer installProgressMu.Unlock()
	for _, ch := range installProgressClients {
		select {
		case ch <- evt:
		default:
		}
	}
}

// handleInstallProgress is the SSE endpoint the desktop onboarding screen
// subscribes to. It streams scanner install progress in real time.
func (s *Server) handleInstallProgress(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan InstallProgressEvent, 8)
	installProgressMu.Lock()
	id := installProgressNextID
	installProgressNextID++
	installProgressClients[id] = ch
	installProgressMu.Unlock()
	defer func() {
		installProgressMu.Lock()
		delete(installProgressClients, id)
		installProgressMu.Unlock()
	}()

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case evt := <-ch:
			data, _ := json.Marshal(evt)
			fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
			flusher.Flush()
			if evt.Status == "done" && evt.Pct == 100 && evt.Scanner == "__all__" {
				return
			}
		}
	}
}
