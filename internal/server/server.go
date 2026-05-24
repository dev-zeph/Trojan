package server

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// Server holds the scan results and serves the UI + API.
type Server struct {
	scan    *normalizer.ScanResult
	uiAssets fs.FS
	port    int
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
	json.NewEncoder(w).Encode(s.scan)
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
