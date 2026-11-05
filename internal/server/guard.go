package server

import (
	"net"
	"net/http"
	"strings"
)

// The report server listens on a random loopback port with no login, so two
// things keep other websites the user has open away from it:
//
//   - Host must be loopback. A page using DNS rebinding reaches the port
//     under its own domain name, which is refused.
//   - Cross-origin access is limited to the Trojan desktop app and its dev
//     server. Any other page's request (which browsers mark with Origin) is
//     refused, and no other origin is allowed to read responses.
//
// Requests without an Origin header (curl, the AI tools, a top-level
// navigation) pass: they don't come from a web page.

// desktopOrigins are the Trojan desktop webview's origins: macOS/Linux
// production, Windows production, and the Vite dev server.
var desktopOrigins = map[string]bool{
	"tauri://localhost":       true,
	"http://tauri.localhost":  true,
	"https://tauri.localhost": true,
	"http://localhost:1420":   true,
}

func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// allowedOrigin reports whether a browser Origin may use the server: the
// desktop app, or the report page the server itself serves.
func allowedOrigin(origin, host string) bool {
	if desktopOrigins[origin] {
		return true
	}
	return origin == "http://"+host
}

func localGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !allowedOrigin(origin, r.Host) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
