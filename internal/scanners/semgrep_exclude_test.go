package scanners

import "testing"

// Trojan's own store (.trojan/scans) holds earlier findings, snippets included;
// semgrep must not scan it and report each secret again.
func TestSemgrepArgsExcludeTrojanStore(t *testing.T) {
	args := semgrepArgs("/tmp/app", nil)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--exclude" && args[i+1] == ".trojan" {
			return
		}
	}
	t.Fatalf("semgrep args do not exclude .trojan: %v", args)
}
