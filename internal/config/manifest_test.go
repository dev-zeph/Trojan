package config

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Every downloadable scanner must carry a checksum: downloadScanner refuses
// assets without one, so a missing checksum means a scanner that never installs.
func TestEveryScannerDownloadHasChecksum(t *testing.T) {
	for _, list := range [][]ScannerManifest{Scanners, DastScanners} {
		for _, s := range list {
			if s.PipFallback != "" && !regexp.MustCompile(`^[a-z0-9-]+==[0-9.]+$`).MatchString(s.PipFallback) {
				t.Errorf("%s: PipFallback %q is not an exact pin", s.Name, s.PipFallback)
			}
			for platform, a := range s.Platforms {
				if a.Archive == ArchivePip {
					if !strings.HasSuffix(a.PipPackage, "=="+s.Version) {
						t.Errorf("%s %s: pip package %q is not pinned to %s", s.Name, platform, a.PipPackage, s.Version)
					}
					continue
				}
				if !sha256Re.MatchString(a.SHA256) {
					t.Errorf("%s %s: missing or malformed SHA256", s.Name, platform)
				}
				if !strings.HasPrefix(a.URL, "https://") {
					t.Errorf("%s %s: URL is not https: %s", s.Name, platform, a.URL)
				}
			}
		}
	}
}

func TestDownloadScannerRefusesUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not the real scanner")) //nolint:errcheck
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "scanner")

	err := downloadScanner(PlatformAsset{URL: srv.URL, Archive: ArchiveDirect}, dest)
	if err == nil || !strings.Contains(err.Error(), "no checksum") {
		t.Errorf("asset without checksum: got %v, want refusal", err)
	}
	err = downloadScanner(PlatformAsset{URL: srv.URL, Archive: ArchiveDirect, SHA256: strings.Repeat("0", 64)}, dest)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("wrong checksum: got %v, want mismatch", err)
	}
}
