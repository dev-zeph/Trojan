package config

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTarGz(t *testing.T, entries map[string]string, links map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.tar.gz")
	f, _ := os.Create(path)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write([]byte(body))                                                                              //nolint:errcheck
	}
	for name, target := range links {
		tw.WriteHeader(&tar.Header{Name: name, Linkname: target, Typeflag: tar.TypeSymlink}) //nolint:errcheck
	}
	tw.Close()
	gz.Close()
	f.Close()
	return path
}

func TestExtractTree(t *testing.T) {
	dest := t.TempDir()
	a := writeTarGz(t, map[string]string{"python/bin/python3.12": "x", "other/skip": "y"}, map[string]string{"python/bin/python3": "python3.12"})
	if err := extractTree(a, dest, "python/"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "bin", "python3")); err != nil {
		t.Errorf("symlinked interpreter missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "skip")); err == nil {
		t.Error("entries outside the prefix must be skipped")
	}

	bad := writeTarGz(t, map[string]string{"python/../../evil": "x"}, nil)
	if err := extractTree(bad, t.TempDir(), "python/"); err == nil {
		t.Error("an entry escaping the folder must be refused")
	}
	badLink := writeTarGz(t, nil, map[string]string{"python/bin/x": "/etc/passwd"})
	if err := extractTree(badLink, t.TempDir(), "python/"); err == nil {
		t.Error("an absolute symlink must be refused")
	}
}

// A failed install must leave nothing at dest, so a broken binary is never
// mistaken for an installed scanner.
func TestDownloadScannerIsAtomic(t *testing.T) {
	body := []byte("binary")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) })) //nolint:errcheck
	defer srv.Close()
	dir := t.TempDir()
	dest := filepath.Join(dir, "scanner")

	// Wrong archive type for the payload: extraction fails.
	err := downloadScanner(PlatformAsset{URL: srv.URL, SHA256: hex.EncodeToString(sum[:]), Archive: ArchiveTarGz, BinaryInArchive: "x"}, dest)
	if err == nil {
		t.Fatal("expected extraction to fail")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("failed install left files behind: %v", entries)
	}

	if err := downloadScanner(PlatformAsset{URL: srv.URL, SHA256: hex.EncodeToString(sum[:]), Archive: ArchiveDirect}, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "binary" {
		t.Errorf("installed %q", got)
	}
}

func TestEnsureSpace(t *testing.T) {
	if err := ensureSpace(t.TempDir(), 1); err != nil {
		t.Errorf("1 MB should fit: %v", err)
	}
	if err := ensureSpace(t.TempDir(), 1<<40); err == nil || !strings.Contains(err.Error(), "disk space") {
		t.Errorf("an impossible size must be refused, got %v", err)
	}
}
