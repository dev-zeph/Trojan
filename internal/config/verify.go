package config

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const (
	binaryChecksumsURL = "https://github.com/dev-zeph/Trojan/releases/download/v%s/trojan_%s_binary_checksums.txt"
	binaryChecksumsSig = "https://github.com/dev-zeph/Trojan/releases/download/v%s/trojan_%s_binary_checksums.txt.sig"
)

// VerifyResult is the outcome of a verification run.
type VerifyResult struct {
	Version         string
	Platform        string
	BinaryPath      string
	BinaryHash      string
	ExpectedHash    string
	HashMatch       bool
	SignatureValid  bool
	SignatureError  error
}

// VerifyBinary verifies the running Trojan binary against the signed checksums
// published with its release. It:
//  1. Computes the SHA256 of the running binary.
//  2. Downloads the binary checksums file for this version from GitHub.
//  3. Verifies the GPG signature on the checksums file using the embedded
//     public key — no gpg binary required.
//  4. Confirms the binary hash matches the expected value in the checksums file.
func VerifyBinary(version string) (*VerifyResult, error) {
	platform := runtime.GOOS + "_" + runtime.GOARCH

	// Resolve the actual binary path (follows symlinks).
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("could not resolve binary path: %w", err)
	}

	// --- Step 1: Hash the running binary ---
	actualHash, err := sha256File(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("could not hash binary: %w", err)
	}

	result := &VerifyResult{
		Version:    version,
		Platform:   platform,
		BinaryPath: binaryPath,
		BinaryHash: actualHash,
	}

	client := &http.Client{Timeout: 15 * time.Second}

	// --- Step 2: Download the checksums file ---
	checksumsURL := fmt.Sprintf(binaryChecksumsURL, version, version)
	checksumsData, err := httpGet(client, checksumsURL)
	if err != nil {
		return result, fmt.Errorf("could not download checksums file: %w", err)
	}

	// --- Step 3: Download and verify the GPG signature ---
	sigURL := fmt.Sprintf(binaryChecksumsSig, version, version)
	sigData, err := httpGet(client, sigURL)
	if err != nil {
		result.SignatureError = fmt.Errorf("could not download signature file: %w", err)
	} else {
		result.SignatureValid, result.SignatureError = verifyDetachedSignature(checksumsData, sigData)
	}

	// --- Step 4: Parse checksums and find our platform ---
	expectedHash, err := findHashForPlatform(checksumsData, platform)
	if err != nil {
		return result, fmt.Errorf("binary hash not found for platform %s: %w", platform, err)
	}

	result.ExpectedHash = expectedHash
	result.HashMatch = strings.EqualFold(actualHash, expectedHash)

	return result, nil
}

// verifyDetachedSignature checks a detached OpenPGP signature against the
// embedded Trojan public key. No external gpg binary is required.
func verifyDetachedSignature(data, sigData []byte) (bool, error) {
	// Only attempt verification if the public key is not the placeholder.
	if strings.Contains(TrojanPublicKey, "PLACEHOLDER") {
		return false, fmt.Errorf("public key not configured — replace the placeholder in pubkey.go")
	}

	// Parse the armored public key.
	block, err := armor.Decode(strings.NewReader(TrojanPublicKey))
	if err != nil {
		return false, fmt.Errorf("could not decode public key: %w", err)
	}
	keyring, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return false, fmt.Errorf("could not read public key: %w", err)
	}

	// The signature from goreleaser is a binary (non-armored) detached sig.
	// Try binary first, then armored.
	_, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(sigData), nil)
	if err != nil {
		// Try armored signature
		sigBlock, aerr := armor.Decode(bytes.NewReader(sigData))
		if aerr != nil {
			return false, fmt.Errorf("signature verification failed: %w", err)
		}
		_, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(data), sigBlock.Body, nil)
		if err != nil {
			return false, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return true, nil
}

// findHashForPlatform parses a checksums file in the format:
//
//	<sha256hex>  trojan_<os>_<arch>
//
// and returns the hash for the given platform string (e.g. "darwin_arm64").
func findHashForPlatform(data []byte, platform string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// format: "<hash>  <name>"
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		hash, name := parts[0], parts[1]
		// name is "trojan_<os>_<arch>" — match the platform suffix
		if strings.HasSuffix(name, "_"+platform) || name == "trojan_"+platform {
			return hash, nil
		}
	}
	return "", fmt.Errorf("no entry found for platform %q", platform)
}

// sha256File computes the lowercase hex SHA256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// httpGet fetches a URL and returns the response body.
func httpGet(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}
