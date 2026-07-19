package scanners

import (
	"os/exec"

	"github.com/dev-zeph/trojan/internal/config"
)

// ManagedBinary returns the path to a scanner binary.
// Prefers the version managed by Trojan in ~/.trojan/bin/.
// Falls back to whatever is on the system PATH.
// Returns the bare name if neither is found (caller handles the error).
func ManagedBinary(name string) string {
	if p := config.ManagedBinaryPath(name); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// IsInstalled returns true if a scanner binary can be found,
// either in ~/.trojan/bin/ or on the system PATH.
func IsInstalled(name string) bool {
	if config.ManagedBinaryPath(name) != "" {
		return true
	}
	_, err := exec.LookPath(name)
	return err == nil
}
