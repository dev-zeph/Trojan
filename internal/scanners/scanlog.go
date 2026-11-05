package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// scanLog records a scanner that failed to run in ~/.trojan/logs/scan.log for
// troubleshooting. Failures are not shown to users: the scan uses the
// scanners that ran.
func scanLog(format string, args ...any) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".trojan", "logs")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "scan.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	msg := strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " ")
	if len(msg) > 2000 {
		msg = msg[:2000] + "..."
	}
	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), msg)
}
