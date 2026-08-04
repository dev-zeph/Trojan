//go:build !windows

package scanners

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcGroup starts the command as its own process-group leader so the whole
// group can be signalled at once on cancel.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree force-kills the process and its group (negative PID).
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
