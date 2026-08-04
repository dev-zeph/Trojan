//go:build windows

package scanners

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// createNewProcessGroup is the Windows CREATE_NEW_PROCESS_GROUP flag, so the
// child (and its children) can be terminated as a tree.
const createNewProcessGroup = 0x00000200

func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// killProcessTree force-kills the process and all of its descendants. Windows
// has no process-group signal like Unix, so `taskkill /T /F` walks the tree.
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = exec.Command("taskkill", "/PID", strconv.Itoa(p.Pid), "/T", "/F").Run()
	_ = p.Kill()
}
