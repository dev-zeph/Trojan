//go:build !windows

package config

import "syscall"

// freeMB returns the free space, in MB, on the volume holding path.
func freeMB(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize) / (1 << 20), true
}
