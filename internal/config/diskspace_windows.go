//go:build windows

package config

import "golang.org/x/sys/windows"

// freeMB returns the free space, in MB, on the volume holding path.
func freeMB(path string) (int64, bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, false
	}
	return int64(free / (1 << 20)), true
}
