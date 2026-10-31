//go:build linux

package firecracker

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// deviceOpenBy lists the PIDs (in this PID namespace, under procRoot) that
// hold the block device dev open. A killed VMM tears down its guest memory
// before closing its files, so it can keep an OverlayBD device open for a
// while after SIGKILL.
func deviceOpenBy(procRoot, dev string) []string {
	var device syscall.Stat_t
	if err := syscall.Stat(dev, &device); err != nil || device.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return nil
	}
	fds, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*", "fd", "*"))
	var holders []string
	seen := map[string]bool{}
	self := strconv.Itoa(os.Getpid())
	for _, fd := range fds {
		var target syscall.Stat_t
		if syscall.Stat(fd, &target) != nil || target.Mode&syscall.S_IFMT != syscall.S_IFBLK || target.Rdev != device.Rdev {
			continue
		}
		pid := filepath.Base(filepath.Dir(filepath.Dir(fd)))
		if !seen[pid] && pid != self {
			seen[pid] = true
			holders = append(holders, pid)
		}
	}
	return holders
}
