//go:build linux || darwin

package firecracker

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"fast-sandbox/internal/artifacts"
)

// collectSharedRootfs removes canonical entries with no artifact or instance
// links. The last-link check is conservative; a race with pull can only force
// that pull to retry, never change bytes behind an existing VM mapping.
func collectSharedRootfs(stateRoot string) error {
	dir := filepath.Join(stateRoot, artifacts.SharedRootfsCacheDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !validImageDigest(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && stat.Nlink == 1 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			_ = os.Remove(path + artifacts.VerificationReceiptSuffix)
		}
	}
	return nil
}

func rootfsDiskBytes(info os.FileInfo) int64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Blocks * 512
	}
	return info.Size()
}
