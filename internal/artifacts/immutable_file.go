//go:build linux || darwin

package artifacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// verifiedFile is a node-local receipt, never an imported artifact. The cache
// must be trusted host state, with consumers restricted to read-only access. A content
// write changes mtime; atomic replacement changes inode. ctime is deliberately
// excluded because creating/removing instance hard links changes ctime too.
type verifiedFile struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mtime  int64  `json:"mtime"`
}

const VerificationReceiptSuffix = ".verified.json"

// VerifyImmutableFile verifies bytes once per immutable inode/version. It
// avoids rehashing a multi-GiB base in every Fastlet on a warm restore. Missing
// or stale receipts require a full digest check; mismatches fail closed.
func VerifyImmutableFile(path, sha string, size int64) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() != size || info.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("invalid immutable file %s: read-only regular inode and exact size required", path)
	}
	expected := verifiedFile{SHA256: sha, Size: size, Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Mtime: info.ModTime().UnixNano()}
	var receipt verifiedFile
	payload, err := os.ReadFile(path + VerificationReceiptSuffix)
	if err == nil && json.Unmarshal(payload, &receipt) == nil && receipt == expected {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	digest, err := SHA256File(path)
	if err != nil {
		return err
	}
	if digest != sha {
		return fmt.Errorf("immutable file digest mismatch: %s", path)
	}
	after, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return fmt.Errorf("immutable file changed during verification")
	}
	payload, err = json.Marshal(expected)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".verified-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path+VerificationReceiptSuffix)
}
