package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"fast-sandbox/internal/artifacts"
)

var sharedBasePullLocks [256]sync.Mutex

// stageSharedBase commits one verified, read-only inode per node and digest.
// stageFile downloads under a non-special local name to avoid recursion.
func stageSharedBase(ctx context.Context, c *Client, dir, key string, file nativeFile) error {
	lock := &sharedBasePullLocks[sha256.Sum256([]byte(file.sha256))[0]]
	lock.Lock()
	defer lock.Unlock()
	root := filepath.Join(filepath.Dir(filepath.Dir(dir)), artifacts.SharedRootfsCacheDir)
	if err := os.MkdirAll(root, cacheDirMode); err != nil {
		return err
	}
	if err := cleanupSharedBaseDownloads(root, file.sha256); err != nil {
		return err
	}

	canonical := filepath.Join(root, file.sha256)
	if err := ensureSharedBase(ctx, c, root, canonical, key, file); err != nil {
		return err
	}

	target := filepath.Join(dir, file.cache)
	if info, err := os.Stat(target); err == nil {
		base, err := os.Stat(canonical)
		if err != nil {
			return err
		}
		if os.SameFile(info, base) {
			return nil
		}
		if err := os.Remove(target); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Link(canonical, target); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func cleanupSharedBaseDownloads(root, digest string) error {
	// Recover disk space after an agent crash before the canonical commit.
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".pull-"+digest+"-") {
			if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureSharedBase(ctx context.Context, c *Client, root, canonical, key string, file nativeFile) error {
	canonicalFile := file
	canonicalFile.publish = file.sha256
	canonicalFile.cache = file.sha256
	if err := artifacts.VerifyImmutableFile(canonical, file.sha256, file.sizeBytes); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err != nil {
		if _, err := os.Stat(canonical); err == nil {
			return fmt.Errorf("corrupt immutable DAX base %s", file.sha256)
		}
		staging, err := os.MkdirTemp(root, ".pull-"+file.sha256+"-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(staging)
		if err := stageFile(ctx, c, staging, key, canonicalFile); err != nil {
			return err
		}
		downloaded := filepath.Join(staging, file.sha256)
		if err := os.Chmod(downloaded, 0o444); err != nil {
			return err
		}
		if err := os.Link(downloaded, canonical); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		// A racing writer must have committed exactly the same verified bytes.
		if ok, err := fileMatches(canonical, canonicalFile); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("DAX base cache digest mismatch")
		}
	}
	if err := artifacts.VerifyImmutableFile(canonical, file.sha256, file.sizeBytes); err != nil {
		return err
	}
	return nil
}
