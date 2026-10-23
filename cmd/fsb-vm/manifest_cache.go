package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	manifestCacheMaxBytes = 128 << 20
	manifestCacheMaxFiles = 4096
)

func manifestCacheRoot() string {
	if global.manifestCacheDir != "" {
		return global.manifestCacheDir
	}
	return filepath.Join(global.stateDir, ".manifest-cache")
}

// createManifestCachePath scopes immutable manifests to the registry access
// context. Credential rotation cannot reuse another credential's cached metadata;
// only a hash of the scope is persisted, never the credential itself.
func createManifestCachePath(ref registry.Reference, config dockerConfig) (string, error) {
	if !strings.HasPrefix(ref.Reference, "sha256:") {
		return "", nil // mutable tags retain their remote resolution semantics
	}
	expected := digest.Digest(ref.Reference)
	if err := expected.Validate(); err != nil {
		return "", err
	}
	credential, _, err := credentialFor(config, ref)
	if err != nil {
		return "", err
	}
	scope, err := json.Marshal(struct {
		Repository string
		PlainHTTP  bool
		Credential auth.Credential
	}{ref.Registry + "/" + ref.Repository, global.plainHTTP, credential})
	if err != nil {
		return "", err
	}
	return filepath.Join(manifestCacheRoot(), digest.FromBytes(scope).Encoded(), expected.Encoded()+".json"), nil
}

func readCachedManifest(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	return raw, true
}

func readCachedImageManifest(path, reference string) ([]byte, bool) {
	raw, ok := readCachedManifest(path)
	if !ok || digest.FromBytes(raw).String() != reference {
		return nil, false
	}
	return raw, true
}

func cacheImageManifest(path, reference string, raw []byte) error {
	// fetchManifestJSON may have selected a platform manifest from an index.
	// Never install that child's bytes under its parent's digest.
	if path == "" || digest.FromBytes(raw).String() != reference {
		return nil
	}
	return cacheManifestFile(path, raw)
}

func cacheManifestFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return err
	}
	return trimManifestCache(manifestCacheRoot(), manifestCacheMaxBytes, manifestCacheMaxFiles)
}

// Eviction only removes metadata, never mounted devices or VM backing files.
// Atomic writes and cache-miss fallback also tolerate concurrent CLI processes.
func trimManifestCache(root string, maxBytes int64, maxFiles int) error {
	type entry struct {
		path string
		info fs.FileInfo
	}
	var entries []entry
	var directories []string
	var total int64
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if item.IsDir() {
			if path != root {
				directories = append(directories, path)
			}
			return nil
		}
		if !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".json.template") {
			return nil
		}
		info, err := item.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			entries = append(entries, entry{path, info})
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].info.ModTime().Before(entries[j].info.ModTime()) })
	count := len(entries)
	for _, item := range entries {
		if total <= maxBytes && count <= maxFiles {
			break
		}
		if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		total -= item.info.Size()
		count--
	}
	// Remove only empty scope directories; another writer may still use them.
	for i := len(directories) - 1; i >= 0; i-- {
		_ = os.Remove(directories[i])
	}
	return nil
}
