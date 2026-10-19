package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
)

func TestSharedBaseReusedAcrossArtifactSets(t *testing.T) {
	content := make([]byte, 2<<20)
	sum := sha256Hex(content)
	store := &fakeStore{bucket: testBucket, prefix: testPrefix, objects: map[string][]byte{"one/base.ext4": content}, flaky: map[string]int{}}
	client := &Client{s3: testS3Client(t, store)}
	root := t.TempDir()
	file := nativeFile{publish: artifacts.SharedRootfsName, cache: artifacts.SharedRootfsName, sha256: sum, sizeBytes: int64(len(content))}
	var first os.FileInfo
	for _, ref := range []string{"golden", "checkpoint"} {
		dir := imageDir(root, ref)
		require.NoError(t, os.MkdirAll(dir, 0o750))
		// The second key does not exist: a valid canonical file avoids a re-download.
		require.NoError(t, stageFile(context.Background(), client, dir, refKey(ref), file))
		info, err := os.Stat(filepath.Join(dir, file.cache))
		require.NoError(t, err)
		require.Zero(t, info.Mode().Perm()&0o222)
		if first == nil {
			first = info
		} else {
			require.True(t, os.SameFile(first, info))
		}
	}
	require.Equal(t, 1, store.countRequested("one/base.ext4"))
}

func refKey(ref string) string {
	if ref == "golden" {
		return "one/base.ext4"
	}
	return "not-present/base.ext4"
}
