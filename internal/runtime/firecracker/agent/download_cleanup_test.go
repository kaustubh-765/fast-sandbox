package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterruptedArtifactDownloadRemovesOnlyItsTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"rootfs.img.tmp-old", "memory.snap.tmp-other", "manifest.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0o600))
	}
	require.NoError(t, removeStaleDownloads(dir, "rootfs.img.tmp-"))
	_, err := os.Stat(filepath.Join(dir, "rootfs.img.tmp-old"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "memory.snap.tmp-other"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
}
