//go:build linux || darwin

package artifacts

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestImmutableFileReceiptTracksContentAndInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base")
	data := []byte("readonly data")
	require.NoError(t, os.WriteFile(path, data, 0o444))
	sum := SHA256Of(data)
	require.NoError(t, VerifyImmutableFile(path, sum, int64(len(data))))
	require.NoError(t, os.Link(path, path+".instance")) // ctime changes, content stays identical.
	require.NoError(t, VerifyImmutableFile(path, sum, int64(len(data))))
	info, err := os.Stat(path)
	require.NoError(t, err)
	replacement := path + ".new"
	require.NoError(t, os.WriteFile(replacement, []byte("changed! data"), 0o444))
	require.NoError(t, os.Chtimes(replacement, time.Now(), info.ModTime()))
	require.NoError(t, os.Rename(replacement, path))
	require.ErrorContains(t, VerifyImmutableFile(path, sum, int64(len(data))), "digest mismatch")
	require.NoError(t, os.Chmod(path, 0o644))
	require.Error(t, VerifyImmutableFile(path, sum, int64(len(data))))
}
