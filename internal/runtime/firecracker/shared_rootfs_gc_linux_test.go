//go:build linux

package firecracker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDAXCacheGCDoesNotChargeEmptyUpperCapacity(t *testing.T) {
	root := t.TempDir()
	base, _ := seedSharedBase(t, root, "dax")
	upper, err := os.Create(filepath.Join(filepath.Dir(base), rootfsImageName))
	require.NoError(t, err)
	require.NoError(t, upper.Truncate(32<<20))
	require.NoError(t, upper.Close())
	removed, err := garbageCollectImages(root, 10<<20, nil)
	require.NoError(t, err)
	require.Empty(t, removed)
	_, err = os.Stat(base)
	require.NoError(t, err)
}
