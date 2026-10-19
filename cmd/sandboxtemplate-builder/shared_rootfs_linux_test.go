//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidationRootfsDoesNotMutateGoldenUpper(t *testing.T) {
	root := t.TempDir()
	golden := filepath.Join(root, rootfsImageName)
	require.NoError(t, os.WriteFile(golden, []byte("golden disk"), 0o600))
	require.NoError(t, os.Symlink(golden, filepath.Join(root, snapshotDriveName)))
	target, err := prepareValidationRootfs(root, golden)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target, []byte("validation writes"), 0o600))
	actual, err := os.ReadFile(golden)
	require.NoError(t, err)
	require.Equal(t, []byte("golden disk"), actual)
	link, err := os.Readlink(filepath.Join(root, snapshotDriveName))
	require.NoError(t, err)
	require.Equal(t, target, link)
}
