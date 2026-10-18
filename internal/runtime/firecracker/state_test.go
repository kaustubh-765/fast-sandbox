package firecracker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	fastletapi "fast-sandbox/internal/protocol/fastlet"
)

func TestSandboxDirRejectsUnsafeIDs(t *testing.T) {
	root := t.TempDir()
	for _, sandboxID := range []string{"", ".", "..", "a/b", "a\\b", "a\x00b"} {
		_, err := sandboxDir(root, sandboxID)
		require.ErrorIs(t, err, ErrInvalidConfig, "sandbox id %q", sandboxID)
	}
}

func TestStateRoundTrip(t *testing.T) {
	root := t.TempDir()
	directory, err := ensureSandboxDir(root, "sandbox-1")
	require.NoError(t, err)

	state := &SandboxState{
		Config:     fastletapi.RuntimeSandboxConfig{Desired: fastletapi.SandboxDesiredSpec{Image: "example.com/app:v1"}, Identity: fastletapi.SandboxIdentity{SandboxUID: "sandbox-1"}},
		Phase:      PhaseRunning,
		PID:        4242,
		APIAddress: filepath.Join(directory, "api.sock"),
		CreatedAt:  1720000000,
	}
	require.NoError(t, saveState(directory, state))

	loaded, err := loadState(directory)
	require.NoError(t, err)
	require.Equal(t, state.Config.Identity.SandboxUID, loaded.Config.Identity.SandboxUID)
	require.Equal(t, state.Config.Desired.Image, loaded.Config.Desired.Image)
	require.Equal(t, PhaseRunning, loaded.Phase)
	require.Equal(t, 4242, loaded.PID)
	require.Equal(t, state.APIAddress, loaded.APIAddress)
}

func TestLoadStateRejectsIncomplete(t *testing.T) {
	root := t.TempDir()
	directory, err := ensureSandboxDir(root, "sandbox-1")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(metaPath(directory), []byte(`{"phase":"Running"}`), 0o600))

	_, err = loadState(directory)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestListAndRemoveSandboxDirs(t *testing.T) {
	root := t.TempDir()
	first, err := ensureSandboxDir(root, "sandbox-1")
	require.NoError(t, err)
	second, err := ensureSandboxDir(root, "sandbox-2")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, sandboxStateDir, "not a valid id!"), 0o750))

	directories, err := listSandboxDirs(root)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{first, second}, directories)

	require.NoError(t, removeSandboxDir(first))
	_, err = os.Stat(first)
	require.True(t, os.IsNotExist(err))
	_, err = loadState(first)
	require.True(t, os.IsNotExist(err))
}

func TestRemoveSandboxDirRefusesRoot(t *testing.T) {
	root := t.TempDir()
	err := removeSandboxDir(filepath.Join(root, sandboxStateDir))
	require.ErrorIs(t, err, ErrInvalidConfig)
}
