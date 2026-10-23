package oci_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeToolInstallVerifiesBeforePublishing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installer uses GNU mv, as in the runtime image")
	}
	source, target := filepath.Join(t.TempDir(), "bundle"), filepath.Join(t.TempDir(), "tools")
	require.NoError(t, os.MkdirAll(filepath.Join(source, "bin"), 0755))
	payload := []byte("#!/bin/sh\necho first\n")
	install := func() ([]byte, error) { return exec.Command("sh", "install-tools.sh", source, target).CombinedOutput() }
	write := func(data []byte) string {
		require.NoError(t, os.WriteFile(filepath.Join(source, "bin/fsb-vm"), data, 0755))
		sums := []byte(fmt.Sprintf("%x  bin/fsb-vm\n", sha256.Sum256(data)))
		require.NoError(t, os.WriteFile(filepath.Join(source, "SHA256SUMS"), sums, 0644))
		revision := fmt.Sprintf("%x", sha256.Sum256(sums))
		require.NoError(t, os.WriteFile(filepath.Join(source, "REVISION"), []byte(revision+"\n"), 0644))
		return revision
	}
	first := write(payload)
	output, err := install()
	require.NoError(t, err, string(output))
	current, err := os.Readlink(filepath.Join(target, "current"))
	require.NoError(t, err)
	require.Equal(t, "releases/"+first, current)
	require.NoError(t, os.WriteFile(filepath.Join(source, "bin/fsb-vm"), []byte("corrupt"), 0755))
	_, err = install()
	require.Error(t, err)
	current, err = os.Readlink(filepath.Join(target, "current"))
	require.NoError(t, err)
	require.Equal(t, "releases/"+first, current)
	second := write([]byte("#!/bin/sh\necho second\n"))
	output, err = install()
	require.NoError(t, err, string(output))
	current, err = os.Readlink(filepath.Join(target, "current"))
	require.NoError(t, err)
	require.Equal(t, "releases/"+second, current)
	retained, err := os.ReadFile(filepath.Join(target, "releases", first, "bin/fsb-vm"))
	require.NoError(t, err)
	require.Equal(t, payload, retained)
}
