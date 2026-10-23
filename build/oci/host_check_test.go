package oci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostCheckOCIStorageRequirement(t *testing.T) {
	for _, test := range []struct {
		name, enabled, fs, blocks, status, detail string
	}{
		{"enabled-ext4", "true", "ext2/ext3", "26214400", "WARN", "skipping XFS/reflink validation"},
		{"enabled-xfs", "true", "xfs", "26214400", "WARN", "skipping XFS/reflink validation"},
		{"disabled-ext4", "false", "ext2/ext3", "26214400", "FAIL", "must use XFS"},
		{"default-ext4", "", "ext2/ext3", "26214400", "FAIL", "must use XFS"},
		{"invalid-ext4", "invalid", "ext2/ext3", "26214400", "FAIL", "must use XFS"},
		{"enabled-full-disk", "true", "ext2/ext3", "1", "FAIL", "minimum 10 GiB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte("#!/bin/sh\nprintf '%s %s 4096\\n' \"$TEST_FS\" \"$TEST_FREE_BLOCKS\"\n"), 0755))
			probe := filepath.Join(dir, "cp-probe")
			require.NoError(t, os.WriteFile(filepath.Join(dir, "cp"), []byte("#!/bin/sh\ntouch \"$TEST_CP_PROBE\"\nexit 1\n"), 0755))
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("FAST_SANDBOX_OCI_ENABLED", test.enabled)
			t.Setenv("TEST_FS", test.fs)
			t.Setenv("TEST_FREE_BLOCKS", test.blocks)
			t.Setenv("TEST_CP_PROBE", probe)
			cmd := exec.Command("bash", "../../scripts/firecracker-host-check.sh", "--state-root", filepath.Join(dir, "state"), "--assets-dir", filepath.Join(dir, "assets"))
			output, err := cmd.CombinedOutput()
			// Device/asset checks may fail on the test host; inspect the storage
			// result independently instead of requiring real KVM or Firecracker.
			if err != nil {
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
				require.Equal(t, 1, exitErr.ExitCode(), string(output))
			}
			storage := ""
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "stateroot-filesystem") {
					storage = line
				}
			}
			require.Contains(t, storage, test.status)
			require.Contains(t, storage, test.detail)
			require.NoFileExists(t, probe, "OCI mode must not run the reflink probe")
		})
	}
}
