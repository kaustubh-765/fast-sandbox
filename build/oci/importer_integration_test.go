package oci_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeRawImporterRoundTrip(t *testing.T) {
	if os.Getenv("FAST_SANDBOX_TEST_NATIVE_OCI") != "1" {
		t.Skip("requires the built OCI native tools")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source.raw")
	file, err := os.Create(source)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(1<<20))
	_, err = file.WriteAt(bytes.Repeat([]byte("checkpoint-data"), 256), 4096)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	commit := filepath.Join(dir, "sealed.commit")
	output, err := exec.CommandContext(ctx, "overlaybd-import-raw", source, filepath.Join(dir, "data"), filepath.Join(dir, "index"), commit).CombinedOutput()
	require.NoError(t, err, "%s", output)
	// The importer reopens the sealed layer and verifies every byte against
	// the source before emitting this marker, including skipped sparse holes.
	require.Contains(t, string(output), "OVERLAYBD_IMPORT_SUCCEEDED logical_bytes=1048576")
	require.FileExists(t, commit)
}
