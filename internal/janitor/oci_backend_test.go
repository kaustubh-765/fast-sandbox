package janitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	fastletapi "fast-sandbox/internal/protocol/fastlet"
)

func TestOCICleanupKeepsOtherPodsAndRetainsFailedPack(t *testing.T) {
	root := t.TempDir()
	for _, pod := range []string{"old-pod", "replacement-pod"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "oci/pods", pod, "sandboxes/same-sandbox"), 0750))
	}
	for _, name := range []string{".locks", ".manifest-cache"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "oci/pods/old-pod/sandboxes", name), 0750))
	}
	staging := filepath.Join(root, "snapshots/old-pod/snapshot-a")
	require.NoError(t, os.MkdirAll(staging, 0750))
	raw, err := json.Marshal(fastletapi.SandboxIdentity{FastletPodUID: "old-pod"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(staging, ".pack-owner.json"), raw, 0600))
	backend := NewOCIBackend(root)
	resources, err := backend.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, resources, 3)
	var commands [][]string
	backend.run = func(_ context.Context, args ...string) error { commands = append(commands, args); return nil }
	for _, resource := range resources {
		if resource.ResourceID == "sandbox/old-pod/same-sandbox" {
			require.NoError(t, backend.Cleanup(context.Background(), resource))
		}
	}
	require.Len(t, commands, 1)
	require.Contains(t, commands[0], filepath.Join(root, "oci/pods/old-pod/sandboxes"))
	require.NotContains(t, commands[0], filepath.Join(root, "oci/pods/replacement-pod/sandboxes"))
	for _, resource := range resources {
		if resource.ResourceID != "pack/old-pod/snapshot-a" {
			continue
		}
		backend.run = func(context.Context, ...string) error { return errors.New("device busy") }
		require.ErrorContains(t, backend.Cleanup(context.Background(), resource), "device busy")
		require.DirExists(t, staging)
		require.NoError(t, os.WriteFile(filepath.Join(staging, ".pack-owner.json"), []byte(`{"fastletPodUid":"replacement-pod"}`), 0600))
		require.ErrorContains(t, backend.Cleanup(context.Background(), resource), "ownership")
	}
}
