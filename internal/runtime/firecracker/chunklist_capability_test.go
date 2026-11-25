package firecracker

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	agentpull "fast-sandbox/internal/runtime/firecracker/agent"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

// The Fastlet skips whole-file hashes only on a capability the agent reports
// in the Health call made right before the decision; a failed Health clears
// it, so the Fastlet falls back to hashing.
func TestAgentStagesBySizeFollowsLiveHealth(t *testing.T) {
	server := newFakeAgentServer(t)
	var capability, healthy atomic.Bool
	healthy.Store(true)
	server.responses[agentprotocol.RouteHealth] = func(writer http.ResponseWriter, _ []byte) {
		if !healthy.Load() {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(agentprotocol.HealthResponse{OK: true, ChunkListDigest: capability.Load()})
	}
	server.responses[agentprotocol.RoutePublishImage] = func(writer http.ResponseWriter, _ []byte) {
		_ = json.NewEncoder(writer).Encode(agentprotocol.PublishImageResponse{ManifestRef: "s3://b/x/manifest.json", ArtifactDigest: "d", ChunkListDigest: true})
	}
	client, err := NewAgentClient(server.socket, "tenant-a", "pod-1")
	require.NoError(t, err)
	driver := &Driver{agentClient: client}
	reporter := client.(chunkListDigestReporter)

	require.False(t, driver.agentStagesBySize(context.Background()), "no capability reported")
	capability.Store(true)
	require.True(t, driver.agentStagesBySize(context.Background()))

	// The agent restarted without the capability: the cached value is not
	// trusted, the Health right before the decision is.
	capability.Store(false)
	require.False(t, driver.agentStagesBySize(context.Background()))

	// PublishImage responses update the cached capability too.
	_, err = client.PublishImage(context.Background(), "req", agentprotocol.PublishKindCheckpoint, "", "/staging")
	require.NoError(t, err)
	require.True(t, reporter.ChunkListDigest())

	healthy.Store(false)
	require.False(t, driver.agentStagesBySize(context.Background()), "a Health error means hashing")
	require.False(t, reporter.ChunkListDigest(), "a Health error clears the cached capability")

	// An agent client that cannot report the capability means hashing.
	require.False(t, (&Driver{agentClient: &fakeAgentClient{}}).agentStagesBySize(context.Background()))
}

// Size-only staging records the native files by size, hashes only the state
// files, and lists only those in SHA256SUMS.
func TestCollectSnapshotManifestEntriesSizeOnly(t *testing.T) {
	staging := t.TempDir()
	for _, name := range []string{publishedRootfsName, vmstateSnapshotName, memorySnapshotName, policyBundleName} {
		require.NoError(t, os.WriteFile(filepath.Join(staging, name), []byte("data-"+name), 0o640))
	}
	var hashed atomic.Int64
	previous := hashStagedFile
	hashStagedFile = func(path string) (string, int64, agentpull.VerifiedFile, error) {
		hashed.Add(1)
		return previous(path)
	}
	t.Cleanup(func() { hashStagedFile = previous })

	entries, err := collectSnapshotManifestEntries(staging, false, nil, true)
	require.NoError(t, err)
	require.Equal(t, int64(1), hashed.Load(), "only the policy bundle is hashed")
	require.Equal(t, []string{policyBundleName}, entries.Names)
	for _, name := range []string{publishedRootfsName, vmstateSnapshotName, memorySnapshotName} {
		require.Equal(t, artifacts.ManifestFile{SizeBytes: int64(len("data-" + name))}, entries.Files[name])
	}
	require.Equal(t, artifacts.SHA256Of([]byte("data-"+policyBundleName)), entries.StateFiles[policyBundleName].SHA256)

	hashed.Store(0)
	entries, err = collectSnapshotManifestEntries(staging, false, nil, false)
	require.NoError(t, err)
	require.Equal(t, int64(4), hashed.Load())
	require.Len(t, entries.Names, 4)
	require.NotEmpty(t, entries.Files[memorySnapshotName].SHA256)
}
