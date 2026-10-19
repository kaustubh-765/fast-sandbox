package firecracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	runtimecatalog "fast-sandbox/internal/catalog/runtime"
	runtimecontract "fast-sandbox/internal/runtime/contract"
)

func seedSharedBase(t *testing.T, root, image string) (string, map[string]any) {
	t.Helper()
	dir := filepath.Dir(cachedManifestPath(root, image))
	require.NoError(t, os.MkdirAll(dir, 0o750))
	path := filepath.Join(dir, artifacts.SharedRootfsName)
	require.NoError(t, os.WriteFile(path, make([]byte, 2<<20), 0o444))
	sum, err := artifacts.SHA256File(path)
	require.NoError(t, err)
	doc := map[string]any{"sharedRootfs": artifacts.SharedRootfs{Layout: artifacts.SharedRootfsLayout, SHA256: sum, SizeBytes: 2 << 20}, "files": map[string]any{artifacts.SharedRootfsName: map[string]any{"sha256": sum, "sizeBytes": int64(2 << 20)}}}
	payload, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), payload, 0o600))
	return path, doc
}

func TestSharedBaseHardLinksSurviveCacheRemoval(t *testing.T) {
	root := t.TempDir()
	base, _ := seedSharedBase(t, root, "image")
	a, b := t.TempDir(), t.TempDir()
	require.NoError(t, stageSharedRootfs(root, "image", a))
	require.NoError(t, stageSharedRootfs(root, "image", b))
	require.NoError(t, stageSharedRootfs(root, "image", a)) // replay after interrupted setup
	source, err := os.Stat(base)
	require.NoError(t, err)
	for _, dir := range []string{a, b} {
		target, err := os.Stat(filepath.Join(dir, artifacts.SharedRootfsName))
		require.NoError(t, err)
		require.True(t, os.SameFile(source, target))
	}
	require.NoError(t, os.RemoveAll(filepath.Dir(base)))
	_, err = os.Stat(filepath.Join(a, artifacts.SharedRootfsName))
	require.NoError(t, err)
}

func TestSharedBaseRejectsTamperAndBudget(t *testing.T) {
	root := t.TempDir()
	base, _ := seedSharedBase(t, root, "image")
	require.NoError(t, validateSharedRootfsBudget(runtimecatalog.FirecrackerConfig{}, root, "image"))
	require.Error(t, validateSharedRootfsBudget(runtimecatalog.FirecrackerConfig{SharedRootfsMemory: "0"}, root, "image"))
	require.Error(t, validateSharedRootfsBudget(runtimecatalog.FirecrackerConfig{SharedRootfsMemory: "1Mi"}, root, "image"))
	require.NoError(t, os.Chmod(base, 0o600))
	f, err := os.OpenFile(base, os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("corrupt"), 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.ErrorContains(t, stageSharedRootfs(root, "image", t.TempDir()), "digest mismatch")
}

func TestCheckpointStagesVerifiedBase(t *testing.T) {
	root := t.TempDir()
	base, doc := seedSharedBase(t, root, "image")
	staging := t.TempDir()
	require.NoError(t, stageSnapshotBase(doc, filepath.Dir(base), staging))
	info, err := os.Stat(filepath.Join(staging, artifacts.SharedRootfsName))
	require.NoError(t, err)
	require.EqualValues(t, 2<<20, info.Size())
	require.NoError(t, os.Remove(base))
	require.Error(t, stageSnapshotBase(doc, filepath.Dir(base), t.TempDir()))
}

func TestSharedRootfsAllocationRequiresFullSlotReservation(t *testing.T) {
	root := t.TempDir()
	seedSharedBase(t, root, "image")
	d := &Driver{config: runtimecatalog.FirecrackerConfig{SharedRootfsMemory: "16Gi"}}
	t.Setenv("FASTLET_CAPACITY", "2")
	t.Setenv("MEMORY_LIMIT", "16Gi")
	require.ErrorContains(t, d.validateSharedRootfsAllocation(root, "image", "8Gi"), "cannot cover DAX allocation")
	t.Setenv("MEMORY_LIMIT", "49Gi") // 2 * (8Gi + 16Gi + 512Mi)
	require.NoError(t, d.validateSharedRootfsAllocation(root, "image", "8Gi"))
	t.Setenv("MEMORY_LIMIT", "")
	require.ErrorContains(t, d.validateSharedRootfsAllocation(root, "image", "8Gi"), "MEMORY_LIMIT")
}

func TestAgentRestoreWaitsForManifestAndDAXBase(t *testing.T) {
	root := t.TempDir()
	image := "cold-dax"
	dir := filepath.Dir(cachedManifestPath(root, image))
	require.NoError(t, os.MkdirAll(dir, 0o750))
	for _, name := range []string{rootfsImageName, vmstateSnapshotName, memorySnapshotName} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("present"), 0o640))
	}
	d := &Driver{agentSocket: "agent.sock"}
	require.ErrorIs(t, d.verifyRestorableImage(root, image), ErrImageNotReady)
	base, _ := seedSharedBase(t, root, image)
	require.NoError(t, d.verifyRestorableImage(root, image))
	require.NoError(t, os.Remove(base))
	require.ErrorIs(t, d.verifyRestorableImage(root, image), ErrImageNotReady)
}

func TestCheckpointCacheRetainsSharedBase(t *testing.T) {
	root := t.TempDir()
	base, _ := seedSharedBase(t, root, "source")
	staging := filepath.Dir(base)
	for _, name := range []string{publishedRootfsName, vmstateSnapshotName, memorySnapshotName} {
		require.NoError(t, os.WriteFile(filepath.Join(staging, name), []byte("checkpoint"), 0o640))
	}
	d := &Driver{config: runtimecatalog.FirecrackerConfig{StateRoot: root}, imageUseCount: map[string]int64{}}
	result := &runtimecontract.SnapshotResult{ArtifactDigest: "checkpoint-digest"}
	require.NoError(t, d.commitCheckpointCache(result, staging))
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, verifyRestorableImage(root, reference))
	_, err := os.Stat(filepath.Join(filepath.Dir(cachedManifestPath(root, reference)), artifacts.SharedRootfsName))
	require.NoError(t, err)
}
