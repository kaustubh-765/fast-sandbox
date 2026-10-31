package firecracker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	fastletapi "fast-sandbox/internal/protocol/fastlet"
)

const testOCIDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func testOCIDrive() artifacts.OCIDrive {
	return artifacts.OCIDrive{Image: "python:3.12-slim", Digest: testOCIDigest, DiskKey: ociDiskKey(testOCIDigest)}
}

// writeOCIManifest commits a cached manifest for image, optionally recording
// an OCI drive. The T2 CPU template keeps validation independent of the host.
func writeOCIManifest(t *testing.T, stateRoot, image string, drive *artifacts.OCIDrive) {
	t.Helper()
	document := artifacts.NewVMManifest(artifacts.VMMachine{VCPUCount: 2, MemoryMiB: 4096, RootfsSizeMiB: 4096, RootfsDriveID: "rootfs", RootfsDrivePath: "rootfs.img"}, "6.1.177", "/missing/firecracker", artifacts.CPUTemplateT2)
	document.Compatibility.FirecrackerVersion = "1.16.1"
	document.OCIDrive = drive
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	path := cachedManifestPath(stateRoot, image)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, raw, 0o644))
}

func seedOCIDisk(t *testing.T, manager *ociDiskManager, key string) string {
	t.Helper()
	path := manager.diskPath(key)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("ext4"), 0o444))
	return path
}

func TestOCIDiskKeyIsStablePerDigest(t *testing.T) {
	require.Equal(t, ociDiskKey(testOCIDigest), ociDiskKey(testOCIDigest))
	require.NotEqual(t, ociDiskKey(testOCIDigest), ociDiskKey("sha256:2222222222222222222222222222222222222222222222222222222222222222"))
	require.NoError(t, testOCIDrive().Validate())
}

func TestOCIPullReferenceRewritesOnlyDockerHub(t *testing.T) {
	manager := &ociDiskManager{mirror: "10.0.0.5:5000"}
	tests := map[string]string{
		"python:3.12-slim":                    "10.0.0.5:5000/library/python:3.12-slim",
		"docker.io/library/node:24-slim":      "10.0.0.5:5000/library/node:24-slim",
		"bitnami/redis:7.4":                   "10.0.0.5:5000/bitnami/redis:7.4",
		"gcr.io/distroless/static:nonroot":    "gcr.io/distroless/static:nonroot",
		"python@" + testOCIDigest:             "10.0.0.5:5000/library/python@" + testOCIDigest,
		"registry.local:5000/team/app:v1.2.3": "registry.local:5000/team/app:v1.2.3",
	}
	for image, want := range tests {
		reference, err := manager.pullReference(image)
		require.NoError(t, err, image)
		require.Equal(t, want, reference.Name(), image)
	}

	unmirrored := &ociDiskManager{}
	reference, err := unmirrored.pullReference("python:3.12-slim")
	require.NoError(t, err)
	require.Equal(t, "index.docker.io/library/python:3.12-slim", reference.Name())
}

func TestPlaceOCIDrivePlaceholderAndDisk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, placeOCIDrive(dir, ""))
	info, err := os.Stat(filepath.Join(dir, artifacts.OCIDriveFileName))
	require.NoError(t, err)
	require.Equal(t, int64(artifacts.OCIDrivePlaceholderBytes), info.Size())

	disk := filepath.Join(t.TempDir(), "disk.img")
	require.NoError(t, os.WriteFile(disk, []byte("converted"), 0o444))
	require.NoError(t, placeOCIDrive(dir, disk), "replaces an existing placeholder")
	content, err := os.ReadFile(filepath.Join(dir, artifacts.OCIDriveFileName))
	require.NoError(t, err)
	require.Equal(t, "converted", string(content))
}

func TestResolveOCIDriveDisabledIsNoop(t *testing.T) {
	driver := &Driver{}
	drive, disk, fresh, err := driver.resolveOCIDrive(context.Background(), t.TempDir(), "tpl-golden",
		fastletapi.SandboxSpec{Env: map[string]string{OCIDriveImageEnv: "python:3.12-slim"}})
	require.NoError(t, err)
	require.Nil(t, drive)
	require.Empty(t, disk)
	require.False(t, fresh)
}

// A resume or a create from a snapshot restores a set whose manifest records
// the drive: the recorded disk is re-attached and the spec env is ignored.
func TestResolveOCIDriveManifestRecordWinsOverEnv(t *testing.T) {
	stateRoot := t.TempDir()
	manager := &ociDiskManager{stateRoot: stateRoot, inflight: map[string]*sync.Mutex{}}
	recorded := testOCIDrive()
	disk := seedOCIDisk(t, manager, recorded.DiskKey)
	writeOCIManifest(t, stateRoot, "osb-snap-1", &recorded)
	driver := &Driver{ociDisks: manager}

	drive, path, fresh, err := driver.resolveOCIDrive(context.Background(), stateRoot, "osb-snap-1",
		fastletapi.SandboxSpec{Env: map[string]string{OCIDriveImageEnv: "node:24-slim"}})
	require.NoError(t, err)
	require.Equal(t, &recorded, drive)
	require.Equal(t, disk, path)
	require.False(t, fresh, "the vmstate already carries the disk size")
}

// The golden template carries no drive record and no image was requested:
// the placeholder is attached.
func TestResolveOCIDriveGoldenWithoutImageUsesPlaceholder(t *testing.T) {
	stateRoot := t.TempDir()
	writeOCIManifest(t, stateRoot, "tpl-golden", nil)
	driver := &Driver{ociDisks: &ociDiskManager{stateRoot: stateRoot, inflight: map[string]*sync.Mutex{}}}
	drive, disk, fresh, err := driver.resolveOCIDrive(context.Background(), stateRoot, "tpl-golden", fastletapi.SandboxSpec{})
	require.NoError(t, err)
	require.Nil(t, drive)
	require.Empty(t, disk)
	require.False(t, fresh)
}

func TestResolveOCIDriveRejectsCorruptRecord(t *testing.T) {
	stateRoot := t.TempDir()
	manager := &ociDiskManager{stateRoot: stateRoot, inflight: map[string]*sync.Mutex{}}
	_, err := manager.attach(context.Background(), artifacts.OCIDrive{Image: "python", Digest: "sha256:nope", DiskKey: "../escape"})
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestOCIDiskSizeGBRoundsUp(t *testing.T) {
	require.Equal(t, int64(1), ceilGB(0))
	require.Equal(t, int64(2), ceilGB(1_000_000_001))
}
