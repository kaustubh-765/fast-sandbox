package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
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

func TestOCIDiskSizeLeavesHeadroom(t *testing.T) {
	require.Equal(t, int64(256*1024), ociDiskSizeKiB(0))
	require.Greater(t, ociDiskSizeKiB(100<<20), int64(150<<10))
}

func tarLayer(t *testing.T, entries []tar.Header, bodies map[string]string) v1.Layer {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range entries {
		header := header
		header.Uid, header.Gid = os.Getuid(), os.Getgid()
		body := bodies[header.Name]
		header.Size = int64(len(body))
		require.NoError(t, writer.WriteHeader(&header))
		_, err := writer.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	payload := buffer.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil })
	require.NoError(t, err)
	return layer
}

// A hostile image may plant a symlink to an absolute host path and then write
// through it; every entry must still land inside the extraction root.
func TestExtractImageStaysInsideRoot(t *testing.T) {
	outside := t.TempDir()
	layer := tarLayer(t, []tar.Header{
		{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/bin/tool", Typeflag: tar.TypeReg, Mode: 0o4755},
		{Name: "usr/bin/alias", Typeflag: tar.TypeLink, Linkname: "usr/bin/tool"},
		{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: outside},
		{Name: "escape/owned", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "../../dotdot", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"usr/bin/tool": "#!/bin/sh\n", "escape/owned": "x", "../../dotdot": "y"})
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	parent := t.TempDir()
	root := filepath.Join(parent, "rootfs")
	total, err := extractImage(img, root)
	require.NoError(t, err)
	require.GreaterOrEqual(t, total, int64(len("#!/bin/sh\n")))

	info, err := os.Stat(filepath.Join(root, "usr/bin/tool"))
	require.NoError(t, err)
	require.Equal(t, os.ModeSetuid|0o755, info.Mode()&(os.ModeSetuid|os.ModePerm))
	alias, err := os.Stat(filepath.Join(root, "usr/bin/alias"))
	require.NoError(t, err)
	require.True(t, os.SameFile(info, alias), "hard link resolves inside root")
	target, err := os.Readlink(filepath.Join(root, "escape"))
	require.NoError(t, err)
	require.Equal(t, outside, target, "the symlink itself is preserved for the guest")

	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	require.Empty(t, entries, "nothing was written through the symlink on the host")
	_, err = os.Stat(filepath.Join(parent, "dotdot"))
	require.True(t, os.IsNotExist(err), "dot-dot names never land above the root")
}
