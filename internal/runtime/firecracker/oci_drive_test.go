package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	fastletapi "fast-sandbox/internal/protocol/fastlet"
	runtimecontract "fast-sandbox/internal/runtime/contract"
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

func testOCIDiskManager(stateRoot string) *ociDiskManager {
	manager := newOCIDiskManager(stateRoot)
	manager.mirror = ""
	return manager
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
	manager := testOCIDiskManager(stateRoot)
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
	driver := &Driver{ociDisks: testOCIDiskManager(stateRoot)}
	drive, disk, fresh, err := driver.resolveOCIDrive(context.Background(), stateRoot, "tpl-golden", fastletapi.SandboxSpec{})
	require.NoError(t, err)
	require.Nil(t, drive)
	require.Empty(t, disk)
	require.False(t, fresh)
}

func TestResolveOCIDriveRejectsCorruptRecord(t *testing.T) {
	stateRoot := t.TempDir()
	manager := testOCIDiskManager(stateRoot)
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

func TestOCIDeliverReportsCachedDiskWithoutRegistry(t *testing.T) {
	manager := testOCIDiskManager(t.TempDir())
	drive := testOCIDrive()
	seedOCIDisk(t, manager, drive.DiskKey)
	manager.recent[drive.Image] = ociResolved{drive: drive, at: time.Now()}

	status, err := manager.deliver(drive.Image)
	require.NoError(t, err)
	require.Equal(t, runtimecontract.ImageDelivered, status)
	got, path, err := manager.ensure(context.Background(), drive.Image)
	require.NoError(t, err)
	require.Equal(t, drive, got)
	require.Equal(t, manager.diskPath(drive.DiskKey), path)

	manager.now = func() time.Time { return time.Now().Add(ociResolveTTL + time.Minute) }
	_, _, ok := manager.cached(drive.Image)
	require.False(t, ok, "a stale tag resolution is not reused")
}

// A conversion runs in the background while the create stays parked; its
// failure is reported exactly once and the next poll starts a new attempt.
func TestOCIDeliverParksThenReportsFailureOnce(t *testing.T) {
	manager := testOCIDiskManager(t.TempDir())
	const broken = "NOT//a valid reference"

	status, err := manager.deliver(broken)
	require.NoError(t, err)
	require.Equal(t, runtimecontract.ImageDelivering, status)
	manager.mu.Lock()
	delivery := manager.deliveries[broken]
	manager.mu.Unlock()
	<-delivery.done

	_, err = manager.deliver(broken)
	require.ErrorIs(t, err, ErrInvalidConfig)
	status, err = manager.deliver(broken)
	require.NoError(t, err)
	require.Equal(t, runtimecontract.ImageDelivering, status, "a new attempt starts after the failure was reported")
}

// The create waits until execd in the attached image's container answers;
// a container that never starts fails the create instead of reporting a
// false ready.
func TestWaitForOCIContainer(t *testing.T) {
	ready := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:"+ociExecdPort)
	if err != nil {
		t.Skipf("execd port %s is busy on this host: %v", ociExecdPort, err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		select {
		case <-ready:
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	time.AfterFunc(200*time.Millisecond, func() { close(ready) })
	started := time.Now()
	require.NoError(t, waitForOCIContainer(context.Background(), "127.0.0.1", 5*time.Second))
	require.GreaterOrEqual(t, time.Since(started), 150*time.Millisecond)

	require.NoError(t, server.Close())
	err = waitForOCIContainer(context.Background(), "127.0.0.1", 300*time.Millisecond)
	require.ErrorContains(t, err, "not ready")
}

func TestOCILaunchFromSpecAndPlacement(t *testing.T) {
	spec := fastletapi.SandboxSpec{Env: map[string]string{
		OCILaunchEntrypointEnv: `["python3","-m","http.server","8080"]`,
		OCILaunchEnvEnv:        `{"FOO":"bar"}`,
		OCILaunchWorkdirEnv:    "/tmp",
		OCILaunchUserEnv:       "nobody",
	}}
	launch, err := ociLaunchFromSpec(spec)
	require.NoError(t, err)
	require.Equal(t, []string{"python3", "-m", "http.server", "8080"}, launch.Entrypoint)
	require.Equal(t, "bar", launch.Env["FOO"])

	dir := t.TempDir()
	require.NoError(t, placeOCILaunch(dir, launch))
	content, err := os.ReadFile(filepath.Join(dir, artifacts.OCILaunchFileName))
	require.NoError(t, err)
	require.Len(t, content, artifacts.OCILaunchDriveBytes)
	decoded, err := artifacts.DecodeOCILaunch(content)
	require.NoError(t, err)
	require.Equal(t, launch, decoded)

	// A restore gets the zero placeholder of the same size.
	require.NoError(t, placeOCILaunch(dir, artifacts.OCILaunch{}))
	content, err = os.ReadFile(filepath.Join(dir, artifacts.OCILaunchFileName))
	require.NoError(t, err)
	require.Len(t, content, artifacts.OCILaunchDriveBytes)
	empty, err := artifacts.DecodeOCILaunch(content)
	require.NoError(t, err)
	require.True(t, empty.Empty())

	_, err = ociLaunchFromSpec(fastletapi.SandboxSpec{Env: map[string]string{OCILaunchEntrypointEnv: "python3 -m"}})
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func seedOCIDiskEntry(t *testing.T, root, digest string, size int, lastUsed time.Time) string {
	t.Helper()
	key := ociDiskKey(digest)
	dir := filepath.Join(root, ociDiskCacheDir, key)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ociDiskName), bytes.Repeat([]byte{1}, size), 0o444))
	meta := filepath.Join(dir, ociDiskMetaName)
	require.NoError(t, os.WriteFile(meta, []byte("{}"), 0o644))
	require.NoError(t, os.Chtimes(meta, lastUsed, lastUsed))
	return key
}

func TestGarbageCollectOCIDisks(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	old := now.Add(-3 * time.Hour)
	digest := func(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b]), 64) }

	oldest := seedOCIDiskEntry(t, root, digest(1), 64<<10, old.Add(-time.Hour))
	older := seedOCIDiskEntry(t, root, digest(2), 64<<10, old)
	recent := seedOCIDiskEntry(t, root, digest(3), 64<<10, now.Add(-10*time.Minute))
	bySandbox := seedOCIDiskEntry(t, root, digest(4), 64<<10, old.Add(-2*time.Hour))
	byManifest := seedOCIDiskEntry(t, root, digest(5), 64<<10, old.Add(-2*time.Hour))
	require.NoError(t, os.MkdirAll(filepath.Join(root, ociDiskCacheDir, ".convert-abc-123"), 0o750))

	directory, err := ensureSandboxDir(root, "sbx-1")
	require.NoError(t, err)
	require.NoError(t, saveState(directory, &SandboxState{
		Config:   fastletapi.RuntimeSandboxConfig{Spec: fastletapi.SandboxSpec{Image: "tpl-golden"}, Identity: fastletapi.SandboxIdentity{SandboxUID: "sbx-1"}},
		Phase:    PhaseRunning,
		OCIDrive: &artifacts.OCIDrive{Image: "x", Digest: digest(4), DiskKey: bySandbox},
	}))
	drive := artifacts.OCIDrive{Image: "y", Digest: digest(5), DiskKey: byManifest}
	writeOCIManifest(t, root, "osb-snap-1", &drive)

	removed, err := garbageCollectOCIDisks(root, 0, now)
	require.NoError(t, err)
	require.Equal(t, []string{oldest, older}, removed, "least recently attached first; referenced and recent disks stay")
	for _, kept := range []string{recent, bySandbox, byManifest} {
		_, err := os.Stat(filepath.Join(root, ociDiskCacheDir, kept, ociDiskName))
		require.NoError(t, err)
	}
	_, err = os.Stat(filepath.Join(root, ociDiskCacheDir, ".convert-abc-123"))
	require.NoError(t, err, "in-flight conversions are never touched")

	// Under the limit nothing is removed.
	seedOCIDiskEntry(t, root, digest(6), 64<<10, old)
	removed, err = garbageCollectOCIDisks(root, 1<<40, now)
	require.NoError(t, err)
	require.Empty(t, removed)
}
