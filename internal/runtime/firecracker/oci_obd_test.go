package firecracker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
)

const testOBDHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeUblkd is an overlaybd-ublkd stand-in on a Unix socket.
type fakeUblkd struct {
	mu      sync.Mutex
	next    int
	devices map[int]string // dev_id -> config path
	fail    bool
}

func startFakeUblkd(t *testing.T) (*fakeUblkd, string) {
	t.Helper()
	// Unix socket paths are length-limited; t.TempDir can be too long.
	dir, err := os.MkdirTemp("", "ublkd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	fake := &fakeUblkd{devices: map[int]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/add", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.fail {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "device failed to start"})
			return
		}
		if _, err := os.Stat(request["config"]); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := fake.next
		fake.next++
		fake.devices[id] = request["config"]
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "dev_id": id, "dev": "/dev/ublkb" + string(rune('0'+id))})
	})
	mux.HandleFunc("/v1/del", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]int
		_ = json.NewDecoder(r.Body).Decode(&request)
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if _, ok := fake.devices[request["dev_id"]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(fake.devices, request["dev_id"])
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return fake, socket
}

func (f *fakeUblkd) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.devices)
}

func testOBDDrive() artifacts.OCIDrive {
	return artifacts.OCIDrive{
		Image: "python:3.12-slim", Digest: "sha256:" + testOBDHex, DiskKey: testOBDHex,
		Format: artifacts.OCIDriveFormatOverlayBD, Repository: "oci-zot.oci-poc.svc:5000/library/python",
		Lowers: []artifacts.OCIDriveLayer{{Digest: "sha256:" + testOBDHex, Size: 4096}},
		Config: &artifacts.OCIImageConfig{Cmd: []string{"python3"}},
	}
}

func TestOBDEnsureMapsConvertdAnswer(t *testing.T) {
	var requested string
	convertd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/ensure", r.URL.Path)
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		requested = request["image"]
		if requested == "private.example.com/app:1" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "only Docker Hub images are mirrored"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sourceDigest": "sha256:" + testOBDHex, "repository": "oci-zot.oci-poc.svc:5000/library/python",
			"obdDigest": "sha256:" + testOBDHex, "lowers": []map[string]any{{"digest": "sha256:" + testOBDHex, "size": 4096}},
			"config": map[string]any{"Cmd": []string{"python3"}, "WorkingDir": "/app"},
		})
	}))
	defer convertd.Close()
	manager := newOBDManagerAt(t.TempDir(), "/nonexistent", convertd.URL)

	drive, err := manager.ensure(context.Background(), "python:3.12-slim")
	require.NoError(t, err)
	require.Equal(t, "python:3.12-slim", requested)
	require.Equal(t, artifacts.OCIDriveFormatOverlayBD, drive.Format)
	require.Equal(t, testOBDHex, drive.DiskKey)
	require.Equal(t, "/app", drive.Config.WorkingDir)

	_, err = manager.ensure(context.Background(), "private.example.com/app:1")
	require.ErrorContains(t, err, "only Docker Hub images are mirrored")

	_, err = newOBDManagerAt(t.TempDir(), "/nonexistent", "").ensure(context.Background(), "python:3.12-slim")
	require.ErrorContains(t, err, ociConvertdURLEnv)
}

func TestOBDAttachReleaseAndSweep(t *testing.T) {
	fake, socket := startFakeUblkd(t)
	stateRoot := t.TempDir()
	manager := newOBDManagerAt(stateRoot, socket, "")
	ctx := context.Background()

	device, err := manager.attach(ctx, "sandbox-a", testOBDDrive())
	require.NoError(t, err)
	require.Equal(t, "/dev/ublkb0", device)
	raw, err := os.ReadFile(filepath.Join(manager.deviceDir("sandbox-a"), ociOBDConfigName))
	require.NoError(t, err)
	var config obdConfig
	require.NoError(t, json.Unmarshal(raw, &config))
	require.Equal(t, "http://oci-zot.oci-poc.svc:5000/v2/library/python/blobs", config.RepoBlobURL)
	require.Len(t, config.Lowers, 1)

	// A retried attach replaces, never leaks, the earlier device.
	_, err = manager.attach(ctx, "sandbox-a", testOBDDrive())
	require.NoError(t, err)
	require.Equal(t, 1, fake.count())

	require.NoError(t, manager.release(ctx, "sandbox-a"))
	require.Equal(t, 0, fake.count())
	require.NoError(t, manager.release(ctx, "sandbox-a"), "release is idempotent")
	_, err = os.Stat(manager.deviceDir("sandbox-a"))
	require.True(t, os.IsNotExist(err))

	// Sweep: a live Sandbox keeps its device, an orphan is released once old.
	_, err = manager.attach(ctx, "live", testOBDDrive())
	require.NoError(t, err)
	_, err = manager.attach(ctx, "orphan", testOBDDrive())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(stateRoot, sandboxStateDir, "live"), 0o750))
	require.Empty(t, manager.sweep(ctx, time.Now()), "young orphans are kept")
	require.Equal(t, []string{"orphan"}, manager.sweep(ctx, time.Now().Add(2*ociOBDSweepAge)))
	require.Equal(t, 1, fake.count())

	// A device the daemon no longer knows counts as released.
	fake.mu.Lock()
	fake.devices = map[int]string{}
	fake.mu.Unlock()
	require.NoError(t, manager.release(ctx, "live"))

	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()
	_, err = manager.attach(ctx, "sandbox-b", testOBDDrive())
	require.ErrorContains(t, err, "device failed to start")
	_, err = os.Stat(manager.deviceDir("sandbox-b"))
	require.True(t, os.IsNotExist(err), "a failed attach leaves no record")

	_, err = manager.attach(ctx, "../escape", testOBDDrive())
	require.Error(t, err)
	ext4 := testOBDDrive()
	ext4.Format = ""
	_, err = manager.attach(ctx, "sandbox-c", ext4)
	require.Error(t, err)
}

func TestOCIDiskManagerPrefersOverlayBDAndFallsBack(t *testing.T) {
	healthy := true
	convertd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "converting"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sourceDigest": "sha256:" + testOBDHex, "repository": "oci-zot.oci-poc.svc:5000/library/python",
			"obdDigest": "sha256:" + testOBDHex, "lowers": []map[string]any{{"digest": "sha256:" + testOBDHex, "size": 4096}},
		})
	}))
	defer convertd.Close()
	manager := testOCIDiskManager(t.TempDir())
	manager.obd = newOBDManagerAt(manager.stateRoot, "/nonexistent", convertd.URL)
	manager.preferOBD = true

	drive, disk, err := manager.ensure(context.Background(), "python:3.12-slim")
	require.NoError(t, err)
	require.Empty(t, disk)
	require.Equal(t, artifacts.OCIDriveFormatOverlayBD, drive.Format)
	cached, _, ok := manager.cached("python:3.12-slim")
	require.True(t, ok, "an OverlayBD drive is cached without a node disk")
	require.Equal(t, drive.DiskKey, cached.DiskKey)
	status, err := manager.deliver("python:3.12-slim")
	require.NoError(t, err)
	require.EqualValues(t, "Delivered", status)

	// A recorded OverlayBD drive needs no node disk to restore.
	path, err := manager.attach(context.Background(), drive)
	require.NoError(t, err)
	require.Empty(t, path)

	// convertd failing falls back to the ext4 path (which fails here on the
	// unreachable registry, proving it was taken).
	healthy = false
	_, _, err = manager.ensure(context.Background(), "127.0.0.1:1/alpine:3.20")
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "converting"), "the ext4 error is returned, not convertd's: %v", err)
}
