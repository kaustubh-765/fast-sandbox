package firecracker

// End-to-end stage-1 chain: driver client -> UDS server -> Service ->
// real pull client -> fake S3 store, landing a committed cache that the
// driver's resolveRootfsImage path consumes unchanged.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/registryconfig"
	agentpull "fast-sandbox/internal/runtime/firecracker/agent"
	agentserver "fast-sandbox/internal/runtime/firecracker/agent/server"
	agentstate "fast-sandbox/internal/runtime/firecracker/agent/state"
)

const e2eImage = "registry.example.com/sandbox:v1.0.21"

// fakeS3Store serves path-style GETs at /<bucket>/<prefix>/<key>.
type fakeS3Store struct {
	mu       sync.Mutex
	objects  map[string][]byte
	requests []string
	server   *httptest.Server
}

func (s *fakeS3Store) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	key := strings.TrimPrefix(request.URL.Path, "/"+e2eBucket+"/"+e2ePrefix+"/")
	s.mu.Lock()
	s.requests = append(s.requests, key)
	payload, ok := s.objects[key]
	s.mu.Unlock()
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = writer.Write(payload)
}

const (
	e2eBucket = "sandbox-images"
	e2ePrefix = "publish"
)

func hexSHA256Bytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// publishE2EFixture publishes index + manifest + artifacts into the store,
// mirroring the builder's publish order (files -> manifest -> index).
func publishE2EFixture(t *testing.T, store *fakeS3Store, image string) {
	rootfs := []byte("e2e-rootfs-content")
	vmstate := []byte("e2e-vmstate-content")
	memory := []byte("e2e-memory-content")
	document := testManifestDocument(t)
	document["files"] = map[string]any{
		"rootfs.ext4":  map[string]any{"sha256": hexSHA256Bytes(rootfs), "sizeBytes": len(rootfs)},
		"vmstate.snap": map[string]any{"sha256": hexSHA256Bytes(vmstate), "sizeBytes": len(vmstate)},
		"memory.snap":  map[string]any{"sha256": hexSHA256Bytes(memory), "sizeBytes": len(memory)},
	}
	manifestPayload, _ := json.Marshal(document)
	manifestRef := "s3://" + e2eBucket + "/" + e2ePrefix + "/" + hexSHA256Bytes(manifestPayload)[:16] + "/manifest.json"
	index, _ := json.Marshal(map[string]any{
		"image": image, "manifestRef": manifestRef,
		"artifactDigest": hexSHA256Bytes(manifestPayload), "updatedAt": "2026-08-27T00:00:00Z",
	})
	key := func(parts ...string) string { return path.Join(parts...) }
	store.objects[key("index", hexSHA256Bytes([]byte(image))+".json")] = index
	store.objects[key(strings.TrimPrefix(strings.TrimPrefix(manifestRef, "s3://"+e2eBucket+"/"), e2ePrefix+"/"))] = manifestPayload
	store.objects[key(hexSHA256Bytes(manifestPayload)[:16], "rootfs.ext4")] = rootfs
	store.objects[key(hexSHA256Bytes(manifestPayload)[:16], "vmstate.snap")] = vmstate
	store.objects[key(hexSHA256Bytes(manifestPayload)[:16], "memory.snap")] = memory
}

// startE2EAgent wires the full agent stack over a Unix socket and returns
// the socket path.
func startE2EAgent(t *testing.T, stateRoot string, store *fakeS3Store) string {
	t.Helper()
	endpoint := store.serverURL(t)
	credential := registryconfig.Credential{Host: endpoint, Username: "readonly-ak", Password: "readonly-sk"}
	pull, err := agentpull.NewClient("s3://"+e2eBucket+"/"+e2ePrefix, credential,
		agentpull.WithHTTPClient(store.httpClient(t)))
	require.NoError(t, err)
	state, err := agentstate.New(stateRoot)
	require.NoError(t, err)
	t.Cleanup(func() { _ = state.Close() })
	service := agentserver.NewService(pull, state, stateRoot)
	socketPath := testAgentSocketPath(t)
	server := agentserver.New(service, socketPath)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Serve(ctx) }()
	t.Cleanup(cancel)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent socket %s never appeared", socketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return socketPath
}

func (s *fakeS3Store) serverURL(t *testing.T) string {
	t.Helper()
	if s.server != nil {
		return s.server.URL
	}
	s.server = httptest.NewServer(s)
	t.Cleanup(s.server.Close)
	return s.server.URL
}

func (s *fakeS3Store) httpClient(t *testing.T) *http.Client {
	t.Helper()
	_ = s.serverURL(t)
	return s.server.Client()
}

func TestPullImageFullChainE2E(t *testing.T) {
	store := &fakeS3Store{objects: make(map[string][]byte)}
	publishE2EFixture(t, store, e2eImage)
	stateRoot := t.TempDir()
	socketPath := startE2EAgent(t, stateRoot, store)

	driver := newDriverFixture(t)
	driver.driver.newAgentClient = func(string) (AgentClient, error) {
		return NewAgentClient(socketPath, "tenant-a", "pod-1")
	}
	driver.driver.agentSocket = socketPath

	require.NoError(t, driver.driver.PullImage(context.Background(), e2eImage))

	// The driver's existing resolveRootfsImage path consumes the pulled
	// cache without any change.
	rootfs, err := resolveRootfsImage(stateRoot, e2eImage)
	require.NoError(t, err)
	payload, err := os.ReadFile(rootfs)
	require.NoError(t, err)
	require.Equal(t, "e2e-rootfs-content", string(payload))

	// The idempotency contract: pulling again performs no network request.
	store.mu.Lock()
	requestsBefore := len(store.requests)
	store.mu.Unlock()
	require.NoError(t, driver.driver.PullImage(context.Background(), e2eImage))
	store.mu.Lock()
	require.Equal(t, requestsBefore, len(store.requests))
	store.mu.Unlock()
}

func TestPullImageE2ENotPublished(t *testing.T) {
	store := &fakeS3Store{objects: make(map[string][]byte)}
	stateRoot := t.TempDir()
	socketPath := startE2EAgent(t, stateRoot, store)

	driver := newDriverFixture(t)
	driver.driver.newAgentClient = func(string) (AgentClient, error) {
		return NewAgentClient(socketPath, "tenant-a", "pod-1")
	}
	driver.driver.agentSocket = socketPath

	err := driver.driver.PullImage(context.Background(), "registry.example.com/not-published:v1")
	require.ErrorIs(t, err, ErrImageNotReady)
}

// Ensure the fake store shape compiles against the agent's expected S3
// client by exercising a direct pull (the real signing path).
func TestDirectPullReachesStore(t *testing.T) {
	store := &fakeS3Store{objects: make(map[string][]byte)}
	publishE2EFixture(t, store, e2eImage)
	stateRoot := t.TempDir()
	credential := registryconfig.Credential{Host: store.serverURL(t), Username: "ak", Password: "sk"}
	client, err := agentpull.NewClient("s3://"+e2eBucket+"/"+e2ePrefix, credential,
		agentpull.WithHTTPClient(store.httpClient(t)))
	require.NoError(t, err)
	require.NoError(t, client.PullImage(context.Background(), stateRoot, e2eImage))
	ready, err := agentpull.ImageReady(stateRoot, e2eImage)
	require.NoError(t, err)
	require.True(t, ready)
}

var _ = io.Discard
var _ = net.Listen
