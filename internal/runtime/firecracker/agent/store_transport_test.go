package agent

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

func TestChunkedClientUsesPooledTransport(t *testing.T) {
	legacy, err := NewClient("s3://bucket/publish", writeCredential())
	require.NoError(t, err)
	require.Nil(t, legacy.s3.http.Transport, "legacy keeps net/http's default transport")

	chunked, err := NewClient("s3://bucket/publish", writeCredential(), WithTransfer(TransferConfig{Format: TransferFormatChunked}))
	require.NoError(t, err)
	transport, ok := chunked.s3.http.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, storeConnsPerHost, transport.MaxIdleConnsPerHost)
	require.Equal(t, storeIdleConnTimeout, transport.IdleConnTimeout)
	require.Same(t, transport, chunked.s3.putHTTP.Transport, "publishes share the pool")

	custom := &http.Client{}
	explicit, err := NewClient("s3://bucket/publish", writeCredential(), WithTransfer(TransferConfig{Format: TransferFormatChunked}), WithHTTPClient(custom))
	require.NoError(t, err)
	require.Same(t, custom, explicit.s3.http, "an explicit HTTP client is kept")
}

// TestChunkedTransferRetriesStalledConnection models a collapsed TCP
// connection behind a lossy policer: one chunk request hangs. The
// per-attempt timeout must drop it and the retry must succeed, for both the
// publish (PUT) and the pull (GET).
func TestChunkedTransferRetriesStalledConnection(t *testing.T) {
	previous := chunkAttemptTimeout
	chunkAttemptTimeout = 200 * time.Millisecond
	defer func() { chunkAttemptTimeout = previous }()

	store := newFakeObjectStore()
	var stalledPut, stalledGet atomic.Bool
	release := make(chan struct{})
	stall := func(r *http.Request) bool {
		if !strings.Contains(r.URL.Path, artifacts.ChunkStorePrefix) {
			return false
		}
		switch r.Method {
		case http.MethodPut:
			return stalledPut.CompareAndSwap(false, true)
		case http.MethodGet:
			return stalledGet.CompareAndSwap(false, true)
		}
		return false
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stall(r) {
			// Hang until the test ends: a handler that never reads its body
			// is not cancelled when the client drops the connection.
			<-release
			return
		}
		store.handle(w, r)
	}))
	defer server.Close()
	defer close(release) // runs first: frees parked handlers before Close waits on them

	files := stagedFiles()
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, nil))
	require.NoError(t, err)
	require.True(t, stalledPut.Load(), "a chunk PUT was stalled")

	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, newTestClient(t, server, TransferConfig{}).
		PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
	require.True(t, stalledGet.Load(), "a chunk GET was stalled")
	got, err := os.ReadFile(filepath.Join(imageDir(stateRoot, reference), nativeRootfsCacheName))
	require.NoError(t, err)
	require.True(t, bytes.Equal(files["rootfs.ext4"], got))
}
