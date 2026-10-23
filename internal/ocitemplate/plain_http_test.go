package ocitemplate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	registrytest "github.com/google/go-containerregistry/pkg/registry"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
)

func TestPushPlainHTTPReadsRemoteParentLayers(t *testing.T) {
	ctx := context.Background()
	sourceHandler, destinationHandler := registrytest.New(), registrytest.New()
	var sourceReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("from") != "" {
			w.WriteHeader(http.StatusForbidden) // force the cross-repository stream fallback
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/parent/base/") {
			if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
				sourceReads.Add(1)
			}
			sourceHandler.ServeHTTP(w, r)
			return
		}
		destinationHandler.ServeHTTP(w, r)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	source, _, err := Repository(host+"/parent/base:rootfs", nil, WithPlainHTTP(true))
	require.NoError(t, err)
	layer := []byte("snapshot data")
	desc := content.NewDescriptorFromBytes(oci.MediaTypeImageLayer, layer)
	require.NoError(t, source.Blobs().Push(ctx, desc, bytes.NewReader(layer)))
	dir := localPairFixture(t)
	// Incremental exports contain only the parent's descriptor and source repo.
	require.NoError(t, os.Remove(filepath.Join(dir, "blobs/sha256", desc.Digest.Encoded())))
	raw, err := json.Marshal(map[string]string{desc.Digest.String(): host + "/parent/base"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, RemoteSourcesName), raw, 0600))
	ref, _, err := Push(ctx, dir, host+"/snapshots/test:http-test", []byte(`{}`), nil, WithPlainHTTP(true))
	require.NoError(t, err)
	require.Contains(t, ref, "@sha256:")
	require.Positive(t, sourceReads.Load(), "the parent blob must also be fetched over plain HTTP")
	repository, _, err := Repository(ref, nil, WithPlainHTTP(true))
	require.NoError(t, err)
	for _, tag := range []string{"http-test_rootfs", "http-test_snapfiles"} {
		_, err := repository.Resolve(ctx, tag)
		require.NoError(t, err)
	}
}
