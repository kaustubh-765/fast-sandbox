package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestArtifactStreamOutlivesMetadataTimeoutAndHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(100 * time.Millisecond):
			_, _ = w.Write([]byte("artifact"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	for _, gateway := range []bool{false, true} {
		name := "direct"
		if gateway {
			name = "gateway"
		}
		t.Run(name, func(t *testing.T) {
			metadataHTTP := &http.Client{Timeout: 10 * time.Millisecond}
			client := &Client{s3: &s3Client{endpoint: server.URL, bucket: "bucket", http: metadataHTTP}}
			if gateway {
				client.peer = &peerGateway{base: server.URL, routePrefix: "/dart/", http: metadataHTTP}
			}
			body, err := client.getArtifact(context.Background(), "base.ext4")
			require.NoError(t, err)
			payload, err := io.ReadAll(body)
			require.NoError(t, body.Close())
			require.NoError(t, err)
			require.Equal(t, "artifact", string(payload))
			require.Equal(t, 10*time.Millisecond, metadataHTTP.Timeout)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body, err = client.getArtifact(ctx, "base.ext4")
			require.NoError(t, err)
			cancel()
			_, err = io.ReadAll(body)
			require.ErrorIs(t, err, context.Canceled)
			require.NoError(t, body.Close())
		})
	}
}
