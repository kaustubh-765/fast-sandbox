package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/registryconfig"
	"fast-sandbox/internal/runtime/firecracker/agent"
)

// TestAgentPullFeedsDriverCache wires the runtime-agent pull layer to the
// driver's existing cache consumer: after PullImage, the restore path
// (resolveRootfsImage) resolves the pulled artifact without any driver
// change, and the per-build digest namespace and file mapping
// (rootfs.ext4 -> rootfs.img) match the published layout.
func TestAgentPullFeedsDriverCache(t *testing.T) {
	const (
		image       = "registry.example.com/sandbox:v1.0.21"
		bucket      = "sandbox-images"
		storePrefix = "publish"
	)
	artifacts := map[string][]byte{
		"rootfs.ext4":  []byte("rootfs-content"),
		"vmstate.snap": []byte("vmstate-content"),
		"memory.snap":  []byte("memory-content"),
	}
	files := map[string]any{}
	for name, content := range artifacts {
		files[name] = map[string]any{
			"sha256":    sha256HexTest(content),
			"sizeBytes": len(content),
		}
	}
	document := testManifestDocument(t)
	document["files"] = files
	manifestBytes, err := json.Marshal(document)
	require.NoError(t, err)
	digest16 := sha256HexTest(manifestBytes)[:16]

	objects := map[string][]byte{
		digest16 + "/manifest.json": manifestBytes,
	}
	for name, content := range artifacts {
		objects[digest16+"/"+name] = content
	}
	indexBytes, err := json.Marshal(map[string]string{
		"image":          image,
		"manifestRef":    "s3://" + bucket + "/" + storePrefix + "/" + digest16 + "/manifest.json",
		"artifactDigest": sha256HexTest(manifestBytes),
		"updatedAt":      "2026-08-27T00:00:00Z",
	})
	require.NoError(t, err)
	objects["index/"+imageKey(image)+".json"] = indexBytes

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, ok := objects[strings.TrimPrefix(r.URL.Path, "/"+bucket+"/"+storePrefix+"/")]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()

	client, err := agent.NewClient("s3://"+bucket+"/"+storePrefix,
		registryconfig.Credential{Host: server.URL, Username: "ak", Password: "sk"})
	require.NoError(t, err)

	stateRoot := t.TempDir()
	require.NoError(t, client.PullImage(context.Background(), stateRoot, image))

	// The driver's existing restore consumer resolves the pulled rootfs
	// image under the shared cache layout.
	resolved, err := resolveRootfsImage(stateRoot, image)
	require.NoError(t, err)
	expected, err := imageCachePath(stateRoot, image)
	require.NoError(t, err)
	require.Equal(t, expected, resolved)
	content, err := os.ReadFile(resolved)
	require.NoError(t, err)
	require.Equal(t, artifacts["rootfs.ext4"], content)

	// A second pull is a no-op for the store, and the driver's idempotent
	// PullImage also sees the image as ready.
	require.NoError(t, client.PullImage(context.Background(), stateRoot, image))
	driver := &Driver{config: firecrackerConfigForTest(t, stateRoot)}
	require.NoError(t, driver.PullImage(context.Background(), image))
}

func sha256HexTest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
