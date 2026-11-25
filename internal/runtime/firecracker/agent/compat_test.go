package agent

// Store compatibility with chunked sets already in stores (FSEP-0004). The
// fixture in testdata/compat-2e505cb was published by the reference
// implementation (#213 as deployed, 2e505cb) against an in-memory store:
// compatContent staged with a sparse rootfs, an allocated zero chunk in
// memory.snap and a policy bundle: with raw chunks, with zstd chunks, and
// staged by size alone so the manifest identifies the native files only by
// chunk-list digest. The tests pin that this reader restores those sets byte
// for byte and that this publisher writes byte-identical objects (chunks,
// chunks.json, SHA256SUMS, bundle, manifest) for the same staged input.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

const compatFixtureDir = "testdata/compat-2e505cb"

func compatPattern(seed byte, n int) []byte {
	block := make([]byte, n)
	for i := range block {
		block[i] = seed + byte(i%251)
	}
	return block
}

// compatContent is the content the fixture was generated from; it must stay
// identical to the generator's.
func compatContent() map[string][]byte {
	const chunk = 64 << 10
	zero := make([]byte, chunk)
	return map[string][]byte{
		"rootfs.ext4":  bytes.Join([][]byte{zero, compatPattern(1, chunk), zero, compatPattern(1, chunk), compatPattern(7, 1000)}, nil),
		"memory.snap":  bytes.Join([][]byte{compatPattern(3, chunk), zero, compatPattern(5, 500)}, nil),
		"vmstate.snap": compatPattern(9, 777),
		"policy.json":  []byte(`{"egress":{"default":"deny"}}`),
	}
}

type compatSet struct {
	ManifestRef    string `json:"manifestRef"`
	ArtifactDigest string `json:"artifactDigest"`
}

func compatSets(t *testing.T) map[string]compatSet {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(compatFixtureDir, "sets.json"))
	require.NoError(t, err)
	sets := map[string]compatSet{}
	require.NoError(t, json.Unmarshal(payload, &sets))
	return sets
}

// compatStoreServer serves the fixture store read-only.
func compatStoreServer(t *testing.T) *httptest.Server {
	t.Helper()
	root := filepath.Join(compatFixtureDir, "store")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/bucket/"))))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func compatCacheName(name string) string {
	if name == "rootfs.ext4" {
		return nativeRootfsCacheName
	}
	return name
}

func TestCompatReaderRestoresDeployedChunkedSets(t *testing.T) {
	server := compatStoreServer(t)
	content := compatContent()
	for name, set := range compatSets(t) {
		for _, reader := range []TransferConfig{{}, chunkedTransfer(TransferCompressionZstd)} {
			t.Run(name+"/"+reader.normalized().Format, func(t *testing.T) {
				stateRoot := t.TempDir()
				reference := artifacts.CheckpointReference(set.ArtifactDigest)
				require.NoError(t, newTestClient(t, server, reader).PullCheckpoint(context.Background(), stateRoot, reference, set.ManifestRef, set.ArtifactDigest))
				dir := imageDir(stateRoot, reference)
				for file, want := range content {
					got, err := os.ReadFile(filepath.Join(dir, compatCacheName(file)))
					require.NoError(t, err)
					require.True(t, bytes.Equal(want, got), "%s restored with different bytes", file)
				}
				ready, err := CheckpointReady(stateRoot, reference, set.ArtifactDigest)
				require.NoError(t, err)
				require.True(t, ready)
			})
		}
	}
}

// writeCompatStaging stages the fixture's input exactly as the generator
// did: content (rootfs sparse), staged manifest and SHA256SUMS.
func writeCompatStaging(t *testing.T, set string) string {
	t.Helper()
	dir := t.TempDir()
	for name, payload := range compatContent() {
		path := filepath.Join(dir, name)
		if name != "rootfs.ext4" {
			require.NoError(t, os.WriteFile(path, payload, 0o640))
			continue
		}
		handle, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, handle.Truncate(int64(len(payload))))
		for offset := 0; offset < len(payload); offset += testChunkSize {
			block := payload[offset:min(offset+testChunkSize, len(payload))]
			if !artifacts.IsZero(block) {
				_, err := handle.WriteAt(block, int64(offset))
				require.NoError(t, err)
			}
		}
		require.NoError(t, handle.Close())
	}
	for _, name := range []string{publishManifestName, artifacts.SHA256SUMSName} {
		payload, err := os.ReadFile(filepath.Join(compatFixtureDir, "staged", set, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), payload, 0o644))
	}
	return dir
}

func TestCompatPublisherMatchesDeployedSets(t *testing.T) {
	for name, set := range compatSets(t) {
		t.Run(name, func(t *testing.T) {
			transfer := chunkedTransfer(TransferCompressionNone)
			switch name {
			case "zstd":
				transfer.Compression = TransferCompressionZstd
			case "chunklist":
				transfer.ChunkListOnly = true
			}
			store := newFakeObjectStore()
			server := httptest.NewServer(http.HandlerFunc(store.handle))
			defer server.Close()
			result, err := newTestClient(t, server, transfer).
				PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", writeCompatStaging(t, name))
			require.NoError(t, err)

			fixtureBase := strings.TrimSuffix(strings.TrimPrefix(set.ManifestRef, "s3://bucket/"), "/manifest.json")
			fixture := func(key string) []byte {
				payload, err := os.ReadFile(filepath.Join(compatFixtureDir, "store", filepath.FromSlash(key)))
				require.NoError(t, err)
				return payload
			}
			base := publishedBase(result)
			for _, file := range []string{artifacts.ChunkIndexName, artifacts.SHA256SUMSName, publishPolicyName} {
				require.Equal(t, fixture(fixtureBase+"/"+file), store.object(base+"/"+file), "%s differs from the deployed publisher's", file)
			}
			require.Equal(t, string(fixture(fixtureBase+"/manifest.json")), string(store.object(base+"/manifest.json")), "the manifest differs from the deployed publisher's")
			require.Equal(t, set.ArtifactDigest, result.ArtifactDigest)
			for _, key := range store.putKeys() {
				if isChunkKey(key) {
					require.Equal(t, fixture(key), store.object(key), "chunk object %s differs", key)
				}
			}
		})
	}
}

// Every chunk object in the fixture is named by the SHA-256 of its decoded
// bytes, and the fixture holds nothing else under chunks/.
func TestCompatFixtureChunkKeys(t *testing.T) {
	root := filepath.Join(compatFixtureDir, "store", "publish")
	count := 0
	require.NoError(t, filepath.WalkDir(filepath.Join(root, filepath.FromSlash(artifacts.ChunkStorePrefix)), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		stored, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum, encoding := strings.TrimSuffix(entry.Name(), ".zst"), artifacts.ChunkEncodingRaw
		decoded := stored
		if strings.HasSuffix(entry.Name(), ".zst") {
			encoding = artifacts.ChunkEncodingZstd
			if decoded, err = chunkDecoder().DecodeAll(stored, nil); err != nil {
				return err
			}
		}
		if filepath.ToSlash(relative) != artifacts.ChunkObjectKey(sum, encoding) || sha256Hex(decoded) != sum {
			return errors.New("chunk object " + relative + " is not named by its content")
		}
		count++
		return nil
	}))
	require.Positive(t, count)
}
