package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

const testChunkSize = 64 << 10

// fakeObjectStore is an S3-ish store serving PUT/GET/HEAD by path. Like
// RGW, it rejects a PUT whose signed x-amz-content-sha256 does not match.
type fakeObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    []string
	heads   int
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{objects: map[string][]byte{}}
}

func (s *fakeObjectStore) handle(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if claimed := r.Header.Get("X-Amz-Content-Sha256"); claimed != unsignedPayload && claimed != sha256Hex(body) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.objects[key] = body
		s.puts = append(s.puts, key)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		if r.Method == http.MethodHead {
			s.heads++
		}
		body, ok := s.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeObjectStore) putKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.puts...)
}

func (s *fakeObjectStore) headCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heads
}

func (s *fakeObjectStore) object(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[key]
}

func (s *fakeObjectStore) setObject(key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = body
}

// patternData returns n non-zero bytes derived from seed.
func patternData(seed byte, n int) []byte {
	block := make([]byte, n)
	for i := range block {
		block[i] = seed + byte(i%251)
	}
	return block
}

// stagedFiles builds artifacts with zero chunks, data chunks, a repeated
// chunk and a partial tail, so every chunking branch is exercised.
func stagedFiles() map[string][]byte {
	zero := make([]byte, testChunkSize)
	rootfs := bytes.Join([][]byte{zero, patternData(1, testChunkSize), zero, patternData(1, testChunkSize), patternData(7, 1000)}, nil)
	memory := bytes.Join([][]byte{patternData(3, testChunkSize), zero, zero}, nil)
	return map[string][]byte{
		"rootfs.ext4":       rootfs,
		manifestMemoryName:  memory,
		manifestVMStateName: patternData(9, 777),
	}
}

// stageSet writes files plus a VM manifest describing them; the optional
// state bundles (policy.json, vault.json) land in platform.stateFiles, and
// extra adds unknown top-level fields.
func stageSet(t *testing.T, files map[string][]byte, extra map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	manifest := artifacts.VMManifest{
		SchemaVersion: artifacts.VMManifestVersion,
		Runtime:       "firecracker",
		Machine:       artifacts.VMMachine{VCPUCount: 2, MemoryMiB: 1024, RootfsSizeMiB: 1, RootfsDriveID: "rootfs", RootfsDrivePath: "rootfs.img"},
		Kernel:        artifacts.VMKernel{Version: "6.1.177"},
		Compatibility: artifacts.SnapshotCompatibility{CPUArch: "x86_64", FirecrackerVersion: "1.16.1", CPUTemplate: artifacts.CPUTemplateNone, Vendor: artifacts.VendorGenuineIntel, CPUFamily: 6, CPUModel: 85, CPUStepping: 7},
		Files:         map[string]artifacts.ManifestFile{},
	}
	var names []string
	for name, payload := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, payload, 0o640))
		entry, err := artifacts.FileEntry(path, nil)
		require.NoError(t, err)
		names = append(names, name)
		if name == publishVaultName || name == publishPolicyName {
			if manifest.Platform == nil {
				manifest.Platform = &artifacts.VMPlatform{StateFiles: map[string]artifacts.ManifestFile{}}
			}
			manifest.Platform.StateFiles[name] = entry
			continue
		}
		manifest.Files[name] = entry
	}
	sort.Strings(names)
	require.NoError(t, artifacts.WriteSHA256SUMS(dir, names, nil))
	payload, err := artifacts.MarshalVMManifest(manifest)
	require.NoError(t, err)
	if len(extra) > 0 {
		document := map[string]any{}
		require.NoError(t, json.Unmarshal(payload, &document))
		for key, value := range extra {
			document[key] = value
		}
		payload, err = json.MarshalIndent(document, "", "  ")
		require.NoError(t, err)
		payload = append(payload, '\n')
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, publishManifestName), payload, 0o644))
	return dir
}

// editStagedManifest rewrites one native entry of a staged manifest.
func editStagedManifest(t *testing.T, dir, name string, edit func(entry map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, publishManifestName)
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	document := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &document))
	edit(document["files"].(map[string]any)[name].(map[string]any))
	payload, err = json.MarshalIndent(document, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(payload, '\n'), 0o644))
}

func newTestClient(t *testing.T, server *httptest.Server, transfer TransferConfig) *Client {
	t.Helper()
	credential := writeCredential()
	credential.Endpoint = server.URL
	client, err := NewClient("s3://bucket/publish", credential, WithTransfer(transfer))
	require.NoError(t, err)
	client.s3.retryDelay = 0
	return client
}

func chunkedTransfer(compression string) TransferConfig {
	return TransferConfig{Format: TransferFormatChunked, Compression: compression, Concurrency: 4, ChunkSize: testChunkSize}
}

func publishedBase(result PublishResult) string {
	return "publish/" + strings.TrimSuffix(strings.TrimPrefix(result.ManifestRef, "s3://bucket/publish/"), "/manifest.json")
}

func isChunkKey(key string) bool {
	return strings.HasPrefix(key, "publish/"+artifacts.ChunkStorePrefix+"/")
}

func TestTransferConfigValidate(t *testing.T) {
	require.NoError(t, TransferConfig{}.Validate())
	require.False(t, TransferConfig{}.Chunked(), "the empty config is legacy")
	require.True(t, TransferConfig{Format: TransferFormatChunked}.Chunked())
	require.NoError(t, TransferConfig{Format: TransferFormatChunked, Compression: TransferCompressionZstd}.Validate())

	require.ErrorContains(t, TransferConfig{Format: "fast"}.Validate(), "unknown transfer format")
	require.ErrorContains(t, TransferConfig{Compression: "gzip"}.Validate(), "unknown transfer compression")
	require.ErrorContains(t, TransferConfig{Compression: TransferCompressionZstd}.Validate(), "requires format chunked")
	require.ErrorContains(t, TransferConfig{Format: TransferFormatChunked, ChunkSize: 1000}.Validate(), "multiple of 64KiB")
	_, err := NewClient("s3://bucket/publish", writeCredential(), WithTransfer(TransferConfig{Compression: TransferCompressionZstd}))
	require.ErrorContains(t, err, "requires format chunked")
}

func TestChunkedPublishPullRoundTrip(t *testing.T) {
	for _, compression := range []string{TransferCompressionNone, TransferCompressionZstd} {
		t.Run(compression, func(t *testing.T) {
			store := newFakeObjectStore()
			server := httptest.NewServer(http.HandlerFunc(store.handle))
			defer server.Close()
			files := stagedFiles()
			dir := stageSet(t, files, nil)
			client := newTestClient(t, server, chunkedTransfer(compression))

			result, err := client.PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
			require.NoError(t, err)

			// Only chunks and metadata are uploaded; zero chunks and the
			// duplicated rootfs chunk are not.
			chunkPuts := 0
			for _, key := range store.putKeys() {
				require.NotContains(t, []string{"rootfs.ext4", manifestMemoryName, manifestVMStateName}, filepath.Base(key),
					"whole-file artifact %s uploaded", key)
				if isChunkKey(key) {
					chunkPuts++
					if compression == TransferCompressionZstd {
						require.True(t, strings.HasSuffix(key, ".zst"), key)
					}
				}
			}
			require.Equal(t, 4, chunkPuts, "rootfs data (deduped) + rootfs tail + memory + vmstate")

			// The published manifest binds the chunk index and is the
			// digest the caller got back; the staged manifest matches it,
			// so a same-node cache commit of the staging directory holds
			// the published bytes.
			base := publishedBase(result)
			published := store.object(base + "/manifest.json")
			require.Equal(t, result.ArtifactDigest, sha256Hex(published))
			staged, err := os.ReadFile(filepath.Join(dir, publishManifestName))
			require.NoError(t, err)
			require.Equal(t, published, staged)
			binding, err := chunkBinding(published)
			require.NoError(t, err)
			require.NotNil(t, binding)
			index := store.object(base + "/" + artifacts.ChunkIndexName)
			require.Equal(t, sha256Hex(index), binding.SHA256)

			// Either transfer setting reads the set: the manifest, not
			// the agent's setting, selects the reader.
			for _, reader := range []TransferConfig{{}, chunkedTransfer(TransferCompressionNone)} {
				stateRoot := t.TempDir()
				reference := artifacts.CheckpointReference(result.ArtifactDigest)
				require.NoError(t, newTestClient(t, server, reader).PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
				cacheDir := imageDir(stateRoot, reference)
				for name, payload := range files {
					cacheName := name
					if name == "rootfs.ext4" {
						cacheName = nativeRootfsCacheName
					}
					got, err := os.ReadFile(filepath.Join(cacheDir, cacheName))
					require.NoError(t, err)
					require.True(t, bytes.Equal(payload, got), "%s content differs after round trip", name)
				}
				// The committed files are in the verified-digest memo: the
				// readiness check does not read them again.
				hashes := fileMatchesHashCount.Load()
				ready, err := CheckpointReady(stateRoot, reference, result.ArtifactDigest)
				require.NoError(t, err)
				require.True(t, ready)
				require.Equal(t, hashes, fileMatchesHashCount.Load(), "a chunked pull records its files in the memo")
			}
		})
	}
}

func TestChunkedPublishSkipsHolesOfSparseFiles(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	files := stagedFiles()
	// The rootfs as a genuinely sparse file with a long trailing hole.
	rootfs := append(append([]byte(nil), files["rootfs.ext4"]...), make([]byte, 40*testChunkSize)...)
	files["rootfs.ext4"] = rootfs
	dir := stageSet(t, files, nil)
	path := filepath.Join(dir, "rootfs.ext4")
	require.NoError(t, os.Remove(path))
	handle, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, handle.Truncate(int64(len(rootfs))))
	for offset := 0; offset < len(rootfs); offset += testChunkSize {
		block := rootfs[offset:min(offset+testChunkSize, len(rootfs))]
		if !artifacts.IsZero(block) {
			_, err := handle.WriteAt(block, int64(offset))
			require.NoError(t, err)
		}
	}
	require.NoError(t, handle.Close())

	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
	require.NoError(t, err)

	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, newTestClient(t, server, TransferConfig{}).
		PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
	got, err := os.ReadFile(filepath.Join(imageDir(stateRoot, reference), nativeRootfsCacheName))
	require.NoError(t, err)
	require.True(t, bytes.Equal(rootfs, got))
}

func TestChunkedPublishReusesStoredChunks(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	files := stagedFiles()
	client := newTestClient(t, server, chunkedTransfer(TransferCompressionNone))

	_, err := client.PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, nil))
	require.NoError(t, err)
	before, heads := len(store.putKeys()), store.headCount()

	// The same client remembers the keys: no HEAD, no chunk upload.
	_, err = client.PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, map[string]any{"rebuild": "second"}))
	require.NoError(t, err)
	require.Equal(t, heads, store.headCount(), "known chunks skip the HEAD")
	for _, key := range store.putKeys()[before:] {
		require.False(t, isChunkKey(key), "chunk %s re-uploaded", key)
	}

	// A fresh client (no in-memory known set) finds the chunks via HEAD
	// and uploads only the per-build metadata.
	before = len(store.putKeys())
	_, err = newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, map[string]any{"rebuild": "third"}))
	require.NoError(t, err)
	require.Greater(t, store.headCount(), heads)
	for _, key := range store.putKeys()[before:] {
		require.False(t, isChunkKey(key), "chunk %s re-uploaded", key)
	}
}

func TestChunkedPublishUploadOrder(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	files := stagedFiles()
	files[publishPolicyName] = []byte(`{"egress":"policy"}`)

	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindTemplate, "app-v2", stageSet(t, files, nil))
	require.NoError(t, err)
	base := publishedBase(result)
	puts := store.putKeys()
	var rest []string
	for i, key := range puts {
		if !isChunkKey(key) {
			rest = puts[i:]
			break
		}
	}
	for _, key := range rest {
		require.False(t, isChunkKey(key), "chunk %s uploaded after the chunk index", key)
	}
	require.Equal(t, []string{
		base + "/" + artifacts.ChunkIndexName,
		base + "/" + publishPolicyName,
		base + "/" + artifacts.SHA256SUMSName,
		base + "/" + publishManifestName,
		"publish/index/" + artifacts.ImageIndexKey("app-v2") + ".json",
	}, rest, "chunks, chunks.json, bundles and SHA256SUMS, manifest, then the index")
}

func TestLegacyPublishKeepsWholeFileLayout(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	dir := stageSet(t, stagedFiles(), nil)
	staged, err := os.ReadFile(filepath.Join(dir, publishManifestName))
	require.NoError(t, err)

	result, err := newTestClient(t, server, TransferConfig{}).PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
	require.NoError(t, err)

	// The staged manifest is published byte for byte, under its own digest,
	// after the whole-file artifacts and SHA256SUMS.
	require.Equal(t, artifacts.SHA256Of(staged), result.ArtifactDigest)
	base := "publish/" + artifacts.Digest16(staged)
	require.Equal(t, []string{
		base + "/rootfs.ext4", base + "/" + manifestVMStateName, base + "/" + manifestMemoryName,
		base + "/" + artifacts.SHA256SUMSName, base + "/" + publishManifestName,
	}, store.putKeys())
	require.Equal(t, staged, store.object(base+"/"+publishManifestName))
	after, err := os.ReadFile(filepath.Join(dir, publishManifestName))
	require.NoError(t, err)
	require.Equal(t, staged, after, "a legacy publish leaves the staged manifest untouched")
	require.Zero(t, store.headCount())
}

func TestLegacyPublishDropsInheritedChunkBinding(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	inherited := map[string]any{artifacts.ManifestChunksField: map[string]any{"version": 1, "ref": "chunks.json", "sha256": strings.Repeat("a", 64), "sizeBytes": 1}}
	dir := stageSet(t, stagedFiles(), inherited)

	result, err := newTestClient(t, server, TransferConfig{}).PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
	require.NoError(t, err)
	base := publishedBase(result)
	var document map[string]any
	require.NoError(t, json.Unmarshal(store.object(base+"/manifest.json"), &document))
	require.NotContains(t, document, artifacts.ManifestChunksField)
	require.NotEmpty(t, store.object(base+"/rootfs.ext4"), "legacy publish uploads whole files")
}

func TestChunkedPublishReplacesInheritedChunkBinding(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	inherited := map[string]any{artifacts.ManifestChunksField: map[string]any{"version": 1, "ref": "chunks.json", "sha256": strings.Repeat("a", 64), "sizeBytes": 1}}
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), inherited))
	require.NoError(t, err)
	base := publishedBase(result)
	binding, err := chunkBinding(store.object(base + "/manifest.json"))
	require.NoError(t, err)
	require.Equal(t, sha256Hex(store.object(base+"/"+artifacts.ChunkIndexName)), binding.SHA256)
}

func TestChunkedPullRejectsCorruptChunk(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
	require.NoError(t, err)
	for _, key := range store.putKeys() {
		if isChunkKey(key) {
			body := append([]byte(nil), store.object(key)...)
			body[0] ^= 0xff
			store.setObject(key, body)
			break
		}
	}
	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	err = newTestClient(t, server, TransferConfig{}).PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest)
	require.ErrorContains(t, err, "digest mismatch")
	ready, readyErr := ImageReady(stateRoot, reference)
	require.NoError(t, readyErr)
	require.False(t, ready, "a failed pull must not leave a committed cache entry")
}

func TestChunkedPullRejectsCorruptIndex(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
	require.NoError(t, err)
	key := publishedBase(result) + "/" + artifacts.ChunkIndexName
	index := append([]byte(nil), store.object(key)...)
	store.setObject(key, bytes.Replace(index, []byte(`"off": 0`), []byte(`"off": 1`), 1))

	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	err = newTestClient(t, server, TransferConfig{}).PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest)
	require.ErrorContains(t, err, "does not match the manifest binding")
	entries, readErr := os.ReadDir(imageDir(stateRoot, reference))
	require.NoError(t, readErr)
	require.Empty(t, entries, "an index that fails verification writes nothing")
}

func TestParseChunkIndexRejectsMalformedIndex(t *testing.T) {
	valid := artifacts.ChunkIndex{Version: 1, ChunkSize: testChunkSize, Files: map[string]artifacts.ChunkIndexFile{
		"memory.snap": {SizeBytes: 2 * testChunkSize, Chunks: []artifacts.Chunk{{Offset: testChunkSize, Length: testChunkSize, SHA256: strings.Repeat("a", 64), StoredSize: 10}}},
	}}
	payload, err := artifacts.MarshalChunkIndex(valid)
	require.NoError(t, err)
	_, err = artifacts.ParseChunkIndex(payload)
	require.NoError(t, err)
	for name, chunk := range map[string]artifacts.Chunk{
		"misaligned":    {Offset: 1, Length: 10, SHA256: strings.Repeat("a", 64), StoredSize: 10},
		"out of bounds": {Offset: 2 * testChunkSize, Length: 1, SHA256: strings.Repeat("a", 64), StoredSize: 1},
		"bad digest":    {Offset: 0, Length: 1, SHA256: "xyz", StoredSize: 1},
		"bad encoding":  {Offset: 0, Length: 1, SHA256: strings.Repeat("a", 64), Encoding: "gzip", StoredSize: 1},
		"bad stored":    {Offset: 0, Length: 1, SHA256: strings.Repeat("a", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			index := artifacts.ChunkIndex{Version: 1, ChunkSize: testChunkSize, Files: map[string]artifacts.ChunkIndexFile{
				"memory.snap": {SizeBytes: 2 * testChunkSize, Chunks: []artifacts.Chunk{chunk}},
			}}
			payload, err := json.Marshal(index)
			require.NoError(t, err)
			_, err = artifacts.ParseChunkIndex(payload)
			require.Error(t, err)
		})
	}
}

func TestChunkedPublishCarriesStateBundles(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	files := stagedFiles()
	files[publishPolicyName] = []byte(`{"egress":"policy"}`)

	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, nil))
	require.NoError(t, err)
	require.Equal(t, files[publishPolicyName], store.object(publishedBase(result)+"/"+publishPolicyName),
		"the state bundle is uploaded whole next to the chunk index")

	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, newTestClient(t, server, TransferConfig{}).
		PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
	got, err := os.ReadFile(filepath.Join(imageDir(stateRoot, reference), publishPolicyName))
	require.NoError(t, err)
	require.True(t, bytes.Equal(files[publishPolicyName], got))
}

// A native RootfsOnly set chunks exactly the files its manifest lists: the
// rootfs, nothing else.
func TestChunkedRootfsOnlyPublishPullRoundTrip(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	dir := stageRootfsArtifactSet(t)
	rootfs, err := os.ReadFile(filepath.Join(dir, "rootfs.ext4"))
	require.NoError(t, err)

	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindTemplate, "rootfs-only", dir)
	require.NoError(t, err)
	index, err := artifacts.ParseChunkIndex(store.object(publishedBase(result) + "/" + artifacts.ChunkIndexName))
	require.NoError(t, err)
	require.Equal(t, []string{"rootfs.ext4"}, sortedKeys(index.Files))

	stateRoot := t.TempDir()
	require.NoError(t, newTestClient(t, server, TransferConfig{}).PullImage(context.Background(), stateRoot, "rootfs-only"))
	got, err := os.ReadFile(ImageRootfsPath(stateRoot, "rootfs-only"))
	require.NoError(t, err)
	require.Equal(t, rootfs, got)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Acceptance runs before any upload: a malformed digest or a size that does
// not match the staged file fails the publish with nothing in the store.
func TestPublishAcceptanceFailsBeforeAnyUpload(t *testing.T) {
	for name, edit := range map[string]func(entry map[string]any){
		"malformed digest": func(entry map[string]any) { entry["sha256"] = "not-a-digest" },
		"size mismatch":    func(entry map[string]any) { entry["sizeBytes"] = 12345 },
	} {
		for _, transfer := range []TransferConfig{{}, chunkedTransfer(TransferCompressionNone)} {
			t.Run(name+"/"+transfer.normalized().Format, func(t *testing.T) {
				store := newFakeObjectStore()
				server := httptest.NewServer(http.HandlerFunc(store.handle))
				defer server.Close()
				dir := stageSet(t, stagedFiles(), nil)
				editStagedManifest(t, dir, manifestMemoryName, edit)
				_, err := newTestClient(t, server, transfer).PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
				require.Error(t, err)
				require.Empty(t, store.putKeys())
			})
		}
	}
}

// A size-only native entry passes acceptance, but this agent requires the
// whole-file sha256 in what it publishes: the pre-manifest check fails the
// publish before any manifest, chunk index or whole-file object exists.
func TestPublishSizeOnlyEntryFailsPreManifestCheck(t *testing.T) {
	for _, transfer := range []TransferConfig{{}, chunkedTransfer(TransferCompressionNone)} {
		t.Run(transfer.normalized().Format, func(t *testing.T) {
			store := newFakeObjectStore()
			server := httptest.NewServer(http.HandlerFunc(store.handle))
			defer server.Close()
			dir := stageSet(t, stagedFiles(), nil)
			editStagedManifest(t, dir, manifestMemoryName, func(entry map[string]any) { delete(entry, "sha256") })
			_, err := newTestClient(t, server, transfer).PublishImage(context.Background(), agentprotocol.PublishKindTemplate, "app", dir)
			require.ErrorContains(t, err, "invalid sha256")
			for _, key := range store.putKeys() {
				require.True(t, isChunkKey(key), "only unreferenced chunks may exist, got %s", key)
			}
		})
	}
}

func TestChunkedPublishCancelledWritesNoManifest(t *testing.T) {
	store := newFakeObjectStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store.handle(w, r)
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, artifacts.ChunkStorePrefix) {
			cancel()
		}
	}))
	defer server.Close()
	transfer := chunkedTransfer(TransferCompressionNone)
	transfer.Concurrency = 1
	_, err := newTestClient(t, server, transfer).PublishImage(ctx, agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
	require.ErrorIs(t, err, context.Canceled)
	for _, key := range store.putKeys() {
		require.True(t, isChunkKey(key), "a cancelled publish wrote %s", key)
	}
}

// Chunk PUTs are payload-signed with the SHA-256 of the stored body (raw or
// zstd), which the store checks.
func TestChunkPutSignsPayloadDigest(t *testing.T) {
	for _, compression := range []string{TransferCompressionNone, TransferCompressionZstd} {
		t.Run(compression, func(t *testing.T) {
			store := newFakeObjectStore()
			var mu sync.Mutex
			signed := map[string]string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/chunks/") {
					mu.Lock()
					signed[strings.TrimPrefix(r.URL.Path, "/bucket/")] = r.Header.Get("X-Amz-Content-Sha256")
					mu.Unlock()
				}
				store.handle(w, r)
			}))
			defer server.Close()
			_, err := newTestClient(t, server, chunkedTransfer(compression)).
				PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
			require.NoError(t, err)
			require.NotEmpty(t, signed)
			for key, claimed := range signed {
				require.Equal(t, sha256Hex(store.object(key)), claimed, "chunk %s signed with a wrong payload hash", key)
			}
		})
	}
}

func TestChunkHeadForbiddenFallsBackToUpload(t *testing.T) {
	store := newFakeObjectStore()
	// AWS answers HEAD on a missing key with 403 when the credential has
	// no s3:ListBucket.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		store.handle(w, r)
	}))
	defer server.Close()
	files := stagedFiles()

	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, files, nil))
	require.NoError(t, err)
	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, newTestClient(t, server, TransferConfig{}).
		PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
	got, err := os.ReadFile(filepath.Join(imageDir(stateRoot, reference), nativeRootfsCacheName))
	require.NoError(t, err)
	require.True(t, bytes.Equal(files["rootfs.ext4"], got))
}

// A transient chunk GET failure, including a body cut short, is retried.
func TestChunkedPullRetriesTruncatedChunk(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
	require.NoError(t, err)

	var truncated atomic.Bool
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, artifacts.ChunkStorePrefix) && truncated.CompareAndSwap(false, true) {
			body := store.object(strings.TrimPrefix(r.URL.Path, "/bucket/"))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body[:len(body)/2])
			return
		}
		store.handle(w, r)
	}))
	defer flaky.Close()
	stateRoot := t.TempDir()
	reference := artifacts.CheckpointReference(result.ArtifactDigest)
	require.NoError(t, newTestClient(t, flaky, TransferConfig{}).
		PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
	require.True(t, truncated.Load())
}
