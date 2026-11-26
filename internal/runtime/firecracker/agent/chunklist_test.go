package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

// stageChunkListSet stages a set the way a Fastlet does when the agent
// reports chunkListDigest: the native artifacts carry only their size, and
// SHA256SUMS lists only the hashed state files.
func stageChunkListSet(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := stageSet(t, files, nil)
	path := filepath.Join(dir, publishManifestName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	document := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &document))
	for _, entry := range document["files"].(map[string]any) {
		delete(entry.(map[string]any), "sha256")
	}
	raw, err = json.MarshalIndent(document, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o644))
	var hashed []string
	for name := range files {
		if name == publishPolicyName || name == publishVaultName {
			hashed = append(hashed, name)
		}
	}
	if len(hashed) == 0 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, artifacts.SHA256SUMSName), []byte("\n"), 0o644))
	} else {
		require.NoError(t, artifacts.WriteSHA256SUMS(dir, hashed, nil))
	}
	return dir
}

func chunkListOnlyTransfer() TransferConfig {
	transfer := chunkedTransfer(TransferCompressionNone)
	transfer.ChunkListOnly = true
	return transfer
}

func filesWithPolicy() map[string][]byte {
	files := stagedFiles()
	files[publishPolicyName] = []byte(`{"egress":"policy"}`)
	return files
}

func TestTransferConfigChunkListOnly(t *testing.T) {
	require.ErrorContains(t, TransferConfig{ChunkListOnly: true}.Validate(), "requires format chunked")
	require.NoError(t, chunkListOnlyTransfer().Validate())
	require.True(t, chunkListOnlyTransfer().ChunkListDigest())
	require.False(t, chunkedTransfer(TransferCompressionNone).ChunkListDigest(), "chunked alone keeps whole-file hashes")
	require.False(t, TransferConfig{}.ChunkListDigest())
}

func TestChunkListPublishPullRoundTrip(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	files := filesWithPolicy()
	dir := stageChunkListSet(t, files)
	stagedSums, err := os.ReadFile(filepath.Join(dir, artifacts.SHA256SUMSName))
	require.NoError(t, err)

	result, err := newTestClient(t, server, chunkListOnlyTransfer()).PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", dir)
	require.NoError(t, err)
	base := publishedBase(result)
	document, err := artifacts.DecodeVMManifest(store.object(base + "/manifest.json"))
	require.NoError(t, err)
	for _, name := range []string{"rootfs.ext4", manifestMemoryName, manifestVMStateName} {
		entry := document.Files[name]
		require.Empty(t, entry.SHA256, "%s must stay without a whole-file sha256", name)
		require.NotNil(t, entry.ChunkList, "%s needs its chunk-list digest", name)
		want, err := artifacts.FileChunkListSHA256(filepath.Join(dir, name), testChunkSize, 2)
		require.NoError(t, err)
		require.Equal(t, want, entry.ChunkList.SHA256, "%s chunk-list digest", name)
	}
	require.Equal(t, stagedSums, store.object(base+"/"+artifacts.SHA256SUMSName), "SHA256SUMS lists the hashed state files as staged")

	for _, reader := range []TransferConfig{{}, chunkedTransfer(TransferCompressionNone)} {
		stateRoot := t.TempDir()
		reference := artifacts.CheckpointReference(result.ArtifactDigest)
		require.NoError(t, newTestClient(t, server, reader).PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
		for name, payload := range files {
			got, err := os.ReadFile(filepath.Join(imageDir(stateRoot, reference), compatCacheName(name)))
			require.NoError(t, err)
			require.True(t, bytes.Equal(payload, got), "%s content differs", name)
		}
		// The pull recorded its files in the memo under their chunk-list
		// identity: the readiness check reads nothing.
		hashes := fileMatchesHashCount.Load()
		ready, err := CheckpointReady(stateRoot, reference, result.ArtifactDigest)
		require.NoError(t, err)
		require.True(t, ready)
		require.Equal(t, hashes, fileMatchesHashCount.Load())

		// Without the memo (another process) the chunk-list re-verify
		// still detects a changed byte.
		memory := filepath.Join(imageDir(stateRoot, reference), manifestMemoryName)
		defaultVerifiedDigests.invalidate(memory)
		ready, err = CheckpointReady(stateRoot, reference, result.ArtifactDigest)
		require.NoError(t, err)
		require.True(t, ready, "the chunk-list re-verify accepts the intact file")
		payload, err := os.ReadFile(memory)
		require.NoError(t, err)
		payload[0] ^= 0xff
		require.NoError(t, os.WriteFile(memory, payload, 0o640))
		ready, err = CheckpointReady(stateRoot, reference, result.ArtifactDigest)
		require.NoError(t, err)
		require.False(t, ready, "a changed byte must fail the chunk-list re-verify")
	}
}

// With the default chunkListOnly: false a chunked set keeps the whole-file
// sha256 next to the chunk-list digest, so older chunk readers still read it.
func TestChunkedPublishKeepsWholeFileSHA256(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkedTransfer(TransferCompressionNone)).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageSet(t, stagedFiles(), nil))
	require.NoError(t, err)
	document, err := artifacts.DecodeVMManifest(store.object(publishedBase(result) + "/manifest.json"))
	require.NoError(t, err)
	for _, name := range []string{"rootfs.ext4", manifestMemoryName, manifestVMStateName} {
		require.True(t, validSHA256(document.Files[name].SHA256), "%s keeps its sha256", name)
		require.NotNil(t, document.Files[name].ChunkList, "%s also gets its chunk-list digest", name)
	}
}

// A size-only staged entry (a Fastlet on a stale capability, or an agent
// restarted into another mode) is completed unless the agent runs chunked
// with chunkListOnly: the agent hashes it and rewrites SHA256SUMS from the
// completed manifest.
func TestPublishCompletesSizeOnlyEntries(t *testing.T) {
	for name, transfer := range map[string]TransferConfig{
		"legacy":  {},
		"chunked": chunkedTransfer(TransferCompressionNone),
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeObjectStore()
			server := httptest.NewServer(http.HandlerFunc(store.handle))
			defer server.Close()
			files := filesWithPolicy()
			result, err := newTestClient(t, server, transfer).PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageChunkListSet(t, files))
			require.NoError(t, err)
			base := publishedBase(result)
			document, err := artifacts.DecodeVMManifest(store.object(base + "/manifest.json"))
			require.NoError(t, err)
			sums, err := artifacts.ParseSHA256SUMS(store.object(base + "/" + artifacts.SHA256SUMSName))
			require.NoError(t, err)
			for file, payload := range files {
				require.Equal(t, artifacts.SHA256Of(payload), sums[file], "SHA256SUMS lists %s", file)
				if file != publishPolicyName {
					require.Equal(t, artifacts.SHA256Of(payload), document.Files[file].SHA256, "%s completed", file)
				}
			}
			stateRoot := t.TempDir()
			reference := artifacts.CheckpointReference(result.ArtifactDigest)
			require.NoError(t, newTestClient(t, server, TransferConfig{}).PullCheckpoint(context.Background(), stateRoot, reference, result.ManifestRef, result.ArtifactDigest))
		})
	}
}

// SHA256SUMS is never published empty, which readers reject: a chunkListOnly
// agent given a set without any hashed state file completes it.
func TestChunkListOnlyNeverPublishesEmptySHA256SUMS(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkListOnlyTransfer()).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageChunkListSet(t, stagedFiles()))
	require.NoError(t, err)
	sums, err := artifacts.ParseSHA256SUMS(store.object(publishedBase(result) + "/" + artifacts.SHA256SUMSName))
	require.NoError(t, err)
	require.Len(t, sums, 3)
}

// The pre-manifest check fails a manifest that lacks a digest its mode
// requires; nothing but chunks has been uploaded at that point.
func TestCheckPublishManifestRequiresModeDigests(t *testing.T) {
	dir := stageSet(t, stagedFiles(), nil)
	staged, err := os.ReadFile(filepath.Join(dir, publishManifestName))
	require.NoError(t, err)
	index := artifacts.ChunkIndex{Version: 1, ChunkSize: testChunkSize, Files: map[string]artifacts.ChunkIndexFile{}}
	for _, name := range []string{"rootfs.ext4", manifestMemoryName, manifestVMStateName} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		index.Files[name] = artifacts.ChunkIndexFile{SizeBytes: info.Size(), Chunks: []artifacts.Chunk{}}
	}
	indexBytes, err := artifacts.MarshalChunkIndex(index)
	require.NoError(t, err)
	ref := artifacts.ChunkIndexRef{Version: 1, Ref: artifacts.ChunkIndexName, SHA256: sha256Hex(indexBytes), SizeBytes: int64(len(indexBytes))}
	rewrite := func(edit func(document map[string]any)) []byte {
		document := map[string]any{}
		require.NoError(t, json.Unmarshal(staged, &document))
		edit(document)
		payload, err := json.MarshalIndent(document, "", "  ")
		require.NoError(t, err)
		return payload
	}
	files := func(document map[string]any) map[string]any { return document["files"].(map[string]any) }
	list := func(name string) artifacts.ChunkListDigest {
		return artifacts.ChunkListDigest{Version: 1, ChunkSize: testChunkSize, SHA256: artifacts.ChunkListSHA256(testChunkSize, index.Files[name].SizeBytes, nil)}
	}
	bound := func(document map[string]any) {
		document[artifacts.ManifestChunksField] = ref
		for name, entry := range files(document) {
			entry.(map[string]any)["chunkList"] = list(name)
		}
	}

	require.NoError(t, checkPublishManifest(staged, nil, dir, false), "legacy with sha256")
	require.NoError(t, checkPublishManifest(rewrite(bound), indexBytes, dir, false), "chunked with both digests")
	sizeOnly := rewrite(func(document map[string]any) {
		bound(document)
		delete(files(document)[manifestMemoryName].(map[string]any), "sha256")
	})
	require.NoError(t, checkPublishManifest(sizeOnly, indexBytes, dir, true), "chunkListOnly omits sha256")
	require.ErrorContains(t, checkPublishManifest(sizeOnly, indexBytes, dir, false), "has no sha256")

	noList := rewrite(func(document map[string]any) {
		bound(document)
		delete(files(document)[manifestMemoryName].(map[string]any), "chunkList")
	})
	require.ErrorContains(t, checkPublishManifest(noList, indexBytes, dir, false), "chunk-list digest")
	wrongList := rewrite(func(document map[string]any) {
		bound(document)
		files(document)[manifestMemoryName].(map[string]any)["chunkList"] = artifacts.ChunkListDigest{Version: 1, ChunkSize: testChunkSize, SHA256: strings.Repeat("ab", 32)}
	})
	require.ErrorContains(t, checkPublishManifest(wrongList, indexBytes, dir, false), "chunk-list digest")
	require.ErrorContains(t, checkPublishManifest(rewrite(func(document map[string]any) { document[artifacts.ManifestChunksField] = ref }), nil, dir, false), "binds a chunk index")

	require.NoError(t, os.WriteFile(filepath.Join(dir, artifacts.SHA256SUMSName), []byte("\n"), 0o644))
	require.ErrorContains(t, checkPublishManifest(staged, nil, dir, false), "lists no entries")
}

// A manifest whose chunk-list digest does not describe the bound index is
// rejected before any chunk is trusted.
func TestChunkedPullRejectsChunkListMismatch(t *testing.T) {
	store := newFakeObjectStore()
	server := httptest.NewServer(http.HandlerFunc(store.handle))
	defer server.Close()
	result, err := newTestClient(t, server, chunkListOnlyTransfer()).
		PublishImage(context.Background(), agentprotocol.PublishKindCheckpoint, "", stageChunkListSet(t, filesWithPolicy()))
	require.NoError(t, err)
	base := publishedBase(result)

	document := map[string]any{}
	require.NoError(t, json.Unmarshal(store.object(base+"/manifest.json"), &document))
	memory := document["files"].(map[string]any)[manifestMemoryName].(map[string]any)
	memory["chunkList"].(map[string]any)["sha256"] = strings.Repeat("ab", 32)
	forged, err := json.MarshalIndent(document, "", "  ")
	require.NoError(t, err)
	forged = append(forged, '\n')
	store.setObject(base+"/manifest.json", forged)

	digest := sha256Hex(forged)
	err = newTestClient(t, server, TransferConfig{}).PullCheckpoint(context.Background(), t.TempDir(),
		artifacts.CheckpointReference(digest), result.ManifestRef, digest)
	require.ErrorContains(t, err, "chunk-list digest")
}

func TestNativeFilesNeedADigest(t *testing.T) {
	list := &artifacts.ChunkListDigest{Version: 1, ChunkSize: testChunkSize, SHA256: strings.Repeat("cd", 32)}
	entries := map[string]artifacts.ManifestFile{
		"rootfs.ext4":       {SHA256: strings.Repeat("ab", 32), SizeBytes: 1},
		manifestVMStateName: {SizeBytes: 1, ChunkList: list},
		manifestMemoryName:  {SizeBytes: 1},
	}
	_, err := manifest{Files: entries}.nativeFiles()
	require.ErrorContains(t, err, "memory.snap has an invalid sha256", "an entry with neither digest fails closed")

	entries[manifestMemoryName] = artifacts.ManifestFile{SizeBytes: 1, ChunkList: &artifacts.ChunkListDigest{Version: 9, ChunkSize: testChunkSize, SHA256: list.SHA256}}
	_, err = manifest{Files: entries}.nativeFiles()
	require.ErrorContains(t, err, "unsupported chunk-list digest version")

	entries[manifestMemoryName] = artifacts.ManifestFile{SizeBytes: 1, ChunkList: list}
	files, err := manifest{Files: entries}.nativeFiles()
	require.NoError(t, err)
	for _, file := range files {
		switch file.publish {
		case "rootfs.ext4":
			require.Equal(t, strings.Repeat("ab", 32), file.digestKey(), "a whole-file sha256 stays the memo identity")
		default:
			require.Equal(t, chunkListDigestPrefix+list.SHA256, file.digestKey())
		}
	}

	// A whole-file download has nothing to check a chunk-list-only entry
	// against.
	err = stageFile(context.Background(), &Client{}, t.TempDir(), "unused", nativeFile{publish: manifestMemoryName, cache: manifestMemoryName, sizeBytes: 1, chunkList: list})
	require.ErrorContains(t, err, "no whole-file sha256")
}
