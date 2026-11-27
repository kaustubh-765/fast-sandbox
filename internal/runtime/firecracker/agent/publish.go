package agent

// publish.go implements the node-side artifact-set publication for live
// Sandbox snapshots. The layout and upload order are byte-identical to the
// golden-image builder (cmd/sandboxtemplate-builder publish stage): the
// per-build namespace is the first 16 hex chars of the manifest document's
// SHA-256, artifacts and SHA256SUMS upload first, the manifest last within
// the namespace, and the image index object last overall. Unlike a
// SandboxTemplate build, a snapshot publishes ONLY the index key given by
// the caller (the template name) — never a default sha256(image) key,
// which would alias and pollute the source golden image (last-writer-wins).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"fast-sandbox/internal/artifacts"
	agentprotocol "fast-sandbox/internal/runtime/firecracker/agent/protocol"
)

// publishVaultName / publishPolicyName are the optional state bundle files
// of a snapshot set (checkpoint vault; recorded policy on checkpoint AND
// template sets): uploaded when staged next to the manifest. The names are
// owned by the shared protocol package — the driver stages and the pull
// layer materializes the same bytes under the same names.
const (
	publishVaultName  = agentprotocol.VaultBundleName
	publishPolicyName = agentprotocol.PolicyBundleName
)

// publishManifestName is the commit-point document of the artifact set.
const publishManifestName = "manifest.json"

// PublishResult reports one successful publication.
type PublishResult struct {
	ManifestRef    string
	ArtifactDigest string
}

// PublishImage uploads the artifact set staged in dir to the configured
// store and returns the manifest reference and digest. It is synchronous:
// multi-GiB memory files legitimately take minutes. kind selects the
// publication mode: a template set (default) requires key and writes the
// image index last; a checkpoint set carries no key and writes no index —
// the instance-private set is addressed by its returned ref + digest.
func (c *Client) PublishImage(ctx context.Context, kind, key, dir string) (PublishResult, error) {
	if kind == "" {
		kind = agentprotocol.PublishKindTemplate
	}
	switch kind {
	case agentprotocol.PublishKindTemplate:
		if strings.TrimSpace(key) == "" {
			return PublishResult{}, fmt.Errorf("publish key is required for a template artifact set")
		}
	case agentprotocol.PublishKindCheckpoint:
		if strings.TrimSpace(key) != "" {
			return PublishResult{}, fmt.Errorf("checkpoint artifact sets publish no image index; key must be empty")
		}
	default:
		return PublishResult{}, fmt.Errorf("unknown publish kind %q", kind)
	}
	staged, err := os.ReadFile(filepath.Join(dir, publishManifestName))
	if err != nil {
		return PublishResult{}, fmt.Errorf("read staged manifest: %w", err)
	}
	document, err := parseManifest(staged)
	if err != nil {
		return PublishResult{}, err
	}
	files, err := acceptStagedSet(document, kind, dir)
	if err != nil {
		return PublishResult{}, err
	}
	started := time.Now()
	if files, err = c.completeStagedSet(dir, files); err != nil {
		klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "stage", "completion", "elapsed", time.Since(started).String())
		return PublishResult{}, err
	}
	manifestBytes, chunkIndex, err := c.prepareManifest(ctx, kind, key, dir, files, started)
	if err != nil {
		return PublishResult{}, err
	}
	if err := checkPublishManifest(manifestBytes, chunkIndex, dir, c.transfer.ChunkListOnly); err != nil {
		klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "stage", "manifest check", "elapsed", time.Since(started).String())
		return PublishResult{}, err
	}
	artifactDigest := artifacts.SHA256Of(manifestBytes)
	base := artifacts.Digest16(manifestBytes)
	klog.InfoS("runtime-agent publish started", "kind", kind, "key", key, "digest", artifactDigest, "format", c.transfer.Format, "stagingDir", dir)

	// Artifacts and SHA256SUMS first: the namespace stays incomplete (and
	// unaddressable) until the manifest lands. A chunked set uploaded its
	// native artifacts as chunks already and adds its chunk index instead.
	// The optional state bundle files (vault, recorded policy) join the
	// uploads when staged — any stat failure other than absence fails the
	// publish, since the staged manifest and SHA256SUMS already reference
	// the files and a stranded member would break the cross-node resume.
	entries := make([]string, 0, len(files)+3)
	if chunkIndex != nil {
		if err := c.s3.putBytes(ctx, base+"/"+artifacts.ChunkIndexName, chunkIndex); err != nil {
			klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "file", artifacts.ChunkIndexName, "elapsed", time.Since(started).String())
			return PublishResult{}, fmt.Errorf("publish chunk index: %w", err)
		}
	} else {
		for _, file := range files {
			entries = append(entries, file.publish)
		}
	}
	for _, bundleName := range []string{publishVaultName, publishPolicyName} {
		if _, err := os.Stat(filepath.Join(dir, bundleName)); err == nil {
			entries = append(entries, bundleName)
		} else if !errors.Is(err, os.ErrNotExist) {
			klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "file", bundleName)
			return PublishResult{}, fmt.Errorf("stat staged %s: %w", bundleName, err)
		}
	}
	entries = append(entries, artifacts.SHA256SUMSName)
	for _, name := range entries {
		if err := c.putFile(ctx, dir, name, base+"/"+name); err != nil {
			klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "file", name, "elapsed", time.Since(started).String())
			return PublishResult{}, fmt.Errorf("publish %s: %w", name, err)
		}
	}
	manifestURI := c.s3.storeRootURI() + "/" + base + "/" + publishManifestName
	if err := c.putFile(ctx, dir, publishManifestName, base+"/"+publishManifestName); err != nil {
		klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "file", publishManifestName, "elapsed", time.Since(started).String())
		return PublishResult{}, fmt.Errorf("publish manifest: %w", err)
	}
	if kind == agentprotocol.PublishKindCheckpoint {
		// No index: the set is complete and addressed by ref + digest only.
		klog.InfoS("runtime-agent publish completed", "kind", kind, "key", key, "manifestRef", manifestURI, "elapsed", time.Since(started).String())
		return PublishResult{ManifestRef: manifestURI, ArtifactDigest: artifactDigest}, nil
	}

	// The index is written last overall: a consumer that resolves the key is
	// guaranteed a complete artifact set. The payload's image field equals
	// the key so pull-side byte matching works unchanged.
	indexPayload, err := artifacts.ImageIndexPayload(key, manifestURI, artifactDigest, nowFunc())
	if err != nil {
		return PublishResult{}, err
	}
	indexKey := "index/" + artifacts.ImageIndexKey(key) + ".json"
	payload := string(indexPayload)
	if err := c.s3.put(ctx, indexKey, int64(len(payload)), func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(payload)), nil
	}); err != nil {
		klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "file", indexKey, "elapsed", time.Since(started).String())
		return PublishResult{}, fmt.Errorf("publish index: %w", err)
	}
	klog.InfoS("runtime-agent publish completed", "kind", kind, "key", key, "manifestRef", manifestURI, "elapsed", time.Since(started).String())
	return PublishResult{ManifestRef: manifestURI, ArtifactDigest: artifactDigest}, nil
}

// prepareManifest returns the manifest bytes the set publishes under and,
// for a chunked set, its chunk index. A legacy set publishes the staged
// manifest as is; only a chunk binding inherited from the manifest the
// Sandbox booted from is dropped, since the set carries whole files. A
// chunked set first uploads the chunks of the native files its manifest
// lists, then binds their index into the manifest: the manifest digest, and
// with it the namespace, is only known after.
func (c *Client) prepareManifest(ctx context.Context, kind, key, dir string, files []nativeFile, started time.Time) ([]byte, []byte, error) {
	if !c.transfer.Chunked() {
		manifestBytes, err := bindChunkIndex(dir, nil, nil)
		return manifestBytes, nil, err
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.publish)
	}
	index, stats, err := c.publishChunks(ctx, dir, names)
	if err == nil {
		// A cancelled publish must not bind (and rewrite the staged
		// manifest with) a chunk index that may be missing chunks.
		err = ctx.Err()
	}
	if err != nil {
		klog.ErrorS(err, "runtime-agent publish failed", "kind", kind, "key", key, "stage", "chunks", "elapsed", time.Since(started).String())
		return nil, nil, fmt.Errorf("publish chunks: %w", err)
	}
	logPublishStats(kind, key, stats)
	indexBytes, err := artifacts.MarshalChunkIndex(index)
	if err != nil {
		return nil, nil, err
	}
	// Every chunked artifact gets its chunk-list digest, from the index just
	// built: the identity under which an entry staged without a whole-file
	// sha256 is published.
	lists := map[string]artifacts.ChunkListDigest{}
	for name, file := range index.Files {
		lists[name] = artifacts.ChunkListDigest{
			Version: artifacts.ChunkListDigestVersion, ChunkSize: index.ChunkSize,
			SHA256: artifacts.ChunkListSHA256(index.ChunkSize, file.SizeBytes, file.Chunks),
		}
	}
	manifestBytes, err := bindChunkIndex(dir, &artifacts.ChunkIndexRef{
		Version: artifacts.ChunkIndexVersion, Ref: artifacts.ChunkIndexName,
		SHA256: sha256Hex(indexBytes), SizeBytes: int64(len(indexBytes)),
	}, lists)
	if err != nil {
		return nil, nil, err
	}
	return manifestBytes, indexBytes, nil
}

// acceptStagedSet checks a staged set before anything is uploaded: every
// native file the set needs and every declared state bundle exists as a
// regular file of the declared size, and every digest that is present is
// well-formed. A native entry with only its size is accepted; whether the
// published set may omit the digest is decided by checkPublishManifest. It
// returns the native files to publish.
func acceptStagedSet(document manifest, kind, dir string) ([]nativeFile, error) {
	if artifacts.VMManifest(document).IsRootfsOnly() {
		if err := validateRootfsStaging(kind, dir); err != nil {
			return nil, err
		}
	}
	files, err := document.stagedNativeFiles()
	if err != nil {
		return nil, err
	}
	members := append([]nativeFile(nil), files...)
	for _, bundleFile := range []func() (nativeFile, bool, error){document.vaultFile, document.policyFile} {
		file, ok, err := bundleFile()
		if err != nil {
			return nil, err
		}
		if ok {
			members = append(members, file)
		}
	}
	for _, member := range members {
		info, err := os.Stat(filepath.Join(dir, member.publish))
		if err != nil {
			return nil, fmt.Errorf("stat staged %s: %w", member.publish, err)
		}
		if !info.Mode().IsRegular() || info.Size() != member.sizeBytes {
			return nil, fmt.Errorf("staged %s has invalid type or size", member.publish)
		}
	}
	return files, nil
}

// checkPublishManifest is the last check before any manifest, chunk index or
// whole-file object is uploaded: readers must accept the manifest about to
// be published. Every native entry needs a size and the digests its mode
// requires (legacy: sha256; chunked: a chunkList bound to the chunk index
// just built, plus sha256 unless chunkListOnly), state files need a sha256,
// the chunk binding must match the index (and be absent from a whole-file
// set), and SHA256SUMS must list at least one entry. A failure leaves at
// most unreferenced chunks behind.
func checkPublishManifest(payload, chunkIndex []byte, dir string, chunkListOnly bool) error {
	document, err := parseManifest(payload)
	if err != nil {
		return err
	}
	files, err := document.downloadFiles()
	if err != nil {
		return fmt.Errorf("published manifest is incomplete: %w", err)
	}
	binding, err := chunkBinding(payload)
	if err != nil {
		return err
	}
	var index artifacts.ChunkIndex
	switch {
	case chunkIndex == nil && binding != nil:
		return errors.New("whole-file set binds a chunk index")
	case chunkIndex != nil && (binding == nil || binding.Version != artifacts.ChunkIndexVersion ||
		binding.Ref != artifacts.ChunkIndexName || binding.SHA256 != sha256Hex(chunkIndex) ||
		binding.SizeBytes != int64(len(chunkIndex))):
		return errors.New("chunk index binding does not match the chunk index")
	case chunkIndex != nil:
		if index, err = artifacts.ParseChunkIndex(chunkIndex); err != nil {
			return err
		}
	}
	for _, file := range files {
		if !isNativeArtifact(file.publish) {
			continue
		}
		if (chunkIndex == nil || !chunkListOnly) && file.sha256 == "" {
			return fmt.Errorf("published manifest artifact %s has no sha256", file.publish)
		}
		if chunkIndex == nil {
			continue
		}
		entry, ok := index.Files[file.publish]
		if !ok || file.chunkList == nil || file.chunkList.ChunkSize != index.ChunkSize ||
			file.chunkList.SHA256 != artifacts.ChunkListSHA256(index.ChunkSize, entry.SizeBytes, entry.Chunks) {
			return fmt.Errorf("published manifest artifact %s has no chunk-list digest bound to the chunk index", file.publish)
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, artifacts.SHA256SUMSName))
	if err != nil {
		return fmt.Errorf("read staged %s: %w", artifacts.SHA256SUMSName, err)
	}
	if _, err := artifacts.ParseSHA256SUMS(sums); err != nil {
		return fmt.Errorf("staged %s: %w", artifacts.SHA256SUMSName, err)
	}
	return nil
}

// completeStagedSet fills in the whole-file sha256 of native entries staged
// by size alone (a Fastlet that skipped the hash, possibly on a stale
// capability) and rewrites SHA256SUMS from the completed manifest. Only an
// agent with format: chunked and chunkListOnly: true publishes such entries
// as they are, and even then not when SHA256SUMS would list nothing, which
// readers reject. It returns the native files with their digests.
func (c *Client) completeStagedSet(dir string, files []nativeFile) ([]nativeFile, error) {
	var missing []int
	for i, file := range files {
		if file.sha256 == "" {
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 {
		return files, nil
	}
	if c.transfer.ChunkListDigest() {
		sums, err := os.ReadFile(filepath.Join(dir, artifacts.SHA256SUMSName))
		if err == nil {
			if _, err := artifacts.ParseSHA256SUMS(sums); err == nil {
				return files, nil
			}
		}
	}
	var (
		wg   sync.WaitGroup
		errs = make([]error, len(missing))
	)
	completed := append([]nativeFile(nil), files...)
	for slot, i := range missing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sum, _, _, err := HashAndTrackFile(filepath.Join(dir, completed[i].publish))
			if err != nil {
				errs[slot] = fmt.Errorf("checksum staged %s: %w", completed[i].publish, err)
				return
			}
			completed[i].sha256 = sum
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(dir, publishManifestName)
	_, document, err := readStagedManifestDocument(manifestPath)
	if err != nil {
		return nil, err
	}
	entries, _ := document["files"].(map[string]any)
	cache := map[string]string{}
	names := make([]string, 0, len(completed)+2)
	for _, file := range completed {
		entry, ok := entries[file.publish].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("staged manifest is missing the %s artifact", file.publish)
		}
		entry["sha256"] = file.sha256
		cache[filepath.Join(dir, file.publish)] = file.sha256
		names = append(names, file.publish)
	}
	payload, err := rewriteStagedManifest(manifestPath, document)
	if err != nil {
		return nil, err
	}
	completedDocument, err := parseManifest(payload)
	if err != nil {
		return nil, err
	}
	for _, bundleFile := range []func() (nativeFile, bool, error){completedDocument.vaultFile, completedDocument.policyFile} {
		bundle, ok, err := bundleFile()
		if err != nil {
			return nil, err
		}
		if ok {
			cache[filepath.Join(dir, bundle.publish)] = bundle.sha256
			names = append(names, bundle.publish)
		}
	}
	sort.Strings(names)
	if err := artifacts.WriteSHA256SUMS(dir, names, cache); err != nil {
		return nil, err
	}
	klog.InfoS("runtime-agent completed size-only staged entries", "dir", dir, "files", len(missing))
	return completed, nil
}

// putFile streams one staged file into the store under a store-relative
// key. The opener reopens the file per attempt (net/http closes request
// bodies), so a transient failure retries against a fresh reader.
func (c *Client) putFile(ctx context.Context, dir, name, storeKey string) error {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return c.s3.put(ctx, storeKey, info.Size(), func() (io.ReadCloser, error) {
		return os.Open(path)
	})
}

// nowFunc is the publish clock; factored for tests.
var nowFunc = time.Now

func validateRootfsStaging(kind, dir string) error {
	if kind == agentprotocol.PublishKindCheckpoint {
		return fmt.Errorf("rootfsOnly cannot be published as a checkpoint")
	}
	// Reject mixed staging directories rather than silently ignoring VM state.
	for _, name := range []string{manifestVMStateName, manifestMemoryName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("rootfsOnly staging contains %s", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat staged %s: %w", name, err)
		}
	}
	return nil
}
