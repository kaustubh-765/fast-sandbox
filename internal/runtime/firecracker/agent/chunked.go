package agent

// chunked.go implements the chunked artifact-set transfer (FSEP-0004; the
// format is in internal/artifacts/chunks.go). Publish splits each native
// artifact the staged manifest lists into fixed-size chunks, drops all-zero
// chunks and uploads the rest in parallel to content-addressed keys,
// skipping chunks the store already holds. Pull fetches the listed chunks in
// parallel into sparse files, verifying each chunk before it is written.
// The bytes on the wire, not request parallelism, are what this saves: most
// of a guest memory dump and of a rootfs are all-zero blocks, and
// consecutive snapshots of one Sandbox share most of the rest.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"k8s.io/klog/v2"

	"fast-sandbox/internal/artifacts"
)

const (
	// TransferFormatLegacy publishes whole-file sets (the original layout).
	TransferFormatLegacy = "legacy"
	// TransferFormatChunked publishes chunked, zero-elided sets.
	TransferFormatChunked = "chunked"

	// TransferCompressionNone stores chunks raw.
	TransferCompressionNone = "none"
	// TransferCompressionZstd stores chunks zstd-compressed.
	TransferCompressionZstd = "zstd"

	// defaultTransferConcurrency: with zero chunks elided a set is a few
	// hundred MiB at most, so 8 streams already hide per-request latency;
	// more only adds loss behind a rate-policed link.
	defaultTransferConcurrency = 8
	// chunkSizeAlignment keeps chunk boundaries on sparse-file and store
	// stripe boundaries.
	chunkSizeAlignment = 64 << 10
	// maxChunkIndexBytes caps the downloaded chunk index (a 64 GiB fully
	// dense file is ~16k entries, well under this).
	maxChunkIndexBytes = 32 << 20
)

// TransferConfig selects the store format of new publishes. Pulls read both
// layouts whatever it says: the reader is chosen by each set's manifest, so
// switching back to legacy keeps every chunked set restorable. Nothing local
// (cache durability, hashing) depends on it.
type TransferConfig struct {
	Format      string
	Compression string
	Concurrency int
	ChunkSize   int64
}

func (t TransferConfig) normalized() TransferConfig {
	if t.Format == "" {
		t.Format = TransferFormatLegacy
	}
	if t.Compression == "" {
		t.Compression = TransferCompressionNone
	}
	if t.Concurrency <= 0 {
		t.Concurrency = defaultTransferConcurrency
	}
	if t.ChunkSize <= 0 {
		t.ChunkSize = artifacts.DefaultChunkSize
	}
	return t
}

// Chunked reports whether new publishes use the chunked format.
func (t TransferConfig) Chunked() bool {
	return t.normalized().Format == TransferFormatChunked
}

// Validate rejects unknown values and combinations that only make sense in
// another format, so a typo never silently falls back to a default.
func (t TransferConfig) Validate() error {
	t = t.normalized()
	switch t.Format {
	case TransferFormatLegacy, TransferFormatChunked:
	default:
		return fmt.Errorf("unknown transfer format %q (want %s or %s)", t.Format, TransferFormatLegacy, TransferFormatChunked)
	}
	switch t.Compression {
	case TransferCompressionNone, TransferCompressionZstd:
	default:
		return fmt.Errorf("unknown transfer compression %q (want %s or %s)", t.Compression, TransferCompressionNone, TransferCompressionZstd)
	}
	if t.Format == TransferFormatLegacy && t.Compression != TransferCompressionNone {
		return fmt.Errorf("transfer compression %q requires format %s", t.Compression, TransferFormatChunked)
	}
	if t.ChunkSize%chunkSizeAlignment != 0 {
		return fmt.Errorf("transfer chunk size %d must be a multiple of 64KiB", t.ChunkSize)
	}
	return nil
}

// WithTransfer sets the transfer configuration of the client.
func WithTransfer(transfer TransferConfig) Option {
	return func(config *optionsConfig) { config.transfer = transfer }
}

var (
	zstdEncoderOnce sync.Once
	zstdEncoder     *zstd.Encoder
	zstdDecoderOnce sync.Once
	zstdDecoder     *zstd.Decoder
)

// chunkEncoder returns the shared encoder (EncodeAll is safe for concurrent
// use). The level is part of what a publisher writes, not of the format:
// readers decode any zstd frame.
func chunkEncoder() *zstd.Encoder {
	zstdEncoderOnce.Do(func() {
		zstdEncoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	})
	return zstdEncoder
}

// chunkDecoder returns the shared decoder (DecodeAll is safe for concurrent
// use).
func chunkDecoder() *zstd.Decoder {
	zstdDecoderOnce.Do(func() {
		zstdDecoder, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
	})
	return zstdDecoder
}

// chunkJob is one chunk of one file.
type chunkJob struct {
	file   string
	offset int64
	length int64
}

// runChunkJobs runs fn over jobs on n workers and returns the first error;
// remaining jobs are skipped once one fails. It returns nil only when every
// job ran to success: a parent cancelled between jobs stops the workers
// without a job error, and must still fail the run, or a pull would commit
// files whose unfetched chunks read as zeros.
func runChunkJobs(parent context.Context, n int, jobs []chunkJob, fn func(context.Context, chunkJob) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var (
		next     atomic.Int64
		done     atomic.Int64
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	for range min(n, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(jobs) || ctx.Err() != nil {
					return
				}
				if err := fn(ctx, jobs[i]); err != nil {
					once.Do(func() { firstErr = err; cancel() })
					return
				}
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	if completed := done.Load(); completed != int64(len(jobs)) {
		if err := parent.Err(); err != nil {
			return err
		}
		return fmt.Errorf("chunk jobs: %d of %d completed", completed, len(jobs))
	}
	return nil
}

// publishStats summarizes one chunked publish for the log line.
type publishStats struct {
	logicalBytes  int64
	zeroChunks    int64
	dataChunks    int64
	reusedChunks  int64
	uploadedBytes int64
}

// publishChunks uploads the non-zero chunks of the named staged files and
// returns the chunk index describing them. Chunk objects are content
// addressed and immutable, so an existing key (known to this client, or
// answered by HEAD) is reused without uploading it again.
func (c *Client) publishChunks(ctx context.Context, dir string, names []string) (artifacts.ChunkIndex, publishStats, error) { //nolint:gocognit // one scan-then-upload pipeline; splitting it scatters the shared index and stats
	transfer := c.transfer.normalized()
	index := artifacts.ChunkIndex{Version: artifacts.ChunkIndexVersion, ChunkSize: transfer.ChunkSize, Files: map[string]artifacts.ChunkIndexFile{}}
	stats := publishStats{}
	handles := map[string]*os.File{}
	defer func() {
		for _, handle := range handles {
			_ = handle.Close()
		}
	}()
	var jobs []chunkJob
	for _, name := range names {
		handle, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return index, stats, err
		}
		handles[name] = handle
		info, err := handle.Stat()
		if err != nil {
			return index, stats, err
		}
		index.Files[name] = artifacts.ChunkIndexFile{SizeBytes: info.Size(), Chunks: []artifacts.Chunk{}}
		stats.logicalBytes += info.Size()
		// Chunks entirely inside a hole are zero without reading them; the
		// rest are read and zero-checked (allocated zeros are common too).
		offsets, ok := dataChunkOffsets(handle, info.Size(), transfer.ChunkSize)
		if !ok {
			offsets = offsets[:0]
			for offset := int64(0); offset < info.Size(); offset += transfer.ChunkSize {
				offsets = append(offsets, offset)
			}
		}
		total := (info.Size() + transfer.ChunkSize - 1) / transfer.ChunkSize
		stats.zeroChunks += total - int64(len(offsets))
		for _, offset := range offsets {
			jobs = append(jobs, chunkJob{file: name, offset: offset, length: min(transfer.ChunkSize, info.Size()-offset)})
		}
	}

	encoding := artifacts.ChunkEncodingRaw
	if transfer.Compression == TransferCompressionZstd {
		encoding = artifacts.ChunkEncodingZstd
	}
	buffers := sync.Pool{New: func() any { buffer := make([]byte, transfer.ChunkSize); return &buffer }}
	var mu sync.Mutex
	err := runChunkJobs(ctx, transfer.Concurrency, jobs, func(ctx context.Context, job chunkJob) error {
		bufferRef := buffers.Get().(*[]byte) //nolint:forcetypeassert // the pool only holds *[]byte
		defer buffers.Put(bufferRef)
		block := (*bufferRef)[:job.length]
		if _, err := handles[job.file].ReadAt(block, job.offset); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read %s at %d: %w", job.file, job.offset, err)
		}
		if artifacts.IsZero(block) {
			atomic.AddInt64(&stats.zeroChunks, 1)
			return nil
		}
		digest := sha256.Sum256(block)
		sum := hex.EncodeToString(digest[:])
		storedSize, reused, err := c.storeChunk(ctx, sum, encoding, block)
		if err != nil {
			return err
		}
		atomic.AddInt64(&stats.dataChunks, 1)
		if reused {
			atomic.AddInt64(&stats.reusedChunks, 1)
		} else {
			atomic.AddInt64(&stats.uploadedBytes, storedSize)
		}
		mu.Lock()
		file := index.Files[job.file]
		file.Chunks = append(file.Chunks, artifacts.Chunk{
			Offset: job.offset, Length: job.length, SHA256: sum, Encoding: encoding, StoredSize: storedSize,
		})
		index.Files[job.file] = file
		mu.Unlock()
		return nil
	})
	return index, stats, err
}

// storeChunk makes the chunk object present in the store and returns its
// stored size and whether an existing object was reused.
func (c *Client) storeChunk(ctx context.Context, sum, encoding string, block []byte) (int64, bool, error) {
	key := artifacts.ChunkObjectKey(sum, encoding)
	if size, ok := c.knownChunks.Load(key); ok {
		return size.(int64), true, nil //nolint:forcetypeassert // the map only holds int64
	}
	// Identical chunks inside one set (or concurrent publishes) race to the
	// same key: one worker uploads, the others share its outcome.
	type stored struct {
		size   int64
		reused bool
	}
	// singleflight reports shared=true to the caller that ran the function
	// as well as to its waiters, so it cannot tell who uploaded. Do runs fn
	// on the calling goroutine: executed marks the one caller whose outcome
	// is its own, and only the waiters count the chunk as reused.
	executed := false
	outcome, err, _ := c.chunkFlight.Do(key, func() (any, error) {
		executed = true
		size, reused, err := c.storeChunkOnce(ctx, key, encoding, block)
		return stored{size: size, reused: reused}, err
	})
	if err != nil {
		return 0, false, err
	}
	result := outcome.(stored) //nolint:forcetypeassert // the flight only returns stored
	return result.size, result.reused || !executed, nil
}

func (c *Client) storeChunkOnce(ctx context.Context, key, encoding string, block []byte) (int64, bool, error) {
	if size, ok := c.knownChunks.Load(key); ok {
		return size.(int64), true, nil //nolint:forcetypeassert // the map only holds int64
	}
	type head struct {
		size int64
		ok   bool
	}
	found, err := withChunkAttempts(ctx, "HEAD "+key, func(ctx context.Context) (head, error) {
		size, ok, err := c.s3.size(ctx, key)
		return head{size: size, ok: ok}, err
	})
	if err != nil {
		return 0, false, fmt.Errorf("check chunk %s: %w", key, err)
	}
	if found.ok {
		c.knownChunks.Store(key, found.size)
		return found.size, true, nil
	}
	payload := block
	if encoding == artifacts.ChunkEncodingZstd {
		payload = chunkEncoder().EncodeAll(block, make([]byte, 0, len(block)/2))
	}
	if err := c.s3.putBytes(ctx, key, payload); err != nil {
		return 0, false, fmt.Errorf("upload chunk %s: %w", key, err)
	}
	c.knownChunks.Store(key, int64(len(payload)))
	return int64(len(payload)), false, nil
}

// bindChunkIndex rewrites the staged manifest so it binds the chunk index,
// or with ref == nil drops a binding inherited from a source manifest (the
// Fastlet builds a snapshot manifest from the one the Sandbox booted from,
// and a whole-file set must not point at a chunks.json it never uploaded).
// A document without a binding to drop keeps its exact bytes, so a legacy
// publish stays byte-identical. The rewrite is atomic and deterministic: the
// staged manifest then equals the published one, which the Fastlet's
// same-node cache commit relies on. It returns the manifest bytes to publish.
func bindChunkIndex(dir string, ref *artifacts.ChunkIndexRef) ([]byte, error) {
	manifestPath := filepath.Join(dir, publishManifestName)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read staged manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(original))
	decoder.UseNumber()
	document := map[string]any{}
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode staged manifest: %w", err)
	}
	if _, had := document[artifacts.ManifestChunksField]; ref == nil && !had {
		return original, nil
	}
	delete(document, artifacts.ManifestChunksField)
	if ref != nil {
		document[artifacts.ManifestChunksField] = ref
	}
	return rewriteStagedManifest(manifestPath, document)
}

// rewriteStagedManifest atomically replaces the staged manifest with
// document, in the layout of artifacts.MarshalVMManifest (two-space indent,
// trailing newline). The generic map keeps every unknown field; its keys
// marshal sorted, so the bytes depend only on the content.
func rewriteStagedManifest(manifestPath string, document map[string]any) ([]byte, error) {
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	tmp := manifestPath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil { //nolint:gosec // published manifest, world-readable like the original
		return nil, err
	}
	if err := os.Rename(tmp, manifestPath); err != nil {
		return nil, err
	}
	return payload, nil
}

// chunkBinding returns the optional chunk index binding of a manifest
// document (nil for a whole-file set). It is a manifest extension outside
// the shared VMManifest model, so it is decoded from the raw bytes.
func chunkBinding(payload []byte) (*artifacts.ChunkIndexRef, error) {
	var document struct {
		Chunks *artifacts.ChunkIndexRef `json:"chunks,omitempty"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("decode manifest chunk binding: %w", err)
	}
	return document.Chunks, nil
}

// chunkTarget is one cache file a chunked pull writes.
type chunkTarget struct {
	file nativeFile
	tmp  *os.File
}

// materializeChunked pulls a chunked set into dir: the chunk index
// (verified against the manifest binding), then every listed chunk in
// parallel into sparse temporary files, each chunk verified against its
// digest before it is written. Files are committed only after every chunk
// of every file was written, and each committed file is recorded in the
// verified-digest memo under the manifest's digest, which the verified
// chain (artifactDigest -> manifest -> chunks.json -> chunk digests) vouches
// for. The state bundles (vault, policy) are small whole-file objects.
func (c *Client) materializeChunked(ctx context.Context, dir, buildDir string, ref artifacts.ChunkIndexRef, files []nativeFile) error { //nolint:gocognit // verify-then-write chain kept in one place for review
	// Version 1 sets carry their index under one fixed name in the set's
	// namespace; anything else would address an object outside it.
	if ref.Version != artifacts.ChunkIndexVersion {
		return fmt.Errorf("unsupported chunk index binding version %d", ref.Version)
	}
	if ref.Ref != artifacts.ChunkIndexName {
		return fmt.Errorf("unsupported chunk index ref %q (want %s)", ref.Ref, artifacts.ChunkIndexName)
	}
	index, err := c.fetchChunkIndex(ctx, buildDir+"/"+ref.Ref, ref)
	if err != nil {
		return err
	}
	targets := map[string]*chunkTarget{}
	defer func() {
		for _, entry := range targets {
			_ = entry.tmp.Close()
			_ = os.Remove(entry.tmp.Name())
		}
	}()
	var jobs []chunkJob
	var whole []nativeFile
	chunks := map[chunkJob]artifacts.Chunk{}
	for _, file := range files {
		entry, ok := index.Files[file.publish]
		if !ok {
			if !isNativeArtifact(file.publish) {
				whole = append(whole, file)
				continue
			}
			return fmt.Errorf("chunk index is missing %s", file.publish)
		}
		if entry.SizeBytes != file.sizeBytes {
			return fmt.Errorf("chunk index %s size %d does not match the manifest size %d", file.publish, entry.SizeBytes, file.sizeBytes)
		}
		if match, err := fileMatches(filepath.Join(dir, file.cache), file); err == nil && match {
			continue
		}
		tmp, err := os.CreateTemp(dir, file.cache+".tmp-*")
		if err != nil {
			return err
		}
		targets[file.publish] = &chunkTarget{file: file, tmp: tmp}
		if err := tmp.Truncate(file.sizeBytes); err != nil {
			return err
		}
		for _, chunk := range entry.Chunks {
			job := chunkJob{file: file.publish, offset: chunk.Offset, length: chunk.Length}
			jobs = append(jobs, job)
			chunks[job] = chunk
		}
	}

	transfer := c.transfer.normalized()
	err = runChunkJobs(ctx, transfer.Concurrency, jobs, func(ctx context.Context, job chunkJob) error {
		chunk := chunks[job]
		block, err := c.fetchChunk(ctx, chunk)
		if err != nil {
			return err
		}
		if _, err := targets[job.file].tmp.WriteAt(block, chunk.Offset); err != nil {
			return fmt.Errorf("write %s at %d: %w", job.file, chunk.Offset, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Never commit after a cancellation, whatever the jobs reported: the
	// files are only complete if every chunk was written.
	if err := ctx.Err(); err != nil {
		return err
	}
	for name, entry := range targets {
		if err := commitChunkedFile(entry, filepath.Join(dir, entry.file.cache)); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
		delete(targets, name)
	}
	return c.stageWholeFiles(ctx, dir, buildDir, whole)
}

// commitChunkedFile commits one fully written chunked cache file the way
// stageFile commits a download: settled mtime, fsync, rename, then the
// verified-digest memo bound to the open descriptor's identity. It closes
// the file on every path.
func commitChunkedFile(entry *chunkTarget, target string) error {
	tmp := entry.tmp
	if err := tmp.Chmod(cacheFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	PrepareCommittedCacheFile(tmp.Name())
	if err := fsyncFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		_ = tmp.Close()
		return err
	}
	info, statErr := tmp.Stat()
	if err := tmp.Close(); err != nil {
		return err
	}
	if statErr == nil {
		recordVerifiedFile(target, info, entry.file.sha256, time.Now())
	}
	return nil
}

// isNativeArtifact reports whether a published name is one of the native
// artifacts a chunked set carries in its chunk index.
func isNativeArtifact(name string) bool {
	for _, artifact := range nativeArtifactNames {
		if artifact.publish == name {
			return true
		}
	}
	return false
}

// fetchChunkIndex downloads the chunk index and verifies it against the
// manifest binding before parsing it.
func (c *Client) fetchChunkIndex(ctx context.Context, key string, ref artifacts.ChunkIndexRef) (artifacts.ChunkIndex, error) {
	body, err := c.s3.get(ctx, key)
	if err != nil {
		return artifacts.ChunkIndex{}, fmt.Errorf("fetch chunk index: %w", err)
	}
	defer body.Close()
	payload, err := io.ReadAll(io.LimitReader(body, maxChunkIndexBytes+1))
	if err != nil {
		return artifacts.ChunkIndex{}, fmt.Errorf("read chunk index: %w", err)
	}
	if len(payload) > maxChunkIndexBytes {
		return artifacts.ChunkIndex{}, fmt.Errorf("chunk index exceeds the %d-byte limit", maxChunkIndexBytes)
	}
	if int64(len(payload)) != ref.SizeBytes || sha256Hex(payload) != ref.SHA256 {
		return artifacts.ChunkIndex{}, errors.New("chunk index does not match the manifest binding")
	}
	return artifacts.ParseChunkIndex(payload)
}

// withChunkAttempts runs one chunk request with a per-attempt timeout,
// retrying transient failures: a stalled connection, which the timeout
// drops so the retry dials a fresh one, and a truncated body, which the
// store client's own retry does not cover. A missing object and a cancelled
// context are final.
func withChunkAttempts[T any](ctx context.Context, what string, attempt func(context.Context) (T, error)) (T, error) {
	var (
		zero    T
		lastErr error
	)
	for try := 0; try <= s3RetryAttempts; try++ {
		attemptCtx, cancel := context.WithTimeout(ctx, chunkAttemptTimeout)
		result, err := attempt(attemptCtx)
		cancel()
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if errors.Is(err, ErrObjectNotFound) {
			return zero, err
		}
		lastErr = err
		klog.InfoS("chunk request attempt failed, retrying", "request", what, "attempt", try+1, "err", err)
	}
	return zero, fmt.Errorf("%s: %w", what, lastErr)
}

// fetchChunk downloads, decodes and verifies one chunk.
func (c *Client) fetchChunk(ctx context.Context, chunk artifacts.Chunk) ([]byte, error) {
	key := artifacts.ChunkObjectKey(chunk.SHA256, chunk.Encoding)
	return withChunkAttempts(ctx, "GET "+key, func(ctx context.Context) ([]byte, error) {
		return c.fetchChunkOnce(ctx, key, chunk)
	})
}

func (c *Client) fetchChunkOnce(ctx context.Context, key string, chunk artifacts.Chunk) ([]byte, error) {
	body, err := c.getArtifact(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("fetch chunk %s: %w", key, err)
	}
	defer body.Close()
	stored, err := io.ReadAll(io.LimitReader(body, chunk.StoredSize+1))
	if err != nil {
		return nil, fmt.Errorf("read chunk %s: %w", key, err)
	}
	if int64(len(stored)) != chunk.StoredSize {
		return nil, fmt.Errorf("chunk %s: got %d bytes, want %d", key, len(stored), chunk.StoredSize)
	}
	block := stored
	if chunk.Encoding == artifacts.ChunkEncodingZstd {
		block, err = chunkDecoder().DecodeAll(stored, make([]byte, 0, chunk.Length))
		if err != nil {
			return nil, fmt.Errorf("decode chunk %s: %w", key, err)
		}
	}
	if int64(len(block)) != chunk.Length {
		return nil, fmt.Errorf("chunk %s: decoded %d bytes, want %d", key, len(block), chunk.Length)
	}
	if digest := sha256.Sum256(block); hex.EncodeToString(digest[:]) != chunk.SHA256 {
		return nil, fmt.Errorf("chunk %s digest mismatch", key)
	}
	return block, nil
}

// logPublishStats reports what a chunked publish actually moved.
func logPublishStats(kind, key string, stats publishStats) {
	klog.InfoS("runtime-agent chunked publish stats", "kind", kind, "key", key,
		"logicalBytes", stats.logicalBytes, "zeroChunks", stats.zeroChunks, "dataChunks", stats.dataChunks,
		"reusedChunks", stats.reusedChunks, "uploadedBytes", stats.uploadedBytes)
}
