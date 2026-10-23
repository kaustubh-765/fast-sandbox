package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

type manifestCacheRegistry struct {
	server   *httptest.Server
	mu       sync.Mutex
	payload  []byte
	byDigest map[string][]byte
	requests int
	deny     bool
}

func newManifestCacheRegistry(t *testing.T, payload []byte) *manifestCacheRegistry {
	t.Helper()
	r := &manifestCacheRegistry{payload: payload, byDigest: map[string][]byte{}}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.requests++
		if r.deny {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw := r.payload
		if selected, ok := r.byDigest[path.Base(req.URL.Path)]; ok {
			raw = selected
		}
		mediaType := oci.MediaTypeImageManifest
		if bytes.Contains(raw, []byte(`"manifests"`)) {
			mediaType = oci.MediaTypeImageIndex
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(raw).String())
		if req.Method != http.MethodHead {
			_, _ = w.Write(raw)
		}
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *manifestCacheRegistry) reference(selector string) string {
	separator := ":"
	if strings.HasPrefix(selector, "sha256:") {
		separator = "@"
	}
	return strings.TrimPrefix(r.server.URL, "http://") + "/team/template" + separator + selector
}

func (r *manifestCacheRegistry) requestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

func cacheTestManifest(t *testing.T, layer string) []byte {
	t.Helper()
	manifest := oci.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: oci.MediaTypeImageManifest,
		Config: oci.Descriptor{MediaType: oci.MediaTypeImageConfig, Digest: digest.FromString("{}"), Size: 2},
		Layers: []oci.Descriptor{{MediaType: overlaybdZfileLayerMediaType, Digest: digest.FromString(layer), Size: int64(len(layer))}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func setupManifestCache(t *testing.T) {
	t.Helper()
	previous := global
	global.stateDir, global.plainHTTP = t.TempDir(), true
	t.Cleanup(func() { global = previous })
}

func testManifestCachePath(t *testing.T, reference string, config dockerConfig) string {
	t.Helper()
	ref, err := parseRegistryReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	cachePath, err := createManifestCachePath(ref, config)
	if err != nil {
		t.Fatal(err)
	}
	return cachePath
}

func TestResolveImageCachesBothImmutableManifestsOffline(t *testing.T) {
	setupManifestCache(t)
	rootfs, snapfiles := cacheTestManifest(t, "rootfs"), cacheTestManifest(t, "snapfiles")
	r := newManifestCacheRegistry(t, rootfs)
	r.mu.Lock()
	r.byDigest[digest.FromBytes(snapfiles).String()] = snapfiles
	r.mu.Unlock()
	config := dockerConfig{}
	for _, raw := range [][]byte{rootfs, snapfiles} {
		reference := r.reference(digest.FromBytes(raw).String())
		if _, err := resolveImage(context.Background(), reference, config); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(testManifestCachePath(t, reference, config))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("cache file permissions: %v, %v", info, err)
		}
	}
	coldRequests := r.requestCount()
	r.server.Close()
	for _, raw := range [][]byte{rootfs, snapfiles} {
		if _, err := resolveImage(context.Background(), r.reference(digest.FromBytes(raw).String()), config); err != nil {
			t.Fatalf("warm create must work with registry offline: %v", err)
		}
	}
	if r.requestCount() != coldRequests {
		t.Fatal("warm lookup contacted the registry")
	}
}

func TestResolveImageRepairsCorruptManifestCache(t *testing.T) {
	setupManifestCache(t)
	raw := cacheTestManifest(t, "rootfs")
	r := newManifestCacheRegistry(t, raw)
	reference := r.reference(digest.FromBytes(raw).String())
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err != nil {
		t.Fatal(err)
	}
	cachePath := testManifestCachePath(t, reference, dockerConfig{})
	if err := os.WriteFile(cachePath, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := r.requestCount()
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(cachePath)
	if err != nil || !bytes.Equal(stored, raw) || r.requestCount() <= before {
		t.Fatalf("corrupt cache was not fetched and repaired: %v", err)
	}
	if err := os.WriteFile(cachePath, []byte("corrupt again"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.server.Close()
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err == nil {
		t.Fatal("corrupt cache must not be accepted when the registry is offline")
	}
}

func TestResolveImageDoesNotCacheMutableTags(t *testing.T) {
	setupManifestCache(t)
	r := newManifestCacheRegistry(t, cacheTestManifest(t, "first"))
	reference := r.reference("v1")
	first, err := resolveImage(context.Background(), reference, dockerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.payload = cacheTestManifest(t, "second")
	r.mu.Unlock()
	second, err := resolveImage(context.Background(), reference, dockerConfig{})
	if err != nil || first.Lowers[0].Digest == second.Lowers[0].Digest {
		t.Fatalf("mutable tag did not resolve its new contents: %v", err)
	}
	if testManifestCachePath(t, reference, dockerConfig{}) != "" {
		t.Fatal("mutable tag was assigned a cache entry")
	}
}

func TestManifestCacheScopesRegistryAccess(t *testing.T) {
	setupManifestCache(t)
	reference := "registry.example/team/template@" + digest.FromString("manifest").String()
	config := dockerConfig{Auths: map[string]authEntry{"registry.example": {Username: "alice", Password: "secret"}}}
	original := testManifestCachePath(t, reference, config)
	encoded := dockerConfig{Auths: map[string]authEntry{"registry.example": {Auth: base64.StdEncoding.EncodeToString([]byte("alice:secret"))}}}
	if original != testManifestCachePath(t, reference, encoded) {
		t.Fatal("equivalent credential encodings should share the same scope")
	}
	for _, changed := range []string{
		strings.Replace(reference, "registry.example", "other.example", 1),
		strings.Replace(reference, "team/template", "other/template", 1),
	} {
		if original == testManifestCachePath(t, changed, config) {
			t.Fatal("different registry/repository reused a cache scope")
		}
	}
	if original == testManifestCachePath(t, reference, dockerConfig{}) {
		t.Fatal("anonymous access reused a private credential scope")
	}
	config.Auths["registry.example"] = authEntry{Username: "alice", Password: "rotated"}
	if original == testManifestCachePath(t, reference, config) {
		t.Fatal("rotated credential reused the old scope")
	}
	global.plainHTTP = false
	if original == testManifestCachePath(t, reference, encoded) {
		t.Fatal("HTTPS reused the HTTP cache scope")
	}
}

func TestResolveImageCredentialChangeCannotUseCachedManifest(t *testing.T) {
	setupManifestCache(t)
	raw := cacheTestManifest(t, "rootfs")
	r := newManifestCacheRegistry(t, raw)
	reference := r.reference(digest.FromBytes(raw).String())
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.deny = true
	r.mu.Unlock()
	host := strings.TrimPrefix(r.server.URL, "http://")
	config := dockerConfig{Auths: map[string]authEntry{host: {Username: "new-user", Password: "new-password"}}}
	if _, err := resolveImage(context.Background(), reference, config); err == nil {
		t.Fatal("changed credentials must not use another access scope's cached manifest")
	}
}

func TestResolveImageCacheWriteFailureIsNonFatal(t *testing.T) {
	setupManifestCache(t)
	global.stateDir = filepath.Join(global.stateDir, "not-a-directory")
	if err := os.WriteFile(global.stateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	raw := cacheTestManifest(t, "rootfs")
	r := newManifestCacheRegistry(t, raw)
	if _, err := resolveImage(context.Background(), r.reference(digest.FromBytes(raw).String()), dockerConfig{}); err != nil {
		t.Fatalf("cache persistence failure rejected a valid remote manifest: %v", err)
	}
}

func TestResolveImageDoesNotCacheInvalidManifest(t *testing.T) {
	setupManifestCache(t)
	var manifest oci.Manifest
	if err := json.Unmarshal(cacheTestManifest(t, "rootfs"), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Layers[0].Digest = "sha256:bad"
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	r := newManifestCacheRegistry(t, raw)
	reference := r.reference(digest.FromBytes(raw).String())
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err == nil {
		t.Fatal("invalid layer descriptor was accepted")
	}
	if _, err := os.Stat(testManifestCachePath(t, reference, dockerConfig{})); !os.IsNotExist(err) {
		t.Fatalf("invalid manifest was cached: %v", err)
	}
}

func TestResolveImageConcurrentCachePublication(t *testing.T) {
	setupManifestCache(t)
	raw := cacheTestManifest(t, "rootfs")
	r := newManifestCacheRegistry(t, raw)
	reference := r.reference(digest.FromBytes(raw).String())
	errors := make(chan error, 8)
	for range cap(errors) {
		go func() {
			_, err := resolveImage(context.Background(), reference, dockerConfig{})
			errors <- err
		}()
	}
	for range cap(errors) {
		if err := <-errors; err != nil {
			t.Error(err)
		}
	}
	r.server.Close()
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err != nil {
		t.Fatalf("concurrent writers left an invalid entry: %v", err)
	}
}

func TestResolveImageIndexDigestDoesNotCacheChildUnderParent(t *testing.T) {
	setupManifestCache(t)
	child := cacheTestManifest(t, "rootfs")
	index := oci.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: oci.MediaTypeImageIndex, Manifests: []oci.Descriptor{{
		MediaType: oci.MediaTypeImageManifest, Digest: digest.FromBytes(child), Size: int64(len(child)),
		Platform: &oci.Platform{OS: "linux", Architecture: "amd64"},
	}}}
	// Match the platform selected by the existing create resolver.
	index.Manifests[0].Platform.Architecture = runtime.GOARCH
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	r := newManifestCacheRegistry(t, raw)
	r.mu.Lock()
	r.byDigest[digest.FromBytes(child).String()] = child
	r.mu.Unlock()
	reference := r.reference(digest.FromBytes(raw).String())
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(testManifestCachePath(t, reference, dockerConfig{})); !os.IsNotExist(err) {
		t.Fatalf("selected child was cached under its parent index digest: %v", err)
	}
}

func TestResolveImageRevokedCredentialCannotUsePrivateManifestCache(t *testing.T) {
	setupManifestCache(t)
	raw := cacheTestManifest(t, "private-rootfs")
	r := newManifestCacheRegistry(t, raw)
	reference := r.reference(digest.FromBytes(raw).String())
	host := strings.TrimPrefix(r.server.URL, "http://")
	private := dockerConfig{Auths: map[string]authEntry{host: {Username: "reader", Password: "secret"}}}
	_, err := resolveImage(context.Background(), reference, private)
	if err != nil {
		t.Fatal(err)
	}
	before := r.requestCount()
	r.mu.Lock()
	r.deny = true
	r.mu.Unlock()
	if _, err := resolveImage(context.Background(), reference, dockerConfig{}); err == nil {
		t.Fatal("revoked access reused the private manifest cache")
	}
	if r.requestCount() <= before {
		t.Fatal("revoked access did not revalidate anonymous access with the registry")
	}
}

func TestManifestCacheSurvivesSandboxStateRootReplacement(t *testing.T) {
	setupManifestCache(t)
	global.manifestCacheDir = t.TempDir()
	reference, config, requests, closeRegistry := templateRegistry(t)
	first := templateFile{Template: templateRef{Reference: reference}}
	if err := resolveTemplate(context.Background(), &first, config); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{first.rootfsRef(), first.snapfilesRef()} {
		if _, err := resolveImage(context.Background(), ref, config); err != nil {
			t.Fatal(err)
		}
	}
	coldRequests := requests.Load()
	if err := os.RemoveAll(global.stateDir); err != nil {
		t.Fatal(err)
	}
	global.stateDir = t.TempDir()
	closeRegistry()
	second := templateFile{Template: templateRef{Reference: reference}}
	if err := resolveTemplate(context.Background(), &second, config); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{second.rootfsRef(), second.snapfilesRef()} {
		if _, err := resolveImage(context.Background(), ref, config); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != coldRequests || first.Template.Rootfs != second.Template.Rootfs {
		t.Fatal("replaced sandbox state root did not reuse the cached immutable pair")
	}
	rotated := dockerConfig{Auths: map[string]authEntry{strings.SplitN(strings.TrimPrefix(reference, "oci://"), "/", 2)[0]: {Username: "other", Password: "rotated"}}}
	third := templateFile{Template: templateRef{Reference: reference}}
	if err := resolveTemplate(context.Background(), &third, rotated); err == nil {
		t.Fatal("shared cache crossed credential scopes")
	}
}

func TestManifestCacheEvictsOldestEntriesByBytesAndCount(t *testing.T) {
	for _, limit := range []struct {
		name  string
		bytes int64
		files int
	}{{"bytes", 16, 100}, {"files", 100, 2}} {
		t.Run(limit.name, func(t *testing.T) {
			root := t.TempDir()
			paths := []string{filepath.Join(root, "old-scope", "old.json"), filepath.Join(root, "scope", "warm.json"), filepath.Join(root, "scope", "new.json.template")}
			for i, path := range paths {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("12345678"), 0600); err != nil {
					t.Fatal(err)
				}
				stamp := time.Unix(int64(i+1), 0)
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			// A read refreshes recency, so a recently reused entry beats a newer write.
			if _, ok := readCachedManifest(paths[0]); !ok {
				t.Fatal("cache read failed")
			}
			if err := trimManifestCache(root, limit.bytes, limit.files); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(paths[1]); !os.IsNotExist(err) {
				t.Fatalf("oldest entry retained: %v", err)
			}
			for _, path := range []string{paths[0], paths[2]} {
				if _, err := os.Stat(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := trimManifestCache(root, 0, 0); err != nil {
				t.Fatal(err)
			}
			items, err := os.ReadDir(root)
			if err != nil || len(items) != 0 {
				t.Fatalf("evicted scopes remain: %v %v", items, err)
			}
		})
	}
}
