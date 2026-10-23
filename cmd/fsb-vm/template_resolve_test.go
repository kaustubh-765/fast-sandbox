package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/ocitemplate"
)

func templateRegistry(t *testing.T) (string, dockerConfig, *atomic.Int64, func()) {
	t.Helper()
	root := cacheTestManifest(t, "rootfs")
	var snap oci.Manifest
	require.NoError(t, json.Unmarshal(cacheTestManifest(t, "snapfiles"), &snap))
	snap.Annotations = map[string]string{
		ocitemplate.AnnotationTemplateID:   "checkpoint-1",
		ocitemplate.AnnotationSandboxUID:   "sandbox-1",
		ocitemplate.AnnotationNamespace:    "tenant-a",
		ocitemplate.AnnotationCheckpointID: "checkpoint-1",
	}
	snapRaw, err := json.Marshal(snap)
	require.NoError(t, err)
	requests := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		username, password, _ := r.BasicAuth()
		if username != "reader" || password != "pool-secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var raw []byte
		switch strings.TrimPrefix(r.URL.Path, "/v2/team/template/") {
		case "manifests/checkpoint-1_rootfs", "manifests/" + digest.FromBytes(root).String():
			raw = root
		case "manifests/checkpoint-1_snapfiles", "manifests/" + digest.FromBytes(snapRaw).String():
			raw = snapRaw
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", oci.MediaTypeImageManifest)
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(raw).String())
		if r.Method != http.MethodHead {
			_, _ = w.Write(raw)
		}
	}))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")
	repository := host + "/team/template"
	config := dockerConfig{Auths: map[string]authEntry{host + "/team": {Username: "reader", Password: "pool-secret"}}}
	return ocitemplate.Prefix + repository + "@" + digest.FromBytes(snapRaw).String(), config, requests, server.Close
}

func TestTemplateReferenceUsesPoolAuthAndCachesEntirePairOffline(t *testing.T) {
	setupManifestCache(t)
	reference, config, requests, closeRegistry := templateRegistry(t)
	anonymous := templateFile{Template: templateRef{Reference: reference}}
	require.Error(t, resolveTemplate(context.Background(), &anonymous, dockerConfig{}), "private templates require Pool credentials on the first resolution")
	first := templateFile{SandboxID: "first", Template: templateRef{Reference: reference}}
	require.NoError(t, resolveTemplate(context.Background(), &first, config))
	for _, image := range []string{first.rootfsRef(), first.snapfilesRef()} {
		_, err := resolveImage(context.Background(), image, config)
		require.NoError(t, err)
	}
	require.Contains(t, string(first.Metadata), `"sandboxUID":"sandbox-1"`)
	require.NotContains(t, string(first.Metadata), "spoofed")
	coldRequests := requests.Load()
	require.Positive(t, coldRequests)
	closeRegistry()
	second := templateFile{SandboxID: "second", Template: templateRef{Reference: reference}}
	require.NoError(t, resolveTemplate(context.Background(), &second, config))
	require.Equal(t, first.Template.Rootfs, second.Template.Rootfs)
	require.Equal(t, first.Template.Snapfiles, second.Template.Snapfiles)
	require.JSONEq(t, string(first.Metadata), string(second.Metadata))
	for _, image := range []string{second.rootfsRef(), second.snapfilesRef()} {
		_, err := resolveImage(context.Background(), image, config)
		require.NoError(t, err)
	}
	require.Equal(t, coldRequests, requests.Load(), "warm preparation must not query registry metadata")

	rotated := dockerConfig{Auths: map[string]authEntry{strings.SplitN(strings.TrimPrefix(reference, ocitemplate.Prefix), "/", 2)[0]: {Username: "other", Password: "other-secret"}}}
	third := templateFile{Template: templateRef{Reference: reference}}
	require.Error(t, resolveTemplate(context.Background(), &third, rotated), "another access context cannot reuse cached metadata")
}

func TestTemplateTagIsResolvedAgainAndCacheCorruptionIsRepaired(t *testing.T) {
	setupManifestCache(t)
	reference, config, requests, _ := templateRegistry(t)
	template := templateFile{Template: templateRef{Reference: reference}}
	require.NoError(t, resolveTemplate(context.Background(), &template, config))
	ref, err := parseRegistryReference(strings.TrimPrefix(reference, ocitemplate.Prefix))
	require.NoError(t, err)
	path, err := createManifestCachePath(ref, config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".template", []byte(`{"oci":null}`), 0600))
	for range 2 {
		template = templateFile{Template: templateRef{Reference: reference}}
		require.NoError(t, resolveTemplate(context.Background(), &template, config))
	}
	tag := strings.SplitN(reference, "@", 2)[0] + ":checkpoint-1"
	template = templateFile{Template: templateRef{Reference: tag}}
	require.NoError(t, resolveTemplate(context.Background(), &template, config))
	before := requests.Load()
	template = templateFile{Template: templateRef{Reference: tag}}
	require.NoError(t, resolveTemplate(context.Background(), &template, config))
	require.Greater(t, requests.Load(), before, "mutable tags must not silently become immutable")
}
