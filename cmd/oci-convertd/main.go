// Command oci-convertd converts customer OCI images into per-layer OverlayBD
// images once per cluster, for Stage B OCI image drives. Fastlets ask it for
// the drive of an image (POST /v1/ensure); it resolves the linux/amd64 image
// through the in-cluster registry (a Docker Hub pull-through cache), runs the
// OverlayBD convertor on first use, and answers with the OverlayBD layers and
// the image config. Converted images are tagged obd-<source manifest hex> in
// the source repository, so the answer is stable and conversions survive
// restarts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	obdTagPrefix = "obd-"
	// maxConvert bounds one conversion (pull through the cache, per-layer
	// ext4 apply, push).
	maxConvert = 30 * time.Minute
)

var amd64 = v1.Platform{OS: "linux", Architecture: "amd64"}

type layer struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type imageConfig struct {
	Env        []string `json:"Env,omitempty"`
	Entrypoint []string `json:"Entrypoint,omitempty"`
	Cmd        []string `json:"Cmd,omitempty"`
	WorkingDir string   `json:"WorkingDir,omitempty"`
	User       string   `json:"User,omitempty"`
}

type ensureResponse struct {
	SourceDigest string      `json:"sourceDigest"`
	Repository   string      `json:"repository"`
	OBDDigest    string      `json:"obdDigest"`
	Lowers       []layer     `json:"lowers"`
	Config       imageConfig `json:"config"`
	Converted    bool        `json:"converted"`
	Seconds      float64     `json:"seconds"`
}

type runner func(ctx context.Context, binary string, args ...string) ([]byte, error)

type server struct {
	// registry is host:port of the plain-HTTP registry holding source and
	// converted images; it is also the host Fastlets hand to ublkd.
	registry  string
	convertor string
	workDir   string
	vsizeGiB  int
	run       runner
	slots     chan struct{}

	mu       sync.Mutex
	inflight map[string]*conversion
}

// conversion is one in-flight convertor run shared by concurrent requests;
// err is written before done is closed.
type conversion struct {
	done chan struct{}
	err  error
}

type requestError struct {
	status int
	err    error
}

func (e *requestError) Error() string { return e.err.Error() }

func newServer(registry, convertor, workDir string, vsizeGiB, concurrency int, run runner) *server {
	return &server{
		registry: registry, convertor: convertor, workDir: workDir, vsizeGiB: vsizeGiB, run: run,
		slots: make(chan struct{}, max(concurrency, 1)), inflight: map[string]*conversion{},
	}
}

// repository maps a Docker Hub reference to its repository in the cache.
// Other registries are not mirrored.
func repository(image string) (name.Reference, string, error) {
	reference, err := name.ParseReference(image)
	if err != nil {
		return nil, "", &requestError{http.StatusBadRequest, fmt.Errorf("parse image %q: %w", image, err)}
	}
	if reference.Context().RegistryStr() != name.DefaultRegistry {
		return nil, "", &requestError{http.StatusBadRequest, fmt.Errorf("image %q: only Docker Hub images are mirrored", image)}
	}
	return reference, reference.Context().RepositoryStr(), nil
}

func (s *server) local(repo, identifier string) (name.Reference, error) {
	separator := ":"
	if strings.HasPrefix(identifier, "sha256:") {
		separator = "@"
	}
	return name.ParseReference(s.registry+"/"+repo+separator+identifier, name.Insecure)
}

func (s *server) ensure(ctx context.Context, image string) (*ensureResponse, error) {
	started := time.Now()
	reference, repo, err := repository(image)
	if err != nil {
		return nil, err
	}
	source, err := s.local(repo, reference.Identifier())
	if err != nil {
		return nil, &requestError{http.StatusBadRequest, err}
	}
	descriptor, err := remote.Get(source, remote.WithContext(ctx), remote.WithPlatform(amd64))
	if err != nil {
		return nil, &requestError{http.StatusBadGateway, fmt.Errorf("resolve %s: %w", image, err)}
	}
	img, err := descriptor.Image()
	if err != nil {
		return nil, &requestError{http.StatusBadGateway, fmt.Errorf("resolve %s: %w", image, err)}
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}
	config, err := img.ConfigFile()
	if err != nil {
		return nil, &requestError{http.StatusBadGateway, fmt.Errorf("read config of %s: %w", image, err)}
	}
	target, err := s.local(repo, obdTagPrefix+digest.Hex)
	if err != nil {
		return nil, err
	}
	converted := false
	obd, err := remote.Get(target, remote.WithContext(ctx))
	if err != nil {
		if err := s.convert(ctx, repo, digest); err != nil {
			return nil, &requestError{http.StatusBadGateway, err}
		}
		converted = true
		if obd, err = remote.Get(target, remote.WithContext(ctx)); err != nil {
			return nil, &requestError{http.StatusBadGateway, fmt.Errorf("read converted %s: %w", target, err)}
		}
	}
	manifest, err := v1.ParseManifest(strings.NewReader(string(obd.Manifest)))
	if err != nil || len(manifest.Layers) == 0 {
		return nil, &requestError{http.StatusBadGateway, fmt.Errorf("converted %s has no layers: %v", target, err)}
	}
	response := &ensureResponse{
		SourceDigest: digest.String(),
		Repository:   s.registry + "/" + repo,
		OBDDigest:    obd.Digest.String(),
		Config: imageConfig{
			Env: config.Config.Env, Entrypoint: config.Config.Entrypoint, Cmd: config.Config.Cmd,
			WorkingDir: config.Config.WorkingDir, User: config.Config.User,
		},
		Converted: converted,
	}
	for _, l := range manifest.Layers {
		response.Lowers = append(response.Lowers, layer{Digest: l.Digest.String(), Size: l.Size})
	}
	response.Seconds = time.Since(started).Seconds()
	return response, nil
}

// convert runs the convertor once per source manifest, however many
// requests wait for it, with at most cap(slots) conversions at a time. A
// failed attempt is not remembered: the next request retries.
func (s *server) convert(ctx context.Context, repo string, digest v1.Hash) error {
	key := repo + "@" + digest.String()
	s.mu.Lock()
	if running, ok := s.inflight[key]; ok {
		s.mu.Unlock()
		select {
		case <-running.done:
			return running.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	running := &conversion{done: make(chan struct{})}
	s.inflight[key] = running
	s.mu.Unlock()

	// The conversion outlives a cancelled request: others may be waiting.
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
			close(running.done)
		}()
		s.slots <- struct{}{}
		defer func() { <-s.slots }()
		convertCtx, cancel := context.WithTimeout(context.Background(), maxConvert)
		defer cancel()
		dir := filepath.Join(s.workDir, digest.Hex)
		_ = os.RemoveAll(dir)
		defer os.RemoveAll(dir)
		started := time.Now()
		output, err := s.run(convertCtx, s.convertor,
			"--repository", s.registry+"/"+repo,
			"--input-digest", digest.String(),
			"--overlaybd", obdTagPrefix+digest.Hex,
			"--plain", "--oci", "--mkfs",
			"--vsize", strconv.Itoa(s.vsizeGiB),
			"--dir", dir)
		if err != nil {
			running.err = fmt.Errorf("convert %s: %w: %s", key, err, lastLines(output, 5))
			log.Printf("conversion failed: %v", running.err)
			return
		}
		log.Printf("converted %s in %.1fs", key, time.Since(started).Seconds())
	}()
	select {
	case <-running.done:
		return running.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func lastLines(output []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (s *server) handleEnsure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var request struct {
		Image string `json:"image"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil || strings.TrimSpace(request.Image) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"image\": \"<reference>\"}"})
		return
	}
	response, err := s.ensure(r.Context(), strings.TrimSpace(request.Image))
	if err != nil {
		status := http.StatusInternalServerError
		var requestErr *requestError
		if errors.As(err, &requestErr) {
			status = requestErr.status
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("ensure %s → %s (%d layers, converted=%t, %.2fs)", request.Image, response.OBDDigest, len(response.Lowers), response.Converted, response.Seconds)
	writeJSON(w, http.StatusOK, response)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func main() {
	registry := env("OCI_CONVERTD_REGISTRY", "")
	if registry == "" {
		log.Fatal("OCI_CONVERTD_REGISTRY (host:port of the plain-HTTP registry) is required")
	}
	vsize, err := strconv.Atoi(env("OCI_CONVERTD_VSIZE_GB", "64"))
	if err != nil || vsize <= 0 {
		log.Fatalf("invalid OCI_CONVERTD_VSIZE_GB: %v", err)
	}
	concurrency, err := strconv.Atoi(env("OCI_CONVERTD_CONCURRENCY", "2"))
	if err != nil || concurrency <= 0 {
		log.Fatalf("invalid OCI_CONVERTD_CONCURRENCY: %v", err)
	}
	s := newServer(registry, env("OCI_CONVERTD_CONVERTOR", "/usr/local/bin/convertor"), env("OCI_CONVERTD_WORKDIR", "/work"),
		vsize, concurrency, func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, binary, args...).CombinedOutput()
		})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ensure", s.handleEnsure)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	address := env("OCI_CONVERTD_LISTEN", ":8080")
	log.Printf("oci-convertd listening on %s, registry %s, %d concurrent conversions", address, registry, concurrency)
	srv := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
