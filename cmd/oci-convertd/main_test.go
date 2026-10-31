package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// fakeConvertor pushes a two-layer "OverlayBD" image to the requested tag.
type fakeConvertor struct {
	calls atomic.Int32
	delay time.Duration
	fail  atomic.Bool
}

func (f *fakeConvertor) run(ctx context.Context, _ string, args ...string) ([]byte, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if f.fail.Load() {
		return []byte("layer 0\nfailed to overlaybd-apply"), errors.New("exit status 1")
	}
	flags := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			flags[args[i]] = args[i+1]
		}
	}
	img, err := random.Image(1024, 2)
	if err != nil {
		return nil, err
	}
	target, err := name.ParseReference(flags["--repository"]+":"+flags["--overlaybd"], name.Insecure)
	if err != nil {
		return nil, err
	}
	return nil, remote.Write(target, img, remote.WithContext(ctx))
}

func setup(t *testing.T) (*server, *fakeConvertor, string) {
	t.Helper()
	registryServer := httptest.NewServer(registry.New())
	t.Cleanup(registryServer.Close)
	host := strings.TrimPrefix(registryServer.URL, "http://")
	source, err := random.Image(2048, 3)
	if err != nil {
		t.Fatal(err)
	}
	source, err = mutate.Config(source, v1.Config{Cmd: []string{"python3"}, WorkingDir: "/app", Env: []string{"PATH=/usr/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := name.ParseReference(host+"/library/python:3.12", name.Insecure)
	if err := remote.Write(reference, source); err != nil {
		t.Fatal(err)
	}
	fake := &fakeConvertor{}
	return newServer(host, "convertor", t.TempDir(), 64, 2, fake.run), fake, host
}

func TestEnsureConvertsOnceAndReuses(t *testing.T) {
	s, fake, host := setup(t)
	first, err := s.ensure(context.Background(), "python:3.12")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Converted || fake.calls.Load() != 1 {
		t.Fatalf("first ensure must convert once: converted=%t calls=%d", first.Converted, fake.calls.Load())
	}
	if first.Repository != host+"/library/python" || len(first.Lowers) != 2 || !strings.HasPrefix(first.OBDDigest, "sha256:") {
		t.Fatalf("unexpected answer: %+v", first)
	}
	if first.Config.WorkingDir != "/app" || first.Config.Cmd[0] != "python3" {
		t.Fatalf("image config not carried: %+v", first.Config)
	}
	second, err := s.ensure(context.Background(), "docker.io/library/python:3.12")
	if err != nil {
		t.Fatal(err)
	}
	if second.Converted || fake.calls.Load() != 1 || second.OBDDigest != first.OBDDigest {
		t.Fatalf("a converted image must be reused: %+v calls=%d", second, fake.calls.Load())
	}
	byDigest, err := s.ensure(context.Background(), "python@"+first.SourceDigest)
	if err != nil || byDigest.OBDDigest != first.OBDDigest {
		t.Fatalf("digest reference: %+v, %v", byDigest, err)
	}
}

func TestEnsureMergesConcurrentRequests(t *testing.T) {
	s, fake, _ := setup(t)
	fake.delay = 200 * time.Millisecond
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ensure(context.Background(), "python:3.12")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("concurrent requests must share one conversion, got %d", fake.calls.Load())
	}
}

func TestEnsureErrors(t *testing.T) {
	s, fake, _ := setup(t)
	var requestErr *requestError
	if _, err := s.ensure(context.Background(), "ghcr.io/org/app:1"); !errors.As(err, &requestErr) || requestErr.status != http.StatusBadRequest {
		t.Fatalf("a non-Docker Hub image must be a 400: %v", err)
	}
	if _, err := s.ensure(context.Background(), "python:missing"); !errors.As(err, &requestErr) || requestErr.status != http.StatusBadGateway {
		t.Fatalf("an unknown tag must be a 502: %v", err)
	}
	fake.fail.Store(true)
	_, err := s.ensure(context.Background(), "python:3.12")
	if err == nil || !strings.Contains(err.Error(), "failed to overlaybd-apply") {
		t.Fatalf("a convertor failure must surface its output: %v", err)
	}
	fake.fail.Store(false)
	if _, err := s.ensure(context.Background(), "python:3.12"); err != nil {
		t.Fatalf("a failed conversion is retried by the next request: %v", err)
	}
	if fake.calls.Load() != 2 {
		t.Fatalf("expected a retry, got %d convertor runs", fake.calls.Load())
	}
}

func TestHandleEnsure(t *testing.T) {
	s, _, _ := setup(t)
	handler := http.HandlerFunc(s.handleEnsure)
	post := func(body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/ensure", bytes.NewBufferString(body)))
		return recorder
	}
	ok := post(`{"image":"python:3.12"}`)
	var answer ensureResponse
	if ok.Code != http.StatusOK || json.Unmarshal(ok.Body.Bytes(), &answer) != nil || len(answer.Lowers) != 2 {
		t.Fatalf("ensure: %d %s", ok.Code, ok.Body)
	}
	if bad := post(`{}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d", bad.Code)
	}
	if foreign := post(`{"image":"quay.io/x/y:1"}`); foreign.Code != http.StatusBadRequest || !strings.Contains(foreign.Body.String(), "Docker Hub") {
		t.Fatalf("foreign registry: %d %s", foreign.Code, foreign.Body)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/ensure?"+url.Values{}.Encode(), nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", recorder.Code)
	}
}
