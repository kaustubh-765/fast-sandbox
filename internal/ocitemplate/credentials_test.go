package ocitemplate

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	registrytest "github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type credentialTransport func(*http.Request) (*http.Response, error)

func (f credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRepositoryCredentialsUseDockerHubEndpoint(t *testing.T) {
	for _, test := range []struct{ registry, endpoint string }{
		{"docker.io", "registry-1.docker.io"},
		{"registry-1.docker.io", "registry-1.docker.io"},
		{"registry.example", "registry.example"},
	} {
		t.Run(test.registry, func(t *testing.T) {
			ctx := context.Background()
			reference := test.registry + "/team/private:build"
			credential := auth.Credential{Username: "reader", Password: "secret"}
			calls := 0
			repo, ref, err := Repository(reference, func(_ context.Context, selected string) (auth.Credential, error) {
				require.Equal(t, reference, selected, "preserve the full repository scope")
				calls++
				return credential, nil
			})
			require.NoError(t, err)
			client := repo.Client.(*auth.Client)
			client.Client = &http.Client{Transport: credentialTransport(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, test.endpoint, r.URL.Host)
				require.Equal(t, "/v2/team/private/manifests/build", r.URL.Path)
				response := &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}
				user, password, ok := r.BasicAuth()
				if ok && user == credential.Username && password == credential.Password {
					response.StatusCode = http.StatusOK
					response.Header.Set("Content-Type", oci.MediaTypeImageManifest)
					response.Header.Set("Content-Length", "8")
					response.Header.Set("Docker-Content-Digest", digest.FromString("manifest").String())
				} else {
					response.Header.Set("WWW-Authenticate", `Basic realm="registry"`)
				}
				return response, nil
			})}
			_, err = repo.Resolve(ctx, ref.Reference)
			require.NoError(t, err)
			require.Equal(t, 1, calls)
			other, err := client.Credential(ctx, "other.example")
			require.NoError(t, err)
			require.Equal(t, auth.EmptyCredential, other)
			require.Equal(t, 1, calls, "do not resolve credentials for another host")
		})
	}
}

func TestInheritBlobUsesRepositoryScopedSourceCredentials(t *testing.T) {
	for _, crossHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-host", true: "cross-host"}[crossHost], func(t *testing.T) {
			var sourceReads atomic.Int32
			sourceHandler, destinationHandler := registrytest.New(), registrytest.New()
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("from") != "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				user, password, ok := r.BasicAuth()
				reader := strings.HasPrefix(r.URL.Path, "/v2/templates/")
				want := "writer"
				if reader {
					want = "reader"
				}
				if !ok || user != want || password != want+"-secret" {
					w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if reader {
					if r.Method == http.MethodGet {
						sourceReads.Add(1)
					}
					sourceHandler.ServeHTTP(w, r)
				} else {
					destinationHandler.ServeHTTP(w, r)
				}
			}
			server := httptest.NewTLSServer(http.HandlerFunc(handler))
			defer server.Close()
			sourceHost := strings.TrimPrefix(server.URL, "https://")
			destinationHost := sourceHost
			if crossHost {
				other := httptest.NewTLSServer(http.HandlerFunc(handler))
				defer other.Close()
				destinationHost = strings.TrimPrefix(other.URL, "https://")
			}
			old := retry.DefaultClient
			retry.DefaultClient = server.Client()
			defer func() { retry.DefaultClient = old }()
			credentials := func(_ context.Context, reference string) (auth.Credential, error) {
				ref, err := registry.ParseReference(reference)
				if err != nil {
					return auth.EmptyCredential, err
				}
				user := "writer"
				if ref.Registry == sourceHost && ref.Repository == "templates/base" {
					user = "reader"
				}
				return auth.Credential{Username: user, Password: user + "-secret"}, nil
			}
			ctx := context.Background()
			source, _, err := Repository(sourceHost+"/templates/base:rootfs", credentials)
			require.NoError(t, err)
			payload := []byte("inherited layer from private parent")
			desc := content.NewDescriptorFromBytes(oci.MediaTypeImageLayer, payload)
			require.NoError(t, source.Blobs().Push(ctx, desc, bytes.NewReader(payload)))
			destination, _, err := Repository(destinationHost+"/checkpoints/sandbox:pause", credentials)
			require.NoError(t, err)
			require.NoError(t, inheritBlob(ctx, destination, desc, sourceHost+"/templates/base", credentials))
			stream, err := destination.Blobs().Fetch(ctx, desc)
			require.NoError(t, err)
			defer stream.Close()
			got, err := io.ReadAll(stream)
			require.NoError(t, err)
			require.Equal(t, payload, got)
			require.Positive(t, sourceReads.Load(), "parent must be read using its own credential")
		})
	}
}
