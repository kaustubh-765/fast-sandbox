package agent

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMultipartStreamsRetriesAndAborts(t *testing.T) {
	for _, mode := range []string{"success", "retry-part", "missing-etag", "embedded-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			const uploadID = "upload+/ &id"
			var parts []string
			var completed []completedPart
			attempts, aborts := 0, 0
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if !strings.Contains(r.Header.Get("Authorization"), "Credential=writer/") {
					t.Error("multipart request must use the write credential")
				}
				query := r.URL.Query()
				if r.Method == http.MethodPost && query.Has("uploads") {
					_, _ = io.WriteString(w, "<InitiateMultipartUploadResult><UploadId>upload+/ &amp;id</UploadId></InitiateMultipartUploadResult>")
					return
				}
				if query.Get("uploadId") != uploadID {
					t.Error("upload ID did not round-trip through the signed query")
				}
				switch r.Method {
				case http.MethodPut:
					body, _ := io.ReadAll(r.Body)
					attempts++
					if mode == "cancel" {
						cancel()
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					if mode == "retry-part" && attempts == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					parts = append(parts, string(body))
					if mode != "missing-etag" {
						w.Header().Set("ETag", `"etag&<>"`)
					}
				case http.MethodPost:
					var document struct {
						Parts []completedPart `xml:"Part"`
					}
					if err := xml.NewDecoder(r.Body).Decode(&document); err != nil {
						t.Error(err)
					}
					completed = document.Parts
					if mode == "embedded-error" {
						_, _ = io.WriteString(w, " \n<Error><Code>InternalError</Code><Message>assembly failed</Message></Error>")
					} else {
						_, _ = io.WriteString(w, "<CompleteMultipartUploadResult><ETag>object</ETag></CompleteMultipartUploadResult>")
					}
				case http.MethodDelete:
					aborts++
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			client, err := newS3Client("s3://bucket", writeCredential(), nil, "", server.URL)
			require.NoError(t, err)
			client.retryDelay = time.Millisecond
			path := filepath.Join(t.TempDir(), "artifact")
			require.NoError(t, os.WriteFile(path, []byte("abcdefghijk"), 0o600))
			err = client.putMultipart(ctx, server.URL+"/bucket/artifact", 11, 4, func() (io.ReadCloser, error) { return os.Open(path) })
			mu.Lock()
			defer mu.Unlock()
			if mode == "success" || mode == "retry-part" {
				require.NoError(t, err)
				require.Zero(t, aborts)
				require.Equal(t, []string{"abcd", "efgh", "ijk"}, parts)
				require.Equal(t, []completedPart{{1, `"etag&<>"`}, {2, `"etag&<>"`}, {3, `"etag&<>"`}}, completed)
				if mode == "retry-part" {
					require.Equal(t, 4, attempts)
				}
			} else {
				require.Error(t, err)
				require.Equal(t, 1, aborts, "failed/cancelled uploads must be aborted before returning")
			}
		})
	}
}

func TestPutAboveSingleObjectLimitUsesBoundedMultipart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-sparse-artifact")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(singlePutLimit+1))
	require.NoError(t, f.Close())
	parts := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		payload := "<CompleteMultipartUploadResult/>"
		if r.URL.Query().Has("uploads") {
			payload = "<InitiateMultipartUploadResult><UploadId>large</UploadId></InitiateMultipartUploadResult>"
		}
		if r.Method == http.MethodPut {
			parts++
			require.LessOrEqual(t, r.ContentLength, int64(64<<20))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {`"part"`}}, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	client, err := newS3Client("s3://bucket", writeCredential(), &http.Client{Transport: transport}, "", "http://store.test")
	require.NoError(t, err)
	require.NoError(t, client.put(context.Background(), "large", singlePutLimit+1, func() (io.ReadCloser, error) { return os.Open(path) }))
	require.Equal(t, 81, parts)
}
