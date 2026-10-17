package action

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	actionapi "fast-sandbox/internal/protocol/action"
)

func (f *fakeCaller) snapshotRelay() []recordedRelay {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRelay(nil), f.relayCalls...)
}

func TestRelayHandlerResolvesDeclaredPortAndPassesThrough(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", relayStatus: http.StatusConflict, relayBody: []byte(`{"error":"exists"}`)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)

	status, body, err := manager.RelayHandler(context.Background(), "uid-a", "egress", http.MethodPut, "/vault/uid-a", []byte(`{"revision":1}`))
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, status, "the handler's status is the result, not an error")
	require.Equal(t, []byte(`{"error":"exists"}`), body)

	calls := caller.snapshotRelay()
	require.Len(t, calls, 1)
	require.Equal(t, int32(18080), calls[0].port)
	require.Equal(t, "uid-a", calls[0].sandboxUID)
	require.Equal(t, http.MethodPut, calls[0].method)
	require.Equal(t, "/vault/uid-a", calls[0].path)
	require.Equal(t, []byte(`{"revision":1}`), calls[0].body)
}

func TestRelayHandlerRejectsUnknownHandler(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1"}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	_, _, err := manager.RelayHandler(context.Background(), "uid-a", "vault", http.MethodPost, "/vault/uid-a", nil)
	require.ErrorIs(t, err, ErrUnknownHandler)
	require.Empty(t, caller.snapshotRelay())
}

func TestHTTPCallerRelayDefaultsMethodToPost(t *testing.T) {
	var seenMethod, seenSandboxUID string
	handlerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenSandboxUID = r.Header.Get(actionapi.HeaderSandboxUID)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(handlerServer.Close)
	status, _, err := NewHTTPCaller().Relay(context.Background(),
		int32(handlerServer.Listener.Addr().(*net.TCPAddr).Port), "uid-a", "", "/vault/uid-a", []byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, http.MethodPost, seenMethod)
	require.Equal(t, "uid-a", seenSandboxUID)
}

func TestHTTPCallerRelayIsVerbatimOverRealHTTP(t *testing.T) {
	var seenMethod, seenURI, seenContentType, seenSandboxUID string
	var seenBody []byte
	handlerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod, seenURI, seenContentType = r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type")
		seenSandboxUID = r.Header.Get(actionapi.HeaderSandboxUID)
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Handler", "yes")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"exists"}`))
	}))
	t.Cleanup(handlerServer.Close)
	port := int32(handlerServer.Listener.Addr().(*net.TCPAddr).Port)

	status, body, err := NewHTTPCaller().Relay(context.Background(), port, "uid-a", http.MethodPut, "/vault/uid-a?x=1", []byte(`{"revision":1}`))
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, []byte(`{"error":"exists"}`), body)
	require.Equal(t, http.MethodPut, seenMethod)
	require.Equal(t, "/vault/uid-a?x=1", seenURI)
	require.Equal(t, "application/json", seenContentType)
	require.Equal(t, "uid-a", seenSandboxUID)
	require.Equal(t, []byte(`{"revision":1}`), seenBody)
}

func TestHTTPCallerRelaySurfacesTransportFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := int32(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())

	_, _, err = NewHTTPCaller().Relay(context.Background(), port, "", http.MethodGet, "/vault/s-a", nil)
	require.Error(t, err, "an unreachable Handler is a relay failure, not a handler outcome")
}

func TestHTTPCallerRelayBoundsResponsesAndRedirects(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/vault/moved")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	status, body, err := NewHTTPCaller().Relay(context.Background(),
		int32(redirect.Listener.Addr().(*net.TCPAddr).Port), "uid-a", http.MethodGet, "/vault/s-a", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, status, "redirects are surfaced verbatim, never followed")
	require.Empty(t, body)

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxResponseSize+1))
	}))
	t.Cleanup(oversized.Close)
	_, _, err = NewHTTPCaller().Relay(context.Background(),
		int32(oversized.Listener.Addr().(*net.TCPAddr).Port), "uid-a", http.MethodGet, "/vault/s-a", nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "32 KiB")
}

func TestHTTPCallerRelaySurfacesContextCancellation(t *testing.T) {
	release := make(chan struct{})
	held := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(held.Close)
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	var relayErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, relayErr = NewHTTPCaller().Relay(ctx, int32(held.Listener.Addr().(*net.TCPAddr).Port), "uid-a", http.MethodGet, "/vault/s-a", nil)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not honor context cancellation")
	}
	require.ErrorIs(t, relayErr, context.Canceled)
}
