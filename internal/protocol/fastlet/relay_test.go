package fastlet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateHandlerRelay(t *testing.T) {
	valid := []struct{ method, path string }{
		{"", "/vault/s-a"},
		{"", "/vault/s-a?x=1"},
		{"POST", "/vault/s-a"},
		{"PUT", "/vault/s-a"},
		{"GET", "/vault/s-a"},
		{"DELETE", "/vault/s-a"},
		{"PATCH", "/x/y/z"},
		{"HEAD", "/health"},
		{"OPTIONS", "/"},
	}
	for _, request := range valid {
		require.NoError(t, ValidateHandlerRelay(request.method, request.path), "%s %s", request.method, request.path)
	}

	invalid := []struct{ method, path, message string }{
		{"TRACE", "/vault/s-a", "method"},
		{"CONNECT", "/vault/s-a", "method"},
		{"get", "/vault/s-a", "method"},
		{"POST", "", "path is required"},
		{"POST", "vault/s-a", "must start with '/'"},
		{"POST", "http://127.0.0.1:18080/vault/s-a", "must start with '/'"},
		{"POST", "/vault/s-a x", "printable ASCII"},
		{"POST", "/vault/\x7f", "printable ASCII"},
		{"POST", strings.Repeat("/a", 2048), "exceeds"},
		{"POST", "/vault/s-a/../vault/s-b", "dot segments"},
		// Percent-encodings decode in the handler's router: %2F can
		// reassemble the reserved prefix, %2e%2e can smuggle dot segments.
		{"POST", "//_fastlet%2Fv1%2Factions", "percent-encodings"},
		{"GET", "/vault/%2e%2e/v1/actions/status", "percent-encodings"},
		{"POST", "/vault/s-a%3Fx=1", "percent-encodings"},
		// The handler's own privileged Action management surface shares the
		// TargetHTTPPort and is fenced by attachment identity — the tenant
		// relay must never address it, including via dot-segment traversal.
		{"POST", "/_fastlet/v1/actions", "reserved"},
		{"GET", "/_fastlet/v1/actions/status", "reserved"},
		{"PUT", "/_fastlet/", "reserved"},
		{"POST", "/_fastlet/v1/actions/../vault/s-a", "reserved|dot"},
		{"POST", "/vault/../_fastlet/v1/actions", "dot segments"},
		{"GET", "/vault/../../_fastlet/v1/actions/status", "dot segments"},
	}
	for _, request := range invalid {
		err := ValidateHandlerRelay(request.method, request.path)
		require.Error(t, err, "%s %q", request.method, request.path)
		if request.message == "reserved|dot" {
			require.True(t, strings.Contains(err.Error(), "reserved") || strings.Contains(err.Error(), "dot segments"), "%q", err.Error())
			continue
		}
		require.ErrorContains(t, err, request.message)
	}
}
