package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The build VM must attach the entropy device before it boots: without it the
// guest CRNG may never initialize, execd blocks in getrandom() and never
// serves its port, and the build times out waiting for SANDBOX_READY
// (OpenSandbox #1695). Each failing call stops the sequence before the boot.
func TestConfigureBuildVMAttachesEntropyBeforeBoot(t *testing.T) {
	options := &buildOptions{rootfsDriveID: "rootfs", vcpu: 1, memoryMB: 512, tapName: "fsbbuild0", guestMAC: "02:00:00:00:00:01", guestControlPort: 1234}
	want := []string{"/boot-source", "/drives/rootfs", "/machine-config", "/entropy", "/network-interfaces/eth0", "/vsock", "/actions"}
	for _, fail := range append([]string{""}, want...) {
		t.Run("failure="+fail, func(t *testing.T) {
			var calls []string
			client := &firecrackerClient{httpClient: &http.Client{Transport: rootfsRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.URL.Path)
				code := http.StatusNoContent
				if r.URL.Path == fail {
					code = http.StatusInternalServerError
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
			})}}
			err := configureBuildVM(t.Context(), client, options, "/kernel", "console=ttyS0")
			expected := want
			if fail != "" {
				require.Error(t, err)
				for i, path := range want {
					if path == fail {
						expected = want[:i+1]
						break
					}
				}
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, expected, calls)
		})
	}
}

// Optional devices stay optional: without a TAP or guest control, the
// sequence still attaches entropy and boots.
func TestConfigureBuildVMWithoutOptionalDevices(t *testing.T) {
	var calls []string
	client := &firecrackerClient{httpClient: &http.Client{Transport: rootfsRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}}
	err := configureBuildVM(t.Context(), client, &buildOptions{rootfsDriveID: "rootfs", vcpu: 1, memoryMB: 512}, "/kernel", "console=ttyS0")
	require.NoError(t, err)
	require.Equal(t, []string{"/boot-source", "/drives/rootfs", "/machine-config", "/entropy", "/actions"}, calls)
}
