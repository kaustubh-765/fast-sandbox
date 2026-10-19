package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	"fast-sandbox/internal/artifacts"
)

func TestSharedRootfsDefaultAndManifest(t *testing.T) {
	require.True(t, sharedRootfsEnabled(apiv1alpha2.SandboxTemplateSpec{}))
	spec, kernel, rootfs, vmstate, memory := buildManifestFixture(t)
	require.False(t, sharedRootfsEnabled(spec))
	spec.Output.SharedRootfs = nil
	_, err := buildManifest(spec, "source", kernel, rootfs, vmstate, memory, nil, nil, 1, "", nil)
	require.ErrorContains(t, err, "DAX base required")
	base := filepath.Join(filepath.Dir(rootfs), artifacts.SharedRootfsName)
	require.NoError(t, os.WriteFile(base, make([]byte, 2<<20), 0o444))
	doc, err := buildManifest(spec, "source", kernel, rootfs, vmstate, memory, nil, nil, 1, "", nil)
	require.NoError(t, err)
	payload, err := artifacts.MarshalManifest(doc)
	require.NoError(t, err)
	parsed, err := artifacts.DecodeSharedRootfs(payload)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.NoError(t, writeChecksums(filepath.Dir(rootfs), nil))
	sums, err := os.ReadFile(filepath.Join(filepath.Dir(rootfs), "SHA256SUMS"))
	require.NoError(t, err)
	require.Contains(t, string(sums), artifacts.SharedRootfsName)
}

func TestInitramfsNewcEntryAlignment(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, writeInitramfsEntry(&output, 1, "init", 0100755, []byte("abc")))
	data := output.Bytes()
	require.Equal(t, "070701", string(data[:6]))
	size, err := strconv.ParseUint(string(data[54:62]), 16, 32)
	require.NoError(t, err)
	require.EqualValues(t, 3, size)
	namesize, err := strconv.ParseUint(string(data[94:102]), 16, 32)
	require.NoError(t, err)
	require.EqualValues(t, 5, namesize)
	require.Equal(t, "init\x00", string(data[110:115]))
	require.Equal(t, "abc", string(data[116:119]))
	require.Len(t, data, 120)
}
