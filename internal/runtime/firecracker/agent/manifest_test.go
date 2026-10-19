package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseManifest(t *testing.T) {
	payload := testManifest(map[string][]byte{
		"rootfs.ext4":  []byte("rootfs"),
		"vmstate.snap": []byte("vmstate"),
		"memory.snap":  []byte("memory"),
	})
	document, err := parseManifest(payload)
	require.NoError(t, err)
	require.Len(t, document.Files, 3)
	require.Equal(t, sha256Hex([]byte("rootfs")), document.Files["rootfs.ext4"].SHA256)
	require.Equal(t, int64(6), document.Files["rootfs.ext4"].SizeBytes)
}

func TestParseManifestInvalidJSON(t *testing.T) {
	_, err := parseManifest([]byte("{nope"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode manifest")
}

func TestParseManifestEmptyFiles(t *testing.T) {
	payload, err := json.Marshal(map[string]any{"files": map[string]any{}})
	require.NoError(t, err)
	_, err = parseManifest(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no files")
}

func TestNativeFiles(t *testing.T) {
	artifacts := map[string][]byte{
		"rootfs.ext4":  []byte("rootfs"),
		"vmstate.snap": []byte("vmstate"),
		"memory.snap":  []byte("memory"),
	}
	payload := testManifest(artifacts)
	document, err := parseManifest(payload)
	require.NoError(t, err)

	files, err := document.nativeFiles()
	require.NoError(t, err)
	require.Len(t, files, 3)
	// The mapping renames rootfs.ext4 to rootfs.img and keeps the rest;
	// every entry carries the expected digest.
	want := map[string]string{"rootfs.img": "rootfs.ext4", "vmstate.snap": "vmstate.snap", "memory.snap": "memory.snap"}
	for _, file := range files {
		publishName, ok := want[file.cache]
		require.True(t, ok, file.cache)
		require.Equal(t, publishName, file.publish)
		require.Equal(t, sha256Hex(artifacts[publishName]), file.sha256)
	}
}

func TestNativeFilesMissingArtifact(t *testing.T) {
	payload := testManifest(map[string][]byte{
		"rootfs.ext4": []byte("rootfs"),
		"memory.snap": []byte("memory"),
	})
	document, err := parseManifest(payload)
	require.NoError(t, err)
	_, err = document.nativeFiles()
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing the vmstate.snap artifact")
}

func TestNativeFilesInvalidDigest(t *testing.T) {
	payload := testManifest(map[string][]byte{
		"rootfs.ext4":  []byte("rootfs"),
		"vmstate.snap": []byte("vmstate"),
		"memory.snap":  []byte("memory"),
	})
	var document map[string]any
	require.NoError(t, json.Unmarshal(payload, &document))
	files := document["files"].(map[string]any)
	files["rootfs.ext4"].(map[string]any)["sha256"] = strings.Repeat("Z", 64)
	tampered, err := json.Marshal(document)
	require.NoError(t, err)

	parsed, err := parseManifest(tampered)
	require.NoError(t, err)
	_, err = parsed.nativeFiles()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid sha256")
}

func TestValidSHA256(t *testing.T) {
	require.True(t, validSHA256(strings.Repeat("a", 64)))
	require.False(t, validSHA256(strings.Repeat("a", 63)))
	require.False(t, validSHA256(strings.Repeat("A", 64)))
	require.False(t, validSHA256(strings.Repeat("g", 64)))
	require.False(t, validSHA256(""))
}

func TestSharedBaseIsRequiredAndVerified(t *testing.T) {
	payload := testManifest(map[string][]byte{"rootfs.ext4": []byte("upper"), "vmstate.snap": []byte("state"), "memory.snap": []byte("memory")})
	var doc map[string]any
	require.NoError(t, json.Unmarshal(payload, &doc))
	sum := strings.Repeat("a", 64)
	doc["sharedRootfs"] = map[string]any{"layout": "pmem-dax-v1", "sha256": sum, "sizeBytes": 2 << 20}
	encode := func() []byte { p, e := json.Marshal(doc); require.NoError(t, e); return p }
	_, err := parseManifest(encode())
	require.Error(t, err)
	doc["files"].(map[string]any)["base.ext4"] = map[string]any{"sha256": sum, "sizeBytes": 2 << 20}
	parsed, err := parseManifest(encode())
	require.NoError(t, err)
	files, err := parsed.nativeFiles()
	require.NoError(t, err)
	require.Len(t, files, 4)
	doc["files"].(map[string]any)["base.ext4"].(map[string]any)["sha256"] = strings.Repeat("b", 64)
	_, err = parseManifest(encode())
	require.Error(t, err)
}
