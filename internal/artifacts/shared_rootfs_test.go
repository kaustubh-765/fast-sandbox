package artifacts

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeSharedRootfsRejectsBrokenDependencies(t *testing.T) {
	base := SharedRootfs{Layout: SharedRootfsLayout, SHA256: strings.Repeat("a", 64), SizeBytes: 2 << 20}
	doc := map[string]any{"sharedRootfs": base, "files": map[string]any{SharedRootfsName: map[string]any{"sha256": base.SHA256, "sizeBytes": base.SizeBytes}}}
	encode := func() []byte { p, err := json.Marshal(doc); require.NoError(t, err); return p }
	parsed, err := DecodeSharedRootfs(encode())
	require.NoError(t, err)
	require.Equal(t, base, *parsed)
	for _, change := range []func(){
		func() { base.Layout = "future-layout" }, func() { base.SHA256 = strings.Repeat("A", 64) }, func() { base.SizeBytes++ },
	} {
		saved := base
		change()
		doc["sharedRootfs"] = base
		_, err := DecodeSharedRootfs(encode())
		require.Error(t, err)
		base = saved
		doc["sharedRootfs"] = base
	}
	delete(doc, "sharedRootfs")
	_, err = DecodeSharedRootfs(encode())
	require.Error(t, err)
	delete(doc, "files")
	parsed, err = DecodeSharedRootfs(encode())
	require.NoError(t, err)
	require.Nil(t, parsed)
}
