package agent

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSparseArtifactWriterPreservesZerosAndTrailingSize(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "artifact"))
	require.NoError(t, err)
	defer file.Close()
	writer := sparseArtifactWriter{file: file}
	var expected bytes.Buffer
	for _, chunk := range [][]byte{make([]byte, 256<<10), []byte("state"), make([]byte, 512<<10), []byte("tail"), make([]byte, 256<<10)} {
		n, err := writer.Write(chunk)
		require.NoError(t, err)
		require.Equal(t, len(chunk), n)
		expected.Write(chunk)
	}
	require.NoError(t, file.Truncate(int64(expected.Len())))
	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)
	data, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), data)
	info, err := file.Stat()
	require.NoError(t, err)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && runtime.GOOS == "linux" {
		require.Less(t, stat.Blocks*512, info.Size()/2)
	}
}
