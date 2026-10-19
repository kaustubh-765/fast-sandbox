package artifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSha256FileSparse verifies the sparse-aware hasher produces the same
// digest as a plain full read on a file with holes (regression: the SEEK_DATA
// path previously hashed from the wrong offset).
func TestSha256FileSparse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sparse.bin")
	handle, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payload := []byte("hello-sparse-world-0123456789")
	for _, offset := range []int64{0, 4 << 20, 16 << 20, 40 << 20, 63 << 20} {
		if _, err := handle.Seek(offset, 0); err != nil {
			t.Fatalf("seek: %v", err)
		}
		if _, err := handle.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := handle.Truncate(64 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reference: hash the file as a plain byte stream (holes read as zeros).
	handle, err = os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	reference := sha256.New()
	if _, err := io.Copy(reference, handle); err != nil {
		t.Fatalf("reference hash: %v", err)
	}
	_ = handle.Close()
	want := hex.EncodeToString(reference.Sum(nil))

	got, err := SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	if got != want {
		t.Fatalf("sparse hash mismatch: got %s want %s", got, want)
	}
}

func TestSHA256FileConcurrentInputs(t *testing.T) {
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		data := bytes.Repeat([]byte{byte(i + 1)}, 2<<20)
		path := filepath.Join(t.TempDir(), "data")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		want := SHA256Of(data)
		workers.Add(1)
		go func() {
			defer workers.Done()
			got, err := SHA256File(path)
			if err == nil && got != want {
				err = fmt.Errorf("concurrent digest mismatch")
			}
			failures <- err
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
}
