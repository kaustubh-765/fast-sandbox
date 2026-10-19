package agent

import (
	"io"
	"os"
)

// sparseArtifactWriter preserves zero ranges while consuming the ordinary
// byte stream. Digests and logical sizes remain byte-for-byte unchanged, but
// empty private disks and sparse RAM snapshots do not fill the node cache.
type sparseArtifactWriter struct{ file *os.File }

func (w sparseArtifactWriter) Write(p []byte) (int, error) {
	zero := true
	for _, b := range p {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		if _, err := w.file.Seek(int64(len(p)), io.SeekCurrent); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return w.file.Write(p)
}
