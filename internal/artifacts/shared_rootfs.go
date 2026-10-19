package artifacts

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SharedRootfsName is both the published member and the relative pmem path
// embedded in vmstate. Changing it requires rebuilding the golden snapshot.
const SharedRootfsName = "base.ext4"
const SharedRootfsLayout = "pmem-dax-v1"
const BlockRootfsLayout = "block-root-v1"
const RootfsLayoutAnnotation = "sandbox.fast.io/rootfs-layout"

// SharedRootfs binds immutable device bytes to a snapshot. Private writes
// always go to rootfs.ext4, which is an OverlayFS upper disk in this layout.
type SharedRootfs struct {
	Layout    string `json:"layout"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

// DecodeSharedRootfs rejects incomplete or unknown device layouts. An absent
// block is the legacy block-root topology, never an instruction to retrofit it.
func DecodeSharedRootfs(payload []byte) (*SharedRootfs, error) {
	var doc struct {
		SharedRootfs *SharedRootfs `json:"sharedRootfs"`
		Files        map[string]struct {
			SHA256    string `json:"sha256"`
			SizeBytes int64  `json:"sizeBytes"`
		} `json:"files"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	base := doc.SharedRootfs
	_, listed := doc.Files[SharedRootfsName]
	if base == nil {
		if listed {
			return nil, fmt.Errorf("base.ext4 requires sharedRootfs device metadata")
		}
		return nil, nil //nolint:nilnil // absent dependency explicitly selects the legacy device layout
	}
	sum, err := hex.DecodeString(base.SHA256)
	if base.Layout != SharedRootfsLayout || err != nil || len(sum) != 32 || hex.EncodeToString(sum) != base.SHA256 || base.SizeBytes <= 0 || base.SizeBytes%(2<<20) != 0 {
		return nil, fmt.Errorf("invalid sharedRootfs device metadata")
	}
	entry := doc.Files[SharedRootfsName]
	if !listed || entry.SHA256 != base.SHA256 || entry.SizeBytes != base.SizeBytes {
		return nil, fmt.Errorf("sharedRootfs does not match base.ext4 file entry")
	}
	return base, nil
}

// SharedRootfsCacheDir holds node-wide immutable files keyed by byte digest.
// Artifact-set and instance paths are hard links, so removing a set never
// invalidates a running VM. A later checkpoint pull reuses the same inode.
const SharedRootfsCacheDir = "shared-rootfs"
