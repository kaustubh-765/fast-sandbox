package artifacts

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// OCI image drive: a generic golden VM is built with one extra read-only
// virtio-blk placeholder drive. After a restore the Fastlet points that
// drive at an ext4 disk converted from a customer OCI image, and the guest
// agent runs the image as a container from it. The disk is immutable and
// content-addressed, so snapshots never carry it: they record which disk the
// guest had mounted (VMManifest.OCIDrive) and the restore re-attaches it.
const (
	// OCIDriveID is the Firecracker drive_id of the placeholder.
	OCIDriveID = "oci"
	// OCIDriveFileName is the drive path relative to the VMM working
	// directory (the jail root in jailer mode), next to rootfs.img.
	OCIDriveFileName = "oci.img"
	// OCIDrivePlaceholderBytes is the size of the placeholder backing file
	// the golden snapshot is taken with; a restore with a converted disk
	// changes the drive size, which is what the guest agent watches for.
	OCIDrivePlaceholderBytes = 1 << 20
	// OCIDriveImageLabel on a template source image asks the builder to
	// attach the placeholder drive.
	OCIDriveImageLabel      = "io.fastsandbox.extra-drives"
	OCIDriveImageLabelValue = "oci"
)

// OCIDrive identifies the converted image disk attached to a Sandbox.
type OCIDrive struct {
	// Image is the reference the Sandbox asked for.
	Image string `json:"image"`
	// Digest is the resolved linux/amd64 image manifest digest.
	Digest string `json:"digest"`
	// DiskKey addresses the converted disk in the node cache.
	DiskKey string `json:"diskKey"`
}

// Validate rejects an incomplete or path-unsafe record.
func (d OCIDrive) Validate() error {
	if strings.TrimSpace(d.Image) == "" {
		return fmt.Errorf("OCI drive image is required")
	}
	if !strings.HasPrefix(d.Digest, "sha256:") || !validHex(strings.TrimPrefix(d.Digest, "sha256:")) {
		return fmt.Errorf("OCI drive digest %q is not a sha256 digest", d.Digest)
	}
	if !validHex(d.DiskKey) {
		return fmt.Errorf("OCI drive disk key %q is not a sha256 hex key", d.DiskKey)
	}
	return nil
}

func validHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
