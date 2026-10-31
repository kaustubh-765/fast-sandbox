package artifacts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
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

// OCI launch drive: a fixed-size, read-only second drive next to the image
// drive. On a fresh create the Fastlet fills it with the Sandbox's launch
// parameters (entrypoint, env, working directory, user); the guest agent reads
// it with O_DIRECT when the image drive appears. Its size never changes, so a
// restore (resume, create from snapshot) just provides a zero placeholder of
// the same size: the container is already running and the guest never
// re-reads it.
const (
	OCILaunchDriveID    = "launch"
	OCILaunchFileName   = "launch.img"
	OCILaunchDriveBytes = 64 << 10
	// ociLaunchMagic starts an encoded launch drive; a zero placeholder has
	// none, which the guest reads as "image defaults".
	ociLaunchMagic = "FSBL1\n"
)

// OCILaunch overrides the image config for one Sandbox. Empty fields keep the
// image defaults.
type OCILaunch struct {
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"workingDir,omitempty"`
	User       string            `json:"user,omitempty"`
}

// Empty reports whether the launch keeps every image default.
func (l OCILaunch) Empty() bool {
	return len(l.Entrypoint) == 0 && len(l.Env) == 0 && l.WorkingDir == "" && l.User == ""
}

// EncodeOCILaunch renders the drive content: magic, the decimal payload
// length, a newline, the JSON payload, zero padding to OCILaunchDriveBytes.
func EncodeOCILaunch(launch OCILaunch) ([]byte, error) {
	drive := make([]byte, OCILaunchDriveBytes)
	if launch.Empty() {
		return drive, nil
	}
	payload, err := json.Marshal(launch)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf("%s%d\n", ociLaunchMagic, len(payload))
	if len(header)+len(payload) > OCILaunchDriveBytes {
		return nil, fmt.Errorf("OCI launch parameters are %d bytes; the limit is %d", len(payload), OCILaunchDriveBytes-len(header))
	}
	copy(drive, header)
	copy(drive[len(header):], payload)
	return drive, nil
}

// DecodeOCILaunch parses drive content written by EncodeOCILaunch; a zero
// placeholder decodes to an empty launch.
func DecodeOCILaunch(drive []byte) (OCILaunch, error) {
	var launch OCILaunch
	if !bytes.HasPrefix(drive, []byte(ociLaunchMagic)) {
		return launch, nil
	}
	rest := drive[len(ociLaunchMagic):]
	newline := bytes.IndexByte(rest, '\n')
	if newline < 0 {
		return launch, fmt.Errorf("OCI launch drive has no length line")
	}
	length, err := strconv.Atoi(string(rest[:newline]))
	if err != nil || length < 0 || newline+1+length > len(rest) {
		return launch, fmt.Errorf("OCI launch drive has an invalid length")
	}
	err = json.Unmarshal(rest[newline+1:newline+1+length], &launch)
	return launch, err
}
