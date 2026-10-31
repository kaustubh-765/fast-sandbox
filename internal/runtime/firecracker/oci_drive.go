package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"k8s.io/klog/v2"

	"fast-sandbox/internal/artifacts"
	fastletapi "fast-sandbox/internal/protocol/fastlet"
)

// OCI image drive (artifacts.OCIDriveID). A Pool opts in with
// FAST_SANDBOX_OCI_DRIVE=true; its golden template carries a read-only
// placeholder drive. A create whose spec env names an image
// (OCIDriveImageEnv) gets that image converted once per node into an
// immutable ext4 disk, hard-linked next to the instance rootfs, and patched
// into the restored VM. Snapshots record the attached disk in the manifest
// (VMManifest.OCIDrive), so a resume or a create from a snapshot re-attaches
// the same disk without carrying it in the artifact set.
const (
	ociDriveEnv = "FAST_SANDBOX_OCI_DRIVE"
	// ociDriveMirrorEnv names a plain-HTTP Docker Hub pull-through cache
	// (host:port) used for docker.io references.
	ociDriveMirrorEnv = "FAST_SANDBOX_OCI_DOCKERHUB_MIRROR"
	// OCIDriveImageEnv is the Sandbox env key that carries the image to run.
	OCIDriveImageEnv = "FSB_OCI_IMAGE"

	ociDiskCacheDir = "oci-disks"
	ociDiskName     = "disk.img"
	ociDiskMetaName = "drive.json"
	// ociDiskFormatVersion is part of the disk key: a converter change must
	// never reuse disks produced by an older layout.
	ociDiskFormatVersion = "oci-drive/v1"
	// ociGuestMetaDir holds the image config and drive record inside the
	// converted disk, next to the image rootfs.
	ociGuestMetaDir = ".fsb-oci"
	oci2rootfsBin   = "oci2rootfs"
)

var ociDrivePlatform = v1.Platform{OS: "linux", Architecture: "amd64"}

// ociDriveEnabled reports whether this Fastlet manages the OCI drive.
func ociDriveEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ociDriveEnv))) {
	case "true", "1":
		return true
	default:
		return false
	}
}

// ociDiskManager converts OCI images into cached, immutable ext4 disks under
// <StateRoot>/oci-disks/<key>/disk.img. Conversions are single-flight per
// disk key; distinct images convert in parallel.
type ociDiskManager struct {
	stateRoot string
	mirror    string
	runner    func(ctx context.Context, name string, args ...string) ([]byte, error)

	mu       sync.Mutex
	inflight map[string]*sync.Mutex
}

func newOCIDiskManager(stateRoot string) *ociDiskManager {
	return &ociDiskManager{
		stateRoot: stateRoot,
		mirror:    strings.TrimSpace(os.Getenv(ociDriveMirrorEnv)),
		runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		inflight: map[string]*sync.Mutex{},
	}
}

// ociDiskKey addresses the converted disk of one image manifest digest.
func ociDiskKey(digest string) string {
	sum := sha256.Sum256([]byte(ociDiskFormatVersion + "\n" + digest))
	return hex.EncodeToString(sum[:])
}

func (m *ociDiskManager) diskPath(key string) string {
	return filepath.Join(m.stateRoot, ociDiskCacheDir, key, ociDiskName)
}

// pullReference rewrites a Docker Hub reference to the mirror, which is
// reached over plain HTTP; other registries pass through unchanged.
func (m *ociDiskManager) pullReference(image string) (name.Reference, error) {
	reference, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("%w: parse OCI image %q: %w", ErrInvalidConfig, image, err)
	}
	if m.mirror == "" || reference.Context().RegistryStr() != name.DefaultRegistry {
		return reference, nil
	}
	mirrored := m.mirror + "/" + reference.Context().RepositoryStr()
	if tag, ok := reference.(name.Tag); ok {
		mirrored += ":" + tag.TagStr()
	} else {
		mirrored += "@" + reference.Identifier()
	}
	return name.ParseReference(mirrored, name.Insecure)
}

// resolve fetches the linux/amd64 image of a reference.
func (m *ociDiskManager) resolve(ctx context.Context, image string) (v1.Image, artifacts.OCIDrive, error) {
	reference, err := m.pullReference(image)
	if err != nil {
		return nil, artifacts.OCIDrive{}, err
	}
	descriptor, err := remote.Get(reference, remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(ociDrivePlatform))
	if err != nil {
		return nil, artifacts.OCIDrive{}, fmt.Errorf("resolve OCI image %q: %w", image, err)
	}
	img, err := descriptor.Image()
	if err != nil {
		return nil, artifacts.OCIDrive{}, fmt.Errorf("resolve OCI image %q: %w", image, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, artifacts.OCIDrive{}, err
	}
	drive := artifacts.OCIDrive{Image: image, Digest: digest.String(), DiskKey: ociDiskKey(digest.String())}
	return img, drive, nil
}

// ensure returns the cached disk of image, converting it on first use.
func (m *ociDiskManager) ensure(ctx context.Context, image string) (artifacts.OCIDrive, string, error) {
	img, drive, err := m.resolve(ctx, image)
	if err != nil {
		return artifacts.OCIDrive{}, "", err
	}
	path, err := m.convert(ctx, img, drive)
	return drive, path, err
}

// attach returns the disk recorded by a snapshot. A disk missing from this
// node is converted again from the recorded digest.
func (m *ociDiskManager) attach(ctx context.Context, drive artifacts.OCIDrive) (string, error) {
	if err := drive.Validate(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if path := m.diskPath(drive.DiskKey); fileExists(path) {
		return path, nil
	}
	repository, err := name.ParseReference(drive.Image)
	if err != nil {
		return "", fmt.Errorf("%w: parse OCI image %q: %w", ErrInvalidConfig, drive.Image, err)
	}
	pinned := repository.Context().Digest(drive.Digest).String()
	img, resolved, err := m.resolve(ctx, pinned)
	if err != nil {
		return "", err
	}
	if resolved.DiskKey != drive.DiskKey {
		return "", fmt.Errorf("%w: OCI drive %s resolved to disk key %s, snapshot recorded %s", ErrInvalidConfig, pinned, resolved.DiskKey, drive.DiskKey)
	}
	klog.InfoS("re-converting OCI drive disk missing on this node; restored guest relies on a byte-identical conversion",
		"image", drive.Image, "digest", drive.Digest)
	return m.convert(ctx, img, drive)
}

func (m *ociDiskManager) lock(key string) func() {
	m.mu.Lock()
	keyLock, ok := m.inflight[key]
	if !ok {
		keyLock = &sync.Mutex{}
		m.inflight[key] = keyLock
	}
	m.mu.Unlock()
	keyLock.Lock()
	return keyLock.Unlock
}

// convert writes the image as an OCI layout, renders it to ext4 with
// oci2rootfs (the template builder's converter), adds the image config under
// /.fsb-oci, verifies the filesystem, and commits it read-only.
func (m *ociDiskManager) convert(ctx context.Context, img v1.Image, drive artifacts.OCIDrive) (string, error) {
	unlock := m.lock(drive.DiskKey)
	defer unlock()
	final := m.diskPath(drive.DiskKey)
	if fileExists(final) {
		return final, nil
	}
	root := filepath.Join(m.stateRoot, ociDiskCacheDir)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(root, ".convert-"+drive.DiskKey[:12]+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	layoutDir := filepath.Join(work, "layout")
	index, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		return "", fmt.Errorf("write OCI layout: %w", err)
	}
	if err := index.AppendImage(img, layout.WithPlatform(ociDrivePlatform)); err != nil {
		return "", fmt.Errorf("download OCI image %s: %w", drive.Image, err)
	}
	sizeGB, err := ociDiskSizeGB(img)
	if err != nil {
		return "", err
	}
	disk := filepath.Join(work, ociDiskName)
	if output, err := m.runner(ctx, oci2rootfsBin, layoutDir, "--output", disk,
		"--size", fmt.Sprintf("%dG", sizeGB), "--platform", "linux/amd64"); err != nil {
		return "", fmt.Errorf("oci2rootfs: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := m.fsck(ctx, disk, "-fy"); err != nil {
		return "", err
	}
	if err := m.writeGuestMetadata(ctx, img, drive, disk, work); err != nil {
		return "", err
	}
	if err := m.fsck(ctx, disk, "-fn"); err != nil {
		return "", err
	}
	if err := os.Chmod(disk, 0o444); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
		return "", err
	}
	meta, err := json.Marshal(drive)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(final), ociDiskMetaName), meta, 0o644); err != nil { //nolint:gosec // non-secret cache metadata
		return "", err
	}
	if err := os.Rename(disk, final); err != nil {
		return "", err
	}
	klog.InfoS("converted OCI image into a drive disk", "image", drive.Image, "digest", drive.Digest, "diskKey", drive.DiskKey, "sizeGB", sizeGB)
	return final, nil
}

// fsck runs e2fsck; with -fy exit status 1 means errors were corrected.
func (m *ociDiskManager) fsck(ctx context.Context, disk, mode string) error {
	output, err := m.runner(ctx, "e2fsck", mode, disk)
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if mode == "-fy" && errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	return fmt.Errorf("e2fsck %s: %w: %s", mode, err, strings.TrimSpace(string(output)))
}

// writeGuestMetadata stores the raw image config and the drive record at
// /.fsb-oci in the disk, where the guest agent reads entrypoint, env and
// working directory.
func (m *ociDiskManager) writeGuestMetadata(ctx context.Context, img v1.Image, drive artifacts.OCIDrive, disk, work string) error {
	config, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("read image config: %w", err)
	}
	record, err := json.Marshal(drive)
	if err != nil {
		return err
	}
	if err := ensureLoopDevices(); err != nil {
		return err
	}
	mountpoint := filepath.Join(work, "mnt")
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	if output, err := m.runner(ctx, "mount", "-o", "loop", disk, mountpoint); err != nil {
		return fmt.Errorf("mount OCI drive disk: %w: %s", err, strings.TrimSpace(string(output)))
	}
	writeErr := func() error {
		dir := filepath.Join(mountpoint, ociGuestMetaDir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "image-config.json"), config, 0o644); err != nil { //nolint:gosec // image config is public metadata
			return err
		}
		return os.WriteFile(filepath.Join(dir, ociDiskMetaName), record, 0o644) //nolint:gosec // non-secret drive record
	}()
	if output, err := m.runner(context.Background(), "umount", mountpoint); err != nil {
		return errors.Join(writeErr, fmt.Errorf("umount OCI drive disk: %w: %s", err, strings.TrimSpace(string(output))))
	}
	return writeErr
}

// ociDiskSizeGB sizes the sparse ext4 disk generously from the compressed
// layer sizes (an image unpacks to a few times its compressed size).
func ociDiskSizeGB(img v1.Image) (int64, error) {
	layers, err := img.Layers()
	if err != nil {
		return 0, err
	}
	compressed := int64(0)
	for _, layer := range layers {
		size, err := layer.Size()
		if err != nil {
			return 0, err
		}
		compressed += size
	}
	return ceilGB(compressed*4 + 512*1000*1000), nil
}

// ceilGB rounds a byte count up to whole SI gigabytes (oci2rootfs --size),
// never below one.
func ceilGB(bytes int64) int64 {
	const gb = 1000 * 1000 * 1000
	if bytes <= gb {
		return 1
	}
	return (bytes + gb - 1) / gb
}

// placeOCIDrive provides artifacts.OCIDriveFileName in the VMM working
// directory: the converted disk (hard-linked; it is immutable) or the
// placeholder the golden snapshot was taken with.
func placeOCIDrive(dir, disk string) error {
	target := filepath.Join(dir, artifacts.OCIDriveFileName)
	_ = os.Remove(target)
	if disk != "" {
		return linkOrCopy(disk, target)
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return fmt.Errorf("create OCI placeholder drive: %w", err)
	}
	defer file.Close()
	return file.Truncate(artifacts.OCIDrivePlaceholderBytes)
}

// resolveOCIDrive selects the disk of a create: the drive recorded by the
// restore set's manifest (resume, create from snapshot) wins over the image
// requested in the spec env (fresh create). fresh reports whether the drive
// must be patched into the restored VM. A nil drive means the placeholder.
func (d *Driver) resolveOCIDrive(ctx context.Context, stateRoot, restoreRef string, spec fastletapi.SandboxSpec) (drive *artifacts.OCIDrive, disk string, fresh bool, err error) {
	if d.ociDisks == nil {
		return nil, "", false, nil
	}
	if raw, readErr := os.ReadFile(cachedManifestPath(stateRoot, restoreRef)); readErr == nil {
		manifest, decodeErr := artifacts.DecodeVMManifest(raw)
		if decodeErr != nil {
			return nil, "", false, decodeErr
		}
		if manifest.OCIDrive != nil {
			path, attachErr := d.ociDisks.attach(ctx, *manifest.OCIDrive)
			if attachErr != nil {
				return nil, "", false, attachErr
			}
			recorded := *manifest.OCIDrive
			return &recorded, path, false, nil
		}
	}
	image := strings.TrimSpace(spec.Env[OCIDriveImageEnv])
	if image == "" {
		return nil, "", false, nil
	}
	resolved, path, err := d.ociDisks.ensure(ctx, image)
	if err != nil {
		return nil, "", false, err
	}
	return &resolved, path, true, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
