package firecracker

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"fast-sandbox/internal/artifacts"
	fastletapi "fast-sandbox/internal/protocol/fastlet"
	runtimecontract "fast-sandbox/internal/runtime/contract"
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
	// ociResolveTTL bounds how long a tag-to-digest resolution is reused, so
	// warm creates skip the registry round trip without pinning a moving tag
	// forever.
	ociResolveTTL = 10 * time.Minute
	// ociConvertTimeout bounds one background conversion.
	ociConvertTimeout = 30 * time.Minute
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
	// recent remembers the drive each image reference last resolved to.
	recent map[string]ociResolved
	// deliveries tracks background conversions of parked creates.
	deliveries map[string]*ociDelivery
	now        func() time.Time
}

type ociResolved struct {
	drive artifacts.OCIDrive
	at    time.Time
}

// ociDelivery is one background conversion; err is written before done is
// closed.
type ociDelivery struct {
	done chan struct{}
	err  error
}

func newOCIDiskManager(stateRoot string) *ociDiskManager {
	return &ociDiskManager{
		stateRoot: stateRoot,
		mirror:    strings.TrimSpace(os.Getenv(ociDriveMirrorEnv)),
		runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		inflight:   map[string]*sync.Mutex{},
		recent:     map[string]ociResolved{},
		deliveries: map[string]*ociDelivery{},
		now:        time.Now,
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

// cached returns the disk of a recently resolved image that is present on
// this node, without contacting the registry.
func (m *ociDiskManager) cached(image string) (artifacts.OCIDrive, string, bool) {
	m.mu.Lock()
	resolved, ok := m.recent[image]
	m.mu.Unlock()
	if !ok || m.now().Sub(resolved.at) > ociResolveTTL {
		return artifacts.OCIDrive{}, "", false
	}
	path := m.diskPath(resolved.drive.DiskKey)
	if !fileExists(path) {
		return artifacts.OCIDrive{}, "", false
	}
	return resolved.drive, path, true
}

// ensure returns the cached disk of image, converting it on first use.
func (m *ociDiskManager) ensure(ctx context.Context, image string) (artifacts.OCIDrive, string, error) {
	if drive, path, ok := m.cached(image); ok {
		return drive, path, nil
	}
	img, drive, err := m.resolve(ctx, image)
	if err != nil {
		return artifacts.OCIDrive{}, "", err
	}
	path, err := m.convert(ctx, img, drive)
	if err != nil {
		return artifacts.OCIDrive{}, "", err
	}
	m.mu.Lock()
	m.recent[image] = ociResolved{drive: drive, at: m.now()}
	m.mu.Unlock()
	return drive, path, nil
}

// deliver reports whether the disk of image is ready, starting one
// background conversion per image otherwise. A finished attempt's error is
// reported once; the next call starts a fresh attempt.
func (m *ociDiskManager) deliver(image string) (runtimecontract.ImageDeliveryStatus, error) {
	if _, _, ok := m.cached(image); ok {
		return runtimecontract.ImageDelivered, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if delivery, ok := m.deliveries[image]; ok {
		select {
		case <-delivery.done:
			delete(m.deliveries, image)
			if delivery.err != nil {
				return "", delivery.err
			}
			return runtimecontract.ImageDelivered, nil
		default:
			return runtimecontract.ImageDelivering, nil
		}
	}
	delivery := &ociDelivery{done: make(chan struct{})}
	m.deliveries[image] = delivery
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), ociConvertTimeout)
		defer cancel()
		_, _, delivery.err = m.ensure(ctx, image)
		if delivery.err != nil {
			klog.ErrorS(delivery.err, "OCI drive conversion failed", "image", image)
		}
		close(delivery.done)
	}()
	return runtimecontract.ImageDelivering, nil
}

// DeliverSandbox implements runtimecontract.SandboxDelivery: the golden image
// is delivered like any template, then an OCI image drive requested in the
// spec env converts in the background, so the create parks instead of
// running past its deadline.
func (d *Driver) DeliverSandbox(ctx context.Context, spec fastletapi.SandboxSpec) (runtimecontract.ImageDeliveryStatus, error) {
	status, err := d.DeliverImage(ctx, spec.Image)
	if err != nil || status != runtimecontract.ImageDelivered || d.ociDisks == nil {
		return status, err
	}
	image := strings.TrimSpace(spec.Env[OCIDriveImageEnv])
	if image == "" {
		return status, nil
	}
	return d.ociDisks.deliver(image)
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

// convert flattens the image into a directory, adds the image config under
// /.fsb-oci, renders the tree into a sparse ext4 disk with mkfs.ext4 -d (no
// loop mount), verifies it, and commits it read-only.
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

	tree := filepath.Join(work, "rootfs")
	contentBytes, err := extractImage(img, tree)
	if err != nil {
		return "", fmt.Errorf("unpack OCI image %s: %w", drive.Image, err)
	}
	if err := writeGuestMetadata(img, drive, tree); err != nil {
		return "", err
	}
	disk := filepath.Join(work, ociDiskName)
	if output, err := m.runner(ctx, "mkfs.ext4", "-F", "-q", "-L", "fsb-oci", "-d", tree,
		disk, fmt.Sprintf("%dk", ociDiskSizeKiB(contentBytes))); err != nil {
		return "", fmt.Errorf("mkfs.ext4: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := m.fsck(ctx, disk); err != nil {
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
	klog.InfoS("converted OCI image into a drive disk", "image", drive.Image, "digest", drive.Digest,
		"diskKey", drive.DiskKey, "contentMiB", contentBytes>>20)
	return final, nil
}

// fsck verifies the fresh filesystem read-only.
func (m *ociDiskManager) fsck(ctx context.Context, disk string) error {
	if output, err := m.runner(ctx, "e2fsck", "-fn", disk); err != nil {
		return fmt.Errorf("e2fsck: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// extractImage writes the flattened image filesystem under root with its
// ownership, modes, and device nodes, and returns the regular file bytes.
// Every path is resolved inside root (symlinks included), so a hostile
// image cannot write outside it.
func extractImage(img v1.Image, root string) (int64, error) { //nolint:gocognit // one switch over tar entry types
	if err := os.MkdirAll(root, 0o755); err != nil {
		return 0, err
	}
	stream := mutate.Extract(img)
	defer stream.Close()
	reader := tar.NewReader(stream)
	type dirMode struct {
		path string
		mode os.FileMode
	}
	var dirs []dirMode
	total := int64(0)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		target, err := securejoin.SecureJoin(root, header.Name)
		if err != nil {
			return 0, err
		}
		if target == root {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, err
		}
		mode := header.FileInfo().Mode()
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return 0, err
			}
			dirs = append(dirs, dirMode{path: target, mode: mode})
		case tar.TypeReg:
			_ = os.RemoveAll(target)
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return 0, err
			}
			written, copyErr := io.Copy(file, reader) //nolint:gosec // image size is bounded by the registry blob
			closeErr := file.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return 0, err
			}
			total += written
		case tar.TypeSymlink:
			_ = os.RemoveAll(target)
			if err := os.Symlink(header.Linkname, target); err != nil {
				return 0, err
			}
		case tar.TypeLink:
			source, err := securejoin.SecureJoin(root, header.Linkname)
			if err != nil {
				return 0, err
			}
			_ = os.RemoveAll(target)
			if err := os.Link(source, target); err != nil {
				return 0, err
			}
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			_ = os.RemoveAll(target)
			kind := uint32(unix.S_IFIFO)
			switch header.Typeflag {
			case tar.TypeChar:
				kind = unix.S_IFCHR
			case tar.TypeBlock:
				kind = unix.S_IFBLK
			}
			device := int(unix.Mkdev(uint32(header.Devmajor), uint32(header.Devminor))) //nolint:gosec // tar device numbers fit
			if err := unix.Mknod(target, kind|uint32(mode.Perm()), device); err != nil {
				return 0, err
			}
		default:
			continue
		}
		if err := os.Lchown(target, header.Uid, header.Gid); err != nil {
			return 0, err
		}
		if header.Typeflag != tar.TypeSymlink && header.Typeflag != tar.TypeDir {
			if err := os.Chmod(target, mode&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)); err != nil {
				return 0, err
			}
		}
	}
	// Directory modes last: a read-only directory must not block its
	// children from being written.
	for index := len(dirs) - 1; index >= 0; index-- {
		mode := dirs[index].mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		if err := os.Chmod(dirs[index].path, mode); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// writeGuestMetadata stores the raw image config and the drive record at
// /.fsb-oci in the tree, where the guest agent reads entrypoint, env and
// working directory.
func writeGuestMetadata(img v1.Image, drive artifacts.OCIDrive, tree string) error {
	config, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("read image config: %w", err)
	}
	record, err := json.Marshal(drive)
	if err != nil {
		return err
	}
	dir := filepath.Join(tree, ociGuestMetaDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "image-config.json"), config, 0o644); err != nil { //nolint:gosec // image config is public metadata
		return err
	}
	return os.WriteFile(filepath.Join(dir, ociDiskMetaName), record, 0o644) //nolint:gosec // non-secret drive record
}

// ociDiskSizeKiB sizes the sparse disk from the unpacked content: ext4
// metadata and small-file slack need headroom, and the guest mounts the disk
// read-only, so unused space costs nothing.
func ociDiskSizeKiB(contentBytes int64) int64 {
	return (contentBytes+contentBytes/2)/1024 + 256*1024
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
