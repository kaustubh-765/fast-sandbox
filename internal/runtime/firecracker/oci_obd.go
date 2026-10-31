package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"fast-sandbox/internal/artifacts"
	runtimecatalog "fast-sandbox/internal/catalog/runtime"
)

// OverlayBD OCI image drives. Instead of converting every image into an ext4
// disk on every node, oci-convertd converts each image once per cluster into
// per-layer OverlayBD blobs in the registry, and the node's overlaybd-ublkd
// daemon serves them as a read-only /dev/ublkbN that fetches blocks on first
// read. Each Sandbox gets its own device, bind-mounted where the converted
// disk would be hard-linked; the device is released with the Sandbox.
const (
	// ociDriveFormatEnv selects the format of fresh OCI drives: "overlaybd",
	// or empty for the ext4 conversion on the node. A drive recorded by a
	// snapshot keeps its own format regardless.
	ociDriveFormatEnv = "FAST_SANDBOX_OCI_DRIVE_FORMAT"
	// ociConvertdURLEnv is the base URL of the oci-convertd service.
	ociConvertdURLEnv = "FAST_SANDBOX_OCI_CONVERTD_URL"
	// ociOBDDeviceDir holds <id>/{config.v1.json,device.json} per attached
	// device, node-wide under StateRoot (the ublkd daemon reads the config).
	ociOBDDeviceDir  = "oci-obd/devices"
	ociOBDConfigName = "config.v1.json"
	ociOBDDeviceName = "device.json"
	// ociOBDSweepAge is how long a device record without a Sandbox state
	// directory survives before the sweep releases it; it covers the window
	// between attach and the Sandbox's first state save.
	ociOBDSweepAge = 10 * time.Minute
	// ociOBDCloseWait bounds how long release waits for the VMM to close the
	// device before asking ublkd to delete it anyway. Deleting an open device
	// makes ublkd (kernels without UBLK_CMD_DEL_DEV_ASYNC) fall back to a
	// bounded synchronous delete, which was seen to crash the daemon.
	ociOBDCloseWait = 10 * time.Second
	ociOBDClosePoll = 50 * time.Millisecond
	// ociOBDControlLock serializes ublkd add/del node-wide (all Fastlets on
	// a node share StateRoot). ublkd handles control requests concurrently,
	// and an add racing the bounded synchronous delete of the device number
	// it is about to reuse crashes the daemon (kernels without
	// UBLK_CMD_DEL_DEV_ASYNC).
	ociOBDControlLock = "oci-obd/ublkd-control.lock"
	// ociOBDGoneWait bounds how long a delete waits, still holding the
	// control lock, for the kernel to remove the block device.
	ociOBDGoneWait = 5 * time.Second
)

// obdConfig is the overlaybd device config (config.v1.json): read-only, so
// lowers only.
type obdConfig struct {
	RepoBlobURL string                    `json:"repoBlobUrl"`
	Lowers      []artifacts.OCIDriveLayer `json:"lowers"`
	ResultFile  string                    `json:"resultFile"`
}

type obdDevice struct {
	DevID int    `json:"devId"`
	Dev   string `json:"dev"`
}

// obdManager resolves OverlayBD drives through oci-convertd and attaches and
// releases their devices through the node ublkd.
type obdManager struct {
	stateRoot   string
	convertdURL string
	convertd    *http.Client
	ublkd       *http.Client
	// procRoot is scanned for processes still holding a device open.
	procRoot string
}

func newOBDManager(stateRoot string) *obdManager {
	return newOBDManagerAt(stateRoot, filepath.Join(runtimecatalog.OCISocketDir, "ublkd.sock"),
		strings.TrimRight(strings.TrimSpace(os.Getenv(ociConvertdURLEnv)), "/"))
}

func newOBDManagerAt(stateRoot, socket, convertdURL string) *obdManager {
	return &obdManager{
		stateRoot:   stateRoot,
		convertdURL: convertdURL,
		procRoot:    "/proc",
		convertd:    &http.Client{Timeout: ociConvertTimeout},
		ublkd: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			}},
		},
	}
}

// ociOBDPreferred reports whether fresh drives use the OverlayBD format.
func ociOBDPreferred() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(ociDriveFormatEnv)), artifacts.OCIDriveFormatOverlayBD)
}

// convertdResponse is oci-convertd's POST /v1/ensure answer.
type convertdResponse struct {
	SourceDigest string                    `json:"sourceDigest"`
	Repository   string                    `json:"repository"`
	OBDDigest    string                    `json:"obdDigest"`
	Lowers       []artifacts.OCIDriveLayer `json:"lowers"`
	Config       artifacts.OCIImageConfig  `json:"config"`
	Error        string                    `json:"error"`
}

// ensure returns the OverlayBD drive of image, converting it cluster-wide on
// first use (oci-convertd blocks until the conversion is pushed).
func (m *obdManager) ensure(ctx context.Context, image string) (artifacts.OCIDrive, error) {
	if m.convertdURL == "" {
		return artifacts.OCIDrive{}, fmt.Errorf("%s is not set", ociConvertdURLEnv)
	}
	body, err := json.Marshal(map[string]string{"image": image})
	if err != nil {
		return artifacts.OCIDrive{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.convertdURL+"/v1/ensure", bytes.NewReader(body))
	if err != nil {
		return artifacts.OCIDrive{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.convertd.Do(request)
	if err != nil {
		return artifacts.OCIDrive{}, fmt.Errorf("oci-convertd: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return artifacts.OCIDrive{}, err
	}
	var answer convertdResponse
	if err := json.Unmarshal(payload, &answer); err != nil {
		return artifacts.OCIDrive{}, fmt.Errorf("oci-convertd: %s: %s", response.Status, bytes.TrimSpace(payload))
	}
	if response.StatusCode != http.StatusOK {
		return artifacts.OCIDrive{}, fmt.Errorf("oci-convertd: %s: %s", response.Status, answer.Error)
	}
	config := answer.Config
	drive := artifacts.OCIDrive{
		Image:      image,
		Digest:     answer.SourceDigest,
		DiskKey:    strings.TrimPrefix(answer.OBDDigest, "sha256:"),
		Format:     artifacts.OCIDriveFormatOverlayBD,
		Repository: answer.Repository,
		Lowers:     answer.Lowers,
		Config:     &config,
	}
	if err := drive.Validate(); err != nil {
		return artifacts.OCIDrive{}, fmt.Errorf("oci-convertd returned an invalid drive: %w", err)
	}
	return drive, nil
}

func (m *obdManager) deviceDir(id string) string {
	return filepath.Join(m.stateRoot, ociOBDDeviceDir, id)
}

// attach creates the read-only device of drive for Sandbox id and returns
// its /dev path. A leftover device of an earlier attempt is released first.
func (m *obdManager) attach(ctx context.Context, id string, drive artifacts.OCIDrive) (string, error) {
	if err := validateSandboxID(id); err != nil {
		return "", err
	}
	if err := drive.Validate(); err != nil || drive.Format != artifacts.OCIDriveFormatOverlayBD {
		return "", fmt.Errorf("%w: not an OverlayBD OCI drive: %v", ErrInvalidConfig, err)
	}
	if err := m.release(ctx, id); err != nil {
		return "", err
	}
	dir := m.deviceDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	host, repository, _ := strings.Cut(drive.Repository, "/")
	config, err := json.Marshal(obdConfig{
		RepoBlobURL: "http://" + host + "/v2/" + repository + "/blobs",
		Lowers:      drive.Lowers,
		ResultFile:  filepath.Join(dir, "result"),
	})
	if err != nil {
		return "", err
	}
	configPath := filepath.Join(dir, ociOBDConfigName)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return "", err
	}
	var added struct {
		OK    bool   `json:"ok"`
		DevID int    `json:"dev_id"`
		Dev   string `json:"dev"`
		Error string `json:"error"`
	}
	unlock, err := m.lockControl()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	err = m.call(ctx, http.MethodPost, "/v1/add", map[string]string{"config": configPath}, &added)
	unlock()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("attach OverlayBD drive %s: %w", drive.Image, err)
	}
	if !added.OK || !strings.HasPrefix(added.Dev, "/dev/ublkb") {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("attach OverlayBD drive %s: ublkd: %s", drive.Image, added.Error)
	}
	record, err := json.Marshal(obdDevice{DevID: added.DevID, Dev: added.Dev})
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, ociOBDDeviceName), record, 0o600)
	}
	if err != nil {
		_ = m.del(context.Background(), added.DevID, added.Dev)
		_ = os.RemoveAll(dir)
		return "", err
	}
	return added.Dev, nil
}

// release deletes the device of Sandbox id, if any. The VMM must be gone and
// the jail bind unmounted.
func (m *obdManager) release(ctx context.Context, id string) error {
	if err := validateSandboxID(id); err != nil {
		return err
	}
	dir := m.deviceDir(id)
	raw, err := os.ReadFile(filepath.Join(dir, ociOBDDeviceName))
	if errors.Is(err, os.ErrNotExist) {
		return os.RemoveAll(dir)
	}
	if err != nil {
		return err
	}
	var device obdDevice
	if err := json.Unmarshal(raw, &device); err != nil {
		klog.InfoS("dropping unreadable OverlayBD device record", "sandboxID", id, "err", err)
		return os.RemoveAll(dir)
	}
	m.waitClosed(ctx, id, device.Dev)
	if err := m.del(ctx, device.DevID, device.Dev); err != nil {
		return fmt.Errorf("release OverlayBD drive of sandbox %s: %w", id, err)
	}
	return os.RemoveAll(dir)
}

// waitClosed waits until no process holds dev open, up to ociOBDCloseWait.
func (m *obdManager) waitClosed(ctx context.Context, id, dev string) {
	started := time.Now()
	deadline := started.Add(ociOBDCloseWait)
	for {
		holders := deviceOpenBy(m.procRoot, dev)
		if len(holders) == 0 {
			if waited := time.Since(started); waited > ociOBDClosePoll {
				klog.InfoS("OverlayBD device closed before release", "sandboxID", id, "dev", dev, "waited", waited)
			}
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			klog.InfoS("OverlayBD device still open at release; deleting anyway", "sandboxID", id, "dev", dev, "holders", holders)
			return
		}
		time.Sleep(ociOBDClosePoll)
	}
}

// lockControl takes the node-wide ublkd control lock.
func (m *obdManager) lockControl() (func(), error) {
	path := filepath.Join(m.stateRoot, ociOBDControlLock)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock ublkd control: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}

// del removes a ublkd device; one the daemon no longer knows is gone. It
// holds the control lock until the kernel has removed dev, so no add can
// reuse the device number while the delete is still in progress.
func (m *obdManager) del(ctx context.Context, devID int, dev string) error {
	unlock, err := m.lockControl()
	if err != nil {
		return err
	}
	defer unlock()
	var answer struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	err = m.call(ctx, http.MethodPost, "/v1/del", map[string]int{"dev_id": devID}, &answer)
	if err == nil && answer.OK {
		waitDeviceGone(dev, ociOBDGoneWait)
	}
	var status *ublkdStatusError
	if errors.As(err, &status) && status.code == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if !answer.OK {
		return fmt.Errorf("ublkd: %s", answer.Error)
	}
	return nil
}

// waitDeviceGone waits until the kernel no longer lists dev's block device.
func waitDeviceGone(dev string, timeout time.Duration) {
	if !strings.HasPrefix(dev, "/dev/ublkb") {
		return
	}
	sys := filepath.Join("/sys/block", filepath.Base(dev))
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(sys); errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			klog.InfoS("ublk block device still present after delete", "dev", dev, "waited", timeout)
			return
		}
		time.Sleep(ociOBDClosePoll)
	}
}

// sweep releases devices whose Sandbox no longer has a state directory on
// this node (a Fastlet that crashed or was deleted before releasing them).
// Device records are node-wide, so any Fastlet's sweep covers the node.
func (m *obdManager) sweep(ctx context.Context, now time.Time) []string {
	entries, err := os.ReadDir(filepath.Join(m.stateRoot, ociOBDDeviceDir))
	if err != nil {
		return nil
	}
	var released []string
	for _, entry := range entries {
		id := entry.Name()
		if !entry.IsDir() || validateSandboxID(id) != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(m.stateRoot, sandboxStateDir, id)); err == nil {
			continue
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < ociOBDSweepAge {
			continue
		}
		if err := m.release(ctx, id); err != nil {
			klog.InfoS("OverlayBD device sweep could not release a device", "sandboxID", id, "err", err)
			continue
		}
		released = append(released, id)
	}
	return released
}

type ublkdStatusError struct {
	code int
	body string
}

func (e *ublkdStatusError) Error() string { return fmt.Sprintf("ublkd: HTTP %d: %s", e.code, e.body) }

func (m *obdManager) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		payload, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://ublkd"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.ublkd.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return &ublkdStatusError{code: response.StatusCode, body: string(bytes.TrimSpace(payload))}
	}
	return json.Unmarshal(payload, output)
}

// placeOBDDrive provides artifacts.OCIDriveFileName in the VMM working
// directory as a bind mount of the Sandbox's OverlayBD device.
func (m *obdManager) placeOBDDrive(ctx context.Context, dir, id string, drive artifacts.OCIDrive) error {
	device, err := m.attach(ctx, id, drive)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, artifacts.OCIDriveFileName)
	_ = unmountPath(target)
	_ = os.Remove(target)
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err == nil {
		err = file.Close()
	}
	if err == nil {
		err = bindMount(device, target)
	}
	if err != nil {
		_ = os.Remove(target)
		return errors.Join(fmt.Errorf("place OverlayBD drive: %w", err), m.release(context.Background(), id))
	}
	return nil
}

// placeOCIDriveFor provides the image drive of a create: the Sandbox's
// OverlayBD device, or the converted disk / placeholder (placeOCIDrive).
func (d *Driver) placeOCIDriveFor(ctx context.Context, dir, id string, drive *artifacts.OCIDrive, disk string) error {
	if drive == nil || drive.Format != artifacts.OCIDriveFormatOverlayBD {
		return placeOCIDrive(dir, disk)
	}
	if d.ociDisks == nil || d.ociDisks.obd == nil {
		return fmt.Errorf("%w: OverlayBD OCI drive requires OCI drives to be enabled", ErrInvalidConfig)
	}
	return d.ociDisks.obd.placeOBDDrive(ctx, dir, id, *drive)
}

// releaseOCIDriveDevice releases the Sandbox's OverlayBD device. It is part
// of releaseOCI, which every teardown path (delete, pause, failed create)
// reaches after the VMM is gone; the jail bind is unmounted first in case
// the jail root still exists.
func (d *Driver) releaseOCIDriveDevice(ctx context.Context, id string) error {
	if d.ociDisks == nil || d.ociDisks.obd == nil || validateSandboxID(id) != nil {
		return nil
	}
	if d.config.JailerPath != "" {
		root := jailerRoot(filepath.Join(d.config.StateRoot, jailerChrootBaseDir), filepath.Base(d.config.BinaryPath), truncatedSandboxID(id))
		_ = unmountPath(filepath.Join(root, artifacts.OCIDriveFileName))
	} else if directory, err := sandboxDir(d.config.StateRoot, id); err == nil {
		_ = unmountPath(filepath.Join(directory, artifacts.OCIDriveFileName))
	}
	return d.ociDisks.obd.release(ctx, id)
}
