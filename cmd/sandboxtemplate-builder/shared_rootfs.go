package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	"fast-sandbox/internal/artifacts"
)

func sharedRootfsEnabled(spec apiv1alpha2.SandboxTemplateSpec) bool {
	return spec.Output.SharedRootfs == nil || *spec.Output.SharedRootfs
}

// prepareSharedRootfs seals the converted image as pmem and replaces the
// writable root drive with an empty upper filesystem of the requested capacity.
func prepareSharedRootfs(spec apiv1alpha2.SandboxTemplateSpec, workdir, rootfs string) error {
	if !sharedRootfsEnabled(spec) {
		if spec.Output.WritableSize != "" {
			return fmt.Errorf("writableSize requires sharedRootfs")
		}
		return nil
	}
	if spec.Output.WritableSize != "" {
		q, err := resource.ParseQuantity(spec.Output.WritableSize)
		if err != nil || q.Sign() <= 0 {
			return fmt.Errorf("invalid writableSize %q", spec.Output.WritableSize)
		}
	}
	base := filepath.Join(workdir, artifacts.SharedRootfsName)
	if err := os.Rename(rootfs, base); err != nil {
		return err
	}
	// resize2fs requires a writable forced fsck after runtime injection;
	// the conversion stage's read-only verification does not update it.
	if out, err := exec.Command("e2fsck", "-fy", base).CombinedOutput(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return fmt.Errorf("check DAX base: %w: %s", err, out)
		}
	}
	if out, err := exec.Command("resize2fs", "-M", base).CombinedOutput(); err != nil {
		return fmt.Errorf("compact DAX base: %w: %s", err, out)
	}
	info, err := os.Stat(base)
	if err != nil {
		return err
	}
	aligned := (info.Size() + (2 << 20) - 1) / (2 << 20) * (2 << 20)
	if err := os.Truncate(base, aligned); err != nil {
		return err
	}
	if err := os.Chmod(base, 0o444); err != nil {
		return err
	}
	quantity := spec.Output.WritableSize
	if quantity == "" {
		quantity = spec.Output.RootfsSize
	}
	size, err := sizeGiB(quantity)
	if err != nil {
		return err
	}
	disk, err := os.Create(rootfs)
	if err != nil {
		return err
	}
	err = disk.Truncate(int64(size) * 1000000000)
	closeErr := disk.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", rootfs).CombinedOutput(); err != nil {
		return fmt.Errorf("format private upper: %w: %s", err, out)
	}
	return buildDAXInitramfs(workdir, guestInitPath(spec))
}

// buildDAXInitramfs uses only the builder's static busybox. It is a boot-time
// artifact: live snapshots carry the initialized mounts in RAM, not the initrd.
func buildDAXInitramfs(workdir, initPath string) error {
	var busybox []byte
	for _, path := range hostBusyboxCandidates {
		if payload, err := os.ReadFile(path); err == nil {
			busybox = payload
			break
		}
	}
	if len(busybox) == 0 {
		return fmt.Errorf("static busybox is required for DAX boot")
	}
	output, err := os.Create(filepath.Join(workdir, "dax-initramfs.cpio"))
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	entries := []struct {
		name string
		mode uint32
		data []byte
	}{
		{"bin", 0040755, nil}, {"proc", 0040755, nil}, {"sys", 0040755, nil}, {"dev", 0040755, nil},
		{"bin/busybox", 0100755, busybox}, {"init", 0100755, []byte(strings.ReplaceAll(daxInit, "@INIT@", shellQuote(initPath)))},
		{"TRAILER!!!", 0, nil},
	}
	for index, entry := range entries {
		if err := writeInitramfsEntry(output, uint32(index+1), entry.name, entry.mode, entry.data); err != nil {
			return err
		}
	}
	return output.Close()
}

const daxInit = `#!/bin/busybox sh
set -eu
trap 'echo SANDBOX_STARTUP_FAILED dax_rootfs_setup' EXIT
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t sysfs sysfs /sys
$bb mount -t devtmpfs devtmpfs /dev
$bb mkdir -p /lower /rw /newroot
$bb mount -t ext4 -o ro,dax=always /dev/pmem0 /lower
$bb mount -t ext4 /dev/vda /rw
$bb mkdir -p /rw/upper /rw/work
$bb mount -t overlay overlay -o lowerdir=/lower,upperdir=/rw/upper,workdir=/rw/work /newroot
$bb mkdir -p /newroot/.sandbox-base /newroot/.sandbox-upper /newroot/proc /newroot/sys /newroot/dev
$bb mount --move /lower /newroot/.sandbox-base
$bb mount --move /rw /newroot/.sandbox-upper
$bb mount --move /proc /newroot/proc
$bb mount --move /sys /newroot/sys
$bb mount --move /dev /newroot/dev
exec $bb switch_root /newroot @INIT@
`

// writeInitramfsEntry writes the kernel's uncompressed newc format. Boot needs
// just one static executable and no host cpio utility or shell pipeline.
func writeInitramfsEntry(out io.Writer, ino uint32, name string, mode uint32, data []byte) error {
	if _, err := fmt.Fprintf(out, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0); err != nil {
		return err
	}
	if _, err := io.WriteString(out, name+"\x00"); err != nil {
		return err
	}
	if _, err := out.Write(make([]byte, (4-(110+len(name)+1)%4)%4)); err != nil {
		return err
	}
	if _, err := out.Write(data); err != nil {
		return err
	}
	_, err := out.Write(make([]byte, (4-len(data)%4)%4))
	return err
}
