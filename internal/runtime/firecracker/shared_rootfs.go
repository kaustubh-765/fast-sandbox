package firecracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"k8s.io/apimachinery/pkg/api/resource"

	"fast-sandbox/internal/artifacts"
	runtimecatalog "fast-sandbox/internal/catalog/runtime"
)

func cachedSharedRootfs(stateRoot, image string) (*artifacts.SharedRootfs, string, error) {
	path := cachedManifestPath(stateRoot, image)
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	base, err := artifacts.DecodeSharedRootfs(payload)
	return base, filepath.Join(filepath.Dir(path), artifacts.SharedRootfsName), err
}

// stageSharedRootfs takes a hard link, never a reflink or full copy: pmem
// mappings must reference the same inode to share physical file pages. A jail
// owns its link independently of cache eviction and is removed after VMM exit.
func stageSharedRootfs(stateRoot, image, targetDir string) error {
	base, source, err := cachedSharedRootfs(stateRoot, image)
	if err != nil || base == nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("DAX base unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != base.SizeBytes {
		return fmt.Errorf("DAX base size/type mismatch")
	}
	canonical := filepath.Join(stateRoot, artifacts.SharedRootfsCacheDir, base.SHA256)
	if shared, statErr := os.Stat(canonical); statErr == nil && os.SameFile(info, shared) {
		if err := artifacts.VerifyImmutableFile(canonical, base.SHA256, base.SizeBytes); err != nil {
			return err
		}
	} else {
		// Legacy hand-seeded local caches have no node-generated receipt.
		sum, err := artifacts.SHA256File(source)
		if err != nil {
			return err
		}
		if sum != base.SHA256 {
			return fmt.Errorf("DAX base digest mismatch")
		}
	}

	target := filepath.Join(targetDir, artifacts.SharedRootfsName)
	if err := os.Link(source, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			linked, statErr := os.Stat(target)
			if statErr == nil && os.SameFile(info, linked) {
				return nil
			}
		}
		return fmt.Errorf("hard-link DAX base (cache and jail must share a filesystem): %w", err)
	}
	return nil
}

// stageSnapshotBase makes checkpoints self-contained. The source is immutable;
// its contents are independent of the upper-disk snapshot's pause window.
func stageSnapshotBase(document map[string]any, source, staging string) error {
	payload, err := json.Marshal(document)
	if err != nil {
		return err
	}
	base, err := artifacts.DecodeSharedRootfs(payload)
	if err != nil || base == nil {
		return err
	}
	path := filepath.Join(source, artifacts.SharedRootfsName)
	sum, err := artifacts.SHA256File(path)
	if err != nil {
		return err
	}
	if sum != base.SHA256 {
		return fmt.Errorf("snapshot DAX base digest mismatch")
	}
	return linkOrCopy(path, filepath.Join(staging, artifacts.SharedRootfsName))
}

// validateSharedRootfsBudget refuses a layout which the pool's per-slot
// reservation cannot cover. Legacy snapshots keep their existing behavior.
func validateSharedRootfsBudget(config runtimecatalog.FirecrackerConfig, stateRoot, image string) error {
	base, _, err := cachedSharedRootfs(stateRoot, image)
	if err != nil || base == nil {
		return err
	}
	budget, err := config.SharedRootfsBudget()
	if err != nil {
		return err
	}
	if base.SizeBytes > budget {
		return fmt.Errorf("%w: DAX base requires %d bytes, runtime sharedRootfsMemory is %d", ErrInvalidConfig, base.SizeBytes, budget)
	}
	return nil
}

// validateSharedRootfsAllocation catches mixed-version upgrades and hand-written
// Fastlet Pods whose limits omit the new reservation. The controller's downward
// API limit and slot count are required for a shared-rootfs restore.
func (d *Driver) validateSharedRootfsAllocation(stateRoot, image, memory string) error {
	base, _, err := cachedSharedRootfs(stateRoot, image)
	if err != nil || base == nil {
		return err
	}
	limit, err := resource.ParseQuantity(os.Getenv("MEMORY_LIMIT"))
	if err != nil || limit.Sign() <= 0 {
		return fmt.Errorf("%w: DAX requires MEMORY_LIMIT from the runtime owner downward API", ErrInvalidConfig)
	}
	capacity, err := strconv.ParseInt(os.Getenv("FASTLET_CAPACITY"), 10, 32)
	if err != nil || capacity <= 0 {
		return fmt.Errorf("%w: DAX requires a positive FASTLET_CAPACITY", ErrInvalidConfig)
	}
	guest, err := resource.ParseQuantity(memory)
	if err != nil || guest.Sign() <= 0 {
		return fmt.Errorf("%w: DAX requires guest memory", ErrInvalidConfig)
	}
	budget, err := d.config.SharedRootfsBudget()
	if err != nil {
		return err
	}
	reserve := runtimecatalog.SharedRootfsReservation(budget)
	if guest.Value() > math.MaxInt64-reserve || guest.Value()+reserve > math.MaxInt64/capacity {
		return fmt.Errorf("%w: DAX memory allocation out of range", ErrInvalidConfig)
	}
	required := (guest.Value() + reserve) * capacity
	overhead := d.profile.Deployment.Overhead["memory"]
	if overhead.Value() > math.MaxInt64-required {
		return fmt.Errorf("%w: DAX memory allocation out of range", ErrInvalidConfig)
	}
	required += overhead.Value()
	if limit.Value() < required {
		return fmt.Errorf("%w: runtime owner memory limit %s cannot cover DAX allocation %d bytes", ErrInvalidConfig, limit.String(), required)
	}
	return nil
}
