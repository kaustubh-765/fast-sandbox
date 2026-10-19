package reconciler

import (
	"fmt"
	"math"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	"fast-sandbox/internal/artifacts"
	runtimecatalog "fast-sandbox/internal/catalog/runtime"
)

func templateBuildResources(spec apiv1alpha2.SandboxTemplateSpec) (corev1.ResourceRequirements, error) {
	memoryLimit := resource.MustParse("4Gi")
	if machineMemory, err := resource.ParseQuantity(spec.Machine.Memory); err == nil {
		withHeadroom := machineMemory.DeepCopy()
		withHeadroom.Add(resource.MustParse("1Gi"))
		if withHeadroom.Cmp(memoryLimit) > 0 {
			memoryLimit = withHeadroom
		}
	}
	memoryRequest := resource.MustParse("2Gi")
	if spec.Output.SharedRootfs == nil || *spec.Output.SharedRootfs {
		// The cold-boot VMM can map every base page in addition to guest RAM.
		// Use the conversion capacity as an upper bound before compaction.
		baseSize := resource.MustParse("30Gi")
		if spec.Output.RootfsSize != "" {
			parsed, err := resource.ParseQuantity(spec.Output.RootfsSize)
			if err != nil || parsed.Sign() <= 0 {
				return corev1.ResourceRequirements{}, fmt.Errorf("invalid rootfsSize for DAX memory sizing")
			}
			baseSize = parsed
		}
		// oci2rootfs rounds GiB declarations up to SI GB; allow one SI GB.
		baseBytes, exact := baseSize.AsInt64()
		if !exact || baseBytes > math.MaxInt64/4-1000000000 {
			return corev1.ResourceRequirements{}, fmt.Errorf("rootfsSize out of range")
		}
		baseBytes += 1000000000
		memoryLimit.Add(*resource.NewQuantity(runtimecatalog.SharedRootfsReservation(baseBytes), resource.BinarySI))
		memoryRequest = memoryLimit.DeepCopy()
	}
	// The workspace emptyDir lives on the node's local disk and holds the
	// rootfs plus the 1:1 guest memory snapshot; size the ephemeral-storage
	// limit from the declared rootfsSize + machine.memory so a build cannot
	// fill a shared node's disk. The kubelet enforces this via eviction.
	storageLimit := resource.MustParse("10Gi")
	if rootfsSize, err := resource.ParseQuantity(spec.Output.RootfsSize); err == nil {
		total := rootfsSize.DeepCopy()
		if machineMemory, err := resource.ParseQuantity(spec.Machine.Memory); err == nil {
			total.Add(machineMemory)
		}
		total.Add(resource.MustParse("2Gi"))
		if total.Cmp(storageLimit) > 0 {
			storageLimit = total
		}
	}
	storageRequest := resource.MustParse("5Gi")
	if spec.Output.SharedRootfs == nil || *spec.Output.SharedRootfs {
		total, err := sharedTemplateStorage(spec)
		if err != nil {
			return corev1.ResourceRequirements{}, err
		}
		if total.Cmp(storageLimit) > 0 {
			storageLimit = total
		}
		storageRequest = storageLimit.DeepCopy()
	}

	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: memoryRequest, corev1.ResourceEphemeralStorage: storageRequest},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: memoryLimit, corev1.ResourceEphemeralStorage: storageLimit},
	}, nil
}

func applyRuntimeResources(c *corev1.Container, profile runtimecatalog.RuntimeProfile, sandboxResources apiv1alpha2.SandboxResourceProfile, capacitySlots int32) error {
	overhead := profile.Deployment.Overhead.DeepCopy()
	if profile.Driver == runtimecatalog.DriverKindFirecracker && profile.Firecracker != nil {
		budget, err := profile.Firecracker.SharedRootfsBudget()
		if err != nil {
			return err
		}
		if overhead == nil {
			overhead = corev1.ResourceList{}
		}
		perSlot := runtimecatalog.SharedRootfsReservation(budget)
		capacity := int64(capacitySlots)
		if capacity <= 0 || perSlot > math.MaxInt64/capacity {
			return fmt.Errorf("DAX memory reservation out of range")
		}
		extra := perSlot * capacity
		addScaledQuantity(overhead, corev1.ResourceMemory, *resource.NewQuantity(extra, resource.BinarySI), 1)
		if budget > 0 {
			minimum := overhead[corev1.ResourceMemory]
			guestBytes, exact := sandboxResources.Memory.AsInt64()
			if !exact || guestBytes < 0 || guestBytes > (math.MaxInt64-extra)/capacity {
				return fmt.Errorf("DAX guest memory reservation out of range")
			}
			minimum.Add(*resource.NewQuantity(guestBytes*capacity, resource.BinarySI))
			for _, list := range []corev1.ResourceList{c.Resources.Requests, c.Resources.Limits} {
				if v, ok := list[corev1.ResourceMemory]; ok && !v.IsZero() && v.Cmp(minimum) < 0 {
					return fmt.Errorf("DAX runtime owner memory %s is below conservative requirement %s; increase resources or set sharedRootfsMemory=0 for legacy-only snapshots", v.String(), minimum.String())
				}
			}
		}
	}
	return applyFastletResources(c, overhead, sandboxResources, capacitySlots)
}

func sharedTemplateStorage(spec apiv1alpha2.SandboxTemplateSpec) (resource.Quantity, error) {
	baseSize := resource.MustParse("30Gi")
	if spec.Output.RootfsSize != "" {
		baseSize = resource.MustParse(spec.Output.RootfsSize)
	}
	// Conversion may hold OCI extraction alongside the base. Packaging
	// additionally holds layers for the upper disk and RAM snapshot.
	total := baseSize.DeepCopy()
	total.Mul(2)
	upper := baseSize.DeepCopy()
	if spec.Output.WritableSize != "" {
		q, err := resource.ParseQuantity(spec.Output.WritableSize)
		if err != nil || q.Sign() <= 0 {
			return resource.Quantity{}, fmt.Errorf("invalid writableSize")
		}
		upper = q
	}
	memory, err := resource.ParseQuantity(spec.Machine.Memory)
	if err != nil || memory.Sign() <= 0 {
		return resource.Quantity{}, fmt.Errorf("invalid machine memory")
	}
	if spec.Output.Format == apiv1alpha2.ArtifactFormatOverlayBD {
		upper.Mul(2)
		memory.Mul(2)
	}
	total.Add(upper)
	total.Add(memory)
	total.Add(resource.MustParse("4Gi"))
	return total, nil
}

func validateBuiltRootfsLayout(spec apiv1alpha2.SandboxTemplateSpec, layout string) error {
	shared := spec.Output.SharedRootfs == nil || *spec.Output.SharedRootfs
	if shared && layout != artifacts.SharedRootfsLayout {
		return fmt.Errorf("builder did not produce the requested DAX rootfs layout; upgrade the builder image or explicitly disable sharedRootfs")
	}
	if !shared && layout != "" && layout != artifacts.BlockRootfsLayout {
		return fmt.Errorf("builder produced unexpected rootfs layout %q", layout)
	}
	return nil
}
