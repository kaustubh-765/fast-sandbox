package runtime

import (
	"fmt"
	"math"

	"k8s.io/apimachinery/pkg/api/resource"
)

// SharedRootfsBudget is a per-slot upper bound, not an estimate of residency.
// Reserving it for every slot covers worst-case first-touch memcg ownership,
// including when other Fastlets on the node map the same inode. Zero disables
// DAX admission and its reservation (for legacy-only runtime deployments).
func (c FirecrackerConfig) SharedRootfsBudget() (int64, error) {
	value := c.SharedRootfsMemory
	if value == "" {
		value = "32Gi"
	}
	q, err := resource.ParseQuantity(value)
	if err != nil || q.Sign() < 0 {
		return 0, fmt.Errorf("invalid sharedRootfsMemory %q", value)
	}
	n, exact := q.AsInt64()
	if !exact || n > math.MaxInt64/2 {
		return 0, fmt.Errorf("sharedRootfsMemory out of range")
	}
	return n, nil
}

// SharedRootfsReservation includes the entire file plus a conservative 1/32
// metadata allowance (guest struct pages, host/guest page tables), rounded to
// 2 MiB. It is additional to full guest RAM and the runtime process overhead.
func SharedRootfsReservation(base int64) int64 {
	if base == 0 {
		return 0
	}
	return base + ((base/32+(2<<20)-1)/(2<<20))*(2<<20)
}
