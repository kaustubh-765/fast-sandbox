package runtime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedRootfsMemoryBudget(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    int64
		invalid bool
	}{{"", 32 << 30, false}, {"0", 0, false}, {"4Gi", 4 << 30, false}, {"-1Gi", 0, true}, {"oops", 0, true}, {"0.1", 0, true}, {"999999Ei", 0, true}} {
		got, err := (FirecrackerConfig{SharedRootfsMemory: tc.value}).SharedRootfsBudget()
		if tc.invalid {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
	require.Zero(t, SharedRootfsReservation(0))
	require.EqualValues(t, 33<<30, SharedRootfsReservation(32<<30))
	require.EqualValues(t, (2<<20)+(2<<20), SharedRootfsReservation(2<<20))
}
