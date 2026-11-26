package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	agentpull "fast-sandbox/internal/runtime/firecracker/agent"
	agentstate "fast-sandbox/internal/runtime/firecracker/agent/state"
)

// The Fastlet learns the agent's store format from Health; an agent
// without the transfer option reports legacy, the default.
func TestServiceHealthReportsTransferFormat(t *testing.T) {
	stateRoot := t.TempDir()
	state, err := agentstate.New(stateRoot)
	require.NoError(t, err)
	t.Cleanup(func() { _ = state.Close() })

	health, err := NewService(newFakePuller(), state, stateRoot).Health(context.Background())
	require.NoError(t, err)
	require.Equal(t, agentpull.TransferFormatLegacy, health.TransferFormat)

	chunked := agentpull.TransferConfig{Format: agentpull.TransferFormatChunked}
	health, err = NewService(newFakePuller(), state, stateRoot, WithTransfer(chunked)).Health(context.Background())
	require.NoError(t, err)
	require.Equal(t, agentpull.TransferFormatChunked, health.TransferFormat)
}

// chunkListDigest is reported only for format: chunked with chunkListOnly.
func TestServiceReportsChunkListDigestOnlyWithChunkListOnly(t *testing.T) {
	stateRoot := t.TempDir()
	state, err := agentstate.New(stateRoot)
	require.NoError(t, err)
	t.Cleanup(func() { _ = state.Close() })
	for _, case_ := range []struct {
		transfer agentpull.TransferConfig
		want     bool
	}{
		{agentpull.TransferConfig{}, false},
		{agentpull.TransferConfig{Format: agentpull.TransferFormatChunked}, false},
		{agentpull.TransferConfig{Format: agentpull.TransferFormatChunked, ChunkListOnly: true}, true},
	} {
		health, err := NewService(newFakePuller(), state, stateRoot, WithTransfer(case_.transfer)).Health(context.Background())
		require.NoError(t, err)
		require.Equal(t, case_.want, health.ChunkListDigest, "%+v", case_.transfer)
	}
}
