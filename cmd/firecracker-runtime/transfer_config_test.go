package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadAgentConfigTransferDefaultsToLegacy(t *testing.T) {
	config, err := loadAgentConfig(filepath.Join(t.TempDir(), "absent.yaml"))
	require.NoError(t, err)
	require.False(t, config.Transfer.transfer().Chunked(), "an absent transfer section is legacy")
}

func TestLoadAgentConfigParsesTransfer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	payload := `
transfer:
  format: chunked
  compression: zstd
  concurrency: 4
  chunkSizeMiB: 8
  chunkListOnly: true
`
	require.NoError(t, os.WriteFile(path, []byte(payload), 0o600))
	config, err := loadAgentConfig(path)
	require.NoError(t, err)
	transfer := config.Transfer.transfer()
	require.True(t, transfer.Chunked())
	require.Equal(t, "zstd", transfer.Compression)
	require.Equal(t, 4, transfer.Concurrency)
	require.Equal(t, int64(8<<20), transfer.ChunkSize)
	require.True(t, transfer.ChunkListDigest())
}

func TestLoadAgentConfigRejectsInvalidTransfer(t *testing.T) {
	for name, payload := range map[string]string{
		"unknown format":            "transfer:\n  format: fast\n",
		"unknown compression":       "transfer:\n  format: chunked\n  compression: gzip\n",
		"zstd without chunked":      "transfer:\n  compression: zstd\n",
		"zstd with legacy":          "transfer:\n  format: legacy\n  compression: zstd\n",
		"chunkListOnly with legacy": "transfer:\n  chunkListOnly: true\n",
		"negative concurrency":      "transfer:\n  format: chunked\n  concurrency: -1\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			require.NoError(t, os.WriteFile(path, []byte(payload), 0o600))
			_, err := loadAgentConfig(path)
			require.ErrorContains(t, err, "transfer:")
		})
	}
}
