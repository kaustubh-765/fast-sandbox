package main

import (
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stretchr/testify/require"

	"fast-sandbox/internal/artifacts"
)

func imageWithLabels(t *testing.T, labels map[string]string) v1.Image {
	t.Helper()
	image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{Config: v1.Config{Env: []string{"PATH=/usr/bin"}, Labels: labels}})
	require.NoError(t, err)
	return image
}

// Only a source image labeled for the OCI drive gets the placeholder; every
// other template builds exactly as before.
func TestOCIDrivePlaceholderFollowsImageLabel(t *testing.T) {
	labeled := t.TempDir()
	require.NoError(t, writeImageEnv(imageWithLabels(t, map[string]string{artifacts.OCIDriveImageLabel: artifacts.OCIDriveImageLabelValue}), labeled))
	require.NoError(t, prepareOCIDrivePlaceholder(labeled))
	info, err := os.Stat(filepath.Join(labeled, artifacts.OCIDriveFileName))
	require.NoError(t, err)
	require.Equal(t, int64(artifacts.OCIDrivePlaceholderBytes), info.Size())

	plain := t.TempDir()
	require.NoError(t, writeImageEnv(imageWithLabels(t, map[string]string{"other": "label"}), plain))
	require.NoError(t, prepareOCIDrivePlaceholder(plain))
	_, err = os.Stat(filepath.Join(plain, artifacts.OCIDriveFileName))
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(plain, ociDriveMarkerName))
	require.True(t, os.IsNotExist(err))
}
