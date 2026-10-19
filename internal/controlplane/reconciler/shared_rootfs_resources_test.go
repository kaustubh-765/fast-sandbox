package reconciler

import (
	"testing"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	"fast-sandbox/internal/artifacts"
)

func TestBuildRejectsOldBuilderForDefaultDAX(t *testing.T) {
	require.Error(t, validateBuiltRootfsLayout(apiv1alpha2.SandboxTemplateSpec{}, ""))
	require.NoError(t, validateBuiltRootfsLayout(apiv1alpha2.SandboxTemplateSpec{}, artifacts.SharedRootfsLayout))
	legacy := apiv1alpha2.SandboxTemplateSpec{Output: apiv1alpha2.OutputSpec{SharedRootfs: ptr(false)}}
	require.NoError(t, validateBuiltRootfsLayout(legacy, ""))
	require.NoError(t, validateBuiltRootfsLayout(legacy, artifacts.BlockRootfsLayout))
	require.Error(t, validateBuiltRootfsLayout(legacy, artifacts.SharedRootfsLayout))
}

func TestDAXBuilderReservesBaseUpperAndRAM(t *testing.T) {
	spec := apiv1alpha2.SandboxTemplateSpec{Machine: apiv1alpha2.MachineSpec{Memory: "8Gi"}, Output: apiv1alpha2.OutputSpec{RootfsSize: "20Gi", WritableSize: "4Gi", Format: apiv1alpha2.ArtifactFormatOverlayBD}}
	resources, err := templateBuildResources(spec)
	require.NoError(t, err)
	require.Equal(t, resources.Limits.Memory().Value(), resources.Requests.Memory().Value())
	require.Greater(t, resources.Limits.Memory().Value(), int64(28<<30))
	require.Equal(t, resources.Limits.StorageEphemeral().Value(), resources.Requests.StorageEphemeral().Value())
	require.EqualValues(t, 68<<30, resources.Requests.StorageEphemeral().Value())
	spec.Output.RootfsSize = "invalid"
	_, err = templateBuildResources(spec)
	require.Error(t, err)
}
