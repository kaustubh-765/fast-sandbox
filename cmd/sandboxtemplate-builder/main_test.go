package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
)

func TestRunRejectsOverlayBDObjectStoreBeforeBuild(t *testing.T) {
	for _, publish := range []string{"s3://bucket/templates", ""} {
		t.Run(publish, func(t *testing.T) {
			raw, err := json.Marshal(apiv1alpha2.SandboxTemplateSpec{
				Kernel: "missing-kernel",
				Output: apiv1alpha2.OutputSpec{Format: apiv1alpha2.ArtifactFormatOverlayBD, Publish: publish},
			})
			require.NoError(t, err)
			t.Setenv(specEnv, string(raw))
			t.Setenv(workDirEnv, t.TempDir())
			t.Setenv("SANDBOX_TEMPLATE_ALLOW_NO_PUBLISH", "1")
			require.ErrorContains(t, run(context.Background()), "overlaybd requires output.publish=oci://")
		})
	}
}
