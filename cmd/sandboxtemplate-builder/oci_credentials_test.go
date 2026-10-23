package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
)

func TestOCIBuilderRejectsSelectedTokenOnlyCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	spec := apiv1alpha2.SandboxTemplateSpec{Image: "source.example/team/base:build", Execd: "execd.example/team/execd:build", Output: apiv1alpha2.OutputSpec{Publish: "oci://destination.example/team/template"}}
	for _, host := range []string{"source.example", "execd.example", "destination.example"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"auths":{"`+host+`":{"identitytoken":"private-token"}}}`), 0600))
		require.ErrorContains(t, stageOCICredentials(spec, dir), "identitytoken-only credentials are not supported")
	}
	for _, config := range []string{`{"auths":{}}`, `{"auths":{"destination.example":{"auth":"cmVhZGVyOnNlY3JldA==","identitytoken":"unused"},"unrelated.example":{"identitytoken":"unused"}}}`} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0600))
		require.NoError(t, stageOCICredentials(spec, dir))
		raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
		require.NoError(t, err)
		require.NotContains(t, string(raw), "identitytoken")
		for _, image := range []string{spec.Image, spec.Execd, "destination.example/team/template"} {
			ref, err := name.ParseReference(image)
			require.NoError(t, err)
			selected, err := authn.DefaultKeychain.Resolve(ref.Context())
			require.NoError(t, err)
			credential, err := selected.Authorization()
			require.NoError(t, err)
			require.Empty(t, credential.IdentityToken)
			if image == "destination.example/team/template" && config != `{"auths":{}}` {
				require.Equal(t, "reader", credential.Username)
				require.Equal(t, "secret", credential.Password)
			} else {
				require.Empty(t, credential.Username)
				require.Empty(t, credential.Password)
			}
		}
	}
}
