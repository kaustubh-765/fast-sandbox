package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerCredentialsUseBasicOrRejectTokenOnly(t *testing.T) {
	setupManifestCache(t)
	ref, err := parseRegistryReference("registry.invalid/team/template:build")
	require.NoError(t, err)
	for _, raw := range []string{
		`{"auths":{"registry.invalid":{"username":"reader","password":"secret","identitytoken":"unused"}}}`,
		`{"auths":{"registry.invalid":{"auth":"cmVhZGVyOnNlY3JldA==","identitytoken":"unused"}}}`,
	} {
		config, err := parseDockerConfig(raw)
		require.NoError(t, err)
		credential, _, err := credentialFor(config, ref)
		require.NoError(t, err)
		require.Equal(t, "reader", credential.Username)
		require.Equal(t, "secret", credential.Password)
		require.Empty(t, credential.RefreshToken)
		handoff, err := overlaybdCredentials(config, ref.String())
		require.NoError(t, err)
		require.Equal(t, "cmVhZGVyOnNlY3JldA==", handoff.Auths["registry.invalid/team/template"].Auth)
		require.Empty(t, handoff.Auths["registry.invalid/team/template"].IdentityToken)
	}
	config, err := parseDockerConfig(`{"auths":{"registry.invalid":{"identitytoken":"private-token"}}}`)
	require.NoError(t, err)
	_, err = resolveImage(context.Background(), ref.String(), config)
	require.ErrorContains(t, err, "identitytoken-only credentials are not supported")
	_, err = overlaybdCredentials(config, ref.String())
	require.ErrorContains(t, err, "identitytoken-only credentials are not supported")
}
