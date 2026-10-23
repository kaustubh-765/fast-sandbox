package ocitemplate

import (
	"testing"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestBasicCredentialAuthenticationContract(t *testing.T) {
	for _, test := range []struct {
		name, username, password, token string
		unsupported                     bool
	}{
		{name: "anonymous"},
		{name: "basic", username: "reader", password: "secret"},
		{name: "token in password", username: "reader", password: "access-token"},
		{name: "basic with unused identity token", username: "reader", password: "secret", token: "unused-token"},
		{name: "identity token only", token: "private-token", unsupported: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			credential, err := BasicCredential(test.username, test.password, test.token)
			if test.unsupported {
				require.ErrorContains(t, err, "identitytoken-only credentials are not supported")
				require.NotContains(t, err.Error(), test.token)
				return
			}
			require.NoError(t, err)
			require.Equal(t, auth.Credential{Username: test.username, Password: test.password}, credential)
		})
	}
}
