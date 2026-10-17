package action

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	actionapi "fast-sandbox/internal/protocol/action"
)

// newVaultTransferManager wires a manager declaring the egress handler with
// vault transfer enabled, and registers one Sandbox's Action state.
func newVaultTransferManager(t *testing.T) (*Manager, *fakeCaller) {
	t.Helper()
	caller := &fakeCaller{instanceID: "handler-1"}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "egress", TargetHTTPPort: 18080}}, caller)
	require.NoError(t, err)
	manager.SetVaultHandler("egress")
	manager.probe(context.Background())
	_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
	require.NoError(t, reconcileErr)
	return manager, caller
}

// vaultCalls returns the recorded vault-transfer invocations, excluding the
// SET_BINDING traffic the registration itself emits.
func vaultCalls(caller *fakeCaller) []recordedRequest {
	var calls []recordedRequest
	for _, request := range caller.snapshot() {
		switch request.request.Operation {
		case actionapi.OperationVaultExport, actionapi.OperationVaultImport:
			calls = append(calls, request)
		}
	}
	return calls
}

func TestExportVaultSendsEnvelopeOpWithBundlePath(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	require.NoError(t, manager.ExportVault(context.Background(), "a", "/state/snapshots/ckpt-1/vault.json"))
	requests := vaultCalls(caller)
	require.Len(t, requests, 1)
	require.Equal(t, int32(18080), requests[0].port)
	require.Equal(t, actionapi.OperationVaultExport, requests[0].request.Operation)
	require.Equal(t, "/state/snapshots/ckpt-1/vault.json", requests[0].request.Snapshot.Path)
	require.Equal(t, "a", requests[0].request.Sandbox.UID)
	// The envelope fence is the registered fence: the Handler matches it
	// against the registration and rejects stale invocations itself.
	require.Equal(t, "runtime-a", requests[0].request.Revision.RuntimeInstanceID)
	require.Empty(t, requests[0].request.Binding)
}

func TestImportVaultSendsEnvelopeOpWithBundlePath(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	require.NoError(t, manager.ImportVault(context.Background(), "a", "/state/images/ckpt/vault.json"))
	requests := vaultCalls(caller)
	require.Len(t, requests, 1)
	require.Equal(t, actionapi.OperationVaultImport, requests[0].request.Operation)
	require.Equal(t, "/state/images/ckpt/vault.json", requests[0].request.Snapshot.Path)
}

func TestVaultTransferSurfacesHandlerFailure(t *testing.T) {
	manager, caller := newVaultTransferManager(t)
	caller.mu.Lock()
	caller.fail = map[actionapi.Operation]int{actionapi.OperationVaultExport: 1}
	caller.mu.Unlock()

	err := manager.ExportVault(context.Background(), "a", "/tmp/vault.json")
	require.ErrorContains(t, err, "VAULT_EXPORT vault transfer")
}

func TestVaultTransferSkipsWhenDisabledOrUndeclared(t *testing.T) {
	t.Run("transfer disabled", func(t *testing.T) {
		caller := &fakeCaller{instanceID: "handler-1"}
		manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "egress", TargetHTTPPort: 18080}}, caller)
		require.NoError(t, err)
		manager.probe(context.Background())
		_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
		require.NoError(t, reconcileErr)
		require.NoError(t, manager.ExportVault(context.Background(), "a", "/tmp/vault.json"), "no vault handler configured: nothing to transfer")
		require.Empty(t, vaultCalls(caller))
	})
	t.Run("handler undeclared by the Pool", func(t *testing.T) {
		caller := &fakeCaller{instanceID: "handler-1"}
		manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "audit", TargetHTTPPort: 18081}}, caller)
		require.NoError(t, err)
		manager.probe(context.Background())
		manager.SetVaultHandler("egress")
		_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("audit", "v1")})
		require.NoError(t, reconcileErr)
		require.NoError(t, manager.ExportVault(context.Background(), "a", "/tmp/vault.json"), "a pool without the vault handler can never hold vault state")
		require.Empty(t, vaultCalls(caller))
	})
}

func TestVaultTransferFailsForUnregisteredSandbox(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	err := manager.ExportVault(context.Background(), "ghost", "/tmp/vault.json")
	require.ErrorContains(t, err, "no registered Action state")
	require.Empty(t, vaultCalls(caller))
}

func TestVaultHandlerFromEnvDefaultsToEgress(t *testing.T) {
	t.Setenv("FAST_SANDBOX_VAULT_HANDLER", "")
	require.Equal(t, "egress", VaultHandlerFromEnv())
	t.Setenv("FAST_SANDBOX_VAULT_HANDLER", "secret-vault")
	require.Equal(t, "secret-vault", VaultHandlerFromEnv())
}
