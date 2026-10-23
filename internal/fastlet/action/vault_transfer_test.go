package action

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	actionapi "fast-sandbox/internal/protocol/action"
)

// newVaultTransferManager wires a manager declaring the egress handler with
// vault and policy transfer enabled, and registers one Sandbox's Action state.
func newVaultTransferManager(t *testing.T) (*Manager, *fakeCaller) {
	t.Helper()
	caller := &fakeCaller{instanceID: "handler-1", vaultTransfer: true, policyTransfer: true}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "egress", TargetHTTPPort: 18080}}, caller)
	require.NoError(t, err)
	manager.SetVaultHandler("egress")
	manager.probe(context.Background())
	_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
	require.NoError(t, reconcileErr)
	return manager, caller
}

// stateCalls returns the recorded state-transfer invocations, excluding the
// SET_BINDING traffic the registration itself emits.
func stateCalls(caller *fakeCaller) []recordedRequest {
	var calls []recordedRequest
	for _, request := range caller.snapshot() {
		switch request.request.Operation {
		case actionapi.OperationVaultExport, actionapi.OperationVaultImport,
			actionapi.OperationPolicyExport, actionapi.OperationPolicyImport:
			calls = append(calls, request)
		}
	}
	return calls
}

func TestExportVaultSendsEnvelopeOpWithBundlePath(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	require.NoError(t, manager.ExportVault(context.Background(), "a", "/state/snapshots/ckpt-1/vault.json"))
	requests := stateCalls(caller)
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
	requests := stateCalls(caller)
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
	require.ErrorContains(t, err, "VAULT_EXPORT state transfer")
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
		require.Empty(t, stateCalls(caller))
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
		require.Empty(t, stateCalls(caller))
	})
}

func TestVaultTransferFailsForUnregisteredSandbox(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	err := manager.ExportVault(context.Background(), "ghost", "/tmp/vault.json")
	require.ErrorContains(t, err, "no registered Action state")
	require.Empty(t, stateCalls(caller))
}

// A Handler without the vaultTransfer capability (older build predating the
// vault operations, or vault persistence not configured) must not fail the
// checkpoint: the transfer is skipped and the pause proceeds without a vault.
func TestVaultTransferSkipsWhenHandlerNotVaultCapable(t *testing.T) {
	manager, caller := newVaultTransferManager(t)
	caller.mu.Lock()
	caller.vaultTransfer = false
	caller.mu.Unlock()

	require.NoError(t, manager.ExportVault(context.Background(), "a", "/tmp/vault.json"))
	require.NoError(t, manager.ImportVault(context.Background(), "a", "/tmp/vault.json"))
	require.Empty(t, stateCalls(caller))
}

// An unreachable Handler is not a capability answer: the probe failure fails
// the checkpoint so the egress-local vault survives for the retry.
func TestVaultTransferFailsWhenCapabilityProbeFails(t *testing.T) {
	manager, caller := newVaultTransferManager(t)
	caller.mu.Lock()
	caller.statusErr = errors.New("handler unreachable")
	caller.mu.Unlock()

	err := manager.ExportVault(context.Background(), "a", "/tmp/vault.json")
	require.ErrorContains(t, err, "capability probe")
	require.Empty(t, stateCalls(caller))
}

func TestVaultHandlerFromEnvDefaultsToEgress(t *testing.T) {
	t.Setenv("FAST_SANDBOX_VAULT_HANDLER", "")
	require.Equal(t, "egress", VaultHandlerFromEnv())
	t.Setenv("FAST_SANDBOX_VAULT_HANDLER", "secret-vault")
	require.Equal(t, "secret-vault", VaultHandlerFromEnv())
}

// The policy transfer rides the same handler and envelope shape as the
// vault, with its own POLICY_EXPORT / POLICY_IMPORT operations.
func TestPolicyTransferSendsEnvelopeOpWithBundlePath(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	require.NoError(t, manager.ExportPolicy(context.Background(), "a", "/state/snapshots/ckpt-1/policy.json"))
	requests := stateCalls(caller)
	require.Len(t, requests, 1)
	require.Equal(t, int32(18080), requests[0].port)
	require.Equal(t, actionapi.OperationPolicyExport, requests[0].request.Operation)
	require.Equal(t, "/state/snapshots/ckpt-1/policy.json", requests[0].request.Snapshot.Path)
	require.Equal(t, "a", requests[0].request.Sandbox.UID)
	require.Equal(t, "runtime-a", requests[0].request.Revision.RuntimeInstanceID,
		"the envelope fence is the registered fence, shared with the vault transfer")
	require.Empty(t, requests[0].request.Binding)

	require.NoError(t, manager.ImportPolicy(context.Background(), "a", "/state/images/ckpt/policy.json"))
	requests = stateCalls(caller)
	require.Len(t, requests, 2)
	require.Equal(t, actionapi.OperationPolicyImport, requests[1].request.Operation)
	require.Equal(t, "/state/images/ckpt/policy.json", requests[1].request.Snapshot.Path)
}

// The StateMover entry point dispatches per kind and rejects unknown kinds.
func TestStateMoverDispatchesPerKind(t *testing.T) {
	manager, caller := newVaultTransferManager(t)

	require.NoError(t, manager.ExportState(context.Background(), "a", "vault", "/tmp/vault.json"))
	require.NoError(t, manager.ExportState(context.Background(), "a", "policy", "/tmp/policy.json"))
	requests := stateCalls(caller)
	require.Len(t, requests, 2)
	require.Equal(t, actionapi.OperationVaultExport, requests[0].request.Operation)
	require.Equal(t, actionapi.OperationPolicyExport, requests[1].request.Operation)

	require.ErrorContains(t, manager.ExportState(context.Background(), "a", "bogus", "/tmp/x.json"), "unknown state kind")
	require.ErrorContains(t, manager.ImportState(context.Background(), "a", "bogus", "/tmp/x.json"), "unknown state kind")
	require.Len(t, stateCalls(caller), 2, "unknown kinds never reach the handler")
}

// The capability probe is per kind: a Handler that serves the policy surface
// but carries no vault persistence still transfers policy and skips vault —
// and vice versa.
func TestStateTransferCapabilityProbeIsPerKind(t *testing.T) {
	t.Run("policy-capable handler skips vault", func(t *testing.T) {
		caller := &fakeCaller{instanceID: "handler-1", policyTransfer: true}
		manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "egress", TargetHTTPPort: 18080}}, caller)
		require.NoError(t, err)
		manager.SetVaultHandler("egress")
		manager.probe(context.Background())
		_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
		require.NoError(t, reconcileErr)

		require.NoError(t, manager.ExportVault(context.Background(), "a", "/tmp/vault.json"),
			"a handler without vault transfer is skipped (pre-transfer semantics)")
		require.NoError(t, manager.ExportPolicy(context.Background(), "a", "/tmp/policy.json"))
		requests := stateCalls(caller)
		require.Len(t, requests, 1)
		require.Equal(t, actionapi.OperationPolicyExport, requests[0].request.Operation,
			"only the policy operation reached the handler")
	})
	t.Run("vault-capable handler skips policy", func(t *testing.T) {
		caller := &fakeCaller{instanceID: "handler-1", vaultTransfer: true}
		manager, err := NewManager([]apiv1alpha2.ActionHandler{{Name: "egress", TargetHTTPPort: 18080}}, caller)
		require.NoError(t, err)
		manager.SetVaultHandler("egress")
		manager.probe(context.Background())
		_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
		require.NoError(t, reconcileErr)

		require.NoError(t, manager.ExportPolicy(context.Background(), "a", "/tmp/policy.json"),
			"a handler without policy transfer is skipped (pre-transfer semantics)")
		require.NoError(t, manager.ImportPolicy(context.Background(), "a", "/tmp/policy.json"))
		requests := stateCalls(caller)
		require.Empty(t, requests)
	})
}

// A policy transfer failure surfaces to the driver like the vault's.
func TestPolicyTransferSurfacesHandlerFailure(t *testing.T) {
	manager, caller := newVaultTransferManager(t)
	caller.mu.Lock()
	caller.fail = map[actionapi.Operation]int{actionapi.OperationPolicyExport: 1}
	caller.mu.Unlock()

	err := manager.ExportPolicy(context.Background(), "a", "/tmp/policy.json")
	require.ErrorContains(t, err, "POLICY_EXPORT state transfer")
}

// The template-carry channel is gated on the Handler's TemplateStateExport
// flag: without it both directions are silent no-ops (handlers that always
// seal must never be asked for a template carry); with it, exports carry
// Seal=false and imports reuse the transfer operations.
func TestTemplateStateTransferCapabilityGated(t *testing.T) {
	t.Run("no capability: loud failure, never a state-less template", func(t *testing.T) {
		manager, caller := newVaultTransferManager(t)
		caller.mu.Lock()
		caller.policyTransfer = true
		caller.vaultTransfer = true
		caller.templateStateExport = false
		caller.mu.Unlock()

		err := manager.ExportTemplateState(context.Background(), "a", "policy", "/tmp/policy.json")
		require.ErrorContains(t, err, "templateStateExport=false")
		require.ErrorContains(t, err, "refused rather than published without its state")
		require.Empty(t, stateCalls(caller), "a sealing handler is never asked for a template carry")
	})
	t.Run("capability declared: seal-free export + import", func(t *testing.T) {
		manager, caller := newVaultTransferManager(t)
		caller.mu.Lock()
		caller.templateStateExport = true
		caller.mu.Unlock()

		require.NoError(t, manager.ExportTemplateState(context.Background(), "a", "policy", "/state/snap-1/policy.json"))
		require.NoError(t, manager.ExportTemplateState(context.Background(), "a", "vault", "/state/snap-1/vault.json"))
		require.NoError(t, manager.ImportTemplateState(context.Background(), "a", "policy", "/state/images/tpl/policy.json"))
		requests := stateCalls(caller)
		require.Len(t, requests, 3)
		require.Equal(t, actionapi.OperationPolicyExport, requests[0].request.Operation)
		require.NotNil(t, requests[0].request.Snapshot.Seal)
		require.False(t, *requests[0].request.Snapshot.Seal, "template exports never seal the source")
		require.Equal(t, actionapi.OperationVaultExport, requests[1].request.Operation)
		require.False(t, *requests[1].request.Snapshot.Seal)
		require.Equal(t, actionapi.OperationPolicyImport, requests[2].request.Operation)
		require.Nil(t, requests[2].request.Snapshot.Seal, "imports carry no seal flag")
	})
	t.Run("unknown kind rejected", func(t *testing.T) {
		manager, _ := newVaultTransferManager(t)
		require.ErrorContains(t, manager.ExportTemplateState(context.Background(), "a", "bogus", "/tmp/x"), "unknown state kind")
	})
}
