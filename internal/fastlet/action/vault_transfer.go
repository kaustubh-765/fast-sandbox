package action

// vault_transfer.go implements the Fastlet side of the driver-invoked vault
// transfer (runtimecontract.VaultMover, OSEP-0022 "Vault Lifecycle"): the
// subject's vault file moves across pause/resume as VAULT_EXPORT /
// VAULT_IMPORT invocations on the Pool-declared vault-capable Action Handler
// over the existing Pod-loopback Sandbox Actions channel. The envelope
// carries the bundle file PATH (snapshot.path) — the Handler copies/reads
// the file itself through its commit protocol, so no credential bytes ever
// cross this process. The envelope fence is the Sandbox's currently
// registered fence, so a stale invocation is rejected by the Handler.
//
// The default vault handler name matches the OSEP-0022 fast-sandbox profile
// convention ("egress"); pools without that handler never transfer vault
// files, and a successful export without a bundle file simply means the
// subject held no vault.

import (
	"context"
	"fmt"
	"os"

	actionapi "fast-sandbox/internal/protocol/action"
	runtimecontract "fast-sandbox/internal/runtime/contract"
)

// vaultTransferEnvVar optionally overrides the name of the Pool-declared
// Action Handler that serves the egress vault surface.
const vaultTransferEnvVar = "FAST_SANDBOX_VAULT_HANDLER"

// defaultVaultHandler is the conventional name of the egress Action Handler.
const defaultVaultHandler = "egress"

// SetVaultHandler configures the Pool-declared Action Handler name that
// serves the egress vault surface. An empty name disables vault transfer.
func (m *Manager) SetVaultHandler(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vaultHandler = name
}

// VaultHandler returns the configured vault handler name.
func (m *Manager) VaultHandler() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.vaultHandler
}

// VaultHandlerFromEnv resolves the vault handler name from the environment,
// defaulting to the egress convention.
func VaultHandlerFromEnv() string {
	if name := os.Getenv(vaultTransferEnvVar); name != "" {
		return name
	}
	return defaultVaultHandler
}

var _ runtimecontract.VaultMover = (*Manager)(nil)

// ExportVault copies the subject's vault file into the driver-provided
// bundle target. The Handler seals the subject on success; any non-2xx
// answer (unknown subject, stale fence, copy failure) is a transfer failure
// that fails the checkpoint.
func (m *Manager) ExportVault(ctx context.Context, sandboxUID, bundlePath string) error {
	return m.invokeVaultTransfer(ctx, actionapi.OperationVaultExport, sandboxUID, bundlePath)
}

// ImportVault lands the bundle source file as the subject's vault,
// re-stamped by the Handler with the restored runtime fence. A failure is
// returned to the driver, which logs it and proceeds — the restored
// subject's vault then degrades (fail-closed, observable).
func (m *Manager) ImportVault(ctx context.Context, sandboxUID, bundlePath string) error {
	return m.invokeVaultTransfer(ctx, actionapi.OperationVaultImport, sandboxUID, bundlePath)
}

// invokeVaultTransfer sends one vault-transfer invocation on the actions
// channel. Transfer is disabled (a silent no-op) without a configured
// handler or when the Pool does not declare it; a Sandbox without a
// registered Action state cannot be transferred.
func (m *Manager) invokeVaultTransfer(ctx context.Context, operation actionapi.Operation, sandboxUID, bundlePath string) error {
	m.mu.RLock()
	name := m.vaultHandler
	handler, declared := m.byName[name]
	m.mu.RUnlock()
	if name == "" || !declared {
		// The Pool cannot hold vault state at all: nothing to transfer.
		return nil
	}
	invocation, err := m.vaultInvocation(ctx, operation, name, sandboxUID, bundlePath)
	if err != nil {
		return err
	}
	if err := m.caller.Invoke(ctx, handler.TargetHTTPPort, invocation); err != nil {
		return fmt.Errorf("%s vault transfer for Sandbox %s: %w", operation, sandboxUID, err)
	}
	return nil
}

// vaultInvocation builds the transfer envelope from the Sandbox's currently
// registered fence: the Handler matches it against the registration, so a
// stale invocation (replaced runtime, superseded attachment) is rejected
// instead of touching the wrong subject slice.
func (m *Manager) vaultInvocation(ctx context.Context, operation actionapi.Operation, handlerName, sandboxUID, bundlePath string) (actionapi.Request, error) {
	m.mu.RLock()
	state := m.states[sandboxUID]
	m.mu.RUnlock()
	if state == nil {
		return actionapi.Request{}, fmt.Errorf("%s vault transfer: Sandbox %s has no registered Action state", operation, sandboxUID)
	}
	if !state.lockOperations(ctx) {
		return actionapi.Request{}, ctx.Err()
	}
	// The op token serializes against other invocation flows but NOT against
	// the writers: registerDesired mutates both fields under state.mu (before
	// the token is acquired and on the RegisterDesired path), so the field
	// reads take state.mu like every established reader.
	state.mu.RLock()
	attachment := state.attachment
	generation := state.desiredGeneration
	state.mu.RUnlock()
	state.unlockOperations()
	instance, err := m.handlerInstance(handlerName)
	if err != nil {
		instance = ""
	}
	request := buildRequest(operation, stableInvocationID(operation, handlerName, instance, generation, attachment, "", bundlePath), generation, attachment)
	request.Snapshot = &actionapi.SnapshotTransfer{Path: bundlePath}
	return request, nil
}
