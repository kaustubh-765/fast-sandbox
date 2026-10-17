package contract

import (
	"context"
)

// VaultMover carries the egress-owned vault file across pause/resume
// (OSEP-0022 "Vault Lifecycle"): the driver invokes ExportVault inside the
// pause flow — strictly before the runtime teardown purges the egress-local
// file — and ImportVault at restore, before the restored Sandbox's data
// plane becomes ready. The transfer rides the Sandbox Actions envelope
// (VAULT_EXPORT / VAULT_IMPORT, snapshot.path): the Handler copies/reads the
// bundle file itself, so no credential bytes ever cross the driver process.
// bundlePath is the Pod-local staging file: the export target inside the
// snapshot bundle, or the bundle source at restore.
//
// "No vault" is signalled by no file at bundlePath after a successful export
// — not an error. Failure semantics: an export failure fails the checkpoint
// (the control plane only releases the runtime after the checkpoint is
// durable, so the egress-local file survives for the retry); an import
// failure degrades the restored subject's vault (fail-closed, observable)
// and must not fail the restore.
type VaultMover interface {
	// ExportVault copies the subject's vault file into the bundle target.
	ExportVault(ctx context.Context, sandboxUID, bundlePath string) error
	// ImportVault lands the bundle source file as the subject's vault,
	// re-stamped by the Handler with the restored runtime fence.
	ImportVault(ctx context.Context, sandboxUID, bundlePath string) error
}
