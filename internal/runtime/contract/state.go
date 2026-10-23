package contract

import (
	"context"
)

// StateKind names the egress-owned state slice a StateMover carries across
// pause/resume. Each kind maps onto one Sandbox Actions operation pair
// (VAULT_EXPORT / VAULT_IMPORT, POLICY_EXPORT / POLICY_IMPORT) served by the
// same Pool-declared egress Handler over the Pod-loopback actions channel.
type StateKind string

const (
	// StateKindVault is the credential vault file (OSEP-0022 "Vault
	// Lifecycle"): instance-private secret state. Template snapshots never
	// carry it — a shared boot image would leak one sandbox's credentials
	// into every clone.
	StateKindVault StateKind = "vault"
	// StateKindPolicy is the recorded egress network policy file: desired
	// state, not a secret. Checkpoint snapshots carry it (the export seals
	// the subject on the egress, so a template export would lock the
	// still-running source out of its policy CRUD — templates never export,
	// and a clone inherits the create-time CRD seed instead). The imported
	// record stays authoritative over later binding replays (the binding
	// input only ever seeds a fresh subject).
	//
	// Usage contract for the recorded policy — three channels, each with a
	// distinct role:
	//
	//   - Create: initialize the policy with the Sandbox spec's ActionBinding
	//     (handler=egress, input=<policy JSON>). SET_BINDING seeds the
	//     subject's bootstrap policy from the CRD. This is a create-time
	//     seed only — nothing maintains it afterward.
	//   - Runtime: perform every mutation through the generic handler relay
	//     (PUT / GET / DELETE /policy/{sandboxUid} over fastpath
	//     InvokeHandlerAction), i.e. the egress' native policy semantics
	//     with revision preconditions. Relay mutations are SUBJECT-LOCAL:
	//     they bypass the CRD (no re-delivery, no durability across a Pod
	//     recreation) and never leak into clones.
	//   - Snapshot/pause: persistence rides the egress dump — POLICY_EXPORT
	//     copies the subject's persisted policy record into the checkpoint
	//     bundle as policy.json, an OPAQUE artifact (the manifest only
	//     references it; the driver never parses it) whose only consumer is
	//     the resume POLICY_IMPORT, which re-stamps it before
	//     data-plane-ready.
	StateKindPolicy StateKind = "policy"
)

// StateMover carries the egress-owned state files across pause/resume: the
// driver invokes ExportState inside the pause flow — strictly before the
// runtime teardown purges the egress-local file — and ImportState at
// restore, before the restored Sandbox's data plane becomes ready. The
// transfer rides the Sandbox Actions envelope (operation per StateKind,
// snapshot.path): the Handler copies/reads the bundle file itself, so no
// state bytes ever cross the driver process. bundlePath is the Pod-local
// staging file: the export target inside the snapshot bundle, or the bundle
// source at restore.
//
// "No state of this kind" is signalled by no file at bundlePath after a
// successful export — not an error. Failure semantics: an export failure
// fails the checkpoint (the control plane only releases the runtime after
// the checkpoint is durable, so the egress-local file survives for the
// retry); an import failure degrades the restored subject's state
// (fail-closed for the vault, binding-input fallback for the policy —
// observable either way) and must not fail the restore.
type StateMover interface {
	// ExportState copies the subject's state file of kind into the bundle
	// target. The Handler seals the subject on success; any non-2xx answer
	// (unknown subject, stale fence, copy failure) is a transfer failure
	// that fails the checkpoint.
	ExportState(ctx context.Context, sandboxUID string, kind StateKind, bundlePath string) error
	// ImportState lands the bundle source file as the subject's state of
	// kind, re-stamped by the Handler with the restored runtime fence.
	ImportState(ctx context.Context, sandboxUID string, kind StateKind, bundlePath string) error
}
