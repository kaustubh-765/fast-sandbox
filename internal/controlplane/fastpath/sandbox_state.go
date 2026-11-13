package fastpath

// sandbox_state.go implements PauseSandbox/ResumeSandbox: the durable pause
// intent is the Sandbox spec.state field, so both RPCs are compare-and-set
// spec patches that return the CRD projection immediately; the Controller
// converges (checkpoint task, runtime release) asynchronously and clients
// observe runtime_state PAUSED/READY via GetSandbox.

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	fastpathv2 "fast-sandbox/api/proto/v2"
	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	orchestration "fast-sandbox/internal/controlplane/orchestrator"
)

func (s *Server) PauseSandbox(ctx context.Context, request *fastpathv2.PauseSandboxRequest) (*fastpathv2.PauseSandboxResponse, error) {
	if request == nil || request.Sandbox == nil {
		return nil, status.Error(codes.InvalidArgument, "sandbox reference is required")
	}
	if request.RequestId != "" {
		if err := ValidateRequestID(request.RequestId); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	sandbox, err := s.sandboxFromReferenceAtGeneration(ctx, request.Sandbox, request.ExpectedGeneration)
	if err != nil {
		return nil, err
	}
	if sandbox.DeletionTimestamp != nil {
		return nil, status.Error(codes.FailedPrecondition, "Sandbox is being deleted")
	}
	// Pause is impossible once the runtime is terminal or tearing down
	// (Stopping); every other state (including an in-flight create) simply
	// waits for Ready in the Controller. An effective pause replayed here is
	// an idempotent success.
	switch sandbox.Status.Runtime.State {
	case apiv1alpha2.RuntimeStopped, apiv1alpha2.RuntimeFailed, apiv1alpha2.RuntimeStopping:
		return nil, status.Errorf(codes.FailedPrecondition, "Sandbox runtime is %q; only a Ready runtime can be paused", sandbox.Status.Runtime.State)
	}
	updated, err := s.patchSandboxState(ctx, sandbox, apiv1alpha2.SandboxStatePaused, request.ExpectedGeneration, request.Sandbox.ExpectedUid)
	if err != nil {
		return nil, err
	}
	klog.FromContext(ctx).Info("fastpath sandbox pause requested")
	return &fastpathv2.PauseSandboxResponse{Sandbox: sandboxInfoFromCRD(updated), Generation: updated.Generation}, nil
}

func (s *Server) ResumeSandbox(ctx context.Context, request *fastpathv2.ResumeSandboxRequest) (*fastpathv2.ResumeSandboxResponse, error) {
	if request == nil || request.Sandbox == nil {
		return nil, status.Error(codes.InvalidArgument, "sandbox reference is required")
	}
	if request.RequestId != "" {
		if err := ValidateRequestID(request.RequestId); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	sandbox, err := s.sandboxFromReferenceAtGeneration(ctx, request.Sandbox, request.ExpectedGeneration)
	if err != nil {
		return nil, err
	}
	if sandbox.DeletionTimestamp != nil {
		return nil, status.Error(codes.FailedPrecondition, "Sandbox is being deleted")
	}
	// The desired state is already Running (a resumed or never-paused
	// Sandbox): idempotent success. This also covers a replay while the
	// resume is still converging.
	if sandbox.Spec.State != apiv1alpha2.SandboxStatePaused {
		return &fastpathv2.ResumeSandboxResponse{Sandbox: sandboxInfoFromCRD(sandbox), Generation: sandbox.Generation}, nil
	}
	// The pause was released (runtime Paused): resuming requires the durable
	// checkpoint. Before the release a checkpoint may not exist yet and the
	// Resume intent simply cancels the pause.
	if sandbox.Status.Runtime.State == apiv1alpha2.RuntimePaused && sandbox.Status.Runtime.Checkpoint == nil {
		return nil, status.Error(codes.FailedPrecondition, "Sandbox has no recorded checkpoint; resume is impossible, use resetRevision to start a fresh instance")
	}
	checkpoint := sandbox.Status.Runtime.Checkpoint
	if checkpoint != nil && request.ExpectedCheckpointId != "" && request.ExpectedCheckpointId != checkpoint.CheckpointID {
		return nil, status.Errorf(codes.Aborted, "checkpoint changed: expected %s, current %s", request.ExpectedCheckpointId, checkpoint.CheckpointID)
	}
	if sandbox.Status.Runtime.State == apiv1alpha2.RuntimePaused {
		if err := s.resumeHasRoom(ctx, sandbox); err != nil {
			return nil, err
		}
	}
	updated, err := s.patchSandboxState(ctx, sandbox, apiv1alpha2.SandboxStateRunning, request.ExpectedGeneration, request.Sandbox.ExpectedUid)
	if err != nil {
		return nil, err
	}
	klog.FromContext(ctx).Info("fastpath sandbox resume requested")
	return &fastpathv2.ResumeSandboxResponse{Sandbox: sandboxInfoFromCRD(updated), Generation: updated.Generation}, nil
}

// resumeHasRoom refuses the resume of a released pause when no Fastlet in
// the Sandbox's Pool can take it now. Such a resume would otherwise be
// accepted and leave the Sandbox in Resuming (NoCandidate), retried with no
// time limit until room frees up, or until the Sandbox expires and its
// checkpoint is dropped; the caller would see success for a Sandbox that
// doesn't run. Refused, it stays paused and the caller gets
// RESOURCE_EXHAUSTED, as a create into a full Pool does.
//
// The check is the create path's candidate query (selectFastletsForPool):
// the same Pool, the Sandbox's own resources, the Fastlet revision and the
// Registry's cordon and freshness filtering, made before the intent is
// persisted and without extra Kubernetes IO beyond the Pool read. It can't
// reserve the room: a resume that passes and then loses the room to another
// Sandbox still waits, as before. If the check itself can't run (no Pool,
// no Registry, unresolvable resources), the resume goes through unchanged,
// for the Controller to report as it does today.
func (s *Server) resumeHasRoom(ctx context.Context, sandbox *apiv1alpha2.Sandbox) error {
	logger := klog.FromContext(ctx)
	orchestrator, err := s.orchestrator()
	if err != nil {
		logger.Info("fastpath sandbox resume room check skipped", "pool", sandbox.Spec.PoolRef, "err", err)
		return nil
	}
	pool, err := s.getPool(ctx, sandbox.Namespace, sandbox.Spec.PoolRef)
	if err != nil {
		logger.Info("fastpath sandbox resume room check skipped", "pool", sandbox.Spec.PoolRef, "err", err)
		return nil
	}
	parameters, err := fastPathRuntimeParameters(pool, sandbox)
	if err != nil {
		logger.Info("fastpath sandbox resume room check skipped", "pool", sandbox.Spec.PoolRef, "err", err)
		return nil
	}
	candidates, err := orchestrator.FastPathCandidatesMatching(sandbox, string(sandbox.UID), parameters, nil)
	if err != nil && !errors.Is(err, orchestration.ErrNoCandidate) {
		logger.Info("fastpath sandbox resume room check skipped", "pool", sandbox.Spec.PoolRef, "err", err)
		return nil
	}
	if len(compatibleCandidates(candidates, parameters.FastletRevision)) == 0 {
		logger.Info("fastpath sandbox resume refused: no Fastlet has room", "pool", sandbox.Spec.PoolRef)
		return status.Errorf(codes.ResourceExhausted, "no Fastlet in Pool %q has room to resume the Sandbox; it stays paused", sandbox.Spec.PoolRef)
	}
	return nil
}

// patchSandboxState compare-and-set patches spec.state, fenced by the
// optional expected generation and UID. A no-op patch (state already
// desired) still returns the current object, which makes both RPCs replay
// safe.
func (s *Server) patchSandboxState(ctx context.Context, sandbox *apiv1alpha2.Sandbox, state apiv1alpha2.SandboxState, expectedGeneration int64, expectedUID string) (*apiv1alpha2.Sandbox, error) {
	key := client.ObjectKeyFromObject(sandbox)
	var updated apiv1alpha2.Sandbox
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current apiv1alpha2.Sandbox
		if err := s.K8sClient.Get(ctx, key, &current); err != nil {
			return err
		}
		if err := checkExpectedGeneration(&current, expectedGeneration); err != nil {
			return err
		}
		if err := checkReferenceUID(&current, expectedUID); err != nil {
			return err
		}
		if current.Spec.State == state {
			updated = current
			return nil
		}
		current.Spec.State = state
		if err := s.K8sClient.Update(ctx, &current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	if err != nil {
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		return nil, grpcKubernetesError(err)
	}
	return &updated, nil
}
