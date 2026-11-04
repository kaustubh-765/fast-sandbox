package reconciler

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"fast-sandbox/internal/controlplane/placement"
)

// NodeSchedulabilityReconciler mirrors each Node's spec.unschedulable (cordon)
// into the placement Registry. Operators retire worker nodes by cordoning
// them: placement then stops choosing Fastlets there in every resource mode,
// and Pool scale-down drains idle Fastlets on those nodes first. It only
// writes process-local state, so it runs on every replica (FastPath replicas
// included) without leader election.
type NodeSchedulabilityReconciler struct {
	Client   client.Reader
	Registry placement.NodeSchedulabilityRegistry
}

// Reconcile records the Node's cordon state, clearing it once the Node is gone.
func (r *NodeSchedulabilityReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var node corev1.Node
	if err := r.Client.Get(ctx, request.NamespacedName, &node); err != nil {
		if apierrors.IsNotFound(err) {
			r.Registry.SetNodeUnschedulable(request.Name, false)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	r.Registry.SetNodeUnschedulable(node.Name, node.Spec.Unschedulable)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the Node watch. Status-only Node updates (the
// kubelet heartbeats) are filtered out; only creates, deletes and cordon
// changes enqueue.
func (r *NodeSchedulabilityReconciler) SetupWithManager(manager ctrl.Manager) error {
	needLeaderElection := false
	return ctrl.NewControllerManagedBy(manager).
		Named("node-schedulability").
		For(&corev1.Node{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(update event.UpdateEvent) bool {
				previous, previousOK := update.ObjectOld.(*corev1.Node)
				current, currentOK := update.ObjectNew.(*corev1.Node)
				return !previousOK || !currentOK || previous.Spec.Unschedulable != current.Spec.Unschedulable
			},
		})).
		WithOptions(controller.Options{NeedLeaderElection: &needLeaderElection}).
		Complete(r)
}

// TrimNodeForCache is the manager cache transform for Nodes. Placement only
// needs spec.unschedulable, so the cached copy drops status (images,
// conditions, addresses), annotations and managed fields to keep the
// cluster-wide Node cache light. Anything reading Nodes through the manager
// cache sees only these fields.
func TrimNodeForCache(object any) (any, error) {
	node, ok := object.(*corev1.Node)
	if !ok {
		return object, nil
	}
	return &corev1.Node{
		TypeMeta: node.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:              node.Name,
			UID:               node.UID,
			ResourceVersion:   node.ResourceVersion,
			Generation:        node.Generation,
			CreationTimestamp: node.CreationTimestamp,
			DeletionTimestamp: node.DeletionTimestamp,
			Labels:            node.Labels,
		},
		Spec: corev1.NodeSpec{Unschedulable: node.Spec.Unschedulable},
	}, nil
}
