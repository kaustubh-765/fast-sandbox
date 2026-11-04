package reconciler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	"fast-sandbox/internal/controlplane/placement"
)

func TestNodeSchedulabilityReconcilerFeedsRegistryCordonState(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{Unschedulable: true}}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
	registry := placement.NewInMemoryRegistry()
	registry.UpsertPod(placement.FastletInfo{
		ID: "fastlet-a", Namespace: "default", PodName: "fastlet-a", PodUID: "uid-a", NodeName: "node-a", PoolName: "pool-a",
	})
	reconciler := &NodeSchedulabilityReconciler{Client: k8sClient, Registry: registry}
	request := ctrl.Request{NamespacedName: client.ObjectKey{Name: "node-a"}}
	nodeUnschedulable := func() bool {
		info, ok := registry.GetFastletByID("fastlet-a")
		require.True(t, ok)
		return info.NodeUnschedulable
	}

	_, err := reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.True(t, nodeUnschedulable(), "a cordoned Node is recorded")

	node.Spec.Unschedulable = false
	require.NoError(t, k8sClient.Update(context.Background(), node))
	_, err = reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.False(t, nodeUnschedulable(), "uncordon clears the Registry entry")

	node.Spec.Unschedulable = true
	require.NoError(t, k8sClient.Update(context.Background(), node))
	_, err = reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.True(t, nodeUnschedulable())

	require.NoError(t, k8sClient.Delete(context.Background(), node))
	_, err = reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.False(t, nodeUnschedulable(), "a deleted Node never leaves a stale cordon behind")
}

func TestTrimNodeForCacheKeepsOnlySchedulability(t *testing.T) {
	deleted := metav1.Now()
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a", UID: "uid-a", ResourceVersion: "7", Labels: map[string]string{"sandbox.fast.io/kvm": "true"},
			Annotations: map[string]string{"big": "value"}, DeletionTimestamp: &deleted,
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec: corev1.NodeSpec{Unschedulable: true, PodCIDR: "10.0.0.0/24", Taints: []corev1.Taint{{Key: "k"}}},
		Status: corev1.NodeStatus{
			Images:     []corev1.ContainerImage{{Names: []string{"image"}}},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady}},
		},
	}
	trimmed, err := TrimNodeForCache(node)
	require.NoError(t, err)
	got, ok := trimmed.(*corev1.Node)
	require.True(t, ok)
	require.Equal(t, "node-a", got.Name)
	require.Equal(t, "7", got.ResourceVersion)
	require.Equal(t, node.Labels, got.Labels)
	require.Equal(t, &deleted, got.DeletionTimestamp)
	require.True(t, got.Spec.Unschedulable)
	require.Empty(t, got.Annotations)
	require.Empty(t, got.ManagedFields)
	require.Empty(t, got.Spec.PodCIDR)
	require.Empty(t, got.Spec.Taints)
	require.Equal(t, corev1.NodeStatus{}, got.Status)

	other := &apiv1alpha2.SandboxPool{}
	passthrough, err := TrimNodeForCache(other)
	require.NoError(t, err)
	require.Same(t, other, passthrough)
}

var _ placement.NodeSchedulabilityRegistry = (*placement.InMemoryRegistry)(nil)
