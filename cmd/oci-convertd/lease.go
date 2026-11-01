package main

// Cluster-wide conversion lock. With more than one oci-convertd replica, two
// replicas asked for the same new image would both run the convertor and push
// different obd- manifests to one tag; the loser's layers would be orphaned
// for registry GC while a fastlet may already reference them. A Kubernetes
// Lease per source manifest makes one replica convert while the others wait;
// the winner's tag is re-checked after the lock is taken.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	leaseDuration = 30 * time.Second
	leaseRenew    = 10 * time.Second
	leasePoll     = 2 * time.Second
)

// lockFunc takes the cluster lock of key, blocking until it is held or ctx
// ends; unlock releases it.
type lockFunc func(ctx context.Context, key string) (unlock func(), err error)

type leaseLocker struct {
	client    kubernetes.Interface
	namespace string
	identity  string
	now       func() time.Time
	poll      time.Duration
}

// leaseName maps a conversion key to a valid, bounded Lease name.
func leaseName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "oci-convertd-" + hex.EncodeToString(sum[:10])
}

func (l *leaseLocker) lock(ctx context.Context, key string) (func(), error) {
	name := leaseName(key)
	leases := l.client.CoordinationV1().Leases(l.namespace)
	for {
		held, err := l.tryAcquire(ctx, name)
		if err != nil {
			log.Printf("lease %s: %v", name, err)
		}
		if held {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for conversion lock of %s: %w", key, ctx.Err())
		case <-time.After(l.poll):
		}
	}
	renewCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(leaseRenew)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				if _, err := l.tryAcquire(renewCtx, name); err != nil {
					log.Printf("renew lease %s: %v", name, err)
				}
			}
		}
	}()
	return func() {
		stop()
		<-done
		lease, err := leases.Get(context.Background(), name, metav1.GetOptions{})
		if err != nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != l.identity {
			return
		}
		version := lease.ResourceVersion
		if err := leases.Delete(context.Background(), name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &version}}); err != nil && !apierrors.IsNotFound(err) {
			log.Printf("release lease %s: %v", name, err)
		}
	}, nil
}

// tryAcquire creates the Lease, renews it when this replica holds it, or
// takes it over once its holder stopped renewing. It reports whether this
// replica holds the Lease afterwards.
func (l *leaseLocker) tryAcquire(ctx context.Context, name string) (bool, error) {
	leases := l.client.CoordinationV1().Leases(l.namespace)
	now := metav1.NewMicroTime(l.now())
	seconds := int32(leaseDuration / time.Second)
	lease, err := leases.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = leases.Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: l.namespace, Labels: map[string]string{"app": "oci-convertd"}},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity: &l.identity, LeaseDurationSeconds: &seconds, AcquireTime: &now, RenewTime: &now,
			},
		}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	mine := lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == l.identity
	if !mine && !leaseExpired(lease, l.now()) {
		return false, nil
	}
	if !mine {
		lease.Spec.HolderIdentity = &l.identity
		lease.Spec.AcquireTime = &now
	}
	lease.Spec.LeaseDurationSeconds = &seconds
	lease.Spec.RenewTime = &now
	// The update carries the read resourceVersion: of two replicas taking
	// over an expired Lease at once, one gets a conflict and keeps waiting.
	if _, err := leases.Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func leaseExpired(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return true
	}
	return now.After(lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second))
}
