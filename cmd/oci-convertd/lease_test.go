package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
)

func newLocker(client *fake.Clientset, identity string) *leaseLocker {
	return &leaseLocker{client: client, namespace: "fsb-oci", identity: identity, now: time.Now, poll: 10 * time.Millisecond}
}

func TestLeaseNameIsValid(t *testing.T) {
	name := leaseName("library/python@sha256:" + strings.Repeat("ab", 32))
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		t.Fatalf("%s: %v", name, errs)
	}
	if name == leaseName("library/node@sha256:"+strings.Repeat("ab", 32)) {
		t.Fatal("distinct keys must map to distinct Leases")
	}
}

func TestLeaseLockExcludesOtherReplicas(t *testing.T) {
	client := fake.NewClientset()
	a, b := newLocker(client, "a"), newLocker(client, "b")
	unlockA, err := a.lock(context.Background(), "key")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := b.lock(ctx, "key"); err == nil {
		t.Fatal("a held Lease must block another replica")
	}
	if _, err := b.lock(context.Background(), "other"); err != nil {
		t.Fatalf("another key is independent: %v", err)
	}
	acquired := make(chan struct{})
	go func() {
		unlockB, err := b.lock(context.Background(), "key")
		if err == nil {
			unlockB()
		}
		close(acquired)
	}()
	unlockA()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("a released Lease must be taken by the waiting replica")
	}
}

func TestLeaseLockTakesOverAnExpiredHolder(t *testing.T) {
	client := fake.NewClientset()
	stale := metav1.NewMicroTime(time.Now().Add(-time.Hour))
	holder, seconds := "dead", int32(30)
	_, err := client.CoordinationV1().Leases("fsb-oci").Create(context.Background(), &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName("key"), Namespace: "fsb-oci"},
		Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &seconds, RenewTime: &stale},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := newLocker(client, "live").lock(ctx, "key")
	if err != nil {
		t.Fatalf("an expired Lease must be taken over: %v", err)
	}
	unlock()
	if _, err := client.CoordinationV1().Leases("fsb-oci").Get(context.Background(), leaseName("key"), metav1.GetOptions{}); err == nil {
		t.Fatal("unlock must delete the Lease")
	}
}

// Two replicas sharing one registry and one Lease namespace convert a new
// image exactly once.
func TestReplicasConvertOnce(t *testing.T) {
	first, convertor, host := setup(t)
	client := fake.NewClientset()
	first.lock = newLocker(client, "replica-1").lock
	second := newServer(host, "convertor", t.TempDir(), 64, 2, convertor.run)
	second.lock = newLocker(client, "replica-2").lock
	convertor.delay = 200 * time.Millisecond
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := range 6 {
		replica := first
		if i%2 == 1 {
			replica = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := replica.ensure(context.Background(), "python:3.12")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if convertor.calls.Load() != 1 {
		t.Fatalf("two replicas must share one conversion, got %d", convertor.calls.Load())
	}
}

// basicAuth wraps a registry so every request needs user:password.
func basicAuth(next http.Handler, user, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="zot"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestEnsureAuthenticatesToTheRegistry(t *testing.T) {
	registryServer := httptest.NewServer(basicAuth(registry.New(), "writer", "s3cret"))
	t.Cleanup(registryServer.Close)
	host := strings.TrimPrefix(registryServer.URL, "http://")
	source, err := random.Image(2048, 2)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := name.ParseReference(host+"/library/python:3.12", name.Insecure)
	if err := remote.Write(reference, source, remote.WithAuth(&authn.Basic{Username: "writer", Password: "s3cret"})); err != nil {
		t.Fatal(err)
	}
	convertor := &fakeConvertor{}
	anonymous := newServer(host, "convertor", t.TempDir(), 64, 1, convertor.run)
	if _, err := anonymous.ensure(context.Background(), "python:3.12"); err == nil {
		t.Fatal("an anonymous read of a protected registry must fail")
	}
	authenticated := newServer(host, "convertor", t.TempDir(), 64, 1, convertor.run)
	authenticated.username, authenticated.password = "writer", "s3cret"
	answer, err := authenticated.ensure(context.Background(), "python:3.12")
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Converted || len(answer.Lowers) != 2 {
		t.Fatalf("unexpected answer: %+v", answer)
	}
}
