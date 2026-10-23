package action

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
	actionapi "fast-sandbox/internal/protocol/action"
	fastletapi "fast-sandbox/internal/protocol/fastlet"
)

type recordedRequest struct {
	port    int32
	request actionapi.Request
}

type recordedRelay struct {
	port       int32
	sandboxUID string
	method     string
	path       string
	body       []byte
}

type fakeCaller struct {
	mu                  sync.Mutex
	instanceID          string
	vaultTransfer       bool
	policyTransfer      bool
	templateStateExport bool
	statusErr           error
	requests            []recordedRequest
	fail                map[actionapi.Operation]int
	statusCall          atomic.Int32
	relayCalls          []recordedRelay
	relayStatus         int
	relayBody           []byte
	relayErr            error
}

func (f *fakeCaller) Status(context.Context, int32) (actionapi.HandlerStatus, error) {
	f.statusCall.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return actionapi.HandlerStatus{}, f.statusErr
	}
	return actionapi.HandlerStatus{
		APIVersion: actionapi.APIVersion, Ready: true, InstanceID: f.instanceID,
		VaultTransfer:       f.vaultTransfer,
		PolicyTransfer:      f.policyTransfer,
		TemplateStateExport: f.templateStateExport,
	}, nil
}

func (f *fakeCaller) Invoke(_ context.Context, port int32, request actionapi.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, recordedRequest{port: port, request: request})
	if f.fail[request.Operation] > 0 {
		f.fail[request.Operation]--
		return errors.New("injected failure")
	}
	return nil
}

func (f *fakeCaller) snapshot() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}

func (f *fakeCaller) Relay(_ context.Context, port int32, sandboxUID, method, path string, body []byte) (int, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relayCalls = append(f.relayCalls, recordedRelay{port: port, sandboxUID: sandboxUID, method: method, path: path, body: append([]byte(nil), body...)})
	if f.relayErr != nil {
		return 0, nil, f.relayErr
	}
	status := f.relayStatus
	if status == 0 {
		status = http.StatusOK
	}
	return status, f.relayBody, nil
}

func handler(name string, port int32, hooks ...apiv1alpha2.LifecycleHook) apiv1alpha2.ActionHandler {
	return apiv1alpha2.ActionHandler{Name: name, TargetHTTPPort: port, Hooks: hooks}
}

func attachment(uid string) Attachment {
	return Attachment{
		ID: "attachment-" + uid, SandboxUID: uid, SandboxName: "sandbox-" + uid,
		InstanceGeneration: 1, AssignmentAttempt: 1,
		RuntimeInstanceID: "runtime-" + uid, RouteGeneration: 1,
		IP: "172.30.0.2", Gateway: "172.30.0.1", PrivateCIDR: "172.30.0.0/24", HostVeth: "host-" + uid,
	}
}

func input(name, value string) DesiredInput { return DesiredInput{Handler: name, Input: value} }

func readyManager(t *testing.T, handlers []apiv1alpha2.ActionHandler, caller *fakeCaller) *Manager {
	t.Helper()
	manager, err := NewManager(handlers, caller)
	require.NoError(t, err)
	manager.probe(context.Background())
	require.True(t, manager.Ready())
	return manager
}

func TestBindingAndLifecycleHooksAreOrderedOrthogonally(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	hooks := []apiv1alpha2.LifecycleHook{apiv1alpha2.LifecycleHookRuntimeReady, apiv1alpha2.LifecycleHookDataPlaneReady}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{
		handler("audit", 18081, hooks...), handler("egress", 18080, hooks...),
	}, caller)
	desired := []DesiredInput{input("audit", "audit: raw"), input("egress", `{"policy":"deny"}`)}

	statuses, generation, err := manager.Reconcile(context.Background(), attachment("a"), 1, desired)
	require.NoError(t, err)
	require.Equal(t, int64(1), generation)
	require.Len(t, statuses, 2)
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookRuntimeReady, 1))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookDataPlaneReady, 2))

	requests := caller.snapshot()
	require.Len(t, requests, 6)
	require.Equal(t, []int32{18081, 18080, 18081, 18080, 18081, 18080}, requestPorts(requests))
	require.Equal(t, []actionapi.Operation{
		actionapi.OperationSetBinding, actionapi.OperationSetBinding,
		actionapi.OperationLifecycleHook, actionapi.OperationLifecycleHook,
		actionapi.OperationLifecycleHook, actionapi.OperationLifecycleHook,
	}, requestOperations(requests))
	require.Equal(t, "audit: raw", *requests[0].request.Binding.Input)
	require.Equal(t, actionapi.LifecycleHookRuntimeReady, requests[2].request.Hook.Name)
	require.Equal(t, actionapi.LifecycleHookDataPlaneReady, requests[4].request.Hook.Name)
}

// TestSetBindingDefersWhileAttachmentHasNoNetwork pins the #136 fix: desired
// Bindings registered at admission precede the runtime, so the attachment has
// no IP and every Handler would reject the envelope with 400. The Bindings
// park as Pending-with-reason with no Handler I/O until the post-boot
// attachment re-registration carries the IP and convergence fires.
func TestSetBindingDefersWhileAttachmentHasNoNetwork(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	unattached := attachment("a")
	unattached.IP = ""

	require.NoError(t, manager.RegisterDesired(unattached, 1, []DesiredInput{input("egress", "v1")}))
	require.Empty(t, caller.snapshot(), "an IP-less attachment must not reach the Handler")
	var statuses []fastletapi.ActionBindingStatus
	var applied int64
	require.Eventually(t, func() bool {
		statuses, applied = manager.Statuses("a")
		return len(statuses) == 1 && statuses[0].State == string(apiv1alpha2.ActionPending) &&
			strings.Contains(statuses[0].Message, "network attachment has no IP") && applied == 0
	}, time.Second, 10*time.Millisecond)

	manager.probe(context.Background())
	require.Empty(t, caller.snapshot(), "probe ticks must not turn the parked Binding into Handler traffic")

	attached := attachment("a")
	require.NoError(t, manager.RegisterDesired(attached, 1, []DesiredInput{input("egress", "v1")}))
	require.Eventually(t, func() bool {
		statuses, applied = manager.Statuses("a")
		return len(statuses) == 1 && statuses[0].State == string(apiv1alpha2.ActionReady) && applied == 1
	}, time.Second, 10*time.Millisecond)
	requests := caller.snapshot()
	require.Len(t, requests, 1)
	require.Equal(t, actionapi.OperationSetBinding, requests[0].request.Operation)
	require.Equal(t, attached.IP, requests[0].request.Attachment.Network.IP)
	require.Equal(t, "v1", *requests[0].request.Binding.Input)
}

func TestOrdinaryInputUpdateDoesNotReplayReachedHooks(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{
		handler("egress", 18080, apiv1alpha2.LifecycleHookRuntimeReady, apiv1alpha2.LifecycleHookDataPlaneReady),
	}, caller)
	require.NoError(t, manager.RegisterDesired(attachment("a"), 1, []DesiredInput{input("egress", "v1")}))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookRuntimeReady, 1))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookDataPlaneReady, 2))
	before := len(caller.snapshot())

	statuses, applied, err := manager.Reconcile(context.Background(), attachment("a"), 2, []DesiredInput{input("egress", "v2")})
	require.NoError(t, err)
	require.Equal(t, int64(2), applied)
	require.Equal(t, "Ready", statuses[0].State)
	requests := caller.snapshot()[before:]
	require.Len(t, requests, 1)
	require.Equal(t, actionapi.OperationSetBinding, requests[0].request.Operation)
	require.Equal(t, "v2", *requests[0].request.Binding.Input)
}

func TestNewBindingAfterCheckpointsReceivesSetThenHookReplay(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{
		handler("audit", 18081, apiv1alpha2.LifecycleHookRuntimeReady, apiv1alpha2.LifecycleHookDataPlaneReady),
	}, caller)
	require.NoError(t, manager.RegisterDesired(attachment("a"), 1, nil))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookRuntimeReady, 1))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookDataPlaneReady, 2))

	_, _, err := manager.Reconcile(context.Background(), attachment("a"), 2, []DesiredInput{input("audit", "new")})
	require.NoError(t, err)
	requests := caller.snapshot()
	require.Equal(t, []actionapi.Operation{
		actionapi.OperationSetBinding, actionapi.OperationLifecycleHook, actionapi.OperationLifecycleHook,
	}, requestOperations(requests))
}

func TestOpaqueInputPresenceAndReverseRemovalSemantics(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("first", 18080), handler("second", 18081)}, caller)

	_, _, err := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("first", ""), input("second", "null")})
	require.NoError(t, err)
	requests := caller.snapshot()
	require.NotNil(t, requests[0].request.Binding.Input)
	require.Equal(t, "", *requests[0].request.Binding.Input)
	require.Equal(t, "null", *requests[1].request.Binding.Input)

	_, _, err = manager.Reconcile(context.Background(), attachment("a"), 2, nil)
	require.NoError(t, err)
	requests = caller.snapshot()
	require.Equal(t, []int32{18081, 18080}, requestPorts(requests[2:4]))
	for _, request := range requests[2:4] {
		require.Equal(t, actionapi.OperationSetBinding, request.request.Operation)
		require.NotNil(t, request.request.Binding)
		require.Nil(t, request.request.Binding.Input)
	}
}

func TestHandlerRestartReplaysSetThenReachedHooks(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{
		handler("egress", 18080, apiv1alpha2.LifecycleHookRuntimeReady, apiv1alpha2.LifecycleHookDataPlaneReady),
	}, caller)
	_, _, err := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
	require.NoError(t, err)
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookRuntimeReady, 1))
	require.NoError(t, manager.ReachHook(context.Background(), "a", attachment("a"), actionapi.LifecycleHookDataPlaneReady, 2))
	before := len(caller.snapshot())

	caller.mu.Lock()
	caller.instanceID = "handler-2"
	caller.mu.Unlock()
	manager.probe(context.Background())
	require.Eventually(t, func() bool { return len(caller.snapshot()) >= before+3 }, time.Second, 10*time.Millisecond)
	replayed := caller.snapshot()[before : before+3]
	require.Equal(t, []actionapi.Operation{
		actionapi.OperationSetBinding, actionapi.OperationLifecycleHook, actionapi.OperationLifecycleHook,
	}, requestOperations(replayed))
	require.Equal(t, "Ready", mustStatus(t, manager, "a").State)
}

func TestFailedInvocationIsReadyBarrierAndRetryReusesIdentity(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: map[actionapi.Operation]int{actionapi.OperationSetBinding: 1}}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	desired := []DesiredInput{input("egress", "v1")}

	statuses, applied, err := manager.Reconcile(context.Background(), attachment("a"), 1, desired)
	require.Error(t, err)
	require.Zero(t, applied)
	require.Equal(t, "Failed", statuses[0].State)
	firstID := caller.snapshot()[0].request.InvocationID

	statuses, applied, err = manager.Reconcile(context.Background(), attachment("a"), 1, desired)
	require.NoError(t, err)
	require.Equal(t, int64(1), applied)
	require.Equal(t, "Ready", statuses[0].State)
	require.Equal(t, firstID, caller.snapshot()[1].request.InvocationID)
}

func TestStatusesDoNotWaitForSlowHandlerIO(t *testing.T) {
	caller := &blockingCaller{entered: make(chan struct{}), release: make(chan struct{})}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	require.NoError(t, err)
	manager.probe(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, reconcileErr := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("egress", "v1")})
		done <- reconcileErr
	}()
	<-caller.entered
	started := time.Now()
	statuses, _ := manager.Statuses("a")
	require.Less(t, time.Since(started), 100*time.Millisecond)
	require.Equal(t, "Applying", statuses[0].State)
	close(caller.release)
	require.NoError(t, <-done)
}

type blockingCaller struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingCaller) Status(context.Context, int32) (actionapi.HandlerStatus, error) {
	return actionapi.HandlerStatus{APIVersion: actionapi.APIVersion, Ready: true, InstanceID: "handler-1"}, nil
}

func (b *blockingCaller) Invoke(context.Context, int32, actionapi.Request) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return nil
}

func (*blockingCaller) Relay(context.Context, int32, string, string, string, []byte) (int, []byte, error) {
	return http.StatusOK, nil, nil
}

func TestDifferentSandboxesInvokeConcurrently(t *testing.T) {
	caller := &multiBlockingCaller{entered: make(chan string, 2), release: make(chan struct{})}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	require.NoError(t, err)
	manager.probe(context.Background())
	done := make(chan error, 2)
	for _, uid := range []string{"a", "b"} {
		uid := uid
		go func() {
			_, _, reconcileErr := manager.Reconcile(context.Background(), attachment(uid), 1, []DesiredInput{input("egress", uid)})
			done <- reconcileErr
		}()
	}
	seen := map[string]bool{}
	for range 2 {
		select {
		case uid := <-caller.entered:
			seen[uid] = true
		case <-time.After(time.Second):
			t.Fatal("different Sandboxes were serialized")
		}
	}
	close(caller.release)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Equal(t, map[string]bool{"a": true, "b": true}, seen)
}

type multiBlockingCaller struct {
	entered chan string
	release chan struct{}
}

func (*multiBlockingCaller) Status(context.Context, int32) (actionapi.HandlerStatus, error) {
	return actionapi.HandlerStatus{APIVersion: actionapi.APIVersion, Ready: true, InstanceID: "handler-1"}, nil
}

func (b *multiBlockingCaller) Invoke(_ context.Context, _ int32, request actionapi.Request) error {
	b.entered <- request.Sandbox.UID
	<-b.release
	return nil
}

func (*multiBlockingCaller) Relay(context.Context, int32, string, string, string, []byte) (int, []byte, error) {
	return http.StatusOK, nil, nil
}

func TestDeleteUsesReverseOrderAndForgetsStateOnFailure(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("first", 18080), handler("second", 18081)}, caller)
	_, _, err := manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("first", "1"), input("second", "2")})
	require.NoError(t, err)
	caller.mu.Lock()
	caller.fail[actionapi.OperationRemoveBinding] = 1
	caller.mu.Unlock()

	err = manager.Delete(context.Background(), "a")
	require.Error(t, err)
	requests := caller.snapshot()
	require.Equal(t, []int32{18081, 18080}, requestPorts(requests[2:]))
	require.Equal(t, actionapi.OperationRemoveBinding, requests[2].request.Operation)
	require.Nil(t, requests[2].request.Binding)
	statuses, generation := manager.Statuses("a")
	require.Nil(t, statuses)
	require.Zero(t, generation)
}

func TestDeleteFencesLateWorkForTheSameAttachment(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager := readyManager(t, []apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	oldAttachment := attachment("a")
	_, _, err := manager.Reconcile(context.Background(), oldAttachment, 1, []DesiredInput{input("egress", "v1")})
	require.NoError(t, err)
	require.NoError(t, manager.Delete(context.Background(), "a"))
	requestCount := len(caller.snapshot())

	_, _, err = manager.Reconcile(context.Background(), oldAttachment, 1, []DesiredInput{input("egress", "v1")})
	require.ErrorContains(t, err, "terminal")
	require.ErrorContains(t, manager.RecordHook("a", oldAttachment, actionapi.LifecycleHookRuntimeReady, 1), "terminal")
	require.Len(t, caller.snapshot(), requestCount, "late work must not recreate Handler state")

	newAttachment := oldAttachment
	newAttachment.ID = "attachment-a-generation-2"
	newAttachment.InstanceGeneration = 2
	newAttachment.RuntimeInstanceID = "runtime-a-generation-2"
	_, applied, err := manager.Reconcile(context.Background(), newAttachment, 1, []DesiredInput{input("egress", "v1")})
	require.NoError(t, err)
	require.Equal(t, int64(1), applied)
}

func TestDeleteUsesOneSharedContextDeadline(t *testing.T) {
	caller := &deleteDeadlineCaller{}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{handler("first", 18080), handler("second", 18081)}, caller)
	require.NoError(t, err)
	manager.probe(context.Background())
	_, _, err = manager.Reconcile(context.Background(), attachment("a"), 1, []DesiredInput{input("first", "1"), input("second", "2")})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = manager.Delete(ctx, "a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 200*time.Millisecond)
	require.Equal(t, []int32{18081}, caller.removePorts(), "deadline is shared; the next Handler does not get a fresh timeout")
}

type deleteDeadlineCaller struct {
	mu      sync.Mutex
	removes []int32
}

func (*deleteDeadlineCaller) Status(context.Context, int32) (actionapi.HandlerStatus, error) {
	return actionapi.HandlerStatus{APIVersion: actionapi.APIVersion, Ready: true, InstanceID: "handler-1"}, nil
}

func (c *deleteDeadlineCaller) Invoke(ctx context.Context, port int32, request actionapi.Request) error {
	if request.Operation != actionapi.OperationRemoveBinding {
		return nil
	}
	c.mu.Lock()
	c.removes = append(c.removes, port)
	c.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (*deleteDeadlineCaller) Relay(context.Context, int32, string, string, string, []byte) (int, []byte, error) {
	return http.StatusOK, nil, nil
}

func (c *deleteDeadlineCaller) removePorts() []int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int32(nil), c.removes...)
}

func TestStartIsIdempotent(t *testing.T) {
	caller := &fakeCaller{instanceID: "handler-1", fail: make(map[actionapi.Operation]int)}
	manager, err := NewManager([]apiv1alpha2.ActionHandler{handler("egress", 18080)}, caller)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	manager.Start(ctx)
	require.Eventually(t, func() bool { return caller.statusCall.Load() == 1 }, time.Second, 10*time.Millisecond)
	cancel()
}

func TestHTTPCallerAcceptsOnlyStatus200AndIgnoresBody(t *testing.T) {
	caller := &HTTPCaller{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("not-json"))}, nil
	})}}
	require.NoError(t, caller.Invoke(context.Background(), 18080, actionapi.Request{}))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func requestOperations(requests []recordedRequest) []actionapi.Operation {
	result := make([]actionapi.Operation, 0, len(requests))
	for _, request := range requests {
		result = append(result, request.request.Operation)
	}
	return result
}

func requestPorts(requests []recordedRequest) []int32 {
	result := make([]int32, 0, len(requests))
	for _, request := range requests {
		result = append(result, request.port)
	}
	return result
}

func mustStatus(t *testing.T, manager *Manager, uid string) fastletapi.ActionBindingStatus {
	t.Helper()
	statuses, _ := manager.Statuses(uid)
	require.Len(t, statuses, 1)
	return statuses[0]
}
