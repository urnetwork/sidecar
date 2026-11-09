// §9.10's fair queue on a fake clock: turns by network, shedding only when saturated and then the
// heaviest network first, a wait past its bound, and running calls never touched. Every ordering is
// forced by waiting for the queue to report each call queued, never by sleeping.

package socketsservice_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A queue on its own fake clock.
func testSocketFairQueue(concurrency int, queueCount int) (*socketsservice.SocketFairQueue, *sidecartest.FakeClock, *socketsservice.SocketFairQueueSettings) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketFairQueueSettings()
	settings.Concurrency = concurrency
	settings.QueueCount = queueCount
	return socketsservice.NewSocketFairQueue(settings, clock), clock, settings
}

// What one queued call came to.
type testSocketAdmission struct {
	name    string
	release func()
	err     error
}

// Starts a call for networkId that reports on admissions once decided, and waits until the queue holds
// it, so calls queue in the order a test starts them.
func testSocketQueueCall(t *testing.T, ctx context.Context, queue *socketsservice.SocketFairQueue, name string, networkId connect.Id, admissions chan<- *testSocketAdmission) {
	t.Helper()
	_, waitingCount := queue.Counts()
	go func() {
		release, err := queue.Acquire(ctx, networkId)
		admissions <- &testSocketAdmission{name: name, release: release, err: err}
	}()
	if err := queue.AwaitWaiting(ctx, waitingCount+1); err != nil {
		t.Fatalf("%s never queued: %v", name, err)
	}
}

func TestSocketFairQueueRunsUpToItsConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, _, _ := testSocketFairQueue(2, 10)
	networkId := testSocketId()
	firstRelease, err := queue.Acquire(ctx, networkId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Acquire(ctx, networkId); err != nil {
		t.Fatal(err)
	}
	admissions := make(chan *testSocketAdmission, 1)
	testSocketQueueCall(t, ctx, queue, "third", networkId, admissions)
	select {
	case admission := <-admissions:
		t.Fatalf("the third call ran past the concurrency: %v", admission.err)
	default:
	}
	firstRelease()
	admission := <-admissions
	if admission.err != nil {
		t.Fatal(admission.err)
	}
	if running, waiting := queue.Counts(); running != 2 || waiting != 0 {
		t.Fatalf("%d running, %d waiting", running, waiting)
	}
}

// Networks with waiting calls take turns: a network's burst queued first does not run first.
func TestSocketFairQueueTakesNetworksInTurn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, _, _ := testSocketFairQueue(1, 10)
	heavyId := testSocketId()
	lightId := testSocketId()
	holderRelease, err := queue.Acquire(ctx, heavyId)
	if err != nil {
		t.Fatal(err)
	}
	admissions := make(chan *testSocketAdmission, 4)
	for _, name := range []string{"heavy1", "heavy2", "heavy3"} {
		testSocketQueueCall(t, ctx, queue, name, heavyId, admissions)
	}
	testSocketQueueCall(t, ctx, queue, "light1", lightId, admissions)

	order := []string{}
	release := holderRelease
	for range 4 {
		release()
		admission := <-admissions
		if admission.err != nil {
			t.Fatalf("%s: %v", admission.name, admission.err)
		}
		order = append(order, admission.name)
		release = admission.release
	}
	release()
	want := []string{"heavy1", "light1", "heavy2", "heavy3"}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
}

// Nothing is shed until the waiting room is full, and then the heaviest network's newest call goes
// first, or the arrival when its own network is the heaviest.
func TestSocketFairQueueShedsTheHeaviestOnlyWhenSaturated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, _, _ := testSocketFairQueue(1, 3)
	heavyId := testSocketId()
	lightId := testSocketId()
	holderRelease, err := queue.Acquire(ctx, heavyId)
	if err != nil {
		t.Fatal(err)
	}
	admissions := make(chan *testSocketAdmission, 8)
	testSocketQueueCall(t, ctx, queue, "heavy1", heavyId, admissions)
	testSocketQueueCall(t, ctx, queue, "heavy2", heavyId, admissions)
	testSocketQueueCall(t, ctx, queue, "light1", lightId, admissions)
	select {
	case admission := <-admissions:
		t.Fatalf("%s was decided before saturation", admission.name)
	default:
	}

	// a light arrival in a full room sheds the heavy network's newest
	go func() {
		release, err := queue.Acquire(ctx, lightId)
		admissions <- &testSocketAdmission{name: "light2", release: release, err: err}
	}()
	shed := <-admissions
	if shed.name != "heavy2" || !errors.Is(shed.err, socketsservice.ErrSocketShed) {
		t.Fatalf("%s shed: %v", shed.name, shed.err)
	}
	if err := queue.AwaitWaiting(ctx, 3); err != nil {
		t.Fatal(err)
	}

	// a heavy arrival is itself the heaviest, so it goes
	if _, err := queue.Acquire(ctx, heavyId); !errors.Is(err, socketsservice.ErrSocketShed) {
		t.Fatalf("the heaviest arrival: %v", err)
	}

	// what was not shed runs, in turn
	release := holderRelease
	ran := map[string]bool{}
	for range 3 {
		release()
		admission := <-admissions
		if admission.err != nil {
			t.Fatalf("%s: %v", admission.name, admission.err)
		}
		ran[admission.name] = true
		release = admission.release
	}
	release()
	for _, name := range []string{"heavy1", "light1", "light2"} {
		if !ran[name] {
			t.Errorf("%s never ran", name)
		}
	}
}

func TestSocketFairQueueShedsAWaitPastItsBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, clock, settings := testSocketFairQueue(1, 10)
	networkId := testSocketId()
	holderRelease, err := queue.Acquire(ctx, networkId)
	if err != nil {
		t.Fatal(err)
	}
	defer holderRelease()
	admissions := make(chan *testSocketAdmission, 1)
	testSocketQueueCall(t, ctx, queue, "late", networkId, admissions)
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(settings.MaxWait - time.Millisecond)
	select {
	case admission := <-admissions:
		t.Fatalf("decided before its bound: %v", admission.err)
	default:
	}
	clock.Advance(time.Millisecond)
	if admission := <-admissions; !errors.Is(admission.err, socketsservice.ErrSocketShed) {
		t.Fatalf("at its bound: %v", admission.err)
	}
	if _, waiting := queue.Counts(); waiting != 0 {
		t.Fatalf("%d still waiting", waiting)
	}
}

// A caller that gives up leaves the line at once, and the turn it held passes on.
func TestSocketFairQueueCallerGivingUpLeaves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, _, _ := testSocketFairQueue(1, 10)
	networkId := testSocketId()
	holderRelease, err := queue.Acquire(ctx, networkId)
	if err != nil {
		t.Fatal(err)
	}
	callCtx, callCancel := context.WithCancel(ctx)
	admissions := make(chan *testSocketAdmission, 2)
	testSocketQueueCall(t, callCtx, queue, "quitter", networkId, admissions)
	testSocketQueueCall(t, ctx, queue, "stayer", networkId, admissions)
	callCancel()
	quitter := <-admissions
	if quitter.name != "quitter" || !errors.Is(quitter.err, context.Canceled) {
		t.Fatalf("%s: %v", quitter.name, quitter.err)
	}
	holderRelease()
	stayer := <-admissions
	if stayer.err != nil {
		t.Fatal(stayer.err)
	}
	stayer.release()
	if running, waiting := queue.Counts(); running != 0 || waiting != 0 {
		t.Fatalf("%d running, %d waiting", running, waiting)
	}
}

// Calls already running are never shed, however full the waiting room gets (§9.10: established use is
// never charged).
func TestSocketFairQueueNeverShedsRunningCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	queue, _, _ := testSocketFairQueue(2, 1)
	heavyId := testSocketId()
	releases := []func(){}
	for range 2 {
		release, err := queue.Acquire(ctx, heavyId)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	admissions := make(chan *testSocketAdmission, 1)
	testSocketQueueCall(t, ctx, queue, "light", testSocketId(), admissions)
	// the heavy network, running two, is the heaviest, so its arrivals are shed and nothing else
	for range 5 {
		if _, err := queue.Acquire(ctx, heavyId); !errors.Is(err, socketsservice.ErrSocketShed) {
			t.Fatalf("a heavy arrival: %v", err)
		}
	}
	if running, waiting := queue.Counts(); running != 2 || waiting != 1 {
		t.Fatalf("%d running, %d waiting", running, waiting)
	}
	releases[0]()
	if admission := <-admissions; admission.err != nil {
		t.Fatal(admission.err)
	} else {
		admission.release()
	}
	releases[1]()
	// a release is once only
	releases[1]()
	if running, _ := queue.Counts(); running != 0 {
		t.Fatalf("%d running", running)
	}
}
