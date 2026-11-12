package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

type blobFixture struct {
	clock   *FakeClock
	faults  *FaultQueue
	store   *FakeBlobs
	cluster sidecar.BlobCluster
}

func newBlobFixture(t *testing.T) *blobFixture {
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	store := NewFakeBlobs(clock, faults, nil, nil)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return &blobFixture{clock: clock, faults: faults, store: store, cluster: cluster}
}

func (self *blobFixture) arm(t *testing.T, plan *FaultPlan) {
	t.Helper()
	if _, err := self.faults.Add(plan); err != nil {
		t.Fatal(err)
	}
}

func (self *blobFixture) body(t *testing.T, key string) string {
	t.Helper()
	object, err := self.cluster.Get(InspectContext(t.Context()), key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (self *blobFixture) absent(t *testing.T, key string) bool {
	t.Helper()
	_, err := self.cluster.Head(InspectContext(t.Context()), key)
	if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatal(err)
	}
	return err != nil
}

func wantUnknown(t *testing.T, err error) {
	t.Helper()
	var unknown *sidecar.BlobUnknownError
	if !errors.As(err, &unknown) {
		t.Errorf("err %v, want an unknown outcome", err)
	}
}

func TestApplyThenDropAppliesAndHidesTheAnswer(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: ApplyThenDrop})

	_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	wantUnknown(t, err)
	if got := fixture.body(t, "head/a/_"); got != "v1" {
		t.Errorf("body %q", got)
	}
}

func TestFailBeforeApplyLooksTheSameAndAppliesNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: FailBeforeApply})

	_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	wantUnknown(t, err)
	if !fixture.absent(t, "head/a/_") {
		t.Error("the write applied")
	}
}

func TestPreconditionResultFailsAWriteThatWouldPass(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: Precondition})

	_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	if !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
	if !fixture.absent(t, "head/a/_") {
		t.Error("the write applied")
	}
}

func TestHeldResultIsDefiniteAndAppliesNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: Held})
	_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	if !errors.Is(err, sidecar.ErrBlobHeld) {
		t.Errorf("err %v", err)
	}
	if !fixture.absent(t, "head/a/_") {
		t.Error("the write applied")
	}
}

func TestFaultsPickTheirOperationKeyAndNth(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Nth: 2, Result: FailBeforeApply})

	put := func(key string) error {
		_, err := fixture.cluster.PutIfNoneMatch(t.Context(), key, []byte("v"), nil)
		return err
	}
	// another prefix does not count
	if err := put("slot/a/_"); err != nil {
		t.Fatal(err)
	}
	if err := put("head/a/_"); err != nil {
		t.Fatal(err)
	}
	// nor does another operation
	if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); err != nil {
		t.Fatal(err)
	}
	wantUnknown(t, put("head/b/_"))
	if err := put("head/c/_"); err != nil {
		t.Errorf("a one-shot fired twice: %v", err)
	}
}

func TestFaultRepeatKeepsAStoreDown(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpGet, Result: FailBeforeApply, Repeat: 1})
	for range 2 {
		if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); err == nil || errors.Is(err, sidecar.ErrBlobNotFound) {
			t.Errorf("err %v", err)
		}
	}
	if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("after the plan: %v", err)
	}
}

func TestFaultRepeatNegativeLastsTheTest(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpGet, Result: FailBeforeApply, Repeat: -1})
	for range 50 {
		if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); err == nil || errors.Is(err, sidecar.ErrBlobNotFound) {
			t.Fatalf("err %v", err)
		}
	}
}

func TestFaultNarrowsToOneActorAndOneCluster(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	fixture := newBlobFixture(t)
	table := NewActorTable(fixture.clock, driver)
	segment, err := fixture.store.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: FailBeforeApply, Actor: "evs2", ClusterId: "meta-1"})

	evs1 := table.Actor(t.Context(), "evs1").Context()
	evs2 := table.Actor(t.Context(), "evs2").Context()
	if _, err := fixture.cluster.PutIfNoneMatch(evs1, "head/a/_", []byte("v"), nil); err != nil {
		t.Errorf("evs1: %v", err)
	}
	if _, err := segment.PutIfNoneMatch(evs2, "seg/a/_", []byte("v"), nil); err != nil {
		t.Errorf("the other cluster: %v", err)
	}
	_, err = fixture.cluster.PutIfNoneMatch(evs2, "head/b/_", []byte("v"), nil)
	wantUnknown(t, err)
}

func TestFakeRefusesWhatOnlyARealStoreCanDo(t *testing.T) {
	faults := NewFaultQueue()
	for _, result := range []FaultResult{QuorumLoss, DriveMiss} {
		if _, err := faults.Add(&FaultPlan{Op: FaultOpPut, Result: result}); !errors.Is(err, ErrFaultNeedsRealStore) {
			t.Errorf("%s: %v", result, err)
		}
	}
}

// A queue whose stores are real takes QuorumLoss and DriveMiss when they admit the plan, and refuses one they
// do not, while a plan no store could carry out stays refused before they are asked.
func TestARealStoreTakesWhatItAdmits(t *testing.T) {
	faults := NewFaultQueue()
	asked := []*FaultPlan{}
	faults.SetRealStore(func(plan *FaultPlan) error {
		asked = append(asked, plan)
		if plan.ClusterId == "" {
			return errors.New("names no cluster")
		}
		return nil
	})
	for _, plan := range []*FaultPlan{
		{Op: FaultOpPut, Result: QuorumLoss, ClusterId: "meta-1"},
		{Op: FaultOpGet, Result: QuorumLoss, ClusterId: "meta-1"},
		{Op: FaultOpPut, Result: DriveMiss, ClusterId: "seg-1"},
	} {
		if _, err := faults.Add(plan); err != nil {
			t.Errorf("%s: %v", plan, err)
		}
	}
	if _, err := faults.Add(&FaultPlan{Op: FaultOpPut, Result: QuorumLoss}); err == nil || !strings.Contains(err.Error(), "names no cluster") {
		t.Errorf("a plan the store refused: %v", err)
	}
	for _, plan := range []*FaultPlan{
		{Op: FaultOpGet, Result: DriveMiss, ClusterId: "meta-1"},
		{Op: FaultOpRedis, Result: QuorumLoss, ClusterId: "meta-1"},
	} {
		if _, err := faults.Add(plan); err == nil || errors.Is(err, ErrFaultNeedsRealStore) {
			t.Errorf("%s: %v", plan, err)
		}
	}
	if len(asked) != 4 {
		t.Errorf("the store was asked %d times", len(asked))
	}
	faults.SetRealStore(nil)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpPut, Result: QuorumLoss, ClusterId: "meta-1"}); !errors.Is(err, ErrFaultNeedsRealStore) {
		t.Errorf("with no real store: %v", err)
	}
}

func TestFaultPlansThatMakeNoSenseFailWhereWritten(t *testing.T) {
	cases := []*FaultPlan{
		{Op: "put-ish", Result: FailBeforeApply},
		{Op: FaultOpPut, Result: FaultResult(99)},
		{Op: FaultOpGet, Result: Precondition},
		{Op: FaultOpList, Result: Held},
		{Op: FaultOpPut, Nth: -1, Result: FailBeforeApply},
	}
	faults := NewFaultQueue()
	for _, plan := range cases {
		if _, err := faults.Add(plan); err == nil {
			t.Errorf("%s armed", plan)
		}
	}
}

func TestUnfiredFaultsAreReported(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: FailBeforeApply})
	fixture.arm(t, &FaultPlan{Op: FaultOpDelete, Result: FailBeforeApply})
	if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v"), nil); err == nil {
		t.Fatal("the plan did not fire")
	}
	unfired := fixture.faults.Unfired()
	if len(unfired) != 1 || unfired[0].Op != FaultOpDelete {
		t.Errorf("unfired %v", unfired)
	}
}

// A crash point on an apply: the call never returns and the object stands.
func TestCrashAfterApplyCommitsAndNeverReturns(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	fixture := newBlobFixture(t)
	table := NewActorTable(fixture.clock, driver)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: CrashAfterApply})

	returned := false
	actor := table.Actor(t.Context(), "evs1")
	run := driver.Start(actor, func() error {
		fixture.cluster.PutIfNoneMatch(actor.Context(), "head/a/_", []byte("v1"), nil)
		returned = true
		return nil
	})
	awaitEnded(t, run)
	driver.Reap()
	if returned {
		t.Error("a crashed process kept running")
	}
	if !actor.Killed() {
		t.Error("the crash left the actor alive")
	}
	if got := fixture.body(t, "head/a/_"); got != "v1" {
		t.Errorf("body %q", got)
	}
}

func TestCrashBeforeApplyLeavesNothing(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	fixture := newBlobFixture(t)
	table := NewActorTable(fixture.clock, driver)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: CrashBeforeApply})

	actor := table.Actor(t.Context(), "evs1")
	run := driver.Start(actor, func() error {
		fixture.cluster.PutIfNoneMatch(actor.Context(), "head/a/_", []byte("v1"), nil)
		return nil
	})
	awaitEnded(t, run)
	if !fixture.absent(t, "head/a/_") {
		t.Error("a write the process died before sending applied")
	}
}

func TestCrashOutsideAScheduleEndsTheGoroutine(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: CrashBeforeApply})
	returned := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
		returned = true
	}()
	<-done
	if returned {
		t.Error("the call returned")
	}
}

func TestADeadActorsCallStopsAtTheStore(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	fixture := newBlobFixture(t)
	table := NewActorTable(fixture.clock, driver)
	actor := table.Actor(t.Context(), "evs1")
	killed := make(chan struct{})
	run := driver.Start(actor, func() error {
		<-killed
		fixture.cluster.PutIfNoneMatch(context.WithoutCancel(actor.Context()), "head/a/_", []byte("v1"), nil)
		return nil
	})
	actor.Kill()
	close(killed)
	awaitEnded(t, run)
	if !fixture.absent(t, "head/a/_") {
		t.Error("a dead process wrote")
	}
}

// Starts a PUT under a Delay and waits until it is parked.
func startDelayedPut(t *testing.T, fixture *blobFixture, key string, etag string, body string) <-chan error {
	t.Helper()
	answered := make(chan error, 1)
	go func() {
		var err error
		if etag == "" {
			_, err = fixture.cluster.PutIfNoneMatch(t.Context(), key, []byte(body), nil)
		} else {
			_, err = fixture.cluster.PutIfMatch(t.Context(), key, etag, []byte(body), nil)
		}
		answered <- err
	}()
	// the client's timeout is the one timer a parked request sets
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	return answered
}

func TestDelayedWriteLandsBeforeTheNextRequestOnItsKey(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay})
	answered := startDelayedPut(t, fixture, "head/a/_", "", "v1")

	if !fixture.absent(t, "head/a/_") {
		t.Fatal("landed before anything asked")
	}
	// a request on another key settles nothing
	if _, err := fixture.cluster.Head(t.Context(), "head/b/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatal(err)
	}
	if fixture.store.DelayedCount() != 1 {
		t.Error("another key's request settled this one")
	}

	info, err := fixture.cluster.Head(t.Context(), "head/a/_")
	if err != nil {
		t.Fatalf("the next request did not see the write: %v", err)
	}
	if info.ByteCount != 2 {
		t.Errorf("info %+v", info)
	}
	if err := <-answered; err != nil {
		t.Errorf("the caller got %v", err)
	}
}

func TestDelayedWriteThatNeverLandsIsGoneForGood(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: DelayNeverLands})
	answered := startDelayedPut(t, fixture, "head/a/_", "", "v1")

	if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("err %v", err)
	}
	wantUnknown(t, <-answered)
	if fixture.store.DelayedCount() != 0 {
		t.Error("it stayed parked")
	}
	if !fixture.absent(t, "head/a/_") {
		t.Error("it landed after the next request")
	}
}

// A late landing is judged as of then: the condition another write moved fails it (FS-1's delayed PUT).
func TestDelayedWriteIsJudgedWhenItLands(t *testing.T) {
	fixture := newBlobFixture(t)
	etag, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: DelayInNetwork})
	answered := startDelayedPut(t, fixture, "head/a/_", etag, "delayed")

	if _, err := fixture.cluster.PutIfMatch(t.Context(), "head/a/_", etag, []byte("v2"), nil); err != nil {
		t.Fatalf("the newer write: %v", err)
	}
	if delivered := fixture.store.DeliverDelayed("meta-1", "head/"); delivered != 1 {
		t.Fatalf("delivered %d", delivered)
	}
	if err := <-answered; !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
	if got := fixture.body(t, "head/a/_"); got != "v2" {
		t.Errorf("body %q", got)
	}
}

// The other order of the same race: the delayed write gets there first, and the newer one fails.
func TestDelayedWriteThatArrivesFirstWins(t *testing.T) {
	fixture := newBlobFixture(t)
	etag, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: DelayInNetwork})
	answered := startDelayedPut(t, fixture, "head/a/_", etag, "delayed")

	fixture.store.DeliverDelayed("meta-1", "head/")
	if err := <-answered; err != nil {
		t.Errorf("err %v", err)
	}
	_, err = fixture.cluster.PutIfMatch(t.Context(), "head/a/_", etag, []byte("v2"), nil)
	if !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
}

func TestRequestStillInTheNetworkLetsOthersPass(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: DelayInNetwork})
	answered := startDelayedPut(t, fixture, "head/a/_", "", "delayed")

	if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("err %v", err)
	}
	if fixture.store.DelayedCount() != 1 {
		t.Error("a later request settled a request that had not arrived")
	}
	fixture.store.DeliverDelayed("meta-1", "head/")
	if err := <-answered; err != nil {
		t.Errorf("err %v", err)
	}
}

// §19.6: a request delayed in the network past its deadline is refused, never applied.
func TestDelayedRequestPastItsDeadlineNeverApplies(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: DelayInNetwork})
	answered := startDelayedPut(t, fixture, "head/a/_", "", "too late")

	fixture.clock.Advance(fixture.cluster.RequestTimeout())
	// the client gave up at its timeout, and the request is still out there
	wantUnknown(t, <-answered)
	if fixture.store.DelayedCount() != 1 {
		t.Fatal("a client giving up told the store")
	}
	if delivered := fixture.store.DeliverDelayed("meta-1", "head/"); delivered != 1 {
		t.Fatalf("delivered %d", delivered)
	}
	if !fixture.absent(t, "head/a/_") {
		t.Error("a request past its deadline applied")
	}
}

func TestCancellingAParkedRequestTellsTheStoreNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay})
	ctx, cancel := context.WithCancel(t.Context())
	answered := make(chan error, 1)
	go func() {
		_, err := fixture.cluster.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil)
		answered <- err
	}()
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	wantUnknown(t, <-answered)
	if fixture.store.DelayedCount() != 1 {
		t.Fatal("a cancel reached the store")
	}
	// and the settle rule still holds: the next request finds it landed
	if _, err := fixture.cluster.Head(t.Context(), "head/a/_"); err != nil {
		t.Errorf("err %v", err)
	}
}

func TestDelayedDeleteLandsBeforeTheNextRequest(t *testing.T) {
	fixture := newBlobFixture(t)
	if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), "idx/a.e", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpDelete, Result: Delay})
	answered := make(chan error, 1)
	go func() {
		answered <- fixture.cluster.Delete(t.Context(), "idx/a.e")
	}()
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.cluster.Get(t.Context(), "idx/a.e"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("the next read saw %v", err)
	}
	if err := <-answered; err != nil {
		t.Errorf("err %v", err)
	}
}

func TestAListSeesParkedWritesUnderItsPrefixSettled(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "idx/", Result: Delay})
	answered := startDelayedPut(t, fixture, "idx/a.e", "", "v1")
	objects, _, err := fixture.cluster.List(t.Context(), "idx/", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 {
		t.Errorf("listed %d", len(objects))
	}
	if err := <-answered; err != nil {
		t.Errorf("err %v", err)
	}
}

func TestRequestPastItsOwnDeadlineIsRefusedAndAppliesNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	past := sidecar.WithBlobDeadline(t.Context(), fixture.clock.Now())
	_, err := fixture.cluster.PutIfNoneMatch(past, "head/a/_", []byte("v1"), nil)
	wantUnknown(t, err)
	if !fixture.absent(t, "head/a/_") {
		t.Error("it applied")
	}
	if err := fixture.cluster.Delete(past, "head/a/_"); err == nil {
		t.Error("a late delete answered as a success")
	}
	if _, err := fixture.cluster.Get(past, "head/a/_"); err == nil || errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("a late get: %v", err)
	}
}

func TestDeadlineRidesTheSendersClock(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	fixture := newBlobFixture(t)
	table := NewActorTable(fixture.clock, driver)
	slow := table.Actor(t.Context(), "evs2")
	// a sender 11 s behind sends deadlines already past by the store's clock
	slow.SetClockOffset(fixture.clock, -11*time.Second)
	_, err := fixture.cluster.PutIfNoneMatch(slow.Context(), "head/a/_", []byte("v1"), nil)
	wantUnknown(t, err)
	if !fixture.absent(t, "head/a/_") {
		t.Error("it applied")
	}
}

func TestCancelledContextSendsNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := fixture.cluster.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil)
	wantUnknown(t, err)
	if !fixture.absent(t, "head/a/_") {
		t.Error("it applied")
	}
}

func TestEqualBytesGiveEqualEtags(t *testing.T) {
	fixture := newBlobFixture(t)
	first, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/b/_", []byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("%q and %q", first, second)
	}
}

func TestClustersHoldTheirOwnKeys(t *testing.T) {
	fixture := newBlobFixture(t)
	segment, err := fixture.store.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := segment.Head(t.Context(), "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("err %v", err)
	}
}

func TestViewHidesClustersAProcessHasNoCredentialsFor(t *testing.T) {
	fixture := newBlobFixture(t)
	gkm := fixture.store.View("meta-1")
	if _, err := gkm.FirstCluster(); err != nil {
		t.Errorf("err %v", err)
	}
	if _, err := gkm.SegmentCluster(); !errors.Is(err, sidecar.ErrBlobClusterUnknown) {
		t.Errorf("err %v", err)
	}
}

func TestNewRepoClusterMovesWithPlaceNew(t *testing.T) {
	fixture := newBlobFixture(t)
	if got := fixture.store.NewRepoClusterId(); got != "meta-1" {
		t.Errorf("default %q", got)
	}
	fixture.store.SetNewRepoClusterId("meta-9")
	if got := fixture.store.NewRepoClusterId(); got != "meta-9" {
		t.Errorf("after %q", got)
	}
	if _, err := fixture.store.Cluster("meta-9"); !errors.Is(err, sidecar.ErrBlobClusterUnknown) {
		t.Errorf("err %v", err)
	}
}

func TestSettlePassedFollowsTheGate(t *testing.T) {
	fixture := newBlobFixture(t)
	if !fixture.cluster.SettlePassed() {
		t.Error("the fake keeps the rule")
	}
	fixture.store.SetSettlePassed("meta-1", false)
	if fixture.cluster.SettlePassed() {
		t.Error("the gate did not close")
	}
}

func TestLastModifiedReadsTheInjectedClock(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.clock.Advance(25 * time.Hour)
	if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), "slot/a/_", []byte("v"), nil); err != nil {
		t.Fatal(err)
	}
	info, err := fixture.cluster.Head(t.Context(), "slot/a/_")
	if err != nil {
		t.Fatal(err)
	}
	if !info.LastModified.Equal(fixture.clock.Now()) {
		t.Errorf("LastModified %v", info.LastModified)
	}
}

// Writes keys in order to a fresh store's first cluster: what the store reported, as it reported it, and what it
// holds as violations.
func writeKeysForReports(t *testing.T, keys []string) ([]string, []string) {
	t.Helper()
	reported := []string{}
	settings := DefaultFakeBlobsSettings()
	settings.Report = func(violation string) { reported = append(reported, violation) }
	store := NewFakeBlobs(nil, nil, nil, settings)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if _, err := cluster.PutIfNoneMatch(t.Context(), key, []byte("v"), nil); err != nil {
			t.Fatal(err)
		}
	}
	return reported, store.Violations()
}

// §11.8's keys row means a path prefix (owner decision 234): a key followed by / at another's next byte fails the
// test in either order, and a byte prefix that is no path prefix stands in either order, §10.6's <ref>.claim beside
// its <ref> among them.
func TestAKeyThatPrefixesAnotherFailsTheTest(t *testing.T) {
	ref := "gkm/kp/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210"
	cases := []struct {
		first, second string
		violates      bool
	}{
		{first: "place/a", second: "place/a/b", violates: true},
		{first: "place/a/b", second: "place/a", violates: true},
		{first: "proj/n/1", second: "proj/n/11", violates: false},
		{first: "proj/n/11", second: "proj/n/1", violates: false},
		{first: ref, second: ref + ".claim", violates: false},
		{first: ref + ".claim", second: ref, violates: false},
	}
	for _, c := range cases {
		reported, violations := writeKeysForReports(t, []string{c.first, c.second})
		if !c.violates {
			if len(reported) != 0 || len(violations) != 0 {
				t.Errorf("%s and %s: reported %v, violations %v", c.first, c.second, reported, violations)
			}
			continue
		}
		if len(reported) != 1 || !strings.Contains(reported[0], "prefixes") {
			t.Errorf("%s and %s: reported %v", c.first, c.second, reported)
		}
		if len(violations) != 1 {
			t.Errorf("%s and %s: violations %v", c.first, c.second, violations)
		}
	}
}

// The scan for keys under a new key looks at the first key at or after it and a /, not at the key that sorts next:
// a.claim sorts between a and a/b. Written in every order, the three report the a and a/b pair once, and no other.
func TestAPathPrefixIsFoundPastASiblingThatSortsBetween(t *testing.T) {
	orders := [][]string{
		{"a", "a.claim", "a/b"},
		{"a", "a/b", "a.claim"},
		{"a.claim", "a", "a/b"},
		{"a.claim", "a/b", "a"},
		{"a/b", "a", "a.claim"},
		{"a/b", "a.claim", "a"},
	}
	want := fmt.Sprintf("key %q prefixes key %q", "a", "a/b")
	for _, order := range orders {
		reported, violations := writeKeysForReports(t, order)
		if !slices.Equal(reported, []string{want}) || !slices.Equal(violations, []string{want}) {
			t.Errorf("%v: reported %v, violations %v", order, reported, violations)
		}
	}
}

func TestKeysOfOneFamilyDoNotTripThePrefixRule(t *testing.T) {
	fixture := newBlobFixture(t)
	keys := []string{"proj/n/1/_", "proj/n/11/_", "idx/r/a.e", "idx/r/a/b.e", "seg/r/aa", "seg/r/ab"}
	for _, key := range keys {
		if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), key, []byte("v"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if violations := fixture.store.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}

func TestInspectingReadsAroundFaultsDeadlinesAndCounts(t *testing.T) {
	fixture := newBlobFixture(t)
	if _, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpGet, Result: FailBeforeApply})
	past := sidecar.WithBlobDeadline(InspectContext(t.Context()), fixture.clock.Now())
	before := fixture.store.RequestCount("meta-1", FaultOpGet)

	if _, err := fixture.cluster.Head(past, "head/a/_"); err != nil {
		t.Errorf("err %v", err)
	}
	if got := fixture.store.RequestCount("meta-1", FaultOpGet); got != before {
		t.Errorf("counted %d", got-before)
	}
	if len(fixture.faults.Unfired()) != 1 {
		t.Error("an oracle's read took a fault")
	}
}

func TestInspectingLeavesParkedWritesParked(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/", Result: Delay})
	answered := startDelayedPut(t, fixture, "head/a/_", "", "v1")
	if !fixture.absent(t, "head/a/_") {
		t.Fatal("an oracle's read settled a write")
	}
	fixture.store.DeliverDelayed("meta-1", "head/")
	if err := <-answered; err != nil {
		t.Errorf("err %v", err)
	}
}

func TestPutStreamFaultsApplyLikeAnyPut(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "seg/", Result: ApplyThenDrop})
	body := []byte("segment")
	sum := sha256Of(body)
	_, err := fixture.cluster.PutStream(t.Context(), "seg/a/_", bytes.NewReader(body), int64(len(body)), sum)
	wantUnknown(t, err)
	if got := fixture.body(t, "seg/a/_"); got != "segment" {
		t.Errorf("body %q", got)
	}
}

func TestAStalledUploadFailsWithAnUnknownOutcome(t *testing.T) {
	fixture := newBlobFixture(t)
	_, err := fixture.cluster.PutStream(t.Context(), "seg/a/_", iotestErrReader{}, 10, sha256Of([]byte("x")))
	wantUnknown(t, err)
}

type iotestErrReader struct{}

func (iotestErrReader) Read(body []byte) (int, error) {
	return 0, fmt.Errorf("the uploader went away")
}

// Every operation that reaches the queue is recorded with what it was given, the ones a plan fails
// included, which a store's served count leaves out.
func TestTheFaultQueueRecordsEveryOperation(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Nth: 2, Result: FailBeforeApply})
	for _, key := range []string{"a/_", "b/_", "c/_"} {
		fixture.cluster.PutIfNoneMatch(t.Context(), key, []byte("v"), nil)
	}
	want := []FaultResult{0, FailBeforeApply, 0}
	if got := fixture.faults.OpResults(FaultOpPut); !slices.Equal(got, want) {
		t.Errorf("results %v, want %v", got, want)
	}
	if got := fixture.store.RequestCount("meta-1", FaultOpPut); got != 2 {
		t.Errorf("served %d", got)
	}
}

// A displacing plan takes the write an older plan also fires at: the write applies and its caller
// sees its response lost, and the older plan counts as fired there.
func TestADisplacingPlanTakesTheWriteAndTheOtherCountsAsFired(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: FailBeforeApply})
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: ApplyThenDrop, Displaces: true})
	_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "a/_", []byte("v"), nil)
	var unknown *sidecar.BlobUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("err %v", err)
	}
	if got := fixture.body(t, "a/_"); got != "v" {
		t.Errorf("body %q: the write did not apply", got)
	}
	if unfired := fixture.faults.Unfired(); len(unfired) != 0 {
		t.Errorf("unfired %v", unfired)
	}
	// without it, the oldest plan wins as ever
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: FailBeforeApply})
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: ApplyThenDrop})
	fixture.cluster.PutIfNoneMatch(t.Context(), "b/_", []byte("v"), nil)
	if !fixture.absent(t, "b/_") {
		t.Error("a younger plan took the write")
	}
}

// A delivery settles each parked request to its own fate, so a write armed never to land stays off the
// store, and its caller is told nothing it can rely on, as FakeRedis does for its own.
func TestADeliveryLosesAWriteArmedNeverToLand(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/a/", Result: Delay, Delay: DelayNeverLands})
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "head/b/", Result: Delay, Delay: DelayInNetwork})
	lost := startDelayedPut(t, fixture, "head/a/_", "", "never")
	arriving := make(chan error, 1)
	go func() {
		_, err := fixture.cluster.PutIfNoneMatch(t.Context(), "head/b/_", []byte("arrives"), nil)
		arriving <- err
	}()
	// each parked request sets its client's timeout
	if err := fixture.clock.AwaitTimers(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if delivered := fixture.store.DeliverDelayed("meta-1", "head/"); delivered != 2 {
		t.Fatalf("delivered %d", delivered)
	}
	var unknown *sidecar.BlobUnknownError
	if err := <-lost; !errors.As(err, &unknown) {
		t.Errorf("the lost write's caller: %v", err)
	}
	if !fixture.absent(t, "head/a/_") {
		t.Errorf("a write armed never to land holds %q", fixture.body(t, "head/a/_"))
	}
	if err := <-arriving; err != nil {
		t.Errorf("the arriving write's caller: %v", err)
	}
	if got := fixture.body(t, "head/b/_"); got != "arrives" {
		t.Errorf("body %q", got)
	}
}

// PutImmutable on the fake's own faults: a create whose answer is lost after it applied reads back as
// written, with one create and one read.
func TestPutImmutableResolvesApplyThenDrop(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "log/", Result: ApplyThenDrop})
	if _, err := sidecar.PutImmutable(t.Context(), fixture.cluster, "log/r/f/0", []byte("page"), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(fixture.faults.OpResults(FaultOpPut)); got != 1 {
		t.Errorf("%d creates sent", got)
	}
	if got := fixture.body(t, "log/r/f/0"); got != "page" {
		t.Errorf("body %q", got)
	}
}

// One that never reached the store reads back 404 and goes again.
func TestPutImmutableResolvesFailBeforeApply(t *testing.T) {
	fixture := newBlobFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "log/", Result: FailBeforeApply})
	if _, err := sidecar.PutImmutable(t.Context(), fixture.cluster, "log/r/f/0", []byte("page"), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(fixture.faults.OpResults(FaultOpPut)); got != 2 {
		t.Errorf("%d creates sent", got)
	}
	if got := fixture.body(t, "log/r/f/0"); got != "page" {
		t.Errorf("body %q", got)
	}
}

// A create parked until its caller gives up has reached its deadline by then, so whichever fate the
// settle rule gives it, the read-back finds it never landed (D-OPS-20), and the same bytes go again.
func TestPutImmutableWritesAgainPastAParkedCreatesDeadline(t *testing.T) {
	for _, delay := range []FaultDelay{DelayLandsBeforeNext, DelayNeverLands} {
		fixture := newBlobFixture(t)
		fixture.arm(t, &FaultPlan{Op: FaultOpPut, KeyPrefix: "pb/", Result: Delay, Delay: delay})
		done := make(chan error, 1)
		go func() {
			_, err := sidecar.PutImmutable(t.Context(), fixture.cluster, "pb/h/m/a-b", []byte("batch"), nil)
			done <- err
		}()
		// the parked create's caller gives up at its timeout, unknown
		if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		fixture.clock.Advance(fixture.cluster.RequestTimeout())
		if err := <-done; err != nil {
			t.Errorf("%v: %v", delay, err)
		}
		if got := len(fixture.faults.OpResults(FaultOpPut)); got != 2 {
			t.Errorf("%v: %d creates sent", delay, got)
		}
		if got := fixture.body(t, "pb/h/m/a-b"); got != "batch" {
			t.Errorf("%v: body %q", delay, got)
		}
		if got := fixture.store.DelayedCount(); got != 0 {
			t.Errorf("%v: %d requests still parked", delay, got)
		}
	}
}

// A Delete that names its object takes it, and a key already gone is nil.
func TestNamedDeleteTakesTheObjectItNames(t *testing.T) {
	fixture := newBlobFixture(t)
	ctx := t.Context()
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("an orphan"), nil); err != nil {
		t.Fatal(err)
	}
	info, err := fixture.cluster.Head(ctx, "seg/r/s")
	if err != nil {
		t.Fatal(err)
	}
	named := sidecar.WithBlobUnmodified(ctx, info.LastModified)
	if err := fixture.cluster.Delete(named, "seg/r/s"); err != nil {
		t.Errorf("err %v", err)
	}
	if !fixture.absent(t, "seg/r/s") {
		t.Error("the named object stands")
	}
	if err := fixture.cluster.Delete(named, "seg/r/s"); err != nil {
		t.Errorf("a named Delete of a missing key: %v", err)
	}
}

// §11.13's second GC run: the object it listed was deleted and its bytes stored again, days later. Its
// Delete names the object it listed, so it answers ErrBlobPrecondition and changes nothing.
func TestNamedDeleteRefusesAnObjectStoredAgain(t *testing.T) {
	fixture := newBlobFixture(t)
	ctx := t.Context()
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("the bytes"), nil); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.cluster.Head(ctx, "seg/r/s")
	if err != nil {
		t.Fatal(err)
	}
	named := sidecar.WithBlobUnmodified(ctx, listed.LastModified)
	if err := fixture.cluster.Delete(named, "seg/r/s"); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(1 * time.Second)
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("the bytes"), nil); err != nil {
		t.Fatal(err)
	}

	err = fixture.cluster.Delete(named, "seg/r/s")
	if !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
	var unknown *sidecar.BlobUnknownError
	if errors.As(err, &unknown) {
		t.Error("a 412 was reported as an unknown outcome")
	}
	if got := fixture.body(t, "seg/r/s"); got != "the bytes" {
		t.Errorf("the object stored again holds %q", got)
	}
	// inside the second of slack the object is still the one named
	inside := sidecar.WithBlobUnmodified(ctx, fixture.clock.Now().Add(-999*time.Millisecond))
	if err := fixture.cluster.Delete(inside, "seg/r/s"); err != nil {
		t.Errorf("a Delete naming a time inside the slack: %v", err)
	}
}

// A named Delete is judged where the store judges it, when it lands: one parked in the network across
// a delete and a new upload of its key finds the new object, and leaves it.
func TestNamedDeleteIsJudgedWhenItLands(t *testing.T) {
	fixture := newBlobFixture(t)
	ctx := t.Context()
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("the bytes"), nil); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.cluster.Head(ctx, "seg/r/s")
	if err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpDelete, Result: Delay, Delay: DelayInNetwork})
	answered := make(chan error, 1)
	go func() {
		answered <- fixture.cluster.Delete(sidecar.WithBlobUnmodified(ctx, listed.LastModified), "seg/r/s")
	}()
	if err := fixture.clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}

	// another run deletes the object, and its uploader stores the bytes again
	if err := fixture.cluster.Delete(ctx, "seg/r/s"); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(2 * time.Second)
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("the bytes"), nil); err != nil {
		t.Fatal(err)
	}
	if delivered := fixture.store.DeliverDelayed("meta-1", "seg/"); delivered != 1 {
		t.Fatalf("delivered %d", delivered)
	}
	if err := <-answered; !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("the parked Delete: %v", err)
	}
	if got := fixture.body(t, "seg/r/s"); got != "the bytes" {
		t.Errorf("the object stored again holds %q", got)
	}
}

// A key a failed DELETE's stalled commit holds answers ErrBlobHeld to a Delete (§19.6's rule (3)): a
// definite answer that deleted nothing, named or not.
func TestHeldResultOnADeleteAppliesNothing(t *testing.T) {
	fixture := newBlobFixture(t)
	ctx := t.Context()
	if _, err := fixture.cluster.PutIfNoneMatch(ctx, "seg/r/s", []byte("held"), nil); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.cluster.Head(ctx, "seg/r/s")
	if err != nil {
		t.Fatal(err)
	}
	fixture.arm(t, &FaultPlan{Op: FaultOpDelete, Result: Held, Repeat: 2})
	for _, deleteCtx := range []context.Context{ctx, sidecar.WithBlobUnmodified(ctx, listed.LastModified)} {
		err := fixture.cluster.Delete(deleteCtx, "seg/r/s")
		if !errors.Is(err, sidecar.ErrBlobHeld) {
			t.Errorf("err %v", err)
		}
		var unknown *sidecar.BlobUnknownError
		if errors.As(err, &unknown) {
			t.Error("a held key was reported as an unknown outcome")
		}
	}
	if got := fixture.body(t, "seg/r/s"); got != "held" {
		t.Errorf("the object on a held key holds %q", got)
	}
}
