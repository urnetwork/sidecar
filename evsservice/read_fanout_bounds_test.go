// §11.15's fan-out (owner decision 780; QD-1394; read_fanout.go): an attempt's cluster holds its store reads to its
// slots, a read past them waiting under its ctx and reaching nothing when that ctx ends, every slot given back at a
// body's end, failure or close, and writes passing through; EntryReadConcurrency held positive; and, through the
// engine's guard, a step 4, a read's first round and GET .../refs naming more reads than the bound, each finishing
// with no more than the bound at the store at once. read_fanout_bounds_testhooks_test.go holds the schedules that
// need the slot wait's barrier.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A store whose every read waits at the store for the test's word: what a slow store is to a burst. Each read that
// reaches it is counted, with the most at once. Writes and the rest pass to the cluster beneath. Safe for concurrent
// use.
type heldStoreCluster struct {
	sidecar.BlobCluster
	// each read's key as it reaches the store
	arrived chan string
	// one value lets one read at the store on
	release chan struct{}

	stateLock        sync.Mutex
	arrivedCount     int
	inFlightCount    int
	maxInFlightCount int
}

// A held store over a fresh fake cluster holding keyCount objects, keyed by heldStoreKey.
func newHeldStoreCluster(t *testing.T, keyCount int) *heldStoreCluster {
	t.Helper()
	cluster, err := sidecartest.NewFakeBlobs(nil, nil, nil, nil).Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := range keyCount {
		if _, err := cluster.PutIfNoneMatch(t.Context(), heldStoreKey(i), fmt.Appendf(nil, "object %d", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	return &heldStoreCluster{BlobCluster: cluster, arrived: make(chan string, 64), release: make(chan struct{})}
}

func heldStoreKey(i int) string {
	return fmt.Sprintf("held/%d", i)
}

// Counts a read in, waits for the test's word, and counts it out.
func (self *heldStoreCluster) hold(key string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.arrivedCount += 1
		self.inFlightCount += 1
		self.maxInFlightCount = max(self.maxInFlightCount, self.inFlightCount)
	}()
	self.arrived <- key
	<-self.release
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.inFlightCount -= 1
}

func (self *heldStoreCluster) counts() (arrivedCount int, maxInFlightCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.arrivedCount, self.maxInFlightCount
}

func (self *heldStoreCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	self.hold(key)
	return self.BlobCluster.Get(ctx, key)
}

func (self *heldStoreCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	self.hold(key)
	return self.BlobCluster.Head(ctx, key)
}

// An attempt's cluster of slotCount slots over store, telling waiting each time a read starts to wait for a slot.
func newHeldAttemptCluster(store sidecar.BlobCluster, slotCount int, waiting chan<- struct{}) *attemptReadCluster {
	return &attemptReadCluster{
		BlobCluster: store,
		slots:       make(chan struct{}, slotCount),
		barrierKey:  "test",
		waiting:     func() { waiting <- struct{}{} },
	}
}

// A GET read whole and closed, as every evs caller reads one.
func readWhole(ctx context.Context, cluster sidecar.BlobCluster, key string) error {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return err
	}
	defer object.Body.Close()
	_, err = io.ReadAll(object.Body)
	return err
}

// Six reads through two slots, at a store that holds each: two reach it, a third finds both slots taken and waits,
// reaching nothing, and as the store lets each read on, its slot goes to one waiting, so all six finish with never
// more than two at the store, every slot given back.
func TestAttemptReadClusterHoldsReadsToItsSlots(t *testing.T) {
	const slotCount = 2
	const readCount = 6
	store := newHeldStoreCluster(t, readCount)
	waiting := make(chan struct{}, readCount)
	cluster := newHeldAttemptCluster(store, slotCount, waiting)
	results := make(chan error, readCount)
	for i := range readCount {
		go func() {
			results <- readWhole(t.Context(), cluster, heldStoreKey(i))
		}()
	}
	for range slotCount {
		<-store.arrived
	}
	select {
	case <-waiting:
	case key := <-store.arrived:
		t.Fatalf("%s reached the store while %d reads held every slot", key, slotCount)
	}
	for released := range readCount {
		store.release <- struct{}{}
		// the read let on is read to its end, and its slot goes to a waiting read, which reaches the store
		if released+slotCount < readCount {
			<-store.arrived
		}
	}
	for range readCount {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if arrivedCount, maxInFlightCount := store.counts(); arrivedCount != readCount || maxInFlightCount != slotCount {
		t.Fatalf("%d reads reached the store, at most %d at once, want %d and %d", arrivedCount, maxInFlightCount, readCount, slotCount)
	}
	if len(cluster.slots) != 0 {
		t.Fatalf("%d slots still taken", len(cluster.slots))
	}
}

// A read waiting for a slot ends with its ctx, with that ctx's error and nothing sent, while the reads holding the
// slots go on to their answers.
func TestAttemptReadClusterWaitEndsWithItsCtx(t *testing.T) {
	const slotCount = 2
	store := newHeldStoreCluster(t, slotCount+1)
	waiting := make(chan struct{}, 1)
	cluster := newHeldAttemptCluster(store, slotCount, waiting)
	held := make(chan error, slotCount)
	for i := range slotCount {
		go func() {
			held <- readWhole(t.Context(), cluster, heldStoreKey(i))
		}()
	}
	for range slotCount {
		<-store.arrived
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waited := make(chan error, 1)
	go func() {
		_, err := cluster.Head(ctx, heldStoreKey(slotCount))
		waited <- err
	}()
	<-waiting
	cancel()
	if err := <-waited; !errors.Is(err, context.Canceled) {
		t.Fatalf("a read whose ctx ended while it waited: %v", err)
	}
	if arrivedCount, _ := store.counts(); arrivedCount != slotCount {
		t.Fatalf("%d reads reached the store, the waiting one among them", arrivedCount)
	}
	for range slotCount {
		store.release <- struct{}{}
	}
	for range slotCount {
		if err := <-held; err != nil {
			t.Fatal(err)
		}
	}
	if len(cluster.slots) != 0 {
		t.Fatalf("%d slots still taken", len(cluster.slots))
	}
}

// Each read gives its slot back once it is over: a GET at its body's end, before its close, or at a close before
// its end; a GET that failed, a HEAD and a LIST at once; and a body closed again or read past its end gives nothing
// twice. Writes take no slot, so one goes on while every slot is taken.
func TestAttemptReadClusterGivesEachSlotBack(t *testing.T) {
	ctx := t.Context()
	fake, err := sidecartest.NewFakeBlobs(nil, nil, nil, nil).Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fake.PutIfNoneMatch(ctx, "given/a", []byte("whole object"), nil); err != nil {
		t.Fatal(err)
	}
	cluster := newAttemptReadCluster(fake, 2, testId("repo")).(*attemptReadCluster)
	requireTaken := func(what string, want int) {
		t.Helper()
		if got := len(cluster.slots); got != want {
			t.Fatalf("%s: %d slots taken, want %d", what, got, want)
		}
	}

	object, err := cluster.Get(ctx, "given/a")
	if err != nil {
		t.Fatal(err)
	}
	requireTaken("a GET's body unread", 1)
	if body, err := io.ReadAll(object.Body); err != nil || string(body) != "whole object" {
		t.Fatalf("body %q: %v", body, err)
	}
	requireTaken("a GET's body read to its end", 0)
	if count, err := object.Body.Read(make([]byte, 1)); count != 0 || err != io.EOF {
		t.Fatalf("a read past the end: %d %v", count, err)
	}
	object.Body.Close()
	object.Body.Close()
	requireTaken("a body read to its end and closed twice", 0)

	ranged, err := cluster.GetRange(ctx, "given/a", 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ranged.Body.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	requireTaken("a ranged body read in part", 1)
	ranged.Body.Close()
	requireTaken("a ranged body closed in part", 0)

	if _, err := cluster.Get(ctx, "given/missing"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("a missing key: %v", err)
	}
	requireTaken("a GET that failed", 0)
	if info, err := cluster.Head(ctx, "given/a"); err != nil || info.ByteCount != int64(len("whole object")) {
		t.Fatalf("a HEAD: %v %v", info, err)
	}
	requireTaken("a HEAD", 0)
	if objects, _, err := cluster.List(ctx, "given/", "", 10); err != nil || len(objects) != 1 {
		t.Fatalf("a LIST: %v %v", objects, err)
	}
	requireTaken("a LIST", 0)

	first, err := cluster.Get(ctx, "given/a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cluster.Get(ctx, "given/a")
	if err != nil {
		t.Fatal(err)
	}
	requireTaken("two bodies open", 2)
	if _, err := cluster.PutIfNoneMatch(ctx, "given/b", []byte("written"), nil); err != nil {
		t.Fatalf("a write while every slot is taken: %v", err)
	}
	first.Body.Close()
	second.Body.Close()
	requireTaken("both closed", 0)
}

// The bound is the design's 64, and Validate refuses one that is not positive.
func TestEvsSettingsHoldEntryReadConcurrencyPositive(t *testing.T) {
	if got := DefaultEvsSettings().EntryReadConcurrency; got != 64 {
		t.Fatalf("EntryReadConcurrency %d by default, want 64", got)
	}
	for _, concurrency := range []int{0, -1} {
		settings := DefaultEvsSettings()
		settings.EntryReadConcurrency = concurrency
		if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
			t.Errorf("EntryReadConcurrency %d: %v", concurrency, err)
		}
	}
}

// Every GET, ranged GET and HEAD under keyPrefix on meta-1 held at the store until the test lets it on (sidecartest's
// DelayInNetwork): how a test holds a round's reads where they are counted. Each park is told with the reads parked
// at its moment.
type parkedStoreReads struct {
	t         *testing.T
	blobs     *sidecartest.FakeBlobs
	keyPrefix string
	parks     chan int
}

func parkStoreReads(t *testing.T, fixture *pushFixture, keyPrefix string) *parkedStoreReads {
	t.Helper()
	parked := &parkedStoreReads{t: t, blobs: fixture.host.Blobs, keyPrefix: keyPrefix, parks: make(chan int, 1024)}
	plan := &sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpGet,
		KeyPrefix: keyPrefix,
		ClusterId: "meta-1",
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
		Repeat:    -1,
	}
	faults := parked.blobs.Faults()
	faults.SetOnFire(func(fired *sidecartest.FaultPlan) {
		if fired == plan {
			parked.parks <- parked.blobs.DelayedCount()
		}
	})
	if _, err := faults.Add(plan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parked.stop)
	return parked
}

// Disarms the plan and lets every parked read on.
func (self *parkedStoreReads) stop() {
	faults := self.blobs.Faults()
	faults.Clear()
	faults.SetOnFire(nil)
	self.blobs.DeliverDelayed("meta-1", self.keyPrefix)
}

// Fails the test when more reads are parked than bound lets in flight.
func (self *parkedStoreReads) requireWithin(bound int, parkedCount int) {
	self.t.Helper()
	if bound < parkedCount {
		self.t.Fatalf("%d reads at the store at once, past the bound of %d", parkedCount, bound)
	}
}

// Lets the parked reads on in turns until total have gone on, each turn once as many are parked as bound lets in
// flight or as remain. More than bound parked at any park fails the test, as does done closing first.
func (self *parkedStoreReads) deliverInTurns(bound int, total int, done <-chan struct{}) {
	self.t.Helper()
	delivered := 0
	for delivered < total {
		select {
		case parkedCount := <-self.parks:
			self.requireWithin(bound, parkedCount)
		case <-done:
			self.t.Fatalf("done with %d of %d reads let on", delivered, total)
		}
		parkedCount := self.blobs.DelayedCount()
		self.requireWithin(bound, parkedCount)
		if parkedCount < min(bound, total-delivered) {
			continue
		}
		delivered += self.blobs.DeliverDelayed("meta-1", self.keyPrefix)
	}
}

// A one-part push of more changed paths than the bound: step 4's entry reads reach the store no more than the bound
// at once, and the push commits once they have all answered.
func TestPushStep4BeyondTheBoundCommits(t *testing.T) {
	const bound = 3
	const pathCount = 10
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.EntryReadConcurrency = bound })
	plan := fixture.plan()
	for i := range pathCount {
		fixture.create(plan, fmt.Sprintf("path %d", i))
	}
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	parked := parkStoreReads(t, fixture, IndexEpochPrefix(fixture.check.repoId, fixture.check.refId, 1))
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.post(token, body)
	}()
	parked.deliverInTurns(bound, pathCount, done)
	parked.stop()
	<-done
	fixture.requireCommitted(recorder, 1)
}

// A read naming more paths than the bound: its first round's entry reads reach the store no more than the bound at
// once, and it answers every path its version.
func TestReadRoundOneBeyondTheBoundAnswersEveryPath(t *testing.T) {
	const bound = 3
	const pathCount = 10
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.EntryReadConcurrency = bound })
	plan := fixture.plan()
	paths := []map[uint64]sidecar.EvsTokenPath{}
	for i := range pathCount {
		label := fmt.Sprintf("path %d", i)
		fixture.create(plan, label)
		paths = append(paths, map[uint64]sidecar.EvsTokenPath{1: checkTestPath(label)})
	}
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.awaitStepEights()
	token := fixture.token(fixture.check.signerId, "r")
	request := fixture.namedRequest(0, 0, 0, paths...)
	parked := parkStoreReads(t, fixture, IndexEpochPrefix(fixture.check.repoId, fixture.check.refId, 1))
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.call(token, http.MethodPost, "/read", request)
	}()
	parked.deliverInTurns(bound, pathCount, done)
	parked.stop()
	<-done
	if recorder.Code != http.StatusOK {
		t.Fatalf("read: status %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	reply := decodeReadFrames(t, recorder.Body.Bytes())
	if !reply.ended || len(reply.paths) != pathCount {
		t.Fatalf("%d paths answered, ended %t", len(reply.paths), reply.ended)
	}
	for i, pathReply := range reply.paths {
		if pathReply.GetVersion().GetCommitVersion() != 1 {
			t.Fatalf("path %d answered %v", i, pathReply.GetVersion())
		}
	}
}

// GET .../refs over more refs than the bound: its head reads reach the store no more than the bound at once, and
// it lists every ref.
func TestRefsBeyondTheBoundListEveryRef(t *testing.T) {
	const bound = 2
	const refCount = 5
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.EntryReadConcurrency = bound })
	token := fixture.token(fixture.check.signerId)
	for i := range refCount {
		plan := fixture.plan()
		plan.RefId = testId(fmt.Sprintf("ref %d", i))
		plan.BaseVersion, plan.BaseChain = 0, sidecar.EvsChainStart(fixture.check.repoId, plan.RefId)
		fixture.create(plan, "a")
		fixture.requireCommitted(fixture.post(token, fixture.body(plan)), 1)
		fixture.awaitStepEights()
	}
	parked := parkStoreReads(t, fixture, HeadRepoPrefix(fixture.check.repoId))
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.call(token, http.MethodGet, "/refs", nil)
	}()
	parked.deliverInTurns(bound, refCount, done)
	parked.stop()
	<-done
	if recorder.Code != http.StatusOK {
		t.Fatalf("refs: status %d", recorder.Code)
	}
	reply := &protocol.EvsRefsReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatal(err)
	}
	listed := map[sidecar.Id]bool{}
	for _, ref := range reply.GetRefs() {
		listed[sidecar.Id(ref.GetRefId())] = ref.GetVersion() == 1
	}
	for i := range refCount {
		if refId := testId(fmt.Sprintf("ref %d", i)); !listed[refId] {
			t.Errorf("ref %d not listed at version 1: %v", i, reply.GetRefs())
		}
	}
	if len(listed) != refCount {
		t.Fatalf("%d refs listed, want %d", len(listed), refCount)
	}
}
