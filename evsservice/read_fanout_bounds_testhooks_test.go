//go:build sidecar_testhooks

// §11.15's fan-out (owner decision 780; QD-1394) at the slot wait's barrier (BarrierReadSlotWait), with
// read_fanout_bounds_test.go's parked store reads: a step 4 and a read's first round naming more reads than the bound
// put no more than the bound at the store at once, a read past it waiting for a slot rather than reaching the store,
// and a push attempt or a read whose ctx ends while one of its reads waits for a slot ends 503, committing nothing.

package evsservice

import (
	"bytes"
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
)

// Each BarrierReadSlotWait of repoId's reads, told on the channel answered, onWait first when set.
func slotWaits(t *testing.T, repoId sidecar.Id, onWait func()) <-chan struct{} {
	t.Helper()
	waits := make(chan struct{}, 1024)
	key := sidecar.EvsKeyId(repoId)
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, barrierKey string) {
		if name != BarrierReadSlotWait || barrierKey != key {
			return
		}
		if onWait != nil {
			onWait()
		}
		waits <- struct{}{}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	return waits
}

// As deliverInTurns, letting nothing on until a read finds every slot taken (BarrierReadSlotWait): until then a read
// past the bound that reached the store, rather than wait, would be parked past the bound and fail the test. A read
// tells its wait once, as it starts, and may wait through several turns, so the turns after it come as in
// deliverInTurns. Answers how many reads waited.
func (self *parkedStoreReads) deliverAtSlotWaits(bound int, total int, waits <-chan struct{}, done <-chan struct{}) int {
	self.t.Helper()
	waitCount := 0
	delivered := 0
	for delivered < total {
		select {
		case parkedCount := <-self.parks:
			self.requireWithin(bound, parkedCount)
		case <-waits:
			waitCount += 1
		case <-done:
			self.t.Fatalf("done with %d of %d reads let on", delivered, total)
		}
		parkedCount := self.blobs.DelayedCount()
		self.requireWithin(bound, parkedCount)
		if waitCount == 0 || parkedCount < min(bound, total-delivered) {
			continue
		}
		delivered += self.blobs.DeliverDelayed("meta-1", self.keyPrefix)
	}
	return waitCount
}

// Waits for done, letting nothing on, while no more reads are parked than bound lets in flight: a read past the
// bound must wait for a slot, whose barrier ends the request here, rather than reach the store.
func (self *parkedStoreReads) awaitWithin(bound int, done <-chan struct{}) {
	self.t.Helper()
	for {
		select {
		case parkedCount := <-self.parks:
			self.requireWithin(bound, parkedCount)
		case <-done:
			return
		}
	}
}

// A request on ctx through the engine's guard, as fixture.call sends one on the test's.
func (self *pushFixture) callWithContext(ctx context.Context, token string, method string, path string, body proto.Message) *httptest.ResponseRecorder {
	self.t.Helper()
	var reader io.Reader
	if body != nil {
		bodyBytes, err := proto.Marshal(body)
		if err != nil {
			self.t.Fatal(err)
		}
		reader = bytes.NewReader(bodyBytes)
	}
	request := httptest.NewRequestWithContext(ctx, method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+path, reader)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A one-part push of more changed paths than the bound: nothing is let on until a read of step 4 finds every slot
// taken, so a read past the bound that reached the store would be parked past it and fail the test. Reads wait at
// the bound, and the push commits.
func TestPushStep4ReadsPastTheBoundWaitForASlot(t *testing.T) {
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
	waits := slotWaits(t, fixture.check.repoId, nil)
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.post(token, body)
	}()
	waitCount := parked.deliverAtSlotWaits(bound, pathCount, waits, done)
	parked.stop()
	<-done
	sidecar.SetTestHooks(nil)
	fixture.requireCommitted(recorder, 1)
	if waitCount == 0 {
		t.Fatal("no read of step 4 waited for a slot")
	}
}

// A read naming more paths than the bound, as the push above: its first round's reads wait at the bound, and it
// answers every path.
func TestReadRoundOneReadsPastTheBoundWaitForASlot(t *testing.T) {
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
	waits := slotWaits(t, fixture.check.repoId, nil)
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.call(token, http.MethodPost, "/read", request)
	}()
	waitCount := parked.deliverAtSlotWaits(bound, pathCount, waits, done)
	parked.stop()
	<-done
	sidecar.SetTestHooks(nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read: status %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if reply := decodeReadFrames(t, recorder.Body.Bytes()); !reply.ended || len(reply.paths) != pathCount {
		t.Fatalf("%d paths answered, ended %t", len(reply.paths), reply.ended)
	}
	if waitCount == 0 {
		t.Fatal("no read of the first round waited for a slot")
	}
}

// A push attempt whose ctx ends, by the engine's close, while a read of its step 4 waits for a slot behind reads
// held at the store: the attempt ends 503, refusing nothing, and no head is written.
func TestPushAttemptWhoseCtxEndsWhileAReadWaitsEndsUnavailable(t *testing.T) {
	const bound = 2
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.EntryReadConcurrency = bound })
	plan := fixture.plan()
	for i := range 3 * bound {
		fixture.create(plan, fmt.Sprintf("path %d", i))
	}
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	parked := parkStoreReads(t, fixture, IndexEpochPrefix(fixture.check.repoId, fixture.check.refId, 1))
	var closeOnce sync.Once
	waits := slotWaits(t, fixture.check.repoId, func() {
		// the engine's ctx is every attempt's parent
		closeOnce.Do(fixture.engine.Close)
	})
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.post(token, body)
	}()
	parked.awaitWithin(bound, done)
	sidecar.SetTestHooks(nil)
	if len(waits) == 0 {
		t.Fatal("no read waited for a slot")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", recorder.Code)
	}
	if refusal := refusalOf(t, recorder); refusal.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
		t.Fatalf("code %s, want UNAVAILABLE", refusal.GetCode())
	}
	if _, err := fixture.cluster.Get(fixture.ctx, HeadKey(fixture.check.repoId, fixture.check.refId)); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the ref's head after the attempt ended: %v", err)
	}
}

// A read whose ctx ends, as its client leaves, while a read of its first round waits for a slot behind reads held
// at the store: it ends 503 before its first frame.
func TestReadWhoseCtxEndsWhileAReadWaitsEndsUnavailable(t *testing.T) {
	const bound = 2
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.EntryReadConcurrency = bound })
	plan := fixture.plan()
	paths := []map[uint64]sidecar.EvsTokenPath{}
	for i := range 3 * bound {
		label := fmt.Sprintf("path %d", i)
		fixture.create(plan, label)
		paths = append(paths, map[uint64]sidecar.EvsTokenPath{1: checkTestPath(label)})
	}
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.awaitStepEights()
	token := fixture.token(fixture.check.signerId, "r")
	request := fixture.namedRequest(0, 0, 0, paths...)
	parked := parkStoreReads(t, fixture, IndexEpochPrefix(fixture.check.repoId, fixture.check.refId, 1))
	ctx, cancel := context.WithCancel(fixture.ctx)
	defer cancel()
	waits := slotWaits(t, fixture.check.repoId, cancel)
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		recorder = fixture.callWithContext(ctx, token, http.MethodPost, "/read", request)
	}()
	parked.awaitWithin(bound, done)
	sidecar.SetTestHooks(nil)
	if len(waits) == 0 {
		t.Fatal("no read waited for a slot")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", recorder.Code)
	}
}
