//go:build sidecar_testhooks

// The Go twins of details/EvsSlot.tla's EvsSlotTwin configs (DESIGN-DETAILS 14.3, 14.6): each runs one schedule
// twice through the push route and the hourly evacuation, with the delete of a dead record's own slots on, first as
// the design has it and then with one rule broken (slot_twin.go), and wants the design to lose no committed
// version's slot and the twin to lose one, as the model's twin config loses its invariant:
//
//	TakesForeign         step 6 takes the refused statement's object as it stands; evacuation then deletes it for
//	                     that statement's dead record, under the retoken's commit (AdopterKept)
//	TakesLive            a takeover of a statement of the attempt's own epoch, which then commits; the taker dies
//	                     and evacuation deletes its object under that commit (DeadIsFinal)
//	TakesCommitted       a takeover of a committed statement's object; the taker dies and evacuation deletes it
//	                     under the committed version (ClosureHolds)
//	TakesUnsettled       two retokens with no settle wait: the first's DELETE takes the second's object, created
//	                     within the second it names, and the first dies holding the slot (OriginStands)
//	NoOriginAtDelete     evacuation deletes a re-lister's dead record's slot whatever its origin (CreatorKept)
//	UnconditionalDelete  a run stalled between its HEAD and its DELETE deletes the object a later commit created
//	                     (ClosureHolds)
//	NoSettle             two runs judge a late slot settled; the stalled one's DELETE takes the object a later
//	                     commit created within the second it names (ClosureHolds)
//
// The model's other two twins rest on rules this track does not change: StampBeforeRecord on step 6's order, record
// then slots, which TestPushSlotNotWrittenWithoutItsRecord holds, and DeadUnfenced on 2.2.3's fence, which
// evacuate_test.go's fence tests hold.

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs schedule as the design has it and then with rule broken: the design must lose no committed version's slot,
// and the twin must lose one.
func requireSlotTwin(t *testing.T, rule evsSlotTwin, schedule func(t *testing.T, rule evsSlotTwin) bool) {
	t.Helper()
	run := func(broken evsSlotTwin) bool {
		switchSlotTwinForTest(broken)
		defer switchSlotTwinForTest(evsSlotTwinNone)
		return schedule(t, broken)
	}
	if run(evsSlotTwinNone) {
		t.Fatal("the design lost a committed version's slot")
	}
	if !run(rule) {
		t.Fatal("the twin lost no committed version's slot")
	}
}

// Whether the committed version that names slotId under origin has lost its slot: the object gone, or another
// statement's in its place.
func (self *pushFixture) slotLost(slotId sidecar.Id, origin EvsSlotOrigin) bool {
	_, held, _, found := self.slotObject(slotId)
	return !found || held != origin
}

// A cut short as in evacuate_slot_test.go, the retoken arriving once the refused statement's object has settled.
func slotTwinRetokenSchedule(t *testing.T, rule evsSlotTwin) bool {
	fixture := newSlotEvacuateFixture(t)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	slotId, _, slotBody := checkTestSlot(t, "twin retoken")
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	refusedBody, _ := fixture.bodyAndOrigin(refused)
	token := fixture.token(fixture.check.signerId)
	fixture.failHeadWrites()
	requireRefusal(t, fixture.post(token, refusedBody), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.Blobs.Faults().Clear()
	fixture.clock.Advance(fixture.settings2().SlotSettleAge)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))

	retoken := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(retoken, epochPath(2, "s"), slotId, slotBody)
	retoken.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "s")}
	retokenBody, _ := fixture.bodyAndOrigin(retoken)
	fixture.requireCommitted(fixture.post(token, retokenBody), 4)
	fixture.awaitStepEights()
	fixture.requireEvacuated(func(result *EvacuationResult) bool { return result.DeadCount == 1 })
	// the twin's retoken took the refused statement's object as it stood, origin and all, so only its absence tells
	_, _, _, found := fixture.slotObject(slotId)
	return !found
}

func TestSlotTwinTakesForeign(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinTakesForeign, slotTwinRetokenSchedule)
}

// o, a push of the writer's, passes step 6 and is held before step 7; another statement of the writer's in o's own
// epoch lists o's slot, takes it over or is refused, and then dies, every step 7 of its losing its race; o commits.
// 26 h on, evacuation drops the dead statement's record.
func slotTwinTakesLiveSchedule(t *testing.T, rule evsSlotTwin) bool {
	fixture := newSlotEvacuateFixture(t)
	fixture.commitCached("x")
	slotId, _, slotBody := checkTestSlot(t, "twin live")
	live := fixture.plan()
	fixture.createWithSlot(live, checkTestPath("s"), slotId, slotBody)
	liveBody, liveOrigin := fixture.bodyAndOrigin(live)
	taker := fixture.plan()
	fixture.createWithSlot(taker, checkTestPath("t"), slotId, slotBody)
	takerBody, _ := fixture.bodyAndOrigin(taker)
	token := fixture.token(fixture.check.signerId)
	atBarrierOnce(t, BarrierPushStep6After, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		fixture.clock.Advance(fixture.settings2().SlotSettleAge)
		faults := fixture.host.Blobs.Faults()
		if _, err := faults.Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition, Repeat: -1,
		}); err != nil {
			t.Fatal(err)
		}
		if recorder := fixture.post(token, takerBody); recorder.Code == http.StatusOK {
			t.Fatal("the taker committed")
		}
		faults.Clear()
	})
	fixture.requireCommitted(fixture.post(token, liveBody), 2)
	sidecar.SetTestHooks(nil)
	fixture.awaitStepEights()
	fixture.requireEvacuated(func(result *EvacuationResult) bool { return result.DeadCount == 1 })
	return fixture.slotLost(slotId, liveOrigin)
}

func TestSlotTwinTakesLive(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinTakesLive, slotTwinTakesLiveSchedule)
}

// o commits its slot in epoch 1 and a PATH_EPOCH cuts the ref over; a statement of epoch 2 lists o's slot, takes it
// over or is refused, and dies, every step 7 of its losing its race. 26 h on, evacuation drops its record.
func slotTwinTakesCommittedSchedule(t *testing.T, rule evsSlotTwin) bool {
	fixture := newSlotEvacuateFixture(t)
	commitment := fixture.crossRemove(false)
	slotId, _, slotBody := checkTestSlot(t, "twin committed")
	committed := fixture.planAtTwo(commitment)
	fixture.createWithSlot(committed, checkTestPath("s"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	token := fixture.token(fixture.check.signerId)
	fixture.requireCommitted(fixture.post(token, committedBody), 3)
	fixture.clock.Advance(fixture.settings2().SlotSettleAge)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))

	taker := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(taker, epochPath(2, "t"), slotId, slotBody)
	taker.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "t")}
	takerBody, _ := fixture.bodyAndOrigin(taker)
	faults := fixture.host.Blobs.Faults()
	if _, err := faults.Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.post(token, takerBody); recorder.Code == http.StatusOK {
		t.Fatal("the taker committed")
	}
	faults.Clear()
	fixture.awaitStepEights()
	fixture.requireEvacuated(func(result *EvacuationResult) bool { return result.DeadCount == 1 })
	return fixture.slotLost(slotId, committedOrigin)
}

func TestSlotTwinTakesCommitted(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinTakesCommitted, slotTwinTakesCommittedSchedule)
}

// Two retokens of one refused statement whose object was stored just before them: the first reaches its takeover's
// DELETE, waiting out the settle age as the design has it, and is held there while the second, half a second on,
// takes the object over and commits creating path t; the first, creating t too, then sends its DELETE and dies at
// its step 7 if its slot round went on. 26 h on, evacuation drops the first's record.
func slotTwinTakesUnsettledSchedule(t *testing.T, rule evsSlotTwin) bool {
	takeover := newTakeoverCase(t, "twin unsettled", false, nil)
	fixture := takeover.fixture
	evacuation := &evacuateFixture{pushFixture: fixture, settings: DefaultEvacuatorSettings()}
	evacuation.settings.SpoolDirectory = t.TempDir()
	evacuation.settings.DeleteDeadSlots = true
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	firstBody, _ := fixture.bodyAndOrigin(takeover.retoken("t"))
	secondBody, secondOrigin := fixture.bodyAndOrigin(takeover.retoken("t"))
	token := fixture.token(fixture.check.signerId)

	var secondRecorder *httptest.ResponseRecorder
	atBarrierOnce(t, BarrierPushSlotTakeBefore, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		fixture.clock.Advance(500 * time.Millisecond)
		secondRecorder = fixture.post(token, secondBody)
	})
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- fixture.post(token, firstBody)
	}()
	if rule != evsSlotTwinTakesUnsettled {
		settledAt := storedAt.Add(fixture.settings.SlotSettleAge)
		fixture.awaitTimerAt(settledAt)
		fixture.clock.AdvanceTo(settledAt)
	}
	firstRecorder := <-answered
	sidecar.SetTestHooks(nil)
	fixture.requireCommitted(secondRecorder, 4)
	if firstRecorder.Code == http.StatusOK {
		t.Fatal("both retokens committed")
	}
	fixture.awaitStepEights()
	evacuation.requireEvacuated(func(result *EvacuationResult) bool { return result.DeadCount == 1 })
	return fixture.slotLost(takeover.slotId, secondOrigin)
}

func TestSlotTwinTakesUnsettled(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinTakesUnsettled, slotTwinTakesUnsettledSchedule)
}

// B: another writer lists a committed version's slot as new with its bytes and is refused; 26 h on, evacuation drops
// its record.
func slotTwinRelistSchedule(t *testing.T, rule evsSlotTwin) bool {
	fixture := newSlotEvacuateFixture(t)
	slotId, _, slotBody := checkTestSlot(t, "twin relisted")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)
	fixture.awaitStepEights()
	relisting := fixture.plan()
	fixture.createWithSlot(relisting, checkTestPath("b"), slotId, slotBody)
	requireRefusal(t, fixture.pushAsOther(relisting), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.requireEvacuated(func(result *EvacuationResult) bool { return result.DeadCount == 1 })
	return fixture.slotLost(slotId, committedOrigin)
}

func TestSlotTwinNoOriginAtDelete(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinNoOriginAtDelete, slotTwinRelistSchedule)
}

// A run stalled between its HEAD and its DELETE beside a second run, as in evacuate_slot_test.go: the dead
// statement's slot is stored late, at the runs' own time, when late is set, else long before; the second run
// decides it, and a later push of the writer's lists the id again, gap after, and commits if its create stands. The
// stalled run's DELETE then goes.
func slotTwinStalledSchedule(t *testing.T, late bool, gap time.Duration) bool {
	fixture := newSlotEvacuateFixture(t)
	fixture.commit("committed")
	slotId, _, body := checkTestSlot(t, "twin stalled")
	dead := fixture.plan()
	fixture.createWithSlot(dead, checkTestPath("dead"), slotId, body)
	_, deadOrigin := fixture.bodyAndOrigin(dead)
	fixture.putBatch(1, fixture.unposted(dead))
	if !late {
		fixture.plantSlot(slotId, body, deadOrigin)
	}
	fixture.age()
	if late {
		fixture.plantSlot(slotId, body, deadOrigin)
	}
	stalled := make(chan struct{})
	wake := make(chan struct{})
	first := fixture.evacuatorWith(func(name string, key string) error {
		if name == BarrierEvacuateSlotHeadAfter {
			close(stalled)
			<-wake
		}
		return nil
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.Run(fixture.ctx, "meta-1")
		firstDone <- err
	}()
	<-stalled
	if _, err := fixture.evacuatorWith(nil).Run(fixture.ctx, "meta-1"); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(gap)
	later := fixture.plan()
	fixture.createWithSlot(later, checkTestPath("later"), slotId, body)
	laterBody, laterOrigin := fixture.bodyAndOrigin(later)
	recorder := fixture.post(fixture.token(fixture.check.signerId), laterBody)
	close(wake)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK {
		// the later push did not commit: no committed version names the slot to lose
		return false
	}
	return fixture.slotLost(slotId, laterOrigin)
}

func TestSlotTwinUnconditionalDelete(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinUnconditionalDelete, func(t *testing.T, rule evsSlotTwin) bool {
		return slotTwinStalledSchedule(t, false, 5*time.Second)
	})
}

func TestSlotTwinNoSettle(t *testing.T) {
	requireSlotTwin(t, evsSlotTwinNoSettle, func(t *testing.T, rule evsSlotTwin) bool {
		return slotTwinStalledSchedule(t, true, 500*time.Millisecond)
	})
}
