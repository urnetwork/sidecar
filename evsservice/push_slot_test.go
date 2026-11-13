// DESIGN-DETAILS 14.6's step 6 tests on T2's fakes through the push route, one per row of 14.2.3: a create carries
// its statement's origin; a 412 on the statement's own origin with equal bytes is the attempt's under 23 h and 409
// SLOT_STALE past it; its own origin with other bytes alarms and is refused; another statement's object is refused
// whatever the bytes, and so are an object with no origin and a re-seeded one; a retoken takes over the slot its
// refused statement left once the settle age has passed, waiting on the fake clock when it has not; and each of the
// takeover's five conditions failing alone refuses it. 5h's deposit rule (14.2.6, QD-768), and schedules C and D, end
// it. The rows whose schedule holds an attempt between two of its steps are push_slot_testhooks_test.go's.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The slot object the repo's cluster holds: its bytes, its origin and its LastModified, found false for none.
func (self *pushFixture) slotObject(slotId sidecar.Id) ([]byte, EvsSlotOrigin, time.Time, bool) {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, SlotKey(self.check.repoId, slotId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, EvsSlotOrigin{}, time.Time{}, false
	}
	if err != nil {
		self.t.Fatal(err)
	}
	stored, err := readAllLimited(object, self.settings.SlotMaxByteCount)
	object.Body.Close()
	if err != nil {
		self.t.Fatal(err)
	}
	return stored, ParseEvsSlotOrigin(object.Metadata, self.settings.SlotOriginMaxByteCount), object.LastModified, true
}

// The slot must hold body under origin.
func (self *pushFixture) requireSlotOrigin(slotId sidecar.Id, body []byte, origin EvsSlotOrigin) {
	self.t.Helper()
	stored, held, _, found := self.slotObject(slotId)
	if !found {
		self.t.Fatalf("slot %s is gone", slotId)
	}
	if !bytes.Equal(stored, body) || held != origin {
		self.t.Fatalf("slot %s holds origin %+v and %d bytes, want %+v", slotId, held, len(stored), origin)
	}
}

// Creates the slot holding body under origin at the clock's now, as another attempt's step 6, a re-seed or an evs of
// the release before the origin would: none writes no metadata.
func (self *pushFixture) plantSlot(slotId sidecar.Id, body []byte, origin EvsSlotOrigin) {
	self.t.Helper()
	metadata, err := origin.Metadata(self.settings.SlotOriginMaxByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	var options *sidecar.BlobPutOptions
	if metadata != nil {
		options = &sidecar.BlobPutOptions{Metadata: metadata}
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, SlotKey(self.check.repoId, slotId), body, options); err != nil {
		self.t.Fatal(err)
	}
}

// plan signed by key as signerId, who it names its signer: its request body and its statement's origin.
func (self *pushFixture) bodyAndOriginBy(plan *sidecar.EvsPushPlan, key ed25519.PrivateKey, signerId sidecar.Id) (*protocol.EvsPushRequest, EvsSlotOrigin) {
	self.t.Helper()
	plan.SignerSidecarId = signerId
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(key, signerId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	origin, err := EvsSlotOriginOf(built.Statement)
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}, origin
}

// plan signed by the fixture's writer: its request body and its statement's origin.
func (self *pushFixture) bodyAndOrigin(plan *sidecar.EvsPushPlan) (*protocol.EvsPushRequest, EvsSlotOrigin) {
	return self.bodyAndOriginBy(plan, self.check.signingKey, self.check.signerId)
}

// How many slot_foreign refusals step 6 counted, and how many slot_mismatch alarms.
func (self *pushFixture) slotCounts() (foreign float64, mismatch float64) {
	return self.host.Metrics.Value("urnetwork_evs_slot_foreign_total"), self.host.Metrics.Value("urnetwork_evs_alarms_total", "slot_mismatch")
}

// Waits, with no sleep, until a timer at at is pending on the fake clock: a takeover waiting out the settle age.
func (self *pushFixture) awaitTimerAt(at time.Time) {
	self.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-deadline:
			self.t.Fatalf("no timer at %s among %v", at, pending)
		}
	}
}

// The head's cache holds a commit, so an attempt's step 4 reads no head from the cluster.
func (self *pushFixture) commitCached(label string) {
	self.t.Helper()
	plan := self.plan()
	self.create(plan, label)
	self.requireCommitted(self.push(plan), plan.BaseVersion+1)
	self.awaitStepEights()
}

// Every head write and cluster read of the fixture's ref fails until cleared: an attempt past step 6 ends 503
// unknown with its record and slots written.
func (self *pushFixture) failHeadWrites() {
	self.t.Helper()
	for _, op := range []string{sidecartest.FaultOpPut, sidecartest.FaultOpGet} {
		if _, err := self.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
			Op: op, KeyPrefix: HeadKey(self.check.repoId, self.check.refId), Result: sidecartest.FailBeforeApply, Repeat: -1,
		}); err != nil {
			self.t.Fatal(err)
		}
	}
}

// 14.2.3's first row: the create stores the statement's origin beside its bytes: its push id and hash prefix, ref,
// signer, base version, declared path epoch and mode.
func TestPushSlotCreateCarriesItsStatementsOrigin(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "origin")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 1)
	fixture.requireSlotOrigin(slotId, slotBody, origin)
	if origin.PushId != plan.PushId || origin.RefId != fixture.check.refId || origin.SignerSidecarId != fixture.check.signerId ||
		origin.BaseVersion != 0 || origin.PathEpoch != 1 || origin.GitMode {
		t.Fatalf("origin %+v", origin)
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
}

// The statement's own object with equal bytes under 23 h: an attempt cut short after its step 6 left it, and the
// retry's create answers 412, its GET finds its own origin, and it commits with the object as the first attempt
// wrote it.
func TestPushSlotRetryTakesItsOwnObject(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.commitCached("x")
	slotId, _, slotBody := checkTestSlot(t, "retry")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	token := fixture.token(fixture.check.signerId)
	fixture.failHeadWrites()
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.Blobs.Faults().Clear()
	fixture.requireSlotOrigin(slotId, slotBody, origin)
	_, _, written, _ := fixture.slotObject(slotId)

	fixture.clock.Advance(time.Minute)
	fixture.requireCommitted(fixture.post(token, body), 2)
	fixture.requireSlotOrigin(slotId, slotBody, origin)
	if _, _, lastModified, _ := fixture.slotObject(slotId); !lastModified.Equal(written) {
		t.Fatal("the retry wrote its own slot again")
	}
}

// The statement's own object with equal bytes past 23 h: 409 SLOT_STALE, recorded, as a re-uploaded segment's is.
func TestPushSlotOwnObjectPast23HoursIsStale(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "own old")
	plan := fixture.plan()
	plan.TimeMs = fixture.clock.Now().Add(24 * time.Hour).UnixMilli()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	// an attempt of the statement left its slot a day before the time it gives
	fixture.plantSlot(slotId, slotBody, origin)
	fixture.clock.Advance(24 * time.Hour)
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	if len(fixture.head().Head.GetRefused()) == 0 {
		t.Fatal("the refusal was not recorded")
	}
	fixture.requireSlotOrigin(slotId, slotBody, origin)
}

// The statement's own object with other bytes, no ERASE of a commit of it explaining them: the cluster read and 5a
// find the push not committed, so slot_mismatch alarms and the push is refused 409 SLOT_STALE, the object kept.
func TestPushSlotOwnObjectWithOtherBytesAlarms(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "own other")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	otherBody := otherSlotBody(t, 7)
	fixture.plantSlot(slotId, otherBody, origin)
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 1 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
	fixture.requireSlotOrigin(slotId, otherBody, origin)
}

// Another statement's object is refused 409 SLOT_STALE whatever the bytes: another writer's statement and a later
// statement of the same writer, each listing a committed version's young slot as new with its bytes or with others.
// Each is counted slot_foreign and none alarms; the committed version's object stands under its own origin.
func TestPushSlotAnotherStatementsObjectIsRefusedWhateverTheBytes(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "committed")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)

	relists := []struct {
		label string
		body  []byte
		other bool
	}{
		{label: "other writer equal", body: slotBody, other: true},
		{label: "other writer other", body: otherSlotBody(t, 1), other: true},
		{label: "same writer equal", body: slotBody},
		{label: "same writer other", body: otherSlotBody(t, 2)},
	}
	for _, relist := range relists {
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
		plan := fixture.plan()
		fixture.createWithSlot(plan, checkTestPath(relist.label), slotId, relist.body)
		var recorder *httptest.ResponseRecorder
		if relist.other {
			recorder = fixture.pushAsOther(plan)
		} else {
			recorder = fixture.push(plan)
		}
		if recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE {
			t.Fatalf("%s: %d (%s), want 409 SLOT_STALE", relist.label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != float64(len(relists)) || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
	if head := fixture.head(); head.Version() != 1 {
		t.Fatalf("a re-listing committed: the head is at %d", head.Version())
	}
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
}

// An object with no origin, as an evs of the release before writes, and a re-seeded one: neither is any statement's,
// so a push listing either is refused 409 SLOT_STALE with equal bytes, and the object stays as it was.
func TestPushSlotWithNoOriginOrReseededIsRefused(t *testing.T) {
	fixture := newPushFixture(t, nil)
	for i, origin := range []EvsSlotOrigin{{}, EvsSlotOriginReseeded()} {
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
		label := string(rune('a'+i)) + " unowned"
		slotId, _, slotBody := checkTestSlot(t, label)
		fixture.plantSlot(slotId, slotBody, origin)
		plan := fixture.plan()
		fixture.createWithSlot(plan, checkTestPath(label), slotId, slotBody)
		requireRefusal(t, fixture.push(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
		fixture.requireSlotOrigin(slotId, slotBody, origin)
	}
	if foreign, _ := fixture.slotCounts(); foreign != 2 {
		t.Fatalf("counted %v foreign", foreign)
	}
}

// 14.2.4's ground: a ref crossed to generation 2 under a REMOVE, a statement o of the writer's in epoch 1 listing a
// new slot, and o's slot object as o's step 6 left it before a PATH_EPOCH cut the ref over to epoch 2. adjust breaks
// one condition in the object's origin or bytes; settled advances the clock past the settle age. The retoken lists
// the same slot id and bytes in epoch 2, as 9.2.5's retoken of o does.
type takeoverCase struct {
	fixture    *pushFixture
	commitment []byte
	slotId     sidecar.Id
	slotBody   []byte
	// o's origin as its own create would write it, and the one the object carries
	refused EvsSlotOrigin
	planted EvsSlotOrigin
}

func newTakeoverCase(t *testing.T, label string, settled bool, adjust func(origin *EvsSlotOrigin, body *[]byte)) *takeoverCase {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	slotId, _, slotBody := checkTestSlot(t, "takeover "+label)
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	_, refusedOrigin := fixture.bodyAndOrigin(refused)
	planted, plantedBody := refusedOrigin, slotBody
	if adjust != nil {
		adjust(&planted, &plantedBody)
	}
	fixture.plantSlot(slotId, plantedBody, planted)
	if settled {
		fixture.clock.Advance(fixture.settings.SlotSettleAge)
	}
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	return &takeoverCase{fixture: fixture, commitment: commitment, slotId: slotId, slotBody: slotBody, refused: refusedOrigin, planted: planted}
}

// The retoken's plan: the writer's push in epoch 2 creating path, its source in epoch 1 named, listing the slot.
func (self *takeoverCase) retoken(label string) *sidecar.EvsPushPlan {
	plan := self.fixture.planOnHead(2, self.commitment)
	self.fixture.createWithSlot(plan, epochPath(2, label), self.slotId, self.slotBody)
	plan.Changes[0].SourcePaths = [][]byte{epochSourcePath(self.fixture.t, 1, label)}
	return plan
}

// A retoken whose refused statement left its slot, settled: the create answers 412, the GET finds o's origin, and
// every condition holds, so the DELETE naming the object's LastModified goes and the create again stores the
// retoken's own object. It commits, and the slot stands under its origin.
func TestPushSlotRetokenTakesOverItsRefusedStatementsSlot(t *testing.T) {
	takeover := newTakeoverCase(t, "settled", true, nil)
	fixture := takeover.fixture
	body, origin := fixture.bodyAndOrigin(takeover.retoken("s"))
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 4)
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, origin)
	if _, _, lastModified, _ := fixture.slotObject(takeover.slotId); !lastModified.Equal(fixture.clock.Now()) {
		t.Fatal("the retoken's object is not its own create's")
	}
	if foreign, _ := fixture.slotCounts(); foreign != 0 {
		t.Fatalf("counted %v foreign", foreign)
	}
}

// The wait: the refused statement's object stored just before the retoken arrives. The retoken's slot round waits on
// evs's clock until the object's LastModified plus SlotSettleAge, sending nothing meanwhile, and then takes it over.
func TestPushSlotTakeoverWaitsOutTheSettleAge(t *testing.T) {
	takeover := newTakeoverCase(t, "unsettled", false, nil)
	fixture := takeover.fixture
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	body, origin := fixture.bodyAndOrigin(takeover.retoken("s"))
	answered := make(chan *httptest.ResponseRecorder, 1)
	token := fixture.token(fixture.check.signerId)
	go func() {
		answered <- fixture.post(token, body)
	}()
	settledAt := storedAt.Add(fixture.settings.SlotSettleAge)
	fixture.awaitTimerAt(settledAt)
	select {
	case recorder := <-answered:
		t.Fatalf("the retoken answered %d before the settle age", recorder.Code)
	default:
	}
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, takeover.refused)
	fixture.clock.AdvanceTo(settledAt)
	fixture.requireCommitted(<-answered, 4)
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, origin)
}

// A clock that stops being sure while a takeover waits out the settle age: the takeover answers 503 rather than wait
// on a clock it cannot trust (14.5), sending no DELETE, and the refused statement's object stands.
func TestPushSlotTakeoverOnAClockTurnedUnsureAnswers503(t *testing.T) {
	takeover := newTakeoverCase(t, "unsure", false, nil)
	fixture := takeover.fixture
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	body, _ := fixture.bodyAndOrigin(takeover.retoken("s"))
	answered := make(chan *httptest.ResponseRecorder, 1)
	token := fixture.token(fixture.check.signerId)
	go func() {
		answered <- fixture.post(token, body)
	}()
	fixture.awaitTimerAt(storedAt.Add(fixture.settings.SlotSettleAge))
	fixture.host.ClockCheck.SetUnknown()
	requireRefusal(t, <-answered, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.ClockCheck.SetOffset(0)
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, takeover.refused)
	if head := fixture.head(); head.Version() != 3 {
		t.Fatalf("the retoken committed at %d", head.Version())
	}
}

// The takeover's conditions, each failing alone: the object of another ref's statement, another signer's, one in the
// retoken's own epoch, and one holding other bytes are another statement's, refused 409 SLOT_STALE and left as they
// were. The window, a log page and a hold are the next tests'.
func TestPushSlotTakeoverConditionsEachRefuseAlone(t *testing.T) {
	cases := []struct {
		label  string
		adjust func(origin *EvsSlotOrigin, body *[]byte)
	}{
		{label: "another ref", adjust: func(origin *EvsSlotOrigin, body *[]byte) { origin.RefId = testId("takeover another ref") }},
		{label: "another signer", adjust: func(origin *EvsSlotOrigin, body *[]byte) { origin.SignerSidecarId = testId("takeover another signer") }},
		{label: "an equal epoch", adjust: func(origin *EvsSlotOrigin, body *[]byte) { origin.PathEpoch = 2 }},
		{label: "other bytes", adjust: func(origin *EvsSlotOrigin, body *[]byte) { *body = otherSlotBody(t, 3) }},
	}
	for _, c := range cases {
		takeover := newTakeoverCase(t, c.label, true, c.adjust)
		fixture := takeover.fixture
		plantedBody, _, plantedAt, _ := fixture.slotObject(takeover.slotId)
		recorder := fixture.push(takeover.retoken("s"))
		if recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE {
			t.Fatalf("%s: %d (%s), want 409 SLOT_STALE", c.label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
		fixture.requireSlotOrigin(takeover.slotId, plantedBody, takeover.planted)
		if _, _, lastModified, _ := fixture.slotObject(takeover.slotId); !lastModified.Equal(plantedAt) {
			t.Fatalf("%s: the object was replaced", c.label)
		}
		if foreign, _ := fixture.slotCounts(); foreign != 1 {
			t.Fatalf("%s: counted %v foreign", c.label, foreign)
		}
	}
}

// The takeover's third condition through the window: the statement whose origin the object carries committed in
// epoch 1, its slot with it, so a statement of epoch 2 listing the slot finds it committed in the head and is refused
// 409 SLOT_STALE; an origin naming that committed push id under another statement prefix is refused the same way.
func TestPushSlotTakeoverRefusesAnOriginTheWindowShowsCommitted(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	slotId, _, slotBody := checkTestSlot(t, "committed in epoch 1")
	committed := fixture.planAtTwo(commitment)
	fixture.createWithSlot(committed, checkTestPath("s"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 3)
	// the committed push id under another statement's prefix, on a slot of its own
	reusedId, _, reusedBody := checkTestSlot(t, "reused push id")
	reused := committedOrigin
	reused.StatementPrefix[0] ^= 1
	fixture.plantSlot(reusedId, reusedBody, reused)
	fixture.clock.Advance(fixture.settings.SlotSettleAge)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))

	for _, relist := range []struct {
		label  string
		slotId sidecar.Id
		body   []byte
	}{
		{label: "t", slotId: slotId, body: slotBody},
		{label: "u", slotId: reusedId, body: reusedBody},
	} {
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
		plan := fixture.planOnHead(2, commitment)
		fixture.createWithSlot(plan, epochPath(2, relist.label), relist.slotId, relist.body)
		plan.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, relist.label)}
		requireRefusal(t, fixture.push(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	}
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
	fixture.requireSlotOrigin(reusedId, reusedBody, reused)
}

// The takeover's third condition through a log page: the origin's statement committed in epoch 1 and the window
// has since paged it out, so EvsPushStandingIn finds it in the log page of (b, b+64] and the retoken is refused 409
// SLOT_STALE, the committed slot standing.
func TestPushSlotTakeoverRefusesAnOriginALogPageShowsCommitted(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	slotId, _, slotBody := checkTestSlot(t, "committed and paged")
	committed := fixture.planAtTwo(commitment)
	fixture.createWithSlot(committed, checkTestPath("s"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 3)
	for version := uint64(4); EvsHeadWindowFirstVersion(fixture.head().Head) <= 3; version += 1 {
		plan := fixture.planAtTwo(commitment)
		fixture.write(plan, version-2, "a")
		fixture.requireCommitted(fixture.push(plan), version)
	}
	fixture.awaitStepEights()
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	plan := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(plan, epochPath(2, "t"), slotId, slotBody)
	plan.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "t")}
	requireRefusal(t, fixture.push(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
}

// The takeover's fifth condition: under a hold covering the repo the object stays, as a dead record's slot does, and
// the retoken is refused 409 SLOT_STALE, to be rebuilt.
func TestPushSlotTakeoverRefusesUnderAHold(t *testing.T) {
	takeover := newTakeoverCase(t, "held", true, nil)
	fixture := takeover.fixture
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("takeover hold"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, fixture.push(takeover.retoken("s")), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, takeover.refused)
}

// The rule EvsSlotTwin-StampBeforeRecord breaks (S4): step 6 appends the record before any slot, so an attempt whose
// batch is never written stores no slot and no origin without a record evacuation would resolve.
func TestPushSlotNotWrittenWithoutItsRecord(t *testing.T) {
	fixture := newPushFixture(t, nil)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: batchKeyPrefix, Result: sidecartest.FailBeforeApply, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	slotId, _, slotBody := checkTestSlot(t, "no record")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	requireRefusal(t, fixture.push(plan), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if _, _, _, found := fixture.slotObject(slotId); found {
		t.Fatal("a slot was stored with no record written")
	}
}

// 14.2.6's ERASE: the rewrite of a slot without its erased keys keeps the metadata it read, so the slot keeps the
// origin of the statement that created it, and its new LastModified with it.
func TestEraseRewriteKeepsTheSlotsOrigin(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	slotId, object, slotBody := eraseTestSlot(t, "origin kept", 2)
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, object)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 1)
	fixture.clock.Advance(time.Minute)
	fixture.requireCommitted(fixture.slotsDelete(fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 1}), "admin"), 1)
	stored, held, lastModified, found := fixture.slotObject(slotId)
	if !found || held != origin || bytes.Equal(stored, slotBody) || !lastModified.Equal(fixture.clock.Now()) {
		t.Fatalf("the rewritten slot: found %t, origin %+v", found, held)
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 0 {
		t.Fatalf("slot keys %v after erasing key 1", indexes)
	}
}

// A deposit on the depositor's own deposit ref, created on no head, as signer under key.
func (self *pushFixture) depositPlan(depositor sidecar.Id) *sidecar.EvsPushPlan {
	refId := sidecar.EvsDepositRefId(self.check.repoId, depositor)
	plan := self.plan()
	plan.RefId = refId
	plan.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	plan.OwnerSidecarId = &depositor
	plan.SignerSidecarId = depositor
	plan.BaseVersion = 0
	plan.BaseChain = sidecar.EvsChainStart(self.check.repoId, refId)
	if head := self.headOf(refId); !head.Absent() && 0 < head.Version() {
		plan.BaseVersion = head.Version()
		plan.BaseChain = [32]byte(head.Head.GetChain())
	}
	return plan
}

// 5h's deposit rule (DESIGN-DETAILS 14.2.6, QD-768) at the check: on a deposit ref every slot a new version names is
// one its push introduces. A deposit naming a slot through a reuse source or its path's base is 409 SLOT_UNKNOWN,
// recorded, and one introducing its slot passes; the twin on a shared ref cites the same slots and passes.
func TestCheckObjectsDepositNamesOnlySlotsItIntroduces(t *testing.T) {
	fixture := newCheckFixture(t)
	path := checkTestPath("deposit")
	inline := []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}}
	viewOf := func(refKind protocol.EvsRefKind, objects []*sidecar.EvsNewObject, slotBodies [][]byte, slotIds ...sidecar.Id) *PushView {
		plan := fixture.plan()
		plan.RefKind = refKind
		if refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT {
			plan.RefId = sidecar.EvsDepositRefId(fixture.repoId, fixture.signerId)
			plan.OwnerSidecarId = &fixture.signerId
		}
		plan.NewObjects = objects
		plan.SlotBodies = slotBodies
		plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: path, EntryVersion: fixture.fileEntry(plan, 1, inline, slotIds...)}}
		return fixture.view(plan)
	}
	slotId, slotObject, slotBody := checkTestSlot(t, "deposit's own")
	requireCheckPass(t, "a deposit introducing its slot", CheckObjects(viewOf(protocol.EvsRefKind_EVS_REF_DEPOSIT, []*sidecar.EvsNewObject{slotObject}, [][]byte{slotBody}, slotId)))

	cited := testId("check cited by a deposit")
	citedEntry := &protocol.EvsEntryVersion{Version: 1, PushId: testId("check cited push").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		Chain: inline, SlotIds: [][]byte{cited.Bytes()}}
	citedBytes, err := proto.Marshal(citedEntry)
	if err != nil {
		t.Fatal(err)
	}
	reuse := &sidecar.EvsReuse{RefId: testId("check cited ref"), EntryVersion: 1, TokenPath: checkTestPath("source")}
	for _, refKind := range []protocol.EvsRefKind{protocol.EvsRefKind_EVS_REF_DEPOSIT, protocol.EvsRefKind_EVS_REF_SHARED} {
		fromReuse := viewOf(refKind, nil, nil, cited)
		fromReuse.Reuses = []*ReuseRead{{Reuse: reuse, EntryVersion: citedEntry}}
		fromBase := viewOf(refKind, nil, nil, cited)
		fromBase.Paths[path.KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Version: 1, CommitVersion: 1,
			IndexVersion: &protocol.EvsIndexVersion{CommitVersion: 1, EntryVersion: citedBytes}}}
		if refKind == protocol.EvsRefKind_EVS_REF_SHARED {
			requireCheckPass(t, "a shared ref's push citing through a reuse source", CheckObjects(fromReuse))
			requireCheckPass(t, "a shared ref's push citing its path's base", CheckObjects(fromBase))
			continue
		}
		refusal := CheckObjects(fromReuse)
		requireCheckRefusal(t, "a deposit citing through a reuse source", refusal, EvsCheckReasonSlotUnknown)
		if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(path) || refusal.Fate != EvsRefusalRecorded) {
			t.Errorf("the deposit's refusal names %v, fate %v", refusal.Paths, refusal.Fate)
		}
		requireCheckRefusal(t, "a deposit citing its path's base", CheckObjects(fromBase), EvsCheckReasonSlotUnknown)
	}
}

// Schedule C, the second introduction (14.1's C), refused: a depositor lists a young slot of the shared ref as new
// in a deposit, with its bytes, and is refused 409 SLOT_STALE at step 6, the object another statement's. A deposit
// introducing its own slot commits and a reader's CONSUME of it deletes that slot alone; the shared ref's committed
// slot stands under its origin and reads back.
func TestDepositCannotIntroduceAnotherRefsSlotAndItsConsumeDeletesOnlyItsOwn(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "the shared ref's")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)
	fixture.awaitStepEights()

	depositor := fixture.check.otherId
	fixture.auth.grant(depositor, fixture.check.repoId, sidecar.AclEvsDeposit)
	depositToken := fixture.token(depositor, "deposit")
	second := fixture.depositPlan(depositor)
	fixture.createWithSlot(second, checkTestPath("deposit 1"), slotId, slotBody)
	secondBody, _ := fixture.bodyAndOriginBy(second, fixture.check.otherKey, depositor)
	requireRefusal(t, fixture.post(depositToken, secondBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)

	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	ownId, _, ownBody := checkTestSlot(t, "the deposit's own")
	own := fixture.depositPlan(depositor)
	fixture.createWithSlot(own, checkTestPath("deposit 2"), ownId, ownBody)
	ownRequest, ownOrigin := fixture.bodyAndOriginBy(own, fixture.check.otherKey, depositor)
	fixture.requireCommitted(fixture.post(depositToken, ownRequest), 1)
	fixture.requireSlotOrigin(ownId, ownBody, ownOrigin)

	refId := sidecar.EvsDepositRefId(fixture.check.repoId, depositor)
	consume := fixture.plan()
	consume.PushId = testId("consume of the deposit")
	consume.RefId = refId
	consume.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	consume.OwnerSidecarId = &depositor
	consume.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME)
	consume.ConsumedThrough = 1
	consume.BaseVersion = 1
	consume.BaseChain = [32]byte(fixture.headOf(refId).Head.GetChain())
	consume.Changes = append(consume.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath("deposit 2"), BaseEntryVersion: 1})
	consumeBody, _ := fixture.bodyAndOrigin(consume)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), consumeBody), 2)
	if _, _, _, found := fixture.slotObject(ownId); found {
		t.Fatal("the consumed deposit's slot stands")
	}
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
}

// Schedule D, the citing deposit (14.1's D), refused at 5h: a reader that may deposit commits nothing whose version
// names the shared ref's slot through a reuse source of that ref's committed version, with no bytes of its own; it is
// refused 409 SLOT_UNKNOWN, recorded, and the slot stands.
func TestDepositCitingAnotherRefsSlotIsRefusedAtFiveH(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "cited by a deposit")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)
	fixture.awaitStepEights()

	depositor := fixture.check.otherId
	fixture.auth.grant(depositor, fixture.check.repoId, sidecar.AclEvsDeposit)
	citing := fixture.depositPlan(depositor)
	citing.Changes = append(citing.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("deposit 1"), EntryVersion: fixture.check.fileEntry(citing, 1, nil, slotId),
	})
	citing.ReuseList = []*sidecar.EvsReuse{{RefId: fixture.check.refId, EntryVersion: 1, TokenPath: checkTestPath("a")}}
	citingBody, _ := fixture.bodyAndOriginBy(citing, fixture.check.otherKey, depositor)
	recorder := fixture.post(fixture.token(depositor, "deposit"), citingBody)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	if head := fixture.headOf(sidecar.EvsDepositRefId(fixture.check.repoId, depositor)); head.Absent() || len(head.Head.GetRefused()) == 0 {
		t.Fatal("the citing deposit's refusal was not recorded")
	}
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
}
