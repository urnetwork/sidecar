// Erasure over versionless paths on evs (§11.12's versionless and drops rows; FS-69's ERASE clause, FS-96's slot
// clause; EVS2-M10-12), through the push and slots/delete routes:
//
//	closure   a CLOSURE rewrites a versionless file under a fresh key in a new slot, staged; its commit lists the
//	          replaced version's segment and slot for the purge, the ERASE after it destroys the old slot's key at
//	          once, and a minute after the CLOSURE the purge deletes the old ciphertext and slot; one that keeps the
//	          path's slot is refused 409 with the path
//	limit     at the storage limit a CLOSURE's staged bytes spend its eraser's allowance as inline records do
//	hold      an ERASE of a versionless path's one key under a hold destroys it at once, the ciphertext staying
//	          through the path's next replacement
//	drops     an ERASE whose slot a drop deleted, before it or between its commit and its rewrite, is done

package evsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A kind-5 upload of plan's push, stored at seg/ as an upload leaves it: its id and its receipt, its new-objects
// item on the plan.
func (self *pushFixture) kind5Upload(plan *sidecar.EvsPushPlan, label string) ([32]byte, *protocol.EvsUploadReceipt) {
	self.t.Helper()
	segmentId := sha256.Sum256([]byte("closure test segment " + label))
	uploadTime := self.clock.Now().Add(-time.Minute)
	receipt, err := IssueUploadReceipt(self.check.receiptKeys, self.check.repoId, segmentId, 4096, uploadTime, self.check.signerId, true, self.clock.Now())
	if err != nil {
		self.t.Fatal(err)
	}
	plan.NewObjects = append(plan.NewObjects, &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:], PaddedSize: 4096,
		UploadDay: uint32(uploadTime.UnixMilli() / evsUploadDayMs),
	})
	segments, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := segments.PutIfNoneMatch(self.ctx, SegmentKey(self.check.repoId, segmentId), make([]byte, 4096), nil); err != nil {
		self.t.Fatal(err)
	}
	return segmentId, receipt
}

// Whether the segment stands at seg/.
func (self *pushFixture) segmentStored(segmentId [32]byte) bool {
	self.t.Helper()
	segments, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	_, err = segments.Head(self.ctx, SegmentKey(self.check.repoId, segmentId))
	return err == nil
}

// Whether the slot's object stands.
func (self *pushFixture) slotStored(slotId sidecar.Id) bool {
	_, err := self.cluster.Head(self.ctx, SlotKey(self.check.repoId, slotId))
	return err == nil
}

// A versionless version of path at version on base, its chain the one locator, naming slotIds.
func (self *pushFixture) versionlessSlotted(plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, locator *protocol.EvsLocator, slotIds ...sidecar.Id) {
	self.t.Helper()
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), Chain: []*protocol.EvsLocator{locator},
	}
	for _, slotId := range slotIds {
		entry.SlotIds = append(entry.SlotIds, slotId.Bytes())
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: base, EntryVersion: entryBytes})
}

// Commits a versionless file at path as version 1: one uploaded kind-5 segment under a key in a slot of its own.
func (self *pushFixture) commitVersionlessSlotted(path sidecar.EvsTokenPath, label string) (sidecar.Id, [32]byte) {
	self.t.Helper()
	plan := self.plan()
	slotId, slotObject, slotBody := checkTestSlot(self.t, label)
	segmentId, receipt := self.kind5Upload(plan, label)
	self.versionlessSlotted(plan, path, 0, plan.BaseVersion+1, checkTestKind5Locator(segmentId, false), slotId)
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	body := self.bodyFormat2(plan)
	body.Receipts = []*protocol.EvsUploadReceipt{receipt}
	self.requireCommitted(self.post(self.adminToken(), body), plan.BaseVersion+1)
	self.awaitStepEights()
	return slotId, segmentId
}

// A CLOSURE replacing path's version base with a staged rewrite naming slotId, a new slot when its object is given,
// its list the erased keys: the plan and its staged bytes.
func (self *pushFixture) versionlessClosure(path sidecar.EvsTokenPath, base uint64, label string, slotId sidecar.Id, slotObject *sidecar.EvsNewObject, slotBody []byte, erased ...*sidecar.EvsErasedKey) (*sidecar.EvsPushPlan, [][]byte) {
	self.t.Helper()
	plan := self.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
	plan.Erased = erased
	segment, staged := checkTestStaged(self.t, plan, label)
	plan.NewObjects = append(plan.NewObjects, staged.NewObject())
	if slotObject != nil {
		plan.NewObjects = append(plan.NewObjects, slotObject)
		plan.SlotBodies = append(plan.SlotBodies, slotBody)
	}
	self.versionlessSlotted(plan, path, base, plan.BaseVersion+1, checkTestKind5Locator(staged.Id, true), slotId)
	return plan, [][]byte{segment}
}

// A purge over the fixture's host, its gate deleting, driven through runDue on the fixture's clock.
func (self *pushFixture) purger() *Purger {
	self.t.Helper()
	purger, err := newPurger(self.ctx, self.host.ServiceHost(), &PurgerDeps{
		Format2: &testFormat2Gate{purge: sidecar.Format2On},
		Newest:  self.engine.PurgeNewest(),
		wait:    self.clock.Advance,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(purger.Close)
	return purger
}

func TestClosureRewritesAVersionlessFileUnderAFreshSlot(t *testing.T) {
	fixture := newPushFixture(t, nil)
	sink := fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	admin := fixture.adminToken()
	x := checkTestPath("x")
	oldSlot, oldSegment := fixture.commitVersionlessSlotted(x, "x old")
	listed := &sidecar.EvsErasedKey{SlotId: oldSlot, KeyIndex: 0}

	// a rewrite that keeps the path's one key would lose its new content to the ERASE its list is for
	kept, keptStaged := fixture.versionlessClosure(x, 1, "kept", oldSlot, nil, nil, listed)
	recorder := fixture.post(admin, fixture.bodyStaged(kept, keptStaged))
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if paths := refusalOf(t, recorder).GetPaths(); len(paths) != 1 {
		t.Fatalf("the refusal names %d paths", len(paths))
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	newSlot, newSlotObject, newSlotBody := checkTestSlot(t, "x new")
	closure, staged := fixture.versionlessClosure(x, 1, "rewritten", newSlot, newSlotObject, newSlotBody, listed)
	fixture.requireCommitted(fixture.post(admin, fixture.bodyStaged(closure, staged)), 2)
	fixture.awaitStepEights()
	if !fixture.windowEntryAt(2).ReplacesVersionless() {
		t.Error("the CLOSURE's window entry lacks bit 4")
	}
	commits := sink.all()
	if len(commits) != 1 || len(commits[0].List.GetCandidates()) != 1 {
		t.Fatalf("the CLOSURE handed %d lists", len(commits))
	}
	candidate := commits[0].List.GetCandidates()[0]
	if !slices.ContainsFunc(candidate.GetSegmentIds(), func(id []byte) bool { return [32]byte(id) == oldSegment }) ||
		!slices.ContainsFunc(candidate.GetSlotIds(), func(id []byte) bool { return sidecar.Id(id) == oldSlot }) || len(candidate.GetSlotIds()) != 1 {
		t.Fatalf("the CLOSURE's candidates: %d segments, %d slots", len(candidate.GetSegmentIds()), len(candidate.GetSlotIds()))
	}

	// the ERASE waits for no purge: the old slot's key goes at once, the new slot's stays
	erase := fixture.erasePlan(listed)
	fixture.requireCommitted(fixture.slotsDelete(erase, "admin"), 1)
	if indexes := fixture.slotIndexes(oldSlot); indexes == nil || len(indexes) != 0 {
		t.Fatalf("the old slot's keys after the ERASE: %v", indexes)
	}
	if indexes := fixture.slotIndexes(newSlot); len(indexes) != 1 {
		t.Fatalf("the new slot's keys after the ERASE: %v", indexes)
	}

	// a minute after the CLOSURE the purge deletes the old ciphertext and slot, the ERASE's rewrite of it included
	purger := fixture.purger()
	purger.Certain(commits[0])
	fixture.clock.Advance(59 * time.Second)
	purger.runDue()
	if !fixture.segmentStored(oldSegment) || !fixture.slotStored(oldSlot) {
		t.Fatal("the purge deleted inside the readers' allowance")
	}
	fixture.clock.Advance(time.Second)
	purger.runDue()
	if fixture.segmentStored(oldSegment) || fixture.slotStored(oldSlot) {
		t.Fatalf("the old ciphertext or slot stands after the purge: %+v", purger.Stats())
	}
	if !fixture.slotStored(newSlot) {
		t.Fatal("the purge deleted the rewrite's slot")
	}
}

func TestClosureAtTheStorageLimitCountsItsStagedBytesAsInline(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	admin := fixture.adminToken()
	x := checkTestPath("x")
	oldSlot, _ := fixture.commitVersionlessSlotted(x, "x old")
	networkId := connect.Id(fixture.check.networkId)
	firstSlot, firstSlotObject, firstSlotBody := checkTestSlot(t, "x first")
	first, firstStaged := fixture.versionlessClosure(x, 1, "first", firstSlot, firstSlotObject, firstSlotBody, &sidecar.EvsErasedKey{SlotId: oldSlot, KeyIndex: 0})
	stagedByteCount := int64(len(firstStaged[0]))
	fixture.check.quota.atLimit(networkId)
	// the eraser's day, one full re-key at the floor, spent down to one rewrite's staged bytes and not two
	spent := sidecar.QuotaClosureUploadMaxByteCount - stagedByteCount - stagedByteCount/2
	if refusal, err := fixture.check.quota.gate.ChargeClosure(fixture.ctx, networkId, connect.Id(fixture.check.signerId), spent, connect.NewId()); err != nil || refusal != nil {
		t.Fatalf("the eraser's earlier closure upload: %+v %v", refusal, err)
	}
	// at the limit a CLOSURE's staged segment is accepted, as its inline records are
	fixture.requireCommitted(fixture.post(admin, fixture.bodyStaged(first, firstStaged)), 2)
	fixture.awaitStepEights()

	secondSlot, secondSlotObject, secondSlotBody := checkTestSlot(t, "x second")
	second, secondStaged := fixture.versionlessClosure(x, 2, "second", secondSlot, secondSlotObject, secondSlotBody, &sidecar.EvsErasedKey{SlotId: firstSlot, KeyIndex: 0})
	recorder := fixture.post(admin, fixture.bodyStaged(second, secondStaged))
	requireRefusal(t, recorder, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	refusal := refusalOf(t, recorder)
	if refusal.GetQuota().GetLimitKey() != "evs_closure_bytes_per_day" || refusal.GetRetryAfterMs() == 0 {
		t.Fatalf("the second CLOSURE's refusal: %v", refusal)
	}
	if fixture.head().Version() != 2 {
		t.Fatalf("the head after a CLOSURE past its eraser's allowance: %d", fixture.head().Version())
	}
}

func TestEraseUnderAHoldDestroysAVersionlessPathsKeyAndKeepsItsCiphertext(t *testing.T) {
	fixture := newPushFixture(t, nil)
	sink := fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	admin := fixture.adminToken()
	x := checkTestPath("x")
	slotId, segmentId := fixture.commitVersionlessSlotted(x, "x held")
	fixture.clock.Advance(time.Minute)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("erase hold"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)

	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	fixture.requireCommitted(fixture.slotsDelete(erase, "admin"), 1)
	if indexes := fixture.slotIndexes(slotId); indexes == nil || len(indexes) != 0 {
		t.Fatalf("the slot's keys after an ERASE under the hold: %v", indexes)
	}
	if !fixture.segmentStored(segmentId) {
		t.Fatal("the ERASE took the ciphertext")
	}

	// the path's next replacement, a rewrite under a new slot: the hold keeps what stood at its placement
	newSlot, newSlotObject, newSlotBody := checkTestSlot(t, "x after")
	replace := fixture.plan()
	segment, staged := checkTestStaged(t, replace, "after")
	replace.NewObjects = append(replace.NewObjects, staged.NewObject(), newSlotObject)
	replace.SlotBodies = append(replace.SlotBodies, newSlotBody)
	fixture.versionlessSlotted(replace, x, 1, 2, checkTestKind5Locator(staged.Id, true), newSlot)
	fixture.requireCommitted(fixture.post(admin, fixture.bodyStaged(replace, [][]byte{segment})), 2)
	fixture.awaitStepEights()
	commits := sink.all()
	if len(commits) != 1 {
		t.Fatalf("the replacement handed %d lists", len(commits))
	}
	purger := fixture.purger()
	purger.Certain(commits[0])
	fixture.clock.Advance(time.Minute)
	purger.runDue()
	if !fixture.segmentStored(segmentId) {
		t.Fatalf("the purge deleted the ciphertext the hold keeps: %+v", purger.Stats())
	}
	if stats := purger.Stats(); stats.HeldCount < 1 {
		t.Fatalf("the purge under the hold: %+v", stats)
	}
	// the slot the ERASE rewrote under the hold holds no key, whether or not the purge then takes its object
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 0 {
		t.Fatalf("the erased slot's keys: %v", indexes)
	}
}

func TestEraseMeetingASlotADropDeletedIsDone(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	dropped := fixture.commitWithSlot("dropped", 1, "a")
	standing := fixture.commitWithSlot("standing", 1, "b")
	raced := fixture.commitWithSlot("raced", 1, "c")
	deleteSlot := func(slotId sidecar.Id) {
		t.Helper()
		// as the drop's job deletes a slot no live version names
		if err := fixture.cluster.Delete(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err != nil {
			t.Fatal(err)
		}
	}
	deleteSlot(dropped)

	// one slot gone before the ERASE, one standing: it commits, rewrites the standing one, and writes nothing at
	// the deleted one's key
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: dropped, KeyIndex: 0}, &sidecar.EvsErasedKey{SlotId: standing, KeyIndex: 0})
	fixture.requireCommitted(fixture.slotsDelete(erase, "admin"), 1)
	if indexes := fixture.slotIndexes(standing); indexes == nil || len(indexes) != 0 {
		t.Fatalf("the standing slot's keys: %v", indexes)
	}
	if fixture.slotStored(dropped) {
		t.Fatal("the ERASE wrote a slot the drop deleted")
	}

	// the drop deletes a slot between an ERASE's commit and its rewrite: the retry and the reconciler count it done
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: SlotKey(fixture.check.repoId, raced), Result: sidecartest.FailBeforeApply, Repeat: DefaultEvsSettings().SlotRewriteRetryCount,
	}); err != nil {
		t.Fatal(err)
	}
	racing := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: raced, KeyIndex: 0})
	requireRefusal(t, fixture.slotsDelete(racing, "admin"), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if len(fixture.slotIndexes(raced)) != 1 {
		t.Fatal("the failed rewrite applied")
	}
	deleteSlot(raced)
	fixture.requireCommitted(fixture.slotsDelete(racing, "admin"), 2)
	finished, err := FinishErasures(fixture.ctx, fixture.host.ServiceHost(), fixture.check.repoId)
	if err != nil || finished != 2 {
		t.Fatalf("the reconciler over deleted slots: %d %v", finished, err)
	}
	if fixture.slotStored(raced) || fixture.slotStored(dropped) {
		t.Fatal("a rewrite put back a slot the drop deleted")
	}

	// an ERASE naming only slots a drop deleted names no key still held: NOTHING_TO_ERASE, which its client counts
	// done
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	gone := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: dropped, KeyIndex: 0}, &sidecar.EvsErasedKey{SlotId: raced, KeyIndex: 0})
	requireRefusal(t, fixture.slotsDelete(gone, "admin"), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE)
}

// The rewriter's own race: the slot answers its read and is deleted before the If-Match write, which the store
// answers 404; that is done, and nothing is written.
func TestSlotRewriteMeetingNotFoundAtIfMatchIsDone(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId := fixture.commitWithSlot("vanishing", 1, "a")
	key := SlotKey(fixture.check.repoId, slotId)
	priceTable, err := DefaultPriceTable(fixture.settings.PriceBlockByteCount)
	if err != nil {
		t.Fatal(err)
	}
	rewriter := &slotRewriter{budget: fixture.host.ServiceHost().Budget, priceTable: priceTable, settings: fixture.settings}
	cluster := &vanishingSlotCluster{BlobCluster: fixture.cluster, key: key}
	if err := rewriter.rewriteErased(fixture.ctx, cluster, fixture.check.repoId, []*sidecar.EvsErasedKey{{SlotId: slotId, KeyIndex: 0}}); err != nil {
		t.Fatalf("a rewrite meeting 404 at If-Match: %v", err)
	}
	if cluster.putCount != 1 || fixture.slotStored(slotId) {
		t.Fatalf("%d If-Match writes, the slot stored: %v", cluster.putCount, fixture.slotStored(slotId))
	}
}

// A cluster on which key's object is deleted, as a drop deletes a slot, just before each If-Match write of it.
type vanishingSlotCluster struct {
	sidecar.BlobCluster
	key      string
	putCount int
}

func (self *vanishingSlotCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if key == self.key {
		self.putCount += 1
		if err := self.BlobCluster.Delete(ctx, key); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
			return "", err
		}
	}
	return self.BlobCluster.PutIfMatch(ctx, key, etag, body, options)
}
