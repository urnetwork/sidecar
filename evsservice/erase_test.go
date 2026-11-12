// EVS1-M2-20's tests: §22.5's erasure list on T2. An ERASE through slots/delete rewrites the named slots without
// their keys before its 200, and its retry finds nothing left; a list naming no held key gets 409 NOTHING_TO_ERASE,
// recorded; slots/delete below admin is refused at arrival with every slot as it was (I-EVS-16); a rewrite that
// cannot finish queues the reconciler, which FinishErasures runs; FS-47's CLOSURE rows; a CONSUME deleting its
// deposit's slots and raising consumed_through; and the read-receipt budget.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A slot of keyCount keys, its id, new-objects item and body.
func eraseTestSlot(t *testing.T, label string, keyCount int) (sidecar.Id, *sidecar.EvsNewObject, []byte) {
	t.Helper()
	slot := &protocol.EvsSlotObject{}
	for index := 0; index < keyCount; index += 1 {
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: uint32(index), Generation: 1, Wrapped: bytes.Repeat([]byte{byte(index + 1)}, sidecar.EvsWrappedKeyByteCount)})
	}
	body, err := sidecar.EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	slotId := testId("erase slot " + label)
	return slotId, &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()}, body
}

// Commits a file at labels on the shared ref naming a new slot of keyCount keys, at the head's next version.
func (self *pushFixture) commitWithSlot(slotLabel string, keyCount int, labels ...string) sidecar.Id {
	slotId, object, body := eraseTestSlot(self.t, slotLabel, keyCount)
	plan := self.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath(labels...), EntryVersion: self.check.fileEntry(plan, plan.BaseVersion+1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, object)
	plan.SlotBodies = append(plan.SlotBodies, body)
	self.requireCommitted(self.push(plan), plan.BaseVersion+1)
	return slotId
}

// The slot's keys' indexes as stored, nil for a slot that is gone.
func (self *pushFixture) slotIndexes(slotId sidecar.Id) []uint32 {
	object, err := self.cluster.Get(self.ctx, SlotKey(self.check.repoId, slotId))
	if err != nil {
		return nil
	}
	objectBytes, _ := readAllLimited(object, DefaultEvsSettings().SlotMaxByteCount)
	object.Body.Close()
	slot, err := sidecar.EvsDecodeSlotObject(objectBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	indexes := []uint32{}
	for _, key := range slot.GetKeys() {
		indexes = append(indexes, key.GetKeyIndex())
	}
	return indexes
}

// An ERASE on the repo's erasure ref, its note at a random id, naming erased.
func (self *pushFixture) erasePlan(erased ...*sidecar.EvsErasedKey) *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.RefId = sidecar.EvsErasureRefId(self.check.repoId)
	plan.RefKind = protocol.EvsRefKind_EVS_REF_ERASURE
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE)
	plan.Erased = erased
	erasureHead, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.check.repoId, plan.RefId)
	if err != nil {
		self.t.Fatal(err)
	}
	plan.BaseVersion = 0
	plan.BaseChain = sidecar.EvsChainStart(self.check.repoId, plan.RefId)
	if !erasureHead.Absent() && 0 < erasureHead.Version() {
		plan.BaseVersion = erasureHead.Version()
		plan.BaseChain = [32]byte(erasureHead.Head.GetChain())
	}
	plan.Changes = append(plan.Changes, self.check.change(plan, checkTestPath("note", plan.PushId.String()), 0, plan.BaseVersion+1))
	return plan
}

// One POST .../slots/delete of plan under the writer's token with roles.
func (self *pushFixture) slotsDelete(plan *sidecar.EvsPushPlan, roles ...string) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(self.body(plan))
	if err != nil {
		self.t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+"/slots/delete", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+self.token(self.check.signerId, roles...))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestEraseRewritesTheNamedSlots(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	slotId := fixture.commitWithSlot("a", 2, "a")
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	fixture.requireCommitted(fixture.slotsDelete(erase, "admin"), 1)
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v after erasing key 0", indexes)
	}
	// its retry answers the commit, and the slot stays as rewritten
	fixture.requireCommitted(fixture.slotsDelete(erase, "admin"), 1)
	// a list naming no key the slot still holds
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	again := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	requireRefusal(t, fixture.slotsDelete(again, "admin"), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE)
}

// I-EVS-16: below admin, slots/delete is refused at arrival, every slot as it was and nothing committed.
func TestEraseBelowAdminIsRefusedAtArrival(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId := fixture.commitWithSlot("a", 2, "a")
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	requireRefusal(t, fixture.slotsDelete(erase), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 2 {
		t.Fatalf("slot keys %v after a refused erasure", indexes)
	}
	head, err := fixture.engine.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.check.repoId, sidecar.EvsErasureRefId(fixture.check.repoId))
	if err != nil || !head.Absent() {
		t.Fatal("a refused erasure wrote the erasure ref")
	}
}

// A rewrite that cannot finish answers 503 unknown and queues evs.erasure_finish; FinishErasures then finishes it.
func TestEraseRewriteFinishedByTheReconciler(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	slotId := fixture.commitWithSlot("a", 2, "a")
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: SlotKey(fixture.check.repoId, slotId), Result: sidecartest.FailBeforeApply, Repeat: evsSlotRewriteRetryCount,
	}); err != nil {
		t.Fatal(err)
	}
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 1})
	recorder := fixture.slotsDelete(erase, "admin")
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("an unfinished rewrite's answer is not unknown")
	}
	if len(fixture.slotIndexes(slotId)) != 2 {
		t.Fatal("the failed rewrite applied")
	}
	queued := false
	for _, request := range fixture.host.Tasks.AllRequests() {
		queued = queued || request.Name == EvsErasureFinishTaskName
	}
	if !queued {
		t.Fatal("the reconciler was not queued")
	}
	finished, err := FinishErasures(fixture.ctx, fixture.host.ServiceHost(), fixture.check.repoId)
	if err != nil || finished != 1 {
		t.Fatalf("finished %d %v", finished, err)
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 0 {
		t.Fatalf("slot keys %v after the reconciler", indexes)
	}
}

// A CLOSURE replacing a's version 1, its chain records and its list as given.
func (self *pushFixture) closurePlan(base uint64, chain []*protocol.EvsLocator, erased ...*sidecar.EvsErasedKey) *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
	plan.Erased = erased
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), BaseEntryVersion: base, EntryVersion: self.check.fileEntry(plan, base+1, chain),
	})
	return plan
}

// FS-47's CLOSURE rows below the limit: one replacing a's version, listing its slot, within Padmé, commits; one
// omitting the slot, one growing the chain past Padmé and one creating a path get 409 with the paths; a non-admin's
// is refused.
func TestClosureRules(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	slotId := fixture.commitWithSlot("a", 1, "a")
	admin := fixture.token(fixture.check.signerId, "admin")
	inline := func(byteCount int) []*protocol.EvsLocator {
		return []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: make([]byte, byteCount)}}
	}
	listed := &sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0}
	// the committed version's chain is fileEntry's one inline record of 13 bytes
	omitted := fixture.closurePlan(1, inline(13))
	requireRefusal(t, fixture.post(admin, fixture.body(omitted)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	grown := fixture.closurePlan(1, inline(4096), listed)
	requireRefusal(t, fixture.post(admin, fixture.body(grown)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	creating := fixture.plan()
	creating.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
	creating.Erased = []*sidecar.EvsErasedKey{listed}
	fixture.create(creating, "new")
	requireRefusal(t, fixture.post(admin, fixture.body(creating)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	rw := fixture.closurePlan(1, inline(13), listed)
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), fixture.body(rw)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	good := fixture.closurePlan(1, inline(14), listed)
	fixture.requireCommitted(fixture.post(admin, fixture.body(good)), 2)
}

// A depositor's deposit naming a new slot, then a reader's CONSUME of it: the slot goes and consumed_through rises.
func TestConsumeDeletesItsSlotsAndRaisesConsumedThrough(t *testing.T) {
	fixture := newPushFixture(t, nil)
	depositor := fixture.check.signerId
	fixture.auth.grant(depositor, fixture.check.repoId, sidecar.AclEvsDeposit)
	refId := sidecar.EvsDepositRefId(fixture.check.repoId, depositor)
	slotId, object, slotBody := eraseTestSlot(t, "deposit", 1)
	deposit := fixture.plan()
	deposit.RefId = refId
	deposit.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	deposit.OwnerSidecarId = &depositor
	deposit.BaseVersion = 0
	deposit.BaseChain = sidecar.EvsChainStart(fixture.check.repoId, refId)
	deposit.Changes = append(deposit.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("deposit 1"), EntryVersion: fixture.check.fileEntry(deposit, 1, nil, slotId),
	})
	deposit.NewObjects = append(deposit.NewObjects, object)
	deposit.SlotBodies = append(deposit.SlotBodies, slotBody)
	reply := fixture.requireCommitted(fixture.post(fixture.token(depositor, "deposit"), fixture.body(deposit)), 1)
	if reply.GetDepositHead().GetVersion() != 1 {
		t.Fatalf("a depositor's 200 carries head %v", reply.GetDepositHead())
	}

	consume := fixture.plan()
	consume.PushId = testId("consume push")
	consume.RefId = refId
	consume.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	consume.OwnerSidecarId = &depositor
	consume.SignerSidecarId = fixture.check.otherId
	consume.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME)
	consume.ConsumedThrough = 1
	consume.BaseVersion = 1
	consume.BaseChain = [32]byte(fixture.headOf(refId).Head.GetChain())
	consume.Changes = append(consume.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath("deposit 1"), BaseEntryVersion: 1})
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.otherKey, fixture.check.otherId)).Build(consume)
	if err != nil {
		t.Fatal(err)
	}
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.otherId), &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}), 2)
	if _, err := fixture.cluster.Head(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err == nil {
		t.Fatal("a consumed deposit's slot stands")
	}
	if head := fixture.headOf(refId); head.Head.GetConsumedThrough() != 1 {
		t.Fatalf("consumed_through %d", head.Head.GetConsumedThrough())
	}
}

// A ref's head from the cluster.
func (self *pushFixture) headOf(refId sidecar.Id) *EvsStoredHead {
	head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.check.repoId, refId)
	if err != nil {
		self.t.Fatal(err)
	}
	return head
}

// §11.12's receipts: a reader of a vault that does not write it deposits receipts of at most 4 KiB, 256 a day; past
// the count 429 RESOURCE_EXHAUSTED with retry_after_ms, past the size 403 naming evs_read_receipt_bytes.
func TestReadReceiptsBudget(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_VAULT, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	// the state: other reads the vault and does not write it
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: fixture.check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(testId("check member"), fixture.check.signerId, fixture.check.otherId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	fixture.check.auth = fixture.check.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			fixture.check.signerId: fixture.check.signingKey.Public().(ed25519.PublicKey),
			fixture.check.otherId:  fixture.check.otherKey.Public().(ed25519.PublicKey),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{fixture.check.repoId: {fixture.check.signerId, fixture.check.otherId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{fixture.check.repoId: {fixture.check.signerId}},
	})
	fixture.host.Quota.SetLimits(connect.Id(fixture.check.networkId), &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"evs_read_receipts_per_repo_day": 1}})
	reader := fixture.check.otherId
	fixture.auth.grant(reader, fixture.check.repoId, sidecar.AclEvsDeposit)
	refId := sidecar.EvsDepositRefId(fixture.check.repoId, reader)
	receipt := func(label string, paddedSize uint64) *protocol.EvsPushRequest {
		plan := fixture.plan()
		plan.RefId = refId
		plan.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
		plan.OwnerSidecarId = &reader
		plan.SignerSidecarId = reader
		plan.BaseVersion = 0
		plan.BaseChain = sidecar.EvsChainStart(fixture.check.repoId, refId)
		if head := fixture.headOf(refId); !head.Absent() && 0 < head.Version() {
			plan.BaseVersion = head.Version()
			plan.BaseChain = [32]byte(head.Head.GetChain())
		}
		entry := &protocol.EvsEntryVersion{
			Version: plan.BaseVersion + 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: paddedSize, SealedFields: []byte("sealed fields"),
			Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("receipt")}},
		}
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath(label), EntryVersion: entryBytes})
		built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.otherKey, reader)).Build(plan)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
	}
	token := fixture.token(reader, "deposit")
	requireRefusal(t, fixture.post(token, receipt("large", 8192)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	fixture.requireCommitted(fixture.post(token, receipt("first", 4096)), 1)
	limited := fixture.post(token, receipt("second", 4096))
	requireRefusal(t, limited, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	if refusalOf(t, limited).GetRetryAfterMs() == 0 {
		t.Fatal("the receipt budget's 429 carries no wait")
	}
}
