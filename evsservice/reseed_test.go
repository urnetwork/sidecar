// EVSB-M2-20's tests of POST .../reseed on T2 (reseed.go; QD-725): each rule the reseed mode skips, shown beside the
// push route refusing the same statement, and each rule it keeps; the slot call's order and stripping; the repos a
// re-seed is taken for; and the Signed EvsReseed kept at reseed/ and served with the head.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A push fixture in a recovery: sidecar.yml's reseed on, the repo listed live by the projection, and the fixture's
// other sidecar a repo admin by its token, which re-seeds what the writer signed.
type reseedFixture struct {
	*pushFixture
	adminId sidecar.Id
}

func newReseedFixture(t *testing.T) *reseedFixture {
	return reseedFixtureOf(newPushFixture(t, nil))
}

// push's world put in a recovery.
func reseedFixtureOf(push *pushFixture) *reseedFixture {
	fixture := &reseedFixture{pushFixture: push, adminId: push.check.otherId}
	push.auth.grant(fixture.adminId, push.check.repoId, sidecar.AclEvsAdmin)
	fixture.project(nil)
	fixture.gate(true)
	return fixture
}

// sidecar.yml with evs open to the fixture's network and reseed as given.
func (self *reseedFixture) gate(reseed bool) {
	text := "sidecar:\n  evs:\n    enabled: true\n    networks: [\"" + self.check.networkId.String() + "\"]\n"
	if reseed {
		text += "  reseed: true\n"
	}
	if err := self.host.Gates.Set(text); err != nil {
		self.t.Fatal(err)
	}
}

// The projection's facts of the repo, with its newest RepoDelete.
func (self *reseedFixture) project(deletion *EvsRepoDeletionFacts) {
	self.auth.setRepo(self.check.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: self.check.networkId, Deletion: deletion})
}

// The state's next position: the fixture's two sidecars under the identity keys given, writers as listed, and
// admins as the repo's standing admin rows.
func (self *reseedFixture) appendState(signerKey ed25519.PrivateKey, writers []sidecar.Id, admins ...sidecar.Id) *sidecartest.FakeGkmAuthView {
	check := self.check
	repo := &protocol.AclRepo{RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	for _, adminId := range admins {
		repo.Admins = append(repo.Admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes(), At: 1})
	}
	rows := sidecartest.FakeGkmAuthRows(repo)
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(testId("check member"), check.signerId, check.otherId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	check.auth = check.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			check.signerId: signerKey.Public().(ed25519.PublicKey),
			check.otherId:  check.otherKey.Public().(ed25519.PublicKey),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{check.repoId: {check.signerId, check.otherId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{check.repoId: writers},
	})
	return check.auth
}

// A plan as a mirror kept it: the fixture's next push, signed a month ago.
func (self *reseedFixture) kept() *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.TimeMs = self.clock.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	return plan
}

// plan's reseed call, built and signed by key as signerId.
func (self *reseedFixture) signedBody(plan *sidecar.EvsPushPlan, key ed25519.PrivateKey, signerId sidecar.Id) *protocol.EvsReseedRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(key, signerId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
}

// plan's reseed call, signed by the fixture's writer.
func (self *reseedFixture) reseedBody(plan *sidecar.EvsPushPlan) *protocol.EvsReseedRequest {
	self.t.Helper()
	return self.signedBody(plan, self.check.signingKey, self.check.signerId)
}

// One POST .../reseed of body under the admin's token.
func (self *reseedFixture) reseed(body *protocol.EvsReseedRequest) *httptest.ResponseRecorder {
	self.t.Helper()
	return self.call(self.token(self.adminId, "admin"), http.MethodPost, "/reseed", body)
}

// A reseed call's body at the push route, under its signer's token: what the push route answers the same statement.
func (self *reseedFixture) pushed(body *protocol.EvsReseedRequest) *httptest.ResponseRecorder {
	self.t.Helper()
	return self.post(self.token(self.check.signerId), &protocol.EvsPushRequest{Statement: body.GetStatement(), Payload: body.GetPayload()})
}

// The record of the ref's version, from the head's window.
func (self *reseedFixture) recordAt(refId sidecar.Id, version uint64) *sidecar.EvsBatchRecord {
	self.t.Helper()
	head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.check.repoId, refId)
	if err != nil {
		self.t.Fatal(err)
	}
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		self.t.Fatal(err)
	}
	index := int(version - EvsHeadWindowFirstVersion(head.Head))
	if index < 0 || len(window) <= index {
		self.t.Fatalf("version %d is not in the window", version)
	}
	record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.check.repoId, refId, window[index].Place)
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// repo/ as the cluster holds it.
func (self *reseedFixture) repoObject() *protocol.EvsRepoObject {
	self.t.Helper()
	self.engine.repos.Forget(self.check.repoId)
	read, err := self.engine.repos.Read(self.ctx, self.cluster, self.check.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read.Object
}

// The slot call for slotId and its bytes, under the statement of the version that names it.
func (self *reseedFixture) reseedSlot(named *protocol.EvsReseedRequest, slotId sidecar.Id, slot []byte) *httptest.ResponseRecorder {
	self.t.Helper()
	return self.reseed(&protocol.EvsReseedRequest{Statement: named.GetStatement(), SlotId: slotId.Bytes(), Slot: slot})
}

// A file at labels on the shared ref naming a new slot, as the mirror kept its push.
func (self *reseedFixture) keptWithSlot(slotId sidecar.Id, object *sidecar.EvsNewObject, slot []byte, labels ...string) *protocol.EvsReseedRequest {
	self.t.Helper()
	plan := self.kept()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath(labels...), EntryVersion: self.check.fileEntry(plan, plan.BaseVersion+1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, object)
	plan.SlotBodies = append(plan.SlotBodies, slot)
	return self.reseedBody(plan)
}

// A statement a month old, by another sidecar than the token's, commits at the reseed route as an EVS_BATCH_RESEED
// record of its statement and payload as sent, where the push route refuses it TIME_STALE; a retry answers the
// version it committed at.
func TestReseedCommitsAKeptPushAsAReseedRecord(t *testing.T) {
	fixture := newReseedFixture(t)
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	fixture.requireCommitted(fixture.reseed(body), 1)
	record := fixture.recordAt(fixture.check.refId, 1)
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || record.PushId != plan.PushId || record.SignerSidecarId != fixture.check.signerId {
		t.Fatalf("version 1's record is type %s of push %s by %s", record.Type, record.PushId, record.SignerSidecarId)
	}
	statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
	if err != nil || !bytes.Equal(statementBytes, body.GetStatement()) || !bytes.Equal(payloadBytes, body.GetPayload()) {
		t.Fatalf("the record holds other bytes than the mirror sent: %v", err)
	}
	// 5a: the retry answers the commit
	fixture.requireCommitted(fixture.reseed(body), 1)
	if fixture.head().Version() != 1 {
		t.Fatalf("head at %d after a retry", fixture.head().Version())
	}

	// the next kept push at the push route: past its time window
	next := fixture.kept()
	fixture.create(next, "b")
	nextBody := fixture.reseedBody(next)
	requireRefusal(t, fixture.pushed(nextBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE)
	// and the reseed route takes that statement: its time window is not asked
	fixture.requireCommitted(fixture.reseed(nextBody), 2)
	// a read serves the re-seeded version as any other
	reply := fixture.readPath(fixture.token(fixture.check.signerId), 0, true, checkTestPath("a"))
	if reply.head.GetVersion() != 2 || len(reply.statements) != 2 || !bytes.Equal(reply.statements[0].GetStatement(), body.GetStatement()) {
		t.Fatalf("a read of the re-seeded ref: head %d, %d statements", reply.head.GetVersion(), len(reply.statements))
	}
}

// Outside a recovery the route takes nothing, and a token below admin is refused.
func TestReseedIsClosedOutsideARecovery(t *testing.T) {
	fixture := newReseedFixture(t)
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	fixture.gate(false)
	if recorder := fixture.reseed(body); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d with reseed off, want 503", recorder.Code)
	}
	if !fixture.head().Absent() {
		t.Fatal("a re-seed was taken with reseed off")
	}
	fixture.gate(true)
	if recorder := fixture.call(fixture.token(fixture.check.signerId), http.MethodPost, "/reseed", body); recorder.Code != http.StatusForbidden {
		t.Fatalf("status %d for a token below admin, want 403", recorder.Code)
	}
	if !fixture.head().Absent() {
		t.Fatal("a re-seed was taken from a token below admin")
	}
	fixture.requireCommitted(fixture.reseed(body), 1)
}

// The chain onto the current head: base_version and base_chain equal to it. A file-mode push on a base below the
// head, which the push route's 5f takes inside its window, is refused, as is one whose base chain is not the head's;
// neither records a refusal, so the same statement goes once the head is its base.
func TestReseedKeepsTheChainOntoTheHead(t *testing.T) {
	fixture := newReseedFixture(t)
	first := fixture.kept()
	fixture.create(first, "a")
	// built on the absent head too, on another path: a concurrent file-mode writer's push
	sibling := fixture.kept()
	fixture.create(sibling, "b")
	siblingBody := fixture.reseedBody(sibling)
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	requireRefusal(t, fixture.reseed(siblingBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	forked := fixture.kept()
	forked.BaseChain = [32]byte(bytes.Repeat([]byte{9}, 32))
	fixture.create(forked, "c")
	requireRefusal(t, fixture.reseed(fixture.reseedBody(forked)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	ahead := fixture.kept()
	ahead.BaseVersion = 2
	fixture.create(ahead, "d")
	requireRefusal(t, fixture.reseed(fixture.reseedBody(ahead)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	head := fixture.head()
	if head.Version() != 1 || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
	second := fixture.kept()
	fixture.create(second, "e")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(second)), 2)
	// the push route, in file mode, takes a base inside its window: 5f alone does not refuse the sibling
	if refusal := CheckBase(fixture.check.view(sibling)); refusal != nil {
		t.Fatalf("5f refuses the sibling on an absent head: %s", refusal.Detail)
	}
}

// The signature at the statement's own auth pin: a statement verifies under the key its signer held at the state it
// pins, whatever the newest state holds, and under no other; a pin off evs's chain is refused, and one above evs's
// state or below its retention answers 503.
func TestReseedKeepsTheSignatureAtTheStatementsOwnAuthPin(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	oldKey := check.signingKey
	newKey := checkTestKey("signer rotated")
	// the newest state holds another identity key for the signer
	second := fixture.appendState(newKey, []sidecar.Id{check.signerId, check.otherId})

	// pinned at the first state, signed by the key of the first state
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.signedBody(first, oldKey, check.signerId)), 1)

	// pinned at the second state, signed by the first state's key
	stale := fixture.kept()
	stale.Auth = second.Pin()
	fixture.create(stale, "b")
	requireRefusal(t, fixture.reseed(fixture.signedBody(stale, oldKey, check.signerId)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	// pinned at the first state, signed by the second state's key
	early := fixture.kept()
	fixture.create(early, "c")
	requireRefusal(t, fixture.reseed(fixture.signedBody(early, newKey, check.signerId)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	// signed by another sidecar's key
	forged := fixture.kept()
	fixture.create(forged, "d")
	requireRefusal(t, fixture.reseed(fixture.signedBody(forged, check.otherKey, check.signerId)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)

	// a pin on no chain of evs's
	offChain := fixture.kept()
	offChain.Auth = sidecartest.FakeGkmForkPin(1)
	fixture.create(offChain, "e")
	requireRefusal(t, fixture.reseed(fixture.signedBody(offChain, oldKey, check.signerId)), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
	// a pin above evs's state
	above := fixture.kept()
	above.Auth = &bridge.AuthPin{Version: 9, Chain: bytes.Repeat([]byte{1}, 32)}
	fixture.create(above, "f")
	if recorder := fixture.reseed(fixture.signedBody(above, oldKey, check.signerId)); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d for a pin above evs's state, want 503", recorder.Code)
	}

	// pinned at the second state under its key: the pins rise with the history
	rotated := fixture.kept()
	rotated.Auth = second.Pin()
	fixture.create(rotated, "g")
	fixture.requireCommitted(fixture.reseed(fixture.signedBody(rotated, newKey, check.signerId)), 2)
	// and never fall below the head's
	below := fixture.kept()
	fixture.create(below, "h")
	requireRefusal(t, fixture.reseed(fixture.signedBody(below, oldKey, check.signerId)), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)

	// a pin evs's state no longer retains: nothing verifies it, and nothing is refused for good
	check.authLog.Retain(2)
	unretained := fixture.kept()
	fixture.create(unretained, "i")
	if recorder := fixture.reseed(fixture.signedBody(unretained, oldKey, check.signerId)); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d for a pin evs does not retain, want 503", recorder.Code)
	}
	if fixture.head().Version() != 2 || len(fixture.head().Head.GetRefused()) != 0 {
		t.Fatal("a refused re-seed changed the head")
	}
}

// §11.8's refs table, read for the statement's signer at the state its statement pins: a writer of that state
// re-seeds a shared ref whatever the newest state lists, one it does not list is refused, as is the erasure ref from
// a signer who was no admin, and a ref rule the table holds whoever signs.
func TestReseedKeepsTheRefsTable(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	// the second state lists the writer no more, and its admin as writer and admin
	second := fixture.appendState(check.signingKey, []sidecar.Id{check.otherId}, check.otherId)

	// by the writer at the first state, which lists it
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	// by the writer at the second state, which does not
	unlisted := fixture.kept()
	unlisted.Auth = second.Pin()
	fixture.create(unlisted, "b")
	requireRefusal(t, fixture.reseed(fixture.reseedBody(unlisted)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)

	// the erasure ref takes its pushes from an admin of the pinned state alone
	slotId := testId("refs table slot")
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	erase.TimeMs = fixture.clock.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	requireRefusal(t, fixture.reseed(fixture.reseedBody(erase)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	adminErase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	adminErase.TimeMs = erase.TimeMs
	adminErase.Auth = second.Pin()
	adminErase.SignerSidecarId = check.otherId
	fixture.requireCommitted(fixture.reseed(fixture.signedBody(adminErase, check.otherKey, check.otherId)), 1)

	// a ref rule: an owned ref written by another sidecar than its owner
	owned := fixture.kept()
	owned.RefId = testId("reseed owned ref")
	owned.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
	owned.OwnerSidecarId = &check.otherId
	owned.BaseVersion = 0
	owned.BaseChain = sidecar.EvsChainStart(check.repoId, owned.RefId)
	fixture.create(owned, "c")
	requireRefusal(t, fixture.reseed(fixture.reseedBody(owned)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
	if fixture.head().Version() != 1 || len(fixture.head().Head.GetRefused()) != 0 {
		t.Fatal("a refused re-seed changed the head")
	}
}

// A segment counts once PUT seg/ holds it at its padded size, with no receipt and whatever its age: 409 SEGMENT_GONE
// until then, nothing recorded. The quota gate is skipped: the network at its storage limit, where the push route
// answers 402, re-seeds.
func TestReseedTakesSegmentsOnceSegHoldsThemAndSkipsReceiptsAndQuota(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	check.quota.atLimit(connect.Id(check.networkId))
	segmentId, segmentObject, _ := check.upload("reseed", fixture.clock.Now().Add(-40*24*time.Hour), check.signerId)
	plan := fixture.kept()
	plan.NewObjects = append(plan.NewObjects, segmentObject)
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: check.fileEntry(plan, 1, []*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}),
	})
	body := fixture.reseedBody(plan)
	requireRefusal(t, fixture.reseed(body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE)
	if !fixture.head().Absent() {
		t.Fatal("a re-seed whose segment seg/ does not hold wrote the head")
	}

	segmentCluster, err := fixture.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	// seg/ holding an object of another size than the push lists
	if _, err := segmentCluster.PutIfNoneMatch(fixture.ctx, SegmentKey(check.repoId, segmentId), make([]byte, 1024), nil); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, fixture.reseed(body), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if err := segmentCluster.Delete(fixture.ctx, SegmentKey(check.repoId, segmentId)); err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCluster.PutIfNoneMatch(fixture.ctx, SegmentKey(check.repoId, segmentId), make([]byte, 4096), nil); err != nil {
		t.Fatal(err)
	}
	fixture.requireCommitted(fixture.reseed(body), 1)

	// a later version naming that segment cites the version read, as 5h has it, and one naming a segment nothing holds
	// is refused
	cites := fixture.kept()
	cites.Changes = append(cites.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), BaseEntryVersion: 1, EntryVersion: check.fileEntry(cites, 2, []*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}),
	})
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(cites)), 2)
	unknown := fixture.kept()
	unknownId := [32]byte(bytes.Repeat([]byte{5}, 32))
	unknown.Changes = append(unknown.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("b"), EntryVersion: check.fileEntry(unknown, 3, []*protocol.EvsLocator{checkTestSegmentLocator(unknownId)}),
	})
	requireRefusal(t, fixture.reseed(fixture.reseedBody(unknown)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE)

	// the same history at the push route: the network is at its storage limit
	limited := fixture.plan()
	fixture.create(limited, "c")
	requireRefusal(t, fixture.push(limited), http.StatusPaymentRequired, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	kept := fixture.kept()
	fixture.create(kept, "d")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(kept)), 3)
}

// Slots come last: step 6 of a re-seeded push writes none, and a slot call is taken only under the statement of a
// re-seeded version that names the slot. The slot is stored without the keys the ERASEs evs holds cover, with origin
// 1.r; one left with no key is not stored; a second call finds the slot and leaves it, and other bytes at its id
// answer 409 SLOT_STALE. An ERASE re-seeds before the slots it names exist, where the push route refuses it.
func TestReseedSlotWaitsForAReseededVersionAndIsStripped(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	// the admin of the state an ERASE pins
	second := fixture.appendState(check.signingKey, []sidecar.Id{check.signerId, check.otherId}, check.otherId)
	slotId, slotObject, slot := eraseTestSlot(t, "reseeded", 2)
	goneId, goneObject, gone := eraseTestSlot(t, "all erased", 1)

	// a version the push route committed names a slot of its own: no re-seeded version
	routeSlotId, routeSlotObject, routeSlot := eraseTestSlot(t, "push route", 1)
	routePlan := fixture.plan()
	routePlan.Changes = append(routePlan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("route"), EntryVersion: check.fileEntry(routePlan, 1, nil, routeSlotId),
	})
	routePlan.NewObjects = append(routePlan.NewObjects, routeSlotObject)
	routePlan.SlotBodies = append(routePlan.SlotBodies, routeSlot)
	routeBody := fixture.body(routePlan)
	fixture.requireCommitted(fixture.post(fixture.token(check.signerId), routeBody), 1)

	// the ERASE first, as §19.10 orders it, before any slot it names is there
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0}, &sidecar.EvsErasedKey{SlotId: goneId, KeyIndex: 0})
	erase.TimeMs = fixture.clock.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	erase.Auth = second.Pin()
	erase.SignerSidecarId = check.otherId
	fixture.requireCommitted(fixture.reseed(fixture.signedBody(erase, check.otherKey, check.otherId)), 1)
	if record := fixture.recordAt(sidecar.EvsErasureRefId(check.repoId), 1); record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		t.Fatalf("the ERASE's record is type %s", record.Type)
	}

	named := fixture.keptWithSlot(slotId, slotObject, slot, "a")
	// before its version is re-seeded, the slot is not taken
	requireRefusal(t, fixture.reseedSlot(named, slotId, slot), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	fixture.requireCommitted(fixture.reseed(named), 2)
	if indexes := fixture.slotIndexes(slotId); indexes != nil {
		t.Fatalf("step 6 of a re-seeded push wrote its slot: keys %v", indexes)
	}
	namedGone := fixture.keptWithSlot(goneId, goneObject, gone, "b")
	fixture.requireCommitted(fixture.reseed(namedGone), 3)

	// under a statement that does not name it, under the push route's version, and with no statement
	requireRefusal(t, fixture.reseedSlot(namedGone, slotId, slot), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	requireRefusal(t, fixture.reseedSlot(&protocol.EvsReseedRequest{Statement: routeBody.GetStatement()}, routeSlotId, routeSlot),
		http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	requireRefusal(t, fixture.reseedSlot(&protocol.EvsReseedRequest{}, slotId, slot), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	if indexes := fixture.slotIndexes(slotId); indexes != nil {
		t.Fatalf("a refused slot call wrote the slot: keys %v", indexes)
	}

	// taken, without the key the ERASE covers
	if recorder := fixture.reseedSlot(named, slotId, slot); recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for a named slot", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v, want key 1 alone", indexes)
	}
	info, err := fixture.cluster.Head(fixture.ctx, SlotKey(check.repoId, slotId))
	if err != nil {
		t.Fatal(err)
	}
	if origin := ParseEvsSlotOrigin(info.Metadata, fixture.settings.SlotOriginMaxByteCount); origin.Kind != EvsSlotOriginReseed {
		t.Fatalf("the slot's origin is %q", origin.Encode())
	}
	// again: the cluster holds it, equal after stripping, and it is left
	if recorder := fixture.reseedSlot(named, slotId, slot); recorder.Code != http.StatusOK {
		t.Fatalf("status %d for a slot the cluster already holds", recorder.Code)
	}
	after, err := fixture.cluster.Head(fixture.ctx, SlotKey(check.repoId, slotId))
	if err != nil || after.Etag != info.Etag {
		t.Fatalf("a second call rewrote the slot: %v", err)
	}
	// other bytes at the id
	_, _, other := eraseTestSlot(t, "other bytes", 3)
	requireRefusal(t, fixture.reseedSlot(named, slotId, other), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v after a refused call", indexes)
	}

	// a slot whose every key an ERASE covers is not stored
	if recorder := fixture.reseedSlot(namedGone, goneId, gone); recorder.Code != http.StatusOK {
		t.Fatalf("status %d for a slot with no key left", recorder.Code)
	}
	if indexes := fixture.slotIndexes(goneId); indexes != nil {
		t.Fatalf("a slot with no key left was stored: keys %v", indexes)
	}

	// the push route refuses an ERASE naming no key a slot holds
	fixture.auth.grant(check.signerId, check.repoId, sidecar.AclEvsAdmin)
	nothing := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: goneId, KeyIndex: 0})
	nothing.Auth = second.Pin()
	requireRefusal(t, fixture.slotsDelete(nothing, "admin"), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE)
}

// §11.13's repos rule: a repo whose newest RepoDelete carries now, is past the restore window or is not dated is
// refused 409 SHREDDING; one inside the window has repo/ moved to deleted under its RepoDelete, at its entry's time,
// before anything is taken, and takes its history while deleted; a restored one is live. A repo the projection does
// not list, and one repo/ holds shredding, take nothing.
func TestReseedOfADeletedRepoPlacesTheMarkerFirst(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	deletionId := testId("reseed deletion")
	now := fixture.clock.Now()
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)

	for _, deletion := range []*EvsRepoDeletionFacts{
		{DeletionId: deletionId, Now: true, Time: now.Add(-time.Hour), SignerSidecarId: check.otherId},
		{DeletionId: deletionId, Time: now.Add(-fixture.settings.ReseedRestoreWindow), SignerSidecarId: check.otherId},
		{DeletionId: deletionId, SignerSidecarId: check.otherId},
	} {
		fixture.project(deletion)
		requireRefusal(t, fixture.reseed(body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
		if !fixture.head().Absent() || fixture.repoObject().GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Fatal("a repo past restoring took a re-seed or changed state")
		}
	}

	// not listed at all
	fixture.auth.stateLock.Lock()
	delete(fixture.auth.repoFacts, check.repoId)
	fixture.auth.stateLock.Unlock()
	requireRefusal(t, fixture.reseed(body), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)

	// restorable: the marker first, then the history
	entryTime := now.Add(-3 * 24 * time.Hour)
	fixture.project(&EvsRepoDeletionFacts{DeletionId: deletionId, Time: entryTime, SignerSidecarId: check.otherId})
	fixture.requireCommitted(fixture.reseed(body), 1)
	repo := fixture.repoObject()
	if repo.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !evsRepoNamesDeletion(repo, deletionId) || repo.GetStateMs() != entryTime.UnixMilli() {
		t.Fatalf("repo/ is %s at %d after a restorable repo's re-seed", repo.GetState(), repo.GetStateMs())
	}
	next := fixture.kept()
	fixture.create(next, "b")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(next)), 2)
	// and access stays refused while it is deleted
	later := fixture.plan()
	fixture.create(later, "c")
	requireRefusal(t, fixture.push(later), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)

	// repo/ deleted under another RepoDelete than the projection's newest
	fixture.project(&EvsRepoDeletionFacts{DeletionId: testId("another deletion"), Time: entryTime, SignerSidecarId: check.otherId})
	third := fixture.kept()
	fixture.create(third, "d")
	thirdBody := fixture.reseedBody(third)
	requireRefusal(t, fixture.reseed(thirdBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)

	// shredding: nothing comes back
	fixture.project(&EvsRepoDeletionFacts{DeletionId: deletionId, Time: entryTime, SignerSidecarId: check.otherId})
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_SHREDDING)
	requireRefusal(t, fixture.reseed(thirdBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
	if fixture.head().Version() != 2 {
		t.Fatalf("head at %d", fixture.head().Version())
	}
}

// A restored repo is live again: its re-seed leaves repo/ active.
func TestReseedOfARestoredRepoLeavesItActive(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	fixture.project(&EvsRepoDeletionFacts{
		DeletionId: testId("restored deletion"), Time: fixture.clock.Now().Add(-30 * 24 * time.Hour), SignerSidecarId: check.otherId, Restored: true,
	})
	plan := fixture.kept()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(plan)), 1)
	if state := fixture.repoObject().GetState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("repo/ is %s after a restored repo's re-seed", state)
	}
}

// What the route does not build is refused before anything is written: a push in parts answers 503, refusing nothing,
// and a call mixing a slot with a push is invalid.
func TestReseedRefusesWhatItDoesNotBuild(t *testing.T) {
	fixture := newReseedFixture(t)
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	parts := &protocol.EvsReseedRequest{Statement: body.GetStatement(), Parts: [][]byte{[]byte("part")}}
	if recorder := fixture.reseed(parts); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d for a push in parts, want 503", recorder.Code)
	}
	mixed := &protocol.EvsReseedRequest{Statement: body.GetStatement(), Payload: body.GetPayload(), SlotId: testId("mixed slot").Bytes(), Slot: []byte("slot")}
	requireRefusal(t, fixture.reseed(mixed), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	requireRefusal(t, fixture.reseed(&protocol.EvsReseedRequest{Statement: []byte("no statement")}), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if !fixture.head().Absent() {
		t.Fatal("a refused call wrote the head")
	}
	fixture.requireCommitted(fixture.reseed(body), 1)
}

// A Signed EvsReseed is kept at reseed/<repo>/<ref> once it names the ref's current head and a standing repo admin
// of evs's newest state signed it, and a read whose pin is above the head carries it after the head, which
// EvsVerifier.AcceptReseed takes; a read at or below the head carries none.
func TestReseedStatementIsKeptAndServedWithTheHead(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	plan := fixture.kept()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(plan)), 1)
	head := fixture.head()
	chain := [32]byte(head.Head.GetChain())
	sign := func(key ed25519.PrivateKey, signerId sidecar.Id, version uint64, chain [32]byte) *protocol.EvsReseedRequest {
		signedBytes, err := sidecar.SignEvsReseed(checkTestSign(key, signerId), check.repoId, check.refId, version, chain, []byte("incident 1"))
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsReseedRequest{Statement: signedBytes}
	}
	statement := sign(check.otherKey, check.otherId, 1, chain)

	// no admin row stands for the signer in the newest state
	requireRefusal(t, fixture.reseed(statement), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	fixture.appendState(check.signingKey, []sidecar.Id{check.signerId, check.otherId}, check.otherId)
	// by a writer who is no admin, under a key that is not the admin's, and naming another head
	requireRefusal(t, fixture.reseed(sign(check.signingKey, check.signerId, 1, chain)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	requireRefusal(t, fixture.reseed(sign(check.signingKey, check.otherId, 1, chain)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	requireRefusal(t, fixture.reseed(sign(check.otherKey, check.otherId, 2, chain)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	requireRefusal(t, fixture.reseed(sign(check.otherKey, check.otherId, 1, [32]byte(bytes.Repeat([]byte{4}, 32)))), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	if _, err := fixture.cluster.Head(fixture.ctx, ReseedKey(check.repoId, check.refId)); err == nil {
		t.Fatal("a refused statement was stored")
	}
	// a read above the head with none stored carries none
	token := fixture.token(check.signerId)
	request := &protocol.EvsReadRequest{RefId: check.refId.Bytes(), PinVersion: 5, Fresh: true}
	if reply := fixture.read(token, request); len(reply.objects) != 0 || reply.head.GetVersion() != 1 {
		t.Fatalf("a read with no statement stored: %d objects", len(reply.objects))
	}

	reply := &protocol.EvsPushReply{}
	recorder := fixture.reseed(statement)
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil || reply.GetVersion() != 1 {
		t.Fatalf("status %d, version %d for the admin's statement", recorder.Code, reply.GetVersion())
	}
	stored := func() []byte {
		object, err := fixture.cluster.Get(fixture.ctx, ReseedKey(check.repoId, check.refId))
		if err != nil {
			t.Fatal(err)
		}
		defer object.Body.Close()
		storedBytes, err := readAllLimited(object, int64(fixture.settings.ReseedStatementMaxByteCount))
		if err != nil {
			t.Fatal(err)
		}
		return storedBytes
	}
	if !bytes.Equal(stored(), statement.GetStatement()) {
		t.Fatal("reseed/ holds other bytes than the admin signed")
	}
	// again: the same bytes, nothing rewritten
	if recorder := fixture.reseed(statement); recorder.Code != http.StatusOK {
		t.Fatalf("status %d for the statement again", recorder.Code)
	}

	// a read whose pin is above the head carries it after the head
	above := fixture.read(token, request)
	if len(above.objects) != 1 || above.objects[0].GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_RESEED ||
		!bytes.Equal(above.objects[0].GetId(), check.refId.Bytes()) || !bytes.Equal(above.objects[0].GetBody(), statement.GetStatement()) {
		t.Fatalf("a read above the head: %d objects", len(above.objects))
	}
	parsed, err := sidecar.ParseEvsReseedStatement(above.objects[0].GetBody(), fixture.settings.ReseedStatementMaxByteCount)
	if err != nil || parsed.Version != above.head.GetVersion() || !bytes.Equal(parsed.Chain[:], above.head.GetChain()) ||
		parsed.Verify(check.otherKey.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("the served statement does not name the served head: %v", err)
	}
	// at or below the head: none
	for _, pin := range []uint64{0, 1} {
		if at := fixture.read(token, &protocol.EvsReadRequest{RefId: check.refId.Bytes(), PinVersion: pin, Fresh: true}); len(at.objects) != 0 {
			t.Fatalf("a read at pin %d carries %d objects", pin, len(at.objects))
		}
	}

	// the history grows by a version, and the statement naming the new head replaces the first
	next := fixture.kept()
	fixture.create(next, "b")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(next)), 2)
	requireRefusal(t, fixture.reseed(statement), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	second := sign(check.otherKey, check.otherId, 2, [32]byte(fixture.head().Head.GetChain()))
	if recorder := fixture.reseed(second); recorder.Code != http.StatusOK {
		t.Fatalf("status %d for the statement of the new head", recorder.Code)
	}
	if !bytes.Equal(stored(), second.GetStatement()) {
		t.Fatal("reseed/ still holds the first statement")
	}
}

// Evacuation and the nightly pass over re-seeded records (§11.13's when and bytes rows): a reseed record is committed
// where its ref's history names its push, so past 25 h it leaves its batch for a parcel as a push record does, byte
// for byte; the re-seed's retry, a slot call under its version and a read then find it in the parcel, and the nightly
// pass counts it there and deletes nothing.
func TestReseededRecordsEvacuateAndCountAsAnyOther(t *testing.T) {
	nightly := newNightlyFixture(t)
	fixture := reseedFixtureOf(nightly.pushFixture)
	check := fixture.check
	slotId, slotObject, slot := eraseTestSlot(t, "evacuated", 1)
	named := fixture.keptWithSlot(slotId, slotObject, slot, "a")
	fixture.requireCommitted(fixture.reseed(named), 1)
	next := fixture.kept()
	fixture.create(next, "b")
	nextBody := fixture.reseedBody(next)
	fixture.requireCommitted(fixture.reseed(nextBody), 2)
	fixture.awaitStepEights()
	before := fixture.recordAt(check.refId, 1)

	nightly.age()
	result := nightly.mustRun()
	if result.KeptCount != 2 || result.DeadCount != 0 || result.ParcelCount != 1 || result.MinuteWaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if keys := nightly.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	parcels := nightly.keys("meta-1", parcelKeyPrefix)
	if len(parcels) != 1 {
		t.Fatalf("parcels %v", parcels)
	}
	after := fixture.recordAt(check.refId, 1)
	if after.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || !bytes.Equal(after.Body, before.Body) || after.PushId != before.PushId {
		t.Fatalf("version 1's record from its parcel is type %s", after.Type)
	}

	// 5a finds the re-seeded push committed, from its parcel
	fixture.requireCommitted(fixture.reseed(named), 1)
	fixture.requireCommitted(fixture.reseed(nextBody), 2)
	if fixture.head().Version() != 2 {
		t.Fatalf("head at %d after the retries", fixture.head().Version())
	}
	// a slot comes last, after its version's record has left its batch
	if recorder := fixture.reseedSlot(named, slotId, slot); recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for a slot named by an evacuated version", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 {
		t.Fatalf("slot keys %v", indexes)
	}
	// and under the version that does not name it, still not
	requireRefusal(t, fixture.reseedSlot(nextBody, sidecar.NewId(), slot), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	reply := fixture.readPath(fixture.token(check.signerId), 0, true, checkTestPath("a"))
	if reply.head.GetVersion() != 2 || len(reply.statements) != 2 || !bytes.Equal(reply.statements[0].GetStatement(), named.GetStatement()) {
		t.Fatalf("a read of the evacuated ref: head %d, %d statements", reply.head.GetVersion(), len(reply.statements))
	}

	// the nightly pass counts the records in their parcel and deletes nothing of the repo
	parcel, err := fixture.cluster.Head(fixture.ctx, parcels[0])
	if err != nil {
		t.Fatal(err)
	}
	pass := nightly.runPass()
	if !pass.Complete || pass.More || pass.RepoCount != 1 || pass.UnknownNetworkRepoCount != 0 {
		t.Fatalf("the nightly pass %+v", pass)
	}
	stored := pass.NetworkBytes[check.networkId]
	if stored == nil || stored.ParcelByteCount != parcel.ByteCount || stored.BatchRecordByteCount != 0 {
		t.Fatalf("stored after evacuation %+v", stored)
	}
	if keys := nightly.keys("meta-1", parcelKeyPrefix); len(keys) != 1 || keys[0] != parcels[0] {
		t.Fatalf("parcels after the nightly pass: %v", keys)
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 {
		t.Fatalf("slot keys %v after the nightly pass", indexes)
	}
}

// The reseed/ family leaves with its repo: §11.12's phase 5 lists it.
func TestReseedKeyIsUnderItsReposFamily(t *testing.T) {
	repoId, refId := testId("family repo"), testId("family ref")
	want := reseedKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId)
	if key := ReseedKey(repoId, refId); key != want {
		t.Fatalf("reseed key %q, want %q", key, want)
	}
}

// The settings a re-seed reads are held positive.
func TestReseedSettingsAreValidated(t *testing.T) {
	for _, adjust := range []func(settings *EvsSettings){
		func(settings *EvsSettings) { settings.ReseedBodyMaxByteCount = 0 },
		func(settings *EvsSettings) { settings.ReseedStatementMaxByteCount = 0 },
		func(settings *EvsSettings) { settings.ReseedRestoreWindow = 0 },
		func(settings *EvsSettings) { settings.ReseedStatementRetryCount = 0 },
	} {
		settings := DefaultEvsSettings()
		adjust(settings)
		if err := settings.Validate(); err == nil {
			t.Fatal("a non-positive re-seed setting passed")
		}
	}
	if err := DefaultEvsSettings().Validate(); err != nil {
		t.Fatal(err)
	}
}
