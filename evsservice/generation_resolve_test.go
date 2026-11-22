// A statement's gen/<g> resolved through the repo's GroupForms (generation_resolve.go; plan-KEYS-reform-ladder rule 8)
// at the push route, on gkm's objects as a re-form leaves them:
//
//   - resumed: a re-form cut short at its ladder, reseeded and resumed, which leaves the new group's form, its ladder
//     the old group's statements byte for byte, and its first generation claimed in it: every member's next write,
//     crossing a ladder generation from a head of the old group's, commits, and a REMOVE generation the ladder carried
//     records its due, where before every such push was refused 503 UNAVAILABLE (TestE2eGkmConcurrencyReform's
//     resumed repo)
//   - in progress: while the ladder goes up, writes at the old group's generations commit, and one at the new group's
//     first generation answers 503, refusing and recording nothing, until it is claimed; a form landing after a
//     refused push is met once GroupFormCacheTtl has passed
//   - site loss: a write naming the old group, whose objects are gone, resolves through the newest form's ladder, 503
//     until the ladder reaches its generation
//   - refused: a crossing of a statement naming another group in a group no form makes, of one past the form's
//     generation, of one under a form whose signer evs's state does not admit, and of one of another repo each answer
//     503, committing nothing; and a push naming the new group at a generation its ladder carried is a pin of another
//     group, final (412 GATE_CLOSED), as a writer, whose key names the old group there, never sends

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The push fixture with the fixture's group as the repo's first, its form filed, and a re-form's group beside it.
type reformFixture struct {
	*pushFixture
	oldGroupId sidecar.Id
	newGroupId sidecar.Id
	// each generation's commitment by number, gen/1's the fixture's
	commitments map[uint64][]byte
	// the forms filed, by seq
	formCount uint64
}

func newReformFixture(t *testing.T, adjust func(settings *EvsSettings)) *reformFixture {
	fixture := &reformFixture{
		pushFixture: newPushFixture(t, adjust),
		newGroupId:  testId("re-formed group"),
		commitments: map[uint64][]byte{},
	}
	fixture.oldGroupId = fixture.check.groupId
	fixture.commitments[1] = fixture.check.commitment
	// the creation's form, as KF1 files it
	fixture.putForm(fixture.oldGroupId, sidecar.Id{}, 1, fixture.check.signingKey, fixture.check.signerId)
	return fixture
}

// gen/<generation> of groupId under cause, chained from gen/<generation-1>'s commitment, signed by the fixture's writer
// and pinned to the newest state, stored at gkm/<at>/gen/<generation>; its bytes. The commitment is kept as the
// generation's.
func (self *reformFixture) putStatement(at sidecar.Id, groupId sidecar.Id, repoId sidecar.Id, generation uint64, cause sidecar.GkmCause) []byte {
	self.t.Helper()
	commitment := bytes.Repeat([]byte{byte(40 + generation)}, 32)
	record := &protocol.GenRotate{
		GroupId: groupId.Bytes(), RepoId: repoId.Bytes(), Generation: generation, Commitment: commitment,
		ParentCommitment: bytes.Clone(self.commitments[generation-1]), Genlink: make([]byte, 72), Cause: uint32(cause),
		Auth: self.check.auth.Pin(), TimeMs: self.clock.Now().UnixMilli(), HoldersSha256: bytes.Repeat([]byte{4}, 32),
	}
	signed, err := sidecar.SignGenRotate(record, sidecar.GkmSignFunction(checkTestSign(self.check.signingKey, self.check.signerId)))
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	self.putObject(sidecar.GkmGenerationPath(at, generation), signedBytes)
	if repoId == self.check.repoId {
		self.commitments[generation] = commitment
	}
	return signedBytes
}

// key holding objectBytes, as gkm creates it.
func (self *reformFixture) putObject(key string, objectBytes []byte) {
	self.t.Helper()
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, key, objectBytes, nil); err != nil {
		self.t.Fatal(err)
	}
}

// gkm/<groupId>/gen/<generation>'s bytes.
func (self *reformFixture) statement(groupId sidecar.Id, generation uint64) []byte {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, sidecar.GkmGenerationPath(groupId, generation))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	objectBytes, err := readAllLimited(object, self.settings.GenerationRecordMaxByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	return objectBytes
}

// The ladder through generation: the old group's statements byte for byte under the new group, as the ladder route
// writes them.
func (self *reformFixture) putLadder(from uint64, through uint64) {
	for generation := from; generation <= through; generation += 1 {
		self.putObject(sidecar.GkmGenerationPath(self.newGroupId, generation), self.statement(self.oldGroupId, generation))
	}
}

// The repo's next GroupForm, making groupId by re-forming previousGroupId (zero for a creation) at generation, signed
// by signerId under key.
func (self *reformFixture) putForm(groupId sidecar.Id, previousGroupId sidecar.Id, generation uint64, key ed25519.PrivateKey, signerId sidecar.Id) {
	self.t.Helper()
	form := &protocol.GroupForm{RepoId: self.check.repoId.Bytes(), GroupId: groupId.Bytes(), Generation: generation, Auth: self.check.auth.Pin()}
	if previousGroupId != (sidecar.Id{}) {
		form.PreviousGroupId = previousGroupId.Bytes()
	}
	formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(form)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := checkTestSign(key, signerId)("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	formBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	self.formCount += 1
	self.putObject(gkmservice.GkmFormKey(self.check.repoId, self.formCount), formBytes)
}

// A site loss: the old group's objects are gone, and the repo's forms with them.
func (self *reformFixture) loseOldGroup(through uint64) {
	self.t.Helper()
	keys := []string{}
	for generation := uint64(1); generation <= through; generation += 1 {
		keys = append(keys, sidecar.GkmGenerationPath(self.oldGroupId, generation))
	}
	for seq := uint64(1); seq <= self.formCount; seq += 1 {
		keys = append(keys, gkmservice.GkmFormKey(self.check.repoId, seq))
	}
	for _, key := range keys {
		if err := self.cluster.Delete(self.ctx, key); err != nil {
			self.t.Fatal(err)
		}
	}
	self.formCount = 0
}

// A plan by signerId on the head as it stands, under groupId's generation.
func (self *reformFixture) planIn(groupId sidecar.Id, generation uint64, signerId sidecar.Id) *sidecar.EvsPushPlan {
	plan := self.planOnHead(generation, self.commitments[generation])
	plan.GroupId = groupId
	plan.SignerSidecarId = signerId
	return plan
}

// plan pushed by its signer, the fixture's writer or its other device, under its own key and token.
func (self *reformFixture) pushBy(plan *sidecar.EvsPushPlan) *httptest.ResponseRecorder {
	self.t.Helper()
	key := self.check.signingKey
	if plan.SignerSidecarId == self.check.otherId {
		key = self.check.otherKey
	}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(key, plan.SignerSidecarId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.post(self.token(plan.SignerSidecarId), &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload})
}

// Commits a at gen/1 of the old group, as every write before the re-form does, and rotates the old group to its gen/2
// under cause, which nothing writes under: the head stays at gen/1.
func (self *reformFixture) writeThenRotate(cause sidecar.GkmCause) {
	self.t.Helper()
	first := self.planIn(self.oldGroupId, 1, self.check.signerId)
	self.create(first, "a")
	self.requireCommitted(self.pushBy(first), 1)
	self.putStatement(self.oldGroupId, self.oldGroupId, self.check.repoId, 2, cause)
}

// A refusal that refuses nothing: 503 UNAVAILABLE, the head as it was.
func (self *reformFixture) requireUnavailable(label string, recorder *httptest.ResponseRecorder, before *EvsStoredHead) {
	self.t.Helper()
	if recorder.Code != http.StatusServiceUnavailable || refusalOf(self.t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
		self.t.Fatalf("%s: status %d (%s), want 503 UNAVAILABLE", label, recorder.Code, refusalOf(self.t, recorder).GetCode())
	}
	if after := self.head(); after.Etag != before.Etag {
		self.t.Fatalf("%s: the head moved on a refusal that refuses nothing", label)
	}
}

// A re-form cut short at its ladder, then reseeded and resumed: its form stands first with no ladder, the reseed
// carries the old group's statements into the new group, and the resume claims the new group's first generation.
// Every member's next write, in the new group from a head of the old group's gen/1, crosses the carried gen/2 and
// commits; the head then names the new group.
func TestPushAfterAResumedReformCommitsEveryMembersWrite(t *testing.T) {
	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	// cut at its ladder: the form stands, nothing under the new group
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	// the reseed: the ladder, and nothing more
	fixture.putLadder(1, 2)
	// the resume: the first generation that names the new group
	fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)

	// each member device's next write
	writer := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(writer, 1, "a")
	fixture.requireCommitted(fixture.pushBy(writer), 2)
	other := fixture.planIn(fixture.newGroupId, 3, fixture.check.otherId)
	fixture.create(other, "other")
	fixture.requireCommitted(fixture.pushBy(other), 3)

	head := fixture.head().Head
	if sidecar.Id(head.GetGroupId()) != fixture.newGroupId || head.GetGeneration() != 3 || !bytes.Equal(head.GetGenerationCommitment(), fixture.commitments[3]) {
		t.Fatalf("the head's generation pin after the re-form: group %x, generation %d", head.GetGroupId(), head.GetGeneration())
	}
	if head.GetPathEpoch().GetDueGeneration() != 0 {
		t.Fatalf("a crossing of REQUEST generations recorded due %v", head.GetPathEpoch())
	}
}

// The crossing reads a carried generation as the group it was claimed in held it: a REMOVE gen/2 of the old group,
// which the ladder carried, records its due at the first commit in the new group past it.
func TestPushIntoAReformedGroupRecordsACarriedRemoveDue(t *testing.T) {
	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRemove)
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	fixture.putLadder(1, 2)
	fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)

	writer := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(writer, 1, "a")
	fixture.requireCommitted(fixture.pushBy(writer), 2)
	if pathEpoch := fixture.head().Head.GetPathEpoch(); pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() {
		t.Fatalf("the crossing of the carried REMOVE gen/2 recorded due %v", pathEpoch)
	}
}

// While the re-form is under way, writes at the old group's generations commit, since its objects stand; a write at
// the new group's first generation answers 503, refusing and recording nothing, while the ladder goes up and until
// that generation is claimed, and then commits.
func TestPushDuringAReformAnswersAsTheDesignSays(t *testing.T) {
	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	fixture.putLadder(1, 1)

	old := fixture.planIn(fixture.oldGroupId, 2, fixture.check.signerId)
	fixture.write(old, 1, "a")
	fixture.requireCommitted(fixture.pushBy(old), 2)

	before := fixture.head()
	fixture.commitments[3] = bytes.Repeat([]byte{43}, 32)
	unladdered := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(unladdered, 2, "a")
	fixture.requireUnavailable("a write at the new group's first generation while its ladder goes up", fixture.pushBy(unladdered), before)

	fixture.putLadder(2, 2)
	unclaimed := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(unclaimed, 2, "a")
	fixture.requireUnavailable("a write at the new group's first generation before its claim", fixture.pushBy(unclaimed), before)
	if refusals, err := sidecar.DecodeEvsRefusals(fixture.head().Head.GetRefused()); err != nil || len(refusals) != 0 {
		t.Fatalf("the refusals recorded %d records: %v", len(refusals), err)
	}

	fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)
	claimed := fixture.planIn(fixture.newGroupId, 3, fixture.check.otherId)
	fixture.write(claimed, 2, "a")
	fixture.requireCommitted(fixture.pushBy(claimed), 3)
}

// A form that lands after a push its absence refused is met by a retry once GroupFormCacheTtl has passed: the list
// read before it is kept that long, and refuses only.
func TestPushMeetsAFormLandedAfterItsListOnceTheCacheTtlPasses(t *testing.T) {
	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	// the ladder's objects before the form, as no honest gkm writes them, so only the form's absence refuses
	fixture.putLadder(1, 2)
	fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)
	before := fixture.head()
	early := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(early, 1, "a")
	fixture.requireUnavailable("a write crossing a ladder no form carries", fixture.pushBy(early), before)

	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	within := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(within, 1, "a")
	fixture.requireUnavailable("a retry within the form list's ttl", fixture.pushBy(within), before)

	fixture.clock.Advance(fixture.settings.GroupFormCacheTtl)
	after := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
	fixture.write(after, 1, "a")
	fixture.requireCommitted(fixture.pushBy(after), 2)
}

// After a site loss the old group's objects are gone: a write naming it, at a generation the new group's ladder
// carries, resolves through the repo's newest form, answering 503 until the ladder reaches that generation; and the
// first write in the new group, crossing the ladder, commits.
func TestPushAfterASiteLossResolvesTheOldGroupThroughTheNewestForm(t *testing.T) {
	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	oldStatement := fixture.statement(fixture.oldGroupId, 2)
	firstStatement := fixture.statement(fixture.oldGroupId, 1)
	fixture.loseOldGroup(2)
	// the re-form's form is the repo's only one, its ladder going up
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	fixture.putObject(sidecar.GkmGenerationPath(fixture.newGroupId, 1), firstStatement)

	before := fixture.head()
	moved := fixture.planIn(fixture.oldGroupId, 2, fixture.check.signerId)
	fixture.write(moved, 1, "a")
	fixture.requireUnavailable("a write naming the lost group before the ladder reaches its generation", fixture.pushBy(moved), before)

	fixture.putObject(sidecar.GkmGenerationPath(fixture.newGroupId, 2), oldStatement)
	again := fixture.planIn(fixture.oldGroupId, 2, fixture.check.signerId)
	fixture.write(again, 1, "a")
	fixture.requireCommitted(fixture.pushBy(again), 2)

	fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)
	next := fixture.planIn(fixture.newGroupId, 3, fixture.check.otherId)
	fixture.write(next, 2, "a")
	fixture.requireCommitted(fixture.pushBy(next), 3)
}

// What the resolution refuses, each 503 with the head as it was, at the first push into the new group, whose crossing
// reads its gen/2 carried: a statement naming another group in a group no form makes; one past the form's generation;
// one under a form whose signer evs's state does not admit; and one of another repo. And a push naming the new group
// at a generation its ladder carried is a pin of another group, final: the record stands for the old group, whose
// generation it is.
func TestPushRefusesAStatementNoFormCarries(t *testing.T) {
	cases := []struct {
		name  string
		setUp func(fixture *reformFixture)
	}{
		{name: "a group no form makes", setUp: func(fixture *reformFixture) {
			fixture.putLadder(1, 2)
		}},
		{name: "past the form's generation", setUp: func(fixture *reformFixture) {
			fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 1, fixture.check.signingKey, fixture.check.signerId)
			fixture.putLadder(1, 2)
		}},
		{name: "a form evs's state does not admit the signer of", setUp: func(fixture *reformFixture) {
			fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, checkTestKey("stranger"), testId("stranger"))
			fixture.putLadder(1, 2)
		}},
		{name: "another repo's statement", setUp: func(fixture *reformFixture) {
			fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
			fixture.putLadder(1, 1)
			stray := fixture.putStatement(testId("stray group"), fixture.oldGroupId, testId("another repo"), 2, sidecar.GkmCauseRequest)
			fixture.putObject(sidecar.GkmGenerationPath(fixture.newGroupId, 2), stray)
		}},
	}
	for _, c := range cases {
		fixture := newReformFixture(t, nil)
		fixture.writeThenRotate(sidecar.GkmCauseRequest)
		c.setUp(fixture)
		fixture.putStatement(fixture.newGroupId, fixture.newGroupId, fixture.check.repoId, 3, sidecar.GkmCauseRequest)
		plan := fixture.planIn(fixture.newGroupId, 3, fixture.check.signerId)
		fixture.write(plan, 1, "a")
		before := fixture.head()
		recorder := fixture.pushBy(plan)
		if recorder.Code != http.StatusServiceUnavailable || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
			t.Errorf("%s: status %d (%s), want 503 UNAVAILABLE", c.name, recorder.Code, refusalOf(t, recorder).GetCode())
			continue
		}
		if after := fixture.head(); after.Etag != before.Etag {
			t.Errorf("%s: the head moved", c.name)
		}
	}

	fixture := newReformFixture(t, nil)
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	fixture.putLadder(1, 2)
	relabeled := fixture.planIn(fixture.newGroupId, 2, fixture.check.signerId)
	fixture.write(relabeled, 1, "a")
	requireRefusal(t, fixture.pushBy(relabeled), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
}

// The resolution itself, on the cluster as each row leaves it: own, carried and moved, each kept once resolved, and a
// generation no row resolves answering none.
func TestGenerationRecordsResolveEachRow(t *testing.T) {
	fixture := newReformFixture(t, func(settings *EvsSettings) { settings.GroupFormCacheTtl = 0 })
	fixture.writeThenRotate(sidecar.GkmCauseRequest)
	fixture.putForm(fixture.newGroupId, fixture.oldGroupId, 2, fixture.check.signingKey, fixture.check.signerId)
	fixture.putLadder(1, 2)
	records := NewGenerationRecords(fixture.settings, fixture.clock)
	read := func(groupId sidecar.Id, generation uint64) *protocol.GenRotate {
		t.Helper()
		record, err := records.Read(fixture.ctx, fixture.cluster, fixture.check.repoId, groupId, generation, fixture.check.auth)
		if err != nil {
			t.Fatalf("gen/%d of %x: %v", generation, groupId, err)
		}
		return record
	}
	if record := read(fixture.oldGroupId, 2); record == nil || sidecar.Id(record.GetGroupId()) != fixture.oldGroupId {
		t.Fatalf("own: %v", record)
	}
	if record := read(fixture.newGroupId, 2); record == nil || sidecar.Id(record.GetGroupId()) != fixture.oldGroupId ||
		!bytes.Equal(record.GetCommitment(), fixture.commitments[2]) {
		t.Fatalf("carried: %v", record)
	}
	if record := read(fixture.newGroupId, 3); record != nil {
		t.Fatalf("an unclaimed generation resolved to %v", record)
	}
	// the old group lost: its statements move to the newest form's ladder, and the resolutions kept stand
	for generation := uint64(1); generation <= 2; generation += 1 {
		if err := fixture.cluster.Delete(fixture.ctx, sidecar.GkmGenerationPath(fixture.oldGroupId, generation)); err != nil {
			t.Fatal(err)
		}
	}
	if record := read(fixture.oldGroupId, 1); record == nil || sidecar.Id(record.GetGroupId()) != fixture.oldGroupId ||
		!bytes.Equal(record.GetCommitment(), fixture.commitments[1]) {
		t.Fatalf("moved: %v", record)
	}
	if record := read(fixture.oldGroupId, 2); record == nil || !bytes.Equal(record.GetCommitment(), fixture.commitments[2]) {
		t.Fatalf("a kept resolution: %v", record)
	}
	// a repo with no forms moves nothing
	record, err := NewGenerationRecords(fixture.settings, fixture.clock).Read(fixture.ctx, fixture.cluster, testId("formless repo"), fixture.oldGroupId, 2, fixture.check.auth)
	if err != nil || record != nil {
		t.Fatalf("a repo with no forms resolved %v: %v", record, err)
	}
	// a stored form that is no GroupForm is a fault
	fixture.formCount += 1
	fixture.putObject(gkmservice.GkmFormKey(fixture.check.repoId, fixture.formCount), []byte("not a form"))
	if _, err := NewGenerationRecords(fixture.settings, fixture.clock).Read(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.oldGroupId, 1, fixture.check.auth); !errors.Is(err, sidecar.ErrGkmMalformed) {
		t.Fatalf("a malformed newest form: %v", err)
	}
}

// The settings' bounds: a resolution's form count and a form's bytes must be positive.
func TestGenerationFormSettingsValidate(t *testing.T) {
	for _, adjust := range []func(settings *EvsSettings){
		func(settings *EvsSettings) { settings.GroupFormMaxCount = 0 },
		func(settings *EvsSettings) { settings.GroupFormMaxByteCount = 0 },
	} {
		settings := DefaultEvsSettings()
		adjust(settings)
		if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
			t.Errorf("settings validated: %v", err)
		}
	}
	if settings := DefaultEvsSettings(); settings.GroupFormCacheTtl != 5*time.Second || settings.Validate() != nil {
		t.Errorf("the defaults: ttl %s", settings.GroupFormCacheTtl)
	}
}
