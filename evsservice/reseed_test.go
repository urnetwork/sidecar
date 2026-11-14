// EVSB-M2-20's tests of POST .../reseed on T2 (reseed.go; QD-725, QD-815): each rule the reseed mode skips, shown
// beside the push route refusing the same statement, and each rule it keeps, 5f's window and 5g among them, which a
// repo admin's device's walk of its mirror (sidecar.EvsRepo.Reseed, in process) shows returning a ref two devices
// wrote whole; the slot call's order and stripping; the repos a re-seed is taken for; and the Signed EvsReseed kept
// at reseed/ and served with the head.

package evsservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A shared file-mode ref two devices wrote through the push route of a site the test then loses: the writer's pushes
// each on the head, and the other device's, planned at version 1 to write a and create e, sent once the head stood at
// 4, 3 versions above its base, which 5f takes inside its window, so it committed at 5. What the devices' mirrors hold
// of it, by version from 1: each version's statement and payload, its batch record as a read serves it, and C_v.
type reseedTwoDeviceHistory struct {
	bodies  []*protocol.EvsReseedRequest
	records [][]byte
	chains  [][32]byte
	// the lost site's head
	head *EvsStoredHead
}

// Six versions: a, b, c and d by the writer, the other device's push at 5, and f by the writer.
func newReseedTwoDeviceHistory(t *testing.T) *reseedTwoDeviceHistory {
	t.Helper()
	site := newPushFixture(t, nil)
	check := site.check
	history := &reseedTwoDeviceHistory{}
	committed := func(recorder *httptest.ResponseRecorder, body *protocol.EvsPushRequest) {
		t.Helper()
		site.requireCommitted(recorder, uint64(len(history.bodies)+1))
		history.bodies = append(history.bodies, &protocol.EvsReseedRequest{Statement: body.GetStatement(), Payload: body.GetPayload()})
		history.chains = append(history.chains, [32]byte(site.head().Head.GetChain()))
	}
	writer := func(label string) {
		t.Helper()
		plan := site.plan()
		site.create(plan, label)
		body := site.body(plan)
		committed(site.post(site.token(check.signerId), body), body)
	}
	writer("a")
	// the other device plans on version 1
	other := site.plan()
	other.Changes = append(other.Changes, check.change(other, checkTestPath("a"), 1, 2))
	site.create(other, "e")
	otherBody, _ := site.bodyAndOriginBy(other, check.otherKey, check.otherId)
	writer("b")
	writer("c")
	writer("d")
	committed(site.post(site.token(check.otherId), otherBody), otherBody)
	writer("f")

	head := site.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != len(history.bodies) || EvsHeadWindowFirstVersion(head.Head) != 1 {
		t.Fatalf("the lost site's window: %d entries, %v", len(window), err)
	}
	for _, entry := range window {
		recordBytes, err := site.engine.readRecordBytesAt(site.ctx, site.cluster, check.repoId, check.refId, entry.Place)
		if err != nil {
			t.Fatal(err)
		}
		history.records = append(history.records, recordBytes)
	}
	history.head = head
	return history
}

// version's statement, parsed.
func (self *reseedTwoDeviceHistory) statement(t *testing.T, version uint64) *sidecar.EvsStatement {
	t.Helper()
	statement, err := sidecar.ParseEvsStatement(self.bodies[version-1].GetStatement())
	if err != nil {
		t.Fatal(err)
	}
	return statement
}

// A repo admin's device in the fixture's recovery: the admin's EvsClient, whose calls the fixture's engine serves in
// process under tokens for the scopes the client asks, and its sealed mirror of the repo.
type reseedDevice struct {
	fixture *reseedFixture
	client  *sidecar.EvsClient
	mirror  *sidecar.EvsMirrorStore
	// the reseed calls the engine has served
	reseedCallCount int
}

// The admin's device, its mirror empty.
func (self *reseedFixture) device() *reseedDevice {
	t := self.t
	t.Helper()
	check := self.check
	sign := checkTestSign(check.otherKey, check.otherId)
	identity := &sidecar.SidecarIdentity{
		NetworkId: check.networkId, SidecarId: check.otherId, ClientId: check.clientId, Generation: 1,
		IdentityPublicKey: check.otherKey.Public().(ed25519.PublicKey),
	}
	device := &reseedDevice{fixture: self}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: check.networkId,
		EvsUrl:    "https://evs.example",
		Transport: device,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(check.otherId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(check.networkId), ClientId: connect.Id(check.clientId), SidecarId: &connectSidecarId,
				Audience: EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sign,
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      sidecartest.NewFakeGkm(self.clock, self.host.Blobs, nil).Client(check.otherId, sidecar.GkmSignFunction(sign)),
		Store:    sidecartest.NewFakeStore().Root(),
		Clock:    &reseedDeviceClock{clock: self.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	mirror, err := client.Mirror(check.repoId)
	if err != nil {
		t.Fatal(err)
	}
	device.client, device.mirror = client, mirror
	return device
}

// The engine serves the call, counting the reseed calls. Called on the walk's goroutine alone.
func (self *reseedDevice) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "/reseed") {
		self.reseedCallCount += 1
	}
	recorder := httptest.NewRecorder()
	self.fixture.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// The mirror holds history's versions through version, as the devices' syncs kept them.
func (self *reseedDevice) holds(history *reseedTwoDeviceHistory, through uint64) {
	t := self.fixture.t
	t.Helper()
	refId := self.fixture.check.refId
	for version := uint64(1); version <= through; version += 1 {
		statement := history.statement(t, version)
		if err := self.mirror.Put(sidecar.EvsMirrorStatementKey(refId, version), bytes.NewReader(statement.Bytes)); err != nil {
			t.Fatal(err)
		}
		recordKey := sidecar.EvsMirrorRecordKey(sidecar.Id(statement.Push.GetPushId()), 0)
		if err := self.mirror.Put(recordKey, bytes.NewReader(history.records[version-1])); err != nil {
			t.Fatal(err)
		}
	}
	ref := &sidecar.EvsMirrorRef{RefId: refId, Version: through, Chain: history.chains[through-1], MirroredAt: self.fixture.clock.Now()}
	if err := self.mirror.RaiseRef(ref); err != nil {
		t.Fatal(err)
	}
}

// The device's walk of its mirror and what it did to the one ref the mirror holds, once every step 8 of the commits
// it made has finished.
func (self *reseedDevice) reseed() *sidecar.EvsReseedRef {
	t := self.fixture.t
	t.Helper()
	result, err := self.client.Repo(self.fixture.check.repoId).Reseed(self.fixture.ctx, &sidecar.EvsReseedArgs{})
	if err != nil {
		t.Fatal(err)
	}
	self.fixture.awaitStepEights()
	if len(result.Refs) != 1 || result.Refs[0].RefId != self.fixture.check.refId || len(result.Slots) != 0 {
		t.Fatalf("a walk of one ref: %d refs, %d slots not taken", len(result.Refs), len(result.Slots))
	}
	return result.Refs[0]
}

// The device's clock: the fixture's, its waits firing at once, so a retry of a call that refused nothing runs on.
type reseedDeviceClock struct {
	clock *sidecartest.FakeClock
}

func (self *reseedDeviceClock) Now() time.Time {
	return self.clock.Now()
}

func (self *reseedDeviceClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *reseedDeviceClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// A shared file-mode ref two devices wrote, one of them on a base 3 below the head, re-seeds whole from a complete
// mirror (QD-815): the device's walk sends each version in order, the other device's push commits on its own base as
// 5f and 5g take it, and the ref returns at the lost site's version, chain and push, each version an EVS_BATCH_RESEED
// record of the statement the mirror held, with nothing refused or recorded. A second walk changes nothing.
func TestReseedReturnsAFileModeRefTwoDevicesWroteWhole(t *testing.T) {
	history := newReseedTwoDeviceHistory(t)
	fixture := newReseedFixture(t)
	check := fixture.check
	if other := history.statement(t, 5).Push; other.GetBaseVersion() != 1 || !bytes.Equal(other.GetSignerSidecarId(), check.otherId.Bytes()) {
		t.Fatalf("version 5 is %x's push on base %d", other.GetSignerSidecarId(), other.GetBaseVersion())
	}
	device := fixture.device()
	device.holds(history, 6)
	ref := device.reseed()
	if ref.Stopped != nil || ref.MirrorVersion != 6 || ref.Version != 6 || ref.Chain != history.chains[5] || device.reseedCallCount != 6 {
		t.Fatalf("the walk ended at %d of %d after %d calls, stopped by %v", ref.Version, ref.MirrorVersion, device.reseedCallCount, ref.Stopped)
	}
	head := fixture.head()
	if head.Version() != 6 || !bytes.Equal(head.Head.GetChain(), history.head.Head.GetChain()) ||
		!bytes.Equal(head.Head.GetPushId(), history.head.Head.GetPushId()) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d, not the lost site's, with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
	for version := uint64(1); version <= 6; version += 1 {
		record := fixture.recordAt(check.refId, version)
		statementBytes, _, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || err != nil || !bytes.Equal(statementBytes, history.bodies[version-1].GetStatement()) {
			t.Fatalf("version %d's record is type %s, not the mirror's statement: %v", version, record.Type, err)
		}
	}

	// again: 5a answers each version where it stands, and nothing is written
	if again := device.reseed(); again.Stopped != nil || again.Version != 6 {
		t.Fatalf("a second walk ended at %d, stopped by %v", again.Version, again.Stopped)
	}
	if after := fixture.head(); after.Etag != head.Etag {
		t.Fatal("a second walk wrote the head")
	}
}

// A file-mode push the push route's 5f or 5g refuses is refused the same in the reseed mode, recording nothing
// (QD-815): a base past the window below the head, one above the head and one planned on no head 409 BASE_STALE, a
// base_chain the history does not hold 409 BASE_STALE, and a file a version after the base changed 409 PATH_CONFLICT
// naming it, each as the push route answers a twin of it built now. The head keeps its ETag and holds no refusal,
// and the statement sent again answers the same, unrecorded. At the window's edge, a base 63 below the head, a push
// that changes nothing written since commits.
func TestReseedRefusesAFileModeBaseWhereThePushRouteDoes(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	reseeded := func(plan *sidecar.EvsPushPlan, version uint64) {
		t.Helper()
		fixture.requireCommitted(fixture.reseed(fixture.reseedBody(plan)), version)
	}
	first := fixture.kept()
	fixture.create(first, "a")
	reseeded(first, 1)
	chainOne := fixture.head().Head.GetChain()
	second := fixture.kept()
	fixture.create(second, "b")
	reseeded(second, 2)
	chainTwo := fixture.head().Head.GetChain()
	// a written on its version 1 at version 3
	write := fixture.kept()
	write.Changes = append(write.Changes, check.change(write, checkTestPath("a"), 1, 2))
	reseeded(write, 3)
	chainThree := fixture.head().Head.GetChain()
	for version := uint64(4); version <= 65; version += 1 {
		plan := fixture.kept()
		fixture.create(plan, fmt.Sprintf("p%d", version))
		reseeded(plan, version)
	}
	fixture.awaitStepEights()

	// the same base, chain and changes as the mirror kept them, and as a device would push them now
	twins := func(base uint64, chain []byte, labels ...string) (*protocol.EvsReseedRequest, *sidecar.EvsPushPlan) {
		t.Helper()
		kept, fresh := fixture.kept(), fixture.plan()
		for _, plan := range []*sidecar.EvsPushPlan{kept, fresh} {
			plan.BaseVersion = base
			plan.BaseChain = [32]byte(chain)
			fixture.create(plan, labels...)
		}
		return fixture.reseedBody(kept), fresh
	}
	refused := func(what string, body *protocol.EvsReseedRequest, fresh *sidecar.EvsPushPlan, code protocol.EvsRefusalCode) *protocol.EvsRefusalReply {
		t.Helper()
		before := fixture.head()
		requireRefusal(t, fixture.reseed(body), http.StatusConflict, code)
		recorder := fixture.reseed(body)
		requireRefusal(t, recorder, http.StatusConflict, code)
		reply := refusalOf(t, recorder)
		if after := fixture.head(); reply.GetRecorded() || after.Etag != before.Etag || len(after.Head.GetRefused()) != 0 {
			t.Fatalf("%s: a refused re-seed was recorded", what)
		}
		requireRefusal(t, fixture.push(fresh), http.StatusConflict, code)
		if after := fixture.head(); after.Etag != before.Etag {
			t.Fatalf("%s: the push route's refusal wrote the head", what)
		}
		return reply
	}
	start := sidecar.EvsChainStart(check.repoId, check.refId)
	outside, outsideFresh := twins(1, chainOne, "q")
	refused("a base 64 below the head", outside, outsideFresh, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	above, aboveFresh := twins(66, chainThree, "r")
	refused("a base above the head", above, aboveFresh, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	noHead, noHeadFresh := twins(0, start[:], "s")
	refused("a push planned on no head", noHead, noHeadFresh, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	forked, forkedFresh := twins(2, chainThree, "t")
	refused("a base chain the history does not hold", forked, forkedFresh, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	// a on its version 1, on base 2: version 3 wrote it since
	conflict, conflictFresh := fixture.kept(), fixture.plan()
	for _, plan := range []*sidecar.EvsPushPlan{conflict, conflictFresh} {
		plan.BaseVersion = 2
		plan.BaseChain = [32]byte(chainTwo)
		plan.Changes = append(plan.Changes, check.change(plan, checkTestPath("a"), 1, 2))
	}
	reply := refused("a file written after the base", fixture.reseedBody(conflict), conflictFresh, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if paths := reply.GetPaths(); len(paths) != 1 {
		t.Fatalf("the conflict names %d paths", len(paths))
	}

	// at the window's edge, on a path nothing has written
	edge, _ := twins(2, chainTwo, "u")
	fixture.requireCommitted(fixture.reseed(edge), 66)
}

// A git-mode ref keeps QD-725's rule, which is 5f's git mode: a re-seeded push on a base below the head is refused
// 409 non-fast-forward though nothing it changes was written since, and so is one on the head's version under another
// chain, each as the push route refuses a twin of it and recording nothing; one on the head commits.
func TestReseedKeepsTheHeadForAGitModeRef(t *testing.T) {
	fixture := newReseedFixture(t)
	gitPlan := func(plan *sidecar.EvsPushPlan) *sidecar.EvsPushPlan {
		plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
		return plan
	}
	versionChains := map[uint64][]byte{}
	for version, label := range []string{"a", "b", "c"} {
		plan := gitPlan(fixture.kept())
		fixture.create(plan, label)
		fixture.requireCommitted(fixture.reseed(fixture.reseedBody(plan)), uint64(version+1))
		versionChains[uint64(version+1)] = fixture.head().Head.GetChain()
	}
	refused := func(what string, base uint64, chain []byte, label string) {
		t.Helper()
		kept, fresh := gitPlan(fixture.kept()), gitPlan(fixture.plan())
		for _, plan := range []*sidecar.EvsPushPlan{kept, fresh} {
			plan.BaseVersion = base
			plan.BaseChain = [32]byte(chain)
			fixture.create(plan, label)
		}
		before := fixture.head()
		requireRefusal(t, fixture.reseed(fixture.reseedBody(kept)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)
		requireRefusal(t, fixture.push(fresh), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)
		if after := fixture.head(); after.Etag != before.Etag || len(after.Head.GetRefused()) != 0 {
			t.Fatalf("%s: a refusal was recorded", what)
		}
	}
	refused("a base below the head", 1, versionChains[1], "d")
	refused("the head's version under another chain", 3, versionChains[2], "e")
	onHead := gitPlan(fixture.kept())
	fixture.create(onHead, "d")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(onHead)), 4)
}

// The device's version check still catches a statement that lands at another version than the mirror held it at
// (QD-815's cost): the new site's ref holds the history through version 4 from a walk of a mirror that held no more,
// and a writer's push lands at 5 on it. The complete mirror's walk then sends the other device's push, whose base 1
// lies inside 5f's window with nothing it changes written since, so evs commits it at 6; the walk stops the ref at 4
// with ErrEvsReseedVersion and sends nothing past it.
func TestReseedWalkStopsWhereAStatementLandsAtAnotherVersion(t *testing.T) {
	history := newReseedTwoDeviceHistory(t)
	fixture := newReseedFixture(t)
	device := fixture.device()
	device.holds(history, 4)
	if ref := device.reseed(); ref.Stopped != nil || ref.Version != 4 {
		t.Fatalf("the first walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	// a writer's push on the head the walk left, under a push id of its own
	live := fixture.plan()
	live.PushId = testId("reseed live push")
	fixture.create(live, "z")
	fixture.requireCommitted(fixture.push(live), 5)
	fixture.awaitStepEights()

	device.holds(history, 6)
	device.reseedCallCount = 0
	ref := device.reseed()
	if !errors.Is(ref.Stopped, sidecar.ErrEvsReseedVersion) || ref.Version != 4 || ref.Chain != history.chains[3] {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if device.reseedCallCount != 5 {
		t.Fatalf("the walk made %d reseed calls, versions 1 to 5 being 5", device.reseedCallCount)
	}
	head := fixture.head()
	if head.Version() != 6 || !bytes.Equal(head.Head.GetPushId(), history.statement(t, 5).Push.GetPushId()) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with push %x", head.Version(), head.Head.GetPushId())
	}
}

// BASE_STALE carries a deposit ref's head only to its own depositor (plan-EVS1-deposit-head), as a re-seed's 200 does:
// the admin re-seeding the writer's deposit on a base above its head gets the refusal alone, and the writer, a repo
// admin too, re-seeding its own deposit gets the head with it.
func TestReseedBaseStaleCarriesADepositHeadToItsDepositorAlone(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	depositor := check.signerId
	refId := sidecar.EvsDepositRefId(check.repoId, depositor)
	deposit := func(base uint64, chain [32]byte, label string) *protocol.EvsReseedRequest {
		plan := fixture.kept()
		plan.RefId = refId
		plan.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
		plan.OwnerSidecarId = &depositor
		plan.BaseVersion = base
		plan.BaseChain = chain
		plan.Changes = append(plan.Changes, check.change(plan, checkTestPath(label), 0, base+1))
		return fixture.reseedBody(plan)
	}
	reply := fixture.requireCommitted(fixture.reseed(deposit(0, sidecar.EvsChainStart(check.repoId, refId), "deposit 1")), 1)
	if reply.GetDepositHead() != nil {
		t.Fatal("the admin's 200 carries another sidecar's deposit head")
	}
	ahead := deposit(2, [32]byte(bytes.Repeat([]byte{6}, 32)), "deposit 2")
	recorder := fixture.reseed(ahead)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	if refusalOf(t, recorder).GetDepositHead() != nil {
		t.Fatal("the admin's BASE_STALE carries another sidecar's deposit head")
	}
	fixture.auth.grant(depositor, check.repoId, sidecar.AclEvsAdmin)
	own := fixture.call(fixture.token(depositor, "admin"), http.MethodPost, "/reseed", ahead)
	requireRefusal(t, own, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	if head := refusalOf(t, own).GetDepositHead(); head.GetVersion() != 1 || !bytes.Equal(head.GetChain(), fixture.headOf(refId).Head.GetChain()) {
		t.Fatalf("the depositor's BASE_STALE carries head %v", head)
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

// A deleted repo's segments (§11.12's re-seed exception at PUT .../segments): refused 409 REPO_DELETED as §11.12's
// refused row has it, to a writer, outside a recovery, under another RepoDelete than the projection ends in and past
// the restore window; taken from a repo admin while reseed is on and the repo is taking its history back; and a
// repo past deleted takes none.
func TestReseedTakesADeletedReposSegmentsFromItsAdmin(t *testing.T) {
	fixture := newUploadFixture(t)
	network := fixture.networkId.String()
	gate := func(reseed bool) {
		t.Helper()
		text := "sidecar:\n  evs:\n    enabled: true\n    networks: [\"" + network + "\"]\n"
		if reseed {
			text += "  reseed: true\n"
		}
		if err := fixture.host.Gates.Set(text); err != nil {
			t.Fatal(err)
		}
	}
	deletionId := testId("upload deletion")
	entryTime := fixture.clock.Now().Add(-3 * 24 * time.Hour)
	project := func(deletion *EvsRepoDeletionFacts) {
		fixture.auth.setRepo(fixture.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: sidecar.Id(fixture.networkId), Deletion: deletion})
	}
	restorable := &EvsRepoDeletionFacts{DeletionId: deletionId, Time: entryTime, SignerSidecarId: fixture.admin}
	cluster, err := fixture.host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	// the repo active, then deleted under the RepoDelete, as the reseed route places it before any history
	classify := func(ctx context.Context, objectByteCount int) context.Context { return ctx }
	if _, err := transitionRepo(fixture.ctx, cluster, fixture.engine.repos, fixture.repoId, fixture.engine.settings.RepoTransitionRetryCount,
		classify, decideActivate(func() (bool, error) { return true, nil }, fixture.clock.Now())); err != nil {
		t.Fatalf("repo/ to active: %v", err)
	}
	moved, err := transitionRepo(fixture.ctx, cluster, fixture.engine.repos, fixture.repoId, fixture.engine.settings.RepoTransitionRetryCount,
		classify, decideDelete(restorable, fixture.clock.Now()))
	if err != nil || moved.Object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Fatalf("repo/ to deleted: %v", err)
	}
	project(restorable)
	segment := testSegment(fixture.repoId, 4096, 6)
	segmentId := sha256.Sum256(segment)
	refused := func(what string, sidecarId sidecar.Id, role string, code protocol.EvsRefusalCode) {
		t.Helper()
		requireRefusal(t, fixture.upload(sidecarId, role, segment, segmentId, false), http.StatusConflict, code)
		if fixture.object("seg-1", SegmentKey(fixture.repoId, segmentId)) != nil {
			t.Fatalf("%s: a refused upload wrote", what)
		}
	}

	gate(false)
	refused("outside a recovery", fixture.admin, "admin", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	gate(true)
	refused("a writer's upload", fixture.writer, "rw", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	project(&EvsRepoDeletionFacts{DeletionId: testId("another deletion"), Time: entryTime, SignerSidecarId: fixture.admin})
	refused("under another RepoDelete", fixture.admin, "admin", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	project(&EvsRepoDeletionFacts{DeletionId: deletionId, Time: fixture.clock.Now().Add(-fixture.engine.settings.ReseedRestoreWindow), SignerSidecarId: fixture.admin})
	refused("past the restore window", fixture.admin, "admin", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	project(&EvsRepoDeletionFacts{DeletionId: deletionId, Now: true, Time: entryTime, SignerSidecarId: fixture.admin})
	refused("a RepoDelete with now", fixture.admin, "admin", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	project(&EvsRepoDeletionFacts{DeletionId: deletionId, Time: entryTime, Restored: true, SignerSidecarId: fixture.admin})
	refused("a restored RepoDelete repo/ has not followed", fixture.admin, "admin", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)

	// the repo admin's upload while its history returns, a closure upload never
	project(restorable)
	requireRefusal(t, fixture.upload(fixture.admin, "admin", segment, segmentId, true), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	receipt := fixture.receipt(fixture.upload(fixture.admin, "admin", segment, segmentId, false))
	if receipt.GetPaddedSize() != uint64(len(segment)) || !bytes.Equal(fixture.object("seg-1", SegmentKey(fixture.repoId, segmentId)), segment) {
		t.Fatalf("the admin's segment: receipt of %d bytes", receipt.GetPaddedSize())
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
