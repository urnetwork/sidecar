// QD-1178 and QD-1182 at POST .../reseed (reseed.go): a re-seeded statement whose auth pin lies before what evs's
// state retains is taken unjudged, on its signature under the key evs's oldest retained rows that admit its signer
// give it, as a reader takes one, so a re-seed of history older than evs's window finishes where each of its calls
// once answered 503.
//
// On T2's fake log, evs retaining past the first state: the writer's push commits though the newest state lists it no
// more, the erasure ref takes a push from a signer no state made admin, a ref rule that reads no state still refuses,
// and a forged statement or a signer no row admits is refused, while a statement pinned within the window is judged
// as before. On a real network whose gate evs reads, started at the newest base as a new site's gate cache starts:
// two bases past a history three devices wrote, one of them revoked since, a repo admin's walk of its mirror finishes
// and restores every version; a forged statement, a signer never admitted, one admitted after its pin, one revoked at
// it and a pin off the chain are refused, recording nothing, and a pin ahead of evs's state answers 503; and
// statements pinned within the window are judged at their pins as before.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// On the fake log, evs retaining from the second state, which lists the writer no more and makes the other writer
// and admin: a statement pinned at the first state is taken on its signature alone. Before anything commits, a forged
// statement, the writer's id under the other's key, and a signer no row admits are refused 400 INVALID, and an owned
// ref written by another sidecar than its owner, a ref rule that reads no state, 409 REF_MODE, each recording nothing.
// Then the writer's push commits as an EVS_BATCH_RESEED record, and its ERASE commits on the erasure ref, which
// judged at its pin would be refused SCOPE (TestReseedKeepsTheRefsTable). Within the window, at the second state, the
// writer is refused SCOPE as before and the other's push commits.
func TestReseedTakesAStatementPinnedBeforeEvsRetentionOnItsSignature(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	second := fixture.appendState(check.signingKey, []sidecar.Id{check.otherId}, check.otherId)
	check.authLog.Retain(second.Pin().GetVersion())
	if _, err := second.At(check.firstView.Pin()); !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
		t.Fatalf("evs's state at the first state's pin: %v", err)
	}
	keptMs := fixture.clock.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	refused := func(what string, body *protocol.EvsReseedRequest, status int, code protocol.EvsRefusalCode) {
		t.Helper()
		recorder := fixture.reseed(body)
		if recorder.Code != status || refusalOf(t, recorder).GetCode() != code {
			t.Fatalf("%s: status %d (%s), want %d %s", what, recorder.Code, refusalOf(t, recorder).GetCode(), status, code)
		}
		if !fixture.head().Absent() || len(fixture.batchRecords()) != 0 {
			t.Fatalf("%s: a refused re-seed wrote", what)
		}
	}
	forged := fixture.kept()
	fixture.create(forged, "forged")
	refused("a forged statement", fixture.signedBody(forged, check.otherKey, check.signerId), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	strangerId, strangerKey := testId("check stranger"), checkTestKey("stranger")
	stranger := fixture.kept()
	stranger.SignerSidecarId = strangerId
	fixture.create(stranger, "stranger")
	refused("a signer no row admits", fixture.signedBody(stranger, strangerKey, strangerId), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	owned := fixture.kept()
	owned.RefId = testId("reseed unjudged owned ref")
	owned.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
	owned.OwnerSidecarId = &check.otherId
	owned.BaseVersion = 0
	owned.BaseChain = sidecar.EvsChainStart(check.repoId, owned.RefId)
	fixture.create(owned, "owned")
	refused("an owned ref written by another sidecar", fixture.reseedBody(owned), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)

	// the writer, whom the newest state lists no more
	first := fixture.kept()
	fixture.create(first, "a")
	body := fixture.reseedBody(first)
	fixture.requireCommitted(fixture.reseed(body), 1)
	record := fixture.recordAt(check.refId, 1)
	statementBytes, _, err := sidecar.ParseEvsPushRecordBody(record.Body)
	if err != nil || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || !bytes.Equal(statementBytes, body.GetStatement()) {
		t.Fatalf("version 1's record is type %s, not the statement sent: %v", record.Type, err)
	}
	// and its ERASE, though no state made it admin
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: testId("unjudged erase slot"), KeyIndex: 0})
	erase.TimeMs = keptMs
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(erase)), 1)

	// within the window, judged at the second state as before
	unlisted := fixture.kept()
	unlisted.Auth = second.Pin()
	fixture.create(unlisted, "b")
	requireRefusal(t, fixture.reseed(fixture.reseedBody(unlisted)), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	listed := fixture.kept()
	listed.Auth = second.Pin()
	listed.SignerSidecarId = check.otherId
	fixture.create(listed, "c")
	fixture.requireCommitted(fixture.reseed(fixture.signedBody(listed, check.otherKey, check.otherId)), 2)
	if head := fixture.head(); head.Version() != 2 || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
}

// A real network whose gate evs reads, an AdmissionNet on fake stores as epoch_due_test.go builds one: the check
// fixture's writer and other admitted as devices of one member under their own keys, departed beside them, each
// granted writer on the check repo; and a history the three wrote at a site the test then loses, every statement
// pinned at pin, the gate's state once the grants stood. Then departed is revoked at revokedPin, late is admitted, a
// base folds, a repo is created at betweenPin and a second base folds, so the gate a new site starts at the newest
// base retains none of these pins.
type reseedOldHistory struct {
	t         *testing.T
	admission *sidecartest.AdmissionNet
	departed  *sidecartest.AdmissionDevice
	late      *sidecartest.AdmissionDevice

	pin        *bridge.AuthPin
	revokedPin *bridge.AuthPin
	betweenPin *bridge.AuthPin
	// what the devices' mirrors hold of the lost site's ref: a by the writer, b by the other, c by departed, and a
	// written again by the writer
	history *reseedTwoDeviceHistory
	// the gate at the tip, started at the newest base, as a new site's gate cache holds it
	gate *sidecar.ConfigState
}

func newReseedOldHistory(t *testing.T) *reseedOldHistory {
	t.Helper()
	site := newPushFixture(t, nil)
	check := site.check
	blobs := sidecartest.NewFakeBlobs(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), sidecartest.NewFaultQueue(), nil, sidecartest.DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	admission := sidecartest.NewAdmissionNet(t, &sidecartest.AdmissionTier{
		Cluster: cluster,
		NewApi: func(clock sidecar.Clock, cluster sidecar.BlobCluster) sidecartest.AdmissionApi {
			return sidecartest.FakeApiAdmission(sidecartest.NewFakeApi(t.Context(), clock, sidecartest.NewFaultQueue(), nil, cluster, nil))
		},
	})
	t.Cleanup(admission.Close)
	world := &reseedOldHistory{t: t, admission: admission, history: &reseedTwoDeviceHistory{}}
	owner := admission.Owner()
	memberId := admission.AdmitMember(owner, "writer", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	writer := &sidecartest.AdmissionDevice{Name: "check signer", SidecarId: check.signerId, MemberId: memberId, Key: check.signingKey}
	other := &sidecartest.AdmissionDevice{Name: "check other", SidecarId: check.otherId, MemberId: memberId, Key: check.otherKey}
	world.departed = admission.Device("departed", memberId)
	writers := []*sidecartest.AdmissionDevice{writer, other, world.departed}
	for _, device := range writers {
		admission.AdmitDevice(owner, device, 0)
	}
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: admission.Header(), RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	for _, device := range writers {
		admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: admission.Header(), RepoId: check.repoId.Bytes(), Subject: device.SidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER,
		}))
	}

	// the lost site's gate at the state after the grants, and gen/1 of a group of its own pinned there, so no record
	// cached under the fixture's group answers for it
	gate := world.gateState()
	views := &epochDueGateViews{}
	views.set(gate)
	site.engine.deps.GateViews = views
	world.pin = gate.Pin()
	check.groupId = testId("reseed old history group")
	generation := check.record()
	generation.Cause = uint32(sidecar.GkmCauseRequest)
	generation.HoldersSha256 = bytes.Repeat([]byte{3}, 32)
	generation.Auth = proto.Clone(world.pin).(*bridge.AuthPin)
	signedGeneration, err := sidecar.SignGenRotate(generation, sidecar.GkmSignFunction(checkTestSign(check.signingKey, check.signerId)))
	if err != nil {
		t.Fatal(err)
	}
	generationBytes, err := proto.Marshal(signedGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.cluster.PutIfNoneMatch(site.ctx, sidecar.GkmGenerationPath(check.groupId, 1), generationBytes, nil); err != nil {
		t.Fatal(err)
	}
	site.auth.grant(world.departed.SidecarId, check.repoId, sidecar.AclEvsWrite)

	commit := func(device *sidecartest.AdmissionDevice, change func(plan *sidecar.EvsPushPlan)) {
		t.Helper()
		plan := site.plan()
		plan.Auth = proto.Clone(world.pin).(*bridge.AuthPin)
		change(plan)
		body, _ := site.bodyAndOriginBy(plan, device.Key, device.SidecarId)
		site.requireCommitted(site.post(site.token(device.SidecarId), body), uint64(len(world.history.bodies)+1))
		world.history.bodies = append(world.history.bodies, &protocol.EvsReseedRequest{Statement: body.GetStatement(), Payload: body.GetPayload()})
		world.history.chains = append(world.history.chains, [32]byte(site.head().Head.GetChain()))
	}
	commit(writer, func(plan *sidecar.EvsPushPlan) { site.create(plan, "a") })
	commit(other, func(plan *sidecar.EvsPushPlan) { site.create(plan, "b") })
	commit(world.departed, func(plan *sidecar.EvsPushPlan) { site.create(plan, "c") })
	commit(writer, func(plan *sidecar.EvsPushPlan) { site.write(plan, 1, "a") })
	site.awaitStepEights()
	head := site.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != len(world.history.bodies) || EvsHeadWindowFirstVersion(head.Head) != 1 {
		t.Fatalf("the lost site's window: %d entries, %v", len(window), err)
	}
	for _, entry := range window {
		recordBytes, err := site.engine.readRecordBytesAt(site.ctx, site.cluster, check.repoId, check.refId, entry.Place)
		if err != nil {
			t.Fatal(err)
		}
		world.history.records = append(world.history.records, recordBytes)
	}
	world.history.head = head

	world.revokedPin = admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		admission.Revocation(world.departed, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0))).Pin
	world.late = admission.Device("late", memberId)
	admission.AdmitDevice(owner, world.late, 0)
	admission.Fold(true)
	world.betweenPin = admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: admission.Header(), RepoId: admission.Id("a later repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	})).Pin
	admission.Fold(true)
	world.gate = world.gateState()
	for _, pin := range []*bridge.AuthPin{world.pin, world.revokedPin, world.betweenPin} {
		if _, err := world.gate.At(pin); !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
			t.Fatalf("the gate at %d at pin %d: %v, want it not retained", world.gate.Pin().GetVersion(), pin.GetVersion(), err)
		}
	}
	return world
}

// The rows-only gate the network started at its newest base, at the tip.
func (self *reseedOldHistory) gateState() *sidecar.ConfigState {
	self.t.Helper()
	var gate *sidecar.ConfigState
	for _, reader := range self.admission.ReaderStates() {
		if strings.HasPrefix(reader.Name, "a gate") {
			gate = reader.Config
		}
	}
	if gate == nil {
		self.t.Fatal("no gate stands at the tip")
	}
	return gate
}

// A new site in a recovery, the other a repo admin by its token, its gate the network's at the tip.
func (self *reseedOldHistory) newSite() *reseedFixture {
	fixture := newReseedFixture(self.t)
	views := &epochDueGateViews{}
	views.set(self.gate)
	fixture.engine.deps.GateViews = views
	return fixture
}

// plan signed by key as signerId, who it names its signer, pinned at pin: its reseed call.
func reseedPinnedBody(fixture *reseedFixture, plan *sidecar.EvsPushPlan, pin *bridge.AuthPin, key ed25519.PrivateKey, signerId sidecar.Id) *protocol.EvsReseedRequest {
	fixture.t.Helper()
	plan.Auth = proto.Clone(pin).(*bridge.AuthPin)
	plan.SignerSidecarId = signerId
	return fixture.signedBody(plan, key, signerId)
}

// Two bases past a history the writer, the other and departed wrote, departed revoked since: on a new site, whose gate
// starts at the newest base and so retains none of the history's pins, the first version's call commits where it once
// answered 503, and a repo admin's walk of its mirror finishes, every version an EVS_BATCH_RESEED record of the
// statement the mirror held, the ref back at the lost site's version, chain and push, which a fresh read serves.
func TestReseedOfAHistoryTwoBasesOldFinishesAndRestoresEveryVersion(t *testing.T) {
	world := newReseedOldHistory(t)
	history := world.history
	fixture := world.newSite()
	check := fixture.check
	if departed := history.statement(t, 3).Push; !bytes.Equal(departed.GetSignerSidecarId(), world.departed.SidecarId.Bytes()) {
		t.Fatalf("version 3 is %x's push", departed.GetSignerSidecarId())
	}
	fixture.requireCommitted(fixture.reseed(history.bodies[0]), 1)

	device := fixture.device()
	last := uint64(len(history.bodies))
	device.holds(history, last)
	ref := device.reseed()
	if ref.Stopped != nil || ref.MirrorVersion != last || ref.Version != last || ref.Chain != history.chains[last-1] || device.reseedCallCount != int(last) {
		t.Fatalf("the walk ended at %d of %d after %d calls, stopped by %v", ref.Version, ref.MirrorVersion, device.reseedCallCount, ref.Stopped)
	}
	head := fixture.head()
	if head.Version() != last || !bytes.Equal(head.Head.GetChain(), history.head.Head.GetChain()) ||
		!bytes.Equal(head.Head.GetPushId(), history.head.Head.GetPushId()) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d, not the lost site's, with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
	for version := uint64(1); version <= last; version += 1 {
		record := fixture.recordAt(check.refId, version)
		statementBytes, _, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || err != nil || !bytes.Equal(statementBytes, history.bodies[version-1].GetStatement()) {
			t.Fatalf("version %d's record is type %s, not the mirror's statement: %v", version, record.Type, err)
		}
	}
	reply := fixture.readPath(fixture.token(check.signerId), 0, true, checkTestPath("a"))
	if reply.head.GetVersion() != last || len(reply.statements) != int(last) {
		t.Fatalf("a read of the re-seeded ref: head %d, %d statements", reply.head.GetVersion(), len(reply.statements))
	}
}

// On the same network's gate, two bases on, a statement pinned before what the gate retains is refused, recording
// nothing, where its signature does not verify under the key the oldest retained rows give its signer: a forged one,
// the writer's id under the other's key; one by a signer the rows never admitted; one by late, admitted after its pin;
// and one by departed at its revocation's own pin. A pin off the chain, at the position between the bases under
// another chain, is refused as a fork, and one above the gate's state answers 503. Statements by the same signers
// commit at pins they stood at: departed's at the history's pin and the writer's between the bases. Within the window,
// at the tip, each is judged at its pin as before: departed and late, which no grant makes writers there, are refused
// SCOPE, and the writer's commits.
func TestReseedRefusesAnUnjudgedStatementNoRetainedRowAdmits(t *testing.T) {
	world := newReseedOldHistory(t)
	fixture := world.newSite()
	check := fixture.check
	pinned := func(label string) *sidecar.EvsPushPlan {
		plan := fixture.kept()
		fixture.create(plan, label)
		return plan
	}
	refused := func(what string, body *protocol.EvsReseedRequest, status int, code protocol.EvsRefusalCode) {
		t.Helper()
		before := fixture.head()
		recordCount := len(fixture.batchRecords())
		recorder := fixture.reseed(body)
		if recorder.Code != status || refusalOf(t, recorder).GetCode() != code {
			t.Fatalf("%s: status %d (%s), want %d %s", what, recorder.Code, refusalOf(t, recorder).GetCode(), status, code)
		}
		if after := fixture.head(); after.Etag != before.Etag || len(fixture.batchRecords()) != recordCount {
			t.Fatalf("%s: a refused re-seed wrote", what)
		}
	}
	invalid := func(what string, body *protocol.EvsReseedRequest) {
		t.Helper()
		refused(what, body, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
	invalid("a forged statement", reseedPinnedBody(fixture, pinned("forged"), world.pin, check.otherKey, check.signerId))
	invalid("a signer never admitted", reseedPinnedBody(fixture, pinned("stranger"), world.pin, checkTestKey("stranger"), testId("check stranger")))
	invalid("a signer admitted after its pin", reseedPinnedBody(fixture, pinned("late"), world.pin, world.late.Key, world.late.SidecarId))
	invalid("a signer revoked at its pin", reseedPinnedBody(fixture, pinned("revoked"), world.revokedPin, world.departed.Key, world.departed.SidecarId))
	offChain := &bridge.AuthPin{Version: world.betweenPin.GetVersion(), Chain: bytes.Repeat([]byte{9}, 32)}
	if _, err := world.gate.At(offChain); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Fatalf("the gate at a pin off its chain before its window: %v", err)
	}
	refused("a pin off the chain", reseedPinnedBody(fixture, pinned("off chain"), offChain, check.signingKey, check.signerId),
		http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
	ahead := &bridge.AuthPin{Version: world.gate.Pin().GetVersion() + 5, Chain: bytes.Repeat([]byte{1}, 32)}
	refused("a pin above the gate's state", reseedPinnedBody(fixture, pinned("ahead"), ahead, check.signingKey, check.signerId),
		http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if !fixture.head().Absent() {
		t.Fatal("a refused re-seed made the head")
	}

	// the same signers at pins they stood at
	fixture.requireCommitted(fixture.reseed(reseedPinnedBody(fixture, pinned("departed"), world.pin, world.departed.Key, world.departed.SidecarId)), 1)
	fixture.requireCommitted(fixture.reseed(reseedPinnedBody(fixture, pinned("between"), world.betweenPin, check.signingKey, check.signerId)), 2)

	// within the window, judged at the tip as before
	tip := world.gate.Pin()
	for _, device := range []*sidecartest.AdmissionDevice{world.departed, world.late} {
		refused(device.Name+"'s statement at the tip", reseedPinnedBody(fixture, pinned(device.Name+" at the tip"), tip, device.Key, device.SidecarId),
			http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	fixture.requireCommitted(fixture.reseed(reseedPinnedBody(fixture, pinned("writer at the tip"), tip, check.signingKey, check.signerId)), 3)
	if head := fixture.head(); head.Version() != 3 || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
}

// Format 2's lock at a pin before what evs retains (reseedUnjudgedAuth): with the repo locked in evs's newest state,
// which retains from the second state, a versionless creation pinned at the second state, within the window, is
// refused 409 VERSIONING under the lock as before, recording nothing, and its twin pinned at the first state commits,
// whether the lock stood there being not judged.
func TestReseedLeavesTheLockUnjudgedAtAPinBeforeEvsRetention(t *testing.T) {
	fixture := newReseedFixture(t)
	fixture.gateFormat2(true)
	check := fixture.check
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED,
	})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(testId("check member"), check.signerId, check.otherId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	second := check.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			check.signerId: check.signingKey.Public().(ed25519.PublicKey),
			check.otherId:  check.otherKey.Public().(ed25519.PublicKey),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{check.repoId: {check.signerId, check.otherId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{check.repoId: {check.signerId, check.otherId}},
	})
	check.auth = second
	check.authLog.Retain(second.Pin().GetVersion())
	versionless := func(pin *bridge.AuthPin, label string) *protocol.EvsReseedRequest {
		t.Helper()
		plan := fixture.kept()
		plan.Auth = proto.Clone(pin).(*bridge.AuthPin)
		// a kind-5 upload seg/ does not hold: the version reads collected once replaced (reseed_format2.go)
		fixture.versionlessWrite(plan, checkTestPath(label), 0, plan.BaseVersion+1, label)
		built, err := sidecar.NewEvsStatementBuilder(checkTestSign(check.signingKey, check.signerId)).BuildFormat2(plan)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
	}
	recorder := fixture.reseed(versionless(second.Pin(), "within the window"))
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if refusalOf(t, recorder).GetRecorded() || !fixture.head().Absent() || len(fixture.batchRecords()) != 0 {
		t.Fatal("a refused re-seed wrote")
	}
	fixture.requireCommitted(fixture.reseed(versionless(check.firstView.Pin(), "before the window")), 1)
	if record := fixture.recordAt(check.refId, 1); record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		t.Fatalf("version 1's record is type %s", record.Type)
	}
}

// A state whose repo row is one shared object, as a ConfigState's rows are.
type reseedSharedRowAuth struct {
	sidecar.GkmAuthView
	row *protocol.AclRepo
}

func (self *reseedSharedRowAuth) Repo(repoId sidecar.Id) *protocol.AclRepo {
	return self.row
}

// The view an unjudged statement's checks read (reseedUnjudgedAuth): the newest state's repo row with its lock
// cleared, the state's own row left as it was; nil for a repo the state does not hold; the state's keys and rows for
// everything else; and D-ACL-25's consent allowed, so an owner-bound repo's DROP consent, which a state that answers
// none refuses 503 when judged, passes.
func TestReseedUnjudgedViewLeavesTheLockAndConsentUnjudged(t *testing.T) {
	check := newCheckFixture(t)
	shared := &reseedSharedRowAuth{GkmAuthView: check.auth, row: &protocol.AclRepo{
		RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED,
	}}
	unjudged := &reseedUnjudgedAuth{GkmAuthView: shared}
	row := unjudged.Repo(check.repoId)
	if row == nil || row.GetLock() != protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNSPECIFIED || row.GetKind() != protocol.RepoKind_REPO_KIND_VAULT ||
		!bytes.Equal(row.GetRepoId(), check.repoId.Bytes()) {
		t.Fatalf("the unjudged row %v", row)
	}
	if shared.row.GetLock() != protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED {
		t.Fatal("the unjudged view cleared the state's own row")
	}
	if (&reseedUnjudgedAuth{GkmAuthView: check.auth}).Repo(testId("no such repo")) != nil {
		t.Fatal("a row for a repo the state does not hold")
	}
	if !bytes.Equal(unjudged.IdentityKey(check.signerId), check.auth.IdentityKey(check.signerId)) || unjudged.Pin().GetVersion() != check.auth.Pin().GetVersion() {
		t.Fatal("the unjudged view answers other keys or another pin than the state")
	}
	view := &PushView{
		RepoId: check.repoId, TokenSidecarId: check.signerId, Now: check.now, Auth: check.auth,
		Repo: &protocol.EvsRepoObject{RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT},
	}
	requireCheckRefusal(t, "consent judged at a state that answers none", checkDropConsent(view), EvsCheckReasonUnchecked)
	view.Auth = &reseedUnjudgedAuth{GkmAuthView: check.auth}
	requireCheckPass(t, "consent at an unjudged pin", checkDropConsent(view))
}
