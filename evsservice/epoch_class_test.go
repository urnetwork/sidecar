// §11.6's due row at evs classed from the log (question evs1-m2-16-due-classification, option 3; QD-949), on a real
// network's rows-only gate as evs's gate cache holds it: the first commit crossing a REMOVE generation after an agent's
// ordinary revocation records a batched due, 24 h on and blocking no creation; after the same agent's compromise
// revocation, or a member device's removal, an immediate one that blocks creation. A client holding the same log
// classes each crossing as evs recorded it.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The gate view a test sets, for every network.
type epochClassGateViews struct {
	stateLock sync.Mutex
	view      sidecar.GkmAuthView
}

func (self *epochClassGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.view == nil {
		return nil, EvsAuthUnknown
	}
	return self.view, EvsAuthAllowed
}

func (self *epochClassGateViews) set(view sidecar.GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.view = view
}

// A push fixture whose gate view is a rows-only gate of a real network: the fixture's two writers are member m's
// devices under their own keys, writing the fixture's general repo, which an agent of a tag the owner owns reads by
// its own grant; gen/1 of a group of its own pinned at the gate's state after the grants.
type epochClassFixture struct {
	*pushFixture
	admission *sidecartest.AdmissionNet
	views     *epochClassGateViews
	writer    *sidecartest.AdmissionDevice
	agent     *sidecartest.AdmissionDevice
	// gen/1's pin, the gate's state before any span
	firstPin *bridge.AuthPin
}

func newEpochClassFixture(t *testing.T) *epochClassFixture {
	t.Helper()
	fixture := &epochClassFixture{pushFixture: newPushFixture(t, nil), views: &epochClassGateViews{}}
	check := fixture.check
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
	fixture.admission = admission
	owner := admission.Owner()
	memberId := admission.AdmitMember(owner, "writer", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	fixture.writer = &sidecartest.AdmissionDevice{Name: "check signer", SidecarId: check.signerId, MemberId: memberId, Key: check.signingKey}
	other := &sidecartest.AdmissionDevice{Name: "check other", SidecarId: check.otherId, MemberId: memberId, Key: check.otherKey}
	for _, device := range []*sidecartest.AdmissionDevice{fixture.writer, other} {
		admission.AdmitDevice(owner, device, 0)
	}
	tagId := admission.Id("tag ci")
	admission.SetTagOwners(map[sidecar.Id]sidecar.Id{tagId: owner.MemberId})
	fixture.agent = admission.Device("ci agent", sidecar.Id{})
	notAfter := admission.Clock().Now().Add(24 * time.Hour).UnixMilli()
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admission.Admission(fixture.agent, []sidecar.Id{tagId}, false, notAfter, 0)))
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: admission.Header(), RepoId: check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	grants := []struct {
		device *sidecartest.AdmissionDevice
		role   protocol.RepoGrantRole
	}{
		{device: fixture.writer, role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER},
		{device: other, role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER},
		{device: fixture.agent, role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER},
	}
	for _, grant := range grants {
		admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: admission.Header(), RepoId: check.repoId.Bytes(), Subject: grant.device.SidecarId.Bytes(), Role: grant.role,
		}))
	}
	gate := fixture.gateState()
	holders, err := sidecar.KeyHolders(gate, check.repoId, admission.Clock().Now())
	if err != nil || !holders.Contains(sidecar.GkmHolderLeaf, check.signerId.Bytes()) || !holders.Contains(sidecar.GkmHolderAgent, fixture.agent.SidecarId.Bytes()) {
		t.Fatalf("the repo's holders %v: %v", holders, err)
	}
	if !bytes.Equal(gate.IdentityKey(check.signerId), check.signingKey.Public().(ed25519.PublicKey)) {
		t.Fatal("the gate admits no identity key of the fixture's writer")
	}
	fixture.views.set(gate)
	fixture.engine.deps.GateViews = fixture.views
	// a group of its own, so no record cached under the fixture's group answers for it
	check.groupId = testId("epoch class group")
	fixture.firstPin = gate.Pin()
	fixture.putGenerationPinned(1, sidecar.GkmCauseRequest, nil, fixture.firstPin)
	return fixture
}

// The rows-only gate the network restarted at its newest base, at the tip, as evs's gate cache holds it.
func (self *epochClassFixture) gateState() *sidecar.ConfigState {
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

// Moves the gate view to the gate's newest state, its pin.
func (self *epochClassFixture) follow() *bridge.AuthPin {
	self.t.Helper()
	gate := self.gateState()
	self.views.set(gate)
	return gate.Pin()
}

// gen/<generation> of the fixture's group under cause after the generation whose commitment is parent, pinned at
// pin, signed by the fixture's writer; its commitment. gen/1's is the fixture's.
func (self *epochClassFixture) putGenerationPinned(generation uint64, cause sidecar.GkmCause, parent []byte, pin *bridge.AuthPin) []byte {
	self.t.Helper()
	commitment := self.check.commitment
	record := &protocol.GenRotate{
		GroupId: self.check.groupId.Bytes(), RepoId: self.check.repoId.Bytes(), Generation: generation, Commitment: commitment,
		Cause: uint32(cause), Auth: proto.Clone(pin).(*bridge.AuthPin), TimeMs: self.clock.Now().UnixMilli(),
		HoldersSha256: bytes.Repeat([]byte{3}, 32),
	}
	if 1 < generation {
		commitment = bytes.Repeat([]byte{byte(7 + generation)}, 32)
		record.Commitment, record.ParentCommitment, record.Genlink = commitment, bytes.Clone(parent), make([]byte, 72)
	}
	signed, err := sidecar.SignGenRotate(record, sidecar.GkmSignFunction(checkTestSign(self.check.signingKey, self.check.signerId)))
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.GkmGenerationPath(self.check.groupId, generation), signedBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return commitment
}

// A plan at generation under commitment, pinned at pin, in the head's current path epoch.
func (self *epochClassFixture) planPinned(generation uint64, commitment []byte, pin *bridge.AuthPin) *sidecar.EvsPushPlan {
	plan := self.planOnHead(generation, commitment)
	plan.Auth = proto.Clone(pin).(*bridge.AuthPin)
	return plan
}

// Commits a at gen/1, lets span land on the network, then crosses to a REMOVE gen/2 pinned at the gate's state after
// it with a write of a: the pins either side of the span.
func (self *epochClassFixture) crossAfter(span func()) (*bridge.AuthPin, *bridge.AuthPin, []byte) {
	self.t.Helper()
	first := self.planPinned(1, self.check.commitment, self.firstPin)
	first.PathEpoch = 1
	self.create(first, "a")
	self.requireCommitted(self.push(first), 1)
	span()
	secondPin := self.follow()
	commitment := self.putGenerationPinned(2, sidecar.GkmCauseRemove, self.check.commitment, secondPin)
	crossing := self.planPinned(2, commitment, secondPin)
	self.write(crossing, 1, "a")
	self.requireCommitted(self.push(crossing), 2)
	return self.firstPin, secondPin, commitment
}

// An agent's ordinary revocation before the crossing: evs records a batched due, 24 h on and blocking nothing, so a
// creation at the new generation commits; a client holding the same log classes it batched.
func TestPathEpochDueBatchedOnAnAgentsOrdinaryRevocation(t *testing.T) {
	fixture := newEpochClassFixture(t)
	from, to, commitment := fixture.crossAfter(func() {
		fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
			fixture.admission.Revocation(fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
	})
	if shrunk := fixture.gateState().Repo(fixture.check.repoId).GetHoldersShrunkAt(); shrunk <= from.GetVersion() {
		t.Fatalf("the revocation shrank nothing: holders_shrunk_at %d, from %d", shrunk, from.GetVersion())
	}
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() ||
		pathEpoch.GetDueByMs() != fixture.clock.Now().Add(evsPathEpochBatchedDelay).UnixMilli() {
		t.Fatalf("due %v", pathEpoch)
	}
	creation := fixture.planPinned(2, commitment, to)
	fixture.create(creation, "new")
	fixture.requireCommitted(fixture.push(creation), 3)
	if sidecar.EvsClassifyPathEpochDue(fixture.admission.State(), fixture.check.repoId, from, to) {
		t.Error("a client of the same log classes it immediate")
	}
}

// The same agent revoked for compromise, or a member device's removal, before the crossing: evs records an immediate
// due that blocks creation in the general repo, so a creation at the new generation is refused PATH_EPOCH_DUE; a client
// holding the same log classes it immediate.
func TestPathEpochDueImmediateOnACompromiseOrAMemberDevicesRemoval(t *testing.T) {
	cases := []struct {
		name string
		span func(fixture *epochClassFixture)
	}{
		{name: "the agent's compromise revocation", span: func(fixture *epochClassFixture) {
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				fixture.admission.Revocation(fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, fixture.firstPin.GetVersion())))
		}},
		{name: "a member device's removal", span: func(fixture *epochClassFixture) {
			removed := fixture.admission.Device("removed device", fixture.writer.MemberId)
			fixture.admission.AdmitDevice(fixture.admission.Owner(), removed, 0)
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
				Header: fixture.admission.Header(), RepoId: fixture.check.repoId.Bytes(), Subject: removed.SidecarId.Bytes(),
				Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
			}))
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				fixture.admission.Revocation(removed, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
		}},
	}
	for _, c := range cases {
		fixture := newEpochClassFixture(t)
		from, to, commitment := fixture.crossAfter(func() { c.span(fixture) })
		pathEpoch := fixture.head().Head.GetPathEpoch()
		if pathEpoch.GetDueGeneration() != 2 || !pathEpoch.GetDueBlocksCreation() || pathEpoch.GetDueByMs() != fixture.clock.Now().UnixMilli() {
			t.Fatalf("%s: due %v", c.name, pathEpoch)
		}
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
		creation := fixture.planPinned(2, commitment, to)
		fixture.create(creation, "new")
		requireRefusal(t, fixture.push(creation), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
		if !sidecar.EvsClassifyPathEpochDue(fixture.admission.State(), fixture.check.repoId, from, to) {
			t.Errorf("%s: a client of the same log classes it batched", c.name)
		}
	}
}
