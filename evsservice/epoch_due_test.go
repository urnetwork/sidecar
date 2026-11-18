// §11.6's due row at evs with every due batched (QD-1046), on a real network's rows-only gate as evs's gate cache holds
// it: whatever shrank the repo's holders before the first commit crossing a REMOVE generation (an agent's ordinary or
// compromise revocation, a member device's removal, or an agent's ordinary revocation before two later bases moved the
// gate's window past gen/1's pin, each of which once read immediate), the commit records a due 24 h on with
// due_blocks_creation false, and a creation at the new generation commits; and a crossing push that creates a path
// commits it, recording the due, where owner decision 229 once refused it.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
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
type epochDueGateViews struct {
	stateLock sync.Mutex
	view      sidecar.GkmAuthView
}

func (self *epochDueGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.view == nil {
		return nil, EvsAuthUnknown
	}
	return self.view, EvsAuthAllowed
}

func (self *epochDueGateViews) set(view sidecar.GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.view = view
}

// A push fixture whose gate view is a rows-only gate of a real network: the fixture's two writers are member m's
// devices under their own keys, writing the fixture's general repo, which an agent of a tag the owner owns reads by
// its own grant; gen/1 of a group of its own pinned at the gate's state after the grants.
type epochDueFixture struct {
	*pushFixture
	admission *sidecartest.AdmissionNet
	views     *epochDueGateViews
	writer    *sidecartest.AdmissionDevice
	agent     *sidecartest.AdmissionDevice
	// gen/1's pin, the gate's state before any span
	firstPin *bridge.AuthPin
}

func newEpochDueFixture(t *testing.T) *epochDueFixture {
	t.Helper()
	fixture := &epochDueFixture{pushFixture: newPushFixture(t, nil), views: &epochDueGateViews{}}
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
	check.groupId = testId("epoch due group")
	fixture.firstPin = gate.Pin()
	fixture.putGenerationPinned(1, sidecar.GkmCauseRequest, nil, fixture.firstPin)
	return fixture
}

// The rows-only gate the network restarted at its newest base, at the tip, as evs's gate cache holds it.
func (self *epochDueFixture) gateState() *sidecar.ConfigState {
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
func (self *epochDueFixture) follow() *bridge.AuthPin {
	self.t.Helper()
	gate := self.gateState()
	self.views.set(gate)
	return gate.Pin()
}

// gen/<generation> of the fixture's group under cause after the generation whose commitment is parent, pinned at
// pin, signed by the fixture's writer; its commitment. gen/1's is the fixture's.
func (self *epochDueFixture) putGenerationPinned(generation uint64, cause sidecar.GkmCause, parent []byte, pin *bridge.AuthPin) []byte {
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
func (self *epochDueFixture) planPinned(generation uint64, commitment []byte, pin *bridge.AuthPin) *sidecar.EvsPushPlan {
	plan := self.planOnHead(generation, commitment)
	plan.Auth = proto.Clone(pin).(*bridge.AuthPin)
	return plan
}

// Commits a at gen/1, lets span land on the network, then crosses to a REMOVE gen/2 pinned at the gate's state after
// it with a write of a, or with a creation of path when it is not empty: the later pin and gen/2's commitment.
func (self *epochDueFixture) crossAfter(span func(), path string) (*bridge.AuthPin, []byte) {
	self.t.Helper()
	first := self.planPinned(1, self.check.commitment, self.firstPin)
	first.PathEpoch = 1
	self.create(first, "a")
	self.requireCommitted(self.push(first), 1)
	span()
	secondPin := self.follow()
	commitment := self.putGenerationPinned(2, sidecar.GkmCauseRemove, self.check.commitment, secondPin)
	crossing := self.planPinned(2, commitment, secondPin)
	if path == "" {
		self.write(crossing, 1, "a")
	} else {
		self.create(crossing, path)
	}
	self.requireCommitted(self.push(crossing), 2)
	return secondPin, commitment
}

// The agent's ordinary revocation by the owner, which shrinks the repo's holders.
func (self *epochDueFixture) revokeAgent() {
	self.t.Helper()
	self.admission.MustLand(self.admission.Sign(self.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		self.admission.Revocation(self.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
}

// Two later bases, a member's admission between them giving the second a tail to fold, which move the window of the
// gate and of the network's reference reader past every entry before them.
func (self *epochDueFixture) laterBases() {
	self.t.Helper()
	self.admission.Fold(true)
	self.admission.AdmitMember(self.admission.Owner(), "bystander", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.admission.Fold(true)
}

// The spans that shrink the repo's holders before the crossing, each of which once made it immediate but the first.
func epochDueSpans() []struct {
	name string
	span func(fixture *epochDueFixture)
} {
	return []struct {
		name string
		span func(fixture *epochDueFixture)
	}{
		{name: "an agent's ordinary revocation", span: func(fixture *epochDueFixture) {
			fixture.revokeAgent()
		}},
		{name: "the agent's compromise revocation", span: func(fixture *epochDueFixture) {
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				fixture.admission.Revocation(fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, fixture.firstPin.GetVersion())))
		}},
		{name: "a member device's removal", span: func(fixture *epochDueFixture) {
			removed := fixture.admission.Device("removed device", fixture.writer.MemberId)
			fixture.admission.AdmitDevice(fixture.admission.Owner(), removed, 0)
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
				Header: fixture.admission.Header(), RepoId: fixture.check.repoId.Bytes(), Subject: removed.SidecarId.Bytes(),
				Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
			}))
			fixture.admission.MustLand(fixture.admission.Sign(fixture.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				fixture.admission.Revocation(removed, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
		}},
		{name: "an agent's ordinary revocation before two later bases", span: func(fixture *epochDueFixture) {
			fixture.revokeAgent()
			fixture.laterBases()
		}},
	}
}

// The due the crossing recorded: gen/2's, 24 h on, blocking nothing.
func (self *epochDueFixture) requireBatchedDue(label string) {
	self.t.Helper()
	pathEpoch := self.head().Head.GetPathEpoch()
	if pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() ||
		pathEpoch.GetDueByMs() != self.clock.Now().Add(self.settings.PathEpochBatchedDelay).UnixMilli() {
		self.t.Fatalf("%s: due %v", label, pathEpoch)
	}
}

// Whatever shrank the holders, the crossing records a batched due and a creation at the new generation commits.
func TestPathEpochDueBatchedWhateverShrankTheHolders(t *testing.T) {
	for _, c := range epochDueSpans() {
		fixture := newEpochDueFixture(t)
		to, commitment := fixture.crossAfter(func() { c.span(fixture) }, "")
		if shrunk := fixture.gateState().Repo(fixture.check.repoId).GetHoldersShrunkAt(); shrunk <= fixture.firstPin.GetVersion() {
			t.Fatalf("%s: the span shrank nothing: holders_shrunk_at %d, from %d", c.name, shrunk, fixture.firstPin.GetVersion())
		}
		fixture.requireBatchedDue(c.name)
		creation := fixture.planPinned(2, commitment, to)
		fixture.create(creation, "new")
		fixture.requireCommitted(fixture.push(creation), 3)
	}
}

// The push that crosses the REMOVE generation creating a path commits it and records the batched due, whatever shrank
// the holders: no crossing creation is refused (QD-1046).
func TestPathEpochCrossingCreationCommits(t *testing.T) {
	for _, c := range epochDueSpans() {
		fixture := newEpochDueFixture(t)
		fixture.crossAfter(func() { c.span(fixture) }, "new")
		fixture.requireBatchedDue(c.name)
	}
}
