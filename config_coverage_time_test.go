// QD-883's second comparison of §7.9's shrink row on the test network: an entry also shrinks repo R when it drops a
// holder of KeyHolders(R, n-1, t_s) from KeyHolders(R, n, t_s), t_s the time of the entry at R's holders_shrunk_at (R's
// making while that is 0), so the removal of a holder whose access had already ended by time keeps §10.6's gate shut to
// the generation the expiry closed and has GkmRemoveDue ask the rotation: by a RepoRevoke of a lapsed grant, a
// SidecarRevoke of an agent past its not_after, and a base whose policy edit drops a lapsed reader, which api and the
// writer name alike. A removal of a holder still current at t_s shrinks as before, and one whose access ended before
// R's last shrink shrinks nothing more. Where a base's rows folded R's last shrink, so no reader holds t_s (question
// shrink-two-time-compare-shrunk-time-row), the closed reading shrinks R on such a removal at every reader alike, shrinks
// nothing while R's holders do not change with time, and shrinks a repo that holds a lapsed holder once more after each
// base. StateAt's rebuilt states hold the same t_s as the states the log published.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Fails unless the gate refuses the generation formed at formedAt and formedTime at the reader's state now, and
// GkmRemoveDue asks REMOVE of a rotation from it.
func testConfigExpectClosedGeneration(t testing.TB, label string, state *ConfigState, repoId Id, formedAt *bridge.AuthPin, formedTime time.Time, now time.Time) {
	t.Helper()
	if err := GkmGateCheck(state, repoId, formedAt, formedTime, now); !errors.Is(err, ErrGkmGateClosed) {
		t.Errorf("%s: the gate on the generation the expiry closed: %v", label, err)
	}
	if due, err := GkmRemoveDue(state, repoId, formedAt, formedTime, now); err != nil || !due {
		t.Errorf("%s: a rotation from the generation the expiry closed is REMOVE %v: %v", label, due, err)
	}
}

// The probe of question base-shrunk-repos-expired-holder-drop: a reader's RepoGrant expires, GkmGateCheck refuses the
// generation formed before the expiry, a RepoRevoke of that reader then lands and raises holders_shrunk_at to its
// position, GkmGateCheck keeps refusing that generation, GkmRemoveDue asks a rotation from it, and a generation at the
// revoke passes, at every kind of reader.
func TestARevokeOfALapsedReaderKeepsTheGateShut(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, reader := net.repoWithReader("lapsing", expires)
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)

	// the grant expires with no entry: the generation formed before it fails the gate's expiry half
	net.tickAt(expires + 60*1000)
	now := time.UnixMilli(net.timeMs)
	if err := GkmGateCheck(net.log.State(), repoId, formedAt, formedTime, now); !errors.Is(err, ErrGkmGateClosed) {
		t.Fatalf("after the expiry the generation formed before it: %v", err)
	}

	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(),
	})
	now = time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the revoke of the lapsed reader at %d", i, shrunk, revoked.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the revoke", state, repoId, formedAt, formedTime, now)
		if err := GkmGateCheck(state, repoId, revoked.Pin, now, now); err != nil {
			t.Errorf("reader %d: a generation at the revoke: %v", i, err)
		}
	}
	net.everyReaderAgrees()
}

// The same for an agent: a tagged sidecar admitted until its not_after, reading the repo by a grant, passes it; the
// gate refuses the generation formed before then; and a SidecarRevoke of the agent shrinks the repo at its position, so
// the gate stays shut and the rotation is REMOVE.
func TestASidecarRevokeOfALapsedAgentKeepsTheGateShut(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	repoId := net.createRepo("agent read")
	notAfter := net.timeMs + 60*60*1000
	agent := net.device("lapsing agent", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{ci}, false, notAfter, 0))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: agent.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	holders, err := KeyHolders(net.log.State(), repoId, time.UnixMilli(net.timeMs))
	if err != nil || !holders.Contains(GkmHolderAgent, agent.sidecarId.Bytes()) {
		t.Fatalf("the agent holds no key: %v", err)
	}
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)

	net.tickAt(notAfter + 60*1000)
	now := time.UnixMilli(net.timeMs)
	if err := GkmGateCheck(net.log.State(), repoId, formedAt, formedTime, now); !errors.Is(err, ErrGkmGateClosed) {
		t.Fatalf("past the agent's not_after the generation formed before it: %v", err)
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	now = time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the agent's revoke at %d", i, shrunk, revoked.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the agent's revoke", state, repoId, formedAt, formedTime, now)
	}
	net.everyReaderAgrees()
}

// groupReadRows's rows with each rule expiring at expires, ms since the epoch.
func (self *testConfigNet) expiringGroupReadRows(expires int64, reads ...testConfigGroupRead) *bridge.ProjectionRows {
	self.t.Helper()
	rows := self.groupReadRows(reads...)
	aclRows := &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), aclRows); err != nil {
		self.t.Fatal(err)
	}
	for _, rule := range aclRows.GetRules() {
		rule.Expires = expires
	}
	rows.Acl = testConfigMarshal(self.t, aclRows)
	return rows
}

// A base at the tip folding everything under a newer config version over rows, signed as an honest writer signs it,
// unsequenced.
func (self *testConfigNet) policyBase(rows *bridge.ProjectionRows) []byte {
	self.t.Helper()
	state := self.log.State()
	return self.makeBase(self.owner, rows, self.n, state.Base().GetConfigVersion()+1, state.threshold)
}

// A network whose policy lets a reader read the repo by a rule that has expired, with the generation formed before the
// expiry, and the honest base at the tip whose policy edit drops that rule, unsequenced: the repo shrank after the
// policy's base, at the revoke of another reader, so every reader holds its t_s, unless foldedFirst, where another base
// folds that shrink before the expiry, so none does.
func testConfigLapsedRuleNet(t *testing.T, foldedFirst bool) (*testConfigNet, Id, *bridge.AuthPin, time.Time, []byte) {
	t.Helper()
	net := newTestConfigNet(t)
	reader, other := net.admitMemberDevice("reader"), net.admitMemberDevice("other")
	repoId := net.createRepo("rule read")
	expires := net.timeMs + 60*60*1000
	if verdict := net.push(net.policyBase(net.expiringGroupReadRows(expires, testConfigGroupRead{repoId: repoId, memberIds: []Id{reader.memberId}}))); !verdict.Accepted() {
		t.Fatalf("the policy base: %v", verdict.Refusal)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: other.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	shrink := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: other.sidecarId.Bytes()})
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != shrink.Pin.GetVersion() {
		t.Fatalf("holders_shrunk_at %d, the other reader's revoke at %d", shrunk, shrink.Pin.GetVersion())
	}
	if foldedFirst {
		if verdict := net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
		if _, known := net.log.State().shrinkTime(repoId); known {
			t.Fatal("a reader holds t_s for a shrink a base's rows folded")
		}
	}
	holders, err := KeyHolders(net.log.State(), repoId, time.UnixMilli(net.timeMs))
	if err != nil || !holders.Contains(GkmHolderLeaf, reader.sidecarId.Bytes()) {
		t.Fatalf("the reader holds no key by the rule: %v", err)
	}
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)

	net.tickAt(expires + 60*1000)
	if err := GkmGateCheck(net.log.State(), repoId, formedAt, formedTime, time.UnixMilli(net.timeMs)); !errors.Is(err, ErrGkmGateClosed) {
		t.Fatalf("past the rule's expiry the generation formed before it: %v", err)
	}
	return net, repoId, formedAt, formedTime, net.policyBase(net.groupReadRows())
}

// QD-746's base is the same case when its policy edit drops a reader whose rule had already expired: the base names the
// repo, which a present reader holds it to, and every kind of reader, api's among them, holds its position as
// holders_shrunk_at, so the gate stays shut to the generation the expiry closed and the rotation is REMOVE. api and the
// writer compute the same list: api takes the writer's and answers ErrConfigTipMoved to the list the entry's time alone
// gives, which names nothing.
func TestABaseThatDropsALapsedReaderShrinksItsRepo(t *testing.T) {
	net, repoId, formedAt, formedTime, honest := testConfigLapsedRuleNet(t, false)
	signedHeader, rowsBytes, timeMs := net.baseParts(honest)
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(honest, entry); err != nil {
		t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the writer names %x", header.GetShrunkRepoIds())
	}
	api := net.apiAtTip()
	if err := api.CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api refused the writer's list: %v", err)
	}
	unnamed, _, _ := net.baseParts(net.editedBase(honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = nil }))
	if err := api.CheckBase(unnamed, rowsBytes, timeMs); !errors.Is(err, ErrConfigTipMoved) {
		t.Errorf("api took the list the base's own time gives: %v", err)
	}
	if _, err := net.newReader().Apply(net.editedBase(honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = nil }), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a present reader took a base that names nothing: %v", err)
	}

	based := net.push(honest)
	if !based.Accepted() {
		t.Fatal(based.Refusal)
	}
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != based.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the base at %d", i, shrunk, based.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the base", state, repoId, formedAt, formedTime, now)
	}
	net.everyReaderAgrees()
}

// A removal of a holder still current at t_s and at the entry's own time shrinks at its position, as before; then the
// removal of a reader whose grant lapsed before that shrink drops no holder of KeyHolders(R, n-1, t_s), so it shrinks
// nothing more, and the generation formed at the shrink, after the lapse, passes the gate with no REMOVE due.
func TestARemovalOfAHolderThatLapsedBeforeTheLastShrinkShrinksNothingMore(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, lapsing := net.repoWithReader("r", expires)
	current := net.admitMemberDevice("current")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: current.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	olderAt, olderTime := net.log.Pin(), time.UnixMilli(net.timeMs)
	net.tickAt(expires + 60*1000)

	shrink := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: current.sidecarId.Bytes()})
	formedAt, formedTime := shrink.Pin, time.UnixMilli(net.timeMs)
	state := net.log.State()
	if shrunk := state.ShrunkAt(repoId); shrunk != shrink.Pin.GetVersion() {
		t.Fatalf("holders_shrunk_at %d, the current reader's revoke at %d", shrunk, shrink.Pin.GetVersion())
	}
	if GkmGatePasses(state, repoId, olderAt, olderTime, formedTime) {
		t.Error("the generation from before the shrink passes")
	}

	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: lapsing.sidecarId.Bytes()})
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != shrink.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d after the lapsed reader's revoke, the shrink at %d", i, shrunk, shrink.Pin.GetVersion())
		}
		if err := GkmGateCheck(state, repoId, formedAt, formedTime, now); err != nil {
			t.Errorf("reader %d: the generation formed at the shrink: %v", i, err)
		}
		if due, err := GkmRemoveDue(state, repoId, formedAt, formedTime, now); err != nil || due {
			t.Errorf("reader %d: a rotation from the generation formed at the shrink is REMOVE %v: %v", i, due, err)
		}
	}
	net.everyReaderAgrees()
}

// Where a base's rows folded the repo's making, so no reader holds t_s, the revoke of a reader whose grant lapsed
// after the base still shrinks the repo, by the closed reading, at a long-running reader, a reader from genesis, a new
// device and a cold gate that start at the base, and api, alike; the gate stays shut.
func TestARevokeOfALapsedReaderAfterABaseFoldedItKeepsTheGateShut(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, reader := net.repoWithReader("folded", expires)
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	for i, log := range net.everyReaderAndApi() {
		if _, known := log.State().shrinkTime(repoId); known {
			t.Fatalf("reader %d holds t_s for a making a base's rows folded", i)
		}
	}
	net.tickAt(expires + 60*1000)
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(),
	})
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the revoke at %d", i, shrunk, revoked.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the revoke", state, repoId, formedAt, formedTime, now)
	}
	net.everyReaderAgrees()
}

// The base case with no reader holding t_s: a base folded the repo's last shrink before the rule expired, and the
// policy edit that drops the lapsed reader names the repo by the closed reading, which api and the writer compute
// alike, as every reader then holds.
func TestABaseThatDropsALapsedReaderAfterAFoldShrinksItsRepo(t *testing.T) {
	net, repoId, formedAt, formedTime, honest := testConfigLapsedRuleNet(t, true)
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(honest, entry); err != nil {
		t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the writer names %x", header.GetShrunkRepoIds())
	}
	signedHeader, rowsBytes, timeMs := net.baseParts(honest)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api refused the writer's list: %v", err)
	}
	based := net.push(honest)
	if !based.Accepted() {
		t.Fatal(based.Refusal)
	}
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != based.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the base at %d", i, shrunk, based.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the base", state, repoId, formedAt, formedTime, now)
	}
	net.everyReaderAgrees()
}

// With no reader holding t_s, a repo whose holders do not change with time shrinks at no entry that drops none of
// them, and at the removal of a current holder as before.
func TestARepoWithNoLapseFoldedIntoABaseShrinksAsBefore(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("steady", 0)
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	other := net.admitMemberDevice("other")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: other.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != 0 {
		t.Fatalf("entries that drop no holder shrank the repo at %d", shrunk)
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	for i, log := range net.everyReaderAndApi() {
		if shrunk := log.State().ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the revoke at %d", i, shrunk, revoked.Pin.GetVersion())
		}
	}
	net.everyReaderAgrees()
}

// The closed reading's cost until rows carry t_s: a repo whose lapsed reader stays in the rows, its making folded by a
// base after the lapse, shrinks at the first entry after the base that touches the rows though it drops none of the
// repo's holders, and at no later one, since that entry's time is its t_s, at every reader alike.
func TestARepoHoldingALapsedReaderShrinksOnceAfterABase(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, _ := net.repoWithReader("lingering", expires)
	net.tickAt(expires + 60*1000)
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != 0 {
		t.Fatalf("the base shrank the repo at %d", shrunk)
	}
	first := net.n + 1
	net.admitMemberDevice("unrelated")
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != first {
		t.Errorf("holders_shrunk_at %d, the first entry after the base at %d", shrunk, first)
	}
	net.admitMemberDevice("later")
	for i, log := range net.everyReaderAndApi() {
		if shrunk := log.State().ShrunkAt(repoId); shrunk != first {
			t.Errorf("reader %d: holders_shrunk_at %d, the first entry after the base at %d", i, shrunk, first)
		}
	}
	net.everyReaderAgrees()
}

// StateAt's rebuilt states, kept every 4 positions here, hold the t_s each state the log published held: repos made,
// shrunk and folded across a base.
func TestStateAtRebuildsTheShrinkTimes(t *testing.T) {
	net := newTestConfigNetEvery(t, 4)
	expires := net.timeMs + 60*60*1000
	repoId, reader := net.repoWithReader("a", expires)
	steadyId, steady := net.repoWithReader("b", 0)
	previousBase := net.n + 1
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	net.tickAt(expires + 60*1000)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	net.createRepo("c")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: steadyId.Bytes(), Subject: steady.sidecarId.Bytes()})
	net.admitMemberDevice("d")
	if len(net.log.State().shrinkTimes) == 0 {
		t.Fatal("the tip holds no t_s")
	}
	for k := previousBase; k <= net.n; k += 1 {
		testConfigStateAtEqual(t, net, k)
	}
}
