// QD-883's second comparison of §7.9's shrink row on the test network: an entry also shrinks repo R when it drops a
// holder of KeyHolders(R, n-1, t_s) from KeyHolders(R, n, t_s), t_s the time of the entry at R's holders_shrunk_at (R's
// making while that is 0), so the removal of a holder whose access had already ended by time keeps §10.6's gate shut to
// the generation the expiry closed and has GkmRemoveDue ask the rotation: by a RepoRevoke of a lapsed grant, a
// SidecarRevoke of an agent past its not_after, and a base whose policy edit drops a lapsed reader, which api and the
// writer name alike. A removal of a holder still current at t_s shrinks as before, and one whose access ended before
// R's last shrink shrinks nothing more. Rows carry t_s as AclRepo.holders_shrunk_time_ms (QD-1015), so where bases
// moved the retention point past R's making or last shrink, every reader still reads one t_s from R's row: a long-running
// reader, one from the genesis, a new device and a cold gate that start at the newest base, api's warm gate and
// StateAt's rebuilt states. There the second comparison shrinks R on such a removal at every reader alike, a base's
// shrunk_repo_ids agree at a present reader and one that starts at the base before, and a repo that holds a lapsed
// holder shrinks at no entry that drops none of its holders, however many bases pass.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
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

// The time of the entry that made the repo, ms since the epoch: the first state the net's log published that holds its
// row.
func (self *testConfigNet) madeTimeMs(repoId Id) int64 {
	self.t.Helper()
	for n := uint64(1); n <= self.n; n += 1 {
		if state := self.statesAt[n]; state != nil && state.Repo(repoId) != nil {
			return state.TimeMs()
		}
	}
	self.t.Fatalf("no state the net published holds repo %s", repoId)
	return 0
}

// Fails unless the repo's holders_shrunk_at is shrunkAt and its t_s timeMs at the state, both as its row carries them.
func testConfigExpectShrinkTime(t testing.TB, label string, state *ConfigState, repoId Id, shrunkAt uint64, timeMs int64) {
	t.Helper()
	if shrunk := state.ShrunkAt(repoId); shrunk != shrunkAt {
		t.Errorf("%s: holders_shrunk_at %d, want %d", label, shrunk, shrunkAt)
	}
	if shrinkTime, held := state.shrinkTime(repoId); !held || shrinkTime.UnixMilli() != timeMs {
		t.Errorf("%s: t_s %d (held %t), want %d", label, shrinkTime.UnixMilli(), held, timeMs)
	}
	if rowTimeMs := state.Repo(repoId).GetHoldersShrunkTimeMs(); rowTimeMs != timeMs {
		t.Errorf("%s: the row's holders_shrunk_time_ms %d, want %d", label, rowTimeMs, timeMs)
	}
}

// Pushes count bases in a row, each folding through the tip under the same config version, so after two the retention
// point, min(the previous base, folded_through + 1), passes every entry before the first of them.
func (self *testConfigNet) foldTimes(count int) {
	self.t.Helper()
	for range count {
		if verdict := self.fold(self.owner, self.n, self.log.State().Base().GetConfigVersion()); !verdict.Accepted() {
			self.t.Fatalf("a base folding through %d: %v", self.n, verdict.Refusal)
		}
	}
}

// Fails unless a new device and a cold gate started at the newest base hold no state at pin, which lies before what
// they retain.
func (self *testConfigNet) expectStartedReadersPast(label string, pin *bridge.AuthPin) {
	self.t.Helper()
	readers := self.everyReader()
	for i, reader := range readers[1:] {
		if _, err := reader.State().StateAt(pin); !errors.Is(err, ErrConfigPinNotRetained) {
			self.t.Fatalf("%s: started reader %d reaches %d: %v", label, i, pin.GetVersion(), err)
		}
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

// A network whose policy lets a reader read a repo by a rule that has since expired.
type testConfigLapsedRule struct {
	net    *testConfigNet
	repoId Id
	// the revoke of another reader, the repo's last shrink, whose time is its t_s
	shrink ConfigVerdict
	// the generation formed before the rule expired
	formedAt   *bridge.AuthPin
	formedTime time.Time
	// the honest base at the tip whose policy edit drops the expired rule, unsequenced
	honest []byte
}

// A testConfigLapsedRule: the repo shrank after the policy's base, at the revoke of another reader, then foldCount
// bases fold that shrink before the rule expires, so from two on the retention point has passed it and a new device or
// a cold gate holds no entry of it, only the repo's row.
func testConfigLapsedRuleNet(t *testing.T, foldCount int) *testConfigLapsedRule {
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
	net.foldTimes(foldCount)
	if 2 <= foldCount {
		net.expectStartedReadersPast("the folded shrink", shrink.Pin)
	}
	for i, log := range net.everyReaderAndApi() {
		testConfigExpectShrinkTime(t, fmt.Sprintf("reader %d", i), log.State(), repoId, shrink.Pin.GetVersion(), net.statesAt[shrink.Pin.GetVersion()].TimeMs())
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
	return &testConfigLapsedRule{
		net: net, repoId: repoId, shrink: shrink, formedAt: formedAt, formedTime: formedTime,
		honest: net.policyBase(net.groupReadRows()),
	}
}

// The header a base entry carries.
func (self *testConfigNet) baseHeader(entryBytes []byte) *bridge.ProjectionHeader {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return header
}

// QD-746's base is the same case when its policy edit drops a reader whose rule had already expired: the base names the
// repo, which a present reader holds it to, and every kind of reader, api's among them, holds its position as
// holders_shrunk_at, so the gate stays shut to the generation the expiry closed and the rotation is REMOVE. api and the
// writer compute the same list: api takes the writer's and answers ErrConfigTipMoved to the list the entry's time alone
// gives, which names nothing.
func TestABaseThatDropsALapsedReaderShrinksItsRepo(t *testing.T) {
	lapsed := testConfigLapsedRuleNet(t, 0)
	net, repoId := lapsed.net, lapsed.repoId
	signedHeader, rowsBytes, timeMs := net.baseParts(lapsed.honest)
	if header := net.baseHeader(lapsed.honest); !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the writer names %x", header.GetShrunkRepoIds())
	}
	api := net.apiAtTip()
	if err := api.CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api refused the writer's list: %v", err)
	}
	unnamed, _, _ := net.baseParts(net.editedBase(lapsed.honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = nil }))
	if err := api.CheckBase(unnamed, rowsBytes, timeMs); !errors.Is(err, ErrConfigTipMoved) {
		t.Errorf("api took the list the base's own time gives: %v", err)
	}
	if _, err := net.newReader().Apply(net.editedBase(lapsed.honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = nil }), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a present reader took a base that names nothing: %v", err)
	}

	based := net.push(lapsed.honest)
	if !based.Accepted() {
		t.Fatal(based.Refusal)
	}
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != based.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the base at %d", i, shrunk, based.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the base", state, repoId, lapsed.formedAt, lapsed.formedTime, now)
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

// QD-1015: a repo made, and another last shrunk, before the retention point, which two bases moved past both, give
// every reader the same t_s from their rows: the net's long-running reader, one from the genesis, a new device and a
// cold gate started at the newest base, which hold no entry of the making or the shrink, api's warm gate, and StateAt's
// rebuilt states. Past the grants' expiry, an admission drops none of either repo's holders and shrinks neither; the
// revokes of the lapsed readers then shrink each at its position at every reader alike, the gate stays shut to the
// generations the expiry closed, and each row's t_s moves to its revoke's time.
func TestEveryReaderReadsAShrinkTimeOlderThanTheRetentionPoint(t *testing.T) {
	net := newTestConfigNetEvery(t, 4)
	expires := net.timeMs + 60*60*1000
	madeId, madeReader := net.repoWithReader("made", expires)
	shrunkId, shrunkReader := net.repoWithReader("shrunk", expires)
	other := net.admitMemberDevice("other")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: shrunkId.Bytes(), Subject: other.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	shrink := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: net.header(), RepoId: shrunkId.Bytes(), Subject: other.sidecarId.Bytes(),
	})
	madeTimeMs, shrinkTimeMs := net.madeTimeMs(madeId), net.statesAt[shrink.Pin.GetVersion()].TimeMs()
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)

	previousBase := net.n + 1
	net.foldTimes(2)
	if point := net.log.State().RetentionPoint(); point <= shrink.Pin.GetVersion() {
		t.Fatalf("the retention point %d has not passed the shrink at %d", point, shrink.Pin.GetVersion())
	}
	net.expectStartedReadersPast("the bases", shrink.Pin)
	for i, log := range net.everyReaderAndApi() {
		label := fmt.Sprintf("reader %d after the bases", i)
		testConfigExpectShrinkTime(t, label, log.State(), madeId, 0, madeTimeMs)
		testConfigExpectShrinkTime(t, label, log.State(), shrunkId, shrink.Pin.GetVersion(), shrinkTimeMs)
	}
	net.everyReaderAgrees()

	net.tickAt(expires + 60*1000)
	net.admitMemberDevice("bystander")
	for i, log := range net.everyReaderAndApi() {
		label := fmt.Sprintf("reader %d after the admission", i)
		testConfigExpectShrinkTime(t, label, log.State(), madeId, 0, madeTimeMs)
		testConfigExpectShrinkTime(t, label, log.State(), shrunkId, shrink.Pin.GetVersion(), shrinkTimeMs)
	}

	madeRevoke := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: net.header(), RepoId: madeId.Bytes(), Subject: madeReader.sidecarId.Bytes(),
	})
	shrunkRevoke := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: net.header(), RepoId: shrunkId.Bytes(), Subject: shrunkReader.sidecarId.Bytes(),
	})
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		label := fmt.Sprintf("reader %d after the revokes", i)
		state := log.State()
		testConfigExpectShrinkTime(t, label, state, madeId, madeRevoke.Pin.GetVersion(), net.statesAt[madeRevoke.Pin.GetVersion()].TimeMs())
		testConfigExpectShrinkTime(t, label, state, shrunkId, shrunkRevoke.Pin.GetVersion(), net.statesAt[shrunkRevoke.Pin.GetVersion()].TimeMs())
		testConfigExpectClosedGeneration(t, label+", the made repo", state, madeId, formedAt, formedTime, now)
		testConfigExpectClosedGeneration(t, label+", the shrunk repo", state, shrunkId, formedAt, formedTime, now)
	}
	net.everyReaderAgrees()
	for k := previousBase; k <= net.n; k += 1 {
		testConfigStateAtEqual(t, net, k)
	}
}

// Where two bases moved the retention point past the repo's making, every reader still reads its t_s from the repo's
// row (QD-1015), and the revoke of a reader whose grant lapsed after the bases shrinks the repo at a long-running
// reader, a reader from the genesis, a new device and a cold gate that start at the newest base, and api, alike; the
// gate stays shut.
func TestARevokeOfALapsedReaderAfterABaseFoldedItKeepsTheGateShut(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, reader := net.repoWithReader("folded", expires)
	madeTimeMs := net.madeTimeMs(repoId)
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)
	net.foldTimes(2)
	for i, log := range net.everyReaderAndApi() {
		testConfigExpectShrinkTime(t, fmt.Sprintf("reader %d", i), log.State(), repoId, 0, madeTimeMs)
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

// The base case past the retention point: two bases folded the repo's last shrink before the rule expired, and the
// policy edit that drops the lapsed reader names the repo by the comparison at the t_s its row carries, which api and
// the writer compute alike, as every reader then holds.
func TestABaseThatDropsALapsedReaderAfterAFoldShrinksItsRepo(t *testing.T) {
	lapsed := testConfigLapsedRuleNet(t, 2)
	net, repoId := lapsed.net, lapsed.repoId
	if header := net.baseHeader(lapsed.honest); !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the writer names %x", header.GetShrunkRepoIds())
	}
	signedHeader, rowsBytes, timeMs := net.baseParts(lapsed.honest)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api refused the writer's list: %v", err)
	}
	based := net.push(lapsed.honest)
	if !based.Accepted() {
		t.Fatal(based.Refusal)
	}
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if shrunk := state.ShrunkAt(repoId); shrunk != based.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the base at %d", i, shrunk, based.Pin.GetVersion())
		}
		testConfigExpectClosedGeneration(t, "after the base", state, repoId, lapsed.formedAt, lapsed.formedTime, now)
	}
	net.everyReaderAgrees()
}

// A base's shrunk_repo_ids agree at a present reader and at one that starts at the base before it (QD-746, QD-1015):
// with the repo's last shrink past the retention point, a new device and a cold gate started at the newest base hold
// no entry of it, yet compute and check the list the writer, a present long-running reader, signs, naming the repo
// whose lapsed reader the policy edit drops, as api does; each applies the base with no fork, and a new device and a
// cold gate that start at the base itself take the list and hold its position as holders_shrunk_at. A list that names
// nothing forks each of them alike.
func TestABasesShrunkRepoIdsAgreeAtAPresentReaderAndOneThatStartsAtIt(t *testing.T) {
	lapsed := testConfigLapsedRuleNet(t, 2)
	net, repoId := lapsed.net, lapsed.repoId
	header := net.baseHeader(lapsed.honest)
	if !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the present reader names %x", header.GetShrunkRepoIds())
	}
	signedHeader, rowsBytes, timeMs := net.baseParts(lapsed.honest)
	unnamed := net.editedBase(lapsed.honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = nil })
	started := net.everyReader()[1:]
	for i, reader := range started {
		computed, err := reader.BaseShrunkRepoIds(proto.Clone(header).(*bridge.ProjectionHeader), rowsBytes, timeMs)
		if err != nil || !slices.EqualFunc(computed, header.GetShrunkRepoIds(), bytes.Equal) {
			t.Errorf("started reader %d computes %x, the present reader %x: %v", i, computed, header.GetShrunkRepoIds(), err)
		}
		if err := reader.CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
			t.Errorf("started reader %d refused the present reader's list: %v", i, err)
		}
	}
	for i, reader := range net.everyReader() {
		if _, err := reader.Apply(unnamed, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("reader %d took a base that names nothing: %v", i, err)
		}
	}
	for i, reader := range started {
		if verdict, err := reader.Apply(lapsed.honest, net.source); err != nil || !verdict.Accepted() {
			t.Fatalf("started reader %d applying the base: %v, %v", i, err, verdict.Refusal)
		}
	}

	based := net.push(lapsed.honest)
	if !based.Accepted() {
		t.Fatal(based.Refusal)
	}
	for i, reader := range append(started, net.everyReaderAndApi()...) {
		if shrunk := reader.State().ShrunkAt(repoId); shrunk != based.Pin.GetVersion() {
			t.Errorf("reader %d: holders_shrunk_at %d, the base at %d", i, shrunk, based.Pin.GetVersion())
		}
		testConfigStatesEqual(t, reader.State(), net.log.State())
	}
	net.everyReaderAgrees()
}

// A repo whose holders do not change with time, folded past the retention point, shrinks at no entry that drops none
// of them, and at the removal of a current holder as before.
func TestARepoWithNoLapseFoldedIntoABaseShrinksAsBefore(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("steady", 0)
	net.foldTimes(2)
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

// QD-1015: a repo holding a reader whose RepoGrant has expired and an agent past its not_after, both still in the
// rows, shrinks at no entry that drops none of its holders at the entry's time or at t_s, its making, which each base
// folds and its row carries, so it no longer shrinks again after each base: over three bases, each followed by an
// admission and a grant that touch the rows, holders_shrunk_at stays 0 at every reader alike, and a generation formed
// after the lapse passes the gate with no REMOVE due.
func TestARepoHoldingALapsedHolderShrinksNoMoreAfterABase(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, reader := net.repoWithReader("lingering", expires)
	madeTimeMs := net.madeTimeMs(repoId)
	agent := net.device("lingering agent", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{ci}, false, expires, 0))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: agent.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	holders, err := KeyHolders(net.log.State(), repoId, time.UnixMilli(net.timeMs))
	if err != nil || !holders.Contains(GkmHolderLeaf, reader.sidecarId.Bytes()) || !holders.Contains(GkmHolderAgent, agent.sidecarId.Bytes()) {
		t.Fatalf("the repo's holders %v: %v", holders, err)
	}
	net.tickAt(expires + 60*1000)
	formedAt, formedTime := net.log.Pin(), time.UnixMilli(net.timeMs)
	for i := range 3 {
		net.foldTimes(1)
		bystander := net.admitMemberDevice(fmt.Sprintf("bystander %d", i))
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: repoId.Bytes(), Subject: bystander.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
		for j, log := range net.everyReaderAndApi() {
			testConfigExpectShrinkTime(t, fmt.Sprintf("after base %d, reader %d", i, j), log.State(), repoId, 0, madeTimeMs)
		}
	}
	now := time.UnixMilli(net.timeMs)
	for i, log := range net.everyReaderAndApi() {
		state := log.State()
		if err := GkmGateCheck(state, repoId, formedAt, formedTime, now); err != nil {
			t.Errorf("reader %d: the generation formed after the lapse: %v", i, err)
		}
		if due, err := GkmRemoveDue(state, repoId, formedAt, formedTime, now); err != nil || due {
			t.Errorf("reader %d: a rotation from the generation formed after the lapse is REMOVE %v: %v", i, due, err)
		}
	}
	net.everyReaderAgrees()
}

// StateAt's rebuilt states, kept every 4 positions here, read the t_s each state the log published read, from rows
// that carry it: repos made, shrunk and folded across a base.
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
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	madeId := net.createRepo("c")
	steadyRevoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: steadyId.Bytes(), Subject: steady.sidecarId.Bytes()})
	net.admitMemberDevice("d")
	state := net.log.State()
	testConfigExpectShrinkTime(t, "the revoked repo", state, repoId, revoked.Pin.GetVersion(), net.statesAt[revoked.Pin.GetVersion()].TimeMs())
	testConfigExpectShrinkTime(t, "the made repo", state, madeId, 0, net.madeTimeMs(madeId))
	testConfigExpectShrinkTime(t, "the steady repo", state, steadyId, steadyRevoked.Pin.GetVersion(), net.statesAt[steadyRevoked.Pin.GetVersion()].TimeMs())
	for k := previousBase; k <= net.n; k += 1 {
		testConfigStateAtEqual(t, net, k)
	}
}
