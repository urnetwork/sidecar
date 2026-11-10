// TEAM-M4-01 on the test network: a member's page Workers with their admission positions, what config_admissions
// counts, and §7.10's cleanup list from 90% of the cap, the same at every kind of reader at one pin and never judging a
// Worker by its age; then the ordinary rules a stale or cleanup revocation of a page Worker passes (D-TEAM-29): by the
// member's consented device or an admin's, never another member's or a page Worker's, under the presence row with the
// admission it rides beside, and for an AdminSet member's Worker at k = 2 only by a proposal of its own, which expires
// short of k and is proposed again beside the next admission. FS-97's schedule on CORE-M4-02's act is
// sidecartest/fault/fs97_test.go's.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A page Worker's capability bits (§18.8).
const testConfigReadOnly = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)

// Admits a page Worker of member, signed by signer, failing the test unless it takes effect; the Worker and its
// admission's position.
func (self *testConfigNet) admitWorker(signer testConfigDevice, label string, memberId Id) (testConfigDevice, uint64) {
	self.t.Helper()
	worker := self.device(label, memberId)
	verdict := self.mustPost(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(worker, nil, false, 0, testConfigReadOnly))
	return worker, verdict.Pin.GetVersion()
}

// Admits a page Worker of an AdminSet member at k = 2: the proposer proposes and the cosigner completes it; the Worker
// and the completing cosign's position, where the admission took effect.
func (self *testConfigTeam) admitWorkerByProposal(proposer testConfigDevice, cosigner testConfigDevice, label string) (testConfigDevice, uint64) {
	self.t.Helper()
	worker := self.device(label, proposer.memberId)
	proposal, proposalId := self.propose(proposer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(worker, nil, false, 0, testConfigReadOnly))
	if !proposal.Accepted() || proposal.CompletedProposalId != nil {
		self.t.Fatalf("the Worker's admission proposal: %v", proposal.Refusal)
	}
	completed := self.cosign(cosigner, proposalId)
	if !completed.Accepted() || !bytes.Equal(completed.CompletedProposalId, proposalId) {
		self.t.Fatalf("the Worker's admission cosign: %v", completed.Refusal)
	}
	return worker, completed.Pin.GetVersion()
}

// A page Worker as PageWorkers answers it.
func testConfigPageWorker(worker testConfigDevice, admittedAt uint64) ConfigPageWorker {
	return ConfigPageWorker{SidecarId: worker.sidecarId, AdmittedAt: admittedAt}
}

// Whether two cleanup lists are the same list.
func testConfigCleanupListsEqual(a []ConfigCleanupMember, b []ConfigCleanupMember) bool {
	return slices.EqualFunc(a, b, func(x ConfigCleanupMember, y ConfigCleanupMember) bool {
		return x.MemberId == y.MemberId && slices.Equal(x.Workers, y.Workers)
	})
}

// A member's page Workers are its read_only member devices the log holds admitted, oldest admission first: not its
// other devices, not an ephemeral read_only device, not another member's Workers; a parked one still, since a park is
// no removal; a revoked one no more, and none once the member is removed.
func TestPageWorkersAreAMembersReadOnlyDevicesOldestFirst(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	other, otherLaptop := net.consentedMember("n")
	first, firstAt := net.admitWorker(laptop, "m worker 1", member)
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	otherWorker, otherAt := net.admitWorker(otherLaptop, "n worker", other)
	burner := net.device("m quick burner", member)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(burner, nil, true, net.timeMs+testConfigHourMs, testConfigReadOnly))
	second, secondAt := net.admitWorker(phone, "m worker 2", member)

	want := []ConfigPageWorker{testConfigPageWorker(first, firstAt), testConfigPageWorker(second, secondAt)}
	if got := net.log.State().PageWorkers(member); !slices.Equal(got, want) {
		t.Fatalf("page Workers %v, want %v", got, want)
	}
	if got := net.log.State().PageWorkers(other); !slices.Equal(got, []ConfigPageWorker{testConfigPageWorker(otherWorker, otherAt)}) {
		t.Errorf("the other member's page Workers %v", got)
	}

	// a compromise revocation of the phone from the second Worker's admission parks that Worker, which still holds its
	// admission and stays listed and counted
	countBefore := net.log.State().AdmissionCount()
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, secondAt))
	state := net.log.State()
	if !state.Parked(second.sidecarId) {
		t.Fatal("the second Worker is not parked")
	}
	if got := state.PageWorkers(member); !slices.Equal(got, want) {
		t.Errorf("with the second Worker parked: %v", got)
	}
	if count := state.AdmissionCount(); count != countBefore-1 {
		t.Errorf("count %d after revoking the phone, from %d", count, countBefore)
	}

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(first, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if got := net.log.State().PageWorkers(member); !slices.Equal(got, want[1:]) {
		t.Errorf("after the first Worker's revocation: %v", got)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	if got := net.log.State().PageWorkers(member); len(got) != 0 {
		t.Errorf("a removed member's page Workers: %v", got)
	}
	if got := net.log.State().PageWorkers(testConfigId("nobody")); len(got) != 0 {
		t.Errorf("no member's page Workers: %v", got)
	}
	net.everyReaderAgrees()
}

// What config_admissions bounds: the genesis device, member devices, page Workers and agents alike; a revocation frees
// one, and a tagged or ephemeral admission counts until its own not_after, by the state's time for every device at one
// pin and by api's own time at its tip.
func TestAdmissionCountCountsMemberDevicesAndAgentsAlike(t *testing.T) {
	net := newTestConfigNet(t)
	if count := net.log.State().AdmissionCount(); count != 1 {
		t.Fatalf("base 1 counts %d", count)
	}
	member, laptop := net.consentedMember("m")
	tagId := testConfigId("tag ci")
	net.withTagOwner(tagId, member)
	worker, _ := net.admitWorker(laptop, "m worker", member)
	agentNotAfter := net.timeMs + 2*testConfigHourMs
	agent := net.device("ci agent", Id{})
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, agentNotAfter, 0))
	burnerNotAfter := net.timeMs + 4*testConfigHourMs
	burner := net.device("m burner", member)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(burner, nil, true, burnerNotAfter, 0))

	state := net.log.State()
	if count := state.AdmissionCount(); count != 5 {
		t.Errorf("count %d, want the owner's device, the laptop, the Worker, the agent and the burner", count)
	}
	for _, c := range []struct {
		timeMs int64
		count  int
	}{
		{timeMs: agentNotAfter - 1, count: 5},
		{timeMs: agentNotAfter, count: 4},
		{timeMs: burnerNotAfter, count: 3},
	} {
		if count := state.AdmissionCountAt(c.timeMs); count != c.count {
			t.Errorf("at %d: %d, want %d", c.timeMs, count, c.count)
		}
	}

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(worker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if count := net.log.State().AdmissionCount(); count != 4 {
		t.Errorf("count %d after the Worker's revocation", count)
	}
	// the log's own time passing the agent's not_after: from that entry on, every reader counts it out
	net.wait(3 * testConfigHourMs)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a later member"))
	if count := net.log.State().AdmissionCount(); count != 3 {
		t.Errorf("count %d once the agent's not_after passed", count)
	}
	net.everyReaderAgrees()
	for i, reader := range net.everyReader() {
		if count := reader.State().AdmissionCount(); count != 3 {
			t.Errorf("reader %d counts %d", i, count)
		}
	}
}

// §7.10's cleanup row: below 90% of the cap nothing; from it, per member in id order, its page Workers but its newest,
// oldest first, a member with one Worker left out; an admin's or the member's revoke of what it lists frees their
// admissions by the ordinary rules, and once the count falls below 90% the list is gone.
func TestCleanupListFromNinetyPercentOfTheCap(t *testing.T) {
	net := newTestConfigNet(t)
	memberM, laptopM := net.consentedMember("m")
	memberN, laptopN := net.consentedMember("n")
	m1, m1At := net.admitWorker(laptopM, "m worker 1", memberM)
	n1, n1At := net.admitWorker(laptopN, "n worker 1", memberN)
	m2, m2At := net.admitWorker(laptopM, "m worker 2", memberM)
	net.admitWorker(laptopN, "n worker 2", memberN)
	net.admitWorker(laptopM, "m worker 3", memberM)
	net.admitWorker(net.owner, "owner worker", net.ownerMemberId)

	state := net.log.State()
	if count := state.AdmissionCount(); count != 9 {
		t.Fatalf("count %d", count)
	}
	for _, admissionCap := range []int{11, 0, -1} {
		if list := CleanupList(state, admissionCap); len(list) != 0 {
			t.Errorf("cap %d lists %v", admissionCap, list)
		}
	}
	want := []ConfigCleanupMember{
		{MemberId: memberM, Workers: []ConfigPageWorker{testConfigPageWorker(m1, m1At), testConfigPageWorker(m2, m2At)}},
		{MemberId: memberN, Workers: []ConfigPageWorker{testConfigPageWorker(n1, n1At)}},
	}
	slices.SortFunc(want, func(a ConfigCleanupMember, b ConfigCleanupMember) int { return a.MemberId.Cmp(b.MemberId) })
	for _, admissionCap := range []int{10, 9, 5} {
		if list := CleanupList(state, admissionCap); !testConfigCleanupListsEqual(list, want) {
			t.Errorf("cap %d lists %v, want %v", admissionCap, list, want)
		}
	}
	if list := CleanupList(nil, 10); len(list) != 0 {
		t.Errorf("no state lists %v", list)
	}

	// an admin's device revokes another member's listed Worker; below 90% nothing is listed, and there is room
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(n1, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if list := CleanupList(net.log.State(), 10); len(list) != 0 {
		t.Errorf("at 8 of 10: %v", list)
	}
	// back at 90% the list holds what is left, then the member's own revoke frees it again
	net.admitWorker(laptopN, "n worker 3", memberN)
	if list := CleanupList(net.log.State(), 10); len(list) != 2 || len(list[0].Workers)+len(list[1].Workers) != 3 {
		t.Errorf("at 9 of 10 again: %v", list)
	}
	net.mustPost(laptopM, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(m1, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	state = net.log.State()
	if list := CleanupList(state, 10); len(list) != 0 || 10 <= state.AdmissionCount() {
		t.Errorf("at %d of 10: %v", state.AdmissionCount(), list)
	}
	net.everyReaderAgrees()
}

// A pure function of the log: a full reader, another walking from the genesis, a new device restored at the newest base
// and a rows-only gate list the same Workers in the same order at one pin.
func TestCleanupListIsEqualOnEveryReaderAtOnePin(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	other, otherLaptop := net.consentedMember("n")
	workers := []testConfigDevice{}
	for i := range 4 {
		worker, _ := net.admitWorker(laptop, fmt.Sprintf("m worker %d", i), member)
		workers = append(workers, worker)
		net.admitWorker(otherLaptop, fmt.Sprintf("n worker %d", i), other)
	}
	net.fold(net.owner, net.n, 2)
	for i := 4; i < 7; i += 1 {
		worker, _ := net.admitWorker(laptop, fmt.Sprintf("m worker %d", i), member)
		workers = append(workers, worker)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(workers[1], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))

	state := net.log.State()
	admissionCap := state.AdmissionCount()
	want := CleanupList(state, admissionCap)
	if len(want) != 2 {
		t.Fatalf("listed %v", want)
	}
	for _, listed := range want {
		if wantCount := map[Id]int{member: 5, other: 3}[listed.MemberId]; len(listed.Workers) != wantCount {
			t.Errorf("member %s: %d listed, want %d", listed.MemberId, len(listed.Workers), wantCount)
		}
	}
	for i, reader := range net.everyReader() {
		readerState := reader.State()
		if !bytes.Equal(readerState.Pin().GetChain(), state.Pin().GetChain()) {
			t.Fatalf("reader %d stands at %v", i, readerState.Pin())
		}
		if got := CleanupList(readerState, admissionCap); !testConfigCleanupListsEqual(got, want) {
			t.Errorf("reader %d lists %v, want %v", i, got, want)
		}
		if got := readerState.PageWorkers(member); !slices.Equal(got, state.PageWorkers(member)) {
			t.Errorf("reader %d: page Workers %v", i, got)
		}
		if count := readerState.AdmissionCount(); count != admissionCap {
			t.Errorf("reader %d counts %d", i, count)
		}
	}
}

// The trap: the log cannot see a leaf's staleness, so nothing here judges a Worker by its age. A Worker admitted
// 400 days before another, and every Worker after another 400 days, stays listed in admission order.
func TestThePageWorkersAreNeverJudgedByAge(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	old, oldAt := net.admitWorker(laptop, "m worker old", member)
	net.wait(400 * 24 * testConfigHourMs)
	recent, recentAt := net.admitWorker(laptop, "m worker recent", member)
	newest, newestAt := net.admitWorker(laptop, "m worker newest", member)
	want := []ConfigPageWorker{testConfigPageWorker(old, oldAt), testConfigPageWorker(recent, recentAt), testConfigPageWorker(newest, newestAt)}
	admissionCap := net.log.State().AdmissionCount()
	before := CleanupList(net.log.State(), admissionCap)
	if len(before) != 1 || !slices.Equal(before[0].Workers, want[:2]) {
		t.Fatalf("listed %v", before)
	}

	net.wait(400 * 24 * testConfigHourMs)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a much later member"))
	state := net.log.State()
	if got := state.PageWorkers(member); !slices.Equal(got, want) {
		t.Errorf("page Workers %v after 800 days", got)
	}
	if after := CleanupList(state, admissionCap); !testConfigCleanupListsEqual(after, before) {
		t.Errorf("listed %v after 800 days, %v before", after, before)
	}
}

// D-TEAM-29's revocations pass the ordinary rules: the member's consented device, in its own admission act or at its
// OwnerConfirm, and an admin's device, in its admission act or from the cleanup list, revoke a page Worker as removed;
// another member's device does not, nor a page Worker, which signs only its own sign-out; and with self_admit off,
// when no member device admits, the member's own still revokes.
func TestAStaleRevocationOfAPageWorkerPassesTheOrdinaryRules(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	_, otherLaptop := net.consentedMember("n")
	w1, _ := net.admitWorker(laptop, "m worker 1", member)
	w2, _ := net.admitWorker(laptop, "m worker 2", member)
	w3, _ := net.admitWorker(laptop, "m worker 3", member)
	w4, _ := net.admitWorker(laptop, "m worker 4", member)
	removed := bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w1, removed))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w2, removed))
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w3, removed), ErrConfigAuthority)
	net.mustRefuse(w4, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w3, removed), ErrConfigReadOnly)

	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF}
	net.fold(net.owner, net.n, 2)
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m worker 5", member), nil, false, 0, testConfigReadOnly), ErrConfigAuthority)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w3, removed))
	net.mustPost(w4, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(w4, removed))
	if got := net.log.State().PageWorkers(member); len(got) != 0 {
		t.Errorf("page Workers left: %v", got)
	}
	net.everyReaderAgrees()
}

// §7.9's presence row covers a stale revocation as it covers the admission it rides beside: with a live presence key
// the member's device's revocation is refused alone, and one presence check over the act, the revocation first, lands
// both, each verifying by its own path.
func TestAStaleRevocationRidesThePresenceRow(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	stale, _ := net.admitWorker(laptop, "m worker stale", member)
	key := newTestPresenceKey(t, "m laptop presence key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	net.registerPresenceKey(laptop, key)
	next := net.device("m worker next", member)
	revoke := net.sign(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(stale, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	admit := net.sign(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(next, nil, false, 0, testConfigReadOnly))

	if verdict := net.pushSigned(testConfigActStatement(t, revoke).signed); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
		t.Fatalf("the revocation without a countersignature: %v", verdict.Refusal)
	}
	for i, statement := range testConfigAct(t, key, laptop, revoke, admit) {
		if verdict := net.pushSigned(statement.signed); !verdict.Accepted() {
			t.Fatalf("statement %d of the act: %v", i, verdict.Refusal)
		}
	}
	state := net.log.State()
	if state.SidecarRow(stale.sidecarId).GetRevokedAt() == 0 {
		t.Error("the stale Worker is not revoked")
	}
	if got := state.PageWorkers(member); len(got) != 1 || got[0].SidecarId != next.sidecarId {
		t.Errorf("page Workers %v", got)
	}
	net.everyReaderAgrees()
}

// At k = 2 an AdminSet member's page Worker goes only by a proposal of its own: one signer is refused, the device
// admitting it counts as one and another admin's cosign completes it, either way round, and a page Worker never counts
// toward k.
func TestAnAdminSetMembersStaleWorkerGoesOnlyByItsOwnProposal(t *testing.T) {
	team := newTestConfigTeam(t)
	removed := bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED
	stale, staleAt := team.admitWorkerByProposal(team.adminB, team.owner, "b worker stale")
	other, otherAt := team.admitWorkerByProposal(team.adminB, team.owner, "b worker other")
	if got := team.log.State().PageWorkers(team.adminB.memberId); !slices.Equal(got, []ConfigPageWorker{testConfigPageWorker(stale, staleAt), testConfigPageWorker(other, otherAt)}) {
		t.Fatalf("page Workers %v", got)
	}

	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(stale, removed), ErrConfigAuthority)
	team.mustRefuse(team.adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(stale, removed), ErrConfigAuthority)
	proposal, proposalId := team.propose(team.adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(stale, removed))
	if !proposal.Accepted() || proposal.CompletedProposalId != nil {
		t.Fatalf("the proposal: %v", proposal.Refusal)
	}
	if team.log.State().SidecarRow(stale.sidecarId).GetRevokedAt() != 0 {
		t.Fatal("a proposal took effect alone")
	}
	if verdict := team.cosign(other, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigReadOnly) {
		t.Errorf("a page Worker's cosign: %v", verdict.Refusal)
	}
	completed := team.cosign(team.adminC, proposalId)
	if !completed.Accepted() || !bytes.Equal(completed.CompletedProposalId, proposalId) {
		t.Fatalf("the cosign: %v", completed.Refusal)
	}
	if revokedAt := team.log.State().SidecarRow(stale.sidecarId).GetRevokedAt(); revokedAt != completed.Pin.GetVersion() {
		t.Errorf("revoked at %d, completed at %d", revokedAt, completed.Pin.GetVersion())
	}

	// another admin's device proposes, and the member's own cosigns
	_, otherProposalId := team.propose(team.adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(other, removed))
	if verdict := team.cosign(team.adminB, otherProposalId); !verdict.Accepted() || !bytes.Equal(verdict.CompletedProposalId, otherProposalId) {
		t.Fatalf("the member's cosign: %v", verdict.Refusal)
	}
	if got := team.log.State().PageWorkers(team.adminB.memberId); len(got) != 0 {
		t.Errorf("page Workers left: %v", got)
	}
	team.everyReaderAgrees()
}

// A revocation proposal short of k expires at its not_after and takes no cosign after it; the member's next Worker
// admission proposes it again, a statement of its own beside the admission's proposal, and the cosigner's cosign of
// each completes both.
func TestAProposalShortOfKExpiresAndTheNextAdmissionProposesItAgain(t *testing.T) {
	team := newTestConfigTeam(t)
	removed := bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED
	stale, _ := team.admitWorkerByProposal(team.adminB, team.owner, "b worker stale")
	_, firstId := team.propose(team.adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(stale, removed))
	team.wait(2 * testConfigHourMs)
	if verdict := team.cosign(team.adminC, firstId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Fatalf("a cosign past the proposal's not_after: %v", verdict.Refusal)
	}
	if team.log.State().SidecarRow(stale.sidecarId).GetRevokedAt() != 0 {
		t.Fatal("an expired proposal took effect")
	}

	next := team.device("b worker next", team.adminB.memberId)
	_, admitId := team.propose(team.adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(next, nil, false, 0, testConfigReadOnly))
	again, againId := team.propose(team.adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(stale, removed))
	if !again.Accepted() || bytes.Equal(againId, firstId) {
		t.Fatalf("the revocation proposed again: %v", again.Refusal)
	}
	for _, proposalId := range [][]byte{admitId, againId} {
		if verdict := team.cosign(team.adminC, proposalId); !verdict.Accepted() || !bytes.Equal(verdict.CompletedProposalId, proposalId) {
			t.Fatalf("the cosign: %v", verdict.Refusal)
		}
	}
	if got := team.log.State().PageWorkers(team.adminB.memberId); len(got) != 1 || got[0].SidecarId != next.sidecarId {
		t.Errorf("page Workers %v", got)
	}
	team.everyReaderAgrees()
}

// The authority a ConfigClient gives answers the page Workers, the count and the cleanup list at its newest verified
// state, an ephemeral admission past its not_after counted out as the state counts it.
func TestConfigAuthorityAnswersThePageWorkersAtTheNewestState(t *testing.T) {
	world := newTestConfigClientWorld(t)
	client := world.client(nil)
	authority := client.Authority()
	net := world.net
	if len(authority.PageWorkers(net.ownerMemberId)) != 0 || len(authority.CleanupList(1)) != 0 {
		t.Error("an authority that read nothing answers page Workers")
	}

	member, laptop := net.consentedMember("m")
	net.admitWorker(laptop, "m worker 1", member)
	burner := net.device("m burner", member)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(burner, nil, true, net.timeMs+testConfigHourMs, 0))
	net.admitWorker(laptop, "m worker 2", member)
	net.wait(2 * testConfigHourMs)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a later member"))
	world.publish()
	state := world.caughtUp(client)

	if got := authority.PageWorkers(member); len(got) != 2 || !slices.Equal(got, state.PageWorkers(member)) {
		t.Errorf("page Workers %v", got)
	}
	if count := authority.AdmissionCount(); count != state.AdmissionCount() || count != 4 {
		t.Errorf("count %d, the state's %d", count, state.AdmissionCount())
	}
	if got := authority.CleanupList(4); len(got) != 1 || !testConfigCleanupListsEqual(got, CleanupList(state, 4)) {
		t.Errorf("cleanup list %v", got)
	}
}
