// DESIGN-DETAILS 5.6's reader tests on the test network: a base carries its tail's verdicts, which a reader present at
// the tail compares with its own and a new device takes, so both reach one S(b); the fold rule and the tail cap; the
// replay ring carried in rows; a fold's BASE records and the chain recomputed through them; and re-application
// recomputing what effects derive on the rebuilt rows, an acl statement's from its body's verdict and those rows alone
// (QD-954): a Suspend past a moved tag owner, a stale Unsuspend, a k-of-n Suspend a cosign completes in the tail, and a
// GrantActivate whose requests rule a head deleted or whose check a reader could not pass.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A base's entry over rows, as makeBase makes it but carrying verdicts as given.
func (self *testConfigNet) makeBaseWithVerdicts(signer testConfigDevice, rows *bridge.ProjectionRows, foldedThrough uint64, configVersion uint64, threshold uint32, verdicts []byte) []byte {
	self.t.Helper()
	entryBytes := self.makeBase(signer, rows, foldedThrough, configVersion, threshold)
	entry := &bridge.AuthEntry{}
	signed := &bridge.Signed{}
	header := &bridge.ProjectionHeader{}
	if proto.Unmarshal(entryBytes, entry) != nil || proto.Unmarshal(entry.GetBody(), signed) != nil || proto.Unmarshal(signed.GetBody(), header) != nil {
		self.t.Fatal("a base that does not parse")
	}
	header.TailVerdicts = verdicts
	return self.makeEntry(bridge.AuthEntryKindBase, self.sign(signer, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
}

// A base entry's Signed header bytes, its rows and its time, as api's CheckBase takes them: api checks at the time it
// stamps.
func (self *testConfigNet) baseParts(entryBytes []byte) ([]byte, []byte, int64) {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	rows, err := self.source.Rows(self.networkId, header.GetRowsSha256())
	if err != nil {
		self.t.Fatal(err)
	}
	return entry.GetBody(), rows, entry.GetTimeMs()
}

// A rows-only gate at the tip, as api sequences by: every entry so far applied.
func (self *testConfigNet) apiAtTip() *ConfigLog {
	self.t.Helper()
	gate, err := NewConfigLogRowsOnly(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := gate.ApplyRun(self.entries, self.rowsOnlySource()); err != nil {
		self.t.Fatal(err)
	}
	return gate
}

// The verdicts' codec: two bits an entry, little-endian within a byte, padding 0, exactly ceil(2n/8) bytes, no 3.
func TestConfigTailVerdictsCodec(t *testing.T) {
	verdicts := []uint8{1, 0, 2, 1, 1}
	data := configEncodeTailVerdicts(verdicts)
	if !bytes.Equal(data, []byte{0x61, 0x01}) {
		t.Fatalf("encoded %x", data)
	}
	decoded, err := configDecodeTailVerdicts(data, uint64(len(verdicts)))
	if err != nil || !bytes.Equal(decoded, verdicts) {
		t.Fatalf("decoded %v, %v", decoded, err)
	}
	if data := configEncodeTailVerdicts(nil); len(data) != 0 {
		t.Errorf("an empty tail: %x", data)
	}
	refusals := []struct {
		name  string
		data  []byte
		count uint64
	}{
		{name: "short", data: []byte{0x61}, count: 5},
		{name: "long", data: []byte{0x61, 0x01, 0x00}, count: 5},
		{name: "a 3", data: []byte{0x63, 0x01}, count: 5},
		{name: "a padding bit", data: []byte{0x61, 0x05}, count: 5},
		{name: "bytes for no entry", data: []byte{0x00}, count: 0},
	}
	for _, refusal := range refusals {
		if _, err := configDecodeTailVerdicts(refusal.data, refusal.count); err == nil {
			t.Errorf("%s decoded", refusal.name)
		}
	}
}

// DESIGN-DETAILS 5.6's TestANewDeviceTakesItsBasesTailVerdicts, 5.1's first run: the owner's device admits an agent
// under a tag its member owns, then a base keeping the fold moves the tag's ownership to another member in its head.
// A new device at that base would refuse the admission judged on its rows; it takes the base's verdict instead and
// holds the long-running reader's S(b), as does a rows-only gate.
func TestANewDeviceTakesItsBasesTailVerdictsUnderAMovedTagOwner(t *testing.T) {
	net := newTestConfigNet(t)
	tagId := testConfigId("tag t")
	net.withTagOwner(tagId, net.ownerMemberId)
	previousBase := net.log.State().Base()
	agent := net.device("agent d", Id{})
	admitted := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, true, net.timeMs+60*60*1000, 0))

	// the next head moves t to another member; the fold stays where the previous base left it
	other := testConfigId("member m3")
	rows := proto.Clone(net.log.baseRowsOf(t, previousBase)).(*bridge.ProjectionRows)
	aclRows := &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), aclRows); err != nil {
		t.Fatal(err)
	}
	for _, atom := range aclRows.GetAtoms() {
		if bytes.Equal(atom.GetAtom(), tagId.Bytes()) {
			atom.TagOwnerMemberIds = [][]byte{other.Bytes()}
		}
	}
	rows.Acl = testConfigMarshal(t, aclRows)
	if verdict := net.pushBase(net.owner, rows, previousBase.GetFoldedThrough(), previousBase.GetConfigVersion()+1, 0); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if net.log.State().SidecarRow(agent.sidecarId) == nil {
		t.Fatal("the long-running reader lost the admission")
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
	if err != nil {
		t.Fatal(err)
	}
	if row := restored.State().SidecarRow(agent.sidecarId); row == nil || row.GetAdmittedAt() != admitted.Pin.GetVersion() {
		t.Fatalf("the new device's admission: %v", row)
	}
	if kept := restored.keptEntry(admitted.Pin.GetVersion()); kept == nil || !kept.verdictHeld || !kept.verdict.Accepted() {
		t.Error("the new device holds no verdict from the base's bits")
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())
	net.everyReaderAgrees()
}

// 5.1's second run: a statement whose at lies before the first position a new device holds, accepted at its own
// position; a base folding below it, then a second keeping that fold. The new device at the second base holds entries
// from the statement's position on, and would refuse its at; it takes the verdict.
func TestANewDeviceTakesItsBasesTailVerdictsBelowItsFirstHeldPosition(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("member early")
	early := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{Header: net.header(), MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
	net.fold(net.owner, 1, 2)
	net.fold(net.owner, 1, 3)
	retained := net.log.Retained()
	first := &bridge.AuthEntry{}
	if err := proto.Unmarshal(retained.Entries[0], first); err != nil {
		t.Fatal(err)
	}
	if first.GetN() != early.Pin.GetVersion() {
		t.Fatalf("the new device holds from %d, the statement is at %d", first.GetN(), early.Pin.GetVersion())
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	if restored.State().Member(member) == nil {
		t.Fatal("the new device refused a statement its base carried as taking effect")
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())
	net.everyReaderAgrees()
}

// A base's bits that disagree with a present reader's verdicts fork it and are 403 at api: a flipped bit, a 2 on a
// SidecarAdmit, a 3, a short or a long bitmap, and a 1 at a BASE.
func TestABaseWhoseBitsDisagreeForks(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	second := net.device("m second", member)
	foldedThrough := net.n
	net.admitDevice(first, second, 0)                                                            // 1
	net.post(second, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("refused")) // 0
	net.fold(net.owner, foldedThrough, 2)                                                        // a BASE, 0
	_, proposalId := net.propose(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("by proposal"))
	if verdict := net.verdicts[net.n]; !verdict.Completed() || !bytes.Equal(verdict.CompletedProposalId, proposalId) {
		t.Fatalf("the proposal at k = 1: %v", verdict.Refusal)
	}
	rows := net.statesAt[foldedThrough].Rows()
	honest := net.tailVerdicts(foldedThrough)
	if !bytes.Equal(honest, []byte{0x81}) {
		t.Fatalf("honest verdicts %x", honest)
	}
	cases := []struct {
		name     string
		verdicts []byte
	}{
		{name: "a flipped bit", verdicts: []byte{0x85}},
		{name: "a 2 on a SidecarAdmit", verdicts: []byte{0x82}},
		{name: "a 3", verdicts: []byte{0x83}},
		{name: "short", verdicts: nil},
		{name: "long", verdicts: []byte{0x81, 0x00}},
		{name: "a 1 at a BASE", verdicts: []byte{0x91}},
		{name: "a completion carried as a 1", verdicts: []byte{0x41}},
	}
	api := net.apiAtTip()
	for _, c := range cases {
		entryBytes := net.makeBaseWithVerdicts(net.owner, rows, foldedThrough, 3, 0, c.verdicts)
		signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
		if err := api.CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigRule) {
			t.Errorf("%s: api's check %v", c.name, err)
		}
		reader := net.newReader()
		if _, err := reader.Apply(entryBytes, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("%s: a present reader %v", c.name, err)
		}
	}
	entryBytes := net.makeBaseWithVerdicts(net.owner, rows, foldedThrough, 3, 0, honest)
	signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
	if err := api.CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("the honest base at api: %v", err)
	}
	if verdict := net.push(entryBytes); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// DESIGN-DETAILS 5.6's TestATailOverTheCapIsRefusedAndForks: 4,097 entries unfolded are 403 at api and a fork at every
// reader; 4,096 land.
func TestATailOverTheCapIsRefusedAndForks(t *testing.T) {
	net := newTestConfigNet(t)
	for range configTailMax + 1 {
		if verdict := net.tick(&bridge.ApiTick{}); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
	}
	api := net.apiAtTip()
	rows := net.statesAt[1].Rows()
	over := net.makeBase(net.owner, rows, 1, 2, 0)
	signedHeader, rowsBytes, timeMs := net.baseParts(over)
	if err := api.CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigRule) {
		t.Errorf("api took a tail of %d: %v", configTailMax+1, err)
	}
	reader := net.newReader()
	if _, err := reader.Apply(over, net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a reader took a tail of %d: %v", configTailMax+1, err)
	}
	if verdict := net.fold(net.owner, 2, 2); !verdict.Accepted() {
		t.Fatalf("a tail of %d: %v", configTailMax, verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// DESIGN-DETAILS 5.6's TestAFoldedThroughBelowThePreviousBaseForks: a folded_through between the previous base's and
// that base's own position is 403 at api and a fork if appended; the previous base's fold, or one at or past that base,
// lands.
func TestAFoldedThroughBelowThePreviousBaseForks(t *testing.T) {
	net := newTestConfigNet(t)
	net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.admitMember(net.owner, testConfigId("b"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, 1, 2)
	previousBase := net.n
	net.admitMember(net.owner, testConfigId("c"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	between := net.makeBase(net.owner, net.statesAt[2].Rows(), 2, 3, 0)
	signedHeader, rowsBytes, timeMs := net.baseParts(between)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigRule) {
		t.Errorf("api took a fold between: %v", err)
	}
	if _, err := net.newReader().Apply(between, net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a reader took a fold between: %v", err)
	}
	if verdict := net.fold(net.owner, previousBase, 3); !verdict.Accepted() {
		t.Fatalf("a fold at the previous base: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// DESIGN-DETAILS 5.6's TestAVetoedProposalsReplayIsRefusedAfterAFold: a recovery proposal vetoed, a base folding both,
// then the proposal replayed verbatim: every reader refuses it, a new device from the ring its base's rows carry.
func TestAVetoedProposalsReplayIsRefusedAfterAFold(t *testing.T) {
	net := newTestConfigNet(t)
	key := testConfigRecovery(net.ownerMemberId, "owner")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	phone := net.device("owner phone", net.ownerMemberId)
	signedProposal := net.signByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
	proposed := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signedProposal))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: net.header(), ProposalId: proposed.StatementId[:]})
	net.fold(net.owner, net.n, 2)
	rows := net.log.State().Rows()
	if len(rows.GetRing()) == 0 || len(rows.GetProposals()) != 0 {
		t.Fatalf("the base's ring %d and proposals %d", len(rows.GetRing()), len(rows.GetProposals()))
	}

	replayed := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signedProposal))
	if replayed.Accepted() || !errors.Is(replayed.Refusal, ErrConfigReplay) {
		t.Fatalf("the replay: %v", replayed.Refusal)
	}
	net.everyReaderAgrees()
	for _, reader := range net.everyReader() {
		if len(reader.State().OpenProposalIds()) != 0 {
			t.Error("a reader holds the vetoed proposal open again")
		}
	}
}

// DESIGN-DETAILS 5.6's TestARefusedStatementResubmittedAfterItsReason: a self-admission refused with self_admit off,
// resubmitted verbatim once a head turns it on, takes effect at every reader alike, since the ring holds only what took
// effect.
func TestARefusedStatementResubmittedAfterItsReason(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF}
	net.fold(net.owner, net.n, 2)
	second := net.device("m second", member)
	signedAdmit := net.sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(second, nil, false, 0, 0))
	if refused := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signedAdmit)); refused.Accepted() || !errors.Is(refused.Refusal, ErrConfigAuthority) {
		t.Fatalf("with self_admit off: %v", refused.Refusal)
	}
	net.fold(net.owner, net.n, 3)
	if !net.log.State().SelfAdmit() {
		t.Fatal("self_admit is still off")
	}
	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signedAdmit)); !verdict.Accepted() {
		t.Fatalf("resubmitted: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// DESIGN-DETAILS 5.6's TestReapplyRecomputesRowSignersOnTheNewRows: a tail holding a tagged admission, its
// confirmation, a park's lift and a Suspend of a Delegation's agent, re-applied by a base, gives a long-running reader,
// a new device and a rows-only gate the same sponsor, confirm signer, live_since and key_dropped_at.
func TestReapplyRecomputesRowSignersOnTheNewRows(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	foldedThrough := net.n
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "ci delegation", []Id{ci}, 3, net.timeMs+30*day)
	agent := net.device("ci agent", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("ci tagged", Id{}), []Id{ci}, true, net.timeMs+day, 0))
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: agent.sidecarId.Bytes()})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: agent.sidecarId.Bytes(), SuspendId: aclTestSuspendId("agent")})
	before := net.log.State()
	if before.Delegation(delegation.id).GetKeyDroppedAt() == 0 {
		t.Fatal("the Suspend dropped no key")
	}
	net.fold(net.owner, foldedThrough, 3)
	after := net.log.State()
	if !proto.Equal(before.SidecarRow(agent.sidecarId), after.SidecarRow(agent.sidecarId)) ||
		!proto.Equal(before.Delegation(delegation.id), after.Delegation(delegation.id)) {
		t.Errorf("the re-applied rows differ from the reader's own:\n%v\n%v", before.SidecarRow(agent.sidecarId), after.SidecarRow(agent.sidecarId))
	}
	net.everyReaderAgrees()
}

// Whether readers of every kind hold the net's verdict at each position after the newest base, and its state, as
// everyReaderAgrees asks, each reader under the settings its kind takes here: another long-running reader, which judges
// every entry at its own position, under present, and a new device and a rows-only gate started at the newest base from
// what the net's reader retains, which judge nothing of its tail, under started.
func (self *testConfigNet) everyReaderAgreesUnder(present *ConfigLogSettings, started *ConfigLogSettings) {
	self.t.Helper()
	longRunning, err := NewConfigLog(present, self.signedGenesis)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, entryBytes := range self.entries {
		if _, err := longRunning.Apply(entryBytes, self.source); err != nil {
			self.t.Fatal(err)
		}
	}
	retained := self.log.Retained()
	restored, err := RestoreConfigLog(started, retained, self.source)
	if err != nil {
		self.t.Fatal(err)
	}
	gate, err := RestoreConfigLogRowsOnly(started, retained, self.rowsOnlySource(), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	from := self.log.State().Base().GetVersion() + 1
	for i, reader := range []*ConfigLog{longRunning, restored, gate} {
		for n := from; n <= self.n; n += 1 {
			want, got := self.log.keptEntry(n), reader.keptEntry(n)
			if want == nil || got == nil {
				self.t.Fatalf("reader %d: no verdict at %d", i, n)
			}
			if want.verdict.Accepted() != got.verdict.Accepted() ||
				testConfigRefusalClass(want.verdict.Refusal) != testConfigRefusalClass(got.verdict.Refusal) {
				self.t.Errorf("reader %d at %d: %v, the net's reader %v", i, n, got.verdict.Refusal, want.verdict.Refusal)
			}
		}
		testConfigStatesEqual(self.t, reader.State(), self.log.State())
	}
}

// The settings of a log that runs §16.6's spend check as the test's, as newAclTestGrantNet's does.
func testConfigSpendingLogSettings() *ConfigLogSettings {
	settings := testConfigLogSettings()
	settings.AclSpendCheck = &aclTestSpendCheck{}
	return settings
}

// QD-954's first case: a base's tail holds a tagged agent's admission and its sponsor's Suspend, class 1, and the base's
// head moves the tag to another member, so the admission's check refuses on the rebuilt rows. Neither is judged again:
// the agent stays admitted with its sponsor, and the Suspend folds from its body's verdict and the rebuilt rows to the
// row it had at its own position, its class, signer and position, at a long-running reader, a new device and a rows-only
// gate alike.
func TestReapplyFoldsASuspendAlikePastAMovedTagOwner(t *testing.T) {
	net := newTestConfigNet(t)
	tagId := testConfigId("tag t")
	tagOwner, ownerDevice := net.consentedMember("tag owner")
	net.withTagOwner(tagId, tagOwner)
	previousBase := net.log.State().Base()
	agent := net.device("agent", Id{})
	net.mustPost(ownerDevice, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+60*60*1000, 0))
	net.mustPost(ownerDevice, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: agent.sidecarId.Bytes(), SuspendId: aclTestSuspendId("sponsor")})
	before := net.log.State().aclRows.GetSuspensions()
	if len(before) != 1 || before[0].GetSignerClass() != AclSuspendClassOwner || !bytes.Equal(before[0].GetSigner(), ownerDevice.sidecarId.Bytes()) {
		t.Fatalf("the sponsor's Suspend at its own position: %+v", before)
	}

	// the next head moves t to another member; the fold stays where the previous base left it
	rows := proto.Clone(net.log.baseRowsOf(t, previousBase)).(*bridge.ProjectionRows)
	aclRows := &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), aclRows); err != nil {
		t.Fatal(err)
	}
	for _, atom := range aclRows.GetAtoms() {
		if bytes.Equal(atom.GetAtom(), tagId.Bytes()) {
			atom.TagOwnerMemberIds = [][]byte{testConfigId("member m3").Bytes()}
		}
	}
	rows.Acl = testConfigMarshal(t, aclRows)
	if verdict := net.pushBase(net.owner, rows, previousBase.GetFoldedThrough(), previousBase.GetConfigVersion()+1, 0); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if acl.CanApplyTag(ownerDevice.sidecarId, tagId) {
		t.Fatal("the head left the tag with its owner")
	}
	if sponsor, ok := state.Sponsor(agent.sidecarId); !ok || sponsor != tagOwner {
		t.Errorf("the re-applied admission's sponsor: %s, %v", sponsor, ok)
	}
	if after := state.aclRows.GetSuspensions(); len(after) != 1 || !proto.Equal(after[0], before[0]) {
		t.Errorf("the re-applied Suspend %+v, at its own position %+v", after, before)
	}
	if !state.Suspended(agent.sidecarId) {
		t.Error("the agent stands again past the base")
	}
	net.everyReaderAgrees()
}

// An Unsuspend with a stale id in a base's tail, a no-op at its own position, lifts nothing re-applied either: the
// Suspend of another id before it and the Suspend of its own id after it stay in force, at a long-running reader, a new
// device and a rows-only gate alike.
func TestReapplyOfAStaleUnsuspendLiftsNothingAlike(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	foldedThrough := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("other")})
	stale := net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("stale")})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("stale")})
	before := testConfigMarshal(t, &protocol.AclRows{Suspensions: net.log.State().aclRows.GetSuspensions()})
	if len(net.log.State().aclRows.GetSuspensions()) != 2 {
		t.Fatalf("the Suspends in force: %+v", net.log.State().aclRows.GetSuspensions())
	}

	net.fold(net.owner, foldedThrough, 2)
	state := net.log.State()
	if kept := net.log.keptEntry(stale.Pin.GetVersion()); kept == nil || !kept.verdict.Accepted() {
		t.Error("the stale Unsuspend's own verdict changed at the base")
	}
	if after := testConfigMarshal(t, &protocol.AclRows{Suspensions: state.aclRows.GetSuspensions()}); !bytes.Equal(after, before) {
		t.Errorf("the Suspends past the base: %+v", state.aclRows.GetSuspensions())
	}
	if !state.Suspended(phone.sidecarId) {
		t.Error("the stale Unsuspend lifted a Suspend")
	}
	net.everyReaderAgrees()
}

// A k-of-n Suspend whose cosign completes it in a base's tail reaches its fold through the cosign, which applies the
// proposed statement rather than re-applying it: its verdict is the body's still, so ReapplyStatement derives its
// class, k of n, on the rebuilt rows, and it folds to the row it had at its own position at a long-running reader, a
// new device and a rows-only gate alike.
func TestReapplyOfACompletedKOfNSuspendKeepsItsClass(t *testing.T) {
	team := newTestConfigTeam(t)
	foldedThrough := team.n
	subject := team.adminC.sidecarId
	_, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: team.header(), Subject: subject.Bytes(), SuspendId: aclTestSuspendId("k of n")})
	if verdict := team.cosign(team.adminB, proposalId); !verdict.Accepted() || !verdict.Completed() {
		t.Fatalf("the completing cosign: %v", verdict.Refusal)
	}
	before := team.log.State().aclRows.GetSuspensions()
	if len(before) != 1 || before[0].GetSignerClass() != AclSuspendClassAuthority {
		t.Fatalf("the k-of-n Suspend at its own position: %+v", before)
	}

	team.fold(team.owner, foldedThrough, 2)
	state := team.log.State()
	if after := state.aclRows.GetSuspensions(); len(after) != 1 || !proto.Equal(after[0], before[0]) {
		t.Errorf("the re-applied Suspend %+v, at its own position %+v", after, before)
	}
	if !state.Suspended(subject) {
		t.Error("the subject stands again past the base")
	}
	team.everyReaderAgrees()
}

// The same through a tick: a k-of-n Suspend that an AdminSet member's recovery key cosigns, so Recovery's window holds
// it, activated by a tick 72 h on, all in a base's tail. The tick applies the proposed statement rather than
// re-applying it, on the body's verdict, so ReapplyStatement derives its class there, and it folds to the row it had
// at the tick at a long-running reader, a new device and a rows-only gate alike.
func TestReapplyOfATickActivatedSuspendKeepsItsClass(t *testing.T) {
	team := newTestConfigTeam(t)
	key := testConfigRecovery(team.adminB.memberId, "admin b")
	// an AdminSet member's binding is itself k of n
	_, bindId := team.propose(team.adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, team.recoveryBind(key))
	if bound := team.cosign(team.owner, bindId); !bound.Accepted() || !bound.Completed() {
		t.Fatalf("the binding: %v", bound.Refusal)
	}
	foldedThrough := team.n
	subject := team.adminC.sidecarId
	proposed := team.mustPost(team.owner, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, team.longProposal(bridge.SignedType_SIGNED_SUSPEND,
		&bridge.Suspend{Header: team.header(), Subject: subject.Bytes(), SuspendId: aclTestSuspendId("windowed")}))
	proposalId := proposed.StatementId[:]
	if cosigned := team.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, &protocol.AuthorityCosign{Header: team.header(), ProposalId: proposalId}); !cosigned.Accepted() || cosigned.Completed() {
		t.Fatalf("the recovery key's cosign: %v, completed %v", cosigned.Refusal, cosigned.Completed())
	}
	if team.log.State().Suspended(subject) {
		t.Fatal("a recovery key's cosign completed the Suspend")
	}
	team.wait(72 * testConfigHourMs)
	if activated := team.activate(proposalId); !activated.Accepted() {
		t.Fatalf("the activation: %v", activated.Refusal)
	}
	before := team.log.State().aclRows.GetSuspensions()
	if len(before) != 1 || before[0].GetSignerClass() != AclSuspendClassAuthority {
		t.Fatalf("the activated Suspend at the tick: %+v", before)
	}

	team.fold(team.owner, foldedThrough, 2)
	state := team.log.State()
	if after := state.aclRows.GetSuspensions(); len(after) != 1 || !proto.Equal(after[0], before[0]) {
		t.Errorf("the re-applied Suspend %+v, at the tick %+v", after, before)
	}
	if !state.Suspended(subject) {
		t.Error("the subject stands again past the base")
	}
	team.everyReaderAgrees()
}

// A grant activated under the requests rule a GrantActivate's action names, on a network whose log runs the test's
// spend check: the activation sequenced, and its position.
func testConfigGrantActivation(t *testing.T, requestId []byte) (*testConfigNet, *protocol.GrantActivate, testConfigDevice, uint64) {
	request := &protocol.AclRequestRule{
		RuleId:        requestId,
		SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
		ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
	}
	net := newAclTestGrantNet(t, request)
	phone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	activate := newAclTestGrant(t, requestId, net.owner.sidecarId, []string{aclTestDst(phone.sidecarId)}, []string{"dial"}, 0).
		approve(t, net.ownerMemberId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, net.timeMs+60*60*1000).activate()
	activate.Header = net.header()
	activatedAt := net.mustPost(net.owner, bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate).Pin.GetVersion()
	return net, activate, phone, activatedAt
}

// Whether the network's owner device reaches the phone at state.
func testConfigReaches(t *testing.T, net *testConfigNet, state *ConfigState, phone testConfigDevice) bool {
	t.Helper()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	return acl.Reach(AclSidecarSubject(net.owner.sidecarId), AclSidecarSubject(phone.sidecarId), time.UnixMilli(net.timeMs)).Allowed
}

// QD-954's GrantActivate whose source rule is gone: a base below the activation whose head deleted its requests rule
// ends the grant there, as the base's compile would (FS-14), and keeps its grant_id spent with its activation's
// retention, so a re-signed copy under a fresh header is refused as a replay; a long-running reader, a new device and
// a rows-only gate fold it alike.
func TestReapplyEndsAGrantWhoseRequestsRuleIsGoneAndKeepsItSpent(t *testing.T) {
	net, activate, phone, activatedAt := testConfigGrantActivation(t, testConfigId("gone requests rule").Bytes())
	spent := net.log.State().aclRows.GetSpentGrants()
	if !testConfigReaches(t, net, net.log.State(), phone) || len(spent) != 1 {
		t.Fatalf("the activated grant: %d spent rows", len(spent))
	}

	folded := net.statesAt[activatedAt-1]
	rows := folded.Rows()
	aclRows := proto.Clone(folded.aclRows).(*protocol.AclRows)
	aclRows.Requests = nil
	rows.Acl = testConfigMarshal(t, aclRows)
	if verdict := net.pushBase(net.owner, rows, activatedAt-1, folded.Base().GetConfigVersion()+1, folded.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	state := net.log.State()
	if testConfigReaches(t, net, state, phone) || 0 < len(state.aclRows.GetRules()) {
		t.Errorf("the grant outlived its requests rule: %d rules", len(state.aclRows.GetRules()))
	}
	if after := state.aclRows.GetSpentGrants(); len(after) != 1 || !proto.Equal(after[0], spent[0]) {
		t.Errorf("the spent rows past the base %+v, at the activation %+v", after, spent)
	}
	if kept := net.log.keptEntry(activatedAt); kept == nil || !kept.verdict.Accepted() {
		t.Error("the activation's own verdict changed at the base")
	}

	resigned := proto.Clone(activate).(*protocol.GrantActivate)
	resigned.Header = net.header()
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_GRANT_ACTIVATE, resigned, ErrConfigReplay)
	net.everyReaderAgreesUnder(testConfigSpendingLogSettings(), testConfigSpendingLogSettings())
}

// A GrantActivate re-applied where its check would refuse folds as it took effect: a base below the activation whose
// head keeps its requests rule, re-applied by a new device and a rows-only gate that install no spend check, so §8.8's
// check would refuse every decision there (AclSpendCheckUnbuilt), folds the grant's rule, atom and spent row as the
// long-running reader that judged it does, and the grant reaches at all three alike (QD-954: the grant no longer ends
// at a base for that reason alone).
func TestReapplyFoldsAGrantWhereItsCheckWouldRefuse(t *testing.T) {
	net, activate, phone, activatedAt := testConfigGrantActivation(t, testConfigId("kept requests rule").Bytes())
	folded := net.statesAt[activatedAt-1]
	acl, err := folded.Acl()
	if err != nil {
		t.Fatal(err)
	}
	statement := &AclStatement{Type: bridge.SignedType_SIGNED_GRANT_ACTIVATE, Body: activate,
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: net.owner.sidecarId}}, N: activatedAt, TimeMs: net.timeMs}
	if _, err := acl.CheckStatement(statement, AclSpendCheckUnbuilt{}); !errors.Is(err, ErrConfigAuthority) {
		t.Fatalf("the activation judged with no spend check: %v", err)
	}
	activated := testConfigMarshal(t, net.log.State().aclRows)

	if verdict := net.pushBase(net.owner, folded.Rows(), activatedAt-1, folded.Base().GetConfigVersion()+1, folded.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	state := net.log.State()
	if !testConfigReaches(t, net, state, phone) {
		t.Error("the re-applied grant does not reach")
	}
	if !bytes.Equal(testConfigMarshal(t, state.aclRows), activated) {
		t.Error("the re-applied grant folds other rows than its activation did")
	}
	net.everyReaderAgreesUnder(testConfigSpendingLogSettings(), testConfigLogSettings())
}

// DESIGN-DETAILS 5.6's TestAFoldHoldsItsBaseRecords: a reader's head check needs the BASE entries among a fold's
// records, by the base's id with its position; a head missing one, or holding another, fails; and the chain recomputed
// from the genesis through a head's records reaches the log's A_ft.
func TestAFoldHoldsItsBaseRecords(t *testing.T) {
	net := newTestConfigNet(t)
	net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, net.n, 2)
	net.admitMember(net.owner, testConfigId("b"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, net.n, 3)
	check := net.source.checks[len(net.source.checks)-1]
	kinds := []uint32{}
	for _, record := range check.Folded {
		kinds = append(kinds, record.Kind)
	}
	if len(kinds) != 2 || kinds[0] != bridge.AuthEntryKindBase || kinds[1] != bridge.AuthEntryKindStatement {
		t.Fatalf("the records the third base folds: %v", kinds)
	}
	if !bytes.Equal(check.Folded[0].Id, net.log.keptEntry(3).verdict.StatementId[:]) {
		t.Error("a BASE record's id is not its header's")
	}

	// every record from 1 to the fold, bases included, as a head holds them
	records := []ConfigFoldRecord{}
	for n := uint64(1); n <= net.n-1; n += 1 {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(net.entries[n-1], entry); err != nil {
			t.Fatal(err)
		}
		_, id := configEntryStatementId(entry)
		record := ConfigFoldRecord{N: n, TimeMs: entry.GetTimeMs(), Kind: entry.GetKind(), Body: entry.GetBody()}
		if entry.GetKind() == bridge.AuthEntryKindBase {
			signed, _, err := configParseBase(entry)
			if err != nil {
				t.Fatal(err)
			}
			id = bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody())
		}
		if entry.GetKind() != bridge.AuthEntryKindTick {
			record.Id = id[:]
		}
		records = append(records, record)
	}
	head := testConfigHead(t, net, records)
	foldedThrough := uint64(len(records))
	anchor := func(head *ConfigHead) error {
		_, err := CheckConfigBase(head, &ConfigHeadCheck{
			Header:         &bridge.ProjectionHeader{FoldedThrough: foldedThrough},
			GenesisChain:   bridge.GenesisChain(net.signedGenesis),
			FoldedFrom:     foldedThrough + 1,
			FirstPrevChain: net.statesAt[foldedThrough].chain,
		}, nil)
		return err
	}
	if err := anchor(head); err != nil {
		t.Fatalf("the chain through the head's records: %v", err)
	}
	withoutBase := append([]ConfigFoldRecord{}, records[:2]...)
	withoutBase = append(withoutBase, records[3:]...)
	if err := anchor(testConfigHead(t, net, withoutBase)); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Errorf("a head missing a BASE record: %v", err)
	}
	forged := append([]ConfigFoldRecord{}, records...)
	forged[2].Body = append(bytes.Clone(forged[2].Body), 0)
	if err := anchor(testConfigHead(t, net, forged)); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Errorf("a head holding another BASE body: %v", err)
	}
}

// DESIGN-DETAILS 5.6's TestAFarBehindReaderLinksThroughTheHead: a reader whose last pin lies below what api retains
// restarts at the newest base, its anchor recomputing the chain through the head's records past its pin; a pin off that
// chain, or a run whose first entry the head's chain does not reach, fails.
func TestAFarBehindReaderLinksThroughTheHead(t *testing.T) {
	net := newTestConfigNet(t)
	for _, label := range []string{"a", "b", "c"} {
		net.admitMember(net.owner, testConfigId(label), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	}
	records := []ConfigFoldRecord{}
	for n := uint64(1); n <= net.n; n += 1 {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(net.entries[n-1], entry); err != nil {
			t.Fatal(err)
		}
		record := configFoldRecordOf(&configKeptEntry{n: n, entry: entry, verdict: net.log.keptEntryOrEmpty(n).verdict})
		records = append(records, record)
	}
	head := testConfigHead(t, net, records)
	foldedThrough := net.n
	held := net.statesAt[2].Pin()
	check := func(floor *bridge.AuthPin, firstPrevChain [sha256.Size]byte) error {
		_, err := CheckConfigBase(head, &ConfigHeadCheck{
			Header:         &bridge.ProjectionHeader{FoldedThrough: foldedThrough},
			GenesisChain:   bridge.GenesisChain(net.signedGenesis),
			FoldedFrom:     foldedThrough + 1,
			FirstPrevChain: firstPrevChain,
			Floor:          floor,
		}, nil)
		return err
	}
	if err := check(held, net.chain); err != nil {
		t.Fatalf("the reader's own pin on the head's chain: %v", err)
	}
	forgedPin := &bridge.AuthPin{Version: held.GetVersion(), Chain: make([]byte, sha256.Size)}
	if err := check(forgedPin, net.chain); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Errorf("a pin off the head's chain: %v", err)
	}
	if err := check(held, sha256.Sum256([]byte("another run"))); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Errorf("a run the head's chain does not reach: %v", err)
	}
}

// The rows of a base this log keeps, parsed.
func (self *ConfigLog) baseRowsOf(t testing.TB, header *bridge.ProjectionHeader) *bridge.ProjectionRows {
	t.Helper()
	rowsBytes, found := self.baseRows[[sha256.Size]byte(header.GetRowsSha256())]
	if !found {
		t.Fatal("no rows kept for the base")
	}
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// The kept entry at n, or an empty one with no verdict.
func (self *ConfigLog) keptEntryOrEmpty(n uint64) *configKeptEntry {
	if kept := self.keptEntry(n); kept != nil {
		return kept
	}
	return &configKeptEntry{}
}
