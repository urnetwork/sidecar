// DESIGN-DETAILS 5.6's reader tests on the test network: a base carries its tail's verdicts, which a reader present at
// the tail compares with its own and a new device takes, so both reach one S(b); the fold rule and the tail cap; the
// replay ring carried in rows; a fold's BASE records and the chain recomputed through them; and re-application
// recomputing what effects derive on the rebuilt rows.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

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

// A base entry's Signed header bytes and its rows, as api's CheckBase takes them.
func (self *testConfigNet) baseParts(entryBytes []byte) ([]byte, []byte) {
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
	return entry.GetBody(), rows
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
	net.admitDevice(first, second, 0)                                                           // 1
	net.post(second, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("refused")) // 0
	net.fold(net.owner, foldedThrough, 2)                                                       // a BASE, 0
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
		signedHeader, rowsBytes := net.baseParts(entryBytes)
		if err := api.CheckBase(signedHeader, rowsBytes); !errors.Is(err, ErrConfigRule) {
			t.Errorf("%s: api's check %v", c.name, err)
		}
		reader := net.newReader()
		if _, err := reader.Apply(entryBytes, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("%s: a present reader %v", c.name, err)
		}
	}
	entryBytes := net.makeBaseWithVerdicts(net.owner, rows, foldedThrough, 3, 0, honest)
	signedHeader, rowsBytes := net.baseParts(entryBytes)
	if err := api.CheckBase(signedHeader, rowsBytes); err != nil {
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
	signedHeader, rowsBytes := net.baseParts(over)
	if err := api.CheckBase(signedHeader, rowsBytes); !errors.Is(err, ErrConfigRule) {
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
	signedHeader, rowsBytes := net.baseParts(between)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes); !errors.Is(err, ErrConfigRule) {
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
