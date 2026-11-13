// TEAM-M2-17's causal identities on the test network: a shrink advances holders_shrunk_at at its entry and closes the
// gate to an older generation, through KEYS's GkmGatePasses; an expired grant fails a generation older than its expiry;
// a compromise rebind shrinks with the holder's identity unchanged; time alone with no expiring grant shrinks nothing;
// every kind of reader holds the same values after a base; and a base's own change shrinks exactly the repos its
// shrunk_repo_ids name (QD-746), which a present reader holds the base to, api judges at the time it stamps, and a new
// device and a cold gate take, so §10.6's gate refuses an older generation at every one of them.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A general repo the owner made, and a member device it granted reading, which a KeyHolders leaf holds.
func (self *testConfigNet) repoWithReader(label string, expires int64) (Id, testConfigDevice) {
	self.t.Helper()
	reader := self.admitMemberDevice(label + " reader")
	repoId := testConfigId(label + " repo")
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: self.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: self.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires,
	})
	holders, err := KeyHolders(self.log.State(), repoId, time.UnixMilli(self.timeMs))
	if err != nil || !holders.Contains(GkmHolderLeaf, reader.sidecarId.Bytes()) {
		self.t.Fatalf("the reader holds no key: %v", err)
	}
	return repoId, reader
}

// FS-14: a generation rotated at n1, then a shrink at n2 > n1: holders_shrunk_at is n2, the gate refuses the n1
// generation, and a generation at n2 passes; a grant to another reader shrinks nothing.
func TestAShrinkAfterARotationReopensNoGate(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("r", 0)
	rotatedAt := net.log.Pin()
	other := net.admitMemberDevice("other")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: other.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	if shrunk := net.log.State().ShrunkAt(repoId); rotatedAt.GetVersion() < shrunk {
		t.Fatalf("a grant shrank the repo at %d", shrunk)
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	state := net.log.State()
	if shrunk := state.ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
		t.Fatalf("holders_shrunk_at %d, the revoke at %d", shrunk, revoked.Pin.GetVersion())
	}
	now := time.UnixMilli(net.timeMs)
	if GkmGatePasses(state, repoId, rotatedAt, now, now) {
		t.Error("the generation from before the shrink passes the gate")
	}
	if !GkmGatePasses(state, repoId, revoked.Pin, now, now) {
		t.Error("a generation at the shrink does not pass")
	}
	net.everyReaderAgrees()
}

// FS-14: an expired grant fails a generation older than its expiry, at its expiry and no entry; one at or after it
// passes. ExpiriesFor finds the expiry.
func TestAnExpiredGrantFailsAnOlderGeneration(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, _ := net.repoWithReader("expiring", expires)
	pin := net.log.Pin()
	state := net.log.State()
	before := time.UnixMilli(net.timeMs)
	after := time.UnixMilli(expires + 1000)
	expiry, found, err := state.ExpiriesFor(repoId, before, after)
	if err != nil || !found || expiry.UnixMilli() != expires {
		t.Fatalf("the expiry: %v %v %v", expiry, found, err)
	}
	if GkmGatePasses(state, repoId, pin, before, after) {
		t.Error("a generation from before the expiry passes after it")
	}
	if !GkmGatePasses(state, repoId, pin, time.UnixMilli(expires), after) {
		t.Error("a generation at the expiry does not pass")
	}
	// time with no expiring holder shrinks and expires nothing: a ReaderKey's lapse is no expiry
	plain, _ := net.repoWithReader("plain", 0)
	if _, found, err := net.log.State().ExpiriesFor(plain, before, after.Add(30*24*time.Hour)); err != nil || found {
		t.Errorf("an expiry with no expiring grant: %v %v", found, err)
	}
}

// A compromise rebind of a member who reads a repo shrinks it, though the member's recovery identity stays: the new
// binding is current.
func TestACompromiseRebindShrinksWithTheIdentityUnchanged(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	repoId := testConfigId("m repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: laptop.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	at := time.UnixMilli(net.timeMs)
	holders, err := KeyHolders(net.log.State(), repoId, at)
	if err != nil || !holders.Contains(GkmHolderRecovery, member.Bytes()) {
		t.Fatalf("the member's recovery holds no key: %v", err)
	}
	next := testConfigRecovery(member, "m next")
	rebound := net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{
		Header: net.header(), MemberId: member.Bytes(), PrevSha256: key.sha256(), Ed25519PublicKeySha256: next.sha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE,
	})
	state := net.log.State()
	if after, err := KeyHolders(state, repoId, time.UnixMilli(net.timeMs)); err != nil || !after.Contains(GkmHolderRecovery, member.Bytes()) {
		t.Fatalf("the recovery identity left: %v", err)
	}
	if shrunk := state.ShrunkAt(repoId); shrunk != rebound.Pin.GetVersion() {
		t.Errorf("holders_shrunk_at %d, the rebind at %d", shrunk, rebound.Pin.GetVersion())
	}
	net.everyReaderAgrees()
}

// A shrink in a base's tail re-applies to the same holders_shrunk_at at a long-running reader, a new device and a
// rows-only gate (DESIGN-DETAILS 5.7's TEAM-M2-17 note).
func TestShrunkAtIsEqualAtEveryReaderAfterABase(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("r", 0)
	foldedThrough := net.n
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	net.fold(net.owner, foldedThrough, 1)
	for _, reader := range net.everyReader() {
		if shrunk := reader.State().ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("a reader's holders_shrunk_at %d, the revoke at %d", shrunk, revoked.Pin.GetVersion())
		}
	}
	net.everyReaderAgrees()
}

// A general repo the owner made, which no rule or grant lets anyone but its creator read yet.
func (self *testConfigNet) createRepo(label string) Id {
	self.t.Helper()
	repoId := testConfigId(label + " repo")
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: self.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	return repoId
}

// One rule of a test policy: a group of members, which reads one repo.
type testConfigGroupRead struct {
	repoId    Id
	memberIds []Id
}

// The acl rows the state holds with its policy replaced, as a head change compiles it: a document whose only rules let
// each group read its repo, one group atom a rule (§8.4).
func (self *testConfigNet) groupReadRows(reads ...testConfigGroupRead) *bridge.ProjectionRows {
	self.t.Helper()
	state := self.log.State()
	rows := state.Rows()
	aclRows := proto.Clone(state.aclRows).(*protocol.AclRows)
	aclRows.HasDocument = true
	aclRows.Atoms, aclRows.Rules = nil, nil
	for _, read := range reads {
		groupId := testConfigId("group of " + read.repoId.String())
		atom := &protocol.AclAtom{Atom: groupId.Bytes()}
		for _, memberId := range read.memberIds {
			atom.MemberIds = append(atom.MemberIds, memberId.Bytes())
		}
		aclRows.Atoms = append(aclRows.Atoms, atom)
		aclRows.Rules = append(aclRows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("rule of " + read.repoId.String()).Bytes(),
			SrcAtoms: [][]byte{groupId.Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: read.repoId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)},
		})
	}
	rows.Acl = testConfigMarshal(self.t, aclRows)
	return rows
}

// A base at the tip folding everything under a newer config version, its policy groupReadRows's, signed as an honest
// writer signs it; its verdict, which must take effect.
func (self *testConfigNet) withGroupReads(reads ...testConfigGroupRead) ConfigVerdict {
	self.t.Helper()
	state := self.log.State()
	verdict := self.pushBase(self.owner, self.groupReadRows(reads...), self.n, state.Base().GetConfigVersion()+1, state.threshold)
	if !verdict.Accepted() {
		self.t.Fatalf("the policy base: %v", verdict.Refusal)
	}
	return verdict
}

// The base entry makeBase gives with its header edited, re-signed, at the same position and time.
func (self *testConfigNet) editedBase(entryBytes []byte, edit func(header *bridge.ProjectionHeader)) []byte {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	edit(header)
	return self.makeEntry(bridge.AuthEntryKindBase, self.sign(self.owner, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
}

// A network where member devices a and b read repo a through one group and b reads repo b through another, on a base
// whose policy says so: the two repos and the devices.
func testConfigTwoGroupNet(t *testing.T) (*testConfigNet, Id, Id, testConfigDevice, testConfigDevice) {
	net := newTestConfigNet(t)
	a, b := net.admitMemberDevice("a"), net.admitMemberDevice("b")
	repoA, repoB := net.createRepo("a"), net.createRepo("b")
	net.withGroupReads(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId, b.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	at := time.UnixMilli(net.timeMs)
	holdersA, err := KeyHolders(net.log.State(), repoA, at)
	if err != nil || !holdersA.Contains(GkmHolderLeaf, a.sidecarId.Bytes()) || !holdersA.Contains(GkmHolderLeaf, b.sidecarId.Bytes()) {
		t.Fatalf("repo a's holders: %v", err)
	}
	holdersB, err := KeyHolders(net.log.State(), repoB, at)
	if err != nil || !holdersB.Contains(GkmHolderLeaf, b.sidecarId.Bytes()) || holdersB.Contains(GkmHolderLeaf, a.sidecarId.Bytes()) {
		t.Fatalf("repo b's holders: %v", err)
	}
	return net, repoA, repoB, a, b
}

// QD-746: a group edit at a base drops b's device from repo a's readers and not from repo b's. The base names repo a
// alone; a long-running reader, a reader that applied every entry since genesis, a new device and a cold gate that start
// at the base each hold its position as repo a's holders_shrunk_at and repo b's below it; and §10.6's gate refuses the
// generation from before the edit on repo a at every one of them, passing it on repo b and passing one at the base.
func TestAGroupEditAtABaseShrinksOneRepoAtEveryReader(t *testing.T) {
	net, repoA, repoB, a, b := testConfigTwoGroupNet(t)
	rotatedAt := net.log.Pin()
	shrunkBefore := net.log.State().ShrunkAt(repoB)
	edited := net.withGroupReads(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	header := net.log.State().Base()
	if !slices.EqualFunc(header.GetShrunkRepoIds(), [][]byte{repoA.Bytes()}, bytes.Equal) {
		t.Fatalf("the base names %x", header.GetShrunkRepoIds())
	}
	now := time.UnixMilli(net.timeMs)
	readers := append([]*ConfigLog{net.log}, net.everyReader()...)
	for i, reader := range readers {
		state := reader.State()
		if shrunk := state.ShrunkAt(repoA); shrunk != edited.Pin.GetVersion() {
			t.Errorf("reader %d: repo a's holders_shrunk_at %d, the base at %d", i, shrunk, edited.Pin.GetVersion())
		}
		if shrunk := state.ShrunkAt(repoB); shrunk != shrunkBefore {
			t.Errorf("reader %d: repo b's holders_shrunk_at %d, %d before the edit", i, shrunk, shrunkBefore)
		}
		if err := GkmGateCheck(state, repoA, rotatedAt, now, now); !errors.Is(err, ErrGkmGateClosed) {
			t.Errorf("reader %d: the generation from before the edit on repo a: %v", i, err)
		}
		if err := GkmGateCheck(state, repoB, rotatedAt, now, now); err != nil {
			t.Errorf("reader %d: the generation from before the edit on repo b: %v", i, err)
		}
		if err := GkmGateCheck(state, repoA, edited.Pin, now, now); err != nil {
			t.Errorf("reader %d: a generation at the base on repo a: %v", i, err)
		}
	}
	net.everyReaderAgrees()
}

// QD-746: a base whose shrunk_repo_ids are not exactly the repos its own change shrinks forks a reader present before
// it, whatever the list: one missing repo a, one naming repo b or both, out of order, twice, a short id, or a repo the
// rows do not hold. api refuses each before it is sequenced, a well-formed list with ErrConfigTipMoved, since its writer
// signs again at its clock, and the rest as a rule; and a new device that starts at a base naming a repo out of order
// forks rather than take it. The honest base then lands.
func TestAWritersWrongShrunkListForksAPresentReader(t *testing.T) {
	net, repoA, repoB, a, b := testConfigTwoGroupNet(t)
	state := net.log.State()
	rows := net.groupReadRows(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	honest := net.makeBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, state.threshold)
	ordered := [][]byte{repoA.Bytes(), repoB.Bytes()}
	if 0 < bytes.Compare(ordered[0], ordered[1]) {
		ordered[0], ordered[1] = ordered[1], ordered[0]
	}
	cases := []struct {
		name string
		ids  [][]byte
		want error
	}{
		{name: "none", ids: nil, want: ErrConfigTipMoved},
		{name: "repo b instead", ids: [][]byte{repoB.Bytes()}, want: ErrConfigTipMoved},
		{name: "both", ids: ordered, want: ErrConfigTipMoved},
		{name: "out of order", ids: [][]byte{ordered[1], ordered[0]}, want: ErrConfigRule},
		{name: "twice", ids: [][]byte{repoA.Bytes(), repoA.Bytes()}, want: ErrConfigRule},
		{name: "a short id", ids: [][]byte{repoA.Bytes()[:8]}, want: ErrConfigRule},
		{name: "a repo the rows do not hold", ids: [][]byte{testConfigId("no such repo").Bytes()}, want: ErrConfigRule},
	}
	api := net.apiAtTip()
	for _, c := range cases {
		entryBytes := net.editedBase(honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = c.ids })
		signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
		if err := api.CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, c.want) {
			t.Errorf("%s: api's check %v, want %v", c.name, err, c.want)
		}
		if _, err := net.newReader().Apply(entryBytes, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("%s: a present reader %v", c.name, err)
		}
	}
	if api.Fork() != nil {
		t.Error("a refused base forked api's log")
	}

	// a new device that starts at a base naming its repos out of order
	retained := net.log.Retained()
	retained.Entries = append(retained.Entries, net.editedBase(honest, func(header *bridge.ProjectionHeader) {
		header.ShrunkRepoIds = [][]byte{ordered[1], ordered[0]}
	}))
	if _, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a new device took a list out of order: %v", err)
	}

	signedHeader, rowsBytes, timeMs := net.baseParts(honest)
	if err := api.CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("the honest base at api: %v", err)
	}
	if verdict := net.push(honest); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if shrunk := net.log.State().ShrunkAt(repoA); shrunk != net.n {
		t.Errorf("repo a's holders_shrunk_at %d, the base at %d", shrunk, net.n)
	}
	net.everyReaderAgrees()
}

// QD-746's time: b reads repo a by its group and by a RepoGrant that expires at T, and a group edit at a base leaves it
// the grant alone. Before T the base shrinks nothing; from T it shrinks repo a, since b held repo a at T under the
// state before and holds nothing then under the base's. A writer that signed before T and meets api's stamp from T on
// gets ErrConfigTipMoved, and signs again at its later clock, naming repo a, which api and a reader take.
func TestApiJudgesABasesShrinksAtTheTimeItStamps(t *testing.T) {
	net, repoA, repoB, a, b := testConfigTwoGroupNet(t)
	expires := net.timeMs + 60*60*1000
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoA.Bytes(), Subject: b.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires,
	})
	state := net.log.State()
	rows := net.groupReadRows(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	unsigned := net.makeBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, state.threshold)
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(unsigned, entry); err != nil {
		t.Fatal(err)
	}
	_, header, err := configParseBase(entry)
	if err != nil {
		t.Fatal(err)
	}
	rowsBytes, err := net.source.Rows(net.networkId, header.GetRowsSha256())
	if err != nil {
		t.Fatal(err)
	}
	early, err := net.log.BaseShrunkRepoIds(header, rowsBytes, expires-1)
	if err != nil || len(early) != 0 {
		t.Fatalf("before the grant's expiry the base shrinks %x: %v", early, err)
	}
	late, err := net.log.BaseShrunkRepoIds(header, rowsBytes, expires)
	if err != nil || !slices.EqualFunc(late, [][]byte{repoA.Bytes()}, bytes.Equal) {
		t.Fatalf("from the grant's expiry the base shrinks %x: %v", late, err)
	}
	api := net.apiAtTip()
	header.ShrunkRepoIds = early
	signedEarly := net.sign(net.owner, bridge.SignedType_SIGNED_PROJECTION_HEADER, header)
	if err := api.CheckBase(signedEarly, rowsBytes, expires); !errors.Is(err, ErrConfigTipMoved) {
		t.Errorf("api took a list signed before the expiry at a stamp after it: %v", err)
	}
	header.ShrunkRepoIds = late
	signedLate := net.sign(net.owner, bridge.SignedType_SIGNED_PROJECTION_HEADER, header)
	if err := api.CheckBase(signedLate, rowsBytes, expires); err != nil {
		t.Fatalf("api refused the list signed again: %v", err)
	}
	stamped := testConfigMarshal(t, &bridge.AuthEntry{
		NetworkId: net.networkId.Bytes(), N: net.n + 1, PrevChain: bytes.Clone(net.chain[:]), Kind: bridge.AuthEntryKindBase,
		TimeMs: expires, Body: signedLate,
	})
	if verdict := net.push(stamped); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if shrunk := net.log.State().ShrunkAt(repoA); shrunk != net.n {
		t.Errorf("repo a's holders_shrunk_at %d, the base at %d", shrunk, net.n)
	}
	net.everyReaderAgrees()
}

// QD-746 across a later base: once a base shrank repo a, a base after it that keeps the fold below it, so its tail holds
// the shrinking base and its rows the log before it, keeps repo a's holders_shrunk_at at the shrinking base at every
// reader, and §10.6's gate stays shut to the generation from before the edit.
func TestABaseKeepingAFoldBelowAShrinkKeepsItsPosition(t *testing.T) {
	net, repoA, repoB, a, b := testConfigTwoGroupNet(t)
	rotatedAt := net.log.Pin()
	edited := net.withGroupReads(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	editedBase := net.log.State().Base()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("later"))
	rowsBytes, err := net.source.Rows(net.networkId, editedBase.GetRowsSha256())
	if err != nil {
		t.Fatal(err)
	}
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil {
		t.Fatal(err)
	}
	configVersion := editedBase.GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{WitnessBoundHours: 48}
	kept := net.pushBase(net.owner, rows, editedBase.GetFoldedThrough(), configVersion, editedBase.GetThreshold())
	if !kept.Accepted() {
		t.Fatal(kept.Refusal)
	}
	if header := net.log.State().Base(); header.GetFoldedThrough() >= edited.Pin.GetVersion() || len(header.GetShrunkRepoIds()) != 0 {
		t.Fatalf("the later base folds through %d and names %x", header.GetFoldedThrough(), header.GetShrunkRepoIds())
	}
	now := time.UnixMilli(net.timeMs)
	for i, reader := range append([]*ConfigLog{net.log}, net.everyReader()...) {
		state := reader.State()
		if shrunk := state.ShrunkAt(repoA); shrunk != edited.Pin.GetVersion() {
			t.Errorf("reader %d: repo a's holders_shrunk_at %d after the later base, the edit at %d", i, shrunk, edited.Pin.GetVersion())
		}
		if err := GkmGateCheck(state, repoA, rotatedAt, now, now); !errors.Is(err, ErrGkmGateClosed) {
			t.Errorf("reader %d: the generation from before the edit: %v", i, err)
		}
	}
	net.everyReaderAgrees()
}
