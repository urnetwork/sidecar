// TEAM-M2-17's causal identities on the test network: a shrink advances holders_shrunk_at at its entry and closes the
// gate to an older generation, through KEYS's GkmGatePasses; an expired grant fails a generation older than its expiry;
// a compromise rebind shrinks with the holder's identity unchanged; time alone with no expiring grant shrinks nothing;
// every kind of reader holds the same values after a base; and a base's own change shrinks exactly the repos its
// shrunk_repo_ids name (QD-746), which a present reader holds the base to, api judges at the time it stamps, and a new
// device and a cold gate take, so §10.6's gate refuses an older generation at every one of them. The config repo's row
// joins the rows at the first shrink of its holders and advances there like any repo's (QD-762): each kind of entry
// that shrinks it, the gate and REMOVE following its shrinks alone, bases carrying it, and a base's own shrink of it.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
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
	t.Helper()
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
// at the base, and a warm gate present before it each hold its position as repo a's holders_shrunk_at and repo b's
// below it; and §10.6's gate refuses the generation from before the edit on repo a at every one of them, passing it on
// repo b and passing one at the base.
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
	// the net's reader, one from genesis, a new device and a cold gate starting at the base, and a warm gate that was
	// present before it, as api's and evs's and gkm's caches are once loaded
	readers := append(append([]*ConfigLog{net.log}, net.everyReader()...), net.apiAtTip())
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
	for i, reader := range append(append([]*ConfigLog{net.log}, net.everyReader()...), net.apiAtTip()) {
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

// The config repo the test network's Genesis names.
func (self *testConfigNet) configRepoId() Id {
	return Id(self.log.State().Genesis().GetConfigRepoId())
}

// The rows' AclRepo rows of the config repo at a state, by id or by kind, as its acl bytes hold them, and the rows'
// repo ids in order.
func testConfigConfigRepoRows(t testing.TB, state *ConfigState) ([]*protocol.AclRepo, []Id) {
	t.Helper()
	acl := &protocol.AclRows{}
	if err := proto.Unmarshal(state.Rows().GetAcl(), acl); err != nil {
		t.Fatal(err)
	}
	configRepoIdBytes := state.Genesis().GetConfigRepoId()
	configRows := []*protocol.AclRepo{}
	repoIds := []Id{}
	for _, repo := range acl.GetRepos() {
		if bytes.Equal(repo.GetRepoId(), configRepoIdBytes) || repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG {
			configRows = append(configRows, repo)
		}
		repoIds = append(repoIds, Id(repo.GetRepoId()))
	}
	return configRows, repoIds
}

// Fails unless the config's holders_shrunk_at is shrunkAt at a reader's state: its rows hold no row of the config while
// it is 0, else exactly AclRepo{repo_id, kind: config, holders_shrunk_at: shrunkAt}, which every repo the rows hold
// before it sorts below and the one after it above; and the state's own row, of kind config with no admins, answers
// the same.
func testConfigExpectConfigShrunkAt(t testing.TB, label string, state *ConfigState, shrunkAt uint64) {
	t.Helper()
	configRepoId := Id(state.Genesis().GetConfigRepoId())
	configRows, repoIds := testConfigConfigRepoRows(t, state)
	if shrunkAt == 0 && len(configRows) != 0 {
		t.Errorf("%s: the rows hold the config's row before its first shrink: %v", label, configRows)
	}
	if want := (&protocol.AclRepo{RepoId: configRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG, HoldersShrunkAt: shrunkAt}); shrunkAt != 0 &&
		(len(configRows) != 1 || !proto.Equal(configRows[0], want)) {
		t.Errorf("%s: the rows' config rows %v, want %v", label, configRows, want)
	}
	if index := slices.Index(repoIds, configRepoId); 0 <= index {
		for i, repoId := range repoIds {
			if (i < index && 0 <= repoId.Cmp(configRepoId)) || (i == index+1 && repoId.Cmp(configRepoId) <= 0) {
				t.Errorf("%s: the config's row is not sorted in at %d of %v", label, index, repoIds)
			}
		}
	}
	row := state.Repo(configRepoId)
	if row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || len(row.GetAdmins()) != 0 || row.GetHoldersShrunkAt() != shrunkAt ||
		state.ShrunkAt(configRepoId) != shrunkAt {
		t.Errorf("%s: the state's config row %v, want holders_shrunk_at %d", label, row, shrunkAt)
	}
}

// Every kind of reader of the net's log at the tip: the net's own, the others everyReader gives, and api's warm gate.
func (self *testConfigNet) everyReaderAndApi() []*ConfigLog {
	self.t.Helper()
	return append(append([]*ConfigLog{self.log}, self.everyReader()...), self.apiAtTip())
}

// QD-762: the rows hold no row of the config before its key holders first shrink, and neither the state adding its row
// nor an entry that shrinks nothing changes their bytes; a revocation puts AclRepo{repo_id, kind: config,
// holders_shrunk_at: n} in at its position, sorted in between the repos whose ids lie on either side of it, a later
// revocation advances it, and an entry that shrinks nothing leaves it standing.
func TestTheConfigsRowJoinsTheRowsAtItsFirstShrink(t *testing.T) {
	net := newTestConfigNet(t)
	configRepoId := net.configRepoId()
	offset := func(delta int64) Id {
		value := new(big.Int).Add(new(big.Int).SetBytes(configRepoId.Bytes()), big.NewInt(delta))
		return Id(value.FillBytes(make([]byte, len(Id{}))))
	}
	below, above := offset(-1), offset(1)
	for _, repoId := range []Id{below, above} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	}
	a, b := net.admitMemberDevice("a"), net.admitMemberDevice("b")
	state := net.log.State()
	aclBytes := bytes.Clone(state.Rows().GetAcl())
	testConfigExpectConfigShrunkAt(t, "before any shrink", state, 0)
	if !bytes.Equal(state.Rows().GetAcl(), aclBytes) {
		t.Error("the state adding the config's row changed the rows")
	}
	net.admitMemberDevice("c")
	if !bytes.Equal(net.log.State().Rows().GetAcl(), aclBytes) {
		t.Error("an admission, which shrinks nothing, changed the acl rows")
	}
	testConfigExpectConfigShrunkAt(t, "an admission", net.log.State(), 0)

	first := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(a, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	testConfigExpectConfigShrunkAt(t, "the first revocation", net.log.State(), first.Pin.GetVersion())
	if _, repoIds := testConfigConfigRepoRows(t, net.log.State()); !slices.Equal(repoIds, []Id{below, configRepoId, above}) {
		t.Errorf("the rows' repos %v, want the config's between %s and %s", repoIds, below, above)
	}
	net.admitMemberDevice("d")
	testConfigExpectConfigShrunkAt(t, "an admission after it", net.log.State(), first.Pin.GetVersion())
	second := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(b, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	testConfigExpectConfigShrunkAt(t, "the second revocation", net.log.State(), second.Pin.GetVersion())
	for i, reader := range net.everyReaderAndApi() {
		testConfigExpectConfigShrunkAt(t, fmt.Sprintf("reader %d", i), reader.State(), second.Pin.GetVersion())
	}
	net.everyReaderAgrees()
}

// Each kind of entry that drops a holder of the config's key, which every admitted sidecar, every live Delegation and
// every live forwarding Delegation holds, puts its row in the rows at that entry's position: a SidecarRevoke, a Suspend,
// a MemberRevoke, a Delegation's DelegationRevoke, one with since_n that parks the agent it admitted, and a forwarding
// Delegation's.
func TestEachShrinkOfTheConfigsHoldersPutsItsRowInTheRows(t *testing.T) {
	day := int64(24 * 60 * 60 * 1000)
	cases := []struct {
		name   string
		shrink func(net *testConfigNet, tagId Id) ConfigVerdict
	}{
		{name: "a SidecarRevoke", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			device := net.admitMemberDevice("revoked")
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		}},
		{name: "a Suspend", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			device := net.admitMemberDevice("suspended")
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: device.sidecarId.Bytes(), SuspendId: aclTestSuspendId("config shrink")})
		}},
		{name: "a MemberRevoke", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			device := net.admitMemberDevice("removed")
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: device.memberId.Bytes()})
		}},
		{name: "a DelegationRevoke", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			delegation := net.delegate(net.owner, "ended", []Id{tagId}, 1, net.timeMs+30*day)
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(delegation.id, 0))
		}},
		{name: "a DelegationRevoke parking its agent", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			delegation := net.delegate(net.owner, "leaked", []Id{tagId}, 1, net.timeMs+30*day)
			sinceN := net.n + 1
			agent := net.device("parked agent", Id{})
			if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
				net.t.Fatalf("the agent's admission: %v", verdict.Refusal)
			}
			verdict := net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(delegation.id, sinceN))
			if !net.log.State().Parked(agent.sidecarId) {
				net.t.Fatal("the revoke parked no agent")
			}
			return verdict
		}},
		{name: "a forwarding Delegation's DelegationRevoke", shrink: func(net *testConfigNet, tagId Id) ConfigVerdict {
			device := net.admitMemberDevice("forwarder")
			forwarding := net.forward(device, "forwarder")
			return net.mustPost(device, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(forwarding.id, 0))
		}},
	}
	for _, c := range cases {
		net, tagId, _ := newTestConfigTagNet(t)
		configRepoId := net.configRepoId()
		shrunk := c.shrink(net, tagId)
		n := shrunk.Pin.GetVersion()
		before := net.statesAt[n-1]
		testConfigExpectConfigShrunkAt(t, c.name+", before it", before, 0)
		at := time.UnixMilli(net.timeMs)
		dropped, err := GkmHoldersDropped(before, net.log.State(), configRepoId, at)
		if err != nil || len(dropped) == 0 {
			t.Errorf("%s: no holder of the config left: %v", c.name, err)
		}
		testConfigExpectConfigShrunkAt(t, c.name, net.log.State(), n)
		net.everyReaderAgrees()
	}
}

// §10.6's gate on the config repo reads the config's own shrinks: with none, a generation pinned at base 1 passes at a
// later state, where the closed interim took only one pinned at the newest position; a revocation refuses a generation
// pinned below it and takes one pinned at it or above, at its own state and after a later entry that shrinks nothing,
// at every kind of reader.
func TestTheConfigsGateTakesAGenerationAtOrAboveItsShrink(t *testing.T) {
	net := newTestConfigNet(t)
	configRepoId := net.configRepoId()
	early := net.log.Pin()
	device := net.admitMemberDevice("revoked")
	net.admitMemberDevice("kept")
	check := func(label string, state *ConfigState, pin *bridge.AuthPin, want error) {
		t.Helper()
		now := time.UnixMilli(state.TimeMs())
		err := GkmGateCheck(state, configRepoId, pin, now, now)
		if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: a config write under a generation pinned at %d: %v, want %v", label, pin.GetVersion(), err, want)
		}
	}
	check("no shrink yet", net.log.State(), early, nil)
	before := net.log.Pin()
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	revokedState := net.statesAt[revoked.Pin.GetVersion()]
	check("the revocation's state, below it", revokedState, before, ErrGkmGateClosed)
	check("the revocation's state, at it", revokedState, revoked.Pin, nil)
	net.admitMemberDevice("later")
	later := net.log.Pin()
	for i, reader := range net.everyReaderAndApi() {
		state := reader.State()
		check(fmt.Sprintf("reader %d, below the shrink", i), state, before, ErrGkmGateClosed)
		check(fmt.Sprintf("reader %d, at base 1", i), state, early, ErrGkmGateClosed)
		check(fmt.Sprintf("reader %d, at the shrink", i), state, revoked.Pin, nil)
		check(fmt.Sprintf("reader %d, above it", i), state, later, nil)
	}
	net.everyReaderAgrees()
}

// §10.9's REMOVE on the config repo: a rotator that makes a REMOVE rotation at the tip whenever GkmRemoveDue asks one
// from its newest generation asks once for each shrink of the config's holders, a revocation and a Suspend, and for no
// entry that shrinks nothing, an Unsuspend among them, where the closed interim asked at every entry.
func TestGkmRemoveDueAsksRemoveOncePerShrinkOfTheConfig(t *testing.T) {
	net := newTestConfigNet(t)
	configRepoId := net.configRepoId()
	parent, parentTime := net.log.Pin(), time.UnixMilli(net.timeMs)
	removes := []uint64{}
	// post's entries, then the rotator's judgment at the tip
	step := func(label string, shrinks bool, post func()) {
		t.Helper()
		post()
		state := net.log.State()
		now := time.UnixMilli(state.TimeMs())
		due, err := GkmRemoveDue(state, configRepoId, parent, parentTime, now)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if due != shrinks {
			t.Errorf("%s at %d: REMOVE due %t from a generation pinned at %d", label, state.Pin().GetVersion(), due, parent.GetVersion())
		}
		if due {
			removes = append(removes, state.Pin().GetVersion())
			parent, parentTime = state.Pin(), now
		}
	}
	var a, b testConfigDevice
	step("a's admission", false, func() { a = net.admitMemberDevice("a") })
	step("b's admission", false, func() { b = net.admitMemberDevice("b") })
	step("a repo's creation", false, func() { net.createRepo("remove") })
	step("a's revocation", true, func() {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(a, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	})
	step("c's admission", false, func() { net.admitMemberDevice("c") })
	step("b's suspension", true, func() {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: b.sidecarId.Bytes(), SuspendId: aclTestSuspendId("remove")})
	})
	step("b's unsuspension", false, func() {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: b.sidecarId.Bytes(), SuspendId: aclTestSuspendId("remove")})
	})
	step("d's admission", false, func() { net.admitMemberDevice("d") })
	if len(removes) != 2 || net.n <= uint64(len(removes)) {
		t.Errorf("REMOVE asked at %v over %d entries, want once for each of the two shrinks", removes, net.n)
	}
	net.everyReaderAgrees()
}

// A base folding below a revocation re-applies the config's row from its tail, and a base folding through it carries
// the row in its own rows; after each, every reader holds it at the revocation's position: the net's, one that applied
// every entry, a new device and a gate that start at the base, and api's warm gate. StateAt rebuilds it.
func TestABaseCarriesTheConfigsRowToEveryReader(t *testing.T) {
	net := newTestConfigNet(t)
	configRepoId := net.configRepoId()
	device := net.admitMemberDevice("revoked")
	foldedBelow := net.n
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.admitMemberDevice("after")
	everyReaderHolds := func(label string) {
		t.Helper()
		for i, reader := range net.everyReaderAndApi() {
			testConfigExpectConfigShrunkAt(t, fmt.Sprintf("%s, reader %d", label, i), reader.State(), revoked.Pin.GetVersion())
		}
	}

	if kept := net.fold(net.owner, foldedBelow, 2); !kept.Accepted() {
		t.Fatal(kept.Refusal)
	}
	if configRows, _ := testConfigConfigRepoRows(t, net.statesAt[foldedBelow]); len(configRows) != 0 {
		t.Fatalf("the rows folded below the revocation hold the config's row: %v", configRows)
	}
	everyReaderHolds("a base folding below the revocation")
	testConfigStateAtEqual(t, net, revoked.Pin.GetVersion())

	if carried := net.fold(net.owner, net.n, 3); !carried.Accepted() {
		t.Fatal(carried.Refusal)
	}
	header := net.log.State().Base()
	rowsBytes, err := net.source.Rows(net.networkId, header.GetRowsSha256())
	if err != nil {
		t.Fatal(err)
	}
	rows := &bridge.ProjectionRows{}
	acl := &protocol.AclRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil || proto.Unmarshal(rows.GetAcl(), acl) != nil {
		t.Fatalf("the base's rows: %v", err)
	}
	want := &protocol.AclRepo{RepoId: configRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG, HoldersShrunkAt: revoked.Pin.GetVersion()}
	if !slices.ContainsFunc(acl.GetRepos(), func(repo *protocol.AclRepo) bool { return proto.Equal(repo, want) }) {
		t.Errorf("the base's own rows hold no %v: %v", want, acl.GetRepos())
	}
	if len(header.GetShrunkRepoIds()) != 0 {
		t.Errorf("a base that changes nothing names %x", header.GetShrunkRepoIds())
	}
	everyReaderHolds("a base folding through the revocation")
	net.everyReaderAgrees()
}

// QD-746 with QD-762: a base whose own rows revoke a device, as only a hand-made base's do, shrinks the config at the
// base though its rows hold no row of it: shrunk_repo_ids name the config repo, and every reader, a new device and a
// gate that start at the base among them, holds the config's row at the base's position. A base naming the config
// where nothing shrank it forks a present reader, and api answers its writer to sign again.
func TestABaseWhoseOwnChangeShrinksTheConfigNamesIt(t *testing.T) {
	net := newTestConfigNet(t)
	configRepoId := net.configRepoId()
	device := net.admitMemberDevice("dropped")
	state := net.log.State()

	honest := net.makeBase(net.owner, state.Rows(), net.n, 2, state.threshold)
	lying := net.editedBase(honest, func(header *bridge.ProjectionHeader) { header.ShrunkRepoIds = [][]byte{configRepoId.Bytes()} })
	signedHeader, rowsBytes, timeMs := net.baseParts(lying)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigTipMoved) {
		t.Errorf("api's check of a base naming the config where nothing shrank it: %v", err)
	}
	if _, err := net.newReader().Apply(lying, net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a present reader took a base naming the config where nothing shrank it: %v", err)
	}

	rows := state.Rows()
	for _, row := range rows.GetSidecars() {
		if bytes.Equal(row.GetSidecarId(), device.sidecarId.Bytes()) {
			row.RevokedAt = net.n
		}
	}
	shrinking := net.pushBase(net.owner, rows, net.n, 2, state.threshold)
	if !shrinking.Accepted() {
		t.Fatal(shrinking.Refusal)
	}
	if shrunkRepoIds := net.log.State().Base().GetShrunkRepoIds(); !slices.EqualFunc(shrunkRepoIds, [][]byte{configRepoId.Bytes()}, bytes.Equal) {
		t.Fatalf("the base names %x, want the config repo alone", shrunkRepoIds)
	}
	for i, reader := range net.everyReaderAndApi() {
		testConfigExpectConfigShrunkAt(t, fmt.Sprintf("reader %d", i), reader.State(), shrinking.Pin.GetVersion())
	}
	net.everyReaderAgrees()
}
