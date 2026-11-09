// §10.5's key holders over hand-made states: each kind and its identity bytes, holders_sha256's fixed vector, live,
// reach and covered, recovery bindings, §10.5's event table and §10.6's shrink, expiry and never lists, a property
// that no never-list event drops a holder, the bisected expiry against a scan of every instant, and KeyHolders over
// a real ConfigState. Pure, on every leg.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A chain value of the test log at a position.
func gkmTestChain(version uint64) []byte {
	digest := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("gkm holders test chain"), version))
	return digest[:]
}

// A pin of the test log.
func gkmTestPin(version uint64) *bridge.AuthPin {
	return &bridge.AuthPin{Version: version, Chain: gkmTestChain(version)}
}

// A pin at version on another chain.
func gkmTestForkPin(version uint64) *bridge.AuthPin {
	digest := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("gkm holders test fork"), version))
	return &bridge.AuthPin{Version: version, Chain: digest[:]}
}

// One state for KeyHolders: a snapshot of an aclTestFixture's admissions and rows, the Delegation rows, and the test
// log's pins up to its own, each A_k retained from retainedFrom on. Older states are not modelled, so At answers
// only its own pin.
type gkmTestView struct {
	view         *aclTestView
	acl          *AclState
	delegations  []*bridge.DelegationRow
	pin          *bridge.AuthPin
	retainedFrom uint64
}

// What the view reads, copied, so the fixture can change after.
func newGkmTestView(t testing.TB, fixture *aclTestFixture, delegations []*bridge.DelegationRow, version uint64) *gkmTestView {
	t.Helper()
	view := &aclTestView{
		pin:           gkmTestPin(version),
		genesis:       fixture.view.genesis,
		sidecars:      map[Id]*AclSidecar{},
		members:       map[Id]*bridge.MemberRow{},
		configWriters: maps.Clone(fixture.view.configWriters),
		parked:        maps.Clone(fixture.view.parked),
		sponsors:      maps.Clone(fixture.view.sponsors),
		voidFrom:      maps.Clone(fixture.view.voidFrom),
	}
	for sidecarId, sidecar := range fixture.view.sidecars {
		view.sidecars[sidecarId] = &AclSidecar{
			Row:       proto.Clone(sidecar.Row).(*bridge.SidecarRow),
			MemberId:  sidecar.MemberId,
			TagIds:    slices.Clone(sidecar.TagIds),
			Ephemeral: sidecar.Ephemeral,
		}
	}
	for memberId, member := range fixture.view.members {
		view.members[memberId] = proto.Clone(member).(*bridge.MemberRow)
	}
	acl, err := NewAclState(proto.Clone(fixture.rows).(*protocol.AclRows), view)
	if err != nil {
		t.Fatalf("NewAclState: %v", err)
	}
	cloned := []*bridge.DelegationRow{}
	for _, delegation := range delegations {
		cloned = append(cloned, proto.Clone(delegation).(*bridge.DelegationRow))
	}
	slices.SortFunc(cloned, func(a *bridge.DelegationRow, b *bridge.DelegationRow) int {
		return bytes.Compare(a.GetDelegationId(), b.GetDelegationId())
	})
	return &gkmTestView{view: view, acl: acl, delegations: cloned, pin: view.pin, retainedFrom: 1}
}

func (self *gkmTestView) Pin() *bridge.AuthPin {
	return proto.Clone(self.pin).(*bridge.AuthPin)
}

func (self *gkmTestView) At(pin *bridge.AuthPin) (GkmAuthView, error) {
	switch {
	case pin == nil:
		return nil, ErrGkmAuthOffChain
	case self.pin.GetVersion() < pin.GetVersion():
		return nil, ErrGkmAuthAhead
	case pin.GetVersion() < self.retainedFrom:
		return nil, ErrGkmAuthNotRetained
	case !bytes.Equal(gkmTestChain(pin.GetVersion()), pin.GetChain()):
		return nil, ErrGkmAuthOffChain
	case pin.GetVersion() == self.pin.GetVersion():
		return self, nil
	}
	return nil, ErrGkmAuthNotRetained
}

func (self *gkmTestView) OnChain(pin *bridge.AuthPin) bool {
	return pin != nil && self.retainedFrom <= pin.GetVersion() && pin.GetVersion() <= self.pin.GetVersion() &&
		bytes.Equal(gkmTestChain(pin.GetVersion()), pin.GetChain())
}

func (self *gkmTestView) IdentityKey(sidecarId Id) []byte {
	return nil
}

func (self *gkmTestView) Repo(repoId Id) *protocol.AclRepo {
	return self.acl.Repo(repoId)
}

func (self *gkmTestView) RepoReaders(repoId Id) []Id {
	return self.acl.RepoReaders(repoId, aclTestNow)
}

func (self *gkmTestView) RepoWriters(repoId Id) []Id {
	return self.acl.RepoWriters(repoId, aclTestNow)
}

func (self *gkmTestView) RepoReadersAt(repoId Id, at time.Time) []Id {
	return self.acl.RepoReaders(repoId, at)
}

// The admission's row with what the fixture keeps beside it: member, tags and the ephemeral flag.
func (self *gkmTestView) SidecarRow(sidecarId Id) *bridge.SidecarRow {
	sidecar := self.view.sidecars[sidecarId]
	if sidecar == nil {
		return nil
	}
	row := proto.Clone(sidecar.Row).(*bridge.SidecarRow)
	if sidecar.MemberId != (Id{}) {
		row.MemberId = sidecar.MemberId.Bytes()
	}
	for _, tagId := range sidecar.TagIds {
		row.TagIds = append(row.TagIds, tagId.Bytes())
	}
	row.Ephemeral = sidecar.Ephemeral
	return row
}

func (self *gkmTestView) Member(memberId Id) *bridge.MemberRow {
	return self.view.members[memberId]
}

func (self *gkmTestView) Delegations() []*bridge.DelegationRow {
	return self.delegations
}

func (self *gkmTestView) ReposGrantedToAtoms(atoms []Id, at time.Time) []Id {
	return self.acl.ReposGrantedToAtoms(atoms, at)
}

func (self *gkmTestView) CascadeVoids(signer []byte, at uint64) bool {
	return self.view.CascadeVoids(signer, at)
}

// What every holders test starts from, and changes in place before taking a state:
//
//	owner, member      members, each with a member device and, for the owner, a current recovery binding
//	tag, delegation    a Delegation over tag, signed by the owner's device, live for 30 days
//	coveredAgent       a non-ephemeral agent the Delegation admitted, carrying tag
//	ephemeralAgent     an ephemeral agent the Delegation admitted, carrying tag, closing in an hour
//	uncoveredAgent     a tagged agent with another tag and no Delegation, its admission ending in 7 days
//	configId           the config, which every admitted sidecar reads
//	repoId             a general repo autogroup:member, tag and the other tag read
//	outsideId          a general repo only coveredAgent's own sidecar atom reads: outside the Delegation's reach
type gkmTestNet struct {
	fixture     *aclTestFixture
	delegations []*bridge.DelegationRow

	owner          Id
	member         Id
	ownerDevice    Id
	memberDevice   Id
	tag            Id
	otherTag       Id
	delegation     *bridge.DelegationRow
	coveredAgent   Id
	ephemeralAgent Id
	uncoveredAgent Id
	configId       Id
	repoId         Id
	outsideId      Id
	// the rule through which otherTag reads repoId
	otherTagRule *protocol.AclRule
	// a member device a RepoGrant lets read outsideId, once grantOutside has run
	granted Id
}

// Admits a device of member and gives it a RepoGrant reading outsideId, expiring at expires (zero: never).
func (self *gkmTestNet) grantOutside(expires int64) {
	self.granted = self.fixture.device(self.member)
	row := self.repoRow(self.outsideId)
	row.Grants = append(row.Grants, &protocol.AclRepoGrantRow{
		Subject: self.granted.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		Expires: expires, Signer: self.ownerDevice.Bytes(), At: 1,
	})
}

func newGkmTestNet() *gkmTestNet {
	fixture := newAclTestFixture()
	net := &gkmTestNet{fixture: fixture}
	net.owner = fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	net.member = fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.ownerDevice = fixture.device(net.owner)
	net.memberDevice = fixture.device(net.member)
	ownerKey := sha256.Sum256([]byte("owner recovery key"))
	ownerRow := fixture.view.members[net.owner]
	ownerRow.RecoveryKeySha256 = ownerKey[:]
	ownerRow.Bindings = []*bridge.RecoveryBindingRow{{KeySha256: ownerKey[:], Signer: net.ownerDevice.Bytes(), At: fixture.next()}}

	net.tag = fixture.tag(net.owner)
	net.otherTag = fixture.tag(net.owner)
	delegationId := sha256.Sum256([]byte("gkm holders test delegation"))
	net.delegation = &bridge.DelegationRow{
		DelegationId: delegationId[:],
		Signer:       net.ownerDevice.Bytes(),
		At:           fixture.next(),
		TagAtoms:     [][]byte{net.tag.Bytes()},
		NotAfter:     aclTestNow.Add(30 * 24 * time.Hour).UnixMilli(),
	}
	net.delegations = []*bridge.DelegationRow{net.delegation}

	net.coveredAgent = fixture.agent(net.owner, net.tag)
	fixture.admission(net.coveredAgent).Row.DelegationId = net.delegation.GetDelegationId()
	fixture.admission(net.coveredAgent).Row.NotAfter = net.delegation.GetNotAfter() + int64(24*time.Hour/time.Millisecond)
	net.ephemeralAgent = fixture.agent(net.owner, net.tag)
	fixture.admission(net.ephemeralAgent).Row.DelegationId = net.delegation.GetDelegationId()
	fixture.admission(net.ephemeralAgent).Row.NotAfter = aclTestNow.Add(time.Hour).UnixMilli()
	fixture.admission(net.ephemeralAgent).Ephemeral = true
	net.uncoveredAgent = fixture.agent(net.owner, net.otherTag)
	fixture.admission(net.uncoveredAgent).Row.NotAfter = aclTestNow.Add(7 * 24 * time.Hour).UnixMilli()

	net.configId, _ = fixture.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	net.repoId, _ = fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	net.outsideId, _ = fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(net.repoId)},
		protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE)
	fixture.rule([]Id{net.tag}, []*protocol.AclTarget{aclRepoTarget(net.repoId)}, protocol.AclAction_ACL_ACTION_READ)
	net.otherTagRule = fixture.rule([]Id{net.otherTag}, []*protocol.AclTarget{aclRepoTarget(net.repoId)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule([]Id{fixture.sidecarAtom(net.coveredAgent)}, []*protocol.AclTarget{aclRepoTarget(net.outsideId)}, protocol.AclAction_ACL_ACTION_READ)
	// the ephemeral agent reads within §8.6's ceiling: the rule names its tag
	return net
}

// The state at a position.
func (self *gkmTestNet) view(t testing.TB, version uint64) *gkmTestView {
	return newGkmTestView(t, self.fixture, self.delegations, version)
}

// A repo's row in the fixture, to change in place.
func (self *gkmTestNet) repoRow(repoId Id) *protocol.AclRepo {
	for _, row := range self.fixture.rows.GetRepos() {
		if Id(row.GetRepoId()) == repoId {
			return row
		}
	}
	return nil
}

// KeyHolders, failing the test on a refusal.
func gkmTestHolders(t testing.TB, view GkmAuthView, repoId Id, at time.Time) GkmHolders {
	t.Helper()
	holders, err := KeyHolders(view, repoId, at)
	if err != nil {
		t.Fatalf("KeyHolders: %v", err)
	}
	return holders
}

// A holder's identity as text, for messages and set comparisons.
func gkmTestIdentity(kind GkmHolderKind, id []byte) string {
	return hex.EncodeToString(GkmHolder{Kind: kind, Id: id}.Identity())
}

// The identities of a set, as text.
func gkmTestIdentities(holders GkmHolders) []string {
	identities := []string{}
	for _, holder := range holders {
		identities = append(identities, hex.EncodeToString(holder.Identity()))
	}
	return identities
}

// Fails unless the set holds exactly these identities.
func gkmTestExpectHolders(t testing.TB, label string, holders GkmHolders, want ...string) {
	t.Helper()
	got := gkmTestIdentities(holders)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s: holders\n %s\nwant\n %s", label, strings.Join(got, "\n "), strings.Join(want, "\n "))
	}
}

// Every kind, each where §10.5 puts it: member devices as leaves, the owner's binding as recovery, the uncovered
// agent as itself, the covered agents under their Delegation, and the covered agent as itself where only its own
// grant reads.
func TestKeyHoldersOfEachKind(t *testing.T) {
	net := newGkmTestNet()
	view := net.view(t, 1)
	gkmTestExpectHolders(t, "repo", gkmTestHolders(t, view, net.repoId, aclTestNow),
		gkmTestIdentity(GkmHolderLeaf, net.ownerDevice.Bytes()),
		gkmTestIdentity(GkmHolderLeaf, net.memberDevice.Bytes()),
		gkmTestIdentity(GkmHolderAgent, net.uncoveredAgent.Bytes()),
		gkmTestIdentity(GkmHolderDelegation, net.delegation.GetDelegationId()),
		gkmTestIdentity(GkmHolderRecovery, net.owner.Bytes()),
	)
	gkmTestExpectHolders(t, "config", gkmTestHolders(t, view, net.configId, aclTestNow),
		gkmTestIdentity(GkmHolderLeaf, net.ownerDevice.Bytes()),
		gkmTestIdentity(GkmHolderLeaf, net.memberDevice.Bytes()),
		gkmTestIdentity(GkmHolderAgent, net.uncoveredAgent.Bytes()),
		gkmTestIdentity(GkmHolderDelegation, net.delegation.GetDelegationId()),
		gkmTestIdentity(GkmHolderRecovery, net.owner.Bytes()),
	)
	outside := gkmTestHolders(t, view, net.outsideId, aclTestNow)
	gkmTestExpectHolders(t, "outside", outside, gkmTestIdentity(GkmHolderAgent, net.coveredAgent.Bytes()))
	if !bytes.Equal(outside[0].AdmittingDelegationId, net.delegation.GetDelegationId()) {
		t.Errorf("an agent's admitting Delegation %x", outside[0].AdmittingDelegationId)
	}
	if !GkmCovered(view, net.coveredAgent, net.repoId, aclTestNow) || GkmCovered(view, net.coveredAgent, net.outsideId, aclTestNow) {
		t.Errorf("covered(s, R) must hold in the Delegation's reach and only there")
	}
	if GkmCovered(view, net.uncoveredAgent, net.repoId, aclTestNow) || GkmCovered(view, net.memberDevice, net.repoId, aclTestNow) {
		t.Errorf("no Delegation admitted these")
	}
}

// Identities are the kind byte then the id, and holders_sha256 hashes them sorted by bytes and joined with nothing
// between (QD-465). The digest was computed apart from this code, by shasum -a 256 and by Python's hashlib over the
// hex below joined.
func TestKeyHoldersSha256FixedVector(t *testing.T) {
	sidecarIdA, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	sidecarIdB, _ := hex.DecodeString("ff0102030405060708090a0b0c0d0e0f")
	delegationId, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	memberId, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f")
	holders := GkmHolders{
		{Kind: GkmHolderLeaf, Id: sidecarIdA},
		{Kind: GkmHolderLeaf, Id: sidecarIdB},
		{Kind: GkmHolderAgent, Id: sidecarIdA},
		{Kind: GkmHolderDelegation, Id: delegationId},
		{Kind: GkmHolderRecovery, Id: memberId},
	}
	wantIdentities := []string{
		"01000102030405060708090a0b0c0d0e0f",
		"01ff0102030405060708090a0b0c0d0e0f",
		"02000102030405060708090a0b0c0d0e0f",
		"03202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"04101112131415161718191a1b1c1d1e1f",
	}
	if got := gkmTestIdentities(holders); !slices.Equal(got, wantIdentities) {
		t.Fatalf("identities %v", got)
	}
	const want = "b54c2c66c907801338bb3e9d347dc364660f1d8575d26e7209bcfb6f5de37ecd"
	if got := hex.EncodeToString(holders.Sha256()); got != want {
		t.Errorf("holders_sha256 %s, want %s", got, want)
	}
	empty := sha256.Sum256(nil)
	if got := (GkmHolders{}).Sha256(); !bytes.Equal(got, empty[:]) {
		t.Errorf("no holders: %x", got)
	}
}

// The order KeyHolders gives is the order holders_sha256 hashes, whatever order the state lists things in.
func TestKeyHoldersSortByIdentityBytes(t *testing.T) {
	net := newGkmTestNet()
	for range 8 {
		agent := net.fixture.agent(net.owner, net.otherTag)
		net.fixture.admission(agent).Row.NotAfter = aclTestNow.Add(time.Hour).UnixMilli()
		net.fixture.device(net.member)
	}
	holders := gkmTestHolders(t, net.view(t, 1), net.repoId, aclTestNow)
	identities := [][]byte{}
	for _, holder := range holders {
		identities = append(identities, holder.Identity())
	}
	if !slices.IsSortedFunc(identities, bytes.Compare) {
		t.Errorf("not sorted by bytes.Compare")
	}
	joined := sha256.Sum256(bytes.Join(identities, nil))
	if !bytes.Equal(holders.Sha256(), joined[:]) {
		t.Errorf("holders_sha256 is not the sorted identities joined")
	}
}

// A Delegation is live until it ends, its key drops, a cascade voids it or its not_after passes, and the config
// reaches every live one.
func TestGkmDelegationLive(t *testing.T) {
	net := newGkmTestNet()
	notAfter := time.UnixMilli(net.delegation.GetNotAfter())
	cases := []struct {
		name   string
		change func(row *bridge.DelegationRow)
		void   bool
		at     time.Time
		live   bool
	}{
		{name: "live", at: aclTestNow, live: true},
		{name: "a ms before its not_after", at: notAfter.Add(-time.Millisecond), live: true},
		{name: "at its not_after", at: notAfter},
		{name: "ended", change: func(row *bridge.DelegationRow) { row.EndedAt = 9 }, at: aclTestNow},
		{name: "key dropped", change: func(row *bridge.DelegationRow) { row.KeyDroppedAt = 9 }, at: aclTestNow},
		{name: "no not_after", change: func(row *bridge.DelegationRow) { row.NotAfter = 0 }, at: aclTestNow},
		{name: "short id", change: func(row *bridge.DelegationRow) { row.DelegationId = row.DelegationId[:16] }, at: aclTestNow},
		{name: "voided", void: true, at: aclTestNow},
	}
	for _, c := range cases {
		net := newGkmTestNet()
		if c.change != nil {
			c.change(net.delegation)
		}
		if c.void {
			net.fixture.view.voidFrom[string(net.delegation.GetSigner())] = 1
		}
		view := net.view(t, 1)
		if live := GkmDelegationLive(view, net.delegation, c.at); live != c.live {
			t.Errorf("%s: live %t", c.name, live)
		}
		holdsConfig := gkmTestHolders(t, view, net.configId, c.at).Contains(GkmHolderDelegation, net.delegation.GetDelegationId())
		if holdsConfig != c.live {
			t.Errorf("%s: a holder of the config %t", c.name, holdsConfig)
		}
	}
}

// reach(d) holds the config and the directory, and a repo only while a grant naming one of d's tags reads it: an
// autogroup:tagged grant is outside it (FS-18), and so is a grant to one agent's own sidecar.
func TestGkmDelegationReach(t *testing.T) {
	net := newGkmTestNet()
	directoryId, _ := net.fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	taggedId, _ := net.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	net.fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), []*protocol.AclTarget{aclRepoTarget(taggedId)},
		protocol.AclAction_ACL_ACTION_READ)
	expiringId, _ := net.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	expiring := net.fixture.rule([]Id{net.tag}, []*protocol.AclTarget{aclRepoTarget(expiringId)}, protocol.AclAction_ACL_ACTION_WRITE)
	expiring.Expires = aclTestNow.Add(time.Hour).UnixMilli()
	view := net.view(t, 1)
	cases := []struct {
		repoId  Id
		at      time.Time
		reaches bool
	}{
		{repoId: net.configId, at: aclTestNow, reaches: true},
		{repoId: directoryId, at: aclTestNow, reaches: true},
		{repoId: net.repoId, at: aclTestNow, reaches: true},
		{repoId: net.outsideId, at: aclTestNow},
		{repoId: taggedId, at: aclTestNow},
		{repoId: expiringId, at: aclTestNow, reaches: true},
		{repoId: expiringId, at: aclTestNow.Add(time.Hour)},
		{repoId: NewId(), at: aclTestNow},
	}
	for i, c := range cases {
		if reaches := GkmDelegationReaches(view, net.delegation, c.repoId, c.at); reaches != c.reaches {
			t.Errorf("case %d: reaches %t", i, reaches)
		}
	}
	// the tagged-only repo: the non-ephemeral agent reads it in its own right, the ephemeral one not at all
	gkmTestExpectHolders(t, "tagged only", gkmTestHolders(t, view, taggedId, aclTestNow),
		gkmTestIdentity(GkmHolderAgent, net.coveredAgent.Bytes()),
		gkmTestIdentity(GkmHolderAgent, net.uncoveredAgent.Bytes()),
	)
}

// recovery(m) needs a member device of m reading R and m's newest binding in effect and outside every cascade: a
// binding a void restored is in effect but takes no wrap (§7.9's cascade).
func TestKeyHoldersRecoveryNeedsACurrentBinding(t *testing.T) {
	recoveryOf := func(net *gkmTestNet) bool {
		return gkmTestHolders(t, net.view(t, 1), net.repoId, aclTestNow).Contains(GkmHolderRecovery, net.owner.Bytes())
	}
	net := newGkmTestNet()
	if !recoveryOf(net) {
		t.Errorf("a current binding holds no key")
	}

	net = newGkmTestNet()
	ownerRow := net.fixture.view.members[net.owner]
	ownerRow.RecoveryKeySha256 = nil
	ownerRow.Bindings = nil
	if recoveryOf(net) {
		t.Errorf("no binding holds a key")
	}

	// a newer binding signed in a cascade's P is void, and the older one it restores is not current
	net = newGkmTestNet()
	ownerRow = net.fixture.view.members[net.owner]
	older := ownerRow.Bindings[0]
	voidKey := sha256.Sum256([]byte("void recovery key"))
	thief := NewId()
	ownerRow.Bindings = []*bridge.RecoveryBindingRow{{KeySha256: voidKey[:], Signer: thief.Bytes(), At: 40}, older}
	ownerRow.RecoveryKeySha256 = older.GetKeySha256()
	net.fixture.view.voidFrom[string(thief.Bytes())] = 30
	if recoveryOf(net) {
		t.Errorf("a binding a void restored holds a key")
	}
	// re-signed outside P, it is current again
	ownerRow.Bindings = append([]*bridge.RecoveryBindingRow{{KeySha256: older.GetKeySha256(), Signer: net.ownerDevice.Bytes(), At: 50}}, ownerRow.Bindings...)
	if !recoveryOf(net) {
		t.Errorf("a binding re-signed outside P holds no key")
	}

	// a newest binding the cascade voids, though no older one is in effect either
	net = newGkmTestNet()
	net.fixture.view.voidFrom[string(net.ownerDevice.Bytes())] = 1
	if recoveryOf(net) {
		t.Errorf("a voided binding holds a key")
	}

	// a member reading through no member device is no recovery holder
	net = newGkmTestNet()
	net.fixture.admission(net.ownerDevice).Row.RevokedAt = 9
	if recoveryOf(net) {
		t.Errorf("a member with no reading device holds a key")
	}
}

// A repo the state does not hold, and a reader the state holds no row for, refuse.
func TestKeyHoldersRefusesWhatTheStateCannotAnswer(t *testing.T) {
	net := newGkmTestNet()
	view := net.view(t, 1)
	if _, err := KeyHolders(view, NewId(), aclTestNow); !errors.Is(err, ErrGkmNoRepo) {
		t.Errorf("unknown repo: %v", err)
	}
	delete(view.view.sidecars, net.memberDevice)
	view.acl.sidecars = slices.Clone(view.acl.sidecars)
	if _, err := KeyHolders(view, net.repoId, aclTestNow); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a reader with no row: %v", err)
	}
}

// One change to the test network and what §10.5's event table and §10.6's lists say of it.
type gkmTestEvent struct {
	// §10.5's event table row, or empty for one only §10.6's lists name
	event string
	// §10.6's list and entry: shrinks, expiries or never
	list  string
	entry string
	// changes the network before the generation, at position 1; nil for none
	setup func(net *gkmTestNet)
	// changes the network for position 2; nil when only time moves
	change func(net *gkmTestNet)
	// how far time moves from the generation to the judgement
	elapsed time.Duration
	// the repo judged; nil for repoId
	repo func(net *gkmTestNet) Id
	// identities KeyHolders loses and gains
	dropped func(net *gkmTestNet) []string
	added   func(net *gkmTestNet) []string
	// a compromise retirement: a shrink whose identity stays (§7.9)
	compromise bool
}

// §10.5's event table and §10.6's lists, one row per event, on the test network.
func gkmTestEvents() []gkmTestEvent {
	none := func(net *gkmTestNet) []string { return nil }
	revoke := func(sidecarId func(net *gkmTestNet) Id) func(net *gkmTestNet) {
		return func(net *gkmTestNet) { net.fixture.admission(sidecarId(net)).Row.RevokedAt = 2 }
	}
	suspend := func(sidecarId func(net *gkmTestNet) Id) func(net *gkmTestNet) {
		return func(net *gkmTestNet) {
			net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{
				Subject: sidecarId(net).Bytes(), SuspendId: NewId().Bytes(), SignerClass: 2, Signer: net.ownerDevice.Bytes(), At: 2,
			})
		}
	}
	coveredAgent := func(net *gkmTestNet) Id { return net.coveredAgent }
	ephemeralAgent := func(net *gkmTestNet) Id { return net.ephemeralAgent }
	uncoveredAgent := func(net *gkmTestNet) Id { return net.uncoveredAgent }
	memberDevice := func(net *gkmTestNet) Id { return net.memberDevice }
	outside := func(net *gkmTestNet) Id { return net.outsideId }
	agentIdentity := func(sidecarId func(net *gkmTestNet) Id) func(net *gkmTestNet) []string {
		return func(net *gkmTestNet) []string {
			return []string{gkmTestIdentity(GkmHolderAgent, sidecarId(net).Bytes())}
		}
	}
	delegationIdentity := func(net *gkmTestNet) []string {
		return []string{gkmTestIdentity(GkmHolderDelegation, net.delegation.GetDelegationId())}
	}
	grantedLeaf := func(net *gkmTestNet) []string {
		return []string{gkmTestIdentity(GkmHolderLeaf, net.granted.Bytes())}
	}
	bothAgents := func(net *gkmTestNet) []string {
		return []string{gkmTestIdentity(GkmHolderAgent, net.coveredAgent.Bytes()), gkmTestIdentity(GkmHolderAgent, net.ephemeralAgent.Bytes())}
	}
	return []gkmTestEvent{
		{
			event: "reap of a covered agent", list: "never", entry: "reaps of covered agents",
			change: revoke(coveredAgent), dropped: none, added: none,
		},
		{
			event: "reap of a covered agent, in a repo its own grant reads", list: "shrinks", entry: "SidecarRevoke",
			change: revoke(coveredAgent), repo: outside, dropped: agentIdentity(coveredAgent), added: none,
		},
		{
			event: "a covered ephemeral agent's not_after passing", list: "never", entry: "ephemeral agents' own not_after where covered",
			elapsed: 2 * time.Hour, dropped: none, added: none,
		},
		{
			event: "reap of an uncovered agent", list: "shrinks", entry: "api's reap of an ephemeral sidecar no live Delegation covers",
			change: func(net *gkmTestNet) {
				net.fixture.admission(net.uncoveredAgent).Ephemeral = true
				net.fixture.admission(net.uncoveredAgent).Row.RevokedAt = 2
			},
			dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			event: "revocation of an uncovered agent", list: "shrinks", entry: "SidecarRevoke",
			change: revoke(uncoveredAgent), dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			event: "Suspend of an uncovered agent", list: "shrinks", entry: "Suspend",
			change: suspend(uncoveredAgent), dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			event: "DelegationRevoke", list: "shrinks", entry: "DelegationRevoke",
			change:  func(net *gkmTestNet) { net.delegation.EndedAt = 2; net.delegation.KeyDroppedAt = 2 },
			dropped: delegationIdentity, added: bothAgents,
		},
		{
			event: "DelegationRevoke with since_n > 0", list: "shrinks", entry: "a leaked bundle's DelegationRevoke with since_n > 0",
			change: func(net *gkmTestNet) {
				net.delegation.EndedAt = 2
				net.delegation.KeyDroppedAt = 2
				net.fixture.view.parked[net.ephemeralAgent] = true
			},
			dropped: delegationIdentity, added: agentIdentity(coveredAgent),
		},
		{
			// the covered agent's own admission outlives its Delegation's by a day, so it reads on uncovered
			event: "a Delegation's not_after passing", list: "expiries", entry: "a Delegation's not_after",
			setup: func(net *gkmTestNet) {
				net.fixture.admission(net.uncoveredAgent).Row.NotAfter = aclTestNow.Add(60 * 24 * time.Hour).UnixMilli()
			},
			elapsed: 30*24*time.Hour + time.Hour, dropped: delegationIdentity, added: agentIdentity(coveredAgent),
		},
		{
			event: "Suspend of a sidecar d admitted", list: "shrinks", entry: "a Delegation's key drop",
			change:  func(net *gkmTestNet) { suspend(coveredAgent)(net); net.delegation.KeyDroppedAt = 2 },
			dropped: delegationIdentity, added: agentIdentity(ephemeralAgent),
		},
		{
			event: "SidecarRevoke for lost of a sidecar d admitted", list: "shrinks", entry: "a Delegation's key drop",
			change:  func(net *gkmTestNet) { revoke(coveredAgent)(net); net.delegation.KeyDroppedAt = 2 },
			dropped: delegationIdentity, added: agentIdentity(ephemeralAgent),
		},
		{
			event: "SidecarRevoke{compromise} of a sidecar d admitted", list: "shrinks", entry: "SidecarRevoke with reason compromise",
			change: func(net *gkmTestNet) {
				revoke(coveredAgent)(net)
				net.delegation.EndedAt = 2
				net.delegation.KeyDroppedAt = 2
				net.fixture.view.parked[net.ephemeralAgent] = true
			},
			dropped: delegationIdentity, added: none,
		},
		{
			event: "SidecarRevoke{compromise} whose closure voids d", list: "shrinks", entry: "parks",
			change: func(net *gkmTestNet) {
				net.fixture.view.voidFrom[string(net.ownerDevice.Bytes())] = 1
				net.delegation.KeyDroppedAt = 2
				net.fixture.view.parked[net.coveredAgent] = true
				net.fixture.view.parked[net.ephemeralAgent] = true
			},
			// the owner's binding, which the voided device signed, is void too
			dropped: func(net *gkmTestNet) []string {
				return append(delegationIdentity(net), gkmTestIdentity(GkmHolderRecovery, net.owner.Bytes()))
			},
			added: none,
		},
		{
			event: "an uncovered agent's SidecarAdmit not_after passing", list: "expiries", entry: "an uncovered agent's SidecarAdmit",
			elapsed: 7 * 24 * time.Hour, dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			event: "a requested grant expiring", list: "expiries", entry: "requested grants' expires",
			setup:   func(net *gkmTestNet) { net.otherTagRule.Expires = aclTestNow.Add(time.Hour).UnixMilli() },
			elapsed: time.Hour, dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			event: "a RepoGrant expiring", list: "expiries", entry: "RepoGrant's expires",
			setup:   func(net *gkmTestNet) { net.grantOutside(aclTestNow.Add(time.Hour).UnixMilli()) },
			elapsed: time.Hour, repo: outside, dropped: grantedLeaf, added: none,
		},
		{
			event: "RecoveryRebind{compromise}", list: "shrinks", entry: "RecoveryRebind with reason compromise",
			change: func(net *gkmTestNet) {
				ownerRow := net.fixture.view.members[net.owner]
				rebound := sha256.Sum256([]byte("rebound recovery key"))
				ownerRow.Bindings = append([]*bridge.RecoveryBindingRow{{
					KeySha256: rebound[:], Signer: net.ownerDevice.Bytes(), At: 2,
					Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE,
				}}, ownerRow.Bindings...)
				ownerRow.RecoveryKeySha256 = rebound[:]
			},
			dropped: none, added: none, compromise: true,
		},
		{
			event: "removal of a member device", list: "shrinks", entry: "MemberRevoke",
			change: func(net *gkmTestNet) { delete(net.fixture.view.members, net.member) },
			dropped: func(net *gkmTestNet) []string {
				return []string{gkmTestIdentity(GkmHolderLeaf, net.memberDevice.Bytes())}
			},
			added: none,
		},
		{
			event: "SidecarRevoke of a member device", list: "shrinks", entry: "SidecarRevoke",
			change: revoke(memberDevice),
			dropped: func(net *gkmTestNet) []string {
				return []string{gkmTestIdentity(GkmHolderLeaf, net.memberDevice.Bytes())}
			},
			added: none,
		},
		{
			event: "ReaderKey lapse or replacement; a move between leaf and wrap", list: "never", entry: "a member device's move between leaf and wrap",
			change: func(net *gkmTestNet) {
				net.fixture.admission(net.memberDevice).Row.LiveSince = 2
			},
			elapsed: 8 * 24 * time.Hour / 7, dropped: none, added: none,
		},
		{
			list: "shrinks", entry: "park",
			change:  func(net *gkmTestNet) { net.fixture.view.parked[net.uncoveredAgent] = true },
			dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			list: "shrinks", entry: "GrantRevoke of a grant that reads",
			change: func(net *gkmTestNet) {
				net.fixture.rows.Rules = slices.DeleteFunc(net.fixture.rows.Rules, func(rule *protocol.AclRule) bool { return rule == net.otherTagRule })
			},
			dropped: agentIdentity(uncoveredAgent), added: none,
		},
		{
			list: "shrinks", entry: "RepoRevoke of a grant that reads",
			setup: func(net *gkmTestNet) { net.grantOutside(0) },
			change: func(net *gkmTestNet) {
				row := net.repoRow(net.outsideId)
				row.Revokes = append(row.Revokes, &protocol.AclRepoRevokeRow{Subject: net.granted.Bytes(), Signer: net.ownerDevice.Bytes(), At: 2})
			},
			repo: outside, dropped: grantedLeaf, added: none,
		},
		{
			list: "never", entry: "admissions",
			change:  func(net *gkmTestNet) { net.fixture.device(net.member) },
			dropped: none, added: func(net *gkmTestNet) []string {
				return []string{gkmTestIdentity(GkmHolderLeaf, net.gkmTestNewest().Bytes())}
			},
		},
		{
			list: "never", entry: "grants",
			change: func(net *gkmTestNet) {
				net.fixture.rule([]Id{net.tag}, []*protocol.AclTarget{aclRepoTarget(net.outsideId)}, protocol.AclAction_ACL_ACTION_READ)
			},
			// the grant brings the covered agent under its Delegation there: it reads on by the Delegation's key
			repo: outside, dropped: none, added: delegationIdentity,
		},
		{
			list: "never", entry: "Unsuspend",
			change: func(net *gkmTestNet) {
				net.fixture.rows.Suspensions = nil
			},
			dropped: none, added: none,
		},
		{
			list: "never", entry: "routine RecoveryRebinds",
			change: func(net *gkmTestNet) {
				ownerRow := net.fixture.view.members[net.owner]
				routine := sha256.Sum256([]byte("routine recovery key"))
				ownerRow.Bindings = append([]*bridge.RecoveryBindingRow{{
					KeySha256: routine[:], Signer: net.ownerDevice.Bytes(), At: 2,
					Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE,
				}}, ownerRow.Bindings...)
				ownerRow.RecoveryKeySha256 = routine[:]
			},
			dropped: none, added: none,
		},
	}
}

// The sidecar the fixture admitted last.
func (self *gkmTestNet) gkmTestNewest() Id {
	newest := Id{}
	newestAt := uint64(0)
	for sidecarId, sidecar := range self.fixture.view.sidecars {
		if newestAt < sidecar.Row.GetAdmittedAt() {
			newest, newestAt = sidecarId, sidecar.Row.GetAdmittedAt()
		}
	}
	return newest
}

// Runs one event: a generation claimed at position 1 and aclTestNow, the event at position 2, judged elapsed later.
// It checks what KeyHolders drops and gains, and, with holders_shrunk_at advanced as TEAM would (by
// GkmHoldersDropped, or for a compromise retirement), that the gate shuts and REMOVE is due exactly when the event
// shrinks or expires a holder.
func gkmTestRunEvent(t *testing.T, event gkmTestEvent) (shrinks bool, expires bool) {
	t.Helper()
	label := event.event
	if label == "" {
		label = event.list + ": " + event.entry
	}
	net := newGkmTestNet()
	repoOf := func(net *gkmTestNet) Id {
		if event.repo != nil {
			return event.repo(net)
		}
		return net.repoId
	}
	if event.setup != nil {
		event.setup(net)
	}
	repoId := repoOf(net)
	before := net.view(t, 1)
	generationTime := aclTestNow
	now := generationTime.Add(event.elapsed)
	beforeHolders := gkmTestHolders(t, before, repoId, generationTime)

	if event.change != nil {
		event.change(net)
	}
	after := net.view(t, 2)
	afterHolders := gkmTestHolders(t, after, repoId, generationTime)
	nowHolders := gkmTestHolders(t, after, repoId, now)

	// an entry's change is judged at its own time; time's at the judgement
	changed := afterHolders
	if event.change == nil {
		changed = nowHolders
	}
	dropped := gkmTestIdentities(beforeHolders.Dropped(changed))
	added := []string{}
	for _, holder := range changed {
		if !beforeHolders.Contains(holder.Kind, holder.Id) {
			added = append(added, hex.EncodeToString(holder.Identity()))
		}
	}
	wantDropped, wantAdded := event.dropped(net), event.added(net)
	slices.Sort(wantDropped)
	slices.Sort(wantAdded)
	if !slices.Equal(dropped, wantDropped) && !(len(dropped) == 0 && len(wantDropped) == 0) {
		t.Errorf("%s: dropped %v, want %v", label, dropped, wantDropped)
	}
	if !slices.Equal(added, wantAdded) && !(len(added) == 0 && len(wantAdded) == 0) {
		t.Errorf("%s: added %v, want %v", label, added, wantAdded)
	}

	shrinks = event.change != nil && (0 < len(beforeHolders.Dropped(afterHolders)) || event.compromise)
	if shrinks {
		net.repoRow(repoId).HoldersShrunkAt = 2
		after = net.view(t, 2)
	}
	expires = !afterHolders.KeptBy(nowHolders)
	expired, err := GkmHolderExpired(after, repoId, generationTime, now)
	if err != nil || expired != expires {
		t.Errorf("%s: expired %t (%v), want %t", label, expired, err, expires)
	}

	closes := shrinks || expires
	if passes := GkmGatePasses(after, repoId, gkmTestPin(1), generationTime, now); passes == closes {
		t.Errorf("%s: gate passes %t for the generation before", label, passes)
	}
	if !GkmGatePasses(after, repoId, gkmTestPin(2), now, now) {
		t.Errorf("%s: a generation at the event's pin and the judgement's time does not pass", label)
	}
	due, err := GkmRemoveDue(after, repoId, gkmTestPin(1), generationTime, now)
	if err != nil || due != closes {
		t.Errorf("%s: REMOVE due %t (%v), want %t", label, due, err, closes)
	}
	return shrinks, expires
}

// §10.5's event table, every row asserted for the KeyHolders change, the gate and the rotation.
func TestKeyHoldersEventTable(t *testing.T) {
	for _, event := range gkmTestEvents() {
		if event.event == "" {
			continue
		}
		gkmTestRunEvent(t, event)
	}
}

// §10.6's shrinks, expiries and never lists, one row each: each shrinks, expires or does neither as its list says.
func TestKeyHoldersShrinkExpiryAndNeverLists(t *testing.T) {
	entries := map[string]bool{}
	for _, event := range gkmTestEvents() {
		shrinks, expires := gkmTestRunEvent(t, event)
		entries[event.list+": "+event.entry] = true
		switch event.list {
		case "shrinks":
			if !shrinks || expires {
				t.Errorf("%s: shrinks %t, expires %t", event.entry, shrinks, expires)
			}
		case "expiries":
			if shrinks || !expires {
				t.Errorf("%s: shrinks %t, expires %t", event.entry, shrinks, expires)
			}
		case "never":
			if shrinks || expires {
				t.Errorf("%s: shrinks %t, expires %t", event.entry, shrinks, expires)
			}
		default:
			t.Errorf("%s: no list %q", event.entry, event.list)
		}
	}
	for _, entry := range []string{
		"shrinks: SidecarRevoke", "shrinks: MemberRevoke", "shrinks: parks", "shrinks: park",
		"shrinks: api's reap of an ephemeral sidecar no live Delegation covers", "shrinks: Suspend",
		"shrinks: GrantRevoke of a grant that reads", "shrinks: RepoRevoke of a grant that reads",
		"shrinks: DelegationRevoke", "shrinks: a Delegation's key drop", "shrinks: SidecarRevoke with reason compromise",
		"shrinks: RecoveryRebind with reason compromise", "shrinks: a leaked bundle's DelegationRevoke with since_n > 0",
		"expiries: RepoGrant's expires", "expiries: requested grants' expires",
		"expiries: an uncovered agent's SidecarAdmit", "expiries: a Delegation's not_after",
		"never: admissions", "never: grants", "never: Unsuspend", "never: routine RecoveryRebinds",
		"never: reaps of covered agents", "never: ephemeral agents' own not_after where covered",
		"never: a member device's move between leaf and wrap",
	} {
		if !entries[entry] {
			t.Errorf("no row for %q", entry)
		}
	}
}

// At position n_r = holders_shrunk_at and at T_e: a generation at n_r covers the shrink and one a position below does
// not; one timed at T_e covers the expiry and one a ms before does not.
func TestKeyHoldersBoundariesAtTheShrinkAndTheExpiry(t *testing.T) {
	net := newGkmTestNet()
	net.fixture.admission(net.uncoveredAgent).Row.RevokedAt = 5
	net.repoRow(net.repoId).HoldersShrunkAt = 5
	view := net.view(t, 6)
	now := aclTestNow
	if !GkmGatePasses(view, net.repoId, gkmTestPin(5), now, now) {
		t.Errorf("n_g = n_r does not cover")
	}
	if GkmGatePasses(view, net.repoId, gkmTestPin(4), now, now) {
		t.Errorf("n_g = n_r - 1 covers")
	}

	net = newGkmTestNet()
	view = net.view(t, 1)
	expiry := time.UnixMilli(net.fixture.admission(net.uncoveredAgent).Row.GetNotAfter())
	if passes := GkmGatePasses(view, net.repoId, gkmTestPin(1), expiry, expiry); !passes {
		t.Errorf("t_g = T_e does not cover")
	}
	if passes := GkmGatePasses(view, net.repoId, gkmTestPin(1), expiry.Add(-time.Millisecond), expiry); passes {
		t.Errorf("t_g = T_e - 1 ms covers")
	}
	if passes := GkmGatePasses(view, net.repoId, gkmTestPin(1), expiry.Add(-time.Millisecond), expiry.Add(-time.Millisecond)); !passes {
		t.Errorf("the gate shuts before T_e")
	}
	at, found, err := GkmHolderExpiry(view, net.repoId, aclTestNow, expiry.Add(time.Hour))
	if err != nil || !found || !at.Equal(expiry) {
		t.Errorf("first expiry %v %t %v, want %v", at, found, err, expiry)
	}
}

// The bisected first expiry equals a scan of every ms: expiries a few ms apart, of an agent's admission, a
// requested grant and a Delegation, judged from several starts.
func TestGkmHolderExpiryMatchesAScanOfEveryInstant(t *testing.T) {
	net := newGkmTestNet()
	base := aclTestNow.UnixMilli()
	net.fixture.admission(net.uncoveredAgent).Row.NotAfter = base + 151
	net.otherTagRule.Expires = base + 90
	extra := net.fixture.agent(net.owner, net.otherTag)
	net.fixture.admission(extra).Row.NotAfter = base + 37
	net.delegation.NotAfter = base + 120
	net.fixture.admission(net.coveredAgent).Row.NotAfter = base + 400
	net.fixture.admission(net.ephemeralAgent).Row.NotAfter = base + 400
	view := net.view(t, 1)
	scan := func(afterMs int64, throughMs int64) (int64, bool) {
		first := gkmTestHolders(t, view, net.repoId, time.UnixMilli(afterMs))
		for ms := afterMs + 1; ms <= throughMs; ms += 1 {
			if !first.KeptBy(gkmTestHolders(t, view, net.repoId, time.UnixMilli(ms))) {
				return ms, true
			}
		}
		return 0, false
	}
	for _, window := range [][2]int64{{0, 200}, {37, 200}, {38, 89}, {89, 90}, {90, 119}, {120, 160}, {151, 300}, {0, 36}} {
		afterMs, throughMs := base+window[0], base+window[1]
		wantMs, wantFound := scan(afterMs, throughMs)
		at, found, err := GkmHolderExpiry(view, net.repoId, time.UnixMilli(afterMs), time.UnixMilli(throughMs))
		if err != nil || found != wantFound || (found && at.UnixMilli() != wantMs) {
			t.Errorf("(%d, %d]: %v %t %v, want %d %t", window[0], window[1], at.UnixMilli()-base, found, err, wantMs-base, wantFound)
		}
	}
}

// A seeded random walk of never-list events over random networks drops no holder of any repo (§10.6's never list):
// admissions, grants, Unsuspends, routine rebinds, the reap of an agent where its Delegation covers it, a covered
// ephemeral agent's not_after passing, and a move between leaf and wrap.
func TestGkmNeverEventsDropNoHolder(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for round := range 40 {
		net := newGkmTestNet()
		// a covered agent reading only inside its Delegation's reach, whose reap is no shrink anywhere
		insideAgent := net.fixture.agent(net.owner, net.tag)
		net.fixture.admission(insideAgent).Row.DelegationId = net.delegation.GetDelegationId()
		net.fixture.admission(insideAgent).Row.NotAfter = net.delegation.GetNotAfter()
		suspended := net.fixture.agent(net.owner, net.otherTag)
		net.fixture.admission(suspended).Row.NotAfter = aclTestNow.Add(48 * time.Hour).UnixMilli()
		net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{
			Subject: suspended.Bytes(), SuspendId: NewId().Bytes(), SignerClass: 2, Signer: net.ownerDevice.Bytes(), At: 1,
		})
		repoIds := []Id{net.configId, net.repoId, net.outsideId}
		version := uint64(1)
		previous := net.view(t, version)
		now := aclTestNow
		for step := range 12 {
			at := now
			switch random.IntN(8) {
			case 0:
				net.fixture.device(net.member)
			case 1:
				agent := net.fixture.agent(net.owner, net.otherTag)
				net.fixture.admission(agent).Row.NotAfter = aclTestNow.Add(72 * time.Hour).UnixMilli()
			case 2:
				repoId := repoIds[random.IntN(len(repoIds))]
				atoms := []Id{net.tag, net.otherTag, AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), net.fixture.sidecarAtom(net.coveredAgent)}
				net.fixture.rule([]Id{atoms[random.IntN(len(atoms))]}, []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_READ)
			case 3:
				net.fixture.rows.Suspensions = nil
			case 4:
				ownerRow := net.fixture.view.members[net.owner]
				key := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("routine"), uint64(step)))
				ownerRow.Bindings = append([]*bridge.RecoveryBindingRow{{
					KeySha256: key[:], Signer: net.ownerDevice.Bytes(), At: version + 1,
					Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE,
				}}, ownerRow.Bindings...)
				ownerRow.RecoveryKeySha256 = key[:]
			case 5:
				net.fixture.admission(insideAgent).Row.RevokedAt = version + 1
			case 6:
				// past the ephemeral agent's not_after, and no further
				at = aclTestNow.Add(time.Hour)
			case 7:
				net.fixture.admission(net.memberDevice).Row.LiveSince = version + 1
			}
			version += 1
			next := net.view(t, version)
			for _, repoId := range repoIds {
				before := gkmTestHolders(t, previous, repoId, now)
				after := gkmTestHolders(t, next, repoId, at)
				if dropped := before.Dropped(after); 0 < len(dropped) {
					t.Fatalf("round %d step %d: a never event dropped %v", round, step, gkmTestIdentities(dropped))
				}
			}
			previous, now = next, at
		}
	}
}

// KeyHolders over a real ConfigState, whose base rows carry the admissions, the Delegation and the acl: ConfigState
// answers what KeyHolders reads.
func TestKeyHoldersOverAConfigState(t *testing.T) {
	net := newTestConfigNet(t)
	device := net.device("member device", net.ownerMemberId)
	agentKey := testConfigDeviceKey("agent")
	agentId := testConfigId("agent")
	tagId := testConfigId("tag")
	configId := testConfigId("config repo")
	repoId := testConfigId("repo")
	delegationId := sha256.Sum256([]byte("config test delegation"))
	notAfter := net.timeMs + int64(30*24*time.Hour/time.Millisecond)
	recoveryKey := sha256.Sum256([]byte("owner recovery"))
	acl := &protocol.AclRows{
		HasDocument: true,
		Atoms:       []*protocol.AclAtom{{Atom: tagId.Bytes(), SidecarIds: [][]byte{agentId.Bytes()}, TagOwnerMemberIds: [][]byte{net.ownerMemberId.Bytes()}}},
		Rules: []*protocol.AclRule{
			{RuleId: testConfigId("member rule").Bytes(), SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
				Targets: []*protocol.AclTarget{{RepoId: repoId.Bytes()}}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)}},
			{RuleId: testConfigId("tag rule").Bytes(), SrcAtoms: [][]byte{tagId.Bytes()},
				Targets: []*protocol.AclTarget{{RepoId: repoId.Bytes()}}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)}},
		},
		Repos: []*protocol.AclRepo{
			{RepoId: configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG},
			{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		},
	}
	rows := net.statesAt[net.n].Rows()
	rows.Members[0].RecoveryKeySha256 = recoveryKey[:]
	rows.Members[0].Bindings = []*bridge.RecoveryBindingRow{{KeySha256: recoveryKey[:], Signer: net.owner.sidecarId.Bytes(), At: 1}}
	rows.Sidecars = append(rows.Sidecars,
		&bridge.SidecarRow{
			SidecarId: device.sidecarId.Bytes(), AdmissionSigners: [][]byte{net.owner.sidecarId.Bytes()}, AdmittedAt: 1,
			IdentityPublicKey: device.publicKey(), IdentityAlg: configIdentityAlgEd25519, MemberId: net.ownerMemberId.Bytes(),
		},
		&bridge.SidecarRow{
			SidecarId: agentId.Bytes(), AdmissionSigners: [][]byte{delegationId[:]}, AdmittedAt: 1, NotAfter: notAfter,
			IdentityPublicKey: agentKey.Public().(ed25519.PublicKey), IdentityAlg: configIdentityAlgEd25519, TagIds: [][]byte{tagId.Bytes()},
			DelegationId: delegationId[:], Sponsor: net.ownerMemberId.Bytes(),
		},
	)
	rows.Delegations = []*bridge.DelegationRow{{
		DelegationId: delegationId[:], Signer: net.owner.sidecarId.Bytes(), At: 1, TagAtoms: [][]byte{tagId.Bytes()}, NotAfter: notAfter,
	}}
	rows.Acl = testConfigMarshal(t, acl)
	if verdict := net.pushBase(net.owner, rows, 1, 2, 0); !verdict.Accepted() {
		t.Fatalf("base 2: %v", verdict.Refusal)
	}
	state := net.log.State()
	at := time.UnixMilli(state.TimeMs())
	want := []string{
		gkmTestIdentity(GkmHolderLeaf, net.owner.sidecarId.Bytes()),
		gkmTestIdentity(GkmHolderLeaf, device.sidecarId.Bytes()),
		gkmTestIdentity(GkmHolderDelegation, delegationId[:]),
		gkmTestIdentity(GkmHolderRecovery, net.ownerMemberId.Bytes()),
	}
	gkmTestExpectHolders(t, "repo", gkmTestHolders(t, state, repoId, at), want...)
	gkmTestExpectHolders(t, "config", gkmTestHolders(t, state, configId, at), want...)
	// past the Delegation's not_after its agent's admission has ended too, so the repo keeps only the members'
	gkmTestExpectHolders(t, "repo after the not_after", gkmTestHolders(t, state, repoId, time.UnixMilli(notAfter)), want[0], want[1], want[3])
	if !GkmGatePasses(state, repoId, state.Pin(), at, at) {
		t.Errorf("a generation at the state's own pin does not pass")
	}
	if GkmGatePasses(state, repoId, state.Pin(), at, time.UnixMilli(notAfter)) {
		t.Errorf("the gate passes past the Delegation's expiry")
	}
}
