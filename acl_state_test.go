// AclState's building blocks: a fake of the view TEAM's ConfigState implements, hand-made rows standing in
// for CompileAcl (ACL-M2-04), and what NewAclState refuses or reads past. Pure, on every leg.

package sidecar

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The time every check here runs at, unless a test moves it.
var aclTestNow = time.UnixMilli(1_800_000_000_000)

// One state's facts, as a test writes them.
type aclTestView struct {
	pin           *bridge.AuthPin
	genesis       *bridge.Genesis
	sidecars      map[Id]*AclSidecar
	members       map[Id]*bridge.MemberRow
	configWriters map[Id]bool
	parked        map[Id]bool
	// a tagged sidecar's live sponsor; absent once that member is removed
	sponsors map[Id]Id
	// a signer whose records are void from a position on, as a cascade's since_n voids them
	voidFrom map[string]uint64
	// devices §7.9's leaves rule entitles to a config or directory leaf; nil entitles none
	leafEntitled map[Id]bool
}

func (self *aclTestView) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *aclTestView) Genesis() *bridge.Genesis {
	return self.genesis
}

func (self *aclTestView) SidecarIds() []Id {
	sidecarIds := []Id{}
	for sidecarId := range self.sidecars {
		sidecarIds = append(sidecarIds, sidecarId)
	}
	return sidecarIds
}

func (self *aclTestView) Sidecar(sidecarId Id) *AclSidecar {
	return self.sidecars[sidecarId]
}

func (self *aclTestView) Member(memberId Id) *bridge.MemberRow {
	return self.members[memberId]
}

func (self *aclTestView) IsConfigWriter(sidecarId Id) bool {
	return self.configWriters[sidecarId]
}

func (self *aclTestView) Parked(sidecarId Id) bool {
	return self.parked[sidecarId]
}

func (self *aclTestView) Sponsor(sidecarId Id) (Id, bool) {
	sponsor, found := self.sponsors[sidecarId]
	return sponsor, found
}

func (self *aclTestView) CascadeVoids(signer []byte, at uint64) bool {
	since, found := self.voidFrom[string(signer)]
	return found && since <= at
}

func (self *aclTestView) LeafEntitled(sidecarId Id) bool {
	return self.leafEntitled[sidecarId]
}

// A state under construction: its view, its rows and the next log position.
type aclTestFixture struct {
	view     *aclTestView
	rows     *protocol.AclRows
	position uint64
}

func newAclTestFixture() *aclTestFixture {
	return &aclTestFixture{
		view: &aclTestView{
			pin:           &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
			sidecars:      map[Id]*AclSidecar{},
			members:       map[Id]*bridge.MemberRow{},
			configWriters: map[Id]bool{},
			parked:        map[Id]bool{},
			sponsors:      map[Id]Id{},
			voidFrom:      map[string]uint64{},
		},
		rows: &protocol.AclRows{HasDocument: true},
	}
}

// The next log position.
func (self *aclTestFixture) next() uint64 {
	self.position += 1
	return self.position
}

// A member of a role.
func (self *aclTestFixture) member(role bridge.MemberRole) Id {
	memberId := NewId()
	self.view.members[memberId] = &bridge.MemberRow{MemberId: memberId.Bytes(), Role: role}
	return memberId
}

// An untagged sidecar of a member, admitted at the next position by signers.
func (self *aclTestFixture) device(memberId Id, signers ...[]byte) Id {
	sidecarId := NewId()
	self.view.sidecars[sidecarId] = &AclSidecar{
		Row:      &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: self.next(), AdmissionSigners: signers},
		MemberId: memberId,
	}
	return sidecarId
}

// A tagged sidecar, its sponsor live.
func (self *aclTestFixture) agent(sponsorId Id, tagIds ...Id) Id {
	sidecarId := NewId()
	self.view.sidecars[sidecarId] = &AclSidecar{
		Row:    &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: self.next(), Sponsor: sponsorId.Bytes()},
		TagIds: tagIds,
	}
	self.view.sponsors[sidecarId] = sponsorId
	for _, atomRow := range self.rows.Atoms {
		for _, tagId := range tagIds {
			if Id(atomRow.Atom) == tagId {
				atomRow.SidecarIds = append(atomRow.SidecarIds, sidecarId.Bytes())
			}
		}
	}
	return sidecarId
}

// A sidecar's admission, to change in place.
func (self *aclTestFixture) admission(sidecarId Id) *AclSidecar {
	return self.view.sidecars[sidecarId]
}

// A new atom row.
func (self *aclTestFixture) atom(row *protocol.AclAtom) Id {
	atom := NewId()
	row.Atom = atom.Bytes()
	self.rows.Atoms = append(self.rows.Atoms, row)
	return atom
}

// A tag atom with its owners.
func (self *aclTestFixture) tag(ownerIds ...Id) Id {
	row := &protocol.AclAtom{}
	for _, ownerId := range ownerIds {
		row.TagOwnerMemberIds = append(row.TagOwnerMemberIds, ownerId.Bytes())
	}
	return self.atom(row)
}

// A group or user atom of members.
func (self *aclTestFixture) group(memberIds ...Id) Id {
	row := &protocol.AclAtom{}
	for _, memberId := range memberIds {
		row.MemberIds = append(row.MemberIds, memberId.Bytes())
	}
	return self.atom(row)
}

// A derived sidecar:<id> atom.
func (self *aclTestFixture) sidecarAtom(sidecarId Id) Id {
	return self.atom(&protocol.AclAtom{SidecarIds: [][]byte{sidecarId.Bytes()}})
}

// A rule: src atoms, targets and actions.
func (self *aclTestFixture) rule(srcAtoms []Id, targets []*protocol.AclTarget, actions ...protocol.AclAction) *protocol.AclRule {
	rule := &protocol.AclRule{RuleId: NewId().Bytes()}
	for _, atom := range srcAtoms {
		rule.SrcAtoms = append(rule.SrcAtoms, atom.Bytes())
	}
	rule.Targets = targets
	for _, action := range actions {
		rule.Actions = append(rule.Actions, uint32(action))
	}
	self.rows.Rules = append(self.rows.Rules, rule)
	return rule
}

// A repo of a kind, with an owner for an owner-bound one.
func (self *aclTestFixture) repo(kind protocol.RepoKind, ownerId Id) (Id, *protocol.AclRepo) {
	repoId := NewId()
	row := &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: kind}
	if ownerId != (Id{}) {
		row.OwnerMemberId = ownerId.Bytes()
	}
	self.rows.Repos = append(self.rows.Repos, row)
	return repoId, row
}

func (self *aclTestFixture) state(t testing.TB) *AclState {
	t.Helper()
	state, err := NewAclState(self.rows, self.view)
	if err != nil {
		t.Fatalf("NewAclState: %v", err)
	}
	return state
}

func aclAtomTarget(atom Id) *protocol.AclTarget {
	return &protocol.AclTarget{Atom: atom.Bytes()}
}

func aclAutogroupTarget(autogroup protocol.AclAutogroup) *protocol.AclTarget {
	return aclAtomTarget(AclAutogroupAtom(autogroup))
}

func aclSidecarTarget(sidecarId Id) *protocol.AclTarget {
	return &protocol.AclTarget{SidecarId: sidecarId.Bytes()}
}

func aclRepoTarget(repoId Id) *protocol.AclTarget {
	return &protocol.AclTarget{RepoId: repoId.Bytes()}
}

func aclWildcardRepoTarget() *protocol.AclTarget {
	return &protocol.AclTarget{RepoId: make([]byte, 16)}
}

func aclSocketRowTarget(prefix bool, tokenPaths ...[]byte) *protocol.AclTarget {
	return &protocol.AclTarget{SocketTokens: tokenPaths, SocketPrefix: prefix}
}

func aclCidrTarget(cidr string) *protocol.AclTarget {
	return &protocol.AclTarget{Cidr: AclRowsCidrBytes(netip.MustParsePrefix(cidr))}
}

// A token path of segments, each one byte repeated to §9.4's 16.
func aclTestTokenPath(segments ...byte) []byte {
	tokenPath := []byte{}
	for _, segment := range segments {
		for range aclSocketTokenByteCount {
			tokenPath = append(tokenPath, segment)
		}
	}
	return tokenPath
}

func autogroupAtoms(autogroups ...protocol.AclAutogroup) []Id {
	atoms := []Id{}
	for _, autogroup := range autogroups {
		atoms = append(atoms, AclAutogroupAtom(autogroup))
	}
	return atoms
}

// Each malformed form refuses to build, and names no value from the rows.
func TestNewAclStateRefusesMalformedRows(t *testing.T) {
	cases := []struct {
		name string
		edit func(fixture *aclTestFixture)
	}{
		{name: "short atom", edit: func(fixture *aclTestFixture) {
			fixture.rows.Atoms = append(fixture.rows.Atoms, &protocol.AclAtom{Atom: []byte{1, 2, 3}})
		}},
		{name: "repeated atom", edit: func(fixture *aclTestFixture) {
			atom := fixture.group()
			fixture.rows.Atoms = append(fixture.rows.Atoms, &protocol.AclAtom{Atom: atom.Bytes()})
		}},
		{name: "autogroup form atom row", edit: func(fixture *aclTestFixture) {
			atom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
			fixture.rows.Atoms = append(fixture.rows.Atoms, &protocol.AclAtom{Atom: atom.Bytes()})
		}},
		{name: "short member id", edit: func(fixture *aclTestFixture) {
			fixture.rows.Atoms = append(fixture.rows.Atoms, &protocol.AclAtom{Atom: NewId().Bytes(), MemberIds: [][]byte{{1}}})
		}},
		{name: "short src atom", edit: func(fixture *aclTestFixture) {
			fixture.rows.Rules = append(fixture.rows.Rules, &protocol.AclRule{SrcAtoms: [][]byte{{1}}})
		}},
		{name: "two target kinds", edit: func(fixture *aclTestFixture) {
			fixture.rule(nil, []*protocol.AclTarget{{SidecarId: NewId().Bytes(), MailSend: true}}, protocol.AclAction_ACL_ACTION_DIAL)
		}},
		{name: "ragged token path", edit: func(fixture *aclTestFixture) {
			fixture.rule(nil, []*protocol.AclTarget{aclSocketRowTarget(false, []byte{1, 2, 3})}, protocol.AclAction_ACL_ACTION_DIAL)
		}},
		{name: "empty exact token path", edit: func(fixture *aclTestFixture) {
			fixture.rule(nil, []*protocol.AclTarget{aclSocketRowTarget(false, []byte{})}, protocol.AclAction_ACL_ACTION_DIAL)
		}},
		{name: "cidr with host bits", edit: func(fixture *aclTestFixture) {
			fixture.rule(nil, []*protocol.AclTarget{{Cidr: []byte{10, 0, 0, 1, 8}}}, protocol.AclAction_ACL_ACTION_ROUTE)
		}},
		{name: "cidr of the wrong size", edit: func(fixture *aclTestFixture) {
			fixture.rule(nil, []*protocol.AclTarget{{Cidr: []byte{10, 0, 0}}}, protocol.AclAction_ACL_ACTION_ROUTE)
		}},
		{name: "short repo id", edit: func(fixture *aclTestFixture) {
			fixture.rows.Repos = append(fixture.rows.Repos, &protocol.AclRepo{RepoId: []byte{1}})
		}},
		{name: "wildcard repo row", edit: func(fixture *aclTestFixture) {
			fixture.rows.Repos = append(fixture.rows.Repos, &protocol.AclRepo{RepoId: make([]byte, 16)})
		}},
		{name: "repeated repo", edit: func(fixture *aclTestFixture) {
			_, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
			fixture.rows.Repos = append(fixture.rows.Repos, &protocol.AclRepo{RepoId: row.RepoId})
		}},
		{name: "short grant subject", edit: func(fixture *aclTestFixture) {
			_, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
			row.Grants = append(row.Grants, &protocol.AclRepoGrantRow{Subject: []byte{1}})
		}},
		{name: "short suspension subject", edit: func(fixture *aclTestFixture) {
			fixture.rows.Suspensions = append(fixture.rows.Suspensions, &protocol.AclSuspension{Subject: []byte{1}})
		}},
		{name: "too many atoms", edit: func(fixture *aclTestFixture) {
			for range aclRowsMaxAtomCount + 1 {
				fixture.group()
			}
		}},
	}
	for _, c := range cases {
		fixture := newAclTestFixture()
		c.edit(fixture)
		_, err := NewAclState(fixture.rows, fixture.view)
		if !errors.Is(err, ErrAclRowsInvalid) {
			t.Errorf("%s: err = %v, want ErrAclRowsInvalid", c.name, err)
		}
	}
	if _, err := NewAclState(nil, newAclTestFixture().view); !errors.Is(err, ErrAclRowsInvalid) {
		t.Errorf("no rows: err = %v", err)
	}
}

// What a later format adds, a target kind or an action value this code does not know, matches nothing, so
// an older reader never allows what it cannot read.
func TestAclStateReadsPastWhatALaterFormatAdds(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	source := fixture.device(owner)
	destination := fixture.device(owner)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{{}}, protocol.AclAction_ACL_ACTION_DIAL)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclSidecarTarget(destination)}, protocol.AclAction(99))
	state := fixture.state(t)
	if decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(destination), aclTestNow); decision.Allowed {
		t.Errorf("an unknown target or action allowed: %+v", decision)
	}
}

// A state answers its pin, document flag and repo rows, and the suspended set from its rows.
func TestAclStateAnswersItsRows(t *testing.T) {
	fixture := newAclTestFixture()
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	suspended := NewId()
	fixture.rows.Suspensions = []*protocol.AclSuspension{{Subject: suspended.Bytes(), SuspendId: NewId().Bytes(), SignerClass: 2}}
	fixture.rows.HasDocument = false
	state := fixture.state(t)
	if state.Pin().GetVersion() != 1 || state.HasDocument() || state.Repo(repoId) != row || state.Repo(NewId()) != nil {
		t.Errorf("pin %v, has_document %t, repo %v", state.Pin(), state.HasDocument(), state.Repo(repoId))
	}
	if !state.Suspended(suspended) || state.Suspended(NewId()) {
		t.Error("suspensions misread")
	}
	if state.Rows() != fixture.rows {
		t.Error("rows not kept")
	}
}

// Each class of subject before it is expanded (D-ACL-19).
func TestAclStateClassesEachSubject(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	memberDevice := fixture.device(owner)
	ephemeral := fixture.device(owner)
	fixture.admission(ephemeral).Ephemeral = true
	tagged := fixture.agent(owner, tagId)
	taggedEphemeral := fixture.agent(owner, tagId)
	fixture.admission(taggedEphemeral).Ephemeral = true
	neither := NewId()
	fixture.view.sidecars[neither] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: neither.Bytes()}}
	both := NewId()
	fixture.view.sidecars[both] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: both.Bytes()}, MemberId: owner, TagIds: []Id{tagId}}
	state := fixture.state(t)
	cases := []struct {
		sidecarId Id
		class     AclSubjectClass
		valid     bool
	}{
		{sidecarId: memberDevice, class: AclSubjectClassMemberDevice, valid: true},
		{sidecarId: ephemeral, class: AclSubjectClassEphemeral, valid: true},
		{sidecarId: tagged, class: AclSubjectClassTagged, valid: true},
		{sidecarId: taggedEphemeral, class: AclSubjectClassEphemeral, valid: true},
		{sidecarId: neither, class: AclSubjectClassOther, valid: false},
		{sidecarId: both, class: AclSubjectClassOther, valid: false},
	}
	for _, c := range cases {
		sidecar := state.sidecarState(c.sidecarId)
		if sidecar == nil || sidecar.class != c.class || sidecar.valid != c.valid {
			t.Errorf("%v: %+v, want class %d valid %t", c.sidecarId, sidecar, c.class, c.valid)
		}
	}
}

// The socket target forms: an exact path, a prefix taking names strictly below it, and a prefix with no
// token taking every application socket.
func TestAclSocketTargetForms(t *testing.T) {
	db := aclTestTokenPath(1)
	dbReplica := aclTestTokenPath(1, 2)
	web := aclTestTokenPath(3)
	cases := []struct {
		target aclSocketTarget
		name   []byte
		covers bool
	}{
		{target: aclSocketTarget{tokenPaths: [][]byte{db}}, name: db, covers: true},
		{target: aclSocketTarget{tokenPaths: [][]byte{db}}, name: dbReplica, covers: false},
		{target: aclSocketTarget{tokenPaths: [][]byte{web, db}}, name: db, covers: true},
		{target: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, name: dbReplica, covers: true},
		{target: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, name: db, covers: false},
		{target: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, name: web, covers: false},
		{target: aclSocketTarget{prefix: true}, name: web, covers: true},
		{target: aclSocketTarget{prefix: true}, name: []byte{1, 2, 3}, covers: false},
		{target: aclSocketTarget{prefix: true}, name: nil, covers: false},
	}
	for i, c := range cases {
		if covers := c.target.covers(c.name); covers != c.covers {
			t.Errorf("case %d: covers = %t", i, covers)
		}
	}
	overlaps := []struct {
		a, b     aclSocketTarget
		overlaps bool
	}{
		{a: aclSocketTarget{tokenPaths: [][]byte{db}}, b: aclSocketTarget{tokenPaths: [][]byte{db}}, overlaps: true},
		{a: aclSocketTarget{tokenPaths: [][]byte{db}}, b: aclSocketTarget{tokenPaths: [][]byte{web}}, overlaps: false},
		{a: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, b: aclSocketTarget{tokenPaths: [][]byte{dbReplica}}, overlaps: true},
		{a: aclSocketTarget{tokenPaths: [][]byte{dbReplica}}, b: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, overlaps: true},
		{a: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, b: aclSocketTarget{tokenPaths: [][]byte{db}}, overlaps: false},
		{a: aclSocketTarget{tokenPaths: [][]byte{db}, prefix: true}, b: aclSocketTarget{tokenPaths: [][]byte{dbReplica}, prefix: true}, overlaps: true},
		{a: aclSocketTarget{prefix: true}, b: aclSocketTarget{tokenPaths: [][]byte{web}}, overlaps: true},
	}
	for i, c := range overlaps {
		if overlaps := c.a.overlaps(&c.b); overlaps != c.overlaps {
			t.Errorf("overlap case %d: %t", i, overlaps)
		}
	}
}

// Rows' cidr bytes round trip, both families.
func TestAclRowsCidrRoundTrips(t *testing.T) {
	for _, text := range []string{"10.0.0.0/8", "0.0.0.0/0", "192.0.2.7/32", "2001:db8::/32", "::/0"} {
		cidr := netip.MustParsePrefix(text)
		parsed, err := aclRowsCidr(AclRowsCidrBytes(cidr))
		if err != nil || parsed != cidr {
			t.Errorf("%s: %v %v", text, parsed, err)
		}
	}
}
