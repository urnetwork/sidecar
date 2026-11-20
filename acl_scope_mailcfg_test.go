// A Team scope's own mailcfg under the owner-bound rules (QD-1107) and a config writer's mailcfg once the network's
// stands (QD-1108): an Admin's device's RepoGrant, RepoAdmin add, RepoDelete, RepoRevoke of the owner and RepoVersioning
// on a member's scope mailcfg refused, the owner's consented device's RepoAdmin add taking effect, rows that hold a
// grant or a foreign admin giving nothing, a rule naming it adding nothing at evaluation, at the validator and in a
// Delegation's reach, the tag:mail kind rule naming the network's mailcfg alone, while the network's mailcfg keeps
// every right; the network's deleted and succeeded by the next config writer's creation; and on TEAM's log two config
// writers racing to one network mailcfg and one scope's, with the same rows at a long-running reader, a new device and
// a rows-only gate, over bases that re-apply those entries and that compile them. Pure, on every leg.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The statement cast with a member's scope mailcfg its laptop created and the network's mailcfg the owner's config
// writer created after it, both through the log's own rules.
func aclTestScopeMailcfgs(t *testing.T) (*aclStatementCast, *AclState, Id, Id) {
	t.Helper()
	cast := newAclStatementCast()
	fixture := cast.fixture
	state := fixture.state(t)
	scopeId, scope := aclTestMailcfgCreate(fixture, cast.laptop)
	state, _ = fixture.apply(t, state, scope)
	networkId, network := aclTestMailcfgCreate(fixture, cast.ownerDevice)
	state, _ = fixture.apply(t, state, network)
	if aclTestRowOwner(state.Repo(scopeId)) != cast.member || aclTestRowOwner(state.Repo(networkId)) != (Id{}) {
		t.Fatalf("the scope's row %+v, the network's %+v", state.Repo(scopeId), state.Repo(networkId))
	}
	return cast, state, scopeId, networkId
}

// The tag the cast's agent carries.
func aclTestAgentTag(cast *aclStatementCast) Id {
	return cast.fixture.admission(cast.agent).TagIds[0]
}

// A row's owner member, the zero id for a row that names none.
func aclTestRowOwner(row *protocol.AclRepo) Id {
	if len(row.GetOwnerMemberId()) == 0 {
		return Id{}
	}
	return Id(row.GetOwnerMemberId())
}

// QD-1107: on a member's scope mailcfg an Admin's config writer files no RepoGrant, no RepoAdmin add of itself, no
// RepoDelete, no RepoRevoke of the owner or its consented device and no RepoVersioning, nor the network Owner's config
// writer a RepoAdmin add of itself, nor the owner a RepoGrant or a RepoAdmin add of an admin's device, and no device
// they named reads after; the owner's own consented device adds its other consented device as admin, which then
// administers it and deletes it, the deleted repo's admin right left to the owner's devices alone. On the network's
// mailcfg the same Admin's RepoGrant and RepoAdmin add take effect.
func TestAclScopeMailcfgRefusesAnAdminsStatementsAndTakesItsOwners(t *testing.T) {
	cast, state, scopeId, networkId := aclTestScopeMailcfgs(t)
	fixture := cast.fixture
	reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
	add := protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD
	refused := []struct {
		name       string
		signedType bridge.SignedType
		body       proto.Message
		signer     Id
		refusal    error
	}{
		{name: "an admin's RepoGrant of itself", signedType: bridge.SignedType_SIGNED_REPO_GRANT, signer: cast.adminDevice, refusal: ErrConfigRule,
			body: &protocol.RepoGrant{RepoId: scopeId.Bytes(), Subject: cast.adminDevice.Bytes(), Role: reader}},
		{name: "an admin's RepoGrant of the member's agent", signedType: bridge.SignedType_SIGNED_REPO_GRANT, signer: cast.adminDevice, refusal: ErrConfigRule,
			body: &protocol.RepoGrant{RepoId: scopeId.Bytes(), Subject: cast.agent.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER}},
		{name: "the owner's own RepoGrant", signedType: bridge.SignedType_SIGNED_REPO_GRANT, signer: cast.laptop, refusal: ErrConfigRule,
			body: &protocol.RepoGrant{RepoId: scopeId.Bytes(), Subject: cast.stranger.Bytes(), Role: reader}},
		{name: "an admin's RepoAdmin add of itself", signedType: bridge.SignedType_SIGNED_REPO_ADMIN, signer: cast.adminDevice, refusal: ErrConfigAuthority,
			body: &protocol.RepoAdmin{RepoId: scopeId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: add}},
		{name: "the network owner's RepoAdmin add of itself", signedType: bridge.SignedType_SIGNED_REPO_ADMIN, signer: cast.ownerDevice, refusal: ErrConfigAuthority,
			body: &protocol.RepoAdmin{RepoId: scopeId.Bytes(), SidecarId: cast.ownerDevice.Bytes(), Change: add}},
		{name: "the owner's RepoAdmin add of an admin's device", signedType: bridge.SignedType_SIGNED_REPO_ADMIN, signer: cast.laptop, refusal: ErrConfigRule,
			body: &protocol.RepoAdmin{RepoId: scopeId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: add}},
		{name: "an admin's RepoDelete", signedType: bridge.SignedType_SIGNED_REPO_DELETE, signer: cast.adminDevice, refusal: ErrConfigAuthority,
			body: &protocol.RepoDelete{RepoId: scopeId.Bytes(), DeletionId: NewId().Bytes()}},
		{name: "an admin's RepoDelete now", signedType: bridge.SignedType_SIGNED_REPO_DELETE, signer: cast.adminDevice, refusal: ErrConfigAuthority,
			body: &protocol.RepoDelete{RepoId: scopeId.Bytes(), DeletionId: NewId().Bytes(), Now: true}},
		{name: "an admin's RepoRevoke of the owner", signedType: bridge.SignedType_SIGNED_REPO_REVOKE, signer: cast.adminDevice, refusal: ErrConfigRule,
			body: &protocol.RepoRevoke{RepoId: scopeId.Bytes(), Subject: cast.member.Bytes()}},
		{name: "an admin's RepoRevoke of the owner's consented device", signedType: bridge.SignedType_SIGNED_REPO_REVOKE, signer: cast.adminDevice, refusal: ErrConfigRule,
			body: &protocol.RepoRevoke{RepoId: scopeId.Bytes(), Subject: cast.phone.Bytes()}},
		{name: "an admin's RepoVersioning", signedType: bridge.SignedType_SIGNED_REPO_VERSIONING, signer: cast.adminDevice, refusal: ErrConfigAuthority,
			body: &protocol.RepoVersioning{RepoId: scopeId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED}},
	}
	for _, c := range refused {
		if _, err := state.CheckStatement(fixture.statement(c.signedType, c.body, c.signer), nil); aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	for name, sidecarId := range map[string]Id{
		"the admin's device": cast.adminDevice, "the network owner's device": cast.ownerDevice, "the member's agent": cast.agent, "another member's device": cast.stranger,
	} {
		if rights := aclTestRights(state, sidecarId, scopeId, AclTokenAudienceEvs); rights != 0 {
			t.Errorf("%s holds %b on the scope's mailcfg", name, rights)
		}
	}
	if readers := state.RepoReaders(scopeId, aclTestNow); !slices.Equal(readers, aclSortedIds(cast.laptop, cast.phone)) {
		t.Errorf("the scope mailcfg's readers %v", readers)
	}

	// the owner's consented device adds its other one, which administers it and deletes it
	if aclTestRights(state, cast.phone, scopeId, AclTokenAudienceEvs).Has(AclEvsAdmin) {
		t.Fatal("the phone administers the scope's mailcfg before its RepoAdmin")
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN,
		&protocol.RepoAdmin{RepoId: scopeId.Bytes(), SidecarId: cast.phone.Bytes(), Change: add}, cast.laptop))
	if rights := aclTestRights(state, cast.phone, scopeId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsWrite|AclEvsAdmin {
		t.Errorf("the owner's added device holds %b", rights)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_DELETE,
		&protocol.RepoDelete{RepoId: scopeId.Bytes(), DeletionId: NewId().Bytes()}, cast.phone))
	if deletion := state.Repo(scopeId).GetDeletion(); deletion.GetDeletedAt() == 0 || !bytes.Equal(deletion.GetSigner(), cast.phone.Bytes()) {
		t.Fatalf("the owner's device's RepoDelete: %+v", deletion)
	}
	deleted := []struct {
		name      string
		sidecarId Id
		rights    AclEvsRights
	}{
		{name: "the deleting admin", sidecarId: cast.phone, rights: AclEvsAdmin},
		{name: "the creating admin", sidecarId: cast.laptop, rights: AclEvsAdmin},
		{name: "the admin's device", sidecarId: cast.adminDevice},
		{name: "the network owner's device", sidecarId: cast.ownerDevice},
	}
	for _, c := range deleted {
		if rights := aclTestRights(state, c.sidecarId, scopeId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("deleted, %s holds %b, want %b", c.name, rights, c.rights)
		}
	}

	// the network's mailcfg keeps a mailcfg's rules: the same Admin's RepoGrant and RepoAdmin add take effect there
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT,
		&protocol.RepoGrant{RepoId: networkId.Bytes(), Subject: cast.agent.Bytes(), Role: reader}, cast.adminDevice))
	if rights := aclTestRights(state, cast.agent, networkId, AclTokenAudienceEvs); rights != AclEvsRead {
		t.Errorf("the agent the network mailcfg's grant names holds %b", rights)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN,
		&protocol.RepoAdmin{RepoId: networkId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: add}, cast.adminDevice))
	if rights := aclTestRights(state, cast.adminDevice, networkId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsWrite|AclEvsAdmin {
		t.Errorf("the admin added to the network's mailcfg holds %b", rights)
	}
}

// QD-1107 at the rights: rows that hold a RepoGrant on a scope's mailcfg, or an admin row of a device that is no
// consented device of its owner, as rows folded before the rule could, give their subjects nothing there, not even a
// deleted repo's admin right, and a Delegation's tags reach no scope mailcfg through such a grant; the network's
// mailcfg takes the same rows.
func TestAclScopeMailcfgRowsGiveNothingByGrantOrForeignAdmin(t *testing.T) {
	cast, _, scopeId, networkId := aclTestScopeMailcfgs(t)
	fixture := cast.fixture
	tagId := aclTestAgentTag(cast)
	writer := protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER
	add := protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD
	fold := func(entries ...AclAccessLogEntry) {
		t.Helper()
		repos, err := FoldAclRepos(fixture.rows.GetRepos(), entries)
		if err != nil {
			t.Fatal(err)
		}
		fixture.rows.Repos = repos
	}
	fold(
		aclTestLogEntry(&protocol.RepoGrant{RepoId: scopeId.Bytes(), Subject: tagId.Bytes(), Role: writer}, bridge.SignedType_SIGNED_REPO_GRANT, cast.adminDevice, fixture.next(), true),
		aclTestLogEntry(&protocol.RepoGrant{RepoId: scopeId.Bytes(), Subject: cast.stranger.Bytes(), Role: writer}, bridge.SignedType_SIGNED_REPO_GRANT, cast.adminDevice, fixture.next(), true),
		aclTestLogEntry(&protocol.RepoAdmin{RepoId: scopeId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: add}, bridge.SignedType_SIGNED_REPO_ADMIN, cast.adminDevice, fixture.next(), true),
		aclTestLogEntry(&protocol.RepoGrant{RepoId: networkId.Bytes(), Subject: tagId.Bytes(), Role: writer}, bridge.SignedType_SIGNED_REPO_GRANT, cast.adminDevice, fixture.next(), true),
		aclTestLogEntry(&protocol.RepoAdmin{RepoId: networkId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: add}, bridge.SignedType_SIGNED_REPO_ADMIN, cast.adminDevice, fixture.next(), true),
	)
	state := fixture.state(t)
	cases := []struct {
		name      string
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{name: "the granted agent in the scope's", sidecarId: cast.agent, repoId: scopeId},
		{name: "the granted stranger in the scope's", sidecarId: cast.stranger, repoId: scopeId},
		{name: "the foreign admin in the scope's", sidecarId: cast.adminDevice, repoId: scopeId},
		{name: "the owner's creating device in the scope's", sidecarId: cast.laptop, repoId: scopeId, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin},
		{name: "the granted agent in the network's", sidecarId: cast.agent, repoId: networkId, rights: AclEvsRead | AclEvsWrite},
		{name: "the added admin in the network's", sidecarId: cast.adminDevice, repoId: networkId, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin},
	}
	for _, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("%s: %b, want %b", c.name, rights, c.rights)
		}
	}
	if writers := state.RepoWriters(scopeId, aclTestNow); !slices.Equal(writers, aclSortedIds(cast.laptop, cast.phone)) {
		t.Errorf("the scope mailcfg's writers %v", writers)
	}
	if reached := state.ReposGrantedToAtoms([]Id{tagId}, aclTestNow); !slices.Equal(reached, []Id{networkId}) {
		t.Errorf("the agent's tag reaches %v", reached)
	}

	// deleted by its owner's device, its admin right is the owner's devices' alone, never the foreign admin row's
	fold(aclTestLogEntry(&protocol.RepoDelete{RepoId: scopeId.Bytes(), DeletionId: NewId().Bytes()}, bridge.SignedType_SIGNED_REPO_DELETE, cast.laptop, fixture.next(), false))
	state = fixture.state(t)
	if rights := aclTestRights(state, cast.adminDevice, scopeId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("the foreign admin holds %b on the deleted scope mailcfg", rights)
	}
	if rights := aclTestRights(state, cast.laptop, scopeId, AclTokenAudienceEvs); rights != AclEvsAdmin {
		t.Errorf("the owner's admin holds %b on the deleted scope mailcfg", rights)
	}
}

// QD-1107: a rule naming a scope's mailcfg outright adds nothing, whatever its actions and whoever it names, the form a
// tag:mail kind rule compiled over every mailcfg would take included, and no Delegation's tags reach it by one; the
// same rule adds to the network's mailcfg.
func TestAclRuleNamingAScopeMailcfgAddsNothing(t *testing.T) {
	cast, _, scopeId, networkId := aclTestScopeMailcfgs(t)
	fixture := cast.fixture
	tagId := aclTestAgentTag(cast)
	all := []protocol.AclAction{
		protocol.AclAction_ACL_ACTION_DEPOSIT, protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE, protocol.AclAction_ACL_ACTION_ADMIN,
	}
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(scopeId), aclRepoTarget(networkId)}, all...)
	fixture.rule([]Id{fixture.group(cast.strangerUser), fixture.sidecarAtom(cast.adminDevice)}, []*protocol.AclTarget{aclRepoTarget(scopeId)}, all...)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(scopeId)}, protocol.AclAction_ACL_ACTION_READ)
	state := fixture.state(t)
	cases := []struct {
		name      string
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{name: "the tagged agent in the scope's", sidecarId: cast.agent, repoId: scopeId},
		{name: "another member's device in the scope's", sidecarId: cast.stranger, repoId: scopeId},
		{name: "an admin's device in the scope's", sidecarId: cast.adminDevice, repoId: scopeId},
		{name: "the network owner's device in the scope's", sidecarId: cast.ownerDevice, repoId: scopeId},
		{name: "the scope's own phone, by its kind default alone", sidecarId: cast.phone, repoId: scopeId, rights: AclEvsRead | AclEvsWrite},
		{name: "the tagged agent in the network's", sidecarId: cast.agent, repoId: networkId, rights: AclEvsDeposit | AclEvsRead | AclEvsWrite | AclEvsAdmin},
	}
	for _, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("%s: %b, want %b", c.name, rights, c.rights)
		}
	}
	if access := state.EvsAccess(AclSidecarSubject(cast.phone), scopeId, AclTokenAudienceEvs, aclTestNow); access.Reason != AclReasonKindDefault {
		t.Errorf("the phone's read comes from %v, not its kind default", access.Reason)
	}
	if reached := state.ReposGrantedToAtoms([]Id{tagId}, aclTestNow); !slices.Equal(reached, []Id{networkId}) {
		t.Errorf("the agent's tag reaches %v", reached)
	}
}

// QD-1107 at §8.8's Saving: a rule naming a scope's mailcfg by its label or a glob matching it is refused, a deposit
// too, while the same rule on the network's mailcfg passes.
func TestValidateAclPolicyRefusesARuleOnAScopeMailcfg(t *testing.T) {
	world := newAclValidateWorld()
	world.repo("mailcfg", protocol.RepoKind_REPO_KIND_MAILCFG, Id{})
	world.repo("scope-mail", protocol.RepoKind_REPO_KIND_MAILCFG, world.id("member dana@acme.example"))
	for _, rule := range []string{
		`{"src": ["tag:db"], "dst": ["evs:scope-mail"], "allow": ["read"]}`,
		`{"src": ["tag:db"], "dst": ["evs:scope-mail"], "allow": ["deposit"]}`,
		`{"src": ["group:eng"], "dst": ["evs:scope-*"], "allow": ["write"]}`,
		`{"src": ["tag:db"], "dst": ["evs:scope-mail", "evs:mailcfg"], "allow": ["admin"]}`,
	} {
		err := aclValidate(world, aclValidateDocument(`"grants": [`+rule+`]`), aclTestProLimits(), nil)
		if err == nil || !strings.Contains(err.Error(), "Team scope's own mailcfg") {
			t.Errorf("%s: %v", rule, err)
		}
	}
	for _, rule := range []string{
		`{"src": ["tag:db"], "dst": ["evs:mailcfg"], "allow": ["read", "write", "admin", "deposit"]}`,
		`{"src": ["group:eng"], "dst": ["evs:mail*"], "allow": ["read"]}`,
	} {
		if err := aclValidate(world, aclValidateDocument(`"grants": [`+rule+`]`), aclTestProLimits(), nil); err != nil {
			t.Errorf("%s: %v", rule, err)
		}
	}
}

// QD-1107 in the compile: the tag:mail kind rule's read names the network's mailcfg and no scope's, so a tag:mail mail
// indexer reads the network's and nothing of a scope's, while its deposit still names every vault and mailbox.
func TestCompileAclMailIndexerReadsTheNetworksMailcfgAlone(t *testing.T) {
	world := newAclCompileWorld("mail scope")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	scoped := world.member("dana@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.device("laptop", owner)
	network := world.repo("mailcfg", protocol.RepoKind_REPO_KIND_MAILCFG, Id{})
	scope := world.repo("scope-mail", protocol.RepoKind_REPO_KIND_MAILCFG, scoped)
	mailbox := world.repo("mailbox", protocol.RepoKind_REPO_KIND_MAILBOX, scoped)
	indexer := world.agent("indexer", owner, aclMailIndexerTag)
	rows := world.compile(t)
	targets := func(index uint32) []Id {
		for _, rule := range rows.GetRules() {
			if !bytes.Equal(rule.GetRuleId(), aclKindRuleId(index).Bytes()) {
				continue
			}
			repoIds := []Id{}
			for _, target := range rule.GetTargets() {
				repoIds = append(repoIds, Id(target.GetRepoId()))
			}
			return repoIds
		}
		return nil
	}
	if read := targets(0); !slices.Equal(read, []Id{network}) {
		t.Errorf("the tag:mail read names %v, want the network's %v", read, network)
	}
	if deposit := targets(1); !slices.Equal(deposit, []Id{mailbox}) {
		t.Errorf("the tag:mail deposit names %v", deposit)
	}
	state := world.state(t)
	for _, c := range []struct {
		name   string
		repoId Id
		rights AclEvsRights
	}{
		{name: "the network's mailcfg", repoId: network, rights: AclEvsRead},
		{name: "a scope's mailcfg", repoId: scope},
		{name: "a scope member's mailbox", repoId: mailbox, rights: AclEvsDeposit},
	} {
		if rights := aclTestRights(state, indexer, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("the indexer in %s: %b, want %b", c.name, rights, c.rights)
		}
	}
}

// The standing unowned mailcfg created first: the network's, as a device takes it (MailRepos.MailConfigRepo), false
// for none.
func aclTestNetworkMailcfg(state *AclState) (Id, bool) {
	var networkId Id
	var createdAt uint64
	for _, row := range state.Rows().GetRepos() {
		if row.GetKind() != protocol.RepoKind_REPO_KIND_MAILCFG || len(row.GetOwnerMemberId()) != 0 || !aclRepoRowStands(row) || len(row.GetAdmins()) == 0 {
			continue
		}
		if at := row.GetAdmins()[0].GetAt(); createdAt == 0 || at < createdAt {
			networkId, createdAt = Id(row.GetRepoId()), at
		}
	}
	return networkId, createdAt != 0
}

// QD-1108: the network's mailcfg deleted, none stands, and the next config writer's mailcfg is the network's again,
// while the scope mailcfg a config writer made beside the first stays its member's; with the successor standing a
// config writer's mailcfg is its scope's again, and should the first be restored, the first standing unowned mailcfg
// in log order is the network's.
func TestAclNetworkMailcfgDeletedIsSucceededByTheNextConfigWritersCreation(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	state := fixture.state(t)
	create := func(signer Id, owner Id) Id {
		t.Helper()
		repoId, statement := aclTestMailcfgCreate(fixture, signer)
		verdict, err := state.CheckStatement(statement, nil)
		if err != nil || verdict.MemberId != owner {
			t.Fatalf("the verdict %+v, %v, want the owner %s", verdict, err, owner)
		}
		state, _ = fixture.apply(t, state, statement)
		if row := state.Repo(repoId); aclTestRowOwner(row) != owner {
			t.Fatalf("the row %+v, want the owner %s", row, owner)
		}
		return repoId
	}
	firstId := create(cast.ownerDevice, Id{})
	adminScopeId := create(cast.adminDevice, cast.admin)
	if networkId, ok := aclTestNetworkMailcfg(state); !ok || networkId != firstId {
		t.Fatalf("the network's mailcfg %s %t", networkId, ok)
	}

	deletionId := NewId()
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_DELETE,
		&protocol.RepoDelete{RepoId: firstId.Bytes(), DeletionId: deletionId.Bytes()}, cast.ownerDevice))
	if _, ok := aclTestNetworkMailcfg(state); ok {
		t.Fatal("a network mailcfg stands once the first is deleted")
	}
	successorId := create(cast.adminDevice, Id{})
	if networkId, ok := aclTestNetworkMailcfg(state); !ok || networkId != successorId {
		t.Fatalf("the successor %s, the network's %s %t", successorId, networkId, ok)
	}
	if Id(state.Repo(adminScopeId).GetOwnerMemberId()) != cast.admin {
		t.Fatal("the admin's scope mailcfg changed owner")
	}
	create(cast.ownerDevice, cast.owner)

	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE,
		&protocol.RepoRestore{RepoId: firstId.Bytes(), DeletionId: deletionId.Bytes()}, cast.ownerDevice))
	if networkId, ok := aclTestNetworkMailcfg(state); !ok || networkId != firstId {
		t.Fatalf("restored, the network's mailcfg %s %t", networkId, ok)
	}
	create(cast.adminDevice, cast.admin)
}

// A member made an Admin by an AdminSet of the owner and it, and its first device, admitted with the invite's bit so it
// is consented for its member (§8.5's invited clause): a config writer that may create its member's scope mailcfg.
func aclTestConsentedAdmin(net *testConfigNet, label string) testConfigDevice {
	net.t.Helper()
	memberId := testConfigId(label + " admin member")
	net.admitMember(net.owner, memberId, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, Admins: [][]byte{memberId.Bytes()},
	})
	device := net.device(label+" admin device", memberId)
	net.admitDevice(net.owner, device, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		net.t.Fatal(err)
	}
	if !state.IsConfigWriter(device.sidecarId) || !acl.ConsentedFor(device.sidecarId, memberId) {
		net.t.Fatal("the admin's device is no consented config writer")
	}
	return device
}

// QD-1108 on TEAM's log: the Owner's and an Admin's config writers sign a mailcfg RepoCreate at the same tip, and the
// one sequenced first is the network's while the other is its member's scope's own; a member's device makes its scope's;
// the network's deleted, the Admin's next is the network's. A long-running reader, a new device and a rows-only gate
// hold the same rows and verdicts, at the tip, past a base below every one of these entries, whose tail each reader
// re-applies over the base's rows, and past a base that folds through them all.
func TestAclScopeMailcfgsFoldAlikeAtEveryReader(t *testing.T) {
	net := newTestConfigNet(t)
	admin := aclTestConsentedAdmin(net, "scope mail")
	member, memberDevice := net.consentedMember("scope mail member")
	belowMailcfgs := net.n
	createBody := func(repoId Id) *protocol.RepoCreate {
		return &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILCFG}
	}
	ownersId, adminsId := testConfigId("owner's mailcfg"), testConfigId("admin's mailcfg")
	ownersSigned := net.sign(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, createBody(ownersId))
	adminsSigned := net.sign(admin, bridge.SignedType_SIGNED_REPO_CREATE, createBody(adminsId))
	for _, signed := range [][]byte{ownersSigned, adminsSigned} {
		if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signed)); !verdict.Accepted() {
			t.Fatalf("a racing RepoCreate: %v", verdict.Refusal)
		}
	}
	memberScopeId := testConfigId("member's mailcfg")
	net.mustPost(memberDevice, bridge.SignedType_SIGNED_REPO_CREATE, createBody(memberScopeId))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: net.header(), RepoId: ownersId.Bytes(), DeletionId: testConfigId("network mailcfg deletion").Bytes(),
	})
	successorId := testConfigId("successor mailcfg")
	net.mustPost(admin, bridge.SignedType_SIGNED_REPO_CREATE, createBody(successorId))

	holdsTheRows := func(label string, log *ConfigLog) {
		t.Helper()
		acl, err := log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name    string
			repoId  Id
			owner   Id
			deleted bool
		}{
			{name: "the first network mailcfg", repoId: ownersId, deleted: true},
			{name: "the racing admin's", repoId: adminsId, owner: admin.memberId},
			{name: "the member's", repoId: memberScopeId, owner: member},
			{name: "the successor", repoId: successorId},
		} {
			row := acl.Repo(c.repoId)
			if row == nil {
				t.Errorf("%s holds no row of %s", label, c.name)
				continue
			}
			if aclTestRowOwner(row) != c.owner || aclRepoRowStands(row) == c.deleted {
				t.Errorf("%s: %s's row %+v", label, c.name, row)
			}
		}
		if networkId, ok := aclTestNetworkMailcfg(acl); !ok || networkId != successorId {
			t.Errorf("%s: the network's mailcfg %s %t", label, networkId, ok)
		}
	}
	holdsTheRows("the reader at the tip", net.log)
	net.everyReaderAgrees()

	// a base below every mailcfg entry: each reader re-applies them over the base's rows
	if verdict := net.fold(net.owner, belowMailcfgs, net.log.State().Base().GetConfigVersion()+1); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	holdsTheRows("the reader past a base below them", net.log)
	for i, reader := range net.everyReader() {
		holdsTheRows(fmt.Sprintf("reader %d past a base below them", i), reader)
	}
	net.everyReaderAgrees()

	// a base through them all, which the head check compiles from
	if verdict := net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	holdsTheRows("the reader past a base through them", net.log)
	for i, reader := range net.everyReader() {
		holdsTheRows(fmt.Sprintf("reader %d past a base through them", i), reader)
	}
	net.everyReaderAgrees()
}
