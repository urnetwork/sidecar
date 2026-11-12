// §8.8's statement rules on the fake view (T1): a table per statement of each allowed and refused signer, §22.5's
// non-admin RepoGrant and a config writer's RepoRevoke winning, an admin's vault EvsShare refused by a reader, Suspend
// and Unsuspend in both orders, FS-95's format-1 lock. Then the same rules through TEAM's ConfigLog: a k-of-n Suspend
// by proposal, effects on §7's rows, and ReapplyStatement keeping a revocation past an authority change. Pure, on every
// leg.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One statement signed by one sidecar at the fixture's next position, at aclTestNow.
func (self *aclTestFixture) statement(signedType bridge.SignedType, body proto.Message, signer Id) *AclStatement {
	return &AclStatement{
		Type:    signedType,
		Body:    body,
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: signer}},
		N:       self.next(),
		TimeMs:  aclTestNow.UnixMilli(),
	}
}

// A k-of-n statement, its signers already counted.
func (self *aclTestFixture) authorityStatement(signedType bridge.SignedType, body proto.Message, signers ...Id) *AclStatement {
	statement := self.statement(signedType, body, signers[0])
	statement.Signers = nil
	for _, signer := range signers {
		statement.Signers = append(statement.Signers, ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: signer})
	}
	statement.Authority = true
	return statement
}

// Checks and folds a statement, failing the test unless it takes effect, and returns the next state over the same
// view.
func (self *aclTestFixture) apply(t *testing.T, state *AclState, statement *AclStatement) (*AclState, AclStatementEffect) {
	t.Helper()
	verdict, err := state.CheckStatement(statement, nil)
	if err != nil {
		t.Fatalf("%s: %v", statement.Type, err)
	}
	rows, effect, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatalf("%s fold: %v", statement.Type, err)
	}
	self.rows = rows
	return self.state(t), effect
}

// A refusal's class, the narrowest first, or nil.
func aclTestRefusal(err error) error {
	return testConfigRefusalClass(err)
}

// A member device of a member with a role, consented by the member's invite, and a config writer when its role signs
// config heads.
func (self *aclTestFixture) memberWithDevice(role bridge.MemberRole) (Id, Id) {
	memberId := self.member(role)
	device := self.invitedDevice(memberId)
	if configRoleInAdminSet(role) {
		self.view.configWriters[device] = true
	}
	return memberId, device
}

// The cast most tables share: an Owner and an Admin, each with a consented config writer device; a Member with a
// consented laptop and a second device its laptop admitted; a tagged agent the Member sponsors; a read_only device of
// the Admin; and a revoked device of the Member.
type aclStatementCast struct {
	fixture      *aclTestFixture
	owner        Id
	ownerDevice  Id
	admin        Id
	adminDevice  Id
	member       Id
	laptop       Id
	phone        Id
	agent        Id
	pageWorker   Id
	revoked      Id
	stranger     Id
	strangerUser Id
}

func newAclStatementCast() *aclStatementCast {
	fixture := newAclTestFixture()
	cast := &aclStatementCast{fixture: fixture}
	cast.owner, cast.ownerDevice = fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	cast.admin, cast.adminDevice = fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	cast.member, cast.laptop = fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	cast.phone = fixture.device(cast.member, cast.laptop.Bytes())
	tagId := fixture.tag(cast.member)
	cast.agent = fixture.agent(cast.member, tagId)
	cast.pageWorker = fixture.device(cast.admin, cast.adminDevice.Bytes())
	fixture.admission(cast.pageWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	cast.revoked = fixture.device(cast.member, cast.laptop.Bytes())
	fixture.admission(cast.revoked).Row.RevokedAt = fixture.next()
	cast.strangerUser, cast.stranger = fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	return cast
}

// A Suspend's or Unsuspend's ids.
func aclTestSuspendId(label string) []byte {
	return testConfigId("suspend " + label).Bytes()
}

// Suspend's signer classes: an admin over a member's devices, the owner or sponsor over its own, k of n over anyone,
// and for an AdminSet member's device no admin class; never a stranger, a read_only or revoked device, a repeated
// suspend_id or ids of the wrong size.
func TestAclSuspendSigners(t *testing.T) {
	cast := newAclStatementCast()
	state := cast.fixture.state(t)
	suspend := func(subject Id, label string) *bridge.Suspend {
		return &bridge.Suspend{Subject: subject.Bytes(), SuspendId: aclTestSuspendId(label)}
	}
	cases := []struct {
		name      string
		statement *AclStatement
		class     uint32
		refusal   error
	}{
		{name: "admin over a member's device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "a"), cast.adminDevice), class: AclSuspendClassAdmin},
		{name: "owner over its own device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "b"), cast.laptop), class: AclSuspendClassOwner},
		{name: "sponsor over its agent", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.agent, "c"), cast.laptop), class: AclSuspendClassOwner},
		{name: "admin over its agent too", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.agent, "d"), cast.ownerDevice), class: AclSuspendClassAdmin},
		{name: "admin over an AdminSet member's device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.ownerDevice, "e"), cast.adminDevice), refusal: ErrConfigAuthority},
		{name: "owner over its own AdminSet device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.adminDevice, "f"), cast.adminDevice), class: AclSuspendClassOwner},
		{name: "k of n over an AdminSet member's device", statement: cast.fixture.authorityStatement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.ownerDevice, "g"), cast.adminDevice, cast.laptop), class: AclSuspendClassAuthority},
		{name: "k of n with the subject among its signers", statement: cast.fixture.authorityStatement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.ownerDevice, "h"), cast.adminDevice, cast.ownerDevice), refusal: ErrConfigAuthority},
		{name: "a stranger", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "i"), cast.stranger), refusal: ErrConfigAuthority},
		{name: "a read_only device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "j"), cast.pageWorker), refusal: ErrConfigReadOnly},
		{name: "a revoked device", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "k"), cast.revoked), refusal: ErrConfigAuthority},
		{name: "an unknown signer", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "l"), NewId()), refusal: ErrConfigSigner},
		{name: "an agent suspending another", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "m"), cast.agent), refusal: ErrConfigAuthority},
		{name: "a client subject by an admin", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(NewId(), "n"), cast.adminDevice), class: AclSuspendClassAdmin},
		{name: "a short suspend_id", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: cast.phone.Bytes(), SuspendId: []byte{1}}, cast.adminDevice), refusal: ErrConfigRule},
		{name: "a short subject", statement: cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: []byte{1}, SuspendId: aclTestSuspendId("o")}, cast.adminDevice), refusal: ErrConfigRule},
	}
	for _, c := range cases {
		verdict, err := state.CheckStatement(c.statement, nil)
		if c.refusal != nil {
			if err == nil || aclTestRefusal(err) != c.refusal {
				t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
			}
			continue
		}
		if err != nil || verdict.Class != c.class {
			t.Errorf("%s: %v, class %v, want %d", c.name, err, verdict, c.class)
		}
	}

	// a suspend_id in force is not taken twice
	state, _ = cast.fixture.apply(t, state, cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "twice"), cast.adminDevice))
	if _, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend(cast.phone, "twice"), cast.laptop), nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a suspend_id in force again: %v", err)
	}
}

// Unsuspend lifts only its own suspend_id, from the class that suspended it or a higher one, never by the subject;
// a stale id lifts nothing; and Suspend and Unsuspend arrive in either order (§8.8).
func TestAclSuspendAndUnsuspendInBothOrders(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	state := fixture.state(t)
	suspend := &bridge.Suspend{Subject: cast.phone.Bytes(), SuspendId: aclTestSuspendId("admin")}
	unsuspend := &bridge.Unsuspend{Subject: cast.phone.Bytes(), SuspendId: aclTestSuspendId("admin")}

	// Unsuspend first: a stale id, a no-op that leaves the later Suspend in force
	verdict, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, unsuspend, cast.adminDevice), nil)
	if err != nil || verdict.Lifts {
		t.Fatalf("a stale Unsuspend: %v, %+v", err, verdict)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, unsuspend, cast.adminDevice))
	state, effect := fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_SUSPEND, suspend, cast.adminDevice))
	if !state.Suspended(cast.phone) || len(effect.SuspendedSubjectIds) != 1 {
		t.Fatal("the Suspend after a stale Unsuspend is not in force")
	}
	if access := state.EvsAccess(AclSidecarSubject(cast.phone), NewId(), AclTokenAudienceEvs, aclTestNow); access.Reason != AclReasonSuspended {
		t.Errorf("a suspended subject: %v", access.Reason)
	}
	suspension := state.Rows().GetSuspensions()[0]
	if suspension.GetSignerClass() != AclSuspendClassAdmin || !bytes.Equal(suspension.GetSigner(), cast.adminDevice.Bytes()) || suspension.GetAt() == 0 {
		t.Errorf("the suspension row %+v", suspension)
	}

	// lower class and the subject itself are refused; another id lifts nothing
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, unsuspend, cast.laptop), nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the owner lifting an admin's Suspend: %v", err)
	}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, unsuspend, cast.phone), nil); err == nil {
		t.Error("the subject lifted its own Suspend")
	}
	other := &bridge.Unsuspend{Subject: cast.phone.Bytes(), SuspendId: aclTestSuspendId("other")}
	state, effect = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, other, cast.ownerDevice))
	if !state.Suspended(cast.phone) || len(effect.UnsuspendedSubjectIds) != 0 {
		t.Error("an Unsuspend of another id lifted the Suspend")
	}

	// Suspend then Unsuspend: an admin's by an admin, and a k-of-n Suspend only by k of n
	state, effect = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, unsuspend, cast.ownerDevice))
	if state.Suspended(cast.phone) || len(effect.UnsuspendedSubjectIds) != 1 {
		t.Error("the Unsuspend did not lift its Suspend")
	}
	authoritySuspend := &bridge.Suspend{Subject: cast.phone.Bytes(), SuspendId: aclTestSuspendId("authority")}
	state, _ = fixture.apply(t, state, fixture.authorityStatement(bridge.SignedType_SIGNED_SUSPEND, authoritySuspend, cast.ownerDevice, cast.adminDevice))
	authorityUnsuspend := &bridge.Unsuspend{Subject: cast.phone.Bytes(), SuspendId: aclTestSuspendId("authority")}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_UNSUSPEND, authorityUnsuspend, cast.adminDevice), nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("an admin lifting k of n: %v", err)
	}
	state, _ = fixture.apply(t, state, fixture.authorityStatement(bridge.SignedType_SIGNED_UNSUSPEND, authorityUnsuspend, cast.ownerDevice, cast.adminDevice))
	if state.Suspended(cast.phone) {
		t.Error("k of n did not lift its own Suspend")
	}
}

// A grant activated for the Member's laptop, folded as ACL-M2-07 folds one: its rule, its subject's atom and its spent
// row, at a requests rule an admin approves.
func (self *aclStatementCast) activatedGrant(t *testing.T) ([]byte, []byte) {
	t.Helper()
	fixture := self.fixture
	requestId := testConfigId("requests rule").Bytes()
	fixture.rows.Requests = append(fixture.rows.Requests, &protocol.AclRequestRule{
		RuleId:        requestId,
		SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)},
		Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
		ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN).Bytes()},
	})
	grantId := bytes.Repeat([]byte{7}, 32)
	atom := AclDerivedAtom(AclDerivedAtomSidecar, self.laptop.Bytes())
	fixture.rows.Atoms = append(fixture.rows.Atoms, &protocol.AclAtom{Atom: atom.Bytes(), SidecarIds: [][]byte{self.laptop.Bytes()}})
	fixture.rows.Rules = append(fixture.rows.Rules, &protocol.AclRule{
		RuleId: grantId, SrcAtoms: [][]byte{atom.Bytes()}, Targets: []*protocol.AclTarget{aclSidecarTarget(self.stranger)},
		Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)}, SourceRuleId: requestId,
	})
	fixture.rows.SpentGrants = append(fixture.rows.SpentGrants, &protocol.AclSpentGrant{GrantId: grantId, RetainUntilMs: 99})
	return grantId, requestId
}

// GrantRevoke: the grant's subject, an approver its requests rule names, or an admin; an id no active grant carries
// only by an admin, spent then for the network's life; never a stranger or a read_only device.
func TestAclGrantRevokeSigners(t *testing.T) {
	cast := newAclStatementCast()
	grantId, _ := cast.activatedGrant(t)
	state := cast.fixture.state(t)
	unknownId := bytes.Repeat([]byte{9}, 32)
	cases := []struct {
		name    string
		signer  Id
		grantId []byte
		refusal error
	}{
		{name: "the subject", signer: cast.laptop, grantId: grantId},
		{name: "an approver, an admin here", signer: cast.adminDevice, grantId: grantId},
		{name: "the owner, an admin", signer: cast.ownerDevice, grantId: grantId},
		{name: "a stranger", signer: cast.stranger, grantId: grantId, refusal: ErrConfigAuthority},
		{name: "the subject's other device", signer: cast.phone, grantId: grantId, refusal: ErrConfigAuthority},
		{name: "a read_only device", signer: cast.pageWorker, grantId: grantId, refusal: ErrConfigReadOnly},
		{name: "an unknown id by an admin", signer: cast.adminDevice, grantId: unknownId},
		{name: "an unknown id by the subject", signer: cast.laptop, grantId: unknownId, refusal: ErrConfigAuthority},
		{name: "a short id", signer: cast.adminDevice, grantId: []byte{1}, refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: c.grantId}, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}

	// the subject's revocation ends the grant and keeps its id spent with its activation's retention
	if reach := state.Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.stranger), aclTestNow); !reach.Allowed {
		t.Fatalf("before the revoke: %v", reach.Reason)
	}
	state, _ = cast.fixture.apply(t, state, cast.fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: grantId}, cast.laptop))
	if reach := state.Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.stranger), aclTestNow); reach.Allowed {
		t.Error("the revoked grant still reaches")
	}
	if spent := state.spentGrant(grantId); spent == nil || spent.GetRetainUntilMs() != 99 {
		t.Errorf("the spent row %+v", spent)
	}
	// an admin's revocation of an id never activated spends it for the network's life
	state, _ = cast.fixture.apply(t, state, cast.fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: unknownId}, cast.adminDevice))
	if spent := state.spentGrant(unknownId); spent == nil || spent.GetRetainUntilMs() != 0 {
		t.Errorf("the unknown id's spent row %+v", spent)
	}
}

// An owner-bound repo of the Member's, with its laptop as its admin and consented device.
func (self *aclStatementCast) vault() (Id, *protocol.AclRepo) {
	repoId, row := self.fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, self.member)
	row.ConsentedSidecarIds = [][]byte{self.laptop.Bytes(), self.phone.Bytes()}
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: self.laptop.Bytes(), Signer: self.laptop.Bytes(), At: 1}}
	return repoId, row
}

// EvsShare: only a consented device of the owner-bound repo's owner, so every reader refuses an admin's vault share
// (FS-85); never a general repo's, an expired one or a read_only device's.
func TestAclEvsShareSigners(t *testing.T) {
	cast := newAclStatementCast()
	vaultId, _ := cast.vault()
	generalId, _ := cast.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	state := cast.fixture.state(t)
	share := func(repoId Id, expires int64) *protocol.EvsShare {
		return &protocol.EvsShare{RepoId: repoId.Bytes(), Subject: cast.stranger.Bytes(), Expires: expires}
	}
	cases := []struct {
		name    string
		signer  Id
		share   *protocol.EvsShare
		refusal error
	}{
		{name: "the owner's laptop", signer: cast.laptop, share: share(vaultId, 0)},
		{name: "the owner's phone, consented by the laptop", signer: cast.phone, share: share(vaultId, aclTestNow.Add(time.Hour).UnixMilli())},
		{name: "an admin", signer: cast.adminDevice, share: share(vaultId, 0), refusal: ErrConfigAuthority},
		{name: "the Owner of the network", signer: cast.ownerDevice, share: share(vaultId, 0), refusal: ErrConfigAuthority},
		{name: "the owner's agent", signer: cast.agent, share: share(vaultId, 0), refusal: ErrConfigAuthority},
		{name: "a general repo", signer: cast.laptop, share: share(generalId, 0), refusal: ErrConfigRule},
		{name: "expired when it lands", signer: cast.laptop, share: share(vaultId, aclTestNow.UnixMilli()), refusal: ErrConfigRule},
		{name: "an unknown repo", signer: cast.laptop, share: share(NewId(), 0), refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, c.share, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}

	// the owner's share opens exactly its repo to the subject, with its signer and position
	state, _ = cast.fixture.apply(t, state, cast.fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, share(vaultId, 0), cast.laptop))
	if rights := aclTestRights(state, cast.stranger, vaultId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsDeposit {
		t.Errorf("the shared subject: %b", rights)
	}
	shares := state.Repo(vaultId).GetShares()
	if len(shares) != 1 || !bytes.Equal(shares[0].GetSigner(), cast.laptop.Bytes()) || shares[0].GetAt() == 0 {
		t.Errorf("the share row %+v", shares)
	}
	// a reader refuses an admin's share the rows hold anyway (FS-85)
	cast.fixture.rows.Repos[0].Shares = []*protocol.AclRepoShareRow{{Subject: cast.stranger.Bytes(), Signer: cast.adminDevice.Bytes(), At: cast.fixture.next()}}
	if rights := aclTestRights(cast.fixture.state(t), cast.stranger, vaultId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("an admin's share opened the vault: %b", rights)
	}
}

// OwnerConfirm: a consented device of the confirmed sidecar's member, of another of its untagged devices; never an
// admin of another member, the device itself, a tagged or revoked one. Its effect names the signer, and it lists the
// device among the member's owner-bound repos' consented ids.
func TestAclOwnerConfirmSigners(t *testing.T) {
	cast := newAclStatementCast()
	vaultId, vault := cast.vault()
	adminAdmitted := cast.fixture.device(cast.member, cast.adminDevice.Bytes())
	vault.ConsentedSidecarIds = [][]byte{cast.laptop.Bytes()}
	state := cast.fixture.state(t)
	cases := []struct {
		name    string
		signer  Id
		target  Id
		refusal error
	}{
		{name: "the member's laptop", signer: cast.laptop, target: adminAdmitted},
		{name: "an admin", signer: cast.adminDevice, target: adminAdmitted, refusal: ErrConfigAuthority},
		{name: "the device itself", signer: cast.laptop, target: cast.laptop, refusal: ErrConfigRule},
		{name: "a tagged sidecar", signer: cast.laptop, target: cast.agent, refusal: ErrConfigRule},
		{name: "a revoked sidecar", signer: cast.laptop, target: cast.revoked, refusal: ErrConfigRule},
		{name: "another member's device", signer: cast.laptop, target: cast.stranger, refusal: ErrConfigAuthority},
		{name: "an unknown sidecar", signer: cast.laptop, target: NewId(), refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: c.target.Bytes()}, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	state, effect := cast.fixture.apply(t, state, cast.fixture.statement(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: adminAdmitted.Bytes()}, cast.laptop))
	if effect.OwnerConfirmed == nil || effect.OwnerConfirmed.SidecarId != adminAdmitted || effect.OwnerConfirmed.Signer != cast.laptop {
		t.Errorf("the effect %+v", effect.OwnerConfirmed)
	}
	if listed := state.Repo(vaultId).GetConsentedSidecarIds(); len(listed) != 2 || !bytes.Equal(listed[1], adminAdmitted.Bytes()) {
		t.Errorf("the vault's consented ids %x", listed)
	}
}

// §22.5: a non-admin's RepoGrant is refused, a repo admin's and a config writer's take effect, and none lands in an
// owner-bound repo, the directory or a deleted repo.
func TestAclRepoGrantSigners(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	vaultId, _ := cast.vault()
	directoryId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	deletedId, deleted := fixture.repo(protocol.RepoKind_REPO_KIND_RECORD, Id{})
	deleted.Admins = row.Admins
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next()}
	state := fixture.state(t)
	grant := func(repoId Id, role protocol.RepoGrantRole) *protocol.RepoGrant {
		return &protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: cast.stranger.Bytes(), Role: role}
	}
	reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
	cases := []struct {
		name    string
		signer  Id
		grant   *protocol.RepoGrant
		refusal error
	}{
		{name: "the repo admin", signer: cast.laptop, grant: grant(repoId, reader)},
		{name: "a config writer", signer: cast.adminDevice, grant: grant(repoId, reader)},
		{name: "a member who is neither", signer: cast.phone, grant: grant(repoId, reader), refusal: ErrConfigAuthority},
		{name: "a stranger", signer: cast.stranger, grant: grant(repoId, reader), refusal: ErrConfigAuthority},
		{name: "an owner-bound repo", signer: cast.laptop, grant: grant(vaultId, reader), refusal: ErrConfigRule},
		{name: "the directory", signer: cast.adminDevice, grant: grant(directoryId, reader), refusal: ErrConfigRule},
		{name: "a deleted repo", signer: cast.laptop, grant: grant(deletedId, reader), refusal: ErrConfigRule},
		{name: "no role", signer: cast.laptop, grant: grant(repoId, protocol.RepoGrantRole_REPO_GRANT_ROLE_UNSPECIFIED), refusal: ErrConfigRule},
		{name: "a read_only device", signer: cast.pageWorker, grant: grant(repoId, reader), refusal: ErrConfigReadOnly},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, c.grant, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
}

// §22.5: a config writer's RepoRevoke wins over a repo admin's grant and stands until a config writer grants the
// subject again; a repo admin's revoke takes the grant out without standing.
func TestAclConfigWritersRepoRevokeWins(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	state := fixture.state(t)
	grant := &protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: cast.stranger.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
	revoke := &protocol.RepoRevoke{RepoId: repoId.Bytes(), Subject: cast.stranger.Bytes()}
	reads := func(state *AclState) bool {
		return aclTestRights(state, cast.stranger, repoId, AclTokenAudienceEvs).Has(AclEvsRead)
	}

	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, grant, cast.laptop))
	if !reads(state) {
		t.Fatal("the repo admin's grant opens nothing")
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_REVOKE, revoke, cast.adminDevice))
	if reads(state) || len(state.Repo(repoId).GetRevokes()) != 1 {
		t.Fatal("the config writer's revoke did not win or does not stand")
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, grant, cast.laptop))
	if reads(state) {
		t.Error("a repo admin's grant lifted a config writer's standing revoke")
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, grant, cast.ownerDevice))
	if !reads(state) || len(state.Repo(repoId).GetRevokes()) != 0 {
		t.Error("a config writer's grant did not lift the standing revoke")
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_REVOKE, revoke, cast.laptop))
	if reads(state) || len(state.Repo(repoId).GetRevokes()) != 0 {
		t.Error("a repo admin's revoke stood or left the grant")
	}
}

// In an owner-bound repo a RepoRevoke never names its owner or one of its owner's consented devices, a config
// writer's revoke of a share subject takes the share out and stands, and the owner's later EvsShare lifts it
// (plan-ACL-owner-bound-standing-revoke).
func TestAclOwnerBoundStandingRevoke(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	vaultId, _ := cast.vault()
	state := fixture.state(t)
	share := &protocol.EvsShare{RepoId: vaultId.Bytes(), Subject: cast.stranger.Bytes()}
	revoke := func(subject Id) *protocol.RepoRevoke {
		return &protocol.RepoRevoke{RepoId: vaultId.Bytes(), Subject: subject.Bytes()}
	}
	for _, subject := range []Id{cast.laptop, cast.phone, cast.member} {
		if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_REVOKE, revoke(subject), cast.adminDevice), nil); !errors.Is(err, ErrConfigRule) {
			t.Errorf("a revoke of the owner's own: %v", err)
		}
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, share, cast.laptop))
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_REVOKE, revoke(cast.stranger), cast.adminDevice))
	if rights := aclTestRights(state, cast.stranger, vaultId, AclTokenAudienceEvs); rights != 0 || len(state.Repo(vaultId).GetRevokes()) != 1 {
		t.Fatalf("after the revoke: %b", rights)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, share, cast.phone))
	if rights := aclTestRights(state, cast.stranger, vaultId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsDeposit || len(state.Repo(vaultId).GetRevokes()) != 0 {
		t.Errorf("the owner's share after the revoke: %b", rights)
	}
}

// RepoCreate by kind: a member device makes a general repo and becomes its admin; a tagged agent only under an admin
// rule; a config writer makes the team record, mailcfg and one directory; an owner-bound repo by a consented device of
// its owner, listing the owner's consented devices; never the config or a repo the rows hold.
func TestAclRepoCreateSigners(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	existingId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	adminRuleAgent := cast.fixture.agent(cast.member, fixture.tag(cast.member))
	fixture.rule([]Id{fixture.sidecarAtom(adminRuleAgent)}, []*protocol.AclTarget{aclWildcardRepoTarget()}, protocol.AclAction_ACL_ACTION_ADMIN)
	state := fixture.state(t)
	create := func(kind protocol.RepoKind) *protocol.RepoCreate {
		return &protocol.RepoCreate{RepoId: NewId().Bytes(), Kind: kind}
	}
	cases := []struct {
		name    string
		signer  Id
		create  *protocol.RepoCreate
		refusal error
	}{
		{name: "general by a member device", signer: cast.phone, create: create(protocol.RepoKind_REPO_KIND_GENERAL)},
		{name: "record by a tagged agent", signer: cast.agent, create: create(protocol.RepoKind_REPO_KIND_RECORD), refusal: ErrConfigAuthority},
		{name: "record by a tagged agent under an admin rule", signer: adminRuleAgent, create: create(protocol.RepoKind_REPO_KIND_RECORD)},
		{name: "team record by a config writer", signer: cast.adminDevice, create: create(protocol.RepoKind_REPO_KIND_TEAM_RECORD)},
		{name: "team record by a member", signer: cast.laptop, create: create(protocol.RepoKind_REPO_KIND_TEAM_RECORD), refusal: ErrConfigAuthority},
		{name: "mailcfg by a config writer", signer: cast.ownerDevice, create: create(protocol.RepoKind_REPO_KIND_MAILCFG)},
		{name: "a vault by its owner's consented device", signer: cast.laptop, create: create(protocol.RepoKind_REPO_KIND_VAULT)},
		{name: "a vault by an agent", signer: cast.agent, create: create(protocol.RepoKind_REPO_KIND_VAULT), refusal: ErrConfigAuthority},
		{name: "the directory by a config writer", signer: cast.ownerDevice, create: create(protocol.RepoKind_REPO_KIND_DIRECTORY)},
		{name: "the directory by a member", signer: cast.laptop, create: create(protocol.RepoKind_REPO_KIND_DIRECTORY), refusal: ErrConfigAuthority},
		{name: "the config", signer: cast.ownerDevice, create: create(protocol.RepoKind_REPO_KIND_CONFIG), refusal: ErrConfigRule},
		{name: "a repo the rows hold", signer: cast.laptop, create: &protocol.RepoCreate{RepoId: existingId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}, refusal: ErrConfigRule},
		{name: "no kind", signer: cast.laptop, create: create(protocol.RepoKind_REPO_KIND_UNSPECIFIED), refusal: ErrConfigRule},
		{name: "the wildcard id", signer: cast.laptop, create: &protocol.RepoCreate{RepoId: make([]byte, 16), Kind: protocol.RepoKind_REPO_KIND_GENERAL}, refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, c.create, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}

	vault := create(protocol.RepoKind_REPO_KIND_VAULT)
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, vault, cast.laptop))
	row := state.Repo(Id(vault.GetRepoId()))
	if Id(row.GetOwnerMemberId()) != cast.member || len(row.GetAdmins()) != 1 || !bytes.Equal(row.GetAdmins()[0].GetSidecarId(), cast.laptop.Bytes()) ||
		len(row.GetConsentedSidecarIds()) != 2 {
		t.Errorf("the vault's row %+v", row)
	}
	if rights := aclTestRights(state, cast.phone, Id(vault.GetRepoId()), AclTokenAudienceEvs); rights != AclEvsRead|AclEvsWrite {
		t.Errorf("the owner's phone in its new vault: %b", rights)
	}
	directory := create(protocol.RepoKind_REPO_KIND_DIRECTORY)
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, directory, cast.ownerDevice))
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, create(protocol.RepoKind_REPO_KIND_DIRECTORY), cast.adminDevice), nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a second directory: %v", err)
	}
}

// RepoAdmin: a repo admin or a config writer adds and removes; never an add in the directory; in an owner-bound repo
// an add only by a consented device of its owner, of one.
func TestAclRepoAdminSigners(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	vaultId, _ := cast.vault()
	directoryId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	state := fixture.state(t)
	admin := func(repoId Id, sidecarId Id, change protocol.RepoAdminChange) *protocol.RepoAdmin {
		return &protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: sidecarId.Bytes(), Change: change}
	}
	add, remove := protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD, protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE
	cases := []struct {
		name    string
		signer  Id
		admin   *protocol.RepoAdmin
		refusal error
	}{
		{name: "the repo admin adds", signer: cast.laptop, admin: admin(repoId, cast.phone, add)},
		{name: "a config writer removes", signer: cast.adminDevice, admin: admin(repoId, cast.laptop, remove)},
		{name: "a member adds", signer: cast.phone, admin: admin(repoId, cast.phone, add), refusal: ErrConfigAuthority},
		{name: "an add in the directory", signer: cast.ownerDevice, admin: admin(directoryId, cast.phone, add), refusal: ErrConfigRule},
		{name: "the owner's phone adds itself to its vault", signer: cast.phone, admin: admin(vaultId, cast.phone, add)},
		{name: "a config writer adds to a vault", signer: cast.adminDevice, admin: admin(vaultId, cast.adminDevice, add), refusal: ErrConfigAuthority},
		{name: "the owner adds an admin's device to its vault", signer: cast.laptop, admin: admin(vaultId, cast.adminDevice, add), refusal: ErrConfigRule},
		{name: "a config writer removes from a vault", signer: cast.adminDevice, admin: admin(vaultId, cast.laptop, remove)},
		{name: "an add of an unknown sidecar", signer: cast.laptop, admin: admin(repoId, NewId(), add), refusal: ErrConfigRule},
		{name: "no change", signer: cast.laptop, admin: admin(repoId, cast.phone, protocol.RepoAdminChange_REPO_ADMIN_CHANGE_UNSPECIFIED), refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN, c.admin, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN, admin(repoId, cast.phone, add), cast.laptop))
	if rights := aclTestRights(state, cast.phone, repoId, AclTokenAudienceEvs); !rights.Has(AclEvsAdmin) {
		t.Errorf("the added admin: %b", rights)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN, admin(repoId, cast.phone, remove), cast.adminDevice))
	if rights := aclTestRights(state, cast.phone, repoId, AclTokenAudienceEvs); rights.Has(AclEvsAdmin) {
		t.Errorf("the removed admin: %b", rights)
	}
}

// A view whose entries' times a test sets, as a ConfigState's log answers them.
type aclTestTimedView struct {
	*aclTestView
	times map[uint64]int64
}

func (self *aclTestTimedView) aclTimeAt(n uint64) (int64, bool) {
	timeMs, found := self.times[n]
	return timeMs, found
}

// RepoDelete by a repo admin, and RepoRestore of its deletion_id within 7 days of its entry: never a RepoDelete with
// now, another deletion's id, one whose entry the state cannot date, or past the window.
func TestAclRepoDeleteAndRestore(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	timed := &aclTestTimedView{aclTestView: fixture.view, times: map[uint64]int64{}}
	stateOver := func() *AclState {
		state, err := NewAclState(fixture.rows, timed)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	state := stateOver()
	deletionId := NewId().Bytes()
	deletion := &protocol.RepoDelete{RepoId: repoId.Bytes(), DeletionId: deletionId}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_DELETE, deletion, cast.ownerDevice), nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("a config writer that is no repo admin deletes: %v", err)
	}
	statement := fixture.statement(bridge.SignedType_SIGNED_REPO_DELETE, deletion, cast.laptop)
	verdict, err := state.CheckStatement(statement, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rows = rows
	timed.times[statement.N] = statement.TimeMs
	state = stateOver()
	if rights := aclTestRights(state, cast.laptop, repoId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("a deleted repo: %b", rights)
	}

	restore := &protocol.RepoRestore{RepoId: repoId.Bytes(), DeletionId: deletionId}
	late := fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, restore, cast.laptop)
	late.TimeMs = statement.TimeMs + aclRepoRestoreWindowMs + 1
	cases := []struct {
		name      string
		statement *AclStatement
		refusal   error
	}{
		{name: "past 7 days", statement: late, refusal: ErrConfigRule},
		{name: "another deletion", statement: fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, &protocol.RepoRestore{RepoId: repoId.Bytes(), DeletionId: NewId().Bytes()}, cast.laptop), refusal: ErrConfigRule},
		{name: "not a repo admin", statement: fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, restore, cast.phone), refusal: ErrConfigAuthority},
		{name: "within 7 days", statement: fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, restore, cast.laptop)},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(c.statement, nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	delete(timed.times, statement.N)
	if _, err := stateOver().CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, restore, cast.laptop), nil); !errors.Is(err, ErrConfigRuleMissing) {
		t.Errorf("a restore whose delete the state cannot date: %v", err)
	}
	timed.times[statement.N] = statement.TimeMs

	restoreStatement := fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, restore, cast.laptop)
	verdict, err = state.CheckStatement(restoreStatement, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.rows, _, err = state.ApplyStatement(restoreStatement, verdict); err != nil {
		t.Fatal(err)
	}
	state = stateOver()
	if rights := aclTestRights(state, cast.laptop, repoId, AclTokenAudienceEvs); !rights.Has(AclEvsAdmin) {
		t.Errorf("a restored repo: %b", rights)
	}
	// a RepoDelete with now is never restored
	nowDeletion := &protocol.RepoDelete{RepoId: repoId.Bytes(), DeletionId: NewId().Bytes(), Now: true}
	state, _ = fixture.applyTimed(t, timed, fixture.statement(bridge.SignedType_SIGNED_REPO_DELETE, nowDeletion, cast.laptop))
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_RESTORE, &protocol.RepoRestore{RepoId: repoId.Bytes(), DeletionId: nowDeletion.GetDeletionId()}, cast.laptop), nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a restore of a delete with now: %v", err)
	}
}

// apply over a timed view.
func (self *aclTestFixture) applyTimed(t *testing.T, timed *aclTestTimedView, statement *AclStatement) (*AclState, AclStatementEffect) {
	t.Helper()
	state, err := NewAclState(self.rows, timed)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := state.CheckStatement(statement, nil)
	if err != nil {
		t.Fatalf("%s: %v", statement.Type, err)
	}
	rows, effect, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	self.rows = rows
	timed.times[statement.N] = statement.TimeMs
	next, err := NewAclState(self.rows, timed)
	if err != nil {
		t.Fatal(err)
	}
	return next, effect
}

// FS-95's format-1 case: a RepoVersioning's signer is verified, its lock folded, and nothing enforced: every right on
// the repo stays as it was, its rules skipped unread.
func TestAclRepoVersioningFoldsTheLockAndEnforcesNothing(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	vaultId, _ := cast.vault()
	state := fixture.state(t)
	versioning := func(repoId Id, lock protocol.RepoVersioningLock) *protocol.RepoVersioning {
		return &protocol.RepoVersioning{RepoId: repoId.Bytes(), Lock: lock, SealedRules: []byte("sealed rules no format-1 reader opens")}
	}
	locked := protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
	cases := []struct {
		name       string
		signer     Id
		versioning *protocol.RepoVersioning
		refusal    error
	}{
		{name: "the repo admin", signer: cast.laptop, versioning: versioning(repoId, locked)},
		{name: "a config writer", signer: cast.adminDevice, versioning: versioning(repoId, locked)},
		{name: "a member", signer: cast.phone, versioning: versioning(repoId, locked), refusal: ErrConfigAuthority},
		{name: "the vault's owner", signer: cast.phone, versioning: versioning(vaultId, locked)},
		{name: "a config writer on a vault", signer: cast.adminDevice, versioning: versioning(vaultId, locked), refusal: ErrConfigAuthority},
		{name: "no lock", signer: cast.laptop, versioning: versioning(repoId, protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNSPECIFIED), refusal: ErrConfigRule},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_VERSIONING, c.versioning, c.signer), nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	before := aclTestRights(state, cast.laptop, repoId, AclTokenAudienceEvs)
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_VERSIONING, versioning(repoId, locked), cast.laptop))
	if state.Repo(repoId).GetLock() != locked {
		t.Error("the lock did not fold")
	}
	if after := aclTestRights(state, cast.laptop, repoId, AclTokenAudienceEvs); after != before {
		t.Errorf("a format-1 lock changed rights: %b to %b", before, after)
	}
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_VERSIONING, versioning(repoId, protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED), cast.adminDevice))
	if state.Repo(repoId).GetLock() != protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED {
		t.Error("the newest RepoVersioning's lock did not win")
	}
}

// Every acl statement refuses a body of another type, k-of-n signers on a type that takes none, and the audit
// statements until ACL-M6-02.
func TestAclStatementShapeRefusals(t *testing.T) {
	cast := newAclStatementCast()
	state := cast.fixture.state(t)
	cases := []struct {
		name      string
		statement *AclStatement
		refusal   error
	}{
		{name: "a body of another type", statement: cast.fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoRevoke{}, cast.laptop), refusal: ErrConfigRule},
		{name: "k of n on a RepoGrant", statement: cast.fixture.authorityStatement(bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{}, cast.laptop, cast.ownerDevice), refusal: ErrConfigRule},
		{name: "one signer's AuditOptIn", statement: cast.fixture.statement(bridge.SignedType_SIGNED_AUDIT_OPT_IN, &protocol.AuditOptIn{}, cast.ownerDevice), refusal: ErrConfigAuthority},
		{name: "two signers on one statement", statement: &AclStatement{Type: bridge.SignedType_SIGNED_REPO_GRANT, Body: &protocol.RepoGrant{},
			Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: cast.laptop}, {Kind: ConfigSignerSidecar, SidecarId: cast.phone}}}, refusal: ErrConfigRule},
		{name: "a recovery key's signature", statement: &AclStatement{Type: bridge.SignedType_SIGNED_REPO_GRANT, Body: &protocol.RepoGrant{},
			Signers: []ConfigSigner{{Kind: ConfigSignerRecovery, MemberId: cast.member}}}, refusal: ErrConfigSigner},
	}
	for _, c := range cases {
		if _, err := state.CheckStatement(c.statement, nil); aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
}

// A member made an Admin by an AdminSet of the owner and it, at k = 1, and its one device, a config writer.
func (self *testConfigNet) admitAdmin(label string) testConfigDevice {
	self.t.Helper()
	memberId := testConfigId(label + " admin member")
	self.admitMember(self.owner, memberId, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.mustPost(self.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: self.header(), Owners: [][]byte{self.ownerMemberId.Bytes()}, Admins: [][]byte{memberId.Bytes()},
	})
	device := self.device(label+" admin device", memberId)
	self.admitDevice(self.owner, device, 0)
	if !self.log.State().IsConfigWriter(device.sidecarId) {
		self.t.Fatal("the admin's device writes no config heads")
	}
	return device
}

// A Suspend of an AdminSet member's device needs its owner or k of n: an admin alone is refused, a proposal and one
// cosign suspend it at class 3, only k of n lifts it, and the Unsuspend makes the device live again at its position
// (§8.8, §7.9's leaves row), all through TEAM's log.
func TestAclKOfNSuspendThroughTheLog(t *testing.T) {
	team := newTestConfigTeam(t)
	suspendId := aclTestSuspendId("k of n")
	subject := team.adminC.sidecarId
	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: team.header(), Subject: subject.Bytes(), SuspendId: suspendId}, ErrConfigAuthority)

	verdict, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: team.header(), Subject: subject.Bytes(), SuspendId: suspendId})
	if !verdict.Accepted() || team.log.State().Suspended(subject) {
		t.Fatalf("the open proposal: %v", verdict.Refusal)
	}
	if verdict := team.cosign(team.adminB, proposalId); !verdict.Accepted() {
		t.Fatalf("the completing cosign: %v", verdict.Refusal)
	}
	state := team.log.State()
	if !state.Suspended(subject) || state.aclRows.GetSuspensions()[0].GetSignerClass() != AclSuspendClassAuthority {
		t.Fatal("the k-of-n Suspend is not in force at class 3")
	}

	unsuspend := func() *bridge.Unsuspend {
		return &bridge.Unsuspend{Header: team.header(), Subject: subject.Bytes(), SuspendId: suspendId}
	}
	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_UNSUSPEND, unsuspend(), ErrConfigAuthority)
	_, proposalId = team.propose(team.owner, bridge.SignedType_SIGNED_UNSUSPEND, unsuspend())
	if verdict := team.cosign(team.adminB, proposalId); !verdict.Accepted() {
		t.Fatalf("the k-of-n Unsuspend: %v", verdict.Refusal)
	}
	state = team.log.State()
	if state.Suspended(subject) || state.SidecarRow(subject).GetLiveSince() != team.n {
		t.Errorf("after the Unsuspend: suspended %v, live_since %d at %d", state.Suspended(subject), state.SidecarRow(subject).GetLiveSince(), team.n)
	}
}

// An OwnerConfirm writes its signer and position on the confirmed sidecar's row, which then counts as consented
// (§8.5's confirmed clause), through TEAM's log.
func TestAclOwnerConfirmWritesTheRow(t *testing.T) {
	net := newTestConfigNet(t)
	admin := net.admitAdmin("admin")
	member, first := net.consentedMember("confirming member")
	second := net.device("admin admitted device", member)
	net.admitDevice(admin, second, 0)
	acl, err := net.log.State().Acl()
	if err != nil || acl.ConsentedFor(second.sidecarId, member) {
		t.Fatalf("an admin's admission consents: %v", err)
	}
	net.mustRefuse(admin, bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{Header: net.header(), SidecarId: second.sidecarId.Bytes()}, ErrConfigAuthority)
	net.mustPost(first, bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{Header: net.header(), SidecarId: second.sidecarId.Bytes()})
	state := net.log.State()
	row := state.SidecarRow(second.sidecarId)
	if !bytes.Equal(row.GetOwnerConfirmSigner(), first.sidecarId.Bytes()) || row.GetOwnerConfirmedAt() != net.n {
		t.Errorf("the confirmed row: %x at %d", row.GetOwnerConfirmSigner(), row.GetOwnerConfirmedAt())
	}
	if acl, err := state.Acl(); err != nil || !acl.ConsentedFor(second.sidecarId, member) {
		t.Errorf("the confirmed device is not consented: %v", err)
	}
}

// A Suspend of an agent a live Delegation admitted drops that Delegation's shared reader key at its position (§8.6's
// one switch, §10.5), through TEAM's log.
func TestAclSuspendDropsTheDelegationsKey(t *testing.T) {
	net := newTestConfigNet(t)
	state := net.log.State()
	rows := state.Rows()
	delegationId := bytes.Repeat([]byte{0xd1}, 32)
	agent := net.device("delegated agent", Id{})
	tagId := testConfigId("ci tag")
	rows.Delegations = append(rows.Delegations, &bridge.DelegationRow{
		DelegationId: delegationId, Signer: net.owner.sidecarId.Bytes(), At: net.n, TagAtoms: [][]byte{tagId.Bytes()},
		NotAfter: testConfigStartMs + 30*24*60*60*1000,
	})
	rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
		SidecarId: agent.sidecarId.Bytes(), AdmissionSigners: [][]byte{delegationId}, AdmittedAt: net.n,
		IdentityPublicKey: agent.publicKey(), IdentityAlg: configIdentityAlgEd25519, TagIds: [][]byte{tagId.Bytes()},
		Sponsor: net.ownerMemberId.Bytes(), DelegationId: delegationId, NotAfter: testConfigStartMs + 24*60*60*1000,
	})
	if verdict := net.pushBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, state.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: agent.sidecarId.Bytes(), SuspendId: aclTestSuspendId("agent")})
	if dropped := net.log.State().Delegation(delegationId).GetKeyDroppedAt(); dropped != net.n {
		t.Errorf("key_dropped_at %d at %d", dropped, net.n)
	}
}

// ReapplyStatement keeps a revocation past an authority change: a config writer's standing RepoRevoke still stands
// once a base folds below it and re-applies its tail, the AdminSet that then took its signer's role among it, where a
// fresh check refuses the same signer; a second reader reaches the same rows. The authority change is the log's own,
// since a re-application recomputes what an effect derives on the rows it rebuilds (DESIGN-DETAILS 5.2.3), and rows at
// the fold are the log's there.
func TestAclReapplyKeepsARevocationPastAnAuthorityChange(t *testing.T) {
	net := newTestConfigNet(t)
	writer := net.admitAdmin("revoking")
	reader := net.admitMemberDevice("revoked reader")
	repoId := testConfigId("general repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	reads := func() bool {
		acl, err := net.log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		return acl.EvsAccess(AclSidecarSubject(reader.sidecarId), repoId, AclTokenAudienceEvs, time.UnixMilli(net.timeMs)).Rights.Has(AclEvsRead)
	}
	if !reads() {
		t.Fatal("the grant opens nothing")
	}
	revoke := &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()}
	revokedAt := net.mustPost(writer, bridge.SignedType_SIGNED_REPO_REVOKE, revoke).Pin.GetVersion()
	// the writer's member no longer an Admin, then a base below the revoke whose tail re-applies both
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()},
	})
	folded := net.statesAt[revokedAt-1]
	if verdict := net.pushBase(net.owner, folded.Rows(), revokedAt-1, 2, folded.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if net.log.State().IsConfigWriter(writer.sidecarId) {
		t.Fatal("the base left the writer a config writer")
	}

	state := net.log.State()
	revokes := state.Repo(repoId).GetRevokes()
	if len(revokes) != 1 || !bytes.Equal(revokes[0].GetSigner(), writer.sidecarId.Bytes()) || revokes[0].GetAt() != revokedAt {
		t.Fatalf("the standing revoke after the base: %+v", revokes)
	}
	if reads() {
		t.Error("the re-applied revocation let the reader back")
	}
	acl, _ := state.Acl()
	fresh := &AclStatement{Type: bridge.SignedType_SIGNED_REPO_REVOKE, Body: revoke, Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: writer.sidecarId}},
		N: net.n + 1, TimeMs: net.timeMs}
	if _, err := acl.CheckStatement(fresh, nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the revoked writer's revoke judged fresh: %v", err)
	}
	if !bytes.Equal(testConfigRowsBytes(t, state), testConfigRowsBytes(t, net.newReader().State())) {
		t.Error("a second reader holds other rows")
	}
}

// api alone refuses a directory RepoCreate outside the team tier: AclStatementNeedsTeamTier names exactly that
// statement, whatever else arrives.
func TestAclStatementNeedsTeamTier(t *testing.T) {
	net := newTestConfigNet(t)
	create := func(kind protocol.RepoKind) []byte {
		return net.sign(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: NewId().Bytes(), Kind: kind})
	}
	cases := []struct {
		name   string
		signed []byte
		team   bool
	}{
		{name: "the directory", signed: create(protocol.RepoKind_REPO_KIND_DIRECTORY), team: true},
		{name: "a general repo", signed: create(protocol.RepoKind_REPO_KIND_GENERAL)},
		{name: "the team record", signed: create(protocol.RepoKind_REPO_KIND_TEAM_RECORD)},
		{name: "another type", signed: net.sign(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("tier"))},
		{name: "no Signed", signed: []byte{0x0A, 0xFF}},
	}
	for _, c := range cases {
		if team := AclStatementNeedsTeamTier(c.signed); team != c.team {
			t.Errorf("%s: %v", c.name, team)
		}
	}
}
