// §8.12's evs rights on hand-made rows: the config by audience, the directory, owner-bound repos, kind
// defaults that * never reaches, deposit granting no read, §8.6's ephemeral ceiling, the access log, and
// the reader and writer sets. Pure, on every leg.

package sidecar

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A repo of a kind as a state comes to hold one: the config from the Genesis, with no row (QD-719), any other as a row.
func aclTestKindRepo(fixture *aclTestFixture, kind protocol.RepoKind, ownerId Id) Id {
	if kind == protocol.RepoKind_REPO_KIND_CONFIG {
		return fixture.configRepo(Id{}, Id{})
	}
	repoId, _ := fixture.repo(kind, ownerId)
	return repoId
}

// The rights a sidecar holds on a repo now, at an audience.
func aclTestRights(state *AclState, sidecarId Id, repoId Id, audience AclTokenAudience) AclEvsRights {
	return state.EvsAccess(AclSidecarSubject(sidecarId), repoId, audience, aclTestNow).Rights
}

// The config gives every admitted sidecar r, gkm rw to member devices but read_only ones, and evs rw only
// to config writers; an ephemeral sidecar never writes it (§7.9, §10.6, FS-19).
func TestAclEvsAccessConfigByAudience(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	writer := fixture.device(owner)
	fixture.view.configWriters[writer] = true
	memberDevice := fixture.device(member)
	pageWorker := fixture.device(member)
	fixture.admission(pageWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	ephemeral := fixture.device(owner)
	fixture.admission(ephemeral).Ephemeral = true
	ephemeralWriter := fixture.device(owner)
	fixture.admission(ephemeralWriter).Ephemeral = true
	fixture.view.configWriters[ephemeralWriter] = true
	agent := fixture.agent(owner, tagId)
	// the config's row is the state's own, from the Genesis (QD-719)
	configId := fixture.configRepo(Id{}, Id{})
	// no rule reaches the config, whatever it names
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR), []*protocol.AclTarget{aclRepoTarget(configId), aclWildcardRepoTarget()},
		protocol.AclAction_ACL_ACTION_ADMIN)
	state := fixture.state(t)
	cases := []struct {
		sidecarId Id
		evs, gkm  AclEvsRights
	}{
		{sidecarId: writer, evs: AclEvsRead | AclEvsWrite, gkm: AclEvsRead | AclEvsWrite},
		{sidecarId: memberDevice, evs: AclEvsRead, gkm: AclEvsRead | AclEvsWrite},
		{sidecarId: pageWorker, evs: AclEvsRead | AclEvsDeposit, gkm: AclEvsRead | AclEvsDeposit},
		{sidecarId: ephemeral, evs: AclEvsRead, gkm: AclEvsRead},
		{sidecarId: ephemeralWriter, evs: AclEvsRead, gkm: AclEvsRead},
		{sidecarId: agent, evs: AclEvsRead, gkm: AclEvsRead},
	}
	for i, c := range cases {
		evs := aclTestRights(state, c.sidecarId, configId, AclTokenAudienceEvs)
		gkm := aclTestRights(state, c.sidecarId, configId, AclTokenAudienceGkm)
		if evs != c.evs || gkm != c.gkm {
			t.Errorf("case %d: evs %b gkm %b, want %b %b", i, evs, gkm, c.evs, c.gkm)
		}
	}
	fixture.view.parked[memberDevice] = true
	if rights := aclTestRights(fixture.state(t), memberDevice, configId, AclTokenAudienceGkm); rights != 0 {
		t.Errorf("parked device reads the config: %b", rights)
	}
}

// §7.9's bootstrap: the Genesis's owner sidecar administers the config repo at both audiences while it stands as a
// config writer, the scope the exchange gives it alone to create the repo, push its head and form its group. No other
// config writer does, nor that sidecar once it is no config writer, read_only, parked or revoked.
func TestAclEvsAccessConfigAdminIsTheBootstrapSidecars(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	first := fixture.device(owner)
	second := fixture.device(owner)
	fixture.view.configWriters[first] = true
	fixture.view.configWriters[second] = true
	configId := fixture.configRepo(first, owner)
	all := AclEvsRead | AclEvsWrite | AclEvsAdmin
	state := fixture.state(t)
	for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
		if rights := aclTestRights(state, first, configId, audience); rights != all {
			t.Errorf("the bootstrap sidecar at %d: %b", audience, rights)
		}
		if rights := aclTestRights(state, second, configId, audience); rights != AclEvsRead|AclEvsWrite {
			t.Errorf("another config writer at %d: %b", audience, rights)
		}
	}
	access := state.EvsAccess(AclSidecarSubject(first), configId, AclTokenAudienceEvs, aclTestNow)
	if !access.Allowed || access.Reason != AclReasonKindDefault {
		t.Errorf("the bootstrap sidecar's decision: %+v", access)
	}

	fixture.view.configWriters[first] = false
	state = fixture.state(t)
	if evs, gkm := aclTestRights(state, first, configId, AclTokenAudienceEvs), aclTestRights(state, first, configId, AclTokenAudienceGkm); evs != AclEvsRead || gkm != AclEvsRead|AclEvsWrite {
		t.Errorf("no longer a config writer: evs %b gkm %b", evs, gkm)
	}
	fixture.view.configWriters[first] = true
	fixture.admission(first).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	if rights := aclTestRights(fixture.state(t), first, configId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsDeposit {
		t.Errorf("read_only: %b", rights)
	}
	fixture.admission(first).Row.Capabilities = 0
	fixture.view.parked[first] = true
	if rights := aclTestRights(fixture.state(t), first, configId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("parked: %b", rights)
	}
	fixture.view.parked[first] = false
	fixture.admission(first).Row.RevokedAt = fixture.next()
	if rights := aclTestRights(fixture.state(t), first, configId, AclTokenAudienceGkm); rights != 0 {
		t.Errorf("revoked: %b", rights)
	}

	// rows that hold the config's row by hand answer alike, and name no admin either
	held := newAclTestFixture()
	owner = held.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	first = held.device(owner)
	held.view.configWriters[first] = true
	configId = held.configRepo(first, owner)
	held.rows.Repos = append(held.rows.Repos, &protocol.AclRepo{RepoId: configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG})
	if rights := aclTestRights(held.state(t), first, configId, AclTokenAudienceEvs); rights != all {
		t.Errorf("with the row in the rows: %b", rights)
	}
}

// The directory: every admitted sidecar reads it and every one not read_only writes its own paths;
// admin only for its consented, not read_only admins, its creator and config writers (D-ACL-24, §8.8).
func TestAclEvsAccessDirectory(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	creator := fixture.invitedDevice(owner)
	writer := fixture.device(owner, creator.Bytes())
	fixture.view.configWriters[writer] = true
	unconsentedWriter := fixture.device(member, NewId().Bytes())
	fixture.view.configWriters[unconsentedWriter] = true
	memberDevice := fixture.device(member, NewId().Bytes())
	pageWorker := fixture.device(member, NewId().Bytes())
	fixture.admission(pageWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	ephemeral := fixture.device(owner, creator.Bytes())
	fixture.admission(ephemeral).Ephemeral = true
	agent := fixture.agent(owner, tagId)
	directoryId, row := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: creator.Bytes(), Signer: creator.Bytes(), At: fixture.next()}}
	// a document neither widens nor narrows it
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), []*protocol.AclTarget{aclRepoTarget(directoryId)}, protocol.AclAction_ACL_ACTION_ADMIN)
	state := fixture.state(t)
	all := AclEvsRead | AclEvsWrite | AclEvsAdmin
	cases := []struct {
		sidecarId Id
		rights    AclEvsRights
	}{
		{sidecarId: creator, rights: all},
		{sidecarId: writer, rights: all},
		{sidecarId: unconsentedWriter, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: memberDevice, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: pageWorker, rights: AclEvsRead | AclEvsDeposit},
		{sidecarId: ephemeral, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: agent, rights: AclEvsRead | AclEvsWrite},
	}
	for i, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, directoryId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("case %d: %b, want %b", i, rights, c.rights)
		}
	}
}

// An owner-bound repo: the owner's consented devices read and write, those among its admins administer,
// an EvsShare's subject reads with the receipt deposit, the owner's other untagged subjects and the tagged
// subjects it sponsors deposit into a vault, and an admin-admitted device of the owner only deposits
// (§8.5, owner decision 126).
func TestAclEvsAccessOwnerBound(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	tagId := fixture.tag(owner)
	adminDevice := fixture.invitedDevice(admin)
	laptop := fixture.invitedDevice(owner)
	phone := fixture.device(owner, laptop.Bytes())
	adminAdmitted := fixture.device(owner, adminDevice.Bytes())
	sponsored := fixture.agent(owner, tagId)
	friend := fixture.invitedDevice(admin)
	vaultId, vault := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	vault.ConsentedSidecarIds = [][]byte{laptop.Bytes(), phone.Bytes()}
	vault.Admins = []*protocol.AclRepoAdminRow{{SidecarId: laptop.Bytes(), Signer: laptop.Bytes(), At: fixture.next()}}
	vault.Shares = []*protocol.AclRepoShareRow{{Subject: friend.Bytes(), Signer: laptop.Bytes(), At: fixture.next()}}
	secretId, secret := fixture.repo(protocol.RepoKind_REPO_KIND_SECRET, owner)
	secret.ConsentedSidecarIds = vault.ConsentedSidecarIds
	state := fixture.state(t)
	cases := []struct {
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{sidecarId: laptop, repoId: vaultId, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin},
		{sidecarId: phone, repoId: vaultId, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: adminAdmitted, repoId: vaultId, rights: AclEvsDeposit},
		{sidecarId: sponsored, repoId: vaultId, rights: AclEvsDeposit},
		{sidecarId: friend, repoId: vaultId, rights: AclEvsRead | AclEvsDeposit},
		{sidecarId: adminDevice, repoId: vaultId, rights: 0},
		{sidecarId: phone, repoId: secretId, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: adminAdmitted, repoId: secretId, rights: 0},
		{sidecarId: sponsored, repoId: secretId, rights: 0},
	}
	for i, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("case %d: %b, want %b", i, rights, c.rights)
		}
	}
}

// An EvsShare opens nothing when an admin signed it, when it expired, or when a cascade voids its signer
// (§7.9, FS-85).
func TestAclEvsShareMustBeTheOwnersAndInForce(t *testing.T) {
	cases := []struct {
		name string
		edit func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id)
		open bool
	}{
		{name: "owner's", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {}, open: true},
		{name: "admin's", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {
			share.Signer = adminDevice.Bytes()
		}},
		{name: "expired", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {
			share.Expires = aclTestNow.UnixMilli()
		}},
		{name: "unexpired", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {
			share.Expires = aclTestNow.Add(time.Millisecond).UnixMilli()
		}, open: true},
		{name: "voided by a cascade", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {
			fixture.view.voidFrom[string(laptop.Bytes())] = share.At
		}},
		{name: "signed before the cascade's since_n", edit: func(fixture *aclTestFixture, share *protocol.AclRepoShareRow, laptop Id, adminDevice Id) {
			fixture.view.voidFrom[string(laptop.Bytes())] = share.At + 1
		}, open: true},
	}
	for _, c := range cases {
		fixture := newAclTestFixture()
		owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
		admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
		adminDevice := fixture.invitedDevice(admin)
		laptop := fixture.invitedDevice(owner)
		friend := fixture.device(admin, adminDevice.Bytes())
		mailboxId, mailbox := fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, owner)
		share := &protocol.AclRepoShareRow{Subject: friend.Bytes(), Signer: laptop.Bytes(), At: fixture.next()}
		mailbox.Shares = []*protocol.AclRepoShareRow{share}
		c.edit(fixture, share, laptop, adminDevice)
		rights := aclTestRights(fixture.state(t), friend, mailboxId, AclTokenAudienceEvs)
		if rights.Has(AclEvsRead) != c.open {
			t.Errorf("%s: rights %b, want open %t", c.name, rights, c.open)
		}
	}
}

// * and evs:* reach general and record repos only, never a kind §8.5 fixes, and a rule naming one of
// those outright adds readers only to team_record and mailcfg.
func TestAclWildcardNeverReachesKindDefaults(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	agent := fixture.agent(owner, tagId)
	repoIds := map[protocol.RepoKind]Id{}
	for kind := protocol.RepoKind_REPO_KIND_GENERAL; kind <= protocol.RepoKind_REPO_KIND_SECRET; kind += 1 {
		repoIds[kind] = aclTestKindRepo(fixture, kind, owner)
	}
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclWildcardRepoTarget()}, protocol.AclAction_ACL_ACTION_READ)
	state := fixture.state(t)
	for kind, repoId := range repoIds {
		want := aclRepoKindGeneral(kind) || kind == protocol.RepoKind_REPO_KIND_CONFIG || kind == protocol.RepoKind_REPO_KIND_DIRECTORY
		if rights := aclTestRights(state, agent, repoId, AclTokenAudienceEvs); rights.Has(AclEvsRead) != want {
			t.Errorf("%s: rights %b", kind, rights)
		}
	}

	explicit := newAclTestFixture()
	owner = explicit.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId = explicit.tag(owner)
	agent = explicit.agent(explicit.member(bridge.MemberRole_MEMBER_ROLE_MEMBER), tagId)
	for kind := protocol.RepoKind_REPO_KIND_GENERAL; kind <= protocol.RepoKind_REPO_KIND_SECRET; kind += 1 {
		repoIds[kind] = aclTestKindRepo(explicit, kind, owner)
		explicit.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(repoIds[kind])}, protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_DEPOSIT)
	}
	state = explicit.state(t)
	for kind, repoId := range repoIds {
		var want AclEvsRights
		switch kind {
		case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_MAILCFG:
			want = AclEvsRead | AclEvsDeposit
		case protocol.RepoKind_REPO_KIND_TEAM_RECORD:
			// a tagged subject deposits by kind default; the rule adds the read
			want = AclEvsRead | AclEvsDeposit
		case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX:
			want = AclEvsDeposit
		case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_DIRECTORY:
			want = AclEvsRead | AclEvsWrite
			if kind == protocol.RepoKind_REPO_KIND_CONFIG {
				want = AclEvsRead
			}
		}
		if rights := aclTestRights(state, agent, repoId, AclTokenAudienceEvs); rights != want {
			t.Errorf("explicit %s: rights %b, want %b", kind, rights, want)
		}
	}
}

// Deposit implies no read: a deposit grant leaves its subject out of RepoReaders.
func TestAclDepositGrantsNoRead(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	depositor := fixture.agent(owner, tagId)
	reader := fixture.device(owner)
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_DEPOSIT)
	row.Grants = []*protocol.AclRepoGrantRow{{Subject: reader.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Signer: reader.Bytes(), At: fixture.next()}}
	state := fixture.state(t)
	if rights := aclTestRights(state, depositor, repoId, AclTokenAudienceEvs); rights != AclEvsDeposit {
		t.Errorf("depositor: %b", rights)
	}
	if readers := state.RepoReaders(repoId, aclTestNow); !slices.Equal(readers, []Id{reader}) {
		t.Errorf("readers %v", readers)
	}
}

// §8.6's ceiling: an ephemeral sidecar takes from rules, RepoGrants and EvsShares only those naming it, and
// kind-default deposits, and never its member's write or admin (D-ACL-19).
func TestAclEphemeralCeiling(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	laptop := fixture.invitedDevice(owner)
	burner := fixture.device(owner, laptop.Bytes())
	fixture.admission(burner).Ephemeral = true
	ci := fixture.agent(owner, tagId)
	fixture.admission(ci).Ephemeral = true
	named, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	byMember, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	byEphemeral, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	byTag, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	grantedToMember, memberGrant := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	grantedToSidecar, sidecarGrant := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	vaultId, vault := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	vault.ConsentedSidecarIds = [][]byte{laptop.Bytes()}
	mailboxId, mailbox := fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, owner)
	mailbox.ConsentedSidecarIds = [][]byte{laptop.Bytes()}
	mailbox.Shares = []*protocol.AclRepoShareRow{{Subject: burner.Bytes(), Signer: laptop.Bytes(), At: fixture.next()}}
	teamRecordId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	fixture.rule([]Id{fixture.sidecarAtom(burner)}, []*protocol.AclTarget{aclRepoTarget(named)}, protocol.AclAction_ACL_ACTION_WRITE)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclWildcardRepoTarget()},
		protocol.AclAction_ACL_ACTION_WRITE, protocol.AclAction_ACL_ACTION_ADMIN)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL), []*protocol.AclTarget{aclRepoTarget(byEphemeral)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(byTag)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), []*protocol.AclTarget{aclWildcardRepoTarget()}, protocol.AclAction_ACL_ACTION_DEPOSIT)
	memberGrant.Grants = []*protocol.AclRepoGrantRow{{Subject: owner.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, At: fixture.next()}}
	sidecarGrant.Grants = []*protocol.AclRepoGrantRow{{Subject: burner.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, At: fixture.next()}}
	state := fixture.state(t)
	cases := []struct {
		name      string
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{name: "rule naming it", sidecarId: burner, repoId: named, rights: AclEvsRead | AclEvsWrite},
		{name: "member's write and admin", sidecarId: burner, repoId: byMember, rights: 0},
		{name: "autogroup:ephemeral", sidecarId: burner, repoId: byEphemeral, rights: AclEvsRead},
		{name: "grant to its member", sidecarId: burner, repoId: grantedToMember, rights: 0},
		{name: "grant to it", sidecarId: burner, repoId: grantedToSidecar, rights: AclEvsRead},
		{name: "vault kind-default deposit", sidecarId: burner, repoId: vaultId, rights: AclEvsDeposit},
		{name: "mailbox share", sidecarId: burner, repoId: mailboxId, rights: AclEvsRead | AclEvsDeposit},
		{name: "team record deposit, no read", sidecarId: burner, repoId: teamRecordId, rights: AclEvsDeposit},
		{name: "tag it carries", sidecarId: ci, repoId: byTag, rights: AclEvsRead},
		{name: "autogroup:tagged deposit names no tag", sidecarId: ci, repoId: byMember, rights: 0},
		{name: "laptop's write", sidecarId: laptop, repoId: byMember, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin},
	}
	for _, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("%s: %b, want %b", c.name, rights, c.rights)
		}
	}
}

// The access log: a repo admin administers, RepoGrants give their roles until they expire, a grant to a
// group reaches its members, and a config writer's standing RepoRevoke overrides grants (§8.8).
func TestAclEvsAccessLog(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.device(owner)
	writer := fixture.device(owner)
	expired := fixture.device(owner)
	grouped := fixture.device(member)
	revoked := fixture.device(member)
	group := fixture.group(member)
	repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_RECORD, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes(), Signer: admin.Bytes(), At: 3}}
	row.Grants = []*protocol.AclRepoGrantRow{
		{Subject: writer.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, Signer: admin.Bytes(), At: 4},
		{Subject: expired.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: aclTestNow.UnixMilli(), Signer: admin.Bytes(), At: 5},
		{Subject: group.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Signer: admin.Bytes(), At: 6},
	}
	row.Revokes = []*protocol.AclRepoRevokeRow{{Subject: revoked.Bytes(), Signer: writer.Bytes(), At: 7}}
	state := fixture.state(t)
	cases := []struct {
		sidecarId Id
		rights    AclEvsRights
		reason    AclReason
		at        uint64
	}{
		{sidecarId: admin, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin, reason: AclReasonRepoAdmin, at: 3},
		{sidecarId: writer, rights: AclEvsRead | AclEvsWrite, reason: AclReasonRepoGrant, at: 4},
		{sidecarId: expired, rights: 0, reason: AclReasonNoGrant},
		{sidecarId: grouped, rights: AclEvsRead, reason: AclReasonRepoGrant, at: 6},
		{sidecarId: revoked, rights: 0, reason: AclReasonNoGrant},
	}
	for i, c := range cases {
		access := state.EvsAccess(AclSidecarSubject(c.sidecarId), repoId, AclTokenAudienceEvs, aclTestNow)
		if access.Rights != c.rights || access.Reason != c.reason || access.At != c.at || access.Allowed != (c.rights != 0) {
			t.Errorf("case %d: %+v", i, access)
		}
	}
	if writers := state.RepoWriters(repoId, aclTestNow); !slices.Equal(writers, aclSortedIds(admin, writer)) {
		t.Errorf("writers %v", writers)
	}
	if readers := state.RepoReaders(repoId, aclTestNow); !slices.Equal(readers, aclSortedIds(admin, writer, grouped)) {
		t.Errorf("readers %v", readers)
	}
	if readers := state.RepoReaders(repoId, aclTestNow.Add(-time.Millisecond)); !slices.Equal(readers, aclSortedIds(admin, writer, expired, grouped)) {
		t.Errorf("readers before the expiry %v", readers)
	}
}

// Ids sorted as the state returns them.
func aclSortedIds(ids ...Id) []Id {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, Id.Cmp)
	return ids
}

// The kind defaults of the team record and mailcfg (§8.5, §15.8).
func TestAclTeamRecordAndMailcfgDefaults(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	auditor := fixture.member(bridge.MemberRole_MEMBER_ROLE_AUDITOR)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	ownerDevice := fixture.invitedDevice(owner)
	auditorDevice := fixture.device(auditor)
	memberDevice := fixture.device(member)
	agent := fixture.agent(member, tagId)
	teamRecordId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	mailcfgId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_MAILCFG, Id{})
	scopeMailcfgId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_MAILCFG, owner)
	state := fixture.state(t)
	cases := []struct {
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{sidecarId: ownerDevice, repoId: teamRecordId, rights: AclEvsRead | AclEvsDeposit},
		{sidecarId: auditorDevice, repoId: teamRecordId, rights: AclEvsRead | AclEvsDeposit},
		{sidecarId: memberDevice, repoId: teamRecordId, rights: AclEvsDeposit},
		{sidecarId: agent, repoId: teamRecordId, rights: AclEvsDeposit},
		{sidecarId: memberDevice, repoId: mailcfgId, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: agent, repoId: mailcfgId, rights: 0},
		{sidecarId: ownerDevice, repoId: scopeMailcfgId, rights: AclEvsRead | AclEvsWrite},
		{sidecarId: memberDevice, repoId: scopeMailcfgId, rights: 0},
	}
	for i, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("case %d: %b, want %b", i, rights, c.rights)
		}
	}
}

// The audit block reads what it names only while its AuditOptIn stands (owner decision 63).
func TestAclAuditBlock(t *testing.T) {
	for _, optedIn := range []bool{true, false} {
		fixture := newAclTestFixture()
		owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
		auditTag := fixture.tag(owner)
		auditor := fixture.agent(owner, auditTag)
		vaultId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
		recordId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
		fixture.rows.Audit = &protocol.AclAudit{ReaderAtoms: [][]byte{auditTag.Bytes()}, RepoKinds: []uint32{uint32(protocol.RepoKind_REPO_KIND_VAULT)}}
		if optedIn {
			fixture.rows.Audit.AuditOptIn = aclTestAuditOptInRecord(t, aclTestNow.Add(time.Hour), auditTag)
		}
		state := fixture.state(t)
		if rights := aclTestRights(state, auditor, vaultId, AclTokenAudienceEvs); rights.Has(AclEvsRead) != optedIn {
			t.Errorf("opted in %t: vault rights %b", optedIn, rights)
		}
		if rights := aclTestRights(state, auditor, recordId, AclTokenAudienceEvs); rights != 0 {
			t.Errorf("unnamed repo: %b", rights)
		}
	}
}

// What EvsAccess refuses outright: a repo the rows lack, a deleted one, a subject that is no sidecar, and a
// hard denied sidecar.
func TestAclEvsAccessRefusals(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	device := fixture.device(owner)
	suspended := fixture.device(owner)
	fixture.rows.Suspensions = []*protocol.AclSuspension{{Subject: suspended.Bytes()}}
	deletedId, deleted := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: 3}
	restoredId, restored := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	restored.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: 3, RestoredAt: 4}
	unknownKindId, _ := fixture.repo(protocol.RepoKind(99), Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclWildcardRepoTarget(), aclRepoTarget(unknownKindId)},
		protocol.AclAction_ACL_ACTION_READ)
	state := fixture.state(t)
	cases := []struct {
		subject AclSubject
		repoId  Id
		reason  AclReason
	}{
		{subject: AclSidecarSubject(device), repoId: NewId(), reason: AclReasonNoRepo},
		{subject: AclSidecarSubject(device), repoId: deletedId, reason: AclReasonRepoDeleted},
		{subject: AclSidecarSubject(device), repoId: unknownKindId, reason: AclReasonNoGrant},
		{subject: AclClientSubject(NewId(), owner, nil, ""), repoId: restoredId, reason: AclReasonNoGrant},
		{subject: AclSidecarSubject(suspended), repoId: restoredId, reason: AclReasonSuspended},
	}
	for i, c := range cases {
		access := state.EvsAccess(c.subject, c.repoId, AclTokenAudienceEvs, aclTestNow)
		if access.Rights != 0 || access.Allowed || access.Reason != c.reason {
			t.Errorf("case %d: %+v", i, access)
		}
	}
	if rights := aclTestRights(state, device, restoredId, AclTokenAudienceEvs); rights != AclEvsRead {
		t.Errorf("restored repo: %b", rights)
	}
}

// ReposGrantedToAtoms lists what a read, write or admin grant naming the atoms reads: explicit and wildcard
// rules, RepoGrants, in force, and no deposit, no deleted repo and no kind default (§10.5's reach(d)).
func TestAclReposGrantedToAtoms(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	ciTag := fixture.tag(owner)
	otherTag := fixture.tag(owner)
	ruleRepo, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	grantRepo, grantRow := fixture.repo(protocol.RepoKind_REPO_KIND_RECORD, Id{})
	depositRepo, depositRow := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	expiredRepo, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deletedRepo, deletedRow := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	vaultRepo, _ := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	otherRepo, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deletedRow.Deletion = &protocol.AclRepoDeletionRow{DeletedAt: 2}
	fixture.rule([]Id{ciTag}, []*protocol.AclTarget{aclRepoTarget(ruleRepo), aclRepoTarget(deletedRepo), aclRepoTarget(vaultRepo)}, protocol.AclAction_ACL_ACTION_WRITE)
	expiring := fixture.rule([]Id{ciTag}, []*protocol.AclTarget{aclRepoTarget(expiredRepo)}, protocol.AclAction_ACL_ACTION_READ)
	expiring.Expires = aclTestNow.UnixMilli()
	fixture.rule([]Id{ciTag}, []*protocol.AclTarget{aclRepoTarget(depositRepo)}, protocol.AclAction_ACL_ACTION_DEPOSIT)
	fixture.rule([]Id{otherTag}, []*protocol.AclTarget{aclRepoTarget(otherRepo)}, protocol.AclAction_ACL_ACTION_READ)
	grantRow.Grants = []*protocol.AclRepoGrantRow{{Subject: ciTag.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, At: 3}}
	depositRow.Grants = []*protocol.AclRepoGrantRow{{Subject: ciTag.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, At: 4}}
	state := fixture.state(t)
	if repos := state.ReposGrantedToAtoms([]Id{ciTag}, aclTestNow); !slices.Equal(repos, aclSortedIds(ruleRepo, grantRepo)) {
		t.Errorf("repos %v", repos)
	}
	if repos := state.ReposGrantedToAtoms([]Id{ciTag}, aclTestNow.Add(-time.Millisecond)); !slices.Equal(repos, aclSortedIds(ruleRepo, grantRepo, expiredRepo)) {
		t.Errorf("repos before the expiry %v", repos)
	}

	wildcard := newAclTestFixture()
	owner = wildcard.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	ciTag = wildcard.tag(owner)
	general, _ := wildcard.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	record, _ := wildcard.repo(protocol.RepoKind_REPO_KIND_RECORD, Id{})
	wildcard.configRepo(Id{}, Id{})
	wildcard.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	wildcard.rule([]Id{ciTag}, []*protocol.AclTarget{aclWildcardRepoTarget()}, protocol.AclAction_ACL_ACTION_READ)
	if repos := wildcard.state(t).ReposGrantedToAtoms([]Id{ciTag, NewId()}, aclTestNow); !slices.Equal(repos, aclSortedIds(general, record)) {
		t.Errorf("wildcard repos %v", repos)
	}
}

// An audit block naming a repo id of the wrong size names nothing, and EvsAccess, a gate's hot path, never panics on
// it: NewAclState does not check the audit block.
func TestAclAuditBlockWithAMalformedRepoId(t *testing.T) {
	fixture := newAclTestFixture()
	auditor := fixture.member(bridge.MemberRole_MEMBER_ROLE_AUDITOR)
	device := fixture.device(auditor)
	repoId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rows.Audit = &protocol.AclAudit{
		ReaderAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR).Bytes()},
		RepoIds:     [][]byte{{1, 2, 3}},
		AuditOptIn:  []byte("an opt-in the compile verified"),
	}
	if rights := aclTestRights(fixture.state(t), device, repoId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("rights %b", rights)
	}
}
