// §8.8's access-log fold: each row with its signer and position, a RepoDelete with its entry's time and a removal
// stamped on the row it keeps (QD-743), the RepoDelete's signer in its row (QD-798), the rows a fold was given never
// changed, a re-application over rows lacking its repo refused, VoidEvsShares listing what a cascade voids, RepoAdminAt
// judging an admin at a position before and after its removal, and the base compile dropping a removed admin's row
// once the retention point passes its removal. Pure, on every leg; the last tests run TEAM's log.

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

// One access-log entry as a fold takes it, signed by signer at position at, sequenced at aclTestEntryTimeMs(at).
func aclTestLogEntry(body proto.Message, signedType bridge.SignedType, signer Id, at uint64, configWriter bool) AclAccessLogEntry {
	return AclAccessLogEntry{
		Statement: &AclStatement{
			Type: signedType, Body: body, N: at, TimeMs: aclTestEntryTimeMs(at),
			Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: signer}},
		},
		Verdict: &AclStatementVerdict{Signer: signer, ConfigWriter: configWriter},
	}
}

// The time a test entry at position at was sequenced: a second a position from aclTestNow.
func aclTestEntryTimeMs(at uint64) int64 {
	return aclTestNow.UnixMilli() + int64(at)*time.Second.Milliseconds()
}

// A fold keeps every statement's signer and carrying position, the newest RepoGrant and EvsShare per subject, a
// config writer's standing RepoRevoke, the newest RepoDelete with its own signer (QD-798) and its RepoRestore, whose
// other signer leaves the deletion's as it was, and the newest lock, and changes no row it was given.
func TestFoldAclReposKeepsSignersAndPositions(t *testing.T) {
	admin, writer, subject := NewId(), NewId(), NewId()
	repoId, deletionId := NewId(), NewId()
	reader, deposit := protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT
	entries := []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}, bridge.SignedType_SIGNED_REPO_CREATE, admin, 10, false),
		aclTestLogEntry(&protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: subject.Bytes(), Role: reader}, bridge.SignedType_SIGNED_REPO_GRANT, admin, 11, false),
		aclTestLogEntry(&protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: subject.Bytes(), Role: deposit, Expires: 77}, bridge.SignedType_SIGNED_REPO_GRANT, admin, 12, false),
		aclTestLogEntry(&protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: writer.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD}, bridge.SignedType_SIGNED_REPO_ADMIN, admin, 13, false),
		aclTestLogEntry(&protocol.RepoVersioning{RepoId: repoId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED}, bridge.SignedType_SIGNED_REPO_VERSIONING, writer, 14, false),
		aclTestLogEntry(&protocol.RepoDelete{RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes()}, bridge.SignedType_SIGNED_REPO_DELETE, admin, 15, false),
		aclTestLogEntry(&protocol.RepoRestore{RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes()}, bridge.SignedType_SIGNED_REPO_RESTORE, writer, 16, false),
	}
	repos, err := FoldAclRepos(nil, entries)
	if err != nil || len(repos) != 1 {
		t.Fatalf("%v, %d repos", err, len(repos))
	}
	repo := repos[0]
	grants := repo.GetGrants()
	if len(grants) != 1 || grants[0].GetRole() != deposit || grants[0].GetExpires() != 77 || grants[0].GetAt() != 12 || !bytes.Equal(grants[0].GetSigner(), admin.Bytes()) {
		t.Errorf("grants %+v", grants)
	}
	admins := repo.GetAdmins()
	if len(admins) != 2 || admins[0].GetAt() != 10 || admins[1].GetAt() != 13 || !bytes.Equal(admins[1].GetSidecarId(), writer.Bytes()) {
		t.Errorf("admins %+v", admins)
	}
	if deletion := repo.GetDeletion(); deletion.GetDeletedAt() != 15 || deletion.GetDeletedTimeMs() != aclTestEntryTimeMs(15) || deletion.GetRestoredAt() != 16 ||
		!bytes.Equal(deletion.GetSigner(), admin.Bytes()) {
		t.Errorf("deletion %+v", deletion)
	}
	if repo.GetLock() != protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED {
		t.Errorf("lock %v", repo.GetLock())
	}

	before := proto.Clone(repo).(*protocol.AclRepo)
	revoked, err := FoldAclRepos(repos, []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoRevoke{RepoId: repoId.Bytes(), Subject: subject.Bytes()}, bridge.SignedType_SIGNED_REPO_REVOKE, writer, 17, true),
		aclTestLogEntry(&protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: writer.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE}, bridge.SignedType_SIGNED_REPO_ADMIN, admin, 18, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(repos[0], before) {
		t.Error("the fold changed the rows it was given")
	}
	after := revoked[0]
	if len(after.GetGrants()) != 0 || len(after.GetRevokes()) != 1 || after.GetRevokes()[0].GetAt() != 17 {
		t.Errorf("after the revoke %+v", after)
	}
	// the remove keeps the writer's row, stamped with its own position, and leaves the creator's standing
	if admins := after.GetAdmins(); len(admins) != 2 || admins[0].GetRemovedAt() != 0 || admins[1].GetAt() != 13 || admins[1].GetRemovedAt() != 18 ||
		!bytes.Equal(admins[1].GetSigner(), admin.Bytes()) {
		t.Errorf("admins after the remove %+v", admins)
	}
}

// QD-743's admin rows: a remove stamps the standing row and keeps it, a re-add after it starts a second row beside the
// stamped one, an add of a sidecar that stands replaces its standing row with the newest add's signer and position,
// and a remove of a sidecar with no standing row stamps nothing; the rows given are never changed.
func TestFoldAclReposStampsARemovedAdminsRow(t *testing.T) {
	creator, admin, other := NewId(), NewId(), NewId()
	repoId := NewId()
	adminOf := func(sidecarId Id, change protocol.RepoAdminChange, signer Id, at uint64) AclAccessLogEntry {
		body := &protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: sidecarId.Bytes(), Change: change}
		return aclTestLogEntry(body, bridge.SignedType_SIGNED_REPO_ADMIN, signer, at, false)
	}
	add, remove := protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD, protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE
	created, err := FoldAclRepos(nil, []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}, bridge.SignedType_SIGNED_REPO_CREATE, creator, 1, false),
		adminOf(admin, add, creator, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	given := proto.Clone(created[0]).(*protocol.AclRepo)
	repos, err := FoldAclRepos(created, []AclAccessLogEntry{
		adminOf(admin, remove, creator, 3),
		// a remove of a sidecar with no standing row: nothing to stamp
		adminOf(other, remove, creator, 4),
		adminOf(admin, remove, creator, 5),
		adminOf(admin, add, creator, 6),
		// an add of a sidecar that stands: its standing row gives way to this one
		adminOf(admin, add, admin, 7),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(created[0], given) {
		t.Error("the fold changed the rows it was given")
	}
	type row struct {
		sidecarId Id
		signer    Id
		at        uint64
		removedAt uint64
	}
	want := []row{
		{sidecarId: creator, signer: creator, at: 1},
		{sidecarId: admin, signer: creator, at: 2, removedAt: 3},
		{sidecarId: admin, signer: admin, at: 7},
	}
	admins := repos[0].GetAdmins()
	if len(admins) != len(want) {
		t.Fatalf("admins %+v", admins)
	}
	for i, w := range want {
		got := admins[i]
		if Id(got.GetSidecarId()) != w.sidecarId || Id(got.GetSigner()) != w.signer || got.GetAt() != w.at || got.GetRemovedAt() != w.removedAt {
			t.Errorf("admin row %d: %+v, want %+v", i, got, w)
		}
	}
}

// A fold refuses what its rows cannot take: a statement on a repo they lack, a second RepoCreate, a RepoRestore of
// another deletion, so a re-application over a new base ends the statement's effect there.
func TestFoldAclReposRefusesWhatItsRowsCannotTake(t *testing.T) {
	signer, repoId := NewId(), NewId()
	repos, err := FoldAclRepos(nil, []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD}, bridge.SignedType_SIGNED_REPO_CREATE, signer, 1, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoGrant{RepoId: NewId().Bytes(), Subject: signer.Bytes()}, bridge.SignedType_SIGNED_REPO_GRANT, signer, 2, false),
		aclTestLogEntry(&protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD}, bridge.SignedType_SIGNED_REPO_CREATE, signer, 2, false),
		aclTestLogEntry(&protocol.RepoRestore{RepoId: repoId.Bytes(), DeletionId: NewId().Bytes()}, bridge.SignedType_SIGNED_REPO_RESTORE, signer, 2, false),
	}
	for i, entry := range cases {
		if _, err := FoldAclRepos(repos, []AclAccessLogEntry{entry}); !errors.Is(err, ErrAclAccessLogFold) {
			t.Errorf("case %d: %v", i, err)
		}
	}

	// over rows that lack the repo, ReapplyStatement refuses as a rule and ApplyStatement's caller sees why
	fixture := newAclTestFixture()
	state := fixture.state(t)
	statement := &AclStatement{Type: bridge.SignedType_SIGNED_REPO_GRANT, Body: cases[0].Statement.Body, N: 3}
	if _, _, err := state.ReapplyStatement(statement, &AclStatementVerdict{Signer: signer}); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a re-application without its repo: %v", err)
	}
}

// VoidEvsShares lists each share whose signer is in P at the share's position, and none signed before its signer
// entered P or by a signer outside it.
func TestAclVoidEvsShares(t *testing.T) {
	cast := newAclStatementCast()
	vaultId, vault := cast.vault()
	vault.Shares = []*protocol.AclRepoShareRow{
		{Subject: cast.stranger.Bytes(), Signer: cast.laptop.Bytes(), At: 40},
		{Subject: cast.agent.Bytes(), Signer: cast.laptop.Bytes(), At: 20},
		{Subject: cast.adminDevice.Bytes(), Signer: cast.phone.Bytes(), At: 50},
	}
	state := cast.fixture.state(t)
	voided := state.VoidEvsShares(map[Id]uint64{cast.laptop: 30})
	if len(voided) != 1 || voided[0].RepoId != vaultId || voided[0].Subject != cast.stranger || voided[0].At != 40 {
		t.Errorf("voided %+v", voided)
	}
	if voided := state.VoidEvsShares(map[Id]uint64{}); len(voided) != 0 {
		t.Errorf("an empty P voids %+v", voided)
	}
}

// RepoAdminAt reads an admin row's positions: an admin from its add on, none before it or for another repo; a removed
// admin up to its removal and not from it on (QD-743), a re-added one again from its second add; and a removed row
// gives no right now.
func TestAclRepoAdminAt(t *testing.T) {
	cast := newAclStatementCast()
	repoId, row := cast.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{
		{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 12},
		{SidecarId: cast.phone.Bytes(), Signer: cast.laptop.Bytes(), At: 20, RemovedAt: 30},
		{SidecarId: cast.agent.Bytes(), Signer: cast.laptop.Bytes(), At: 20, RemovedAt: 30},
		{SidecarId: cast.agent.Bytes(), Signer: cast.laptop.Bytes(), At: 40},
	}
	state := cast.fixture.state(t)
	cases := []struct {
		name      string
		sidecarId Id
		repoId    Id
		position  uint64
		admin     bool
	}{
		{name: "at its add", sidecarId: cast.laptop, repoId: repoId, position: 12, admin: true},
		{name: "long after", sidecarId: cast.laptop, repoId: repoId, position: 100, admin: true},
		{name: "before its add", sidecarId: cast.laptop, repoId: repoId, position: 11},
		{name: "another repo", sidecarId: cast.laptop, repoId: NewId(), position: 100},
		{name: "a removed admin before its add", sidecarId: cast.phone, repoId: repoId, position: 19},
		{name: "a removed admin at its add", sidecarId: cast.phone, repoId: repoId, position: 20, admin: true},
		{name: "a removed admin before its removal", sidecarId: cast.phone, repoId: repoId, position: 29, admin: true},
		{name: "a removed admin at its removal", sidecarId: cast.phone, repoId: repoId, position: 30},
		{name: "a removed admin after it", sidecarId: cast.phone, repoId: repoId, position: 100},
		{name: "a re-added admin in its first span", sidecarId: cast.agent, repoId: repoId, position: 25, admin: true},
		{name: "a re-added admin between its spans", sidecarId: cast.agent, repoId: repoId, position: 35},
		{name: "a re-added admin in its second span", sidecarId: cast.agent, repoId: repoId, position: 40, admin: true},
	}
	for _, c := range cases {
		if admin := state.RepoAdminAt(c.repoId, c.sidecarId, c.position); admin != c.admin {
			t.Errorf("%s: %v", c.name, admin)
		}
	}
	// now, the removed admin administers nothing, and the re-added one does
	if rights := aclTestRights(state, cast.phone, repoId, AclTokenAudienceEvs); rights.Has(AclEvsAdmin) {
		t.Errorf("a removed admin's rights now: %b", rights)
	}
}

// The base compile's rule (QD-743): a removed admin's row leaves once its removal lies before the retention point, and
// stays while the point has not passed it; a standing row stays however old; nothing else of the rows changes, the rows
// given are not changed, and rows with nothing to drop come back as they are.
func TestAclRowsKeptAtDropsRemovedAdminsPastRetention(t *testing.T) {
	first, second := NewId(), NewId()
	admin := func(sidecarId Id, at uint64, removedAt uint64) *protocol.AclRepoAdminRow {
		return &protocol.AclRepoAdminRow{SidecarId: sidecarId.Bytes(), Signer: first.Bytes(), At: at, RemovedAt: removedAt}
	}
	rows := &protocol.AclRows{
		HasDocument: true,
		Repos: []*protocol.AclRepo{
			{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []*protocol.AclRepoAdminRow{admin(first, 1, 0), admin(second, 2, 9), admin(second, 12, 0)}},
			{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD, Admins: []*protocol.AclRepoAdminRow{admin(first, 3, 10)}},
			{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []*protocol.AclRepoAdminRow{admin(first, 4, 0)}},
		},
		SpentGrants: []*protocol.AclSpentGrant{{GrantId: NewId().Bytes(), RetainUntilMs: 5}},
	}
	given := proto.Clone(rows).(*protocol.AclRows)
	if kept := aclRowsKeptAt(rows, 9); kept != rows {
		t.Errorf("a point at the first removal dropped a row")
	}
	kept := aclRowsKeptAt(rows, 10)
	if !proto.Equal(rows, given) {
		t.Error("the rows given changed")
	}
	if admins := kept.GetRepos()[0].GetAdmins(); len(admins) != 2 || admins[0].GetAt() != 1 || admins[1].GetAt() != 12 {
		t.Errorf("past the first removal: %+v", admins)
	}
	if admins := kept.GetRepos()[1].GetAdmins(); len(admins) != 1 {
		t.Errorf("a removal at the point: %+v", admins)
	}
	if kept.GetRepos()[2] != rows.GetRepos()[2] || !proto.Equal(kept.GetSpentGrants()[0], rows.GetSpentGrants()[0]) || !kept.GetHasDocument() {
		t.Error("what the rule does not drop changed")
	}
	if admins := aclRowsKeptAt(rows, 11).GetRepos()[1].GetAdmins(); len(admins) != 0 {
		t.Errorf("past the second removal: %+v", admins)
	}
	if aclRowsKeptAt(nil, 100) != nil {
		t.Error("no rows gave rows")
	}
}

// The 0x11xx types FuzzAclStatement decodes, in SignedType order.
var aclFuzzStatementTypes = []bridge.SignedType{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_GRANT_REVOKE, bridge.SignedType_SIGNED_SUSPEND,
	bridge.SignedType_SIGNED_UNSUSPEND, bridge.SignedType_SIGNED_EVS_SHARE, bridge.SignedType_SIGNED_OWNER_CONFIRM,
	bridge.SignedType_SIGNED_REPO_CREATE, bridge.SignedType_SIGNED_REPO_ADMIN, bridge.SignedType_SIGNED_REPO_GRANT,
	bridge.SignedType_SIGNED_REPO_REVOKE, bridge.SignedType_SIGNED_REPO_DELETE, bridge.SignedType_SIGNED_REPO_RESTORE,
	bridge.SignedType_SIGNED_REPO_VERSIONING, bridge.SignedType_SIGNED_AUDIT_OPT_IN, bridge.SignedType_SIGNED_AUDIT_OPT_OUT,
	bridge.SignedType_SIGNED_REPO_PREFIX_RULES,
}

// The fuzz cast's state, rebuilt per input, with a vault, a general repo and a grant to judge statements against.
func aclFuzzState(t *testing.T) (*aclStatementCast, *AclState, []Id) {
	cast := newAclStatementCast()
	cast.activatedGrant(t)
	cast.vault()
	_, row := cast.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 1}}
	signers := []Id{cast.ownerDevice, cast.adminDevice, cast.laptop, cast.phone, cast.agent, cast.pageWorker, cast.stranger}
	return cast, cast.fixture.state(t), signers
}

// A general repo the owner's genesis device administers from base 2 on, whose rows a test network's withAclRows sets.
func aclTestOwnedRepo(net *testConfigNet, repoId Id) {
	net.t.Helper()
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Repos = append(rows.Repos, &protocol.AclRepo{
			RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: net.owner.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1}},
		})
	})
}

// A network whose general repo's RepoDelete two bases have moved out of the log's retention, so no log dates its entry
// (§7.9's retention point, min(the previous base, folded_through + 1), past it): the repo, the deletion, the entry's
// time.
func aclTestDeletedPastRetention(t *testing.T, net *testConfigNet, repoId Id, deletionId Id) int64 {
	t.Helper()
	aclTestOwnedRepo(net, repoId)
	deletedAt := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: net.header(), RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes(),
	}).Pin.GetVersion()
	deletedTimeMs := net.timeMs
	net.fold(net.owner, deletedAt, 3)
	firstBase := net.n
	net.admitMember(net.owner, testConfigId("between member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, firstBase+1, 4)
	state := net.log.State()
	if point := state.RetentionPoint(); point <= deletedAt {
		t.Fatalf("the retention point %d has not passed the RepoDelete at %d", point, deletedAt)
	}
	if _, dated := state.aclTimeAt(deletedAt); dated {
		t.Fatal("the log still dates the RepoDelete's entry")
	}
	return deletedTimeMs
}

// QD-743 on TEAM's log: a RepoRestore five days after its RepoDelete, whose entry two bases have since moved out of
// the log's retention so no log dates it, is taken from the deletion row's own time at the long-running reader and at a
// new device that starts from what that reader keeps; one eight days after is refused at both.
func TestAclRepoRestoreJudgedFromTheRowAfterItsEntryLeftRetention(t *testing.T) {
	for _, c := range []struct {
		days  int64
		taken bool
	}{{days: 5, taken: true}, {days: 8}} {
		net := newTestConfigNet(t)
		repoId, deletionId := testConfigId("restored repo"), testConfigId("deletion")
		deletedTimeMs := aclTestDeletedPastRetention(t, net, repoId, deletionId)

		newDevice, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
		if err != nil {
			t.Fatal(err)
		}
		net.wait(c.days * 24 * time.Hour.Milliseconds())
		restore := &protocol.RepoRestore{Header: net.header(), RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes()}
		entry := net.makeEntry(bridge.AuthEntryKindStatement, net.sign(net.owner, bridge.SignedType_SIGNED_REPO_RESTORE, restore))
		verdict := net.push(entry)
		newVerdict, err := newDevice.Apply(entry, net.source)
		if err != nil {
			t.Fatal(err)
		}
		for name, v := range map[string]ConfigVerdict{"the reader": verdict, "a new device": newVerdict} {
			switch {
			case c.taken && !v.Accepted():
				t.Errorf("%d days, %s: refused %v", c.days, name, v.Refusal)
			case !c.taken && (v.Accepted() || !errors.Is(v.Refusal, ErrConfigRule)):
				t.Errorf("%d days, %s: %v, want a refusal past the window", c.days, name, v.Refusal)
			}
		}
		if !c.taken {
			continue
		}
		for name, log := range map[string]*ConfigLog{"the reader": net.log, "a new device": newDevice} {
			acl, err := log.State().Acl()
			if err != nil {
				t.Fatal(err)
			}
			if deletion := acl.Repo(repoId).GetDeletion(); deletion.GetRestoredAt() != verdict.Pin.GetVersion() || deletion.GetDeletedTimeMs() != deletedTimeMs {
				t.Errorf("%s's deletion row %+v", name, deletion)
			}
		}
	}
}

// QD-798 on TEAM's log: the deletion row's signer is the RepoDelete statement's own signer, here a repo admin other
// than the one that signs the bases, in every fold that writes the row: the reader's ApplyStatement at the entry; its
// ReapplyStatement over a base whose fold stops before the entry, so the base's tail re-applies it, and a new device's,
// starting at that base; and the base compile that folds through the entry, which the head check compiles from and a
// rows-only reader, as a gate is, starts from without the entry.
func TestAclRepoDeleteRowKeepsTheStatementsSigner(t *testing.T) {
	net := newTestConfigNet(t)
	phone := net.admitMemberDevice("deleting admin")
	repoId, deletionId := testConfigId("signed deletion repo"), testConfigId("signed deletion")
	aclTestOwnedRepo(net, repoId)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
		Header: net.header(), RepoId: repoId.Bytes(), SidecarId: phone.sidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
	})
	signedBytes := net.sign(phone, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: net.header(), RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes(),
	})
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		t.Fatal(err)
	}
	statementSigner := signed.GetSignerId()
	if !bytes.Equal(statementSigner, phone.sidecarId.Bytes()) {
		t.Fatalf("the statement names %x", statementSigner)
	}
	verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, signedBytes))
	if !verdict.Accepted() {
		t.Fatalf("the RepoDelete: %v", verdict.Refusal)
	}
	deletedAt := verdict.Pin.GetVersion()

	rowHoldsTheSigner := func(name string, rows *protocol.AclRows) {
		t.Helper()
		for _, repo := range rows.GetRepos() {
			if Id(repo.GetRepoId()) != repoId {
				continue
			}
			if deletion := repo.GetDeletion(); deletion.GetDeletedAt() != deletedAt || !bytes.Equal(deletion.GetSigner(), statementSigner) {
				t.Errorf("%s's deletion row %+v", name, deletion)
			}
			return
		}
		t.Errorf("%s holds no row of the repo", name)
	}
	stateRows := func(log *ConfigLog) *protocol.AclRows {
		t.Helper()
		acl, err := log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		return acl.Rows()
	}
	rowHoldsTheSigner("the reader at the entry", stateRows(net.log))

	// a base whose fold stops before the entry: each reader re-applies the RepoDelete over the base's rows
	net.fold(net.owner, deletedAt-1, 3)
	rowHoldsTheSigner("the reader past a base whose tail holds the entry", stateRows(net.log))
	newDevice, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
	if err != nil {
		t.Fatal(err)
	}
	rowHoldsTheSigner("a new device starting at that base", stateRows(newDevice))

	// a base folding through the entry: what its head check compiled from, and a rows-only reader starting there
	net.fold(net.owner, net.n, 4)
	if len(net.source.checks) == 0 {
		t.Fatal("no head check")
	}
	rowHoldsTheSigner("the base compile", net.source.checks[len(net.source.checks)-1].CompileRows.AclStatements)
	rowsOnly, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), net.log.Retained(), net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := rowsOnly.State().aclTimeAt(deletedAt); kept {
		t.Fatal("the rows-only reader starting at the base holds the RepoDelete's entry")
	}
	rowHoldsTheSigner("a rows-only reader starting at the base", stateRows(rowsOnly))
}

// The repo's admin rows of a sidecar in what the newest base's head check compiled from.
func aclTestCheckedAdminRows(t *testing.T, net *testConfigNet, repoId Id, sidecarId Id) []*protocol.AclRepoAdminRow {
	t.Helper()
	if len(net.source.checks) == 0 {
		t.Fatal("no head check")
	}
	check := net.source.checks[len(net.source.checks)-1]
	rows := []*protocol.AclRepoAdminRow{}
	for _, repo := range check.CompileRows.AclStatements.GetRepos() {
		if Id(repo.GetRepoId()) != repoId {
			continue
		}
		for _, admin := range repo.GetAdmins() {
			if Id(admin.GetSidecarId()) == sidecarId {
				rows = append(rows, admin)
			}
		}
	}
	return rows
}

// QD-743 on TEAM's log: once a RepoAdmin{remove} lands, the removed admin's own RepoGrant is refused, while RepoAdminAt
// still finds it an admin at the position of the grant it signed before, and at none from its removal on. The base
// compile carries its stamped row while the retention point has not passed the removal, and drops it at the base whose
// point has, leaving the creator's standing row.
func TestAclRemovedRepoAdminJudgedBeforeAndAfterItsRemoval(t *testing.T) {
	net := newTestConfigNet(t)
	phone := net.admitMemberDevice("repo admin")
	repoId := testConfigId("admin repo")
	aclTestOwnedRepo(net, repoId)
	adminChange := func(change protocol.RepoAdminChange) *protocol.RepoAdmin {
		return &protocol.RepoAdmin{Header: net.header(), RepoId: repoId.Bytes(), SidecarId: phone.sidecarId.Bytes(), Change: change}
	}
	grant := func(label string) *protocol.RepoGrant {
		return &protocol.RepoGrant{Header: net.header(), RepoId: repoId.Bytes(), Subject: testConfigId(label).Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
	}
	addedAt := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, adminChange(protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD)).Pin.GetVersion()
	grantedAt := net.mustPost(phone, bridge.SignedType_SIGNED_REPO_GRANT, grant("granted before the removal")).Pin.GetVersion()
	removedAt := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, adminChange(protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE)).Pin.GetVersion()
	net.mustRefuse(phone, bridge.SignedType_SIGNED_REPO_GRANT, grant("granted after the removal"), ErrConfigAuthority)

	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		position uint64
		admin    bool
	}{
		{name: "before the add", position: addedAt - 1},
		{name: "at the add", position: addedAt, admin: true},
		{name: "at the grant it signed", position: grantedAt, admin: true},
		{name: "at the removal", position: removedAt},
		{name: "at the refused grant", position: net.n},
	} {
		if admin := acl.RepoAdminAt(repoId, phone.sidecarId, c.position); admin != c.admin {
			t.Errorf("%s: %v", c.name, admin)
		}
	}
	if rights := aclTestRights(acl, phone.sidecarId, repoId, AclTokenAudienceEvs); rights.Has(AclEvsAdmin) {
		t.Errorf("the removed admin's rights now: %b", rights)
	}

	// a base whose retention point, base 2's position, lies before the removal: the stamped row is compiled on
	net.fold(net.owner, net.n, 3)
	firstBase := net.n
	if rows := aclTestCheckedAdminRows(t, net, repoId, phone.sidecarId); len(rows) != 1 || rows[0].GetRemovedAt() != removedAt || rows[0].GetAt() != addedAt {
		t.Fatalf("the first base compiles %+v", rows)
	}
	// a base whose retention point, the first base's position, has passed the removal: the row leaves
	net.admitMember(net.owner, testConfigId("between member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, firstBase+1, 4)
	if point := net.log.State().RetentionPoint(); point <= removedAt {
		t.Fatalf("the retention point %d has not passed the removal at %d", point, removedAt)
	}
	if rows := aclTestCheckedAdminRows(t, net, repoId, phone.sidecarId); len(rows) != 0 {
		t.Errorf("the second base compiles %+v", rows)
	}
	if rows := aclTestCheckedAdminRows(t, net, repoId, net.owner.sidecarId); len(rows) != 1 || !AclRepoAdminStands(rows[0]) {
		t.Errorf("the creator's row: %+v", rows)
	}
}
