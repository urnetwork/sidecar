// §8.8's access-log fold: each row with its signer and position, the rows a fold was given never changed, a
// re-application over rows lacking its repo refused, VoidEvsShares listing what a cascade voids, and RepoAdminAt
// judging an admin at a position. Pure, on every leg.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One access-log entry as a fold takes it, signed by signer at position at.
func aclTestLogEntry(body proto.Message, signedType bridge.SignedType, signer Id, at uint64, configWriter bool) AclAccessLogEntry {
	return AclAccessLogEntry{
		Statement: &AclStatement{Type: signedType, Body: body, N: at, Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: signer}}},
		Verdict:   &AclStatementVerdict{Signer: signer, ConfigWriter: configWriter},
	}
}

// A fold keeps every statement's signer and carrying position, the newest RepoGrant and EvsShare per subject, a
// config writer's standing RepoRevoke, the newest RepoDelete with its RepoRestore and the newest lock, and changes no
// row it was given.
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
	if deletion := repo.GetDeletion(); deletion.GetDeletedAt() != 15 || deletion.GetRestoredAt() != 16 {
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
	if len(after.GetGrants()) != 0 || len(after.GetRevokes()) != 1 || after.GetRevokes()[0].GetAt() != 17 || len(after.GetAdmins()) != 1 {
		t.Errorf("after the revoke %+v", after)
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

// RepoAdminAt reads an admin row's position: an admin at and after it, none before it or for another repo.
func TestAclRepoAdminAt(t *testing.T) {
	cast := newAclStatementCast()
	repoId, row := cast.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: 12}}
	state := cast.fixture.state(t)
	cases := []struct {
		sidecarId Id
		repoId    Id
		position  uint64
		admin     bool
	}{
		{sidecarId: cast.laptop, repoId: repoId, position: 12, admin: true},
		{sidecarId: cast.laptop, repoId: repoId, position: 100, admin: true},
		{sidecarId: cast.laptop, repoId: repoId, position: 11},
		{sidecarId: cast.phone, repoId: repoId, position: 100},
		{sidecarId: cast.laptop, repoId: NewId(), position: 100},
	}
	for i, c := range cases {
		if admin := state.RepoAdminAt(c.repoId, c.sidecarId, c.position); admin != c.admin {
			t.Errorf("case %d: %v", i, admin)
		}
	}
}

// The 0x11xx types FuzzAclStatement decodes, in SignedType order.
var aclFuzzStatementTypes = []bridge.SignedType{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_GRANT_REVOKE, bridge.SignedType_SIGNED_SUSPEND,
	bridge.SignedType_SIGNED_UNSUSPEND, bridge.SignedType_SIGNED_EVS_SHARE, bridge.SignedType_SIGNED_OWNER_CONFIRM,
	bridge.SignedType_SIGNED_REPO_CREATE, bridge.SignedType_SIGNED_REPO_ADMIN, bridge.SignedType_SIGNED_REPO_GRANT,
	bridge.SignedType_SIGNED_REPO_REVOKE, bridge.SignedType_SIGNED_REPO_DELETE, bridge.SignedType_SIGNED_REPO_RESTORE,
	bridge.SignedType_SIGNED_REPO_VERSIONING, bridge.SignedType_SIGNED_AUDIT_OPT_IN, bridge.SignedType_SIGNED_AUDIT_OPT_OUT,
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
