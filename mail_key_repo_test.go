//go:build !ios_extension

// The network mail key's repo as a server reads it from the rows alone (mail_key_repo.go): a personal network's
// Owner's first standing mailbox, never another member's mailbox or an admin inbox; a Team's standing admin inbox,
// never a group inbox or the Owner's mailbox; and none where the rows name none.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A repo of kind and inbox role, owned by ownerId when it is not zero, created at position at: its creator's admin
// row, as a RepoCreate leaves it, is what dates it.
func (self *aclTestFixture) createdRepo(kind protocol.RepoKind, ownerId Id, inbox protocol.RepoInbox, at uint64) (Id, *protocol.AclRepo) {
	repoId, row := self.repo(kind, ownerId)
	row.Inbox = inbox
	creatorId := NewId().Bytes()
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: creatorId, Signer: creatorId, At: at}}
	return repoId, row
}

func TestNetworkMailKeyRepoIsAPersonalOwnersFirstMailbox(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	fixture.configRepo(NewId(), owner)
	// created before every mailbox of the owner's, and not the owner's
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, other, protocol.RepoInbox_REPO_INBOX_NONE, 1)
	// an admin inbox names a Team's key, never a personal network's
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_GENERAL, Id{}, protocol.RepoInbox_REPO_INBOX_ADMIN, 2)
	// the owner's first mailbox, deleted and not restored
	_, deleted := fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 3)
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: 9}
	// two created at one position, the lower id breaking the tie, and a later one
	tieA, _ := fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 4)
	tieB, _ := fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 4)
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 5)
	want := tieA
	if tieB.Cmp(tieA) < 0 {
		want = tieB
	}
	if repoId, found := fixture.state(t).NetworkMailKeyRepo(); !found || repoId != want {
		t.Fatalf("the key's repo %s, %t; want the owner's first standing mailbox %s", repoId, found, want)
	}
	// a restored deletion stands again, and its mailbox was created first
	deleted.Deletion.RestoredAt = 10
	if repoId, found := fixture.state(t).NetworkMailKeyRepo(); !found || repoId != Id(deleted.GetRepoId()) {
		t.Fatalf("after the restore the key's repo %s, %t; want the restored mailbox", repoId, found)
	}
}

func TestNetworkMailKeyRepoIsATeamsAdminInbox(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	fixture.configRepo(NewId(), owner)
	// a directory makes the network a Team's
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{}, protocol.RepoInbox_REPO_INBOX_NONE, 1)
	// in a Team neither the owner's mailbox nor a group inbox holds the network's key
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 2)
	fixture.createdRepo(protocol.RepoKind_REPO_KIND_GENERAL, Id{}, protocol.RepoInbox_REPO_INBOX_GROUP, 3)
	if repoId, found := fixture.state(t).NetworkMailKeyRepo(); found {
		t.Fatalf("a Team with no admin inbox names %s", repoId)
	}
	adminInbox, row := fixture.createdRepo(protocol.RepoKind_REPO_KIND_GENERAL, Id{}, protocol.RepoInbox_REPO_INBOX_ADMIN, 4)
	if repoId, found := fixture.state(t).NetworkMailKeyRepo(); !found || repoId != adminInbox {
		t.Fatalf("the key's repo %s, %t; want the admin inbox %s", repoId, found, adminInbox)
	}
	row.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: 7}
	if repoId, found := fixture.state(t).NetworkMailKeyRepo(); found {
		t.Fatalf("a deleted admin inbox still names %s", repoId)
	}
}

func TestNetworkMailKeyRepoNamesNoneWithoutItsOwner(t *testing.T) {
	cases := []struct {
		name string
		// the Genesis's owner member's role, or unspecified for a Genesis whose owner holds no member row
		ownerRole bridge.MemberRole
		genesis   bool
		mailbox   bool
	}{
		{name: "no Genesis", ownerRole: bridge.MemberRole_MEMBER_ROLE_OWNER, mailbox: true},
		{name: "an owner who is an Owner no longer", ownerRole: bridge.MemberRole_MEMBER_ROLE_ADMIN, genesis: true, mailbox: true},
		{name: "an owner with no member row", genesis: true, mailbox: true},
		{name: "an Owner with no mailbox", ownerRole: bridge.MemberRole_MEMBER_ROLE_OWNER, genesis: true},
	}
	for _, c := range cases {
		fixture := newAclTestFixture()
		owner := NewId()
		if c.ownerRole != bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED {
			owner = fixture.member(c.ownerRole)
		}
		if c.genesis {
			fixture.configRepo(NewId(), owner)
		}
		if c.mailbox {
			fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, owner, protocol.RepoInbox_REPO_INBOX_NONE, 1)
		}
		// another member's mailbox is never taken in its place
		fixture.createdRepo(protocol.RepoKind_REPO_KIND_MAILBOX, fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER), protocol.RepoInbox_REPO_INBOX_NONE, 2)
		if repoId, found := fixture.state(t).NetworkMailKeyRepo(); found {
			t.Errorf("%s: the rows name %s", c.name, repoId)
		}
	}
	var state *AclState
	if _, found := state.NetworkMailKeyRepo(); found {
		t.Error("no state names a repo")
	}
}
