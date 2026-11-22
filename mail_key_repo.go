//go:build !ios_extension

// The repo whose drop key is the network mail key, as a server reads it from the verified rows alone (§14.8, §15.8;
// D-KEYS-17). A server never reads mailcfg, so it cannot follow the admin@ record a device resolves
// (MailRepos.NetworkMailKeyRepo, the device's twin), and takes §15.8's rule instead:
//
//	Team      the one general repo whose signed RepoCreate.inbox is 2, the network's admin inbox, while it stands; the
//	          rows hold at most one (checkRepoCreate and indexRepos refuse a second)
//	personal  its Owner's mailbox: the Genesis's owner member while that member holds the Owner role, and of its
//	          mailboxes the one every device takes (MailRepos.Mailbox): standing, created first in log order, the
//	          lowest id breaking a tie
//
// A Team is a state that names a team record or a directory (teamNetwork), as the device's twin tells them apart. A Team
// scope's key, its member's mailbox's (§15.8), is not read here: reports reach the network's own token, so only the
// network's key is asked for. §14.8's report seal seals to this repo's newest drop key, and GET /smtp/reports serves
// the copies only to the repo's readers (server's model.SmtpApiGateOf), so the copies' audience and the route's agree.
//
// Pure, and safe for concurrent use as AclState is. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The repo whose drop key is the network mail key, by the rows alone (see the file header). False while the rows name
// none: a Team with no admin inbox standing, a personal network whose Genesis owner no longer holds the Owner role, or
// one whose Owner has no mailbox standing.
func (self *AclState) NetworkMailKeyRepo() (Id, bool) {
	if self == nil {
		return Id{}, false
	}
	if self.teamNetwork() {
		for _, repoId := range self.RepoIds() {
			row := self.Repo(repoId)
			if row.GetInbox() == protocol.RepoInbox_REPO_INBOX_ADMIN && AclRepoIsInbox(row) && mailRepoStands(row) {
				return repoId, true
			}
		}
		return Id{}, false
	}
	ownerMemberId, err := IdFromBytes(self.view.Genesis().GetOwnerMemberId())
	if err != nil || ownerMemberId == (Id{}) || self.view.Member(ownerMemberId).GetRole() != bridge.MemberRole_MEMBER_ROLE_OWNER {
		return Id{}, false
	}
	repoId, _, found := mailRepoOfKind(self, protocol.RepoKind_REPO_KIND_MAILBOX, func(repo *protocol.AclRepo) bool {
		return mailRepoOwnedBy(repo, ownerMemberId)
	})
	return repoId, found
}
