//go:build !ios_extension

// Group mail's repos (§15.7, §15.8, §16.11; D-MAIL-6; MAIL-M7-05): a group is one general repo on a file-mode ref
// whose readers are the group's members, at most mail_group_members of them (§20.4).
//
//	create    `ur id group-create [--private]`: a general repo announced in a team network with requests closed and
//	          no roles offered, or a private marker with --private (EvsCreateRepoArgs.GroupInbox, which the
//	          directory's announcement writer reads), and the group's address in mailcfg. A group inbox takes
//	          deposits, so its RepoCreate must carry the inbox marker plan-MAIL-group-inbox decided (QD-102:
//	          RepoCreate.inbox, with the drop key KEYS-M2-20 rotates for it and the deposit grant to tag:mail).
//	          acl.proto's RepoCreate carries no such field yet, so CreateGroup refuses: a general repo made without
//	          it would be a group no receiver can deposit to
//	join      `ur id group-add` is the only way in: it writes the member into the group's mailcfg record and files
//	          the RepoGrant that lets the member's devices read the repo, together: the record first, then the grant,
//	          each a no-op where it already stands, so a call cut short between them is finished by the same call
//	          again. The group's members are mailcfg's: a RepoGrant alone, with no record, joins no group, since the
//	          members' devices add r/ references only for the groups their mailcfg record names them in
//	admins    only the group repo's admins erase its messages (§15.7): its creating device and those a repo admin
//	          or config writer adds. MailRepos adds none
//
// On every leg but the extension's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A group inbox cannot be created yet: RepoCreate carries no inbox marker, so no drop key would be rotated for the
// repo and no receiver could deposit to it (plan-MAIL-group-inbox, QD-102; KEYS-M2-20, ACL-M2-06).
var ErrMailGroupInboxNotBuilt = errors.New("mail repos: a group inbox needs RepoCreate's inbox marker, which is not built")

// What CreateGroup creates.
type MailCreateGroupArgs struct {
	// The group's address: <LocalPart>@<net>.<root>.
	LocalPart string
	// The name a team network's directory announces the repo under.
	DisplayName string
	// --private: a private marker in place of the announcement (§16.11).
	Private bool
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	Action    MailConfigActionArgs
}

// Creates a group (§15.8's `ur id group-create`): its general repo and its address in config's mailcfg. It refuses
// with ErrMailGroupInboxNotBuilt until RepoCreate carries the inbox marker: see the file header. Nothing is filed
// or written.
func (self *MailRepos) CreateGroup(ctx context.Context, config *MailConfig, args *MailCreateGroupArgs) (*EvsRepo, error) {
	if config == nil || args == nil {
		return nil, fmt.Errorf("%w: no group", ErrMailReposInvalid)
	}
	if err := ValidateNewMailLocalPart(args.LocalPart); err != nil {
		return nil, err
	}
	if _, err := self.verifiedState(); err != nil {
		return nil, err
	}
	return nil, ErrMailGroupInboxNotBuilt
}

// Whether a RepoGrant of role, or a wider one, stands for subject in repo with no expiry.
func mailRepoGrantStands(repo *protocol.AclRepo, subject Id, role protocol.RepoGrantRole) bool {
	revoked := slices.ContainsFunc(repo.GetRevokes(), func(revoke *protocol.AclRepoRevokeRow) bool {
		revokedId, err := IdFromBytes(revoke.GetSubject())
		return err == nil && revokedId == subject
	})
	if revoked {
		return false
	}
	return slices.ContainsFunc(repo.GetGrants(), func(grant *protocol.AclRepoGrantRow) bool {
		grantedId, err := IdFromBytes(grant.GetSubject())
		return err == nil && grantedId == subject && role <= grant.GetRole() && grant.GetExpires() == 0
	})
}

// Adds a member to a group (§15.8's `ur id group-add`, the only way in): the member joins the group's mailcfg
// record, within mail_group_members, and a RepoGrant lets the member read the group's repo. The record goes first
// and the grant after it, each skipped where it stands, so the same call again finishes one cut short. By a device
// that may change the group's record and administers its repo: ErrMailConfigNotOwner otherwise, and
// ErrMailConfigGroupFull past the bound, with nothing filed.
func (self *MailRepos) AddGroupMember(ctx context.Context, config *MailConfig, localPart string, memberId Id) error {
	if config == nil || memberId == (Id{}) {
		return fmt.Errorf("%w: no group or member", ErrMailReposInvalid)
	}
	if self.fileStatement == nil {
		return ErrMailReposNoState
	}
	state, err := self.verifiedState()
	if err != nil {
		return err
	}
	_, groupRepoId, err := config.GroupMembers(ctx, localPart)
	if err != nil {
		return err
	}
	repo := state.Repo(groupRepoId)
	if repo == nil || !mailRepoStands(repo) || repo.GetKind() != protocol.RepoKind_REPO_KIND_GENERAL {
		return fmt.Errorf("%w: the group's repo", ErrMailReposAbsent)
	}
	// the record: the bound, and whether this device may change it, are MailConfig's to refuse, before any grant
	if err := config.AddGroupMember(ctx, localPart, memberId); err != nil {
		return err
	}
	if mailRepoGrantStands(repo, memberId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER) {
		return nil
	}
	grant := &protocol.RepoGrant{RepoId: groupRepoId.Bytes(), Subject: memberId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
	if err := self.fileStatement(ctx, bridge.SignedType_SIGNED_REPO_GRANT, grant); err != nil {
		return fmt.Errorf("mail repos: RepoGrant: %w", err)
	}
	return nil
}
