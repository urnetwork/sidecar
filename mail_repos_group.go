//go:build !ios_extension

// Group mail's repos (§15.7, §15.8, §16.11; D-MAIL-6; MAIL-M7-05): a group is one general repo on a file-mode ref
// whose readers are the group's members, at most mail_group_members of them (§20.4).
//
//	create    `ur id group-create [--private]`: a general repo announced in a team network with requests closed and
//	          no roles offered, or a private marker with --private, and the group's address in mailcfg. The
//	          signed RepoCreate.inbox role selects the drop key and per-message slots. On Team networks the
//	          creator also grants deposit to tag:mail (QD-102).
//	          The device keeps the reserved random repo id and publication choice in its sealed store until the
//	          approved address, repo activation, directory publication and Team deposit grant have all succeeded.
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
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Group creation requires a person's confirmation before reserving a repo or publishing an address.
var ErrMailGroupUnconfirmed = errors.New("mail repos: group creation needs confirmation")

// Deprecated: retained for callers that support releases preceding the signed inbox marker.
var ErrMailGroupInboxNotBuilt = errors.New("mail repos: a group inbox needs RepoCreate's inbox marker, which is not built")

// A Team inbox needs the mail tag from the same verified head as its access projection.
var ErrMailGroupIndexerTag = errors.New("mail repos: the mail indexer tag is unavailable")

// The creation's durable identity and directory choice, shared by retries on this device.
type mailGroupCreation struct {
	RepoId      Id
	DisplayName string
	Private     bool
	Activated   bool
}

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

// Creates the approved address, activates its signed inbox repo, and files its deposit grant on Team networks.
// A failed step leaves the original random id and directory choice available to the next confirmed invocation.
func (self *MailRepos) CreateGroup(ctx context.Context, config *MailConfig, args *MailCreateGroupArgs) (*EvsRepo, error) {
	if config == nil || args == nil || self.fileStatement == nil {
		return nil, fmt.Errorf("%w: no group or statement source", ErrMailReposInvalid)
	}
	if err := ValidateNewMailLocalPart(args.LocalPart); err != nil {
		return nil, err
	}
	if !args.Confirmed {
		return nil, ErrMailGroupUnconfirmed
	}
	select {
	case self.createToken <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.createToken }()
	state, err := self.verifiedState()
	if err != nil {
		return nil, err
	}
	if _, err := self.groupDepositTag(state); err != nil {
		return nil, err
	}
	zone, _, err := config.zone()
	if err != nil {
		return nil, err
	}
	name, ok := mailConfigAddressName(zone, args.LocalPart+"@"+zone.Domain())
	if !ok {
		return nil, ErrMailReposInvalid
	}
	replay, err := config.refresh(ctx, name)
	if err != nil {
		return nil, err
	}
	configRepo := self.evs.Repo(config.store.RepoId())
	journalName := fmt.Sprintf("mail-group-create/%s/%x", configRepo.RepoId(), sha256.Sum256([]byte(name.path)))
	creation := &mailGroupCreation{}
	pending, err := configRepo.readStoreJson(journalName, creation)
	if err != nil {
		return nil, err
	}
	if replay.record != nil {
		lookup := config.lookupOf(name, replay.record)
		if !lookup.Known || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_GROUP || lookup.CreatorSidecarId != self.sidecarId {
			return nil, ErrMailConfigAddressTaken
		}
		if !pending {
			row := state.Repo(lookup.MailboxRepoId)
			if row.GetInbox() == protocol.RepoInbox_REPO_INBOX_GROUP && mailRepoStands(row) && self.created(row) {
				return self.evs.Repo(lookup.MailboxRepoId), nil
			}
			return nil, ErrMailConfigAddressTaken
		}
		if lookup.MailboxRepoId != creation.RepoId {
			return nil, ErrMailConfigAddressTaken
		}
	}
	if !pending {
		creation.RepoId = NewEvsRepoId()
		creation.DisplayName = args.DisplayName
		if creation.DisplayName == "" {
			creation.DisplayName = args.LocalPart
		}
		creation.Private = args.Private
		if err := configRepo.writeStoreJson(journalName, creation); err != nil {
			return nil, err
		}
	}
	if creation.RepoId == (Id{}) {
		return nil, ErrSidecarStoreFailed
	}
	if replay.record == nil {
		lookup, err := config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: args.LocalPart,
			Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: creation.RepoId, Action: args.Action})
		if err != nil {
			return nil, err
		}
		if !lookup.Known || lookup.MailboxRepoId != creation.RepoId || lookup.CreatorSidecarId != self.sidecarId || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_GROUP {
			return nil, ErrMailConfigAddressTaken
		}
	}
	row := state.Repo(creation.RepoId)
	if row != nil && (row.GetInbox() != protocol.RepoInbox_REPO_INBOX_GROUP || !mailRepoStands(row) || !self.created(row)) {
		return nil, ErrMailReposInvalid
	}
	if !creation.Activated {
		create := &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP,
			DisplayName: creation.DisplayName, Private: creation.Private, Confirmed: true}
		if row == nil {
			create.proposedRepoId = &creation.RepoId
		} else {
			create.ResumeRepoId = &creation.RepoId
		}
		if _, err := self.evs.CreateRepo(ctx, create); err != nil {
			return nil, err
		}
		creation.Activated = true
		if err := configRepo.writeStoreJson(journalName, creation); err != nil {
			return nil, err
		}
	}
	// Approval, keying and publication may span a change of verified head.
	state, err = self.verifiedState()
	if err != nil {
		return nil, err
	}
	row = state.Repo(creation.RepoId)
	if row.GetInbox() != protocol.RepoInbox_REPO_INBOX_GROUP || !mailRepoStands(row) || !self.created(row) {
		return nil, ErrMailReposAbsent
	}
	mailTag, err := self.groupDepositTag(state)
	if err != nil {
		return nil, err
	}
	if mailTag != (Id{}) && !mailRepoGrantStands(row, mailTag, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT) {
		grant := &protocol.RepoGrant{RepoId: creation.RepoId.Bytes(), Subject: mailTag.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT}
		if err := self.fileStatement(ctx, bridge.SignedType_SIGNED_REPO_GRANT, grant); err != nil {
			return nil, err
		}
	}
	if err := configRepo.client.args.Store.Remove(journalName); err != nil {
		return nil, err
	}
	return self.evs.Repo(creation.RepoId), nil
}

// Returns the team's required mail indexer tag for deposit grants, or zero on a personal network.
func (self *MailRepos) groupDepositTag(state *AclState) (Id, error) {
	if !state.teamNetwork() {
		return Id{}, nil
	}
	if self.mailIndexerTag != nil {
		if tag, ok := self.mailIndexerTag(state); ok && tag != (Id{}) {
			return tag, nil
		}
	}
	return Id{}, ErrMailGroupIndexerTag
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
	if repo.GetInbox() != protocol.RepoInbox_REPO_INBOX_GROUP || !mailRepoStands(repo) {
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
