// §16.11's Repos block at M6 (RECORD-M6-15): a repo's item rides announce entries, as every item does before format 2,
// and readers hold it to the repo file row, the entry's push's auth pin standing for at (D-MCP-35).
//
// Reading, for each version of a repo's item:
//
//	signed      who.sidecar_id is the entry's signer, and a copy sits in its own stream, as for every item
//	repo        a repo the access log holds, of the kind the item names; never config, mailcfg or the directory,
//	            whose items readers ignore (§16.11's not default row); shown while the repo lives
//	right       its signer held D-MCP-35's right at the push's pin, by retained history: a repo admin of the repo by
//	            its access log, an owner-bound repo's consented device of its owner (owner decision 126); found once,
//	            kept, so a later RepoAdmin remove leaves the version standing; a pin before what the state retains is
//	            taken as §11.9's first pin and judged from the config head's positions
//	voided      a compromise revocation of the signer from a since_n at or before the pin voids it, however late
//	right ended a log entry after the pin ending the right more than 10 min before the push's time_ms voids it for a
//	            reader holding that entry, since evs bounds a push's pin only by its ref's head pin
//	who         member_id is the signer's member, or a sponsored signer's sponsor, at the pin, or in the reader's state
//	            where the pin is past what it retains
//	age         none: repo items carry no expiry, so no 4,096-position bound applies to them at M6, the push's pin
//	            being at itself (FS-101)
//
// Writing, by a device holding the right now:
//
//	default     right after a general or record repo's RepoCreate commits, its creating device writes the item:
//	            display name, kind, roles {reader, writer}, requests open (owner decision 181); a group inbox with
//	            requests closed and no roles; nothing for any other kind
//	private     under --private, a private marker instead: who, repo_id, repo_kind and requests alone, padded to the
//	            same 2,048 B as an announcement (plan-RECORD-m6-carrier #2), so evs cannot tell which repos are private;
//	            no device announces a private repo on its own, and its owner may later, a full item at a higher version;
//	            a create marked private is filed only while the directory stands, a directory admin's device filing it
//	            first and any other refusing (QD-748, directory_private.go), so no private repo predates the directory
//	explicit    ur directory announce repo: any announceable kind, a full item at a higher version; vault, mailbox,
//	            secret and team_record only so, by their owner or repo admin
//	predating   a general or record repo created before the directory, with no item, is written by the first of its
//	            admins' devices to sync it: as a private marker until question record-m6-14-private-before-directory is
//	            answered, since a repo created with --private while its team had no directory has no marker, and only a
//	            marker keeps that choice; its admins announce it explicitly
//	re-sign     once the standing version's signer is revoked, reaped or its member removed, or a compromise voided the
//	            newest, the first repo admin's device to sync writes it again at a higher version; a voided version
//	            gives only its attested fields, never its prose, which its signer's key no longer vouches for
//
// Every write is redacted, checked, padded and appended through the record writer, which routes announce to this
// sidecar's own stream in the directory. Barriers: directory.announce.before and .after around the append, keyed by
// the repo's id.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// This device holds no right to write the repo's item now: D-MCP-35's, or an owner-bound repo's consent. Readers
	// would ignore what it wrote, so nothing is.
	ErrDirectoryRepoRight = errors.New("directory repo right not held")
	// The repo's kind takes no item: config, mailcfg and the directory are never announced (§16.11's not default row).
	ErrDirectoryRepoKind = errors.New("directory repo kind never announced")
	// No record writer is bound, so the directory takes nothing from this client.
	ErrDirectoryNoWriter = errors.New("directory has no record writer")
	// A general or record repo marked private needs the team's directory to hold its private marker, and none stands
	// where this device can see it (QD-748): a create refuses before its RepoCreate is filed, and a repo already made
	// waits for the directory to show, its create resumed by id to write the marker.
	ErrDirectoryPrivateNeedsDirectory = errors.New("a repo marked private needs the team directory standing first")
)

// The warning a repo marked private takes while a config label may still name it (§16.11's labels row): the label
// names it to every admitted sidecar outside the directory.
const DirectoryRepoLabelWarning = "a config label may still name this repo to every admitted sidecar"

// A repo's item as a repo admin writes it (§16.11's Repos block).
type DirectoryRepoAnnounceArgs struct {
	RepoId Id
	// Prose: at most 128 B once redacted.
	DisplayName string
	// Prose: at most 512 B once redacted.
	Description string
	// Labels [a-z0-9-]{1,32}, at most 8.
	Topics []string
	// The roles offered; nil offers reader and writer, an owner-bound repo's reader alone, since its grant is an
	// EvsShare.
	Roles []protocol.RepoGrantRole
	// Whether it takes requests; 0 opens a general, record or team record repo's, and closes an owner-bound one's.
	Requests DirectoryRequests
	// A private marker in place of the announcement: who, repo_id, repo_kind and requests alone.
	Private bool
	// A person confirmed the act on /dev/tty or in an app's UI (§5.8): the entry's source is approver, else observed.
	Confirmed bool
}

// What one repo item write appended.
type DirectoryRepoWrite struct {
	Item  *protocol.Announcement
	Entry *RecordEntryRef
	// What the person should hear, as DirectoryRepoLabelWarning.
	Warnings []string
}

// D-MCP-35's repo file row for one version of a repo's item, the push's pin standing for at.
func (self *directoryJudge) repo(version *directoryVersion) directoryJudgement {
	judgement, ok := self.fixed(version)
	if !ok {
		judgement = self.repoFixed(version)
		self.keepFixed(version, judgement)
	}
	if judgement.verdict != directoryVerdictAccepted {
		return judgement
	}
	position := version.pushPin.GetVersion()
	if self.auth.SignatureVoided(version.writerId, position) {
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	if self.rightEnded(version) {
		// an entry that ended the right came well before the push: final for this reader, which holds it
		refused := directoryRefused(SidecarRecordAlarmBadEntry)
		self.keepFixed(version, refused)
		return refused
	}
	atPin, err := self.auth.At(version.pushPin)
	if err != nil {
		// past what the state retains: who as the reader's state names it
		atPin = self.auth
	}
	if !directoryWhoMatches(atPin, version.writerId, version.item.GetWho().GetMemberId()) {
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	return directoryAccepted
}

// The repo file row's parts that rest on fixed history: who signed and pushed it, the repo and its kind, the pin on
// the reader's chain, and D-MCP-35's right at the push's pin.
func (self *directoryJudge) repoFixed(version *directoryVersion) directoryJudgement {
	item := version.item
	switch {
	case !bytes.Equal(item.GetWho().GetSidecarId(), version.writerId[:]):
		return directoryRefused(SidecarRecordAlarmBadEntry)
	case version.pushPin == nil:
		return directoryRefused(SidecarRecordAlarmPathRule)
	case self.readerPin == nil || self.readerPin.GetVersion() < version.pushPin.GetVersion():
		return directoryPending
	}
	repoId := recordIdOf(item.GetWhere().GetRepoId())
	repo, ok := self.auth.Repo(repoId)
	switch {
	case !ok, directoryRepoFileIgnored(repo.Kind), protocol.RepoKind(item.GetWhat().GetRepoKind()) != repo.Kind:
		// a repo the log never held, one whose items readers ignore, or one the item names a kind it is not
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	_, err := self.auth.At(version.pushPin)
	switch {
	case err == nil, errors.Is(err, ErrDirectoryAuthNotRetained):
		// a pin before what the state retains is taken as §11.9's first pin
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryPending
	default:
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	right, err := self.auth.RepoAdminRight(repoId, version.writerId, version.pushPin.GetVersion())
	switch {
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryPending
	case err != nil, !right:
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	return directoryAccepted
}

// Whether a log entry after version's pin ended its signer's right more than 10 min before the push's time_ms, asked
// of the state once each reader pin.
func (self *directoryJudge) rightEnded(version *directoryVersion) bool {
	readerVersion := self.readerPin.GetVersion()
	checked := func() bool {
		self.fold.stateLock.Lock()
		defer self.fold.stateLock.Unlock()
		at, ok := self.fold.leafNotEndedAt[version.leaf]
		return ok && at == readerVersion
	}()
	if checked {
		return false
	}
	repoId := recordIdOf(version.item.GetWhere().GetRepoId())
	beforeMillis := version.pushTimeMillis - DirectoryRightBound.Milliseconds()
	if self.auth.RepoAdminRightEnded(repoId, version.writerId, version.pushPin.GetVersion(), beforeMillis) {
		return true
	}
	self.fold.stateLock.Lock()
	defer self.fold.stateLock.Unlock()
	self.fold.leafNotEndedAt[version.leaf] = readerVersion
	return false
}

// One repo's item from its versions, highest first: the highest accepted, shown while the repo lives. True when any
// version was accepted.
func (self *directoryJudge) repoItem(versions []*directoryVersion) (*DirectoryItem, bool) {
	winner := self.repoWinner(versions)
	if winner == nil {
		return nil, false
	}
	repo, ok := self.auth.Repo(recordIdOf(winner.item.GetWhere().GetRepoId()))
	if !ok || !repo.Live {
		// §16.11's lifetime row: the item ends with its repo
		return nil, true
	}
	display := DirectoryItemActive
	if winner.item.GetWhere().GetPrivate() {
		display = DirectoryItemPrivate
	}
	return self.itemOf(winner, display), true
}

// The highest version whose signer held D-MCP-35's right at its pin, a compromise having voided it since or not; nil
// for none. The versions are judged first, so each one's fixed verdict is kept.
func (self *directoryJudge) repoHeld(versions []*directoryVersion) *directoryVersion {
	for _, version := range versions {
		self.repo(version)
		if fixed, ok := self.fixed(version); ok && fixed.verdict == directoryVerdictAccepted {
			return version
		}
	}
	return nil
}

// The highest accepted version, alarming each refused one; nil for none.
func (self *directoryJudge) repoWinner(versions []*directoryVersion) *directoryVersion {
	var winner *directoryVersion
	for _, version := range versions {
		judgement := self.repo(version)
		if judgement.verdict != directoryVerdictAccepted {
			self.alarm(version, judgement)
			continue
		}
		if winner == nil {
			winner = version
		}
	}
	return winner
}

// RepoCreated's hook in a team network (EvsClientArgs.RepoCreated): a general or record repo's item at its creation,
// or its private marker under --private; nothing for another kind, and nothing in a network with no directory.
func (self *DirectoryClient) AnnounceNewRepo(ctx context.Context, created *EvsRepoCreated) (*DirectoryRepoWrite, error) {
	if created == nil {
		return nil, fmt.Errorf("%w: no repo", ErrDirectoryFormatInvalid)
	}
	if !aclRepoKindGeneral(created.Kind) {
		// vault, mailbox, secret and team_record repos are not announced by default
		return nil, nil
	}
	args := &DirectoryRepoAnnounceArgs{
		RepoId:      created.RepoId,
		DisplayName: created.DisplayName,
		Private:     created.Private,
		Confirmed:   created.Confirmed,
	}
	if created.GroupInbox {
		// a group's members are mailcfg's: requests closed and no roles, which a RepoGrant would widen
		args.Requests = DirectoryRequestsClosed
		args.Roles = []protocol.RepoGrantRole{}
	}
	return self.AnnounceRepo(ctx, args)
}

// Writes a repo's item, or its private marker, at one version above the highest this copy shows for it (§16.11's
// private and revoke rows: a later full item replaces a marker, a marker an item). A person's act on /dev/tty or in
// an app's UI for an explicit announcement (§5.8); the daemon's own at creation.
func (self *DirectoryClient) AnnounceRepo(ctx context.Context, args *DirectoryRepoAnnounceArgs) (*DirectoryRepoWrite, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no repo", ErrDirectoryFormatInvalid)
	}
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	auth := self.auth()
	if _, ok := auth.Directory(); !ok {
		return nil, ErrDirectoryNone
	}
	repo, ok := auth.Repo(args.RepoId)
	if !ok || !repo.Live {
		return nil, fmt.Errorf("%w: a repo this state does not hold live", ErrDirectoryRepoRight)
	}
	if directoryRepoFileIgnored(repo.Kind) {
		return nil, ErrDirectoryRepoKind
	}
	if err := self.holdsRepoRight(auth, args.RepoId); err != nil {
		return nil, err
	}
	item, err := self.repoItemFor(auth, repo, args)
	if err != nil {
		return nil, err
	}
	write, err := self.appendRepoItem(item, args.Confirmed)
	if err != nil {
		return nil, err
	}
	if args.Private && (self.repoLabeled == nil || self.repoLabeled(args.RepoId)) {
		// unknown counts as labeled: the warning costs nothing, a missed one the name
		write.Warnings = append(write.Warnings, DirectoryRepoLabelWarning)
	}
	return write, nil
}

// Whether this device holds D-MCP-35's right on repoId now, as a reader would judge what it is about to write.
func (self *DirectoryClient) holdsRepoRight(auth DirectoryAuthView, repoId Id) error {
	pin := auth.Pin()
	if pin == nil {
		return ErrDirectoryAuthUnavailable
	}
	right, err := auth.RepoAdminRight(repoId, self.sidecarId, pin.GetVersion())
	if err != nil {
		return err
	}
	if !right || auth.SignatureVoided(self.sidecarId, pin.GetVersion()) {
		return ErrDirectoryRepoRight
	}
	return nil
}

// The item args describe, at one version above the highest this copy shows or this client wrote, redacted and
// checked as a reader will check it.
func (self *DirectoryClient) repoItemFor(auth DirectoryAuthView, repo *DirectoryRepo, args *DirectoryRepoAnnounceArgs) (*protocol.Announcement, error) {
	nowMillis := self.clock.Now().UnixMilli()
	announcementId := DirectoryRepoAnnouncementId(repo.RepoId)
	version, startedMillis := self.repoVersionAbove(auth, repo.RepoId, nowMillis)
	ownerBound := aclRepoKindOwnerBound(repo.Kind)
	requests := args.Requests
	if requests == 0 {
		requests = DirectoryRequestsOpen
		if ownerBound {
			requests = DirectoryRequestsClosed
		}
	}
	who := &protocol.AnnounceWho{SidecarId: self.sidecarId.Bytes()}
	if memberId, ok := DirectoryWhoMember(auth, self.sidecarId); ok {
		who.MemberId = memberId.Bytes()
	}
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(DirectoryAnnouncementKindRepo),
		Version:        version,
		StartedMillis:  startedMillis,
		RenewedMillis:  nowMillis,
		State:          uint32(DirectoryAnnouncementStateActive),
		Who:            who,
		What:           &protocol.AnnounceWhat{RepoKind: uint32(repo.Kind), Requests: uint32(requests)},
		Where:          &protocol.AnnounceWhere{RepoId: repo.RepoId.Bytes()},
	}
	if args.Private {
		item.Where.Private = true
	} else {
		roles := args.Roles
		if roles == nil {
			roles = []protocol.RepoGrantRole{protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
			if !ownerBound {
				roles = append(roles, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
			}
		}
		for _, role := range roles {
			item.What.Roles = append(item.What.Roles, uint32(role))
		}
		item.What.Title = args.DisplayName
		item.What.Description = args.Description
		item.What.Topics = slices.Clone(args.Topics)
		if _, err := DirectoryRedact(self.redactorNow(), item); err != nil {
			return nil, err
		}
	}
	if err := DirectoryCheckItem(item); err != nil {
		return nil, err
	}
	if _, err := DirectoryPadRepoAnnouncement(item); err != nil {
		return nil, err
	}
	return item, nil
}

// One above the highest version of repoId's item whose signer held the right at its pin, a version a compromise has
// voided since included, or that this client wrote and has not read back yet; and the item's started time: the shown
// one's, else now. A version no rightful signer wrote, which readers ignore, moves nothing.
func (self *DirectoryClient) repoVersionAbove(auth DirectoryAuthView, repoId Id, nowMillis int64) (uint64, int64) {
	key := DirectoryItemKey{Kind: DirectoryAnnouncementKindRepo, AnnouncementId: DirectoryRepoAnnouncementId(repoId)}
	version, startedMillis, ok := self.currentFold().repoVersionHeld(auth, nowMillis, key)
	if !ok {
		startedMillis = nowMillis
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return max(version, self.repoWrittenVersions[repoId]) + 1, startedMillis
}

// The highest version of a repo item whose signer held D-MCP-35's right at its pin, voided since or not, and the
// started time of the version that stands, else of that one; false for none.
func (self *DirectoryFold) repoVersionHeld(auth DirectoryAuthView, nowMillis int64, key DirectoryItemKey) (uint64, int64, bool) {
	versions := func() []*directoryVersion {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.keyVersions[key]
	}()
	judge := &directoryJudge{fold: self, auth: auth, readerPin: auth.Pin(), nowMillis: nowMillis, standingNow: map[Id]DirectoryStanding{}}
	winner := judge.repoWinner(versions)
	held := judge.repoHeld(versions)
	for _, alarm := range judge.alarms {
		if self.alarm != nil {
			self.alarm(alarm)
		}
	}
	switch {
	case held == nil:
		return 0, 0, false
	case winner != nil:
		return held.item.GetVersion(), winner.item.GetStartedMillis(), true
	}
	return held.item.GetVersion(), held.item.GetStartedMillis(), true
}

// Appends item, padded, through the record writer: the directory's announce entry in this sidecar's own stream.
func (self *DirectoryClient) appendRepoItem(item *protocol.Announcement, confirmed bool) (*DirectoryRepoWrite, error) {
	if self.writer == nil {
		return nil, ErrDirectoryNoWriter
	}
	repoId := recordIdOf(item.GetWhere().GetRepoId())
	source := RecordSourceObserved
	if confirmed {
		source = RecordSourceApprover
	}
	hookKey := recordChainIdText(repoId)
	testHookBarrier("directory.announce.before", hookKey)
	refs, err := self.writer.Append(&RecordDraft{Kind: RecordKindAnnounce, Source: source, NoSession: true, Body: item})
	testHookBarrier("directory.announce.after", hookKey)
	if err != nil {
		return nil, err
	}
	write := &DirectoryRepoWrite{Item: item}
	for _, ref := range refs {
		if directoryId, ok := self.DirectoryId(); ok && ref.LogId == directoryId {
			write.Entry = ref
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.repoWrittenVersions[repoId] = max(self.repoWrittenVersions[repoId], item.GetVersion())
	}()
	return write, nil
}

// The repo items this device's rights call for after a sync (§16.11's default and repair rows, D-MCP-35): a general
// or record repo predating the directory and holding no item gets its private marker (see the file's predating row),
// and an item whose standing version's signer was revoked, reaped or its member removed, or whose newest version a
// compromise voided, is written again at a higher version. Each repo is written at most once until the copy reads that
// write back. Answers what it wrote; a read_only client, or one with no writer, writes nothing.
func (self *DirectoryClient) MaintainRepos(ctx context.Context) ([]*DirectoryRepoWrite, error) {
	writes := []*DirectoryRepoWrite{}
	if self.readOnly || self.writer == nil {
		return writes, nil
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return writes, nil
	}
	directory, ok := auth.Repo(directoryId)
	if !ok {
		return writes, nil
	}
	fold := self.currentFold()
	keyVersions := func() map[DirectoryItemKey][]*directoryVersion {
		fold.stateLock.Lock()
		defer fold.stateLock.Unlock()
		return fold.keyVersions
	}()
	judge := &directoryJudge{fold: fold, auth: auth, readerPin: auth.Pin(), nowMillis: self.clock.Now().UnixMilli(), standingNow: map[Id]DirectoryStanding{}}
	for _, repo := range auth.Repos() {
		if !repo.Live || directoryRepoFileIgnored(repo.Kind) || self.holdsRepoRight(auth, repo.RepoId) != nil {
			continue
		}
		key := DirectoryItemKey{Kind: DirectoryAnnouncementKindRepo, AnnouncementId: DirectoryRepoAnnouncementId(repo.RepoId)}
		versions := keyVersions[key]
		args := (*DirectoryRepoAnnounceArgs)(nil)
		if winner := judge.repoWinner(versions); winner != nil {
			if winner.writerId != self.sidecarId && auth.Masked(winner.writerId) {
				// the standing version's signer was revoked, reaped or its member removed: the same item, re-signed
				args = directoryRepoArgsOf(winner.item, true)
			}
		} else if held := judge.repoHeld(versions); held != nil && auth.SignatureVoided(held.writerId, held.pushPin.GetVersion()) {
			// the newest rightful version a compromise voided: its attested fields alone
			args = directoryRepoArgsOf(held.item, false)
		} else if aclRepoKindGeneral(repo.Kind) && repo.CreatedAt < directory.CreatedAt {
			// a repo predating the directory, with no item: the first of its admins' devices to sync writes it, as a
			// private marker meanwhile (question record-m6-14-private-before-directory), so a repo its creator marked
			// private before the directory existed is never named by another device
			args = &DirectoryRepoAnnounceArgs{Private: true}
		}
		if args == nil {
			continue
		}
		args.RepoId = repo.RepoId
		written := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			highest := uint64(0)
			for _, version := range versions {
				if version.writerId == self.sidecarId {
					highest = max(highest, version.item.GetVersion())
				}
			}
			// a write of this client's above everything of its own the copy holds has not come back yet
			return highest < self.repoWrittenVersions[repo.RepoId]
		}()
		if written {
			continue
		}
		item, err := self.repoItemFor(auth, repo, args)
		if err != nil {
			return writes, err
		}
		write, err := self.appendRepoItem(item, false)
		if err != nil {
			return writes, err
		}
		writes = append(writes, write)
	}
	for _, alarm := range judge.alarms {
		if self.alarm != nil {
			self.alarm(alarm)
		}
	}
	return writes, nil
}

// The args that write item again: its roles, requests and private bit, and its prose only when withProse, since a
// voided signer's prose is vouched for by no one.
func directoryRepoArgsOf(item *protocol.Announcement, withProse bool) *DirectoryRepoAnnounceArgs {
	what := item.GetWhat()
	args := &DirectoryRepoAnnounceArgs{
		Requests: DirectoryRequests(what.GetRequests()),
		Private:  item.GetWhere().GetPrivate(),
		Roles:    []protocol.RepoGrantRole{},
	}
	for _, role := range what.GetRoles() {
		args.Roles = append(args.Roles, protocol.RepoGrantRole(role))
	}
	if withProse {
		args.DisplayName = what.GetTitle()
		args.Description = what.GetDescription()
		args.Topics = slices.Clone(what.GetTopics())
	}
	return args
}

// EvsClientArgs.RepoCreated for this Sidecar: its team network's directory announces the new repo, or writes its
// private marker. With no directory shown, or a directory client not bound yet, a repo the directory would announce is
// left to §16.11's predating rule and nothing is written; but a general or record repo marked private answers
// ErrDirectoryPrivateNeedsDirectory, since only its marker keeps the choice: EvsClientArgs.PrivateCreate let its
// RepoCreate be filed only once the directory stood, so the view has not caught up yet, and a create resumed by its id
// writes the marker once it has (QD-748).
func (self *Sidecar) announceCreatedRepo(ctx context.Context, created *EvsRepoCreated) error {
	err := ErrDirectoryNone
	if directory := self.Directory(); directory != nil {
		_, err = directory.AnnounceNewRepo(ctx, created)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrDirectoryNone) && created != nil && created.Private && aclRepoKindGeneral(created.Kind):
		return fmt.Errorf("%w: the repo is made, and its private marker waits for the directory: %w", ErrDirectoryPrivateNeedsDirectory, err)
	case errors.Is(err, ErrDirectoryNone):
		return nil
	}
	return err
}
