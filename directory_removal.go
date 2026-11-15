//go:build !ios_extension && !sidecar_http

// §16.11's Erasure and removal block, its member, device and moderation rows (RECORD-M6-21; D-MCP-26, D-MCP-29,
// D-MCP-33, I-15, FI-25, FS-87): what a removal leaves for a daemon to clean up, and a directory admin's moderation.
//
//	mask        every reader masks a removed member's, or a revoked or reaped sidecar's, items, notices and pending
//	            requests at the revocation's position, by DirectoryAuthView.Masked: the fold (directory_rules.go), the
//	            request fold (directory_request.go) and the incoming listing (directory_notice.go) each ask it. A
//	            removed member's tagged agents are not masked and keep announcing, who showing autogroup:admin until
//	            a SponsorSet (the fold's itemOf). Masking is at the position, never at the cleanup, so a reader that
//	            has not read the cleanup shows nothing it masks
//	cleanup     the directory's network-scope indexer at its first sync that shows a masked sidecar's files, else any
//	            standing member device MemberCleanupDelay after the revocation (owner decision 177), removes the
//	            masked sidecars' notices, and from format 2 their cards, in one push that lists each, by path CAS
//	            (DirectoryCardsRemover): the first commit wins, and a device whose push conflicts lists again at its
//	            next sync, finding less. An ephemeral agent's card goes the same way at its reap. A read_only sidecar,
//	            a tagged one that is no indexer, one that does not stand and a phone's view clean nothing; a
//	            member device's cleanup is not read_only's. Grants end with the revocation, history and entries stay
//	            until retention (directory_retention.go)
//	moderation  a directory admin's Moderate ERASEs entries another sidecar wrote, reason moderation, through the
//	            directory log's eraser (D-MCP-33's admin scope); every reader that takes such an erasure from a
//	            directory admin, by its ERASE's note or its erasure entry, and is the moderated writer or a device of
//	            its member or sponsor, raises record_alarm moderation naming the writer, once an erasure and writer,
//	            which apps show as a notice. From format 2 a directory admin's removal of another's card alarms the
//	            same way (directory_card.go)
//	mirror      a designated mirror is a copy for site loss, never the authority over a key: nothing here asks it
//
// Barriers: directory.removal.cleanup.before and .after around the cleanup's push, keyed by the directory's id.
//
// Safe for concurrent use: one cleanup at a time.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The directory's evs binding takes no push of several removals, so the cleanup's one push cannot go: nothing was
	// removed.
	ErrDirectoryCleanupUnbound = errors.New("directory cleanup: the binding takes no push of several removals")
	// Moderation is of another sidecar's writing, and the id names only this sidecar's own, which Erase takes: nothing
	// was erased.
	ErrDirectoryModerateOwn = errors.New("directory moderation of this sidecar's own entries")
)

const (
	directoryRemovalPart = "removal"
	// the moderation alarms raised, kept so a restart raises none again
	directoryModeratedStoreName    = "moderated"
	directoryModeratedStoreVersion = 1
)

// Removes several files of the cards ref in one push, each by its path CAS, all of them or none with PATH_CONFLICT,
// the push's statement listing each: what the removal cleanup needs of the directory's evs binding beyond
// DirectoryCards. Every write names the one push id and auth pin.
type DirectoryCardsRemover interface {
	RemoveCards(ctx context.Context, repoId Id, writes []*DirectoryCardWrite) error
}

// What the removal cleanup runs by.
type DirectoryRemovalSettings struct {
	// How long after a revocation any standing member device removes what the revoked sidecars left, when the
	// directory's network-scope indexer is not this device: 24 h (owner decision 177).
	MemberCleanupDelay time.Duration
}

// §16.11's values.
func DefaultDirectoryRemovalSettings() *DirectoryRemovalSettings {
	return &DirectoryRemovalSettings{
		MemberCleanupDelay: 24 * time.Hour,
	}
}

// What a cleanup is made over.
type DirectoryRemovalArgs struct {
	Client *DirectoryClient
	// The network-scope indexers that serve at the state now (ConfigState.Indexers); nil for none known.
	Indexers func() []Id
	Settings *DirectoryRemovalSettings
}

// What one cleanup did.
type DirectoryCleanupPass struct {
	// This device cleans up: the network-scope indexer, or a standing member device.
	Cleans bool
	// It is the network-scope indexer, which cleans at once.
	Indexer bool
	// The paths its one push removed, in path order; empty when it pushed none.
	Removed []string
	// The masked sidecars whose files wait for MemberCleanupDelay, in id order.
	Waiting []Id
	// Its push found a file changed since the copy read it: nothing was removed, and the next sync lists again.
	Conflict bool
}

// The removal cleanup of one directory client: see the file's header.
type DirectoryRemoval struct {
	client   *DirectoryClient
	indexers func() []Id
	settings *DirectoryRemovalSettings

	// one cleanup at a time
	cleanupLock sync.Mutex
}

// A cleanup over args, which runs after each sync of its client.
func NewDirectoryRemoval(args *DirectoryRemovalArgs) (*DirectoryRemoval, error) {
	if args == nil || args.Client == nil {
		return nil, fmt.Errorf("%w: a removal cleanup needs a directory client", ErrDirectoryCardsUnavailable)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDirectoryRemovalSettings()
	}
	self := &DirectoryRemoval{client: args.Client, indexers: args.Indexers, settings: settings}
	args.Client.addSyncHook(func(ctx context.Context) {
		if _, err := self.Cleanup(ctx); err != nil {
			self.client.log.Infof("[directory]the removal cleanup stopped: %s", err)
		}
	})
	return self, nil
}

// The Sidecar's removal cleanup, made once over its directory client and the config's network-scope indexers: what
// the daemon's composition calls beside the directory's component.
func (self *Sidecar) DirectoryRemoval() (*DirectoryRemoval, error) {
	client, err := self.DirectoryClient()
	if err != nil {
		return nil, err
	}
	var made error
	removal, _ := client.part(directoryRemovalPart+" cleanup", func() any {
		removal, err := NewDirectoryRemoval(&DirectoryRemovalArgs{
			Client: client,
			Indexers: func() []Id {
				state, err := self.configState()
				if err != nil {
					return nil
				}
				ids := []Id{}
				for _, indexer := range state.Indexers() {
					if indexer.Scope == protocol.IndexerScope_INDEXER_SCOPE_NETWORK {
						ids = append(ids, indexer.SidecarId)
					}
				}
				return ids
			},
		})
		if err != nil {
			made = err
			return nil
		}
		return removal
	}).(*DirectoryRemoval)
	if removal == nil {
		return nil, made
	}
	return removal, nil
}

// One file the cleanup takes: a masked sidecar's notice or card.
type directoryCleanupFile struct {
	file      *DirectoryCardFile
	sidecarId Id
}

// The files of the copy that masked sidecars left: each notice whose requester is masked, and from format 2 each card
// whose sidecar is. Removals and files that do not decode are none.
func (self *DirectoryRemoval) maskedFiles(auth DirectoryAuthView) []*directoryCleanupFile {
	found := []*directoryCleanupFile{}
	for _, file := range self.client.store.Cards() {
		if file.Removed {
			continue
		}
		var sidecarId Id
		switch {
		case strings.HasPrefix(file.Path, "q/"):
			notice, err := DirectoryDecodeNotice(file.Content)
			if err != nil {
				continue
			}
			sidecarId = Id(notice.GetRequesterSidecarId())
		case strings.HasPrefix(file.Path, "d/"):
			cardSidecarId, ok := directoryCardPathSidecar(file.Path)
			if !ok {
				continue
			}
			sidecarId = cardSidecarId
		default:
			continue
		}
		if auth.Masked(sidecarId) {
			found = append(found, &directoryCleanupFile{file: file, sidecarId: sidecarId})
		}
	}
	return found
}

// Whether this device cleans up at auth, and whether as the network-scope indexer: a designated indexer that stands,
// else a member device that stands; never a read_only client.
func (self *DirectoryRemoval) cleaner(auth DirectoryAuthView) (bool, bool) {
	client := self.client
	if client.readOnly || client.writer == nil {
		return false, false
	}
	standing, err := auth.SignerStanding(client.sidecarId, auth.Pin())
	if err != nil || standing != DirectoryStandingStanding {
		return false, false
	}
	if self.indexers != nil && slices.Contains(self.indexers(), client.sidecarId) {
		return true, true
	}
	if _, memberDevice := auth.MemberOf(client.sidecarId); memberDevice {
		return true, false
	}
	return false, false
}

// One cleanup: see the file's header's cleanup row. It removes nothing on a device that does not clean up, nor before
// any masked sidecar's files are due.
func (self *DirectoryRemoval) Cleanup(ctx context.Context) (*DirectoryCleanupPass, error) {
	self.cleanupLock.Lock()
	defer self.cleanupLock.Unlock()
	pass := &DirectoryCleanupPass{}
	client := self.client
	auth := client.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return pass, nil
	}
	pass.Cleans, pass.Indexer = self.cleaner(auth)
	if !pass.Cleans {
		return pass, nil
	}
	nowMillis := client.clock.Now().UnixMilli()
	due := []*directoryCleanupFile{}
	waiting := map[Id]bool{}
	for _, found := range self.maskedFiles(auth) {
		if !pass.Indexer {
			_, sinceMillis, masked := auth.MaskedSince(found.sidecarId)
			if !masked || (sinceMillis != 0 && nowMillis < sinceMillis+self.settings.MemberCleanupDelay.Milliseconds()) {
				// a revocation older than this state holds is past the delay too
				waiting[found.sidecarId] = true
				continue
			}
		}
		due = append(due, found)
	}
	for sidecarId := range waiting {
		pass.Waiting = append(pass.Waiting, sidecarId)
	}
	slices.SortFunc(pass.Waiting, Id.Cmp)
	if len(due) == 0 {
		return pass, nil
	}
	remover, ok := client.boundCards().(DirectoryCardsRemover)
	if !ok {
		return pass, ErrDirectoryCleanupUnbound
	}
	pushId := NewId()
	pin := auth.Pin()
	writes := []*DirectoryCardWrite{}
	for _, found := range due {
		writes = append(writes, &DirectoryCardWrite{PushId: pushId, Path: found.file.Path, IfVersion: found.file.Version, AuthPin: pin})
	}
	hookKey := recordChainIdText(directoryId)
	testHookBarrier("directory.removal.cleanup.before", hookKey)
	err := remover.RemoveCards(ctx, directoryId, writes)
	testHookBarrier("directory.removal.cleanup.after", hookKey)
	switch {
	case directoryPathConflict(err):
		// another device's cleanup or a rewrite landed first: the next sync lists what is left
		pass.Conflict = true
		client.ViewSync()
		return pass, nil
	case err != nil:
		return pass, err
	}
	for _, write := range writes {
		pass.Removed = append(pass.Removed, write.Path)
	}
	// the copy reads its own push back at the next sync
	client.ViewSync()
	return pass, nil
}

// A directory admin's moderation (§16.11's moderation row): the ERASE, reason moderation, of every entry that another
// sidecar wrote among those args.Id names, an entry's id or an announcement's, through the eraser BindEraser bound. A
// person's confirmed act, as Erase is; ErrDirectoryModerateOwn when id names only this sidecar's own writing.
func (self *DirectoryClient) Moderate(ctx context.Context, args *DirectoryEraseArgs) (*DirectoryEraseResult, error) {
	if args == nil || args.Id == (Id{}) {
		return nil, fmt.Errorf("%w: a moderation names an announcement or an entry", ErrDirectoryFormatInvalid)
	}
	if !args.Confirmed || args.HarnessAncestor {
		return nil, ErrDirectoryEraseUnconfirmed
	}
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return nil, ErrDirectoryNone
	}
	admin, _, err := self.directoryAdmin(auth)
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, ErrDirectoryEraseNotAdmin
	}
	erase := self.boundEraser()
	if erase == nil {
		return nil, ErrDirectoryEraserUnbound
	}
	entryIds := []Id{}
	own := 0
	for _, entry := range self.allEntries() {
		if entry.Header == nil || entry.Header.Header == nil || entry.State.KeyGone() || !directoryEntryNamedBy(entry, args.Id) {
			continue
		}
		if recordIdOf(entry.Header.Header.GetWriterSidecarId()) == self.sidecarId {
			own += 1
			continue
		}
		entryIds = append(entryIds, entry.EntryId)
	}
	if len(entryIds) == 0 {
		if 0 < own {
			return nil, ErrDirectoryModerateOwn
		}
		return nil, fmt.Errorf("%w: no entry or announcement %s with a key left to erase", ErrDirectoryItemNone, args.Id)
	}
	result, err := erase(ctx, &RecordEraseArgs{LogId: directoryId, EntryIds: entryIds, Reason: RecordErasureReasonModeration, Confirmed: true})
	if err != nil {
		return nil, err
	}
	self.ViewSync()
	return &DirectoryEraseResult{ErasureId: result.ErasureId, EntryIds: result.Erased, Reason: RecordErasureReasonModeration}, nil
}

// Whether id names entry: its own id, or for an announce entry the announcement it carries.
func directoryEntryNamedBy(entry *RecordReadEntry, id Id) bool {
	if entry.EntryId == id {
		return true
	}
	if entry.Header.Kind() != RecordKindAnnounce || entry.Body == nil {
		return false
	}
	item, err := DirectoryDecodeAnnouncement(entry.Body)
	return err == nil && recordIdOf(item.GetAnnouncementId()) == id
}

// Sets the readers' moderation alarm on every leg that links this file.
func init() {
	directoryAfterRead = func(client *DirectoryClient, directoryId Id, entries []*RecordReadEntry) {
		client.moderationAlarms(directoryId, entries)
	}
}

// What the moderation alarm keeps: each (erasure, writer) it raised, so a restart raises none again.
type directoryModeration struct {
	stateLock sync.Mutex
	loaded    bool
	raised    map[string]bool
}

// The kept moderation alarms.
type directoryModeratedDocument struct {
	Version int      `json:"version"`
	Raised  []string `json:"raised"`
}

// The client's moderation part.
func (self *DirectoryClient) moderation() *directoryModeration {
	return self.part(directoryRemovalPart+" moderation", func() any {
		return &directoryModeration{raised: map[string]bool{}}
	}).(*directoryModeration)
}

// One alarm's key: the erasure and the moderated writer.
func directoryModeratedKey(erasureId Id, writerId Id) string {
	return hex.EncodeToString(erasureId[:]) + "/" + hex.EncodeToString(writerId[:])
}

// §16.11's moderation row at a reader, after a sync: each entry a directory admin's moderation erased whose writer is
// this sidecar, or a sidecar whose member or sponsor is this device's member, raises moderation once an erasure and
// writer. It reads only entries, the sync's verified ones, and the ERASEs this process took (the revocations part's),
// since syncLock is held.
func (self *DirectoryClient) moderationAlarms(directoryId Id, entries []*RecordReadEntry) {
	auth := self.auth()
	ownMemberId, ownMember := auth.MemberOf(self.sidecarId)
	recordAuth := self.recordAuth()
	// the erasures a directory admin's erasure entry names, by entry
	byEntry := map[Id]*DirectoryErasure{}
	for _, entry := range entries {
		if entry.Header == nil || entry.Header.Kind() != RecordKindErasure || entry.Body == nil || entry.State != RecordEntryLive {
			continue
		}
		writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
		if !recordAuth.Admins(directoryId, writerId) {
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil || RecordErasureReason(body.GetReason()) != RecordErasureReasonModeration {
			continue
		}
		for _, named := range body.GetEntryIds() {
			if len(named) == len(Id{}) {
				byEntry[recordIdOf(named)] = &DirectoryErasure{EraserSidecarId: writerId, ErasureId: recordIdOf(body.GetErasureId()), Reason: RecordErasureReasonModeration}
			}
		}
	}
	part := self.revocations()
	func() {
		part.stateLock.Lock()
		defer part.stateLock.Unlock()
		for entryId, erasure := range part.entryErasures {
			if erasure.Reason == RecordErasureReasonModeration {
				if _, ok := byEntry[entryId]; !ok {
					copied := *erasure
					byEntry[entryId] = &copied
				}
			}
		}
	}()
	if len(byEntry) == 0 {
		return
	}
	moderation := self.moderation()
	moderation.stateLock.Lock()
	defer moderation.stateLock.Unlock()
	self.loadModeratedWithLock(moderation)
	raise := []*RecordAlarm{}
	for _, entry := range entries {
		if entry.Header == nil || entry.Header.Header == nil || !entry.State.KeyGone() {
			continue
		}
		erasure, ok := byEntry[entry.EntryId]
		if !ok {
			continue
		}
		writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
		if writerId == erasure.EraserSidecarId {
			continue
		}
		mine := writerId == self.sidecarId
		if !mine && ownMember {
			memberId, ok := DirectoryWhoMember(auth, writerId)
			mine = ok && memberId == ownMemberId
		}
		key := directoryModeratedKey(erasure.ErasureId, writerId)
		if !mine || moderation.raised[key] {
			continue
		}
		moderation.raised[key] = true
		alarmWriterId := writerId
		raise = append(raise, &RecordAlarm{Reason: SidecarRecordAlarmModeration, LogId: directoryId, SidecarId: &alarmWriterId})
	}
	if len(raise) == 0 {
		return
	}
	if err := self.keepModeratedWithLock(moderation); err != nil {
		self.log.Warningf("[directory]the moderation alarms raised were not kept: %s", err)
	}
	for _, alarm := range raise {
		if self.alarm != nil {
			self.alarm(alarm)
		}
	}
}

// Loads the kept moderation alarms once. The caller holds moderation.stateLock.
func (self *DirectoryClient) loadModeratedWithLock(moderation *directoryModeration) {
	if moderation.loaded {
		return
	}
	moderation.loaded = true
	content, err := self.store.readFile(directoryModeratedStoreName)
	if err != nil || content == nil {
		return
	}
	document := &directoryModeratedDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryModeratedStoreVersion {
		self.log.Warningf("[directory]the kept moderation alarms do not read")
		return
	}
	for _, key := range document.Raised {
		moderation.raised[key] = true
	}
}

// Keeps the moderation alarms raised. The caller holds moderation.stateLock.
func (self *DirectoryClient) keepModeratedWithLock(moderation *directoryModeration) error {
	document := &directoryModeratedDocument{Version: directoryModeratedStoreVersion, Raised: []string{}}
	for key := range moderation.raised {
		document.Raised = append(document.Raised, key)
	}
	slices.Sort(document.Raised)
	return self.store.writeDocument(directoryModeratedStoreName, document)
}
