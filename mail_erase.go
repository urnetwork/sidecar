//go:build !ios_extension

// §15.7's erasure of mail (R-MAIL-5, D-MAIL-5, FS-13, FS-47; §11.12's closure, rekey and reconcile rows; MAIL-M7-16,
// and MAIL-M10-02 for a format-2 mailbox): an admin of a mailbox or a group repo destroys messages' keys, then re-keys
// every i/ segment that lists them, in parts that a refusal or a crash leaves resumable from what evs holds.
//
//	cut      in a format-2 mailbox, one where the network is in the format2 gate, the erasure's CUT on the mailbox's
//	         ref comes before everything below, and the search index's files holding the messages are rewritten
//	         before the i/ parts (mail_erase_index.go). A format-1 mailbox has neither
//	first    one ERASE takes each message's own keys, the slot of every retained version of its m/ path, and the slot
//	         of any deposit of it not yet consumed, so its body is gone at once and a deposit never brings it back
//	         (FS-13: ingest then consumes that deposit with no message). Its note names the messages by path
//	         (mail_erase_note.go). The m/ path is not removed: it stands as a version no key opens, so a reader that
//	         races the erasure still meets a conflict on it and writes nothing
//	parts    then one part per whole i/ segment listing any of them (mail_erase_closure.go): a CLOSURE writes the
//	         segment again without their rows under a fresh key, and its ERASE destroys the replaced chain's keys.
//	         The last part's ERASE completes the erasure; one with no row in any segment is complete at its first.
//	         One whose parts ran with no segment left to carry complete, as when another step took its rows, ends by
//	         a completion ERASE in a format-2 mailbox (QD-1132, QD-1137; evs_erase_completion.go) unless evs's state
//	         shows it complete, and stays rewriting where evs does not take it or, in format 1, which has no
//	         completion ERASE, until an ERASE of it says complete: never done on this device alone
//	wait     a part evs refuses 429, past the eraser's closure rate, its turn or its day's allowance, stops the
//	         erasure there with the time to try again (retry_after_ms) and §11.13's estimate of its end: the rows
//	         still listed stay openable to key holders until their part commits, and the bodies are gone already
//	resume   Resume checks even completed erasures for bodies that raced their deposit-only ERASE (mail_erase_late.go),
//	         then finishes the parts of each open erasure, whoever began it, from evs alone:
//	         the erasure ref's ERASEs say which messages each names, the main ref's CLOSUREs say which re-checkpoint
//	         no ERASE followed, whose keys the next ERASE destroys, and each segment still listing a message takes
//	         its part. Nothing is kept on the device, so a restart, a wiped phone or another admin's device resumes
//	         the same way. Each ERASE names only the keys it destroys; one whose keys are gone already counts done
//	         (evs's NOTHING_TO_ERASE)
//	readers  on a hint every reader calls Refresh, which reads the erasure ref on and hands each newly erased message
//	         to MailLocalPurge, the hook the IMAP store, the search index and any cache of decrypted copies join, so
//	         no decrypted copy or cached key outlives the ERASE on a device that is running. A group member's device
//	         also drops its r/ reference (MailGroupRefs.Sync)
//	who      only a sidecar the authority says administers the repo erases: a consented, not read-only device of a
//	         mailbox's owner, or a group repo's admin. With no authority every call refuses
//
// A general repo whose signed RepoCreate marks it as a group or admin inbox uses a deletable slot per message
// (§15.7, QD-102). A retained version whose key is in a segment header has no slot to destroy and returns
// ErrMailNotShreddable.
//
// On every leg but the extension's. A MailEraser is safe for concurrent use: one erasure step runs at a time.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"
)

var (
	// This sidecar does not administer the repo, or no authority says it does.
	ErrMailNotEraser = errors.New("mail repo not administered by this sidecar")
	// A message with no m/ version and no deposit: nothing to erase under that month and id.
	ErrMailMessageAbsent = errors.New("mail message absent")
	// A version whose records name no slot, a general repo's: its keys cannot be destroyed by an ERASE of slot keys,
	// so nothing is claimed erased.
	ErrMailNotShreddable = errors.New("mail not shreddable by slot keys")
)

// Where one erasure stands, as SidecarErasure names its states.
const (
	MailErasureDone      = "done"
	MailErasureRewriting = "rewriting"
	MailErasureWaiting   = "waiting"
)

// What local state holds of erased mail. Implementations are safe for concurrent use.
type MailLocalPurge interface {
	// Deletes every decrypted copy and cached key of the messages on this device: the IMAP store's files, the search
	// index's rows, a list's cache. Called again for the same message after a restart, so it is idempotent.
	PurgeMail(ctx context.Context, repoId Id, messageIds []Id) error
}

// What erasure asks of §8's verified state. Implementations are safe for concurrent use.
type MailEraseAuthority interface {
	// Whether sidecarId administers repoId now (§8.8): it may erase there.
	Erases(repoId Id, sidecarId Id) bool
}

// MailEraseAuthority over the installed AclEngine: evs's admin right on the repo.
type MailEraseAclAuthority struct {
	Engine *AclEngine
	// Nil is real time.
	Clock Clock
}

// The admin right at the installed state.
func (self *MailEraseAclAuthority) Erases(repoId Id, sidecarId Id) bool {
	if self == nil || self.Engine == nil {
		return false
	}
	state := self.Engine.State()
	if state == nil {
		return false
	}
	access := state.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, clockOrReal(self.Clock).Now())
	return access.Rights.Has(AclEvsAdmin)
}

// What MailEraser is tuned by (MAIL-M7-16).
type MailEraseSettings struct {
	// How long a message stays in trash before ShredTrash erases it (§15.7: 30 days).
	TrashRetention time.Duration
	// How many times one segment's part goes again after another writer's append moved the segment under it.
	// Non-positive tries once.
	SegmentRetryCount int
	// The closure bytes a day the estimate counts on while an erasure waits: §20.4's evs_closure_bytes_floor, 3
	// full segments, which no tightening goes under, so the estimate is §11.13's bound. Non-positive gives none.
	ClosureFloorByteCountPerDay int64
	// A format-2 mailbox's (mail_erase_index.go). The most bytes of one m/ file the eraser reads to count its chunk
	// documents: a message at pro.yml's highest mail_inbound_message_bytes with ingest's headers. A file past it is
	// listed to the bound this size gives. Non-positive reads none.
	MessageMaxByteCount int
	// The most a message's extracted text outgrows its bytes by, which bounds its chunk documents where they are not
	// counted: 4, past a single-byte charset's 3 UTF-8 bytes a byte. Non-positive takes 1.
	TextGrowthFactor int
	// The most documents one erasure's CUT lists: 256, about 6 KiB of the erasure set's 16,208 B, so pending erasures
	// share the set. An erasure of more refuses with ErrMailEraseBatchTooLarge before anything is destroyed.
	CutDocumentMaxCount int
	// The messages one trash shred's erasure takes in a format-2 mailbox, each batch one CUT: 64. Non-positive takes 1.
	ShredBatchMessageCount int
	// Between tries of a CUT a full erasure set made wait: 10 min, a reading, as the index's re-entry retry.
	CutRetryInterval time.Duration
	// The most bytes of one journaled erasure's file. Non-positive journals none.
	JournalMaxByteCount int64
	// The index's eraser's and extractor 1's; nil takes DefaultIndexEraseSettings and DefaultIndexFormatSettings.
	Index       *IndexEraseSettings
	IndexFormat *IndexFormatSettings
	// The store's; nil takes DefaultMailStoreSettings.
	Store *MailStoreSettings
}

// The one default.
func DefaultMailEraseSettings() *MailEraseSettings {
	return &MailEraseSettings{
		TrashRetention:              30 * 24 * time.Hour,
		SegmentRetryCount:           8,
		ClosureFloorByteCountPerDay: 3008 * 1024,
		MessageMaxByteCount:         int(DefaultMailIngestSettings().DepositMaxByteCount),
		TextGrowthFactor:            4,
		CutDocumentMaxCount:         256,
		ShredBatchMessageCount:      64,
		CutRetryInterval:            10 * time.Minute,
		JournalMaxByteCount:         64 * 1024,
	}
}

// The repo's main ref and erasure ref as an eraser needs them. Implementations are safe for concurrent use.
type mailEraseStore interface {
	mailStore
	// Every retained version of path, newest first, each with the slots its records name and its push's time;
	// ErrEvsPathAbsent where the path never stood.
	Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error)
	// The newest flag push, used to date trash even when older flag history is unavailable.
	NewestPushTime(ctx context.Context, path string) (time.Time, error)
	// One ERASE (evs_erase.go); one naming only keys gone already counts done.
	Erase(ctx context.Context, args *EvsEraseArgs) error
	// The committed ERASEs after afterVersion of the repo's erasure ref, oldest first, each with its note.
	Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
	// One CLOSURE of the erasure (evs_closure.go): path written again as content, a whole checkpoint under a fresh
	// key, held to the version it stands at, its payload listing the replaced chain's keys. A
	// *MailStoreConflictError where the path stands at another version.
	Closure(ctx context.Context, erasureId Id, path string, content []byte, ifVersion uint64, erased []*EvsErasedKey) error
	// The committed CLOSUREs of the main ref, oldest first, each with its erasure's id and the keys it lists.
	Closures(ctx context.Context) ([]*EvsClosure, error)
}

// What one call left of one erasure.
type MailErasure struct {
	ErasureId Id
	// The messages its ERASEs name.
	MessageIds []Id
	// MailErasureDone, MailErasureRewriting where a failure stopped it short, or MailErasureWaiting on a 429.
	State string
	// The i/ segments still listing a message of it, and their bytes: §11.13's wait row.
	SegmentsLeft int
	BytesLeft    int64
	// A format-2 mailbox's: whether the erasure's CUT stands, so its documents are masked and unpublishable; the
	// search index's rekey objects still to rewrite and their closure bytes, as the index's eraser counts them while
	// it waits; and whether its rewrite left a file unproven, so no ERASE said complete and the erasure stays
	// rewriting (mail_erase_index.go).
	Fenced           bool
	IndexObjectsLeft int64
	IndexBytesLeft   int64
	Unproven         bool
	// When evs takes the next part, from the 429's retry_after_ms. Zero unless waiting.
	NextTry time.Time
	// §11.13's bound on its end at the allowance's floor. Zero unless waiting.
	Finish time.Time
}

// The erasure as §5.4's erasure event carries it.
func (self *MailErasure) Event() *SidecarErasure {
	return &SidecarErasure{
		ErasureId: self.ErasureId, State: self.State, ObjectsLeft: int64(self.SegmentsLeft) + self.IndexObjectsLeft,
		BytesLeft: self.BytesLeft + self.IndexBytesLeft, NextTry: self.NextTry, Finish: self.Finish,
	}
}

// What NewMailEraser builds on.
type MailEraserArgs struct {
	// The mailbox or the group repo.
	Repo *EvsRepo
	// This sidecar.
	SidecarId Id
	// Nil refuses every erasure.
	Authority MailEraseAuthority
	// Nil purges nothing: a device with no decrypted copies.
	Purge MailLocalPurge
	// Called with each erasure's standing as a call leaves it, on the caller's goroutine: §5.4's erasure event. In a
	// format-2 mailbox the index's eraser raises its own steps through it too, fenced among them.
	Progress func(erasure *SidecarErasure)
	// Where a format-2 mailbox's eraser journals an erasure between its CUT and its first ERASE: a directory of the
	// mail component's sealed store. Nil journals none, and a device killed there leaves a CUT no device finishes.
	Journal SidecarStore
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailEraseSettings.
	Settings *MailEraseSettings
}

// One mail repo's eraser on this device. See the file header.
type MailEraser struct {
	repoId    Id
	sidecarId Id
	store     mailEraseStore
	// The repo's deposit refs, for a deposit's slot; nil where the repo takes none.
	deposits  mailEraseDeposits
	erased    *mailErasedView
	authority MailEraseAuthority
	purge     MailLocalPurge
	progress  func(erasure *SidecarErasure)
	clock     Clock
	log       Logger
	settings  *MailEraseSettings
	// A format-2 mailbox's index side (mail_erase_index.go): opened at its first use and kept, nil from indexOpen in
	// a format-1 mailbox, and a nil indexOpen where the eraser was built over no EvsRepo. Under eraseLock.
	indexOpen func(ctx context.Context) (*mailEraseIndex, error)
	index     *mailEraseIndex
	journal   *mailEraseJournal

	// Held over an erasure step, so one runs at a time.
	eraseLock sync.Mutex
}

// The eraser of args.Repo.
func NewMailEraser(args *MailEraserArgs) (*MailEraser, error) {
	if args == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: no repo", ErrMailNotEraser)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailEraseSettings()
	}
	store := &mailEraseEvsStore{mailVaultEvsStore: &mailVaultEvsStore{mailEvsStore: newMailEvsStore(args.Repo, nil, settings.Store)}}
	eraser := newMailEraser(args.Repo.RepoId(), store, &mailIngestEvsRepo{repo: args.Repo}, args)
	repo := args.Repo
	eraser.indexOpen = func(ctx context.Context) (*mailEraseIndex, error) {
		if !repo.client.Format2Admitted() {
			// a format-1 mailbox: no CUT, and no index to rewrite
			return nil, nil
		}
		return mailNewEraseIndex(ctx, repo, args, settings)
	}
	return eraser, nil
}

// An eraser of repoId over store's files and deposits' refs.
func newMailEraser(repoId Id, store mailEraseStore, deposits mailEraseDeposits, args *MailEraserArgs) *MailEraser {
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailEraseSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailEraser{
		repoId:    repoId,
		sidecarId: args.SidecarId,
		store:     store,
		deposits:  deposits,
		erased:    newMailErasedView(),
		authority: args.Authority,
		purge:     args.Purge,
		progress:  args.Progress,
		clock:     clockOrReal(args.Clock),
		log:       log,
		settings:  settings,
		journal:   &mailEraseJournal{store: args.Journal, maxByteCount: settings.JournalMaxByteCount},
	}
}

// Reads the erasure ref on and purges this device's copies of each message a newly read ERASE names: what every
// reader does on a hint (the file header's readers row). The purge runs before Refresh returns; one that fails is
// returned, and the next Refresh of a restarted device purges again from the ref's start.
func (self *MailEraser) Refresh(ctx context.Context) ([]Id, error) {
	fresh, err := self.erased.refresh(ctx, self.store.Erasures)
	if err != nil {
		return nil, err
	}
	messageIds := []Id{}
	for _, erasure := range fresh {
		messages, _, ok := parseMailErasureNote(erasure.Note)
		if !ok || erasure.Completion {
			continue
		}
		for _, message := range messages {
			if !slices.Contains(messageIds, message.MessageId) {
				messageIds = append(messageIds, message.MessageId)
			}
		}
	}
	return messageIds, self.purgeLocal(ctx, messageIds)
}

// The local purge of messageIds, where a hook stands.
func (self *MailEraser) purgeLocal(ctx context.Context, messageIds []Id) error {
	if self.purge == nil || len(messageIds) == 0 {
		return nil
	}
	return self.purge.PurgeMail(ctx, self.repoId, messageIds)
}

// Whether this sidecar may erase here.
func (self *MailEraser) allowed() bool {
	return self.authority != nil && self.authority.Erases(self.repoId, self.sidecarId)
}

// The slot keys of every retained version of path: what an ERASE names to destroy it. None where the path never
// stood; ErrMailNotShreddable where a version names no slot.
func (self *MailEraser) pathKeys(ctx context.Context, path string) ([]*EvsErasedKey, error) {
	keys, _, err := self.pathKeysAt(ctx, path)
	return keys, err
}

// pathKeys, with the path's newest standing version, 0 where none stands.
func (self *MailEraser) pathKeysAt(ctx context.Context, path string) ([]*EvsErasedKey, uint64, error) {
	versions, err := self.store.Versions(ctx, path)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	keys := []*EvsErasedKey{}
	newest := uint64(0)
	for _, version := range versions {
		if version.Removed {
			continue
		}
		newest = max(newest, version.Version)
		if len(version.SlotIds) == 0 {
			return nil, 0, ErrMailNotShreddable
		}
		for _, slotId := range version.SlotIds {
			if !slices.ContainsFunc(keys, func(key *EvsErasedKey) bool { return key.SlotId == slotId }) {
				keys = append(keys, &EvsErasedKey{SlotId: slotId, KeyIndex: mailVaultSlotKeyIndex})
			}
		}
	}
	return keys, newest, nil
}

// The slots of all standing deposits of the requested messages and an upper bound on each deposit's size.
// Every ref must answer before the first CUT or ERASE can commit.
func (self *MailEraser) depositKeys(ctx context.Context, messageIds []Id) (map[Id][]*EvsErasedKey, map[Id]uint64, error) {
	keys := map[Id][]*EvsErasedKey{}
	byteCounts := map[Id]uint64{}
	if self.deposits == nil {
		return keys, byteCounts, nil
	}
	depositorIds, err := self.deposits.Depositors(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, depositorId := range depositorIds {
		slots, err := self.deposits.depositSlots(ctx, depositorId, messageIds)
		if err != nil {
			return nil, nil, err
		}
		for _, slot := range slots {
			keys[slot.messageId] = append(keys[slot.messageId], &EvsErasedKey{SlotId: slot.slotId, KeyIndex: mailVaultSlotKeyIndex})
			byteCounts[slot.messageId] = max(byteCounts[slot.messageId], slot.paddedSize)
		}
	}
	return keys, byteCounts, nil
}

// Erases the messages of one month: see the file header. A message an ERASE named already is passed over, since
// Resume finishes its erasure; one with no version and no deposit refuses the call before anything is destroyed,
// as does one whose versions name no slot. The first ERASE destroys every message's body or none. The result says
// where the erasure stands: done, or waiting with the time to call Resume, and an error after the first ERASE
// leaves the erasure for Resume. In a format-2 mailbox the erasure's CUT comes first, an erasure this device journaled
// and did not begin runs before this one, and an error once the CUT is sent leaves the erasure journaled for Resume.
func (self *MailEraser) Erase(ctx context.Context, month MailYearMonth, messageIds []Id) (*MailErasure, error) {
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	if !self.allowed() {
		return nil, ErrMailNotEraser
	}
	if _, err := self.Refresh(ctx); err != nil {
		return nil, err
	}
	index, err := self.indexOf(ctx)
	if err != nil {
		return nil, err
	}
	if index != nil {
		// an erasure a kill left between its CUT and its first ERASE takes its messages under its own id
		if _, err := self.resumeJournaled(ctx, index); err != nil {
			return nil, err
		}
	}
	fresh := []Id{}
	for _, messageId := range messageIds {
		if _, erased := self.erased.erased(messageId); !erased && !slices.Contains(fresh, messageId) {
			fresh = append(fresh, messageId)
		}
	}
	if len(fresh) == 0 {
		return &MailErasure{MessageIds: fresh, State: MailErasureDone}, nil
	}
	return self.begin(ctx, NewId(), month, fresh, index)
}

// Begins the erasure of fresh, none of which an ERASE named, under erasureId: its CUT in a format-2 mailbox, its
// first ERASE, then its parts. Nil with an error where nothing was destroyed.
func (self *MailEraser) begin(ctx context.Context, erasureId Id, month MailYearMonth, fresh []Id, index *mailEraseIndex) (*MailErasure, error) {
	// CONSUME can destroy the inventoried deposit slot after ingest published the body.
	// A no-op ERASE made no durable promise. Re-inventory under the same erasure id.
	for attempt := 0; ; attempt++ {
		erasure, err := self.beginAttempt(ctx, erasureId, month, fresh, index)
		if !errors.Is(err, errMailEraseUncommitted) || attempt >= self.settings.SegmentRetryCount {
			return erasure, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

// One inventory and first ERASE under the original erasure id.
func (self *MailEraser) beginAttempt(ctx context.Context, erasureId Id, month MailYearMonth, fresh []Id, index *mailEraseIndex) (*MailErasure, error) {
	erasure := &MailErasure{MessageIds: fresh, State: MailErasureDone}
	depositKeys, depositByteCounts, err := self.depositKeys(ctx, fresh)
	if err != nil {
		return nil, err
	}
	keys := []*EvsErasedKey{}
	messages := []mailErasedMessage{}
	// whether any message's m/ file stands: only such a message can be in the search index
	standing := false
	documentCount := uint64(0)
	for _, messageId := range fresh {
		path := MailMessagePath(month, messageId)
		messageKeys, version, err := self.pathKeysAt(ctx, path)
		if err != nil {
			return nil, err
		}
		standing = standing || 0 < version
		messageKeys = append(messageKeys, depositKeys[messageId]...)
		if len(messageKeys) == 0 {
			return nil, ErrMailMessageAbsent
		}
		message := mailErasedMessage{Month: month, MessageId: messageId}
		if index != nil {
			message.Version, message.ChunkCount, err = self.documentOf(ctx, index, path, version, depositByteCounts[messageId])
			if err != nil {
				return nil, err
			}
			documentCount += uint64(message.ChunkCount)
		}
		keys = append(keys, messageKeys...)
		messages = append(messages, message)
	}
	if index != nil && uint64(max(self.settings.CutDocumentMaxCount, 0)) < documentCount {
		return nil, ErrMailEraseBatchTooLarge
	}
	segments, err := self.segmentsListing(ctx, messages)
	if err != nil {
		return nil, err
	}
	erasure.ErasureId = erasureId
	if index != nil {
		if err := self.journal.begin(erasureId, month, fresh); err != nil {
			return nil, err
		}
		erasure.Fenced, err = self.cut(ctx, index, erasureId, messages)
		if err != nil {
			if mailEraseCutRefused(err) {
				// evs committed nothing of it: the erasure never began
				if doneErr := self.journal.done(erasureId); doneErr != nil {
					self.log.Warningf("[mail]erase %s: a refused erasure stays journaled: %v", self.repoId, doneErr)
				}
			}
			return nil, err
		}
	}
	// with no i/ row to re-key, this ERASE ends a format-1 erasure, and a format-2 one of messages no m/ file stands
	// for, which the index never held; any other format-2 erasure ends with its index files' rewrite
	complete := len(segments) == 0 && (index == nil || !standing)
	testHookBarrier("mail.erase.message.before", "")
	note := mailErasureNote(messages, nil)
	err = self.store.Erase(ctx, &EvsEraseArgs{
		ErasureId: erasure.ErasureId, Keys: keys, Complete: complete, Note: note,
	})
	testHookBarrier("mail.erase.message.after", "")
	if err != nil {
		return nil, err
	}
	erasures, err := self.store.Erasures(ctx, 0)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(erasures, func(row *EvsErasure) bool {
		return !row.Completion && row.ErasureId == erasureId && bytes.Equal(row.Note, note)
	}) {
		return nil, errMailEraseUncommitted
	}
	if index != nil {
		if err := self.journal.done(erasureId); err != nil {
			// the next step finds its ERASE in evs's state and drops the entry
			self.log.Warningf("[mail]erase %s: a begun erasure stays journaled: %v", self.repoId, err)
		}
	}
	for _, message := range messages {
		self.erased.note(message.Month, message.MessageId, erasure.ErasureId)
	}
	if err := self.purgeLocal(ctx, fresh); err != nil {
		// the bodies are gone from evs; this device's copies go at its next Refresh or restart
		self.log.Warningf("[mail]erase %s: the local purge failed: %v", self.repoId, err)
	}
	messages, complete, _, err = self.eraseLateBodies(ctx, erasureId, messages, mailErasedKeys(erasures), index, complete)
	if err != nil {
		erasure.State = MailErasureRewriting
		return erasure, err
	}
	if complete {
		self.report(erasure)
		return erasure, nil
	}
	err = self.parts(ctx, erasure, messages, index, IndexResumeEraser, nil)
	self.report(erasure)
	return erasure, err
}

// An erasure's parts after its first ERASE: in a format-2 mailbox the search index's files first
// (mail_erase_index.go), then an ERASE for each orphaned CLOSURE a resume found, then the i/ segments' parts, the
// last ERASE of them completing the erasure where the index's rewrite left nothing unproven. With no i/ segment left
// to carry complete, the index's rewrite ends the erasure, by its last ERASE or a completion ERASE, or the last
// orphan's ERASE does; one evs's state still shows incomplete then takes a completion ERASE here (QD-1132), so no
// erasure reads done on this device alone. Fills erasure with where it stands.
func (self *MailEraser) parts(ctx context.Context, erasure *MailErasure, messages []mailErasedMessage, index *mailEraseIndex, role IndexResumeRole, erasedKeys map[EvsErasedKey]bool) error {
	segments, err := self.segmentsListing(ctx, messages)
	if err != nil {
		erasure.State = MailErasureRewriting
		return err
	}
	// A competing CLOSURE can make a row disappear. Read the main ref after the segments so that a CLOSURE
	// responsible for an already absent row is visible before deciding which ERASE can complete the operation.
	closures, err := self.store.Closures(ctx)
	if err != nil {
		erasure.State = MailErasureRewriting
		return err
	}
	var orphans []*EvsClosure
	for _, closure := range closures {
		if closure.ErasureId == erasure.ErasureId && slices.ContainsFunc(closure.Keys, func(key *EvsErasedKey) bool { return !erasedKeys[*key] }) {
			orphans = append(orphans, closure)
		}
	}
	mayComplete := true
	// whether the index's rewrite was asked to end the erasure, a completion ERASE included
	indexEnds := false
	if index != nil && mailErasureDocumented(messages) {
		indexEnds = len(segments) == 0 && len(orphans) == 0
		ended, err := self.indexParts(ctx, index, erasure, messages, segments, role, indexEnds)
		if err != nil || ended {
			return err
		}
		mayComplete = !erasure.Unproven
	}
	// a CLOSURE no ERASE followed: its replaced chain's keys still stand
	for index, closure := range orphans {
		testHookBarrier("mail.erase.orphan.before", "")
		err := self.store.Erase(ctx, &EvsEraseArgs{
			ErasureId: erasure.ErasureId, Keys: closure.Keys, Complete: mayComplete && len(segments) == 0 && index == len(orphans)-1,
		})
		testHookBarrier("mail.erase.orphan.after", "")
		if err != nil {
			erasure.State = MailErasureRewriting
			return err
		}
	}
	if err := self.rewrite(ctx, erasure, segments, messages, mayComplete); err != nil || erasure.State != MailErasureDone {
		return err
	}
	// Even the last segment's ERASE may have found its keys already gone and committed nothing.
	return self.complete(ctx, erasure, index != nil && !indexEnds)
}

// Ends an erasure whose every part ran with no i/ segment left to carry complete (QD-1132): done where an ERASE of it
// in evs's state says complete; else, where send says a format-2 mailbox's completion was not tried yet, by a
// completion ERASE (QD-1137) naming a key an earlier ERASE of it destroyed (evs_erase_completion.go), evs's state read
// back after it, its note naming nothing, since it destroys nothing. One that still reads incomplete stays rewriting,
// as when evs does not take the completion, and a refusal of the eraser's allowance waits.
func (self *MailEraser) complete(ctx context.Context, erasure *MailErasure, send bool) error {
	erasures, err := self.store.Erasures(ctx, 0)
	if err != nil {
		erasure.State = MailErasureRewriting
		return err
	}
	if mailErasureComplete(erasures, erasure.ErasureId) {
		erasure.State = MailErasureDone
		return nil
	}
	erasure.State = MailErasureRewriting
	if !send {
		return nil
	}
	key, ok := evsCompletionKeyOf(erasures, erasure.ErasureId, func(committed *EvsErasure) (Id, []*EvsErasedKey) {
		return committed.ErasureId, committed.Keys
	})
	if !ok {
		return nil
	}
	testHookBarrier("mail.erase.completion.before", "")
	err = self.store.Erase(ctx, &EvsEraseArgs{
		ErasureId: erasure.ErasureId, Keys: []*EvsErasedKey{key}, Complete: true, Note: mailErasureNote(nil, nil), Completion: true,
	})
	testHookBarrier("mail.erase.completion.after", "")
	if wait, refused := mailEraseRefusedForNow(err); refused {
		erasure.State = MailErasureWaiting
		erasure.NextTry = self.clock.Now().Add(wait)
		return nil
	}
	if err != nil {
		return err
	}
	if erasures, err = self.store.Erasures(ctx, 0); err != nil {
		return err
	}
	if mailErasureComplete(erasures, erasure.ErasureId) {
		erasure.State = MailErasureDone
	}
	return nil
}

// Whether an ERASE of erasureId among erasures says complete, as Resume reads an erasure done.
func mailErasureComplete(erasures []*EvsErasure, erasureId Id) bool {
	for _, erasure := range slices.Backward(erasures) {
		if id, complete, applies := erasure.completionState(); id == erasureId && applies {
			return complete
		}
	}
	return false
}

// Finishes every erasure of the repo no ERASE completed: see the file header's resume row. Each erasure it took up is
// returned with where it stands; the first that waits or fails ends the call, since the next would meet the same
// allowance. In a format-2 mailbox an erasure this device journaled and did not begin runs first, and an erasure
// another device began is taken up by the index's role rule (mail_erase_index.go), one not yet this device's left
// rewriting with the time it becomes so.
func (self *MailEraser) Resume(ctx context.Context) ([]*MailErasure, error) {
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	if !self.allowed() {
		return nil, ErrMailNotEraser
	}
	if _, err := self.Refresh(ctx); err != nil {
		return nil, err
	}
	index, err := self.indexOf(ctx)
	if err != nil {
		return nil, err
	}
	resumed := []*MailErasure{}
	if index != nil {
		journaled, err := self.resumeJournaled(ctx, index)
		resumed = append(resumed, journaled...)
		if err != nil || slices.ContainsFunc(journaled, func(erasure *MailErasure) bool { return erasure.State != MailErasureDone }) {
			return resumed, err
		}
	}
	erasures, err := self.store.Erasures(ctx, 0)
	if err != nil {
		return resumed, err
	}
	type standing struct {
		complete bool
		late     bool
		messages []mailErasedMessage
		// the keys its ERASEs destroyed
		erasedKeys map[EvsErasedKey]bool
		// the device whose ERASE began it
		eraserId Id
	}
	byId := map[Id]*standing{}
	order := []Id{}
	for _, erasure := range erasures {
		_, complete, applies := erasure.completionState()
		if !applies {
			continue
		}
		state := byId[erasure.ErasureId]
		if state == nil {
			state = &standing{erasedKeys: map[EvsErasedKey]bool{}, eraserId: erasure.EraserSidecarId}
			byId[erasure.ErasureId] = state
			order = append(order, erasure.ErasureId)
		}
		state.complete = complete
		if erasure.Completion {
			continue
		}
		for _, key := range erasure.Keys {
			state.erasedKeys[*key] = true
		}
		if messages, _, ok := parseMailErasureNote(erasure.Note); ok {
			state.messages = mailMergeErasedMessages(state.messages, messages)
		}
	}
	erasedKeys := mailErasedKeys(erasures)
	began := slices.Clone(resumed)
	// A waiting index or segment rewrite does not hold back the destruction of
	// another erasure's late body. Check the bodies before spending closure quota.
	for _, erasureId := range order {
		state := byId[erasureId]
		if len(state.messages) == 0 || slices.ContainsFunc(began, func(erasure *MailErasure) bool { return erasure.ErasureId == erasureId }) {
			continue
		}
		state.messages, state.complete, state.late, err = self.eraseLateBodies(ctx, erasureId, state.messages, erasedKeys, index, state.complete)
		if err != nil {
			return resumed, err
		}
	}
	for _, erasureId := range order {
		state := byId[erasureId]
		if len(state.messages) == 0 || (state.complete && !state.late) ||
			slices.ContainsFunc(began, func(erasure *MailErasure) bool { return erasure.ErasureId == erasureId }) {
			continue
		}
		erasure := &MailErasure{ErasureId: erasureId, State: MailErasureRewriting}
		for _, message := range state.messages {
			erasure.MessageIds = append(erasure.MessageIds, message.MessageId)
		}
		resumed = append(resumed, erasure)
		if state.complete {
			erasure.State = MailErasureDone
			self.report(erasure)
			continue
		}
		err = self.parts(ctx, erasure, state.messages, index, self.resumeRole(state.eraserId), state.erasedKeys)
		self.report(erasure)
		if err != nil || erasure.State != MailErasureDone {
			return resumed, err
		}
	}
	return resumed, nil
}

// The erasure's standing to the caller's sink.
func (self *MailEraser) report(erasure *MailErasure) {
	if self.progress != nil && erasure.ErasureId != (Id{}) {
		self.progress(erasure.Event())
	}
}

// Whether err is evs's 429, and the wait it names.
func mailEraseRefusedForNow(err error) (time.Duration, bool) {
	evsError, ok := EvsErrorOf(err)
	if !ok || evsError.Status != http.StatusTooManyRequests {
		return 0, false
	}
	return max(evsError.RetryAfter, 0), true
}

// §11.13's bound on a waiting erasure's end at the allowance's floor: the ⌈bytesLeft / floor⌉-th 00:00 UTC after the
// time it may try again. Zero where the floor gives no estimate.
func mailEraseFinish(nextTry time.Time, bytesLeft int64, floorByteCountPerDay int64) time.Time {
	if floorByteCountPerDay <= 0 || bytesLeft <= 0 {
		return time.Time{}
	}
	days := (bytesLeft + floorByteCountPerDay - 1) / floorByteCountPerDay
	midnight := nextTry.UTC().Truncate(24 * time.Hour)
	return midnight.Add(time.Duration(days) * 24 * time.Hour)
}
