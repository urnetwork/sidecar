//go:build !ios_extension

// §15.7's erasure of mail in format 1 (R-MAIL-5, D-MAIL-5, FS-13, FS-47; §11.12's closure, rekey and reconcile rows;
// MAIL-M7-16): an admin of a mailbox or a group repo destroys messages' keys, then re-keys every i/ segment that
// lists them, in parts that a refusal or a crash leaves resumable from what evs holds.
//
//	first    one ERASE takes each message's own keys, the slot of every retained version of its m/ path, and the slot
//	         of any deposit of it not yet consumed, so its body is gone at once and a deposit never brings it back
//	         (FS-13: ingest then consumes that deposit with no message). Its note names the messages by path
//	         (mail_erase_note.go). The m/ path is not removed: it stands as a version no key opens, so a reader that
//	         races the erasure still meets a conflict on it and writes nothing
//	parts    then one part per whole i/ segment listing any of them (mail_erase_closure.go): a CLOSURE writes the
//	         segment again without their rows under a fresh key, and its ERASE destroys the replaced chain's keys.
//	         The last part's ERASE completes the erasure; one with no row in any segment is complete at its first
//	wait     a part evs refuses 429, past the eraser's closure rate, its turn or its day's allowance, stops the
//	         erasure there with the time to try again (retry_after_ms) and §11.13's estimate of its end: the rows
//	         still listed stay openable to key holders until their part commits, and the bodies are gone already
//	resume   Resume finishes every erasure of the repo that no ERASE completed, whoever began it, from evs alone:
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
// A general repo's versions name no slot, since its keys ride its segments, so a group repo's mail is not shreddable
// by slot keys and its erasure refuses (ErrMailNotShreddable) until §15.7's group inbox gives group mail slots
// (QD-102): nothing here claims a group message erased.
//
// On every leg but the extension's. A MailEraser is safe for concurrent use: one erasure step runs at a time.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	// The store's; nil takes DefaultMailStoreSettings.
	Store *MailStoreSettings
}

// The one default.
func DefaultMailEraseSettings() *MailEraseSettings {
	return &MailEraseSettings{
		TrashRetention:              30 * 24 * time.Hour,
		SegmentRetryCount:           8,
		ClosureFloorByteCountPerDay: 3008 * 1024,
	}
}

// The repo's main ref and erasure ref as an eraser needs them. Implementations are safe for concurrent use.
type mailEraseStore interface {
	mailStore
	// Every retained version of path, newest first, each with the slots its records name and its push's time;
	// ErrEvsPathAbsent where the path never stood.
	Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error)
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
	// When evs takes the next part, from the 429's retry_after_ms. Zero unless waiting.
	NextTry time.Time
	// §11.13's bound on its end at the allowance's floor. Zero unless waiting.
	Finish time.Time
}

// The erasure as §5.4's erasure event carries it.
func (self *MailErasure) Event() *SidecarErasure {
	return &SidecarErasure{
		ErasureId: self.ErasureId, State: self.State, ObjectsLeft: int64(self.SegmentsLeft), BytesLeft: self.BytesLeft,
		NextTry: self.NextTry, Finish: self.Finish,
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
	// Called with each erasure's standing as a call leaves it, on the caller's goroutine: §5.4's erasure event.
	Progress func(erasure *SidecarErasure)
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
	deposits  mailIngestRepo
	erased    *mailErasedView
	authority MailEraseAuthority
	purge     MailLocalPurge
	progress  func(erasure *SidecarErasure)
	clock     Clock
	log       Logger
	settings  *MailEraseSettings

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
	return newMailEraser(args.Repo.RepoId(), store, &mailIngestEvsRepo{repo: args.Repo}, args), nil
}

// An eraser of repoId over store's files and deposits' refs.
func newMailEraser(repoId Id, store mailEraseStore, deposits mailIngestRepo, args *MailEraserArgs) *MailEraser {
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
		if !ok {
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
	versions, err := self.store.Versions(ctx, path)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keys := []*EvsErasedKey{}
	for _, version := range versions {
		if version.Removed {
			continue
		}
		if len(version.SlotIds) == 0 {
			return nil, ErrMailNotShreddable
		}
		for _, slotId := range version.SlotIds {
			if !slices.ContainsFunc(keys, func(key *EvsErasedKey) bool { return key.SlotId == slotId }) {
				keys = append(keys, &EvsErasedKey{SlotId: slotId, KeyIndex: mailVaultSlotKeyIndex})
			}
		}
	}
	return keys, nil
}

// The slot of each standing deposit whose id is one of messageIds, by message: a deposit not yet consumed, which the
// first ERASE takes. A deposit that does not open has no key left to take and is passed over.
func (self *MailEraser) depositKeys(ctx context.Context, messageIds []Id) (map[Id][]*EvsErasedKey, error) {
	keys := map[Id][]*EvsErasedKey{}
	if self.deposits == nil {
		return keys, nil
	}
	depositorIds, err := self.deposits.Depositors(ctx)
	if err != nil {
		return nil, err
	}
	for _, depositorId := range depositorIds {
		afterVersion := uint64(0)
		for {
			err := self.deposits.ReadDeposits(ctx, depositorId, afterVersion, func(deposit *EvsDeposit, body io.Reader) error {
				afterVersion = max(afterVersion, deposit.Version)
				messageId := Id(deposit.EntryId)
				if slices.Contains(messageIds, messageId) && deposit.SlotId != (Id{}) {
					keys[messageId] = append(keys[messageId], &EvsErasedKey{SlotId: deposit.SlotId, KeyIndex: mailVaultSlotKeyIndex})
				}
				return nil
			})
			var openError *EvsDepositOpenError
			if errors.As(err, &openError) && openError.Deposit != nil && afterVersion < openError.Deposit.Version && ctx.Err() == nil {
				afterVersion = openError.Deposit.Version
				continue
			}
			if err != nil {
				return nil, err
			}
			break
		}
	}
	return keys, nil
}

// Erases the messages of one month: see the file header. A message an ERASE named already is passed over, since
// Resume finishes its erasure; one with no version and no deposit refuses the call before anything is destroyed,
// as does one whose versions name no slot. The first ERASE destroys every message's body or none. The result says
// where the erasure stands: done, or waiting with the time to call Resume, and an error after the first ERASE
// leaves the erasure for Resume.
func (self *MailEraser) Erase(ctx context.Context, month MailYearMonth, messageIds []Id) (*MailErasure, error) {
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	if !self.allowed() {
		return nil, ErrMailNotEraser
	}
	if _, err := self.Refresh(ctx); err != nil {
		return nil, err
	}
	fresh := []Id{}
	for _, messageId := range messageIds {
		if _, erased := self.erased.erased(messageId); !erased && !slices.Contains(fresh, messageId) {
			fresh = append(fresh, messageId)
		}
	}
	erasure := &MailErasure{MessageIds: fresh, State: MailErasureDone}
	if len(fresh) == 0 {
		return erasure, nil
	}
	depositKeys, err := self.depositKeys(ctx, fresh)
	if err != nil {
		return nil, err
	}
	keys := []*EvsErasedKey{}
	messages := []mailErasedMessage{}
	for _, messageId := range fresh {
		messageKeys, err := self.pathKeys(ctx, MailMessagePath(month, messageId))
		if err != nil {
			return nil, err
		}
		messageKeys = append(messageKeys, depositKeys[messageId]...)
		if len(messageKeys) == 0 {
			return nil, ErrMailMessageAbsent
		}
		keys = append(keys, messageKeys...)
		messages = append(messages, mailErasedMessage{Month: month, MessageId: messageId})
	}
	segments, err := self.segmentsListing(ctx, messages)
	if err != nil {
		return nil, err
	}
	erasure.ErasureId = NewId()
	testHookBarrier("mail.erase.message.before", "")
	err = self.store.Erase(ctx, &EvsEraseArgs{
		ErasureId: erasure.ErasureId, Keys: keys, Complete: len(segments) == 0, Note: mailErasureNote(messages, nil),
	})
	testHookBarrier("mail.erase.message.after", "")
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		self.erased.note(message.Month, message.MessageId, erasure.ErasureId)
	}
	if err := self.purgeLocal(ctx, fresh); err != nil {
		// the bodies are gone from evs; this device's copies go at its next Refresh or restart
		self.log.Warningf("[mail]erase %s: the local purge failed: %v", self.repoId, err)
	}
	err = self.rewrite(ctx, erasure, messages)
	self.report(erasure)
	return erasure, err
}

// Finishes every erasure of the repo no ERASE completed: see the file header's resume row. Each erasure it took up is
// returned with where it stands; the first that waits or fails ends the call, since the next would meet the same
// allowance.
func (self *MailEraser) Resume(ctx context.Context) ([]*MailErasure, error) {
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	if !self.allowed() {
		return nil, ErrMailNotEraser
	}
	if _, err := self.Refresh(ctx); err != nil {
		return nil, err
	}
	erasures, err := self.store.Erasures(ctx, 0)
	if err != nil {
		return nil, err
	}
	type standing struct {
		complete bool
		messages []mailErasedMessage
		// the keys its ERASEs destroyed
		erasedSlotIds map[Id]bool
	}
	byId := map[Id]*standing{}
	order := []Id{}
	for _, erasure := range erasures {
		state := byId[erasure.ErasureId]
		if state == nil {
			state = &standing{erasedSlotIds: map[Id]bool{}}
			byId[erasure.ErasureId] = state
			order = append(order, erasure.ErasureId)
		}
		state.complete = state.complete || erasure.Complete
		for _, key := range erasure.Keys {
			state.erasedSlotIds[key.SlotId] = true
		}
		if messages, _, ok := parseMailErasureNote(erasure.Note); ok {
			state.messages = append(state.messages, messages...)
		}
	}
	closures, err := self.store.Closures(ctx)
	if err != nil {
		return nil, err
	}
	resumed := []*MailErasure{}
	for _, erasureId := range order {
		state := byId[erasureId]
		if state.complete || len(state.messages) == 0 {
			// done, or another writer's erasure, a vault entry's among them
			continue
		}
		erasure := &MailErasure{ErasureId: erasureId, State: MailErasureRewriting}
		for _, message := range state.messages {
			erasure.MessageIds = append(erasure.MessageIds, message.MessageId)
		}
		resumed = append(resumed, erasure)
		segments, err := self.segmentsListing(ctx, state.messages)
		if err != nil {
			return resumed, err
		}
		// a CLOSURE no ERASE followed: its replaced chain's keys still stand
		orphans := []*EvsClosure{}
		for _, closure := range closures {
			if closure.ErasureId == erasureId && slices.ContainsFunc(closure.Keys, func(key *EvsErasedKey) bool { return !state.erasedSlotIds[key.SlotId] }) {
				orphans = append(orphans, closure)
			}
		}
		for index, closure := range orphans {
			testHookBarrier("mail.erase.orphan.before", "")
			err := self.store.Erase(ctx, &EvsEraseArgs{
				ErasureId: erasureId, Keys: closure.Keys, Complete: len(segments) == 0 && index == len(orphans)-1,
			})
			testHookBarrier("mail.erase.orphan.after", "")
			if err != nil {
				self.report(erasure)
				return resumed, err
			}
		}
		err = self.rewrite(ctx, erasure, state.messages)
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
