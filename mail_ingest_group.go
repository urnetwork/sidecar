//go:build !ios_extension

// §15.7's group mail on a member's device (R-MAIL-5, D-MAIL-6; MAIL-M7-15): a group's mail is deposited once, into
// the group repo, where any of its readers ingests it (MailIngestor), and each member's device adds an
// r/<yyyymm>/<h>/<id> reference to its own mailbox, a MailGroupRef naming the group repo and the message, so storage
// counts once (§20) and a member's list reads the message in place.
//
//	add    Sync reads the group repo's i/ on from where it last read, a month and a segment at a time, and creates
//	       the reference of each row it has not referenced, several in one push, each only while absent; another of
//	       the member's devices creating one first is a conflict on that path, which counts as present
//	drop   a group message its repo's admins erased (§15.7: "members' devices then drop their r/ references") loses
//	       its reference: Sync reads the group repo's erasure ref and removes the reference of each message a
//	       committed ERASE names, and never adds one for it
//	month  a reference sits under the group message's month, which is its row's i/ directory; a row whose own time
//	       names another month is passed over, since no reader would find its message there
//
// What Sync read is kept in memory only: a restart reads the group's i/ again from its first month, and every
// reference it would add is found standing. A phone that keeps this position on disk reads less (QD-641, the review
// phase's).
//
// On every leg but the extension's. Safe for concurrent use: one Sync runs at a time.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A mailbox's or a group repo's main ref with the removal of a path. Implementations are safe for concurrent use.
type mailRemoveStore interface {
	mailStore
	// Removes path, held to the version it stands at: a *MailStoreConflictError where it stands at another,
	// ErrEvsPathAbsent where it stands no more.
	Remove(ctx context.Context, path string, ifVersion uint64) error
}

// What MailGroupRefs is tuned by (MAIL-M7-15).
type MailGroupRefSettings struct {
	// The references one push creates: 64 keeps a push's name-table delta small while a busy group's backlog takes
	// few pushes. Non-positive takes 1.
	BatchCount int
	// The most bytes read of a reference to learn its version before its removal. Non-positive takes 1.
	RefMaxByteCount int
	// How many times a batch goes again after a conflict on some of its paths, each time without them. Non-positive
	// tries once.
	WriteRetryCount int
}

// The one default.
func DefaultMailGroupRefSettings() *MailGroupRefSettings {
	return &MailGroupRefSettings{
		BatchCount:      64,
		RefMaxByteCount: 256,
		WriteRetryCount: 8,
	}
}

// What one Sync did.
type MailGroupRefSync struct {
	// References created, and those found standing.
	Added   int
	Present int
	// References of erased messages removed.
	Dropped int
}

// What NewMailGroupRefs builds on.
type MailGroupRefsArgs struct {
	// The group's general repo, which this device reads.
	Group *EvsRepo
	// The member's own mailbox, which this device writes.
	Mailbox *EvsRepo
	// Nil takes DefaultMailGroupRefSettings.
	Settings *MailGroupRefSettings
}

// How far Sync read one i/ segment.
type mailGroupRefPosition struct {
	month MailYearMonth
	n     uint64
}

// The bytes of an index segment whose references have been reconciled.
type mailGroupRefCheckpoint struct {
	byteCount int
	digest    [sha256.Size]byte
	complete  bool
}

// One member's references to one group repo's mail. See the file header.
type MailGroupRefs struct {
	groupRepoId Id
	group       mailStore
	mailbox     mailRemoveStore
	erasures    func(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
	settings    *MailGroupRefSettings

	// Held over a Sync, so one runs at a time.
	syncLock sync.Mutex
	// The last erasure whose references were all removed and the messages that cannot gain another reference.
	erasureVersion uint64
	erased         map[Id]bool
	settled        map[mailGroupRefPosition]mailGroupRefCheckpoint
}

// The references in args.Mailbox to args.Group's mail.
func NewMailGroupRefs(args *MailGroupRefsArgs) (*MailGroupRefs, error) {
	if args == nil || args.Group == nil || args.Mailbox == nil {
		return nil, fmt.Errorf("%w: no group repo or mailbox", ErrMailPathInvalid)
	}
	mailbox := &mailVaultEvsStore{mailEvsStore: newMailEvsStore(args.Mailbox, nil, nil)}
	return newMailGroupRefs(args.Group.RepoId(), newMailEvsStore(args.Group, nil, nil), mailbox, args.Group.ReadErasures, args.Settings), nil
}

// References in mailbox to the mail of the group repo groupRepoId, whose files group reads and whose ERASEs
// erasures reads.
func newMailGroupRefs(groupRepoId Id, group mailStore, mailbox mailRemoveStore, erasures func(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error), settings *MailGroupRefSettings) *MailGroupRefs {
	if settings == nil {
		settings = DefaultMailGroupRefSettings()
	}
	return &MailGroupRefs{
		groupRepoId: groupRepoId,
		group:       group,
		mailbox:     mailbox,
		erasures:    erasures,
		erased:      map[Id]bool{},
		settings:    settings,
		settled:     map[mailGroupRefPosition]mailGroupRefCheckpoint{},
	}
}

// One reference's bytes.
func (self *MailGroupRefs) refContent(messageId Id) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailGroupRef{RepoId: self.groupRepoId.Bytes(), MessageId: messageId.Bytes()})
}

// Drops the references of the group's erased messages, then adds one for each message its i/ lists that has none:
// see the file header. The first failure stops it, keeping what it did.
func (self *MailGroupRefs) Sync(ctx context.Context) (*MailGroupRefSync, error) {
	self.syncLock.Lock()
	defer self.syncLock.Unlock()
	result := &MailGroupRefSync{}
	fresh, err := self.erasures(ctx, self.erasureVersion)
	if err != nil {
		return result, err
	}
	for _, erasure := range fresh {
		if erasure.Version <= self.erasureVersion {
			continue
		}
		if erasure.Completion {
			self.erasureVersion = erasure.Version
			continue
		}
		messages, _, _ := parseMailErasureNote(erasure.Note)
		for _, message := range messages {
			self.erased[message.MessageId] = true
			dropped, err := self.drop(ctx, message)
			if err != nil {
				return result, err
			}
			if dropped {
				result.Dropped += 1
			}
		}
		self.erasureVersion = erasure.Version
	}

	monthNames, err := self.group.List(ctx, mailIndexFamily)
	if errors.Is(err, ErrEvsPathAbsent) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	months := []MailYearMonth{}
	for _, name := range monthNames {
		if month, ok := ParseMailYearMonth(name); ok {
			months = append(months, month)
		}
	}
	slices.Sort(months)
	for _, month := range months {
		numbers, err := mailListSegments(ctx, self.group, MailIndexDirectory(month))
		if err != nil {
			return result, err
		}
		for _, n := range numbers {
			if err := self.syncSegment(ctx, mailGroupRefPosition{month: month, n: n}, result); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

// One i/ segment of the group: a reference for each of its rows past those settled.
func (self *MailGroupRefs) syncSegment(ctx context.Context, position mailGroupRefPosition, result *MailGroupRefSync) error {
	segment, _, err := self.group.Read(ctx, MailIndexPath(position.month, position.n), mailIndexSegmentReadMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	offset := 0
	previous, ok := self.settled[position]
	if ok && previous.byteCount <= len(segment) && sha256.Sum256(segment[:previous.byteCount]) == previous.digest {
		if previous.byteCount == len(segment) {
			return nil
		}
		if previous.complete {
			offset = previous.byteCount
		}
	}
	// A CLOSURE can remove rows before another append brings the segment back to its old length or row count.
	// Only a matching prefix ending on a record boundary can be skipped.
	var messageIds []Id
	walkErr := mailSegmentRecords(segment[offset:], func(index int, record []byte) error {
		messageId, timeMillis, ok := mailIndexRecordKey(record)
		if ok && messageId != (Id{}) && !self.erased[messageId] && MailYearMonthOf(timeMillis) == position.month {
			messageIds = append(messageIds, messageId)
		}
		return nil
	})
	batch := []*mailStoreWrite{}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		added, present, err := self.create(ctx, batch)
		result.Added += added
		result.Present += present
		batch = batch[:0]
		return err
	}
	for _, messageId := range messageIds {
		content, err := self.refContent(messageId)
		if err != nil {
			return err
		}
		batch = append(batch, &mailStoreWrite{Path: MailGroupRefPath(position.month, messageId), Content: content})
		if max(self.settings.BatchCount, 1) <= len(batch) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	self.settled[position] = mailGroupRefCheckpoint{byteCount: len(segment), digest: sha256.Sum256(segment), complete: walkErr == nil}
	return nil
}

// Creates each reference of writes that is absent, in one push; a path a conflict names stands already and leaves
// the batch, which goes again without it.
func (self *MailGroupRefs) create(ctx context.Context, writes []*mailStoreWrite) (added int, present int, err error) {
	writes = slices.Clone(writes)
	for attempt := 0; 0 < len(writes); attempt += 1 {
		if err := ctx.Err(); err != nil {
			return 0, present, err
		}
		testHookBarrier("mail.group.ref.write.before", "")
		_, err := self.mailbox.Write(ctx, writes)
		testHookBarrier("mail.group.ref.write.after", "")
		if err == nil {
			return len(writes), present, nil
		}
		var conflict *MailStoreConflictError
		if !errors.As(err, &conflict) || len(conflict.Paths) == 0 || self.settings.WriteRetryCount <= attempt {
			return 0, present, err
		}
		before := len(writes)
		writes = slices.DeleteFunc(writes, func(write *mailStoreWrite) bool { return slices.Contains(conflict.Paths, write.Path) })
		present += before - len(writes)
	}
	return 0, present, nil
}

// Removes an erased group message's reference where it stands; false where none does.
func (self *MailGroupRefs) drop(ctx context.Context, message mailErasedMessage) (bool, error) {
	path := MailGroupRefPath(message.Month, message.MessageId)
	for attempt := 0; ; attempt += 1 {
		_, version, err := self.mailbox.Read(ctx, path, max(self.settings.RefMaxByteCount, 1))
		if errors.Is(err, ErrEvsPathAbsent) {
			return false, nil
		}
		if err != nil && !errors.Is(err, ErrMailStoreTooLarge) {
			return false, err
		}
		if version == 0 {
			// a file past the bound whose version the read did not give: not a reference this writes
			return false, nil
		}
		testHookBarrier("mail.group.ref.remove.before", "")
		err = self.mailbox.Remove(ctx, path, version)
		testHookBarrier("mail.group.ref.remove.after", "")
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, ErrEvsPathAbsent):
			return false, nil
		case mailStoreConflictOn(err, path) && attempt < self.settings.WriteRetryCount:
			// another device wrote it meanwhile: read its version again
		default:
			return false, err
		}
	}
}
