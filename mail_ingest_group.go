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

// One member's references to one group repo's mail. See the file header.
type MailGroupRefs struct {
	groupRepoId Id
	group       mailStore
	mailbox     mailRemoveStore
	erasures    func(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
	erased      *mailErasedView
	settings    *MailGroupRefSettings

	// Held over a Sync, so one runs at a time.
	syncLock sync.Mutex
	// The records of each segment whose references are settled.
	settledCounts map[mailGroupRefPosition]int
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
		groupRepoId:   groupRepoId,
		group:         group,
		mailbox:       mailbox,
		erasures:      erasures,
		erased:        newMailErasedView(),
		settings:      settings,
		settledCounts: map[mailGroupRefPosition]int{},
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
	fresh, err := self.erased.refresh(ctx, self.erasures)
	if err != nil {
		return result, err
	}
	for _, erasure := range fresh {
		messages, _, ok := parseMailErasureNote(erasure.Note)
		if !ok {
			continue
		}
		for _, message := range messages {
			dropped, err := self.drop(ctx, message)
			if err != nil {
				return result, err
			}
			if dropped {
				result.Dropped += 1
			}
		}
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
	messageIds := []Id{}
	count := 0
	err = mailSegmentRecords(segment, func(index int, record []byte) error {
		count += 1
		messageId, timeMillis, ok := mailIndexRecordKey(record)
		if ok && MailYearMonthOf(timeMillis) == position.month {
			messageIds = append(messageIds, messageId)
		} else {
			// a row with no key, or under another month than its own: no reference, and its place still counts
			messageIds = append(messageIds, Id{})
		}
		return nil
	})
	if err != nil {
		// a segment that does not parse is read no further; its rows before the break still take references
		count = len(messageIds)
	}
	settled := self.settledCounts[position]
	if count < settled {
		// a re-checkpoint wrote the segment again without its erased rows (§15.7): read it whole
		settled = 0
	}
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
	for index := settled; index < count; index += 1 {
		messageId := messageIds[index]
		if messageId == (Id{}) {
			continue
		}
		if _, erased := self.erased.erased(messageId); erased {
			continue
		}
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
	self.settledCounts[position] = count
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
