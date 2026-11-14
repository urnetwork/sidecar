//go:build !ios_extension

// §15.7's trash shred (D-MAIL-5; MAIL-M7-16): an admin's device erases each message that has stood in trash for
// TrashRetention, 30 days, by the erasure of mail_erase.go, which preservation holds never block (owner decision
// 133).
//
// A trash is dated by its winning op's wall time (MAIL-FORMAT.md), which is the trashing device's own clock, so a
// device whose clock runs slow would date a trash in the past and have it shredded early, and a shred cannot be
// taken back. The guard taken here (plan-MAIL-format-readings item 9): a trash is never dated before the newest push
// of any f/ segment of its month, a time evs holds within its own bound of its clock (§11.6) and after which no op
// of that month was written. That can only make a shred later: by as long as the month's flags kept changing after
// the trash, and not at all once they rest. The shredding device's own clock is trusted for now.
//
// On every leg but the extension's.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"time"
)

// What one ShredTrash did.
type MailTrashShred struct {
	// The erasures it began, a month's messages each, with where each stands.
	Erasures []*MailErasure
	// Messages in trash whose retention has not run out, or whose month's flags changed too lately to date them.
	Waiting int
}

// Erases every message of the repo that has stood in trash for TrashRetention: see the file header. A month whose
// erasure waits or fails ends the call, since the next would meet the same allowance.
func (self *MailEraser) ShredTrash(ctx context.Context) (*MailTrashShred, error) {
	if !self.allowed() {
		return nil, ErrMailNotEraser
	}
	if _, err := self.Refresh(ctx); err != nil {
		return nil, err
	}
	shred := &MailTrashShred{}
	monthNames, err := self.store.List(ctx, mailFlagFamily)
	if errors.Is(err, ErrEvsPathAbsent) {
		return shred, nil
	}
	if err != nil {
		return shred, err
	}
	months := []MailYearMonth{}
	for _, name := range monthNames {
		if month, ok := ParseMailYearMonth(name); ok {
			months = append(months, month)
		}
	}
	slices.Sort(months)
	now := self.clock.Now()
	for _, month := range months {
		due, waiting, err := self.trashDue(ctx, month, now)
		shred.Waiting += waiting
		if err != nil {
			return shred, err
		}
		if len(due) == 0 {
			continue
		}
		erasure, err := self.Erase(ctx, month, due)
		if erasure != nil {
			shred.Erasures = append(shred.Erasures, erasure)
		}
		if err != nil || (erasure != nil && erasure.State != MailErasureDone) {
			return shred, err
		}
	}
	return shred, nil
}

// The messages of month whose trash has run its retention at now, and how many in trash have not.
func (self *MailEraser) trashDue(ctx context.Context, month MailYearMonth, now time.Time) (due []Id, waiting int, err error) {
	directory := MailFlagDirectory(month)
	numbers, err := mailListSegments(ctx, self.store, directory)
	if err != nil {
		return nil, 0, err
	}
	merger := newMailFlagMerger(func(messageId Id) bool {
		_, erased := self.erased.erased(messageId)
		return !erased
	})
	// the newest push of the month's flags: no op of the month was written after it
	lastPush := time.Time{}
	for _, n := range numbers {
		path := MailFlagPath(month, n)
		segment, _, err := self.store.Read(ctx, path, mailFlagSegmentReadMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if err := merger.addSegment(segment); err != nil && !errors.Is(err, ErrMailSegmentInvalid) {
			return nil, 0, err
		}
		versions, err := self.store.Versions(ctx, path)
		if err != nil {
			return nil, 0, err
		}
		if 0 < len(versions) && lastPush.Before(versions[0].Time) {
			lastPush = versions[0].Time
		}
	}
	for _, op := range merger.winners() {
		messageId, err := IdFromBytes(op.GetMessageId())
		if err != nil {
			continue
		}
		flags := merger.flags(messageId)
		if !flags.Trash || slices.Contains(due, messageId) {
			continue
		}
		trashed := time.UnixMilli(int64(min(flags.TrashTimeMillis, mailLastMillis))).UTC()
		if trashed.Before(lastPush) {
			trashed = lastPush
		}
		if now.Before(trashed.Add(self.settings.TrashRetention)) {
			waiting += 1
			continue
		}
		due = append(due, messageId)
	}
	return due, waiting, nil
}
