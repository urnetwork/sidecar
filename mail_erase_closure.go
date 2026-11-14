//go:build !ios_extension

// An erasure's parts (§15.7, §11.12's closure and rekey rows; MAIL-M7-16): for each whole i/ segment that lists a
// message of the erasure, one CLOSURE writes the segment again without those rows, a whole checkpoint under a fresh
// key, and one ERASE then destroys the replaced chain's keys, the slot of every version the path retained before it.
//
//	rows     a part takes out only its own erasure's rows, so each erasure completes by its own last part whatever
//	         other erasures of the repo do, and a segment two erasures list is re-keyed by each
//	conflict another writer's append lands under a part: the CLOSURE meets 409 on the segment, and the part reads it
//	         again and goes again. The writer that loses to a CLOSURE reads the segment again in the same way and
//	         appends to what the CLOSURE left, which holds no erased row (MailIndexWriter.Append), so no device
//	         writes an erased row back
//	wait     a CLOSURE evs refuses 429 ends the erasure's call as waiting, with the segments and bytes still to
//	         re-key and the time to try again; the parts before it stand
//	crash    between a CLOSURE and its ERASE the replaced chain's keys still stand: Resume finds the CLOSURE with
//	         its erasure's id and sends the ERASE its keys ask for
//
// The record lengths of the segment written again sum to less than the replaced chain's, so §11.12's closure bound
// holds. On every leg but the extension's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"
)

// One i/ segment listing a message of an erasure, and its bytes as read.
type mailEraseSegment struct {
	segment   mailErasedSegment
	byteCount int64
}

// The i/ segments that list any of messages, in month and number order.
func (self *MailEraser) segmentsListing(ctx context.Context, messages []mailErasedMessage) ([]*mailEraseSegment, error) {
	months := []MailYearMonth{}
	for _, message := range messages {
		if !slices.Contains(months, message.Month) {
			months = append(months, message.Month)
		}
	}
	slices.Sort(months)
	listing := []*mailEraseSegment{}
	for _, month := range months {
		numbers, err := mailListSegments(ctx, self.store, MailIndexDirectory(month))
		if err != nil {
			return nil, err
		}
		for _, n := range numbers {
			content, _, err := self.store.Read(ctx, MailIndexPath(month, n), mailIndexSegmentReadMaxByteCount)
			if errors.Is(err, ErrEvsPathAbsent) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if _, removedCount := mailSegmentWithout(content, month, messages); 0 < removedCount {
				listing = append(listing, &mailEraseSegment{segment: mailErasedSegment{Month: month, N: n}, byteCount: int64(len(content))})
			}
		}
	}
	return listing, nil
}

// A segment's bytes without the rows of messages under month, and how many rows that took out. A segment that does
// not parse keeps its bytes past the fault as they are, so nothing a reader could still read is dropped.
func mailSegmentWithout(segment []byte, month MailYearMonth, messages []mailErasedMessage) ([]byte, int) {
	kept := []byte{}
	removedCount := 0
	err := mailSegmentRecords(segment, func(index int, record []byte) error {
		messageId, _, ok := mailIndexRecordKey(record)
		if ok && slices.ContainsFunc(messages, func(message mailErasedMessage) bool {
			return message.MessageId == messageId && message.Month == month
		}) {
			removedCount += 1
			return nil
		}
		kept = mailSegmentAppend(kept, record)
		return nil
	})
	if err != nil {
		return segment, 0
	}
	return kept, removedCount
}

// The erasure's parts, a segment at a time, the last one's ERASE completing it. Fills erasure with where it stands.
func (self *MailEraser) rewrite(ctx context.Context, erasure *MailErasure, messages []mailErasedMessage) error {
	segments, err := self.segmentsListing(ctx, messages)
	if err != nil {
		erasure.State = MailErasureRewriting
		return err
	}
	left := func(from int) {
		erasure.SegmentsLeft = len(segments) - from
		erasure.BytesLeft = 0
		for _, segment := range segments[from:] {
			erasure.BytesLeft += segment.byteCount
		}
	}
	for index, segment := range segments {
		left(index)
		err := self.part(ctx, erasure.ErasureId, segment.segment, messages, index == len(segments)-1)
		if wait, refused := mailEraseRefusedForNow(err); refused {
			erasure.State = MailErasureWaiting
			erasure.NextTry = self.clock.Now().Add(wait)
			erasure.Finish = mailEraseFinish(erasure.NextTry, erasure.BytesLeft, self.settings.ClosureFloorByteCountPerDay)
			return nil
		}
		if err != nil {
			erasure.State = MailErasureRewriting
			return err
		}
	}
	left(len(segments))
	erasure.State = MailErasureDone
	erasure.NextTry, erasure.Finish = time.Time{}, time.Time{}
	return nil
}

// One part: the segment's CLOSURE without the erasure's rows, then the ERASE of the chain it replaced.
func (self *MailEraser) part(ctx context.Context, erasureId Id, segment mailErasedSegment, messages []mailErasedMessage, complete bool) error {
	path := MailIndexPath(segment.Month, segment.N)
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, version, err := self.store.Read(ctx, path, mailIndexSegmentReadMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			return nil
		}
		if err != nil {
			return err
		}
		without, removedCount := mailSegmentWithout(content, segment.Month, messages)
		if removedCount == 0 {
			// re-checkpointed already: a CLOSURE whose ERASE did not follow is Resume's
			return nil
		}
		keys, err := self.pathKeys(ctx, path)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return ErrMailNotShreddable
		}
		testHookBarrier("mail.erase.closure.before", "")
		err = self.store.Closure(ctx, erasureId, path, without, version, keys)
		testHookBarrier("mail.erase.closure.after", "")
		if mailStoreConflictOn(err, path) && attempt < self.settings.SegmentRetryCount {
			// an append landed under the part: read the segment again
			continue
		}
		if err != nil {
			return err
		}
		testHookBarrier("mail.erase.keys.before", "")
		err = self.store.Erase(ctx, &EvsEraseArgs{
			ErasureId: erasureId, Keys: keys, Complete: complete, Note: mailErasureNote(nil, []mailErasedSegment{segment}),
		})
		testHookBarrier("mail.erase.keys.after", "")
		return err
	}
}

// mailEraseStore over EvsRepo. Safe for concurrent use.
type mailEraseEvsStore struct {
	*mailVaultEvsStore
}

// EvsRepo.Closure of one path, a conflict as the store's.
func (self *mailEraseEvsStore) Closure(ctx context.Context, erasureId Id, path string, content []byte, ifVersion uint64, erased []*EvsErasedKey) error {
	_, err := self.repo.Closure(ctx, &EvsClosureArgs{
		ErasureId: erasureId, RefName: self.refName,
		Writes: []*EvsPathWrite{{Path: path, Content: bytes.NewReader(content), IfVersion: &ifVersion}},
		Erased: erased,
	})
	var conflict *EvsPathConflictError
	evsError, refused := EvsErrorOf(err)
	if errors.As(err, &conflict) || (refused && evsError.Status == http.StatusConflict) {
		// the path moved under the plan, or evs holds the CLOSURE to a version that is no longer the path's, a
		// duplicate CLOSURE's answer among them: the part reads the segment again and sees which
		return &MailStoreConflictError{Paths: []string{path}}
	}
	return err
}

// EvsRepo.ReadClosures of the main ref.
func (self *mailEraseEvsStore) Closures(ctx context.Context) ([]*EvsClosure, error) {
	return self.repo.ReadClosures(ctx, self.refName, 0)
}
