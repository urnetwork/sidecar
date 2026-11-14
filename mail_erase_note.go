//go:build !ios_extension

// What a mail erasure's ERASEs say they destroyed, and a device's view of them (§15.7's erasure, §11.12's reconcile
// row; MAIL-M7-15, MAIL-M7-16): the caller's part of an ERASE's sealed note (evs_erase.go), which mail writes as
// paths, one a line, as the vault writes its entries' (mail_vault.go), so a reader tells the two by the path.
//
//	m/<yyyymm>/<h>/<id>   a message whose own keys this ERASE destroys: its body's, and an unconsumed deposit's
//	i/<yyyymm>/<n>        an i/ segment whose replaced chain's keys this ERASE destroys, after the CLOSURE that wrote
//	                      the segment again without the erasure's messages
//
// A note with any other line is another writer's, a vault's among them, and names nothing of mail's. mailErasedView is
// what ingest and the eraser keep of the erasure ref between reads: every message a committed ERASE named, with its
// erasure's id, read on from the version the last read reached. An erased message is never written again (FS-13).
//
// On every leg but the extension's. Package-level functions and mailErasedView are safe for concurrent use.

package sidecar

import (
	"context"
	"strings"
	"sync"
)

// One message a mail ERASE's note names.
type mailErasedMessage struct {
	Month     MailYearMonth
	MessageId Id
}

// One i/ segment a mail ERASE's note names.
type mailErasedSegment struct {
	Month MailYearMonth
	N     uint64
}

// The month and id of an m/<yyyymm>/<h>/<id> path as MailMessagePath spells it, false for any other.
func parseMailMessagePath(path string) (MailYearMonth, Id, bool) {
	rest, ok := strings.CutPrefix(path, mailMessageFamily+"/")
	if !ok {
		return 0, Id{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return 0, Id{}, false
	}
	month, ok := ParseMailYearMonth(parts[0])
	if !ok {
		return 0, Id{}, false
	}
	messageId, ok := parseMailVaultEntryName(parts[2])
	if !ok || MailMessagePath(month, messageId) != path {
		return 0, Id{}, false
	}
	return month, messageId, true
}

// The month and number of an i/<yyyymm>/<n> path as MailIndexPath spells it, false for any other.
func parseMailIndexPath(path string) (MailYearMonth, uint64, bool) {
	rest, ok := strings.CutPrefix(path, mailIndexFamily+"/")
	if !ok {
		return 0, 0, false
	}
	monthText, numberText, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, 0, false
	}
	month, ok := ParseMailYearMonth(monthText)
	if !ok {
		return 0, 0, false
	}
	n, ok := ParseMailSegmentNumber(numberText)
	if !ok || MailIndexPath(month, n) != path {
		return 0, 0, false
	}
	return month, n, true
}

// The caller's note of a mail ERASE: each message whose own keys it destroys, then each i/ segment whose replaced
// chain's keys it destroys, one path a line.
func mailErasureNote(messages []mailErasedMessage, segments []mailErasedSegment) []byte {
	lines := make([]string, 0, len(messages)+len(segments))
	for _, message := range messages {
		lines = append(lines, MailMessagePath(message.Month, message.MessageId))
	}
	for _, segment := range segments {
		lines = append(lines, MailIndexPath(segment.Month, segment.N))
	}
	return []byte(strings.Join(lines, "\n"))
}

// A mail ERASE's note opened to what it names; false for a note of another shape, a vault's or an empty one among
// them, which names nothing of mail's.
func parseMailErasureNote(note []byte) ([]mailErasedMessage, []mailErasedSegment, bool) {
	if len(note) == 0 {
		return nil, nil, false
	}
	messages := []mailErasedMessage{}
	segments := []mailErasedSegment{}
	for _, line := range strings.Split(string(note), "\n") {
		if month, messageId, ok := parseMailMessagePath(line); ok {
			messages = append(messages, mailErasedMessage{Month: month, MessageId: messageId})
			continue
		}
		if month, n, ok := parseMailIndexPath(line); ok {
			segments = append(segments, mailErasedSegment{Month: month, N: n})
			continue
		}
		return nil, nil, false
	}
	return messages, segments, true
}

// One repo's erased messages as a device holds them between reads of its erasure ref.
type mailErasedView struct {
	stateLock sync.Mutex
	// Each message a committed mail ERASE named, with its month and that erasure's id.
	messageErasureIds map[Id]Id
	messageMonths     map[Id]MailYearMonth
	// The erasure ref's version the view read through.
	through uint64
}

// A view that read nothing yet.
func newMailErasedView() *mailErasedView {
	return &mailErasedView{messageErasureIds: map[Id]Id{}, messageMonths: map[Id]MailYearMonth{}}
}

// Reads the erasure ref on from where the view reached, through erasures (EvsRepo.ReadErasures), and gives the
// ERASEs it had not seen, oldest first.
func (self *mailErasedView) refresh(ctx context.Context, erasures func(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)) ([]*EvsErasure, error) {
	through := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.through
	}()
	read, err := erasures(ctx, through)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fresh := []*EvsErasure{}
	for _, erasure := range read {
		if erasure.Version <= self.through {
			continue
		}
		fresh = append(fresh, erasure)
		if messages, _, ok := parseMailErasureNote(erasure.Note); ok {
			for _, message := range messages {
				self.messageErasureIds[message.MessageId] = erasure.ErasureId
				self.messageMonths[message.MessageId] = message.Month
			}
		}
	}
	for _, erasure := range fresh {
		self.through = max(self.through, erasure.Version)
	}
	return fresh, nil
}

// Marks a message erased ahead of the next read: the eraser's own ERASE, as it commits.
func (self *mailErasedView) note(month MailYearMonth, messageId Id, erasureId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.messageErasureIds[messageId] = erasureId
	self.messageMonths[messageId] = month
}

// Whether a committed ERASE named the message, and that erasure's id.
func (self *mailErasedView) erased(messageId Id) (Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erasureId, ok := self.messageErasureIds[messageId]
	return erasureId, ok
}

// Every erased message's id.
func (self *mailErasedView) messageIds() map[Id]bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ids := make(map[Id]bool, len(self.messageErasureIds))
	for messageId := range self.messageErasureIds {
		ids[messageId] = true
	}
	return ids
}
