// §15.7's message list as a person sees it (R-MAIL-13, D-MAIL-16; MAIL-M7-06): a mailbox's i/ entries and the group
// messages its r/ references name, with f/'s flags merged in, newest first, a page at a time. It reads only through
// mailStore, so a daemon, an app that mirrors i/ in full and head-reads m/ (§18.4), and a page Worker list alike; it
// decides no label and looks nothing up, every value being what ingest sealed (D-MAIL-14).
//
// The view works a month at a time, newest first. A month's order is built once and kept between pages: each entry's
// time, id, spam_score and where its record sits, read off the record without decoding the rest, about 40 bytes, and
// its merged flags, about 72, so a month of n messages costs about 112·n bytes while it is kept and a page decodes
// only its own entries. CachedMonthCount months and CachedSegmentCount segments are kept, so a mailbox of 100,000
// messages pages within §18.4's budget whatever its size, a month being what one view holds. A list asked from its
// first page reads afresh; later pages page the months as they read, so a page never repeats or skips an entry
// because a write landed between pages. Invalidate drops what is kept, for a caller that hears of a write.
//
// Within a month the order is time, newest first, then id as bytes, highest first (MAIL-FORMAT.md). A message id
// has one entry: of two, the view keeps the mailbox's own over a group's, then the first in segment order, so a group
// cannot shadow a mailbox's message and a writer's lost answer cannot show a message twice. An entry whose time is not
// its segment's month, a record that does not parse, a reference that does not match its path, and an op that breaks
// MAIL-FORMAT.md are passed over and counted in Unreadable, never shown and never an error: they are what a broken or
// hostile writer leaves, and one must not hide the rest.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// IndexEntry's spam_score, which a list filters on before it decodes anything else.
const mailIndexEntrySpamScoreField protowire.Number = 14

// The most a reader takes of an r/ reference, a MailGroupRef of two 16-byte ids, with room for a newer writer's
// fields. A format value.
const mailGroupRefReadMaxByteCount = 1024

var (
	// No entry for that id in that month.
	ErrMailViewEntryAbsent = errors.New("mail view: no such entry")
	// A list asked for a folder the view does not have, or a label folder with no label.
	ErrMailViewArgsInvalid = errors.New("mail view: invalid list")
)

// Which messages a list shows. Every folder but trash leaves out what is in trash.
type MailFolder int

const (
	// Every message not in trash.
	MailFolderAll MailFolder = iota
	// Not spam and not sent.
	MailFolderInbox
	// Labeled sent.
	MailFolderSent
	// Spam: a person's spam verdict, or with no verdict a spam_score at or past SpamScoreThreshold.
	MailFolderSpam
	// In trash.
	MailFolderTrash
	// Carrying MailListArgs.Label.
	MailFolderLabel
)

// A place in the list: the last entry a page showed.
type MailListCursor struct {
	Time uint64
	Id   Id
}

// What a list asks.
type MailListArgs struct {
	Folder MailFolder
	// With MailFolderLabel.
	Label string
	// Entries after this one in the list's order; nil starts at the newest, reading afresh.
	After *MailListCursor
	// At most this many; non-positive takes PageEntryCount.
	Limit int
}

// One message as a list shows it.
type MailViewEntry struct {
	// The repo the message is in: the mailbox, or the group repo its r/ reference names, whose m/ holds it.
	RepoId Id
	Entry  *protocol.IndexEntry
	Flags  *MailFlags
	// spam by the person's verdict, else by spam_score against SpamScoreThreshold.
	Spam bool
}

// One page.
type MailListPage struct {
	Entries []*MailViewEntry
	// Where the next page starts; nil after the last.
	Next *MailListCursor
	// Records, references and ops passed over in the months this page read: see the file header.
	Unreadable int
}

// What a view reads.
type MailViewArgs struct {
	// The mailbox's repo id and its store.
	MailboxId Id
	Mailbox   mailStore
	// A group repo's store, by repo id: where an r/ reference's message is. nil passes every reference over.
	Groups func(ctx context.Context, repoId Id) (mailStore, error)
	// The mailbox's clock on this device, which sees every op the view reads; nil when nothing here writes flags.
	Hlc      *MailHlc
	Settings *MailStoreSettings
}

// Where an entry is, and what a list orders and filters it by. 40 bytes.
type mailViewKey struct {
	time    uint64
	id      Id
	segment uint32
	// The repo: 0 the mailbox, else MailViewArgs' order of the month's group repos, from 1.
	source    uint16
	record    uint16
	spamScore uint16
}

// One month's order and flags.
type mailViewMonth struct {
	month MailYearMonth
	// Newest first.
	keys []mailViewKey
	// Indexes into keys, by id.
	byId []uint32
	// The repo of each source, the mailbox first.
	sources []Id
	flags   *mailFlagMerger
	// Passed over while building.
	unreadable int
}

// The key of id, false where the month has none.
func (self *mailViewMonth) key(id Id) (mailViewKey, bool) {
	index, found := slices.BinarySearchFunc(self.byId, id, func(position uint32, target Id) int {
		return mailIdCompare(self.keys[position].id, target)
	})
	if !found {
		return mailViewKey{}, false
	}
	return self.keys[self.byId[index]], true
}

// A segment's bytes, kept to decode a page's entries.
type mailViewSegment struct {
	source  Id
	month   MailYearMonth
	n       uint32
	content []byte
}

// A mailbox's list. See the file header.
type MailView struct {
	args *MailViewArgs

	stateLock sync.Mutex
	// The months as the first page found them, newest first, nil until a list reads them.
	monthNames []MailYearMonth
	// Months and segments kept, least recently used first.
	months   []*mailViewMonth
	segments []*mailViewSegment
}

func NewMailView(args *MailViewArgs) *MailView {
	return &MailView{args: args}
}

// Drops every kept month and segment, so the next call reads afresh.
func (self *MailView) Invalidate() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.monthNames = nil
	self.months = nil
	self.segments = nil
}

// Drops one month, as a caller that wrote to it does.
func (self *MailView) InvalidateMonth(month MailYearMonth) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.months = slices.DeleteFunc(self.months, func(kept *mailViewMonth) bool { return kept.month == month })
	self.segments = slices.DeleteFunc(self.segments, func(kept *mailViewSegment) bool { return kept.month == month })
}

// One page of a folder, newest first. See the file header.
func (self *MailView) List(ctx context.Context, args *MailListArgs) (*MailListPage, error) {
	if args.Folder < MailFolderAll || MailFolderLabel < args.Folder || (args.Folder == MailFolderLabel) != (args.Label != "") {
		return nil, ErrMailViewArgsInvalid
	}
	limit := args.Limit
	if limit <= 0 {
		limit = max(1, self.args.Settings.PageEntryCount)
	}
	if args.After == nil {
		self.Invalidate()
	}
	monthNames, err := self.listMonths(ctx)
	if err != nil {
		return nil, err
	}
	page := &MailListPage{Entries: []*MailViewEntry{}}
	type selected struct {
		month *mailViewMonth
		key   mailViewKey
	}
	picks := []selected{}
	var last *mailViewKey
	for _, monthName := range monthNames {
		if args.After != nil && MailYearMonthOf(args.After.Time) < monthName {
			continue
		}
		month, err := self.month(ctx, monthName)
		if err != nil {
			return nil, err
		}
		page.Unreadable += month.unreadable
		position := 0
		if args.After != nil && MailYearMonthOf(args.After.Time) == monthName {
			// the first key past the cursor in the list's order
			position, _ = slices.BinarySearchFunc(month.keys, *args.After, func(key mailViewKey, cursor MailListCursor) int {
				return -cmp.Or(cmp.Compare(key.time, cursor.Time), mailIdCompare(key.id, cursor.Id))
			})
			if position < len(month.keys) && month.keys[position].time == args.After.Time && month.keys[position].id == args.After.Id {
				position += 1
			}
		}
		for ; position < len(month.keys) && len(picks) < limit; position += 1 {
			key := month.keys[position]
			last = &month.keys[position]
			flags := month.flags.flags(key.id)
			if self.inFolder(args, key, flags) {
				picks = append(picks, selected{month: month, key: key})
			}
		}
		if len(picks) == limit {
			if position < len(month.keys) || monthName != monthNames[len(monthNames)-1] {
				page.Next = &MailListCursor{Time: last.time, Id: last.id}
			}
			break
		}
	}
	for _, pick := range picks {
		entry, err := self.decode(ctx, pick.month, pick.key)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			page.Unreadable += 1
			continue
		}
		page.Entries = append(page.Entries, entry)
	}
	return page, nil
}

// One message, by its IndexEntry's month and id: ErrMailViewEntryAbsent where the month holds none. A month kept
// from before the entry was written is read again once.
func (self *MailView) Entry(ctx context.Context, month MailYearMonth, id Id) (*MailViewEntry, error) {
	viewMonth, key, err := self.find(ctx, month, id)
	if err != nil {
		return nil, err
	}
	entry, err := self.decode(ctx, viewMonth, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrMailViewEntryAbsent
	}
	return entry, nil
}

// One message's flags, as Entry finds it.
func (self *MailView) Flags(ctx context.Context, month MailYearMonth, id Id) (*MailFlags, error) {
	viewMonth, key, err := self.find(ctx, month, id)
	if err != nil {
		return nil, err
	}
	return viewMonth.flags.flags(key.id), nil
}

// The month holding id, read again once when a kept month does not.
func (self *MailView) find(ctx context.Context, month MailYearMonth, id Id) (*mailViewMonth, mailViewKey, error) {
	for attempt := 0; attempt < 2; attempt += 1 {
		viewMonth, err := self.month(ctx, month)
		if err != nil {
			return nil, mailViewKey{}, err
		}
		if key, ok := viewMonth.key(id); ok {
			return viewMonth, key, nil
		}
		self.InvalidateMonth(month)
	}
	return nil, mailViewKey{}, ErrMailViewEntryAbsent
}

// Whether a message is in the list's folder.
func (self *MailView) inFolder(args *MailListArgs, key mailViewKey, flags *MailFlags) bool {
	if args.Folder == MailFolderTrash {
		return flags.Trash
	}
	if flags.Trash {
		return false
	}
	switch args.Folder {
	case MailFolderInbox:
		return !self.spam(key, flags) && !flags.HasLabel(MailLabelSent)
	case MailFolderSent:
		return flags.HasLabel(MailLabelSent)
	case MailFolderSpam:
		return self.spam(key, flags)
	case MailFolderLabel:
		return flags.HasLabel(args.Label)
	}
	return true
}

// A person's verdict, else spam_score against the threshold (§15.9).
func (self *MailView) spam(key mailViewKey, flags *MailFlags) bool {
	if flags.VerdictSpam || flags.VerdictNotSpam {
		return flags.VerdictSpam
	}
	return self.args.Settings.SpamScoreThreshold <= uint32(key.spamScore)
}

// The months holding mail, newest first: the mailbox's i/ and r/ months, as the first page read them.
func (self *MailView) listMonths(ctx context.Context) ([]MailYearMonth, error) {
	self.stateLock.Lock()
	monthNames := self.monthNames
	self.stateLock.Unlock()
	if monthNames != nil {
		return monthNames, nil
	}
	monthNames = []MailYearMonth{}
	for _, family := range []string{mailIndexFamily, mailGroupRefFamily} {
		names, err := self.args.Mailbox.List(ctx, family)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if month, ok := ParseMailYearMonth(name); ok && !slices.Contains(monthNames, month) {
				monthNames = append(monthNames, month)
			}
		}
	}
	slices.SortFunc(monthNames, func(a MailYearMonth, b MailYearMonth) int { return cmp.Compare(b, a) })
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.monthNames == nil {
		self.monthNames = monthNames
	}
	return self.monthNames, nil
}

// A month's order and flags, kept or built.
func (self *MailView) month(ctx context.Context, month MailYearMonth) (*mailViewMonth, error) {
	kept := func() *mailViewMonth {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for index, viewMonth := range self.months {
			if viewMonth.month == month {
				self.months = append(append(self.months[:index:index], self.months[index+1:]...), viewMonth)
				return viewMonth
			}
		}
		return nil
	}()
	if kept != nil {
		return kept, nil
	}
	built, err := self.buildMonth(ctx, month)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.months = append(slices.DeleteFunc(self.months, func(viewMonth *mailViewMonth) bool { return viewMonth.month == month }), built)
	if keep := max(1, self.args.Settings.CachedMonthCount); keep < len(self.months) {
		self.months = slices.Clone(self.months[len(self.months)-keep:])
	}
	return built, nil
}

// Reads a month: its i/ segments, its r/ references and their group repos' segments, then the f/ ops of each.
func (self *MailView) buildMonth(ctx context.Context, month MailYearMonth) (*mailViewMonth, error) {
	viewMonth := &mailViewMonth{month: month, keys: []mailViewKey{}, sources: []Id{self.args.MailboxId}}
	// the mailbox's own entries
	if err := self.readKeys(ctx, viewMonth, self.args.Mailbox, 0, nil); err != nil {
		return nil, err
	}
	// group messages its r/ references name, each group read once
	references, err := self.readReferences(ctx, viewMonth)
	if err != nil {
		return nil, err
	}
	groupStores := []mailStore{nil}
	if self.args.Groups != nil {
		groupIds := []Id{}
		for _, repoId := range references {
			if !slices.Contains(groupIds, repoId) {
				groupIds = append(groupIds, repoId)
			}
		}
		slices.SortFunc(groupIds, mailIdCompare)
		for _, repoId := range groupIds {
			if len(viewMonth.sources) == 1<<16 {
				break
			}
			// a group this device cannot read hides only its own messages, counted, never the mailbox's
			store, err := self.args.Groups(ctx, repoId)
			if err != nil {
				viewMonth.unreadable += 1
				continue
			}
			source := uint16(len(viewMonth.sources))
			keyCount := len(viewMonth.keys)
			if err := self.readKeys(ctx, viewMonth, store, source, func(id Id) bool { return references[id] == repoId }); err != nil {
				viewMonth.keys = viewMonth.keys[:keyCount]
				viewMonth.unreadable += 1
				continue
			}
			viewMonth.sources = append(viewMonth.sources, repoId)
			groupStores = append(groupStores, store)
		}
	}
	// one entry an id: the mailbox's before a group's, then the first in segment order
	slices.SortFunc(viewMonth.keys, func(a mailViewKey, b mailViewKey) int {
		return cmp.Or(mailIdCompare(a.id, b.id), cmp.Compare(a.source, b.source), cmp.Compare(a.segment, b.segment), cmp.Compare(a.record, b.record))
	})
	viewMonth.keys = slices.CompactFunc(viewMonth.keys, func(a mailViewKey, b mailViewKey) bool { return a.id == b.id })
	slices.SortFunc(viewMonth.keys, func(a mailViewKey, b mailViewKey) int {
		return -cmp.Or(cmp.Compare(a.time, b.time), mailIdCompare(a.id, b.id))
	})
	viewMonth.keys = slices.Clip(viewMonth.keys)
	viewMonth.byId = make([]uint32, len(viewMonth.keys))
	for index := range viewMonth.byId {
		viewMonth.byId[index] = uint32(index)
	}
	slices.SortFunc(viewMonth.byId, func(a uint32, b uint32) int {
		return mailIdCompare(viewMonth.keys[a].id, viewMonth.keys[b].id)
	})
	// flags: the mailbox's ops on every message, a group's only on its own
	for source, store := range groupStores {
		if source == 0 {
			store = self.args.Mailbox
		}
		merger := viewMonth.flags
		accept := func(id Id) bool {
			key, ok := viewMonth.key(id)
			return ok && (source == 0 || int(key.source) == source)
		}
		if merger == nil {
			merger = newMailFlagMerger(accept)
			viewMonth.flags = merger
		}
		merger.accept = accept
		if err := self.readOps(ctx, viewMonth, store, merger); err != nil {
			if source == 0 {
				return nil, err
			}
			viewMonth.unreadable += 1
		}
	}
	viewMonth.flags.accept = nil
	if self.args.Hlc != nil {
		self.args.Hlc.Observe(viewMonth.flags.lastHlc)
	}
	return viewMonth, nil
}

// Adds the keys of store's i/ segments of the month that accept takes, every one when nil.
func (self *MailView) readKeys(ctx context.Context, viewMonth *mailViewMonth, store mailStore, source uint16, accept func(id Id) bool) error {
	numbers, err := mailListSegments(ctx, store, MailIndexDirectory(viewMonth.month))
	if err != nil {
		return err
	}
	for _, n := range numbers {
		if 1<<32 <= n {
			viewMonth.unreadable += 1
			continue
		}
		segment, _, err := store.Read(ctx, MailIndexPath(viewMonth.month, n), mailIndexSegmentReadMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if errors.Is(err, ErrMailStoreTooLarge) {
			viewMonth.unreadable += 1
			continue
		}
		if err != nil {
			return err
		}
		walkErr := mailSegmentRecords(segment, func(index int, record []byte) error {
			if MailIndexSegmentMaxEntryCount <= index {
				return ErrMailSegmentInvalid
			}
			id, timeMillis, ok := mailIndexRecordKey(record)
			if !ok || MailYearMonthOf(timeMillis) != viewMonth.month {
				viewMonth.unreadable += 1
				return nil
			}
			if accept != nil && !accept(id) {
				return nil
			}
			viewMonth.keys = append(viewMonth.keys, mailViewKey{
				time: timeMillis, id: id, segment: uint32(n), source: source, record: uint16(index),
				spamScore: mailIndexRecordSpamScore(record),
			})
			return nil
		})
		if walkErr != nil {
			viewMonth.unreadable += 1
		}
	}
	return nil
}

// spam_score off an IndexEntry's bytes, the last winning, held to 1,000: a reader takes more as 1,000
// (MAIL-FORMAT.md). 0 where it is absent or malformed.
func mailIndexRecordSpamScore(record []byte) uint16 {
	score := uint64(0)
	for 0 < len(record) {
		number, wireType, tagByteCount := protowire.ConsumeTag(record)
		if tagByteCount < 0 {
			return 0
		}
		record = record[tagByteCount:]
		if number == mailIndexEntrySpamScoreField && wireType == protowire.VarintType {
			value, valueByteCount := protowire.ConsumeVarint(record)
			if valueByteCount < 0 {
				return 0
			}
			score = value
			record = record[valueByteCount:]
			continue
		}
		valueByteCount := protowire.ConsumeFieldValue(number, wireType, record)
		if valueByteCount < 0 {
			return 0
		}
		record = record[valueByteCount:]
	}
	return uint16(min(score, mailSpamScoreMax))
}

// The month's r/ references: each group message's id and its group repo, from references whose bytes match their
// paths.
func (self *MailView) readReferences(ctx context.Context, viewMonth *mailViewMonth) (map[Id]Id, error) {
	references := map[Id]Id{}
	directory := mailGroupRefFamily + "/" + viewMonth.month.String()
	shards, err := self.args.Mailbox.List(ctx, directory)
	if errors.Is(err, ErrEvsPathAbsent) {
		return references, nil
	}
	if err != nil {
		return nil, err
	}
	slices.Sort(shards)
	for _, shard := range shards {
		names, err := self.args.Mailbox.List(ctx, directory+"/"+shard)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		slices.Sort(names)
		for _, name := range names {
			decoded, err := evsTokenEncoding.DecodeString(name)
			if err != nil || len(decoded) != len(Id{}) || MailShard(name) != shard || strings.ToLower(name) != name {
				viewMonth.unreadable += 1
				continue
			}
			messageId := Id(decoded)
			content, _, err := self.args.Mailbox.Read(ctx, MailGroupRefPath(viewMonth.month, messageId), mailGroupRefReadMaxByteCount)
			if errors.Is(err, ErrEvsPathAbsent) {
				continue
			}
			if errors.Is(err, ErrMailStoreTooLarge) {
				viewMonth.unreadable += 1
				continue
			}
			if err != nil {
				return nil, err
			}
			reference := &protocol.MailGroupRef{}
			if proto.Unmarshal(content, reference) != nil || !bytes.Equal(reference.GetMessageId(), decoded) ||
				len(reference.GetRepoId()) != len(Id{}) {
				viewMonth.unreadable += 1
				continue
			}
			references[messageId] = Id(reference.GetRepoId())
		}
	}
	return references, nil
}

// Merges every op of store's f/ segments of the month into merger.
func (self *MailView) readOps(ctx context.Context, viewMonth *mailViewMonth, store mailStore, merger *mailFlagMerger) error {
	numbers, err := mailListSegments(ctx, store, MailFlagDirectory(viewMonth.month))
	if err != nil {
		return err
	}
	for _, n := range numbers {
		segment, _, err := store.Read(ctx, MailFlagPath(viewMonth.month, n), mailFlagSegmentReadMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if errors.Is(err, ErrMailStoreTooLarge) {
			viewMonth.unreadable += 1
			continue
		}
		if err != nil {
			return err
		}
		invalidBefore := merger.invalidCount
		if merger.addSegment(segment) != nil {
			viewMonth.unreadable += 1
		}
		viewMonth.unreadable += merger.invalidCount - invalidBefore
	}
	return nil
}

// A key's entry with its flags, or nil where its record no longer decodes as the key read it.
func (self *MailView) decode(ctx context.Context, viewMonth *mailViewMonth, key mailViewKey) (*MailViewEntry, error) {
	repoId := viewMonth.sources[key.source]
	segment, err := self.segment(ctx, viewMonth, key)
	if err != nil {
		return nil, err
	}
	var entry *protocol.IndexEntry
	mailSegmentRecords(segment, func(index int, record []byte) error {
		if index != int(key.record) {
			return nil
		}
		decoded := &protocol.IndexEntry{}
		if proto.Unmarshal(record, decoded) == nil && bytes.Equal(decoded.GetId(), key.id[:]) && decoded.GetTime() == key.time {
			entry = decoded
		}
		return errMailViewRecordFound
	})
	if entry == nil {
		return nil, nil
	}
	flags := viewMonth.flags.flags(key.id)
	return &MailViewEntry{RepoId: repoId, Entry: entry, Flags: flags, Spam: self.spam(key, flags)}, nil
}

// Stops a segment walk at the record sought.
var errMailViewRecordFound = errors.New("mail view: record found")

// A key's segment, kept or read.
func (self *MailView) segment(ctx context.Context, viewMonth *mailViewMonth, key mailViewKey) ([]byte, error) {
	repoId := viewMonth.sources[key.source]
	kept := func() []byte {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for index, segment := range self.segments {
			if segment.source == repoId && segment.month == viewMonth.month && segment.n == key.segment {
				self.segments = append(append(self.segments[:index:index], self.segments[index+1:]...), segment)
				return segment.content
			}
		}
		return nil
	}()
	if kept != nil {
		return kept, nil
	}
	store := self.args.Mailbox
	if key.source != 0 {
		// a group this device cannot read now leaves its message out of the page, as buildMonth does
		var err error
		if self.args.Groups == nil {
			return []byte{}, nil
		}
		if store, err = self.args.Groups(ctx, repoId); err != nil {
			return []byte{}, nil
		}
	}
	content, _, err := store.Read(ctx, MailIndexPath(viewMonth.month, uint64(key.segment)), mailIndexSegmentReadMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrMailStoreTooLarge) || (err != nil && key.source != 0) {
		return []byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	if keep := self.args.Settings.CachedSegmentCount; 0 < keep {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.segments = append(self.segments, &mailViewSegment{source: repoId, month: viewMonth.month, n: key.segment, content: content})
		if keep < len(self.segments) {
			self.segments = slices.Clone(self.segments[len(self.segments)-keep:])
		}
	}
	return content, nil
}
