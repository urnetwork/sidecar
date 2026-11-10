//go:build !ios_extension

// §15.7's message list (D-MAIL-5, D-MAIL-16; MAIL-M7-06): i/<yyyymm>/<n>, append-only segments of IndexEntry, each a
// MailIndexSegment holding at most 1 MiB or 4,096 entries, which search never replaces. MAIL-FORMAT.md's i/ section
// is the format: a segment is one field-1 record per entry and nothing else a writer adds, so a writer appends the
// record's tag, length and bytes to the bytes it read and never re-encodes them, and a newer writer's fields stay.
//
// MailIndexWriter appends one entry to its month's newest segment, or starts the next segment once the entry would
// pass either bound, by a path CAS on the segment (mailStore), so a racing writer's 409 makes it read and choose again.
// A segment only ever holds what fits, so it stays under the 1,088 KiB that MAIL-M7-16's re-checkpoint may rewrite.
// An entry already in the newest segment is not appended twice: a writer that lost its answer and writes again finds
// its own entry there. The view keeps the first of any id it meets twice (mail_view.go).
//
// On every leg. Package-level functions are safe for concurrent use, and so is MailIndexWriter.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §15.7's bounds on one i/ segment, and MAIL-FORMAT.md's on one entry. Format values.
const (
	MailIndexSegmentMaxByteCount  = 1024 * 1024
	MailIndexSegmentMaxEntryCount = 4096
	// An entry at MAIL-FORMAT.md's caps takes under this, so a segment holds at least 64.
	MailIndexEntryMaxByteCount = 16 * 1024
	// The most a reader takes of an i/ file: what MAIL-M7-16's re-checkpoint may rewrite (§15.7), a little past
	// what a writer makes, so a rewritten segment still reads.
	mailIndexSegmentReadMaxByteCount = 1088 * 1024
)

// The field every record of an i/ or f/ segment sits in: MailIndexSegment.entries and MailFlagSegment.ops.
const mailSegmentRecordField protowire.Number = 1

// IndexEntry's id and time, which a reader orders by before it decodes anything else.
const (
	mailIndexEntryIdField   protowire.Number = 1
	mailIndexEntryTimeField protowire.Number = 3
)

var (
	// Segment bytes that do not parse as a MailIndexSegment or MailFlagSegment: a record that is not
	// length-delimited, or a field cut short.
	ErrMailSegmentInvalid = errors.New("mail segment invalid")
	// An IndexEntry an i/ segment cannot hold: no 16-byte id, no time, or past MailIndexEntryMaxByteCount.
	ErrMailIndexEntryUnfit = errors.New("mail index entry unfit for a segment")
)

// Calls each with every record of a segment in order, the record's index and its bytes, which alias segment. A
// field other than the record field, which a newer writer may add, is passed over, as proto.Unmarshal would keep it.
// ErrMailSegmentInvalid for bytes that do not parse; an error each returns stops the walk and comes back.
func mailSegmentRecords(segment []byte, each func(index int, record []byte) error) error {
	index := 0
	for 0 < len(segment) {
		number, wireType, tagByteCount := protowire.ConsumeTag(segment)
		if tagByteCount < 0 {
			return fmt.Errorf("%w: a tag", ErrMailSegmentInvalid)
		}
		if number != mailSegmentRecordField {
			valueByteCount := protowire.ConsumeFieldValue(number, wireType, segment[tagByteCount:])
			if valueByteCount < 0 {
				return fmt.Errorf("%w: a field", ErrMailSegmentInvalid)
			}
			segment = segment[tagByteCount+valueByteCount:]
			continue
		}
		if wireType != protowire.BytesType {
			return fmt.Errorf("%w: a record that is not length-delimited", ErrMailSegmentInvalid)
		}
		record, valueByteCount := protowire.ConsumeBytes(segment[tagByteCount:])
		if valueByteCount < 0 {
			return fmt.Errorf("%w: a record cut short", ErrMailSegmentInvalid)
		}
		if err := each(index, record); err != nil {
			return err
		}
		index += 1
		segment = segment[tagByteCount+valueByteCount:]
	}
	return nil
}

// segment with record appended as its next record, in a new slice.
func mailSegmentAppend(segment []byte, record []byte) []byte {
	appended := make([]byte, 0, len(segment)+protowire.SizeTag(mailSegmentRecordField)+protowire.SizeBytes(len(record)))
	appended = append(appended, segment...)
	appended = protowire.AppendTag(appended, mailSegmentRecordField, protowire.BytesType)
	return protowire.AppendBytes(appended, record)
}

// The bytes a record adds to a segment.
func mailSegmentRecordByteCount(record []byte) int {
	return protowire.SizeTag(mailSegmentRecordField) + protowire.SizeBytes(len(record))
}

// An IndexEntry's id and time read off its bytes without decoding the rest, the last of each winning as
// proto.Unmarshal's would. false where either is missing or malformed, or the id is not 16 bytes.
func mailIndexRecordKey(record []byte) (Id, uint64, bool) {
	var id Id
	var timeMillis uint64
	idFound := false
	timeFound := false
	for 0 < len(record) {
		number, wireType, tagByteCount := protowire.ConsumeTag(record)
		if tagByteCount < 0 {
			return Id{}, 0, false
		}
		record = record[tagByteCount:]
		switch {
		case number == mailIndexEntryIdField && wireType == protowire.BytesType:
			value, valueByteCount := protowire.ConsumeBytes(record)
			if valueByteCount < 0 {
				return Id{}, 0, false
			}
			idFound = len(value) == len(id)
			if idFound {
				copy(id[:], value)
			}
			record = record[valueByteCount:]
		case number == mailIndexEntryTimeField && wireType == protowire.VarintType:
			value, valueByteCount := protowire.ConsumeVarint(record)
			if valueByteCount < 0 {
				return Id{}, 0, false
			}
			timeMillis, timeFound = value, true
			record = record[valueByteCount:]
		default:
			valueByteCount := protowire.ConsumeFieldValue(number, wireType, record)
			if valueByteCount < 0 {
				return Id{}, 0, false
			}
			record = record[valueByteCount:]
		}
	}
	return id, timeMillis, idFound && timeFound && timeMillis != 0
}

// The month's segment numbers, ascending, from a listing of i/<yyyymm> or f/<yyyymm>: names that are not <n> are
// passed over, as a newer writer's would be.
func mailSegmentNumbers(names []string) []uint64 {
	numbers := []uint64{}
	for _, name := range names {
		if n, ok := ParseMailSegmentNumber(name); ok {
			numbers = append(numbers, n)
		}
	}
	slices.Sort(numbers)
	return slices.Compact(numbers)
}

// The month's segment numbers in directory, none where it does not stand.
func mailListSegments(ctx context.Context, store mailStore, directory string) ([]uint64, error) {
	names, err := store.List(ctx, directory)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mailSegmentNumbers(names), nil
}

// An entry's record, or ErrMailIndexEntryUnfit for one no segment holds.
func mailIndexEntryRecord(entry *protocol.IndexEntry) ([]byte, error) {
	if len(entry.GetId()) != len(Id{}) || entry.GetTime() == 0 {
		return nil, fmt.Errorf("%w: an id of %d bytes at time %d", ErrMailIndexEntryUnfit, len(entry.GetId()), entry.GetTime())
	}
	record, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMailIndexEntryUnfit, err)
	}
	if MailIndexEntryMaxByteCount < len(record) {
		return nil, fmt.Errorf("%w: %d bytes", ErrMailIndexEntryUnfit, len(record))
	}
	return record, nil
}

// What an append did.
type MailIndexAppend struct {
	// The segment the entry sits in, and its version: the one written, or the one that already held the entry.
	Path    string
	Version uint64
	// The entry stood in the newest segment already, so only the other writes went.
	Present bool
	// Each other write's new version, in order, none when nothing was written.
	WithVersions []uint64
}

// Appends IndexEntry records to one mailbox's or group repo's i/ (§15.7). Safe for concurrent use.
type MailIndexWriter struct {
	store    mailStore
	settings *MailStoreSettings
}

// A writer appending to store's i/.
func NewMailIndexWriter(store mailStore, settings *MailStoreSettings) *MailIndexWriter {
	return &MailIndexWriter{store: store, settings: settings}
}

// Appends entry to its month's newest segment, or to the next one where it would pass a bound, together with with,
// the other paths of the same push: ingest's m/ creation (§15.7). A conflict on the segment reads again, at most
// WriteRetryCount times; a conflict on any of with comes back at once, since only the caller knows what it means. A
// directory full (IsMailDirectoryFull) comes back as evs gave it, never retried.
func (self *MailIndexWriter) Append(ctx context.Context, entry *protocol.IndexEntry, with ...*mailStoreWrite) (*MailIndexAppend, error) {
	record, err := mailIndexEntryRecord(entry)
	if err != nil {
		return nil, err
	}
	id, _ := IdFromBytes(entry.GetId())
	month := MailYearMonthOf(entry.GetTime())
	directory := MailIndexDirectory(month)
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		write, present, err := self.plan(ctx, directory, month, id, record)
		if err != nil {
			return nil, err
		}
		writes := with
		if !present {
			writes = append([]*mailStoreWrite{write}, with...)
		}
		result := &MailIndexAppend{Path: write.Path, Version: write.IfVersion, Present: present}
		if len(writes) == 0 {
			return result, nil
		}
		testHookBarrier("mail.index.write.before", "")
		versions, err := self.store.Write(ctx, writes)
		testHookBarrier("mail.index.write.after", "")
		if err == nil {
			if !present {
				result.Version, versions = versions[0], versions[1:]
			}
			result.WithVersions = versions
			return result, nil
		}
		if !mailStoreConflictOn(err, write.Path) || slices.ContainsFunc(with, func(other *mailStoreWrite) bool {
			return mailStoreConflictOn(err, other.Path)
		}) || self.settings.WriteRetryCount <= attempt {
			return nil, err
		}
	}
}

// The segment write that appends record: to the newest segment while it fits, else creating the next. present when
// the newest segment holds id already, the write then naming that segment as read.
func (self *MailIndexWriter) plan(ctx context.Context, directory string, month MailYearMonth, id Id, record []byte) (*mailStoreWrite, bool, error) {
	numbers, err := mailListSegments(ctx, self.store, directory)
	if err != nil {
		return nil, false, err
	}
	if len(numbers) == 0 {
		return &mailStoreWrite{Path: MailIndexPath(month, 0), Content: mailSegmentAppend(nil, record)}, false, nil
	}
	n := numbers[len(numbers)-1]
	path := MailIndexPath(month, n)
	segment, version, err := self.store.Read(ctx, path, mailIndexSegmentReadMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		// listed, then removed: create it again, which a racing writer's creation turns into a conflict
		return &mailStoreWrite{Path: path, Content: mailSegmentAppend(nil, record)}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	count := 0
	present := false
	err = mailSegmentRecords(segment, func(index int, existing []byte) error {
		count += 1
		if existingId, _, ok := mailIndexRecordKey(existing); ok && existingId == id {
			present = true
		}
		return nil
	})
	if present {
		return &mailStoreWrite{Path: path, IfVersion: version}, true, nil
	}
	// a segment that does not parse is closed: nothing is appended to bytes no reader can walk past
	if err == nil && count < MailIndexSegmentMaxEntryCount && len(segment)+mailSegmentRecordByteCount(record) <= MailIndexSegmentMaxByteCount {
		return &mailStoreWrite{Path: path, Content: mailSegmentAppend(segment, record), IfVersion: version}, false, nil
	}
	return &mailStoreWrite{Path: MailIndexPath(month, n+1), Content: mailSegmentAppend(nil, record)}, false, nil
}
