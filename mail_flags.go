// §15.7's flags (D-MAIL-5; MAIL-M7-06): f/<yyyymm>/<n>, append-only segments of at most 4,096 MailFlagOp, each a
// change to one key (message_id, op, label) of a message of that month: seen, flagged, a label, trash. Last writer
// wins by MAIL-FORMAT.md's order, which is total over what an op says, so devices holding the same ops agree on every
// key whatever order the ops reached them in: the higher (hlc, sidecar_id, set) wins, hlc as a number, the sidecar id
// as bytes, then set over cleared. The sidecar id breaks two devices' equal clocks, and set one device's two ops
// after its clock stepped back.
//
// A member's flags on a group message sit in that member's own mailbox, under the group message's month and id; the
// group repo's f/ holds what its admins set, its trash among them (§15.7), and a view merges both. The labels sent,
// spam and not-spam are MAIL-FORMAT.md's: a sent copy, and a person's verdicts, which outrank spam_score and train
// s/model. Any other label is the person's own.
//
// MailFlagWriter appends ops as the index writer appends entries: to the month's newest segment while it holds fewer
// than 4,096, then to the next, by a path CAS, reading again on a conflict. An op at its caps takes under 128 bytes, so
// the count binds before any byte bound.
//
// On every leg. Package-level functions are safe for concurrent use, and so is MailFlagWriter; mailFlagMerger is not.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// MAIL-FORMAT.md's labels with a meaning of their own.
const (
	// A sent copy, an ordinary entry the sending device writes (plan-MAIL-small-readings#9).
	MailLabelSent = "sent"
	// A person's verdicts, which outrank spam_score and which s/model trains on.
	MailLabelSpam    = "spam"
	MailLabelNotSpam = "not-spam"
)

// MAIL-FORMAT.md's bounds on f/. Format values.
const (
	MailFlagSegmentMaxOpCount = 4096
	MailFlagLabelMaxByteCount = 64
	// 4,096 ops of under 128 bytes each, with room for a newer writer's fields.
	mailFlagSegmentReadMaxByteCount = 1024 * 1024
)

// A flag change no op can say: an op kind MAIL-FORMAT.md does not have, a label on an op that is not label, or a
// label that is empty, past 64 bytes or not UTF-8. The error never repeats the label (I-13).
var ErrMailFlagChangeInvalid = errors.New("mail flag change invalid")

// MAIL-FORMAT.md's order on two ops of one key: negative when a loses to b, positive when a wins, 0 only for ops
// that say the same.
func MailFlagOpCompare(a *protocol.MailFlagOp, b *protocol.MailFlagOp) int {
	rank := func(set bool) int {
		if set {
			return 1
		}
		return 0
	}
	return cmp.Or(
		cmp.Compare(a.GetHlc(), b.GetHlc()),
		bytes.Compare(a.GetSidecarId(), b.GetSidecarId()),
		cmp.Compare(rank(a.GetSet()), rank(b.GetSet())),
	)
}

// Whether a kind and label make a key MAIL-FORMAT.md allows.
func mailFlagKeyValid(kind protocol.MailFlagKind, label string) bool {
	switch kind {
	case protocol.MailFlagKind_MAIL_FLAG_SEEN, protocol.MailFlagKind_MAIL_FLAG_FLAGGED, protocol.MailFlagKind_MAIL_FLAG_TRASH:
		return label == ""
	case protocol.MailFlagKind_MAIL_FLAG_LABEL:
		return label != "" && len(label) <= MailFlagLabelMaxByteCount && utf8.ValidString(label)
	}
	return false
}

// Whether an op read from f/ says something a reader can order: a 16-byte message and writer, and a key
// MAIL-FORMAT.md allows. A reader passes over any other.
func mailFlagOpValid(op *protocol.MailFlagOp) bool {
	return len(op.GetMessageId()) == len(Id{}) && len(op.GetSidecarId()) == len(Id{}) && mailFlagKeyValid(op.GetOp(), op.GetLabel())
}

// One message's flags, every key merged.
type MailFlags struct {
	Seen    bool
	Flagged bool
	Trash   bool
	// The winning trash op's wall ms, which dates the 30-day shred (§15.7); 0 when not in trash.
	TrashTimeMillis uint64
	// The labels set, sorted.
	Labels []string
	// The person's verdict: the later of spam and not-spam where both are set, so at most one is true.
	VerdictSpam    bool
	VerdictNotSpam bool
}

// Whether label is set.
func (self *MailFlags) HasLabel(label string) bool {
	_, found := slices.BinarySearch(self.Labels, label)
	return found
}

// The winning op of one key, kept small: its clock, its writer as an index into the merger's writers, and its set.
type mailFlagWinner struct {
	hlc     uint64
	writer  uint32
	set     bool
	present bool
}

// A message's winners on its three keys that take no label.
type mailFlagMessage struct {
	seen    mailFlagWinner
	flagged mailFlagWinner
	trash   mailFlagWinner
}

// One label's key on one message.
type mailFlagLabelKey struct {
	messageId Id
	label     string
}

// Merges ops into each key's winner. Not safe for concurrent use.
type mailFlagMerger struct {
	// Each writer's sidecar id, as an op names it, in the order first met.
	writers       [][]byte
	writerIndexes map[Id]uint32
	messages      map[Id]*mailFlagMessage
	labels        map[mailFlagLabelKey]mailFlagWinner
	messageLabels map[Id][]string
	// Which messages to keep: nil keeps every one.
	accept func(messageId Id) bool
	// The ops passed over as malformed, and the highest clock met.
	invalidCount int
	lastHlc      uint64
}

// A merger keeping the messages accept takes, every one when nil.
func newMailFlagMerger(accept func(messageId Id) bool) *mailFlagMerger {
	return &mailFlagMerger{
		writerIndexes: map[Id]uint32{},
		messages:      map[Id]*mailFlagMessage{},
		labels:        map[mailFlagLabelKey]mailFlagWinner{},
		messageLabels: map[Id][]string{},
		accept:        accept,
	}
}

// Whether a beats b, b possibly absent.
func (self *mailFlagMerger) beats(a mailFlagWinner, b mailFlagWinner) bool {
	if !b.present {
		return true
	}
	return 0 < cmp.Or(
		cmp.Compare(a.hlc, b.hlc),
		bytes.Compare(self.writers[a.writer], self.writers[b.writer]),
		cmp.Compare(mailFlagRank(a.set), mailFlagRank(b.set)),
	)
}

// set over cleared, as a number to compare.
func mailFlagRank(set bool) int {
	if set {
		return 1
	}
	return 0
}

// Takes one op, false when it was malformed and passed over.
func (self *mailFlagMerger) add(op *protocol.MailFlagOp) bool {
	if !mailFlagOpValid(op) {
		self.invalidCount += 1
		return false
	}
	self.lastHlc = max(self.lastHlc, op.GetHlc())
	messageId := Id(op.GetMessageId())
	if self.accept != nil && !self.accept(messageId) {
		return true
	}
	writerId := Id(op.GetSidecarId())
	writer, ok := self.writerIndexes[writerId]
	if !ok {
		writer = uint32(len(self.writers))
		self.writers = append(self.writers, writerId.Bytes())
		self.writerIndexes[writerId] = writer
	}
	candidate := mailFlagWinner{hlc: op.GetHlc(), writer: writer, set: op.GetSet(), present: true}
	if op.GetOp() == protocol.MailFlagKind_MAIL_FLAG_LABEL {
		key := mailFlagLabelKey{messageId: messageId, label: op.GetLabel()}
		current, ok := self.labels[key]
		if !ok {
			self.messageLabels[messageId] = append(self.messageLabels[messageId], op.GetLabel())
		}
		if self.beats(candidate, current) {
			self.labels[key] = candidate
		}
		return true
	}
	message := self.messages[messageId]
	if message == nil {
		message = &mailFlagMessage{}
		self.messages[messageId] = message
	}
	var winner *mailFlagWinner
	switch op.GetOp() {
	case protocol.MailFlagKind_MAIL_FLAG_SEEN:
		winner = &message.seen
	case protocol.MailFlagKind_MAIL_FLAG_FLAGGED:
		winner = &message.flagged
	default:
		winner = &message.trash
	}
	if self.beats(candidate, *winner) {
		*winner = candidate
	}
	return true
}

// Takes every op of a segment, passing over each that does not decode or is malformed. ErrMailSegmentInvalid for a
// segment that does not parse, whose ops before the fault are kept.
func (self *mailFlagMerger) addSegment(segment []byte) error {
	return mailSegmentRecords(segment, func(index int, record []byte) error {
		op := &protocol.MailFlagOp{}
		if err := proto.Unmarshal(record, op); err != nil {
			self.invalidCount += 1
			return nil
		}
		self.add(op)
		return nil
	})
}

// One message's flags.
func (self *mailFlagMerger) flags(messageId Id) *MailFlags {
	flags := &MailFlags{Labels: []string{}}
	if message := self.messages[messageId]; message != nil {
		flags.Seen = message.seen.set
		flags.Flagged = message.flagged.set
		flags.Trash = message.trash.set
		if message.trash.set {
			flags.TrashTimeMillis = MailHlcWallMillis(message.trash.hlc)
		}
	}
	for _, label := range self.messageLabels[messageId] {
		if self.labels[mailFlagLabelKey{messageId: messageId, label: label}].set {
			flags.Labels = append(flags.Labels, label)
		}
	}
	slices.Sort(flags.Labels)
	spam := self.labels[mailFlagLabelKey{messageId: messageId, label: MailLabelSpam}]
	notSpam := self.labels[mailFlagLabelKey{messageId: messageId, label: MailLabelNotSpam}]
	switch {
	case spam.set && notSpam.set:
		flags.VerdictSpam = self.beats(spam, notSpam)
		flags.VerdictNotSpam = !flags.VerdictSpam
	default:
		flags.VerdictSpam = spam.set
		flags.VerdictNotSpam = notSpam.set
	}
	return flags
}

// Every key's winning op, ordered by message id, op and label: the state two devices holding the same ops agree on,
// byte for byte, whatever order they met the ops in.
func (self *mailFlagMerger) winners() []*protocol.MailFlagOp {
	ops := []*protocol.MailFlagOp{}
	op := func(messageId Id, kind protocol.MailFlagKind, label string, winner mailFlagWinner) {
		if winner.present {
			ops = append(ops, &protocol.MailFlagOp{
				MessageId: messageId.Bytes(), Op: kind, Set: winner.set, Label: label, Hlc: winner.hlc,
				SidecarId: slices.Clone(self.writers[winner.writer]),
			})
		}
	}
	for _, messageId := range slices.SortedFunc(maps.Keys(self.messages), mailIdCompare) {
		message := self.messages[messageId]
		op(messageId, protocol.MailFlagKind_MAIL_FLAG_SEEN, "", message.seen)
		op(messageId, protocol.MailFlagKind_MAIL_FLAG_FLAGGED, "", message.flagged)
		op(messageId, protocol.MailFlagKind_MAIL_FLAG_TRASH, "", message.trash)
	}
	for _, key := range slices.SortedFunc(maps.Keys(self.labels), func(a mailFlagLabelKey, b mailFlagLabelKey) int {
		return cmp.Or(mailIdCompare(a.messageId, b.messageId), cmp.Compare(a.label, b.label))
	}) {
		op(key.messageId, protocol.MailFlagKind_MAIL_FLAG_LABEL, key.label, self.labels[key])
	}
	slices.SortStableFunc(ops, func(a *protocol.MailFlagOp, b *protocol.MailFlagOp) int {
		return cmp.Or(bytes.Compare(a.GetMessageId(), b.GetMessageId()), cmp.Compare(a.GetOp(), b.GetOp()))
	})
	return ops
}

// Ids as bytes.
func mailIdCompare(a Id, b Id) int {
	return bytes.Compare(a[:], b[:])
}

// One change a person or a device makes to a message's flags.
type MailFlagChange struct {
	// The month of the message it names: its IndexEntry's, the group message's for a group message.
	Month     MailYearMonth
	MessageId Id
	Kind      protocol.MailFlagKind
	// true sets the flag or label, false clears it.
	Set bool
	// With MAIL_FLAG_LABEL only.
	Label string
}

// Writes flag ops to one mailbox's or group repo's f/ (§15.7). Safe for concurrent use.
type MailFlagWriter struct {
	store     mailStore
	hlc       *MailHlc
	sidecarId Id
	settings  *MailStoreSettings
}

// A writer signing its ops' clocks with hlc, the mailbox's clock on this device, as sidecarId.
func NewMailFlagWriter(store mailStore, hlc *MailHlc, sidecarId Id, settings *MailStoreSettings) *MailFlagWriter {
	return &MailFlagWriter{store: store, hlc: hlc, sidecarId: sidecarId, settings: settings}
}

// Appends one op per change, in one push across their months, each clocked after every op the writer read from
// the segments it appends to. A conflict reads again, ticking new clocks, at most WriteRetryCount times. The ops
// written, in the changes' order.
func (self *MailFlagWriter) Apply(ctx context.Context, changes []*MailFlagChange) ([]*protocol.MailFlagOp, error) {
	months := []MailYearMonth{}
	for _, change := range changes {
		if !mailFlagKeyValid(change.Kind, change.Label) {
			return nil, fmt.Errorf("%w: op %d", ErrMailFlagChangeInvalid, change.Kind)
		}
		if !slices.Contains(months, change.Month) {
			months = append(months, change.Month)
		}
	}
	if len(changes) == 0 {
		return []*protocol.MailFlagOp{}, nil
	}
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tails := map[MailYearMonth]*mailFlagTail{}
		for _, month := range months {
			tail, err := self.readTail(ctx, month)
			if err != nil {
				return nil, err
			}
			tails[month] = tail
		}
		ops := make([]*protocol.MailFlagOp, 0, len(changes))
		for _, change := range changes {
			op := &protocol.MailFlagOp{
				MessageId: change.MessageId.Bytes(), Op: change.Kind, Set: change.Set, Label: change.Label,
				Hlc: self.hlc.Tick(), SidecarId: self.sidecarId.Bytes(),
			}
			record, err := proto.MarshalOptions{Deterministic: true}.Marshal(op)
			if err != nil {
				return nil, err
			}
			tails[change.Month].add(record)
			ops = append(ops, op)
		}
		writes := []*mailStoreWrite{}
		for _, month := range months {
			writes = append(writes, tails[month].writes...)
		}
		testHookBarrier("mail.flags.write.before", "")
		_, err := self.store.Write(ctx, writes)
		testHookBarrier("mail.flags.write.after", "")
		if err == nil {
			return ops, nil
		}
		if !errors.Is(err, ErrMailStoreConflict) || self.settings.WriteRetryCount <= attempt {
			return nil, err
		}
	}
}

// Where a month's new ops go: its newest segment while it holds fewer than 4,096, then new segments after it.
type mailFlagTail struct {
	month MailYearMonth
	// The newest segment number, and how many ops it holds.
	n     uint64
	count int
	// The writes so far: the newest segment's first, then each new one's.
	writes []*mailStoreWrite
}

// The month's newest segment as it stands, its ops observed by the clock.
func (self *MailFlagWriter) readTail(ctx context.Context, month MailYearMonth) (*mailFlagTail, error) {
	numbers, err := mailListSegments(ctx, self.store, MailFlagDirectory(month))
	if err != nil {
		return nil, err
	}
	if len(numbers) == 0 {
		return &mailFlagTail{month: month, writes: []*mailStoreWrite{{Path: MailFlagPath(month, 0)}}}, nil
	}
	n := numbers[len(numbers)-1]
	path := MailFlagPath(month, n)
	segment, version, err := self.store.Read(ctx, path, mailFlagSegmentReadMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return &mailFlagTail{month: month, n: n, writes: []*mailStoreWrite{{Path: path}}}, nil
	}
	if err != nil {
		return nil, err
	}
	count := 0
	err = mailSegmentRecords(segment, func(index int, record []byte) error {
		count += 1
		op := &protocol.MailFlagOp{}
		if proto.Unmarshal(record, op) == nil {
			self.hlc.Observe(op.GetHlc())
		}
		return nil
	})
	if err != nil || MailFlagSegmentMaxOpCount <= count {
		// a full segment, or one that does not parse, is closed: the next one starts after it
		return &mailFlagTail{month: month, n: n + 1, writes: []*mailStoreWrite{{Path: MailFlagPath(month, n+1)}}}, nil
	}
	return &mailFlagTail{month: month, n: n, count: count, writes: []*mailStoreWrite{{Path: path, Content: segment, IfVersion: version}}}, nil
}

// Appends record to the newest segment, or to a new one after it once that holds 4,096.
func (self *mailFlagTail) add(record []byte) {
	if MailFlagSegmentMaxOpCount <= self.count {
		self.n += 1
		self.count = 0
		self.writes = append(self.writes, &mailStoreWrite{Path: MailFlagPath(self.month, self.n)})
	}
	last := self.writes[len(self.writes)-1]
	last.Content = mailSegmentAppend(last.Content, record)
	self.count += 1
}
