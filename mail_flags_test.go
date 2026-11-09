// MAIL-M7-06's flags: ops merge to the same winners in any order, byte for byte against protoc's vectors on every
// leg; the writer appends one op a change, closes a segment at 4,096 ops, clocks each op past what it read and reads
// again after a racing write; malformed ops are passed over; and the clock never runs backward. Every name is
// synthetic.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A clock a test sets.
type mailTestClock struct {
	now time.Time
}

func (self *mailTestClock) Now() time.Time { return self.now }
func (self *mailTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}
func (self *mailTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

// A flag_merges vector's segment, from its hex and from its text, which must agree.
func testMailFlagVectorSegment(t *testing.T, item mailVectorItem, key string) *protocol.MailFlagSegment {
	t.Helper()
	encoded, err := hex.DecodeString(item[key])
	if err != nil {
		t.Fatal(err)
	}
	fromBytes := &protocol.MailFlagSegment{}
	if err := proto.Unmarshal(encoded, fromBytes); err != nil {
		t.Fatal(err)
	}
	fromText := &protocol.MailFlagSegment{}
	if err := prototext.Unmarshal([]byte(item[key+"_text"]), fromText); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(fromBytes, fromText) {
		t.Fatalf("%s: %s's bytes and text differ", item["name"], key)
	}
	return fromBytes
}

// Every order of a vector's ops merges to protoc's winners, byte for byte: each rotation and reversal, then shuffles
// from fixed seeds, so the result is the same on every leg and in every run.
func TestMailFlagsConvergeInAnyOrder(t *testing.T) {
	items := parseMailVectors(t)["flag_merges"]
	if len(items) == 0 {
		t.Fatal("no flag merges")
	}
	for _, item := range items {
		ops := testMailFlagVectorSegment(t, item, "ops").GetOps()
		winners, err := hex.DecodeString(item["winners"])
		if err != nil {
			t.Fatal(err)
		}
		orders := [][]*protocol.MailFlagOp{}
		for rotation := range ops {
			rotated := append(slices.Clone(ops[rotation:]), ops[:rotation]...)
			orders = append(orders, rotated)
			reversed := slices.Clone(rotated)
			slices.Reverse(reversed)
			orders = append(orders, reversed)
		}
		for seed := range uint64(64) {
			shuffled := slices.Clone(ops)
			rand.New(rand.NewPCG(seed, 0x6d61696c)).Shuffle(len(shuffled), func(i int, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			orders = append(orders, shuffled)
		}
		for number, order := range orders {
			merger := newMailFlagMerger(nil)
			for _, op := range order {
				if !merger.add(op) {
					t.Fatalf("%s: a vector op was refused", item["name"])
				}
			}
			got, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailFlagSegment{Ops: merger.winners()})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, winners) {
				t.Fatalf("%s, order %d: winners %x", item["name"], number, got)
			}
		}
	}
}

// The vector's winners read as flags: an equal clock broken by the writer, a set over a clear at one writer's equal
// clock, the later verdict, a trash dated by its clock, and a label.
func TestMailFlagsOfTheVector(t *testing.T) {
	items := parseMailVectors(t)["flag_merges"]
	merger := newMailFlagMerger(nil)
	if err := merger.addSegment(testMailHex(t, items[0]["ops"])); err != nil {
		t.Fatal(err)
	}
	a := merger.flags(Id(bytes.Repeat([]byte{0x11}, 16)))
	if a.Seen || !a.Flagged || a.Trash || !slices.Equal(a.Labels, []string{MailLabelNotSpam}) || !a.VerdictNotSpam || a.VerdictSpam {
		t.Errorf("a: %+v", a)
	}
	b := merger.flags(Id(bytes.Repeat([]byte{0x22}, 16)))
	if !b.Seen || b.Flagged || !b.Trash || b.TrashTimeMillis != 1793923200000 || !b.HasLabel("work") || b.VerdictSpam || b.VerdictNotSpam {
		t.Errorf("b: %+v", b)
	}
	if none := merger.flags(testMailId(9)); none.Seen || none.Trash || len(none.Labels) != 0 {
		t.Errorf("a message with no ops: %+v", none)
	}
}

// A hex value of a vector.
func testMailHex(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// A person who set both verdicts holds the later one, whichever order the two ops arrive in.
func TestMailFlagsLaterVerdictWins(t *testing.T) {
	message := testMailId(1)
	writer := testMailId(7)
	spam := &protocol.MailFlagOp{MessageId: message.Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: MailLabelSpam, Hlc: 50, SidecarId: writer.Bytes()}
	notSpam := &protocol.MailFlagOp{MessageId: message.Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: MailLabelNotSpam, Hlc: 60, SidecarId: writer.Bytes()}
	for _, order := range [][]*protocol.MailFlagOp{{spam, notSpam}, {notSpam, spam}} {
		merger := newMailFlagMerger(nil)
		for _, op := range order {
			merger.add(op)
		}
		if flags := merger.flags(message); flags.VerdictSpam || !flags.VerdictNotSpam {
			t.Errorf("%+v", flags)
		}
	}
}

// An op a reader cannot order is passed over and counted, and the rest still merge: a short id or writer, an op
// MAIL-FORMAT.md does not have, a label on a seen op, an empty or 65-byte label, and bytes that do not decode.
func TestMailFlagMergerPassesOverMalformedOps(t *testing.T) {
	message := testMailId(1).Bytes()
	writer := testMailId(2).Bytes()
	good := &protocol.MailFlagOp{MessageId: message, Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true, Hlc: 9, SidecarId: writer}
	bad := []*protocol.MailFlagOp{
		{MessageId: message[:15], Op: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true, Hlc: 10, SidecarId: writer},
		{MessageId: message, Op: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true, Hlc: 10, SidecarId: writer[:3]},
		{MessageId: message, Op: protocol.MailFlagKind(9), Set: true, Hlc: 10, SidecarId: writer},
		{MessageId: message, Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: false, Label: "x", Hlc: 10, SidecarId: writer},
		{MessageId: message, Op: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Hlc: 10, SidecarId: writer},
		{MessageId: message, Op: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: strings.Repeat("l", 65), Hlc: 10, SidecarId: writer},
	}
	segment := []byte{}
	for _, op := range append(bad, good) {
		record, err := proto.Marshal(op)
		if err != nil {
			t.Fatal(err)
		}
		segment = mailSegmentAppend(segment, record)
	}
	segment = mailSegmentAppend(segment, []byte{0x08, 0xff})
	merger := newMailFlagMerger(nil)
	if err := merger.addSegment(segment); err != nil {
		t.Fatal(err)
	}
	if merger.invalidCount != len(bad)+1 {
		t.Errorf("%d passed over", merger.invalidCount)
	}
	if flags := merger.flags(testMailId(1)); !flags.Seen || flags.Flagged || len(flags.Labels) != 0 {
		t.Errorf("%+v", flags)
	}
}

// One op a change, in one push across months, each under its message's month, clocked by the writer's clock with its
// sidecar id; a 4,096th op fills a segment and the next starts the following one, in the same push.
func TestMailFlagWriterAppendsAndClosesAtTheOpBound(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	writerId := testMailId(77)
	writer := NewMailFlagWriter(store, NewMailHlc(clock), writerId, DefaultMailStoreSettings())
	november, december := MailYearMonth(202611), MailYearMonth(202612)
	full := []byte{}
	for index := range MailFlagSegmentMaxOpCount - 1 {
		record, _ := proto.Marshal(&protocol.MailFlagOp{MessageId: testMailId(uint64(index)).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true, Hlc: 5, SidecarId: testMailId(1).Bytes()})
		full = mailSegmentAppend(full, record)
	}
	store.put(MailFlagPath(november, 0), full)
	ops, err := writer.Apply(ctx, []*MailFlagChange{
		{Month: november, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true},
		{Month: december, MessageId: testMailId(2), Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: "work"},
		{Month: november, MessageId: testMailId(3), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true},
	})
	if err != nil || len(ops) != 3 || store.writeCount != 1 {
		t.Fatalf("%d ops, %v, %d writes", len(ops), err, store.writeCount)
	}
	for index, op := range ops {
		if !bytes.Equal(op.GetSidecarId(), writerId.Bytes()) || MailHlcWallMillis(op.GetHlc()) != 1793923200000 {
			t.Errorf("op %d: %v", index, op)
		}
		if 0 < index && op.GetHlc() <= ops[index-1].GetHlc() {
			t.Errorf("op %d's clock does not rise", index)
		}
	}
	count := func(path string) int {
		file := store.file(path)
		if file == nil {
			return 0
		}
		n := 0
		mailSegmentRecords(file.content, func(index int, record []byte) error { n += 1; return nil })
		return n
	}
	if count(MailFlagPath(november, 0)) != MailFlagSegmentMaxOpCount || count(MailFlagPath(november, 1)) != 1 || count(MailFlagPath(december, 0)) != 1 {
		t.Errorf("segments hold %d, %d and %d", count(MailFlagPath(november, 0)), count(MailFlagPath(november, 1)), count(MailFlagPath(december, 0)))
	}
	// a full segment takes nothing more: the next op goes to the newest
	if _, err := writer.Apply(ctx, []*MailFlagChange{{Month: november, MessageId: testMailId(4), Kind: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true}}); err != nil {
		t.Fatal(err)
	}
	if count(MailFlagPath(november, 0)) != MailFlagSegmentMaxOpCount || count(MailFlagPath(november, 1)) != 2 {
		t.Errorf("after the next op: %d and %d", count(MailFlagPath(november, 0)), count(MailFlagPath(november, 1)))
	}
}

// Another device's op clocked ahead of this device's wall: this device's next op on the key orders after it, so a
// person's latest act wins though the clocks disagree.
func TestMailFlagWriterTicksPastWhatItRead(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	month := MailYearMonth(202611)
	ahead := MailHlcTick(0, 1793923200000+3_600_000)
	record, _ := proto.Marshal(&protocol.MailFlagOp{MessageId: testMailId(1).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true, Hlc: ahead, SidecarId: testMailId(2).Bytes()})
	store.put(MailFlagPath(month, 0), mailSegmentAppend(nil, record))
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	writer := NewMailFlagWriter(store, NewMailHlc(clock), testMailId(1), DefaultMailStoreSettings())
	ops, err := writer.Apply(ctx, []*MailFlagChange{{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: false}})
	if err != nil || ops[0].GetHlc() <= ahead {
		t.Fatalf("%v, %v", ops, err)
	}
	merger := newMailFlagMerger(nil)
	merger.addSegment(store.file(MailFlagPath(month, 0)).content)
	if merger.flags(testMailId(1)).Seen {
		t.Error("the later act lost")
	}
}

// A racing write between the read and the write: the writer reads again, ticks new clocks past the racer's, and both
// ops stand.
func TestMailFlagWriterReadsAgainAfterARacingWrite(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	month := MailYearMonth(202611)
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	writer := NewMailFlagWriter(store, NewMailHlc(clock), testMailId(1), DefaultMailStoreSettings())
	racer := NewMailFlagWriter(store, NewMailHlc(clock), testMailId(2), DefaultMailStoreSettings())
	store.beforeWrite = func() {
		if _, err := racer.Apply(ctx, []*MailFlagChange{{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true}}); err != nil {
			t.Error(err)
		}
	}
	ops, err := writer.Apply(ctx, []*MailFlagChange{{Month: month, MessageId: testMailId(5), Kind: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: false}})
	if err != nil || store.writeCount != 3 {
		t.Fatalf("%v after %d writes", err, store.writeCount)
	}
	merger := newMailFlagMerger(nil)
	merger.addSegment(store.file(MailFlagPath(month, 0)).content)
	if len(merger.winners()) != 1 || merger.flags(testMailId(5)).Flagged || ops[0].GetHlc() <= MailHlcTick(0, 1793923200000) {
		t.Errorf("winners %v", merger.winners())
	}
}

// A change no op can say is refused before anything is read.
func TestMailFlagWriterRefusesAChangeNoOpCanSay(t *testing.T) {
	ctx := context.Background()
	for _, change := range []*MailFlagChange{
		{Month: 202611, Kind: protocol.MailFlagKind_MAIL_FLAG_KIND_UNSPECIFIED},
		{Month: 202611, Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Label: "x"},
		{Month: 202611, Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL},
		{Month: 202611, Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Label: strings.Repeat("l", MailFlagLabelMaxByteCount+1)},
		{Month: 202611, Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Label: "\xff"},
	} {
		store := newMailTestStore()
		writer := NewMailFlagWriter(store, NewMailHlc(&mailTestClock{now: time.UnixMilli(1)}), testMailId(1), DefaultMailStoreSettings())
		if _, err := writer.Apply(ctx, []*MailFlagChange{change}); !errors.Is(err, ErrMailFlagChangeInvalid) || store.readCount != 0 {
			t.Errorf("%+v: %v", change, err)
		}
	}
}

// The clock: a wall stepping back keeps it rising by one, an observed op raises it, and it stops at its top rather
// than wrapping below every op.
func TestMailHlcNeverRunsBackward(t *testing.T) {
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	hlc := NewMailHlc(clock)
	first := hlc.Tick()
	clock.now = clock.now.Add(-time.Hour)
	if second := hlc.Tick(); second != first+1 {
		t.Errorf("after the wall stepped back: %d, %d", first, second)
	}
	hlc.Observe(first + 1000)
	if third := hlc.Tick(); third != first+1001 {
		t.Errorf("after an observed op: %d", third-first)
	}
	hlc.Observe(^uint64(0))
	if top := hlc.Tick(); top != ^uint64(0) || hlc.Tick() != ^uint64(0) {
		t.Errorf("at the top: %d", top)
	}
	if MailHlcWallMillis(MailHlcTick(0, 1793923200000)) != 1793923200000 {
		t.Error("the wall does not read back")
	}
}
