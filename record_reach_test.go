//go:build !sidecar_http && !ios_extension

// RECORD-M6-02's reach receipts: coalescing on a fake clock across a window edge, a grant ending mid-window, many
// peers past the bound flushing early and dropping nothing, relays from a fixture path, the refusals, a write at
// close, and no visitor address in any byte the record stores, in a personal network's vault and in a team network's
// team record.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A writer that keeps every draft it is handed.
type testReachWriter struct {
	stateLock sync.Mutex
	drafts    []*sidecar.RecordDraft
}

func (self *testReachWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return []*sidecar.RecordEntryRef{{EntryId: sidecar.NewId()}}, nil
}

// The receipts written so far, in order.
func (self *testReachWriter) receipts(t *testing.T) []*protocol.ReachReceipt {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	receipts := []*protocol.ReachReceipt{}
	for _, draft := range self.drafts {
		if draft.Kind != sidecar.RecordKindReach || draft.Source != sidecar.RecordSourceObserved || !draft.NoSession {
			t.Fatalf("a draft of kind %s, source %d", draft.Kind, draft.Source)
		}
		receipt, ok := draft.Body.(*protocol.ReachReceipt)
		if !ok {
			t.Fatalf("a body of %T", draft.Body)
		}
		if !bytes.Equal(draft.GrantId, receipt.GetGrantId()) {
			t.Fatal("the header's grant is not the receipt's")
		}
		receipts = append(receipts, receipt)
	}
	return receipts
}

// Receipts on a fake clock moved to the start of a window, writing to a fake writer.
type testReachEnv struct {
	clock  *sidecartest.FakeClock
	writer *testReachWriter
	reach  *sidecar.RecordReach
	window time.Duration
}

func newTestReachEnv(t *testing.T, settings *sidecar.RecordReachSettings) *testReachEnv {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	recordSettings := sidecar.DefaultSidecarSettings().Record
	window := recordSettings.ReachReceiptCoalesce
	clock.AdvanceTo(clock.Now().Truncate(window).Add(window))
	writer := &testReachWriter{}
	return &testReachEnv{
		clock:  clock,
		writer: writer,
		reach: sidecar.NewRecordReach(&sidecar.RecordReachArgs{
			Writer:         writer,
			Clock:          clock,
			RecordSettings: recordSettings,
			Settings:       settings,
		}),
		window: window,
	}
}

// A grant id of 32 bytes.
func testReachGrantId(seed byte) []byte {
	sum := sha256.Sum256([]byte{seed})
	return sum[:]
}

// A forward through one relay, from a peer sidecar.
func testReachNote(grantId []byte, peerId sidecar.Id) *sidecar.RecordReachNote {
	return &sidecar.RecordReachNote{
		Kind:          sidecar.RecordReachKindForward,
		GrantId:       grantId,
		PolicyVersion: 7,
		Owner:         sidecar.NewId().Bytes(),
		Peers:         [][]byte{peerId.Bytes()},
		StreamCount:   1,
		ByteCount:     1000,
		Relays:        []sidecar.RecordReachRelay{{Host: "relay-1.example", Ip: netip.MustParseAddr("192.0.2.10"), Operator: "example-operator"}},
	}
}

// Notes in one window coalesce into one receipt, written when the window ends; a note in the next window opens the
// next, and a note in a later window closes an earlier receipt its timer has not written yet.
func TestRecordReachCoalescesAcrossAWindowEdge(t *testing.T) {
	env := newTestReachEnv(t, nil)
	windowStart := env.clock.Now()
	grantId := testReachGrantId(1)
	peerId := sidecar.NewId()
	first := testReachNote(grantId, peerId)
	if err := env.reach.Note(first); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(2 * time.Minute)
	second := testReachNote(grantId, peerId)
	second.Owner = first.Owner
	second.StreamCount = 2
	second.ByteCount = 500
	if err := env.reach.Note(second); err != nil {
		t.Fatal(err)
	}
	if receipts := env.writer.receipts(t); len(receipts) != 0 {
		t.Fatalf("%d receipts before the window ended", len(receipts))
	}
	env.clock.Advance(env.window - 2*time.Minute)
	receipts := env.writer.receipts(t)
	if len(receipts) != 1 {
		t.Fatalf("%d receipts at the window's end", len(receipts))
	}
	receipt := receipts[0]
	if receipt.GetStreamCount() != 3 || receipt.GetByteCount() != 1500 || receipt.GetWindowStartMillis() != windowStart.UnixMilli() ||
		receipt.GetKind() != uint32(sidecar.RecordReachKindForward) || receipt.GetPolicyVersion() != 7 ||
		len(receipt.GetPeers()) != 1 || !bytes.Equal(receipt.GetPeers()[0], peerId.Bytes()) || len(receipt.GetRelays()) != 1 {
		t.Fatalf("receipt %v", receipt)
	}

	// the next window: a fresh receipt
	third := testReachNote(grantId, peerId)
	third.Owner = first.Owner
	if err := env.reach.Note(third); err != nil {
		t.Fatal(err)
	}
	if stats := env.reach.Stats(); stats.OpenCount != 1 || stats.WrittenCount != 1 || stats.EarlyCount != 0 {
		t.Fatalf("stats %+v", stats)
	}
	env.clock.Advance(env.window)
	receipts = env.writer.receipts(t)
	if len(receipts) != 2 || receipts[1].GetWindowStartMillis() != windowStart.Add(env.window).UnixMilli() || receipts[1].GetStreamCount() != 1 {
		t.Fatalf("the second window's receipts %v", receipts)
	}
}

// A grant ending mid-window writes its receipt at its end, not the window's; GrantEnded writes a grant's receipts at
// once, and another grant's stay open.
func TestRecordReachGrantEndingMidWindow(t *testing.T) {
	env := newTestReachEnv(t, nil)
	ending := testReachNote(testReachGrantId(1), sidecar.NewId())
	ending.GrantEndMillis = env.clock.Now().Add(90 * time.Second).UnixMilli()
	if err := env.reach.Note(ending); err != nil {
		t.Fatal(err)
	}
	revoked := testReachNote(testReachGrantId(2), sidecar.NewId())
	if err := env.reach.Note(revoked); err != nil {
		t.Fatal(err)
	}
	other := testReachNote(testReachGrantId(3), sidecar.NewId())
	if err := env.reach.Note(other); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(90 * time.Second)
	receipts := env.writer.receipts(t)
	if len(receipts) != 1 || !bytes.Equal(receipts[0].GetGrantId(), ending.GrantId) {
		t.Fatalf("at the grant's end: %v", receipts)
	}
	env.reach.GrantEnded(revoked.GrantId)
	receipts = env.writer.receipts(t)
	if len(receipts) != 2 || !bytes.Equal(receipts[1].GetGrantId(), revoked.GrantId) {
		t.Fatalf("after a revocation: %v", receipts)
	}
	if stats := env.reach.Stats(); stats.OpenCount != 1 {
		t.Fatalf("stats %+v", stats)
	}
	// a note for a grant that ended already is written at once
	late := testReachNote(testReachGrantId(4), sidecar.NewId())
	late.GrantEndMillis = env.clock.Now().Add(-time.Second).UnixMilli()
	if err := env.reach.Note(late); err != nil {
		t.Fatal(err)
	}
	if receipts := env.writer.receipts(t); len(receipts) != 3 || !bytes.Equal(receipts[2].GetGrantId(), late.GrantId) {
		t.Fatalf("an ended grant's note: %v", receipts)
	}
}

// Past ReceiptCount the receipt opened first is written early, never dropped: every stream noted is in some receipt
// once the window ends.
func TestRecordReachManyPeersPastTheBound(t *testing.T) {
	settings := sidecar.DefaultRecordReachSettings()
	settings.ReceiptCount = 4
	env := newTestReachEnv(t, settings)
	grantId := testReachGrantId(1)
	peerCount := 25
	peerIds := []sidecar.Id{}
	for i := 0; i < peerCount; i += 1 {
		peerIds = append(peerIds, sidecar.NewId())
		if err := env.reach.Note(testReachNote(grantId, peerIds[i])); err != nil {
			t.Fatal(err)
		}
	}
	stats := env.reach.Stats()
	if stats.OpenCount != settings.ReceiptCount || stats.EarlyCount != peerCount-settings.ReceiptCount {
		t.Fatalf("stats %+v", stats)
	}
	env.clock.Advance(env.window)
	receipts := env.writer.receipts(t)
	if len(receipts) != peerCount {
		t.Fatalf("%d receipts for %d peers", len(receipts), peerCount)
	}
	streamCount := uint64(0)
	for i, receipt := range receipts {
		streamCount += receipt.GetStreamCount()
		// the oldest first
		if !bytes.Equal(receipt.GetPeers()[0], peerIds[i].Bytes()) {
			t.Fatalf("receipt %d names another peer", i)
		}
	}
	if streamCount != uint64(peerCount) {
		t.Fatalf("%d streams in the receipts, %d noted", streamCount, peerCount)
	}
	if stats := env.reach.Stats(); stats.OpenCount != 0 || stats.WrittenCount != peerCount || stats.FailedCount != 0 {
		t.Fatalf("stats %+v", stats)
	}
}

// relays names each relay or edge of the fixture path once, as host, ip and operator, "-" where not known; a note
// that would pass RelayCount, or that changes the grant's policy version, writes its receipt early and opens the next.
func TestRecordReachRelaysFromAFixturePath(t *testing.T) {
	settings := sidecar.DefaultRecordReachSettings()
	settings.RelayCount = 3
	env := newTestReachEnv(t, settings)
	path := []sidecar.RecordReachRelay{
		{Host: "relay-1.example", Ip: netip.MustParseAddr("192.0.2.10"), Operator: "example-operator"},
		{Host: "edge-2.example", Ip: netip.MustParseAddr("2001:db8::2")},
		{Ip: netip.MustParseAddr("::ffff:198.51.100.3"), Operator: "other-operator"},
	}
	note := testReachNote(testReachGrantId(1), sidecar.NewId())
	note.Relays = path
	if err := env.reach.Note(note); err != nil {
		t.Fatal(err)
	}
	// the same path again adds no relay
	again := *note
	if err := env.reach.Note(&again); err != nil {
		t.Fatal(err)
	}
	env.reach.Flush()
	receipts := env.writer.receipts(t)
	want := []string{
		"relay-1.example 192.0.2.10 example-operator",
		"edge-2.example 2001:db8::2 -",
		"- 198.51.100.3 other-operator",
	}
	if len(receipts) != 1 || len(receipts[0].GetRelays()) != len(want) {
		t.Fatalf("receipts %v", receipts)
	}
	for i, relay := range want {
		if receipts[0].GetRelays()[i] != relay {
			t.Errorf("relay %d: %q, want %q", i, receipts[0].GetRelays()[i], relay)
		}
	}

	if err := env.reach.Note(note); err != nil {
		t.Fatal(err)
	}
	longer := *note
	longer.Relays = []sidecar.RecordReachRelay{{Host: "relay-4.example"}}
	if err := env.reach.Note(&longer); err != nil {
		t.Fatal(err)
	}
	moved := *note
	moved.Relays = nil
	moved.PolicyVersion = 8
	if err := env.reach.Note(&moved); err != nil {
		t.Fatal(err)
	}
	env.reach.Flush()
	receipts = env.writer.receipts(t)
	if len(receipts) != 4 || len(receipts[2].GetRelays()) != 1 || receipts[2].GetRelays()[0] != "relay-4.example - -" ||
		receipts[3].GetPolicyVersion() != 8 {
		t.Fatalf("receipts %v", receipts)
	}
	if stats := env.reach.Stats(); stats.EarlyCount != 2 {
		t.Fatalf("stats %+v", stats)
	}
}

// A note with no peer or both forms of one, a grant id that is no AclGrantId, a kind §16.8 does not name, too many
// relays, or a relay part that is no token is refused, and keeps nothing.
func TestRecordReachRefusesANoteItCannotTake(t *testing.T) {
	env := newTestReachEnv(t, nil)
	base := testReachNote(testReachGrantId(1), sidecar.NewId())
	cases := []func(note *sidecar.RecordReachNote){
		func(note *sidecar.RecordReachNote) { note.Peers = nil },
		func(note *sidecar.RecordReachNote) { note.Visitor = netip.MustParseAddr("203.0.113.7") },
		func(note *sidecar.RecordReachNote) { note.GrantId = note.GrantId[:16] },
		func(note *sidecar.RecordReachNote) { note.Kind = 0 },
		func(note *sidecar.RecordReachNote) { note.Kind = 9 },
		func(note *sidecar.RecordReachNote) { note.ActionId = []byte{1, 2, 3} },
		func(note *sidecar.RecordReachNote) { note.Peers = [][]byte{{}} },
		func(note *sidecar.RecordReachNote) { note.Peers = [][]byte{{1}, {2}, {3}, {4}, {5}} },
		func(note *sidecar.RecordReachNote) { note.Relays = make([]sidecar.RecordReachRelay, 17) },
		func(note *sidecar.RecordReachNote) {
			note.Relays = []sidecar.RecordReachRelay{{Host: "relay one.example"}}
		},
		func(note *sidecar.RecordReachNote) { note.Relays = []sidecar.RecordReachRelay{{Operator: "-"}} },
		func(note *sidecar.RecordReachNote) { note.Relays = []sidecar.RecordReachRelay{{Operator: "op\u202e"}} },
	}
	for i, change := range cases {
		note := *base
		change(&note)
		if err := env.reach.Note(&note); !errors.Is(err, sidecar.ErrRecordReachNoteInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if err := env.reach.Note(nil); !errors.Is(err, sidecar.ErrRecordReachNoteInvalid) {
		t.Errorf("a nil note: %v", err)
	}
	env.reach.Close()
	if stats := env.reach.Stats(); stats.OpenCount != 0 || stats.WrittenCount != 0 {
		t.Fatalf("a refused note kept something: %+v", stats)
	}
}

// Close writes every open receipt, and a note after it is written at once, alone.
func TestRecordReachCloseWritesWhatIsOpen(t *testing.T) {
	env := newTestReachEnv(t, nil)
	for seed := byte(1); seed <= 3; seed += 1 {
		if err := env.reach.Note(testReachNote(testReachGrantId(seed), sidecar.NewId())); err != nil {
			t.Fatal(err)
		}
	}
	env.reach.Close()
	if receipts := env.writer.receipts(t); len(receipts) != 3 {
		t.Fatalf("%d receipts at close", len(receipts))
	}
	if pending := env.clock.PendingTimers(); len(pending) != 0 {
		t.Fatalf("timers left at close: %v", pending)
	}
	if err := env.reach.Note(testReachNote(testReachGrantId(4), sidecar.NewId())); err != nil {
		t.Fatal(err)
	}
	if receipts := env.writer.receipts(t); len(receipts) != 4 {
		t.Fatalf("%d receipts after a note past close", len(receipts))
	}
}

// A public visitor is one keyed hash per interval: the same address, IPv4-mapped or not, one peer; another address
// another; the next interval's key another hash for the same address.
func TestRecordReachVisitorPeerIsKeyedPerInterval(t *testing.T) {
	env := newTestReachEnv(t, nil)
	visitor := netip.MustParseAddr("203.0.113.7")
	first, err := env.reach.VisitorPeer(visitor)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := env.reach.VisitorPeer(netip.MustParseAddr("::ffff:203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := env.reach.VisitorPeer(netip.MustParseAddr("2001:db8::7"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != sidecar.DefaultRecordReachSettings().VisitorHashByteCount || !bytes.Equal(first, mapped) || bytes.Equal(first, other) {
		t.Fatalf("hashes %x %x %x", first, mapped, other)
	}
	env.clock.Advance(sidecar.DefaultRecordReachSettings().VisitorKeyInterval)
	next, err := env.reach.VisitorPeer(visitor)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, next) {
		t.Fatal("the next interval hashed the visitor under the same key")
	}
}

// What a stored byte must not hold for a visitor at address: its four or sixteen bytes, or its text.
func testReachHoldsAddress(stored []byte, address netip.Addr) bool {
	sixteen := address.As16()
	return bytes.Contains(stored, address.AsSlice()) || bytes.Contains(stored, sixteen[:]) ||
		bytes.Contains(stored, []byte(address.String()))
}

// A public visitor's publish receipt through a real record in a personal network: the vault's entry names the
// visitor by its keyed hash alone, and no byte the record stores, journal and stream and opened body alike, holds its
// address.
func TestRecordReachNoVisitorAddressInAnyStoredByte(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	visitor := netip.MustParseAddr("203.0.113.7")
	reach := record.Reach()
	if err := reach.Note(&sidecar.RecordReachNote{
		Kind:        sidecar.RecordReachKindPublish,
		GrantId:     testReachGrantId(1),
		Visitor:     visitor,
		StreamCount: 1,
		ByteCount:   2048,
		Relays:      []sidecar.RecordReachRelay{{Host: "tlsedge.example", Ip: netip.MustParseAddr("192.0.2.44"), Operator: "example-operator"}},
	}); err != nil {
		t.Fatal(err)
	}
	reach.Flush()
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 1 || stored[0].header.GetKind() != uint32(sidecar.RecordKindReach) {
		t.Fatalf("stored %d entries", len(stored))
	}
	receipt := &protocol.ReachReceipt{}
	if err := proto.Unmarshal(stored[0].body, receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.GetPeers()) != 1 || len(receipt.GetPeers()[0]) != sidecar.DefaultRecordReachSettings().VisitorHashByteCount ||
		receipt.GetKind() != uint32(sidecar.RecordReachKindPublish) {
		t.Fatalf("receipt %v", receipt)
	}
	for _, item := range stored {
		for _, held := range [][]byte{item.body, item.entry.GetHeader().GetBody(), item.entry.GetSealedBody()} {
			if testReachHoldsAddress(held, visitor) {
				t.Fatal("an entry holds the visitor's address")
			}
		}
	}
	for _, path := range device.files.Paths() {
		contents, _ := device.files.Contents(path)
		if testReachHoldsAddress(contents, visitor) {
			t.Fatalf("%s holds the visitor's address", path)
		}
	}
}

// In a team network a member device's reach entry goes to the team record alone, by deposit, and none to its vault.
func TestRecordReachGoesToTheTeamRecordInTeamMode(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	reach := record.Reach()
	if err := reach.Note(testReachNote(testReachGrantId(1), sidecar.NewId())); err != nil {
		t.Fatal(err)
	}
	reach.Flush()
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposited := world.teamDeposits(device.sidecarId, admin.sidecarId)
	reachCount := 0
	for _, entry := range deposited {
		if entry.header.Kind() == sidecar.RecordKindReach {
			reachCount += 1
		}
	}
	if reachCount != 1 {
		t.Fatalf("%d reach entries deposited to the team record", reachCount)
	}
	for _, item := range world.storedEntries(device.sidecarId) {
		if item.header.GetKind() == uint32(sidecar.RecordKindReach) {
			t.Fatal("a reach entry in the vault in team mode")
		}
	}
}
