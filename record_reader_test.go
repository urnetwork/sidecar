//go:build !sidecar_http

// record_reader.go on sidecartest's streams and authorization state (§22.6's record.proto headers): a v1 reader keeping
// an entry of an unknown kind with an unknown header field, verified over its stored bytes and shown generically; a
// withheld entry kept as a gap, a rewritten one as a fork; a forged writer refused; a body whose commitment fails shown
// invalid with its header standing; erased entries verifying by header and chain; and a stream wound back below the
// reader's pins after a restart alarming. External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A reader of the world's vault, its alarms kept.
type testRecordReader struct {
	reader *sidecar.RecordReader
	store  sidecar.SidecarStore

	stateLock sync.Mutex
	alarms    []*sidecar.RecordAlarm
}

// The world's reader, over store (a fresh one when nil) and streams (the world's own reach when nil).
func (self *testRecordWorld) newReader(store sidecar.SidecarStore, streams sidecar.RecordStreams) *testRecordReader {
	self.t.Helper()
	if store == nil {
		files := sidecartest.NewFakeStore()
		directory, err := files.Root().Directory("record", "record")
		if err != nil {
			self.t.Fatal(err)
		}
		store = directory
	}
	if streams == nil {
		streams = self.streams.For(self.readerId)
	}
	reader := &testRecordReader{store: store}
	reader.reader = sidecar.NewRecordReader(&sidecar.RecordReaderArgs{
		SidecarId: self.readerId,
		Store:     store,
		Streams:   func() sidecar.RecordStreams { return streams },
		Auth:      func() sidecar.RecordAuthView { return self.auth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, alarm)
		},
		Clock:    self.clock,
		Settings: sidecar.DefaultSidecarSettings().Record,
	})
	return reader
}

// The reasons raised so far, in order.
func (self *testRecordReader) reasons() []sidecar.SidecarRecordAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reasons := []sidecar.SidecarRecordAlarm{}
	for _, alarm := range self.alarms {
		reasons = append(reasons, alarm.Reason)
	}
	return reasons
}

// Syncs the vault, which must succeed, and answers its entries.
func (self *testRecordReader) sync(t *testing.T, world *testRecordWorld) []*sidecar.RecordReadEntry {
	t.Helper()
	if err := self.reader.Sync(t.Context(), world.vaultId); err != nil {
		t.Fatal(err)
	}
	return self.reader.Entries(world.vaultId)
}

// A chain of a device's entries made by hand: its own chain store, so a test can withhold, rewrite or forge.
type testRecordHandChain struct {
	device *testRecordDevice
	env    *sidecar.RecordSealEnv
}

func (self *testRecordDevice) handChain() *testRecordHandChain {
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("hand", "hand")
	if err != nil {
		self.t.Fatal(err)
	}
	return &testRecordHandChain{
		device: self,
		env:    &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, self.sidecarId), Sign: self.sign},
	}
}

// Seals a note as the chain's next entry.
func (self *testRecordHandChain) seal(text string) *sidecar.RecordSealedEntry {
	self.device.t.Helper()
	sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
		LogId:         self.device.world.vaultId,
		Kind:          sidecar.RecordKindNote,
		Source:        sidecar.RecordSourceAgent,
		TimeMillis:    self.device.world.clock.Now().UnixMilli(),
		Tainted:       true,
		PolicyVersion: self.device.world.auth.Tip().Pin().GetVersion(),
		Body:          &protocol.CoordinationBody{Text: text},
	})
	if err != nil {
		self.device.t.Fatal(err)
	}
	return sealed
}

// Pushes entries to the device's own stream as one push at counters, each row as given (key || salt when nil).
func (self *testRecordDevice) pushHand(counters []uint64, entries []*sidecar.RecordSealedEntry, rows [][]byte) {
	self.t.Helper()
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: self.sidecarId,
		SlotId:          sidecar.NewId(),
		AuthPin:         self.world.auth.Tip().Pin(),
	}
	for index, sealed := range entries {
		path, err := sidecar.RecordStreamPath(counters[index])
		if err != nil {
			self.t.Fatal(err)
		}
		row := sealed.SlotRow(uint32(index)).Row
		if rows != nil && rows[index] != nil {
			row = rows[index]
		}
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: uint32(index), Row: row})
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: sealed.EntryBytes(&push.SlotId, uint32(index))})
	}
	if _, err := self.world.streams.For(self.sidecarId).Append(self.t.Context(), self.world.vaultId, push); err != nil {
		self.t.Fatal(err)
	}
}

// §22.6: a v1 reader verifies and keeps an entry whose kind it does not know and whose header carries a field it
// cannot name, over the header's stored bytes, so the next entry chains on it with no alarm; it shows it generically.
func TestRecordReaderKeepsAnUnknownKindAndField(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.seal("first")
	// an entry from a later version: kind 1,500 and header field 99, sealed by hand
	head, err := hand.env.Chain.Head(world.vaultId)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x31}, 32)
	salt := bytes.Repeat([]byte{0x32}, 32)
	body := []byte("a body this build cannot parse")
	commitment, err := sidecar.RecordBodyCommitment(salt, body)
	if err != nil {
		t.Fatal(err)
	}
	entryId := sidecar.NewId()
	header := &protocol.RecordHeader{
		EntryId:         entryId.Bytes(),
		LogId:           world.vaultId.Bytes(),
		WriterSidecarId: device.sidecarId.Bytes(),
		Seq:             head.Seq + 1,
		PrevSha256:      head.Leaf[:],
		Kind:            1500,
		TimeMillis:      world.clock.Now().UnixMilli(),
		Source:          uint32(sidecar.RecordSourceObserved),
		BodyCommitment:  commitment[:],
		PolicyVersion:   world.auth.Tip().Pin().GetVersion(),
	}
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	headerBytes = protowire.AppendTag(headerBytes, 99, protowire.BytesType)
	headerBytes = protowire.AppendBytes(headerBytes, []byte("a field from later"))
	signed, err := device.sign(sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x33}, chacha20poly1305.NonceSizeX)
	aad := append(append([]byte("urnetwork-sidecar-v1/record-seal"), world.vaultId[:]...), entryId[:]...)
	unknown := &sidecar.RecordSealedEntry{
		LogId:      world.vaultId,
		EntryId:    entryId,
		Seq:        head.Seq + 1,
		Leaf:       sidecar.RecordLeafHash(headerBytes),
		Signed:     signedBytes,
		SealedBody: aead.Seal(bytes.Clone(nonce), nonce, body, aad),
		Key:        key,
		Salt:       salt,
	}
	if _, err := hand.env.Chain.Adopt(world.vaultId, sidecar.RecordChainHead{Seq: unknown.Seq, Leaf: unknown.Leaf}); err != nil {
		t.Fatal(err)
	}
	after := hand.seal("after")
	device.pushHand([]uint64{1, 2, 3}, []*sidecar.RecordSealedEntry{first, unknown, after}, nil)

	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries kept", len(entries))
	}
	kept := entries[1]
	if kept.Kind() != 1500 || kept.Kind().Known() || kept.State != sidecar.RecordEntryLive || !bytes.Equal(kept.Body, body) {
		t.Errorf("the unknown kind: %s, %s, %q", kept.Kind(), kept.State, kept.Body)
	}
	if !bytes.Equal(kept.Header.Bytes, headerBytes) {
		t.Error("the header was not kept as stored")
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	// the leaf is the stored bytes', the unknown field among them, so the next entry chained on it with no alarm
	if kept.Leaf != sidecar.RecordLeafHash(headerBytes) {
		t.Error("the leaf is not the stored header's")
	}
}

// A withheld entry leaves a gap, kept and alarmed at once from a writer that does not deposit; a rewritten entry is a
// fork, both kept, the later one shown forked, and alarmed.
func TestRecordReaderKeepsAGapAndAFork(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.seal("first")
	second := hand.seal("second")
	third := hand.seal("third")
	device.pushHand([]uint64{1, 2}, []*sidecar.RecordSealedEntry{first, third}, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 2 || entries[1].State != sidecar.RecordEntryLive {
		t.Fatalf("after a gap: %d entries", len(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmChainGap}) {
		t.Fatalf("a gap raised %v", reasons)
	}
	// the withheld entry arrives, and a rewrite of it from a restored backup
	device.pushHand([]uint64{3}, []*sidecar.RecordSealedEntry{second}, nil)
	restored := device.handChain()
	if _, err := restored.env.Chain.Adopt(world.vaultId, sidecar.RecordChainHead{Seq: first.Seq, Leaf: first.Leaf}); err != nil {
		t.Fatal(err)
	}
	rewritten := restored.seal("second, rewritten")
	device.pushHand([]uint64{4}, []*sidecar.RecordSealedEntry{rewritten}, nil)
	entries = reader.sync(t, world)
	if len(entries) != 4 {
		t.Fatalf("%d entries after the fork", len(entries))
	}
	states := []sidecar.RecordEntryState{}
	for _, entry := range entries {
		states = append(states, entry.State)
	}
	want := []sidecar.RecordEntryState{sidecar.RecordEntryLive, sidecar.RecordEntryLive, sidecar.RecordEntryLive, sidecar.RecordEntryForked}
	if !slices.Equal(states, want) {
		t.Errorf("states %v", states)
	}
	if reasons := reader.reasons(); !slices.Contains(reasons, sidecar.SidecarRecordAlarmChainFork) {
		t.Errorf("a fork raised %v", reasons)
	}
}

// An entry signed by another key than its writer's, or for another log, is ignored and alarmed: no entry shows.
func TestRecordReaderRefusesAForgedWriter(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	forger := device.handChain()
	forger.env.Sign = func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  device.sidecarId.Bytes(),
			Signature: ed25519.Sign(otherKey, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	forged := forger.seal("forged")
	device.pushHand([]uint64{1}, []*sidecar.RecordSealedEntry{forged}, nil)
	reader := world.newReader(nil, nil)
	if entries := reader.sync(t, world); len(entries) != 0 {
		t.Fatalf("a forged entry shows: %d", len(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("a forged writer raised %v", reasons)
	}
}

// A body whose commitment fails shows invalid, its header and chain standing, and alarms.
func TestRecordReaderShowsAnInvalidBodyWithItsHeader(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.seal("first")
	second := hand.seal("second")
	// the right key with another salt: the body opens and does not commit
	badRow := append(bytes.Clone(first.Key), bytes.Repeat([]byte{0x44}, 32)...)
	device.pushHand([]uint64{1, 2}, []*sidecar.RecordSealedEntry{first, second}, [][]byte{badRow, nil})
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 2 || !entries[0].BodyInvalid || entries[0].Body != nil || entries[1].BodyInvalid || entries[1].Body == nil {
		t.Fatalf("an invalid body: %d entries", len(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("an invalid body raised %v", reasons)
	}
}

// An ERASE of an entry's key erases it for every reader: no body, the header and every chain still verifying, and no
// alarm.
func TestRecordReaderErasedEntriesVerifyByHeaderAndChain(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	for _, text := range []string{"one", "two", "three"} {
		testRecordAppend(t, record, testRecordNote(nil, text))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	eraserId := sidecar.NewId()
	if err := world.streams.Grant(world.vaultId, eraserId, sidecartest.RecordStreamsScope{Admin: true}); err != nil {
		t.Fatal(err)
	}
	erase := &sidecar.RecordStreamErase{
		PushId:     sidecar.NewId(),
		Keys:       []*sidecar.RecordSlotKey{{SlotId: stored[1].slotId, KeyIndex: stored[1].keyIndex}},
		SealedNote: []byte("a sealed note"),
	}
	if _, err := world.streams.For(eraserId).Erase(t.Context(), world.vaultId, erase); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("%d entries", len(entries))
	}
	for index, entry := range entries {
		erased := index == 1
		if (entry.State == sidecar.RecordEntryErased) != erased || (entry.Body == nil) != erased {
			t.Errorf("entry %d: %s, body %t", index, entry.State, entry.Body != nil)
		}
	}
	if !reader.reader.Erased(world.vaultId, entries[1].EntryId) {
		t.Error("the erased entry does not read erased")
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("an erasure raised %v", reasons)
	}
}

// evs's view of a stream that a test winds back: it answers as if its newest push were not there.
type testRecordWoundStreams struct {
	sidecar.RecordStreams
	writerId sidecar.Id
}

func (self *testRecordWoundStreams) Streams(ctx context.Context, repoId sidecar.Id) ([]*sidecar.RecordStreamHead, error) {
	heads, err := self.RecordStreams.Streams(ctx, repoId)
	for _, head := range heads {
		if head.SidecarId == self.writerId {
			head.Version -= 1
		}
	}
	return heads, err
}

func (self *testRecordWoundStreams) ReadStream(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) ([]*sidecar.RecordStreamVersion, error) {
	versions, err := self.RecordStreams.ReadStream(ctx, repoId, writerSidecarId, afterVersion)
	if writerSidecarId == self.writerId && 0 < len(versions) {
		versions = versions[:len(versions)-1]
	}
	return versions, err
}

// I-16: a reader's pins outlive it, so after a restart a stream evs winds back below what was read alarms.
func TestRecordReaderPinsCatchAStreamWoundBack(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	testRecordAppend(t, record, testRecordNote(nil, "one"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordAppend(t, record, testRecordNote(nil, "two"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	if entries := reader.sync(t, world); len(entries) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	wound := &testRecordWoundStreams{RecordStreams: world.streams.For(world.readerId), writerId: device.sidecarId}
	restarted := world.newReader(reader.store, wound)
	restarted.sync(t, world)
	if reasons := restarted.reasons(); !slices.Contains(reasons, sidecar.SidecarRecordAlarmChainFork) {
		t.Errorf("a stream wound back raised %v", reasons)
	}
}

// A reader built with no settings or alarm sink reads with the defaults rather than failing.
func TestRecordReaderTakesDefaultSettings(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	testRecordAppend(t, record, testRecordNote(nil, "one"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("record", "record")
	if err != nil {
		t.Fatal(err)
	}
	reader := sidecar.NewRecordReader(&sidecar.RecordReaderArgs{
		SidecarId: world.readerId,
		Store:     store,
		Streams:   func() sidecar.RecordStreams { return world.streams.For(world.readerId) },
		Auth:      func() sidecar.RecordAuthView { return world.auth.Tip() },
	})
	if err := reader.Sync(t.Context(), world.vaultId); err != nil {
		t.Fatal(err)
	}
	if entries := reader.Entries(world.vaultId); len(entries) != 1 || entries[0].Body == nil {
		t.Fatalf("%d entries", len(entries))
	}
}
