// record_chain.go's chain and journal, on sidecartest's store and streams: seq from 1 on 32 zero bytes, then each
// prev_sha256 the leaf before; a crash after the journal's fsync re-sending exactly the journaled bytes, and a write
// that never landed leaving its seq to the next entry, so no seq is burned or reused; acknowledgments compacting the
// head into the head file; a restart adopting a higher head from the writer's own stream, only from entries that
// verify, and refusing a fork; corrupt state refused rather than read as a fresh chain; and one log's appends taking
// distinct seqs however they race. External, since sidecartest imports the root.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One writer's record state on a fake store: what survives a crash is the store, and each chain store opened on it is
// one process's life.
type testRecordWriter struct {
	t         *testing.T
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	files     *sidecartest.FakeStore
	store     sidecar.SidecarStore
}

func newTestRecordWriter(t *testing.T) *testRecordWriter {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("record", "record")
	if err != nil {
		t.Fatal(err)
	}
	return &testRecordWriter{t: t, sidecarId: sidecar.NewId(), key: key, files: files, store: store}
}

// What Sidecar.Sign makes with this writer's key.
func (self *testRecordWriter) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// The writer's identity public key.
func (self *testRecordWriter) publicKey() []byte {
	return self.key.Public().(ed25519.PublicKey)
}

// A process's life: a chain store opened on what the store holds now.
func (self *testRecordWriter) open() *sidecar.RecordSealEnv {
	return &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(self.store, self.sidecarId), Sign: self.sign}
}

// A note as an agent's run files it.
func testChainNote(logId sidecar.Id, text string) *sidecar.RecordSealArgs {
	return &sidecar.RecordSealArgs{
		LogId:       logId,
		Kind:        sidecar.RecordKindNote,
		Source:      sidecar.RecordSourceAgent,
		AgentSource: sidecar.RecordAgentSourceNone,
		TimeMillis:  1762387200000,
		Tainted:     true,
		Body:        &protocol.CoordinationBody{Text: text},
	}
}

// Seals count notes, failing the test on any error.
func (self *testRecordWriter) seal(env *sidecar.RecordSealEnv, logId sidecar.Id, count int) []*sidecar.RecordSealedEntry {
	self.t.Helper()
	entries := []*sidecar.RecordSealedEntry{}
	for index := range count {
		sealed, err := sidecar.RecordSeal(env, testChainNote(logId, fmt.Sprintf("note %d", index)))
		if err != nil {
			self.t.Fatal(err)
		}
		entries = append(entries, sealed)
	}
	return entries
}

// The parsed header of a sealed entry.
func testChainHeader(t *testing.T, sealed *sidecar.RecordSealedEntry) *protocol.RecordHeader {
	t.Helper()
	header, err := sealed.Header()
	if err != nil {
		t.Fatal(err)
	}
	return header.Header
}

// Fails unless entries run seq first, first+1, ..., each chaining on the leaf before, the first on prev.
func testRequireChain(t *testing.T, entries []*sidecar.RecordSealedEntry, first uint64, prev [32]byte) {
	t.Helper()
	for index, sealed := range entries {
		header := testChainHeader(t, sealed)
		if sealed.Seq != first+uint64(index) || header.GetSeq() != sealed.Seq {
			t.Fatalf("entry %d is seq %d, want %d", index, sealed.Seq, first+uint64(index))
		}
		if !bytes.Equal(header.GetPrevSha256(), prev[:]) {
			t.Fatalf("seq %d does not chain on the leaf before it", sealed.Seq)
		}
		prev = sealed.Leaf
	}
}

// §16.8's chain: a writer's first entry in a log is seq 1 on 32 zero bytes, and each later one chains on the leaf
// before; another log's chain starts at 1 of its own.
func TestRecordChainStartsAtOneAndChains(t *testing.T) {
	writer := newTestRecordWriter(t)
	env := writer.open()
	logId := sidecar.NewId()
	entries := writer.seal(env, logId, 3)
	testRequireChain(t, entries, 1, [32]byte{})
	head, err := env.Chain.Head(logId)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 3 || head.Leaf != entries[2].Leaf {
		t.Errorf("the head is seq %d", head.Seq)
	}
	other := writer.seal(env, sidecar.NewId(), 1)
	testRequireChain(t, other, 1, [32]byte{})
}

// A crash after the journal's fsync and before the push: the next life finds each entry pending with exactly the
// bytes it signed and sealed, its key and salt, so a re-send is the same entry, never a re-signed one (D-MCP-10), and
// the next entry chains on it.
func TestRecordChainCrashAfterTheFsyncResendsTheSameBytes(t *testing.T) {
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	sealed := writer.seal(writer.open(), logId, 2)

	env := writer.open()
	pending, err := env.Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("%d pending", len(pending))
	}
	slotId := sidecar.NewId()
	for index, entry := range pending {
		was := sealed[index]
		if entry.Seq != was.Seq || entry.EntryId != was.EntryId || entry.Leaf != was.Leaf || !bytes.Equal(entry.Signed, was.Signed) ||
			!bytes.Equal(entry.SealedBody, was.SealedBody) || !bytes.Equal(entry.Key, was.Key) || !bytes.Equal(entry.Salt, was.Salt) {
			t.Errorf("seq %d came back other than it was journaled", was.Seq)
		}
		if !bytes.Equal(entry.EntryBytes(&slotId, uint32(index)), was.EntryBytes(&slotId, uint32(index))) {
			t.Errorf("seq %d's re-sent entry differs", was.Seq)
		}
	}
	next := writer.seal(env, logId, 1)
	testRequireChain(t, next, 3, sealed[1].Leaf)
}

// A crash before the fsync, staged as a store that takes no more writes: the entry never existed for any reader,
// and the next entry takes its seq again, so the chain shows no gap.
func TestRecordChainUnjournaledEntryLeavesItsSeq(t *testing.T) {
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	env := writer.open()
	first := writer.seal(env, logId, 2)

	writer.files.FailWritesAfter(0)
	if _, err := sidecar.RecordSeal(env, testChainNote(logId, "never journaled")); !errors.Is(err, sidecartest.ErrFakeStoreWriteFailed) {
		t.Fatalf("a journal that refused: %v", err)
	}
	writer.files.FailWritesAfter(-1)
	again := writer.seal(env, logId, 1)
	testRequireChain(t, again, 3, first[1].Leaf)

	// and so in the next life, which reads only the store
	pending, err := writer.open().Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	testRequireChain(t, pending, 1, [32]byte{})
	if len(pending) != 3 || !bytes.Equal(pending[2].Signed, again[0].Signed) {
		t.Errorf("the journal holds %d entries, not the three that went out", len(pending))
	}
}

// An acknowledgment drops journal records and keeps the head: a later life chains on the newest entry though no
// record holds it, and a repeated acknowledgment, or one naming a seq never journaled, changes nothing.
func TestRecordChainAcknowledgeKeepsTheHead(t *testing.T) {
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	env := writer.open()
	entries := writer.seal(env, logId, 3)
	for range 2 {
		if err := env.Chain.Acknowledge(logId, []uint64{1, 2, 3, 99}); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := env.Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d pending after every one was acknowledged", len(pending))
	}
	logIds, err := env.Chain.PendingLogIds()
	if err != nil {
		t.Fatal(err)
	}
	if len(logIds) != 0 {
		t.Errorf("logs %v still pending", logIds)
	}

	next := writer.open()
	head, err := next.Chain.Head(logId)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 3 || head.Leaf != entries[2].Leaf {
		t.Fatalf("the next life's head is seq %d", head.Seq)
	}
	testRequireChain(t, writer.seal(next, logId, 1), 4, entries[2].Leaf)
}

// Acknowledging the newest entry before older ones keeps the older ones pending and the head where it was.
func TestRecordChainAcknowledgedOutOfOrderKeepsTheRest(t *testing.T) {
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	env := writer.open()
	entries := writer.seal(env, logId, 3)
	if err := env.Chain.Acknowledge(logId, []uint64{3}); err != nil {
		t.Fatal(err)
	}
	next := writer.open()
	pending, err := next.Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	testRequireChain(t, pending, 1, [32]byte{})
	if len(pending) != 2 {
		t.Errorf("%d pending", len(pending))
	}
	testRequireChain(t, writer.seal(next, logId, 1), 4, entries[2].Leaf)
}

// Pushes entries to the writer's own stream of logId, one push, as a writer would.
func testChainPush(t *testing.T, streams sidecar.RecordStreams, writerId sidecar.Id, logId sidecar.Id, entries [][]byte) {
	t.Helper()
	push := &sidecar.RecordStreamPush{PushId: sidecar.NewId(), WriterSidecarId: writerId, SlotId: sidecar.NewId()}
	for index, entry := range entries {
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: uint32(index), Row: bytes.Repeat([]byte{0x5a}, 64)})
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: fmt.Sprintf("e/0/0/%d", sidecar.NewId()), Entry: entry})
	}
	if _, err := streams.Append(context.Background(), logId, push); err != nil {
		t.Fatal(err)
	}
}

// A world with one repo the writer reads and writes.
func testChainWorld(t *testing.T, writerId sidecar.Id) (*sidecartest.FakeRecordStreams, sidecar.Id) {
	t.Helper()
	world := sidecartest.NewFakeRecordStreams(nil, nil, nil)
	logId, err := world.NewRepo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(logId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	return world, logId
}

// The entries' stream bytes, each in a slot at its index.
func testChainEntryBytes(entries []*sidecar.RecordSealedEntry) [][]byte {
	slotId := sidecar.NewId()
	entryBytes := [][]byte{}
	for index, entry := range entries {
		entryBytes = append(entryBytes, entry.EntryBytes(&slotId, uint32(index)))
	}
	return entryBytes
}

// RECORD.md section 5.3's restart row: a direct writer whose local state is older than its stream, as after a restore
// from backup, takes its stream's newest entry of this chain as its head, so its next entry chains on what readers
// hold rather than forking it. A writer whose head is already at or past its stream's keeps its own.
func TestRecordChainRestartAdoptsAHigherStreamHead(t *testing.T) {
	writer := newTestRecordWriter(t)
	world, logId := testChainWorld(t, writer.sidecarId)
	streams := world.For(writer.sidecarId)
	entries := writer.seal(writer.open(), logId, 3)
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(entries[:2]))
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(entries[2:]))
	// an empty push after it, of another writer's entries an ingester keeps, so the head is a push back
	other := newTestRecordWriter(t)
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(other.seal(other.open(), logId, 1)))

	restored := newTestRecordWriter(t)
	restored.sidecarId, restored.key = writer.sidecarId, writer.key
	env := restored.open()
	adopted, err := env.Chain.AdoptStream(context.Background(), streams, logId, writer.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !adopted {
		t.Fatal("the stream's head was not adopted")
	}
	head, err := env.Chain.Head(logId)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 3 || head.Leaf != entries[2].Leaf {
		t.Fatalf("adopted seq %d", head.Seq)
	}
	testRequireChain(t, writer.seal(env, logId, 1), 4, entries[2].Leaf)
	// the adoption is durable: a later life of the restored writer still chains on it
	head, err = restored.open().Chain.Head(logId)
	if err != nil || head.Seq != 4 {
		t.Errorf("the next life's head is seq %d: %v", head.Seq, err)
	}

	// the original writer, whose head is the stream's, keeps its own
	ahead := writer.open()
	adopted, err = ahead.Chain.AdoptStream(context.Background(), streams, logId, writer.publicKey())
	if err != nil || adopted {
		t.Errorf("a head at the stream's was raised: %t, %v", adopted, err)
	}
}

// Only an entry that verifies under the writer's own key, as its entry in this log, can raise its head: one a server
// planted in its stream with its writer id and another key's signature, or a garbage file, raises nothing.
func TestRecordChainAdoptsOnlyAnEntryItVerifies(t *testing.T) {
	writer := newTestRecordWriter(t)
	world, logId := testChainWorld(t, writer.sidecarId)
	streams := world.For(writer.sidecarId)
	entries := writer.seal(writer.open(), logId, 2)
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(entries))

	forger := newTestRecordWriter(t)
	forger.sidecarId = writer.sidecarId
	forgerEnv := forger.open()
	if _, err := forgerEnv.Chain.Adopt(logId, sidecar.RecordChainHead{Seq: 40}); err != nil {
		t.Fatal(err)
	}
	forged := forger.seal(forgerEnv, logId, 1)
	if forged[0].Seq != 41 {
		t.Fatalf("forged seq %d", forged[0].Seq)
	}
	planted := testChainEntryBytes(forged)
	planted = append(planted, []byte("not an entry"))
	testChainPush(t, streams, writer.sidecarId, logId, planted)

	restored := newTestRecordWriter(t)
	restored.sidecarId, restored.key = writer.sidecarId, writer.key
	env := restored.open()
	if _, err := env.Chain.AdoptStream(context.Background(), streams, logId, writer.publicKey()); err != nil {
		t.Fatal(err)
	}
	head, err := env.Chain.Head(logId)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 2 || head.Leaf != entries[1].Leaf {
		t.Errorf("adopted seq %d from a planted entry", head.Seq)
	}
}

// A stream entry at a seq this chain holds with another leaf is a fork: Adopt refuses it and the head stands.
func TestRecordChainAdoptRefusesAFork(t *testing.T) {
	writer := newTestRecordWriter(t)
	world, logId := testChainWorld(t, writer.sidecarId)
	streams := world.For(writer.sidecarId)
	// another copy of this writer's state signed seq 1 and 2 first, and pushed them
	copied := newTestRecordWriter(t)
	copied.sidecarId, copied.key = writer.sidecarId, writer.key
	testChainPush(t, streams, writer.sidecarId, logId, testChainEntryBytes(copied.seal(copied.open(), logId, 2)))

	env := writer.open()
	own := writer.seal(env, logId, 2)
	_, err := env.Chain.AdoptStream(context.Background(), streams, logId, writer.publicKey())
	if !errors.Is(err, sidecar.ErrRecordChainForked) {
		t.Fatalf("a fork at the head: %v", err)
	}
	head, err := env.Chain.Head(logId)
	if err != nil || head.Seq != 2 || head.Leaf != own[1].Leaf {
		t.Errorf("the head moved to seq %d: %v", head.Seq, err)
	}
	if _, err := env.Chain.Adopt(logId, sidecar.RecordChainHead{Seq: 1, Leaf: [32]byte{1}}); !errors.Is(err, sidecar.ErrRecordChainForked) {
		t.Errorf("a fork under the head, at a pending seq: %v", err)
	}
}

// A chain file that does not decode, or holds another writer's or log's chain, or a journal that does not chain, is an
// error at every call, never a fresh chain that would sign seq 1 again.
func TestRecordChainRefusesCorruptState(t *testing.T) {
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	entries := writer.seal(writer.open(), logId, 2)
	logHex := hex.EncodeToString(logId[:])
	journalPath := func(seq int) string {
		return fmt.Sprintf("record/journal/%s/%020d", logHex, seq)
	}
	first, ok := writer.files.Contents(journalPath(1))
	if !ok {
		t.Fatal("no journal record for seq 1")
	}
	second, _ := writer.files.Contents(journalPath(2))

	put := func(path string, content []byte) {
		t.Helper()
		file, err := writer.files.Root().Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := file.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	restore := func() {
		put(journalPath(1), first)
		put(journalPath(2), second)
		writer.files.Root().Remove("record/" + logHex)
	}
	cases := map[string]func(){
		"a journal record that does not decode": func() { put(journalPath(2), []byte("{")) },
		"a journal record under another seq":    func() { put(journalPath(3), second) },
		"a journal record of another field": func() {
			put(journalPath(2), append(bytes.Clone(bytes.TrimSuffix(second, []byte("}"))), []byte(`,"other":1}`)...))
		},
		"a head that does not decode": func() { put("record/"+logHex, []byte("not json")) },
		"a journal that does not chain": func() {
			// seq 2's record replaced by another life's seq 2, signed on another seq 1
			other := newTestRecordWriter(t)
			other.sidecarId, other.key = writer.sidecarId, writer.key
			other.seal(other.open(), logId, 2)
			content, _ := other.files.Contents(journalPath(2))
			put(journalPath(2), content)
		},
		"a journal file of a name no seq has": func() { put(fmt.Sprintf("record/journal/%s/12", logHex), first) },
	}
	for name, corrupt := range cases {
		restore()
		corrupt()
		env := writer.open()
		if _, err := env.Chain.Head(logId); !errors.Is(err, sidecar.ErrRecordChainCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := sidecar.RecordSeal(env, testChainNote(logId, "on corrupt state")); !errors.Is(err, sidecar.ErrRecordChainCorrupt) {
			t.Errorf("%s: sealing on it: %v", name, err)
		}
		writer.store.Remove(fmt.Sprintf("journal/%s/%020d", logHex, 3))
		writer.store.Remove(fmt.Sprintf("journal/%s/12", logHex))
	}
	restore()

	// another writer's chain in this store is not this writer's
	stranger := &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(writer.store, sidecar.NewId()), Sign: writer.sign}
	if _, err := stranger.Chain.Head(logId); !errors.Is(err, sidecar.ErrRecordChainCorrupt) {
		t.Errorf("another writer's chain: %v", err)
	}
	head, err := writer.open().Chain.Head(logId)
	if err != nil || head.Leaf != entries[1].Leaf {
		t.Errorf("the restored state does not read: %v", err)
	}
}

// One log's appends serialize through the journal's fsync, so racing writers take every seq once, each chaining on
// the one before.
func TestRecordChainSerializesOneLogsAppends(t *testing.T) {
	writer := newTestRecordWriter(t)
	env := writer.open()
	logId := sidecar.NewId()
	const goroutineCount = 4
	const sealCount = 16
	var waitGroup sync.WaitGroup
	errs := make(chan error, goroutineCount*sealCount)
	for goroutine := range goroutineCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for index := range sealCount {
				_, err := sidecar.RecordSeal(env, testChainNote(logId, fmt.Sprintf("racer %d note %d", goroutine, index)))
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	pending, err := env.Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != goroutineCount*sealCount {
		t.Fatalf("%d entries", len(pending))
	}
	testRequireChain(t, pending, 1, [32]byte{})
}

// The logs a restarted writer replays are those with a journal record not yet acknowledged.
func TestRecordChainListsLogsWithPendingEntries(t *testing.T) {
	writer := newTestRecordWriter(t)
	env := writer.open()
	firstLogId, secondLogId := sidecar.NewId(), sidecar.NewId()
	writer.seal(env, firstLogId, 2)
	writer.seal(env, secondLogId, 1)
	logIds, err := writer.open().Chain.PendingLogIds()
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(logIds, sidecar.Id.Cmp)
	want := []sidecar.Id{firstLogId, secondLogId}
	slices.SortFunc(want, sidecar.Id.Cmp)
	if !slices.Equal(logIds, want) {
		t.Fatalf("pending logs %v", logIds)
	}
	if err := env.Chain.Acknowledge(firstLogId, []uint64{1, 2}); err != nil {
		t.Fatal(err)
	}
	logIds, err = env.Chain.PendingLogIds()
	if err != nil || !slices.Equal(logIds, []sidecar.Id{secondLogId}) {
		t.Errorf("pending logs %v: %v", logIds, err)
	}
}
