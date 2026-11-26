//go:build !js

// DESIGN-COMPUTE §24.5's layout as the writer files it (CTXH-M11-02, D-CTXH-10, D-CTXH-12): a session entry's header at
// e/<n> with sealed_body empty and body_apart set, its sealed body alone at s/<n>, the leaf the header's alone; a
// deposit carrying the entry whole, which an ingester files apart; the s/ paths beside e/'s; and the pushes session
// entries ride: none of their own at a call, the call's model_call's, a turn's end, and the ride interval on a still
// clock. Internal, so the loop is stepped by hand.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// evs as a writer pushes to it, keeping each push and committing it, holding no stream to read back.
type testSessionPushStreams struct {
	RecordStreamsUnavailable

	stateLock sync.Mutex
	pushes    []*RecordStreamPush
	version   uint64
}

func (self *testSessionPushStreams) Append(ctx context.Context, repoId Id, push *RecordStreamPush) (*RecordStreamCommit, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pushes = append(self.pushes, push)
	self.version += 1
	return &RecordStreamCommit{Version: self.version, TimeMillis: 1762387200000}, nil
}

func (self *testSessionPushStreams) Streams(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	return []*RecordStreamHead{}, nil
}

func (self *testSessionPushStreams) ReadStream(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) ([]*RecordStreamVersion, error) {
	return []*RecordStreamVersion{}, nil
}

// The pushes so far.
func (self *testSessionPushStreams) taken() []*RecordStreamPush {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*RecordStreamPush{}, self.pushes...)
}

// A writer of one log on a still clock and the pushes it makes.
type testSessionWriter struct {
	t       *testing.T
	writer  *recordWriter
	streams *testSessionPushStreams
	clock   *testRecordStillClock
	logId   Id
}

func newTestSessionWriter(t *testing.T) *testSessionWriter {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, ed25519.SeedSize))
	writerId := NewId()
	logId := NewId()
	auth := &fuzzRecordAuth{
		pin:       &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x07}, 32)},
		writerId:  writerId,
		logId:     logId,
		publicKey: key.Public().(ed25519.PublicKey),
	}
	streams := &testSessionPushStreams{}
	clock := &testRecordStillClock{now: time.UnixMilli(1762387200000)}
	writer := newRecordWriter(&SidecarRecordArgs{
		SidecarId:         writerId,
		IdentityPublicKey: auth.publicKey,
		Store:             testRecordStore(t),
		Sign:              testRecordSigner(writerId, key),
		Streams:           streams,
		Auth:              func() RecordAuthView { return auth },
		Clock:             clock,
		Settings:          defaultSidecarRecordSettings(),
	})
	// the direct writer reconciles its stream first, as PrepareDirectWrites does, so the loop's passes are its own
	err := func() error {
		writer.pumpLock.Lock()
		defer writer.pumpLock.Unlock()
		if err := writer.load(); err != nil {
			return err
		}
		return writer.adopt(t.Context(), logId)
	}()
	if err != nil {
		t.Fatal(err)
	}
	return &testSessionWriter{t: t, writer: writer, streams: streams, clock: clock, logId: logId}
}

// Seals kind's body as the log's next entry and queues it as Append would.
func (self *testSessionWriter) append(kind RecordKind, body any) *RecordSealedEntry {
	self.t.Helper()
	args := &RecordSealArgs{LogId: self.logId, Kind: kind, Source: RecordSourceObserved, TimeMillis: self.clock.now.UnixMilli(), Tainted: true}
	switch typed := body.(type) {
	case *protocol.SessionEntryBody:
		args.Body = typed
	case *protocol.ModelCallBody:
		args.Body = typed
	}
	sealed, err := RecordSeal(&RecordSealEnv{Chain: self.writer.chain, Sign: self.writer.sign}, args)
	if err != nil {
		self.t.Fatal(err)
	}
	self.writer.enqueue(&recordRoute{logId: self.logId}, sealed, kind)
	return sealed
}

// One pass of the loop, which must not fail.
func (self *testSessionWriter) pump() {
	self.t.Helper()
	if err := self.writer.pump(self.t.Context(), false); err != nil {
		self.t.Fatal(err)
	}
}

// A root session node of text.
func testSessionLayoutNode(text string) *protocol.SessionEntryBody {
	item := []byte(`{"text":"` + text + `"}`)
	itemSha256 := sha256.Sum256(item)
	chainSha256 := sessionChainSha256(nil, itemSha256[:])
	nodeId := NewId()
	return &protocol.SessionEntryBody{NodeId: nodeId.Bytes(), Type: 1, Item: item, ItemSha256: itemSha256[:], ChainSha256: chainSha256[:]}
}

// A session entry's RecordEntry at e/<n> holds its header with sealed_body empty and body_apart set, its body file the
// sealed body alone; its leaf is its header's; a deposit carries it whole, and an ingester's split of the deposit is
// the writer's own e/<n> bytes and body. s/ paths sit beside e/'s, each refusing the other's.
func TestSessionLayoutHeaderAtEAndBodyAtS(t *testing.T) {
	session := newTestSessionWriter(t)
	sealed := session.append(RecordKindSessionEntry, testSessionLayoutNode("filed apart"))
	if !sealed.BodyApart || len(sealed.SealedBody) == 0 {
		t.Fatalf("a session entry sealed with body apart %v and %d body bytes", sealed.BodyApart, len(sealed.SealedBody))
	}
	slotId := NewId()
	fields := &recordEntryFields{}
	if err := fields.parse(sealed.EntryBytes(&slotId, 3)); err != nil {
		t.Fatal(err)
	}
	if !fields.bodyApart || len(fields.sealedBody) != 0 || fields.keyIndex != 3 || !bytes.Equal(fields.keySlotId, slotId[:]) {
		t.Errorf("e/<n> holds body apart %v, %d body bytes, key index %d", fields.bodyApart, len(fields.sealedBody), fields.keyIndex)
	}
	if !bytes.Equal(sealed.BodyBytes(), sealed.SealedBody) {
		t.Error("s/<n> is not the sealed body alone")
	}
	header, err := sealed.Header()
	if err != nil {
		t.Fatal(err)
	}
	if header.LeafHash() != sealed.Leaf {
		t.Error("filing the body apart moved the leaf")
	}
	whole := &recordEntryFields{}
	deposit := sealed.Deposit()
	if err := whole.parse(deposit.GetEntry()); err != nil {
		t.Fatal(err)
	}
	if whole.bodyApart || !bytes.Equal(whole.sealedBody, sealed.SealedBody) {
		t.Errorf("a deposit carries body apart %v and %d body bytes", whole.bodyApart, len(whole.sealedBody))
	}
	apart, body, err := recordEntrySplitApart(deposit.GetEntry(), &slotId, 3)
	if err != nil {
		t.Fatal(err)
	}
	split := &recordEntryFields{}
	if err := split.parse(apart); err != nil {
		t.Fatal(err)
	}
	if !split.bodyApart || len(split.sealedBody) != 0 || split.keyIndex != 3 || !bytes.Equal(split.keySlotId, slotId[:]) ||
		!bytes.Equal(split.signed, fields.signed) || split.version != fields.version || !bytes.Equal(body, sealed.SealedBody) {
		t.Error("an ingester's split is not the writer's own layout")
	}
	// an entry inline and apart at once is no entry
	inline := sealed.entryBytes(&slotId, 3, false)
	if err := (&recordEntryFields{}).parse(append(inline, 6<<3, 1)); err == nil {
		t.Error("an entry with its body inline and apart parsed")
	}

	for _, n := range []uint64{1, 2047, 2048, 4194304} {
		entryPath, _ := RecordStreamPath(n)
		bodyPath, err := RecordBodyPath(n)
		if err != nil || bodyPath != "s/"+entryPath[len("e/"):] {
			t.Errorf("s/ path of %d: %s", n, bodyPath)
		}
		if counter, ok := RecordBodyPathCounter(bodyPath); !ok || counter != n {
			t.Errorf("%s names %d", bodyPath, counter)
		}
		if _, ok := RecordBodyPathCounter(entryPath); ok {
			t.Errorf("%s read as a body path", entryPath)
		}
		if _, ok := RecordStreamPathCounter(bodyPath); ok {
			t.Errorf("%s read as an entry path", bodyPath)
		}
	}
}

// D-CTXH-12: session entries make no push of their own at a call; they leave in the push that carries their call's
// model_call, each body beside its header, at a turn's end, or the ride interval after the oldest waits.
func TestSessionEntriesRideCallPushes(t *testing.T) {
	session := newTestSessionWriter(t)
	session.writer.rideInterval = 60 * time.Second
	settings := session.writer.settings

	for _, text := range []string{"system", "prompt", "tool result"} {
		session.append(RecordKindSessionEntry, testSessionLayoutNode(text))
	}
	session.clock.now = session.clock.now.Add(settings.PushCoalesce)
	session.pump()
	if pushes := session.streams.taken(); len(pushes) != 0 {
		t.Fatalf("session entries made %d pushes of their own", len(pushes))
	}
	if wake, ok := session.writer.nextWake(); !ok || wake != 60*time.Second-settings.PushCoalesce {
		t.Errorf("the loop wakes in %v (%v), not at the ride interval", wake, ok)
	}
	session.append(RecordKindModelCall, &protocol.ModelCallBody{Model: "local-gemma-3n-e4b-low"})
	session.pump()
	if pushes := session.streams.taken(); len(pushes) != 0 {
		t.Fatalf("the call's push went before its coalesce: %d", len(pushes))
	}
	session.clock.now = session.clock.now.Add(settings.PushCoalesce)
	session.pump()
	pushes := session.streams.taken()
	if len(pushes) != 1 || len(pushes[0].Entries) != 4 || len(pushes[0].Bodies) != 3 {
		t.Fatalf("the call's push: %d pushes", len(pushes))
	}
	for index, body := range pushes[0].Bodies {
		want, _ := RecordBodyPath(uint64(index + 1))
		if body.Path != want {
			t.Errorf("body %d at %s", index, body.Path)
		}
	}
	if last := pushes[0].Entries[3]; last.Path != "e/0/0/4" {
		t.Errorf("the model_call at %s", last.Path)
	}

	// a turn's end
	session.append(RecordKindSessionEntry, testSessionLayoutNode("answer"))
	session.append(RecordKindSessionEntry, testSessionLayoutNode("summary"))
	session.pump()
	if count := len(session.streams.taken()); count != 1 {
		t.Fatalf("%d pushes before the turn's end", count)
	}
	session.writer.releaseRides()
	session.pump()
	if pushes := session.streams.taken(); len(pushes) != 2 || len(pushes[1].Entries) != 2 || len(pushes[1].Bodies) != 2 {
		t.Fatalf("the turn's end: %d pushes", len(pushes))
	}

	// the ride interval, on the still clock
	session.append(RecordKindSessionEntry, testSessionLayoutNode("a late node"))
	session.clock.now = session.clock.now.Add(59 * time.Second)
	session.pump()
	if count := len(session.streams.taken()); count != 2 {
		t.Fatalf("%d pushes before the interval", count)
	}
	session.clock.now = session.clock.now.Add(time.Second)
	session.pump()
	if pushes := session.streams.taken(); len(pushes) != 3 || len(pushes[2].Entries) != 1 || len(pushes[2].Bodies) != 1 {
		t.Fatalf("the interval: %d pushes", len(pushes))
	}

	// with no interval set a session entry goes as any, at the coalesce wait
	session.writer.rideInterval = 0
	session.append(RecordKindSessionEntry, testSessionLayoutNode("no interval"))
	session.clock.now = session.clock.now.Add(settings.PushCoalesce)
	session.pump()
	if count := len(session.streams.taken()); count != 4 {
		t.Fatalf("with no interval: %d pushes", count)
	}
}

// A riding draft of a kind that sends at once is refused, and a body held at a cap leaves its header to go alone.
func TestSessionHeldBodyLeavesItsHeaderToGo(t *testing.T) {
	session := newTestSessionWriter(t)
	session.writer.holdBodies = func(logId Id) bool { return true }
	session.append(RecordKindSessionEntry, testSessionLayoutNode("held"))
	if err := session.writer.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pushes := session.streams.taken()
	if len(pushes) != 1 || len(pushes[0].Entries) != 1 || len(pushes[0].Bodies) != 0 {
		t.Fatalf("a held body's push: %d pushes", len(pushes))
	}
	held, err := session.writer.heldBodies(session.logId)
	if err != nil || len(held) != 1 || held[0].Seq != 1 || held[0].Counter != 1 {
		t.Fatalf("held %v: %v", held, err)
	}
	session.writer.holdBodies = nil
	session.append(RecordKindModelCall, &protocol.ModelCallBody{Model: "local-gemma-3n-e4b-low"})
	if err := session.writer.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pushes = session.streams.taken()
	if len(pushes) != 2 || len(pushes[1].Bodies) != 1 || pushes[1].Bodies[0].Path != "s/0/0/1" || !bytes.Equal(pushes[1].Bodies[0].Body, held[0].SealedBody) {
		t.Fatalf("the held body did not ride the next push: %d pushes", len(pushes))
	}
	if held, err := session.writer.heldBodies(session.logId); err != nil || len(held) != 0 {
		t.Errorf("still held %v: %v", held, err)
	}
	if _, err := (&recordWriter{}).Append(&RecordDraft{Kind: RecordKindApproval, Source: RecordSourceObserved, StoredBody: []byte{}, Rides: true}); err == nil {
		t.Error("an approval rode")
	}
}
