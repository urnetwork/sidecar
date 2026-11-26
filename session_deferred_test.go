//go:build !sidecar_http

// DESIGN-COMPUTE §24.5's headers in the chain and bodies apart, as a reader verifies them (CTXH-M11-02, D-CTXH-10; the
// second review's R2-01): on a cold device that fetches no body, an approval filed after two session entries verifies,
// and so does a suffix of session entries up to the writer's head, again across a writer's restart, a cap holding
// bodies and a spool dropping some; a body fetched later completes its entry and one failing its commitment alarms;
// a second header at a seq is a fork and a missing header a gap, whatever the bodies; withheld and dropped bodies
// raise nothing, a dropped one named in its run's coverage; an orphan body is ignored and alarmed; a reader that knows
// neither kind reads the chains whole; and a log's mirror fetches every body. External, as record_reader_test.go.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A session node's body for run, its item text and hashes, a root.
func testSessionNodeBody(text string) *protocol.SessionEntryBody {
	item := []byte(`{"text":"` + text + `","type":"message"}`)
	itemSha256 := sha256.Sum256(item)
	chainSha256 := sha256.Sum256(append(make([]byte, sha256.Size), itemSha256[:]...))
	nodeId := sidecar.NewId()
	return &protocol.SessionEntryBody{NodeId: nodeId.Bytes(), Type: 1, Item: item, ItemSha256: itemSha256[:], ChainSha256: chainSha256[:]}
}

// A session entry's draft in run, its body a root node of text.
func testSessionDraft(runId *sidecar.Id, text string) *sidecar.RecordDraft {
	return &sidecar.RecordDraft{Kind: sidecar.RecordKindSessionEntry, Source: sidecar.RecordSourceObserved, RunId: runId, Body: testSessionNodeBody(text)}
}

// An approval request's draft in run, as a Harness files one after its run's session entries.
func testSessionApprovalDraft(t *testing.T, runId *sidecar.Id) *sidecar.RecordDraft {
	t.Helper()
	approvalId := sidecar.NewId()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), RunId: runId.Bytes(), Summary: "send the summary", Risk: 1, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.RecordDraft{Kind: sidecar.RecordKindApproval, Source: sidecar.RecordSourceObserved, RunId: runId, StoredBody: stored}
}

// The states of entries, in read order.
func testSessionStates(entries []*sidecar.RecordReadEntry) []sidecar.RecordEntryState {
	states := []sidecar.RecordEntryState{}
	for _, entry := range entries {
		states = append(states, entry.State)
	}
	return states
}

// Seals a session entry as the hand chain's next.
func (self *testRecordHandChain) sealSession(text string) *sidecar.RecordSealedEntry {
	self.device.t.Helper()
	return self.sealMessage(sidecar.RecordKindSessionEntry, testSessionNodeBody(text))
}

// Seals body of kind as the hand chain's next entry.
func (self *testRecordHandChain) sealMessage(kind sidecar.RecordKind, body proto.Message) *sidecar.RecordSealedEntry {
	self.device.t.Helper()
	sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
		LogId:         self.device.world.vaultId,
		Kind:          kind,
		Source:        sidecar.RecordSourceObserved,
		TimeMillis:    self.device.world.clock.Now().UnixMilli(),
		Tainted:       true,
		PolicyVersion: self.device.world.auth.Tip().Pin().GetVersion(),
		Body:          body,
	})
	if err != nil {
		self.device.t.Fatal(err)
	}
	return sealed
}

// Pushes entries to the device's own stream at counters as pushHand does, a body-apart entry's body at s/<n> beside it
// unless withhold names its index; bodies adds body files at their counters, from earlier entries or none.
func (self *testRecordDevice) pushSessionHand(counters []uint64, entries []*sidecar.RecordSealedEntry, rows [][]byte, withhold []int, bodies map[uint64][]byte) {
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
		if sealed.BodyApart && !slices.Contains(withhold, index) {
			bodyPath, err := sidecar.RecordBodyPath(counters[index])
			if err != nil {
				self.t.Fatal(err)
			}
			push.Bodies = append(push.Bodies, &sidecar.RecordStreamBody{Path: bodyPath, Body: sealed.BodyBytes()})
		}
	}
	for counter, body := range bodies {
		bodyPath, err := sidecar.RecordBodyPath(counter)
		if err != nil {
			self.t.Fatal(err)
		}
		push.Bodies = append(push.Bodies, &sidecar.RecordStreamBody{Path: bodyPath, Body: body})
	}
	if _, err := self.world.streams.For(self.sidecarId).Append(self.t.Context(), self.world.vaultId, push); err != nil {
		self.t.Fatal(err)
	}
}

// R2-01's acceptance: a cold device that fetches no body verifies an approval its writer filed after two session
// entries in a row, and both entries' headers, raising nothing and reading no body.
func TestSessionApprovalAfterTwoDeferredEntriesVerifies(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	first := testRecordAppend(t, record, testSessionDraft(&runId, "one"))
	second := testRecordAppend(t, record, testSessionDraft(&runId, "two"))
	approval := testRecordAppend(t, record, testSessionApprovalDraft(t, &runId))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || second.Seq != 2 || approval.Seq != 3 {
		t.Fatalf("seqs %d, %d, %d", first.Seq, second.Seq, approval.Seq)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred, sidecar.RecordEntryLive}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	for _, entry := range entries[:2] {
		if !entry.BodyApart || entry.Body != nil || entry.Kind() != sidecar.RecordKindSessionEntry {
			t.Errorf("a session entry read %s, body apart %v, %d body bytes", entry.Kind(), entry.BodyApart, len(entry.Body))
		}
	}
	if entries[2].Kind() != sidecar.RecordKindApproval || entries[2].Body == nil || entries[2].BodyApart {
		t.Errorf("the approval read %s with %d body bytes", entries[2].Kind(), len(entries[2].Body))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	if count := world.streams.BodyReadCount(world.readerId); count != 0 {
		t.Errorf("the cold device read %d bodies", count)
	}
}

// A suffix of session entries up to the writer's head verifies from their headers alone, the chain at its head with
// no gap; fetching them later completes each, its body the node written.
func TestSessionDeferredSuffixVerifiesToHead(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	testRecordAppend(t, record, testRecordNote(&runId, "before the run's history"))
	drafts := []*sidecar.RecordDraft{}
	for _, text := range []string{"a", "b", "c"} {
		draft := testSessionDraft(&runId, text)
		drafts = append(drafts, draft)
		testRecordAppend(t, record, draft)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryLive, sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if entries[3].Header.Header.GetSeq() != 4 {
		t.Errorf("the head is seq %d", entries[3].Header.Header.GetSeq())
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil)
	if err != nil || fetched != 3 {
		t.Fatalf("fetched %d: %v", fetched, err)
	}
	entries = reader.reader.Entries(world.vaultId)
	for i, entry := range entries[1:] {
		body := &protocol.SessionEntryBody{}
		if entry.State != sidecar.RecordEntryLive || proto.Unmarshal(entry.Body, body) != nil || !proto.Equal(body, drafts[i].Body) {
			t.Errorf("entry %d fetched %s", i+2, entry.State)
		}
	}
}

// Session entries journaled before a writer's restart leave after it, in order, each body beside its header, and the
// restarted writer's next entry chains on them.
func TestSessionDeferredAcrossWriterRestart(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	testRecordAppend(t, record, testSessionDraft(&runId, "journaled"))
	testRecordAppend(t, record, testSessionDraft(&runId, "and killed"))
	// a kill: nothing pushed, the next life replays the journal
	restarted := device.open()
	if err := restarted.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	third := testRecordAppend(t, restarted, testSessionDraft(&runId, "after the restart"))
	if err := restarted.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if third.Seq != 3 {
		t.Errorf("the restarted writer took seq %d", third.Seq)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	if fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil || fetched != 3 {
		t.Errorf("fetched %d: %v", fetched, err)
	}
}

// A cap holding a log's bodies: their headers leave in order and read withheld, raising nothing, the entry after them
// live; once the hold lifts, the writer's next push carries them and they read deferred.
func TestSessionDeferredAcrossCap(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	holding := true
	record.SetBodyHold(func(logId sidecar.Id) bool { return holding && logId == world.vaultId })
	runId := sidecar.NewId()
	testRecordAppend(t, record, testSessionDraft(&runId, "held one"))
	testRecordAppend(t, record, testSessionDraft(&runId, "held two"))
	testRecordAppend(t, record, testRecordNote(&runId, "an entry past the cap"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryWithheld, sidecar.RecordEntryWithheld, sidecar.RecordEntryLive}) {
		t.Fatalf("states at the cap %v", testSessionStates(entries))
	}
	if held, err := record.HeldBodies(world.vaultId); err != nil || !slices.Equal(held, []uint64{1, 2}) {
		t.Errorf("held %v: %v", held, err)
	}
	holding = false
	testRecordAppend(t, record, testRecordNote(&runId, "room again"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries = reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries)[:2], []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred}) {
		t.Fatalf("states once there is room %v", testSessionStates(entries))
	}
	if held, err := record.HeldBodies(world.vaultId); err != nil || len(held) != 0 {
		t.Errorf("still held %v: %v", held, err)
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	if fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil || fetched != 2 {
		t.Errorf("fetched %d: %v", fetched, err)
	}
}

// A spool that drops held bodies for good: the run's coverage names their seqs in bodies_dropped and they read dropped,
// the one kept reading deferred once it goes, and nothing alarms.
func TestSessionDeferredAcrossSpoolDrop(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	holding := true
	record.SetBodyHold(func(logId sidecar.Id) bool { return holding })
	runId := sidecar.NewId()
	for _, text := range []string{"dropped one", "dropped two", "kept"} {
		testRecordAppend(t, record, testSessionDraft(&runId, text))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	dropped, err := record.DropHeldBodies(world.vaultId, []uint64{1, 2})
	if err != nil || !slices.Equal(dropped, []uint64{1, 2}) {
		t.Fatalf("dropped %v: %v", dropped, err)
	}
	gap, err := sidecar.RecordCoverageGap(sidecar.RecordCoverageGapSpoolDrop, 2)
	if err != nil {
		t.Fatal(err)
	}
	testRecordAppend(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindCoverage, Source: sidecar.RecordSourceObserved, RunId: &runId,
		Body: &protocol.Coverage{RunId: runId.Bytes(), Sources: []string{sidecar.RecordCoverageSourceHarness}, Gaps: []string{gap},
			BodiesDropped: []*protocol.SeqRange{{First: 1, Last: 2}}},
	})
	holding = false
	testRecordAppend(t, record, testRecordNote(&runId, "room again"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	want := []sidecar.RecordEntryState{sidecar.RecordEntryDropped, sidecar.RecordEntryDropped, sidecar.RecordEntryDeferred, sidecar.RecordEntryLive, sidecar.RecordEntryLive}
	if !slices.Equal(testSessionStates(entries), want) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// A body fetched later that matches its header's commitment completes its entry: live, its body the node, its salt
// kept for a disclosure.
func TestSessionFetchedBodyCompletesEntry(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	draft := testSessionDraft(&runId, "opened later")
	ref := testRecordAppend(t, record, draft)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	reader.sync(t, world)
	selected := 0
	fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, func(entry *sidecar.RecordReadEntry) bool {
		selected += 1
		return entry.EntryId == ref.EntryId
	})
	if err != nil || fetched != 1 || selected != 1 {
		t.Fatalf("fetched %d of %d: %v", fetched, selected, err)
	}
	entry, ok := reader.reader.Entry(world.vaultId, ref.EntryId)
	body := &protocol.SessionEntryBody{}
	if !ok || entry.State != sidecar.RecordEntryLive || entry.Salt == nil || proto.Unmarshal(entry.Body, body) != nil || !proto.Equal(body, draft.Body) {
		t.Fatalf("the fetched entry: %v", entry)
	}
	if count := world.streams.BodyReadCount(world.readerId); count != 1 {
		t.Errorf("%d bodies read", count)
	}
	// a second fetch finds nothing deferred
	if again, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil || again != 0 {
		t.Errorf("fetched again %d: %v", again, err)
	}
}

// A body that opens and fails its header's commitment shows the entry invalid and raises bad_entry, its header
// standing; nothing alarmed before the fetch.
func TestSessionBodyFailingCommitmentAlarms(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.sealSession("committed to one body")
	// the right key with another salt: the body opens and does not commit
	badRow := append(bytes.Clone(first.Key), bytes.Repeat([]byte{0x44}, 32)...)
	device.pushSessionHand([]uint64{1}, []*sidecar.RecordSealedEntry{first}, [][]byte{badRow}, nil, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 1 || entries[0].State != sidecar.RecordEntryDeferred || len(reader.reasons()) != 0 {
		t.Fatalf("before the fetch: %v %v", testSessionStates(entries), reader.reasons())
	}
	if fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil || fetched != 0 {
		t.Fatalf("fetched %d: %v", fetched, err)
	}
	entries = reader.reader.Entries(world.vaultId)
	if !entries[0].BodyInvalid || entries[0].Body != nil || entries[0].State != sidecar.RecordEntryLive {
		t.Errorf("the body that failed: %s, invalid %v", entries[0].State, entries[0].BodyInvalid)
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("alarms %v", reasons)
	}
}

// A second signed header at one seq is a fork, alarmed, whatever the bodies.
func TestSessionSecondHeaderAtSeqIsFork(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.sealSession("first")
	second := hand.sealSession("second")
	device.pushSessionHand([]uint64{1, 2}, []*sidecar.RecordSealedEntry{first, second}, nil, nil, nil)
	restored := device.handChain()
	if _, err := restored.env.Chain.Adopt(world.vaultId, sidecar.RecordChainHead{Seq: first.Seq, Leaf: first.Leaf}); err != nil {
		t.Fatal(err)
	}
	rewritten := restored.sealSession("second, rewritten")
	device.pushSessionHand([]uint64{3}, []*sidecar.RecordSealedEntry{rewritten}, nil, []int{0}, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred, sidecar.RecordEntryForked}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmChainFork}) {
		t.Errorf("alarms %v", reasons)
	}
}

// A missing header is a gap, alarmed at once from a writer that does not deposit, its body nowhere and its neighbors'
// bodies deferred.
func TestSessionMissingHeaderIsGap(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.sealSession("first")
	hand.sealSession("never pushed")
	third := hand.sealSession("third")
	device.pushSessionHand([]uint64{1, 2}, []*sidecar.RecordSealedEntry{first, third}, nil, nil, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmChainGap}) {
		t.Errorf("alarms %v", reasons)
	}
}

// A body no s/ file holds yet reads withheld, and once its writer is removed, dropped: neither alarms nor moves the
// chain.
func TestSessionWithheldAndDroppedDoNotAlarm(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.sealSession("withheld one")
	second := hand.sealSession("withheld two")
	device.pushSessionHand([]uint64{1, 2}, []*sidecar.RecordSealedEntry{first, second}, nil, []int{0, 1}, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryWithheld, sidecar.RecordEntryWithheld}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	// the writer removed: its spool is gone with it
	delete(world.fixture.Members, device.sidecarId)
	world.publish()
	entries = reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDropped, sidecar.RecordEntryDropped}) {
		t.Fatalf("states once removed %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// A withheld body its writer's coverage names in bodies_dropped reads dropped; one it does not name stays withheld; a
// body that comes after all reads deferred.
func TestSessionDroppedNamedInCoverage(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.sealSession("dropped")
	second := hand.sealSession("still held")
	runId := sidecar.NewId()
	coverage := hand.sealMessage(sidecar.RecordKindCoverage, &protocol.Coverage{
		RunId: runId.Bytes(), Gaps: []string{sidecar.RecordCoverageGapSpoolDrop}, BodiesDropped: []*protocol.SeqRange{{First: 1, Last: 1}},
	})
	device.pushSessionHand([]uint64{1, 2, 3}, []*sidecar.RecordSealedEntry{first, second, coverage}, nil, []int{0, 1}, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDropped, sidecar.RecordEntryWithheld, sidecar.RecordEntryLive}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	// the held body arrives beside a later entry
	after := hand.seal("after")
	device.pushSessionHand([]uint64{4}, []*sidecar.RecordSealedEntry{after}, nil, nil, map[uint64][]byte{2: second.BodyBytes()})
	entries = reader.sync(t, world)
	if entries[1].State != sidecar.RecordEntryDeferred {
		t.Errorf("the late body reads %s", entries[1].State)
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// A file at s/<n> with no header at e/<n> in its push or an earlier one is ignored and alarmed; the push's entries
// stand.
func TestSessionOrphanBodyIgnoredAndAlarmed(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	note := hand.seal("a note")
	device.pushSessionHand([]uint64{1}, []*sidecar.RecordSealedEntry{note}, nil, nil, map[uint64][]byte{5: []byte("a body with no header")})
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryLive}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if reasons := reader.reasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("alarms %v", reasons)
	}
}

// Format 1: a reader that knows neither kind, here one past every kind it knows, still verifies the chain whole across
// a body-apart entry and shows it generically, its body deferred, raising nothing.
func TestSessionReaderWithoutKindsReadsChainsWhole(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	hand := device.handChain()
	first := hand.seal("first")
	head, err := hand.env.Chain.Head(world.vaultId)
	if err != nil {
		t.Fatal(err)
	}
	// an entry of a kind this build does not know, sealed by hand with its body apart
	later := hand.sealSession("a later kind's node")
	header := &protocol.RecordHeader{}
	if err := proto.Unmarshal(testSessionSignedBody(t, later.Signed), header); err != nil {
		t.Fatal(err)
	}
	header.Kind = 1500
	header.Seq = head.Seq + 1
	header.PrevSha256 = head.Leaf[:]
	headerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := device.sign(sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	unknown := &sidecar.RecordSealedEntry{
		LogId: world.vaultId, EntryId: later.EntryId, Seq: header.Seq, Leaf: sidecar.RecordLeafHash(headerBytes), Signed: signedBytes,
		SealedBody: later.SealedBody, Key: later.Key, Salt: later.Salt, BodyApart: true,
	}
	restored := device.handChain()
	if _, err := restored.env.Chain.Adopt(world.vaultId, sidecar.RecordChainHead{Seq: unknown.Seq, Leaf: unknown.Leaf}); err != nil {
		t.Fatal(err)
	}
	after := restored.seal("after")
	device.pushSessionHand([]uint64{1, 2, 3}, []*sidecar.RecordSealedEntry{first, unknown, after}, nil, nil, nil)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryLive, sidecar.RecordEntryDeferred, sidecar.RecordEntryLive}) {
		t.Fatalf("states %v", testSessionStates(entries))
	}
	if kept := entries[1]; kept.Kind().Known() || !kept.BodyApart || kept.Body != nil {
		t.Errorf("the unknown kind: %s, body apart %v", kept.Kind(), kept.BodyApart)
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	// fetched, its body is shown generically: it opens, and nothing parses it as a kind this build knows
	if _, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil {
		t.Fatal(err)
	}
	if entry, _ := reader.reader.Entry(world.vaultId, unknown.EntryId); entry.State != sidecar.RecordEntryLive || entry.BodyInvalid {
		t.Errorf("the unknown kind fetched: %s, invalid %v", entry.State, entry.BodyInvalid)
	}
}

// The body a Signed's stored bytes hold.
func testSessionSignedBody(t *testing.T, signedBytes []byte) []byte {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		t.Fatal(err)
	}
	return signed.GetBody()
}

// The vault's mirror fetches every body at each sync, while a reader that is no mirror fetches none.
func TestSessionMirrorFetchesEveryBody(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	for _, text := range []string{"one", "two"} {
		testRecordAppend(t, record, testSessionDraft(&runId, text))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryDeferred, sidecar.RecordEntryDeferred}) {
		t.Fatalf("a reader that is no mirror: %v", testSessionStates(entries))
	}
	reader.reader.SetFetchEveryBody(func(logId sidecar.Id) bool { return logId == world.vaultId })
	entries = reader.sync(t, world)
	if !slices.Equal(testSessionStates(entries), []sidecar.RecordEntryState{sidecar.RecordEntryLive, sidecar.RecordEntryLive}) {
		t.Fatalf("the mirror: %v", testSessionStates(entries))
	}
	// what tells a device it keeps the mirror: its EvsMirror of the log
	view := sidecar.NewRecordEvsMirrorView(&sidecar.RecordEvsMirrorViewArgs{Mirror: func(repoId sidecar.Id) *sidecar.EvsMirror { return nil }})
	if view.KeepsMirror(world.vaultId) {
		t.Error("a device with no mirror keeps one")
	}
}
