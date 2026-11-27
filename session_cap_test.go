//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-06's caps (DESIGN-COMPUTE §24.10, §24.16's Caps and settings row; D-CTXH-8, Q-CTXH-13, Q-CTXH-16) on
// sidecartest's streams: history stops leaving the device at 90% of the network's storage and at the member's share,
// every call still journaled, every header leaving and the bodies held, a part that would need a blob kept by hash and
// size, while the record's other entries keep landing; the one tap's expiry frees room, the hold lifts and the held
// bodies land; the member's share is all of it for one member and 2/n for n; past the spool's budget the oldest held
// bodies drop, named in bodies_dropped of their run's coverage; and the one tap expires the oldest blobs until history
// is under 70% of the cap, every node kept. External, on session_journal_test.go's world.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A session journal world with caps and a storage view on its device, the limit and the members a test sets.
type testSessionCapWorld struct {
	*testSessionJournalWorld
	stateLock sync.Mutex
	limit     int64
	members   int
	caps      *sidecar.SessionCaps
	storage   *sidecar.SessionStorage
}

func newTestSessionCapWorld(t *testing.T, ingest *sidecar.SidecarIngestSettings) *testSessionCapWorld {
	t.Helper()
	if ingest == nil {
		ingest = sidecar.DefaultSidecarSettings().Ingest
	}
	// the device administers the vault, as the one tap's erasure asks
	recordWorld := newTestRecordWorld(t)
	eraser, _ := recordWorld.eraserDevice()
	journalWorld := &testSessionJournalWorld{t: t, world: recordWorld, device: eraser, store: testSessionStore(t), ingest: ingest}
	journalWorld.open(nil)
	world := &testSessionCapWorld{testSessionJournalWorld: journalWorld, limit: -1, members: 1}
	world.install()
	return world
}

// The caps and the storage view over the world's record and journal now.
func (self *testSessionCapWorld) install() {
	self.t.Helper()
	settings := sidecar.DefaultSessionSettings()
	// the limit a test sets is read at every check
	settings.LimitReadInterval = 0
	caps, err := sidecar.NewSessionCaps(&sidecar.SessionCapsArgs{
		Record: self.record, Journal: self.journal, Ingest: self.ingest, Clock: self.world.clock, Settings: settings,
		Sources: &sidecar.SessionCapSources{
			StorageLimit: func(ctx context.Context) (int64, error) {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.limit, nil
			},
			MemberCount: func() (int, error) {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.members, nil
			},
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	storage, err := sidecar.NewSessionStorage(&sidecar.SessionStorageArgs{Record: self.record, Caps: caps})
	if err != nil {
		self.t.Fatal(err)
	}
	self.caps, self.storage = caps, storage
}

func (self *testSessionCapWorld) set(limit int64, members int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limit, self.members = limit, members
}

// Checks the caps, which must read.
func (self *testSessionCapWorld) check() *sidecar.SessionCapState {
	self.t.Helper()
	state, err := self.caps.Check(self.t.Context())
	if err != nil {
		self.t.Fatal(err)
	}
	return state
}

// A run of a prompt and a tool result whose text, past the item cap, is kept as a part in blobs; answering the run and
// the result's key.
func testSessionCapRun(t *testing.T, world *testSessionJournalWorld, partByteCount int) (*testSessionRecorder, string) {
	t.Helper()
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Read the logs."), "")
	user := recorder.message(system, testSessionRebuildUser("What failed overnight?"), "")
	result := recorder.message(user, testSessionRebuildResult("call-logs", "evs_read", strings.Repeat("a log line of the build ", partByteCount/24)), "")
	recorder.call(result, system)
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return recorder, result
}

// The entries of runId another device of the member reads, each body fetched that can be.
func testSessionCapRead(t *testing.T, world *testSessionJournalWorld, runId sidecar.Id) []*sidecar.RecordReadEntry {
	t.Helper()
	record := world.world.device(true).open()
	if err := record.Reader().Sync(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Reader().FetchBodies(t.Context(), world.world.vaultId, nil); err != nil {
		t.Fatal(err)
	}
	entries := []*sidecar.RecordReadEntry{}
	for _, entry := range record.Reader().Entries(world.world.vaultId) {
		if bytes.Equal(entry.Header.Header.GetRunId(), runId.Bytes()) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// The states of entries of kind.
func testSessionCapStates(entries []*sidecar.RecordReadEntry, kind sidecar.RecordKind) []sidecar.RecordEntryState {
	states := []sidecar.RecordEntryState{}
	for _, entry := range entries {
		if entry.Kind() == kind {
			states = append(states, entry.State)
		}
	}
	return states
}

// The cap's case, at the network's storage or at the member's share: once capped a new call's nodes still journal, a
// part that would need a blob kept by hash and size with the gap oversize; their headers leave and their bodies are
// held, read withheld, never a gap, while a note keeps landing whole; the one tap expires the oldest blobs, the hold
// lifts, and the held bodies land with the next push.
func testSessionHistoryStopsLeavingAtCap(t *testing.T, member bool) {
	world := newTestSessionCapWorld(t, nil)
	old, _ := testSessionCapRun(t, world.testSessionJournalWorld, 3*1024*1024)
	state := world.check()
	if member {
		// four members, each's share half the storage: the history at the share, the network well under its cap
		world.set(int64(float64(state.MemberUsed)/0.5), 4)
	} else {
		world.set(int64(float64(state.NetworkUsed)/0.9), 1)
	}
	state = world.check()
	if member && (!state.AtMemberCap || state.AtNetworkCap || state.MemberShare != 0.5) {
		t.Fatalf("at the member's share: %+v", state)
	}
	if !member && (!state.AtNetworkCap || state.Warning == "") {
		t.Fatalf("at the network's cap: %+v", state)
	}

	// a call made at the cap
	recorder := newTestSessionRecorder(t, world.testSessionJournalWorld)
	system := recorder.message("", testSessionRebuildSystem("Keep going."), "")
	user := recorder.message(system, testSessionRebuildUser("Summarize this file."), "")
	result := recorder.message(user, testSessionRebuildResult("call-file", "evs_read", strings.Repeat("a long file ", 4000)), "")
	if parts := recorder.nodes[result].journaled.Parts; len(parts) != 1 || !parts[0].GetOmitted() {
		t.Fatalf("a part at the cap: %v", parts)
	}
	if gaps := world.device.takeGaps(); !slices.Contains(gaps, recorder.run.RunId.String()+" "+sidecar.RecordCoverageGapOversize) {
		t.Fatalf("the oversize gap: %v", gaps)
	}
	recorder.call(result, system)
	// the record's other kinds keep writing
	note := testRecordAppend(t, world.record, testRecordNote(nil, "the mail kept landing"))
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := testSessionCapRead(t, world.testSessionJournalWorld, recorder.run.RunId)
	if states := testSessionCapStates(entries, sidecar.RecordKindSessionEntry); len(states) != 3 ||
		slices.ContainsFunc(states, func(state sidecar.RecordEntryState) bool { return state != sidecar.RecordEntryWithheld }) {
		t.Fatalf("the capped nodes read %v", states)
	}
	if states := testSessionCapStates(entries, sidecar.RecordKindModelCall); len(states) != 1 || states[0] != sidecar.RecordEntryLive {
		t.Fatalf("the capped call's model_call reads %v", states)
	}
	noteRead := world.world.device(true).open()
	if err := noteRead.Reader().Sync(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	if entry, ok := noteRead.Reader().Entry(world.world.vaultId, note.EntryId); !ok || entry.State != sidecar.RecordEntryLive || entry.Body == nil {
		t.Fatal("a note written at the cap did not land whole")
	}

	// the one tap frees room
	capName := sidecar.SessionCapNetwork
	if member {
		capName = sidecar.SessionCapMember
	}
	expired, err := world.storage.ExpireOldestBlobs(t.Context(), &sidecar.SessionExpireArgs{Cap: capName, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if expired.BlobCount == 0 {
		t.Fatalf("the tap expired nothing: %+v", expired)
	}
	if state := world.check(); state.Capped() {
		t.Fatalf("still capped after the tap: %+v", state)
	}
	testRecordAppend(t, world.record, testRecordNote(nil, "a later push the held bodies ride"))
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries = testSessionCapRead(t, world.testSessionJournalWorld, recorder.run.RunId)
	if states := testSessionCapStates(entries, sidecar.RecordKindSessionEntry); len(states) != 3 ||
		slices.ContainsFunc(states, func(state sidecar.RecordEntryState) bool { return state != sidecar.RecordEntryLive }) {
		t.Fatalf("the held nodes after the tap read %v", states)
	}
	// the old run's nodes stayed through the expiry
	if states := testSessionCapStates(testSessionCapRead(t, world.testSessionJournalWorld, old.run.RunId), sidecar.RecordKindSessionEntry); slices.ContainsFunc(states,
		func(state sidecar.RecordEntryState) bool { return state != sidecar.RecordEntryLive }) {
		t.Fatalf("the expiry took a node: %v", states)
	}
}

// At 90% of the network's storage history stops leaving the device, every call still journaled and every header
// leaving, until the one tap frees room.
func TestSessionHistoryStopsLeavingAtNetworkCap(t *testing.T) {
	testSessionHistoryStopsLeavingAtCap(t, false)
}

// At the member's share, the network well under its cap, history stops leaving likewise.
func TestSessionHistoryStopsLeavingAtMemberShare(t *testing.T) {
	testSessionHistoryStopsLeavingAtCap(t, true)
}

// auto is all of the storage for a network of one member, and of two, and 2/n for n; a share an Owner or Admin set
// is held within 0.05 and 1.
func TestSessionMemberShareAutoOneAndTwoOverN(t *testing.T) {
	settings := sidecar.DefaultSessionSettings()
	for _, want := range []struct {
		share   *sidecar.SessionMemberShare
		members int
		got     float64
	}{
		{nil, 1, 1}, {nil, 2, 1}, {nil, 4, 0.5}, {nil, 20, 0.1}, {&sidecar.SessionMemberShare{Auto: true}, 10, 0.2},
		{&sidecar.SessionMemberShare{Fraction: 0.3}, 20, 0.3}, {&sidecar.SessionMemberShare{Fraction: 0.01}, 20, 0.05},
		{&sidecar.SessionMemberShare{Fraction: 2}, 20, 1},
	} {
		if got := sidecar.SessionMemberShareOf(want.share, want.members, settings); got != want.got {
			t.Errorf("%+v of %d members: %v, not %v", want.share, want.members, got, want.got)
		}
	}
}

// Past the spool's budget the oldest held bodies drop: a coverage entry of their run names them in bodies_dropped,
// gap spool_drop, and readers read them dropped, the newer ones still withheld, none alarming.
func TestSessionSpoolDropNamesBodiesDropped(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	ingest.SpoolByteCount = 40 * 1024
	world := newTestSessionCapWorld(t, ingest)
	testSessionCapRun(t, world.testSessionJournalWorld, 256*1024)
	world.set(0, 1)
	if state := world.check(); !state.Capped() {
		t.Fatalf("not capped at no storage: %+v", state)
	}
	recorder := newTestSessionRecorder(t, world.testSessionJournalWorld)
	parent := recorder.message("", testSessionRebuildSystem("Take notes."), "")
	for i := range 6 {
		// each item near the cap, so six of them pass the budget
		parent = recorder.message(parent, testSessionRebuildUser(strings.Repeat("note "+string(rune('a'+i))+" ", 1500)), "")
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	state := world.check()
	if state.HeldByteCount > ingest.SpoolByteCount || state.HeldBodyCount == 0 {
		t.Fatalf("after the drop: %+v", state)
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := testSessionCapRead(t, world.testSessionJournalWorld, recorder.run.RunId)
	dropped := []uint64{}
	withheld := 0
	var coverage *protocol.Coverage
	for _, entry := range entries {
		switch {
		case entry.Kind() == sidecar.RecordKindSessionEntry && entry.State == sidecar.RecordEntryDropped:
			dropped = append(dropped, entry.Header.Header.GetSeq())
		case entry.Kind() == sidecar.RecordKindSessionEntry && entry.State == sidecar.RecordEntryWithheld:
			withheld += 1
		case entry.Kind() == sidecar.RecordKindCoverage:
			coverage = &protocol.Coverage{}
			if err := proto.Unmarshal(entry.Body, coverage); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(dropped) == 0 || withheld == 0 || coverage == nil {
		t.Fatalf("%d dropped, %d withheld, coverage %v", len(dropped), withheld, coverage)
	}
	if !strings.HasPrefix(coverage.GetGaps()[0], sidecar.RecordCoverageGapSpoolDrop) || len(coverage.GetBodiesDropped()) == 0 {
		t.Fatalf("the coverage: %v", coverage)
	}
	named := []uint64{}
	for _, seqs := range coverage.GetBodiesDropped() {
		for seq := seqs.GetFirst(); seq <= seqs.GetLast(); seq += 1 {
			named = append(named, seq)
		}
	}
	slices.Sort(dropped)
	if !slices.Equal(named, dropped) {
		t.Fatalf("bodies_dropped names %v, the readers dropped %v", named, dropped)
	}
	if reasons := world.device.alarmReasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// At 80% of the storage the warning names the largest runs and the bytes to free; the one tap, the person's act alone,
// expires the oldest blobs by push time until history is under 70% of that cap, no more, and every node stays.
func TestSessionOneTapExpiryToSeventyPercent(t *testing.T) {
	world := newTestSessionCapWorld(t, nil)
	runs := []*testSessionRecorder{}
	for range 4 {
		recorder, _ := testSessionCapRun(t, world.testSessionJournalWorld, 1024*1024)
		runs = append(runs, recorder)
		world.world.clock.Advance(time.Hour)
	}
	state := world.check()
	// warned at the network's storage, under its cap
	world.set(int64(float64(state.NetworkUsed)/0.85), 1)
	state = world.check()
	if state.Warning != sidecar.SessionCapNetwork || state.Capped() || state.ExpiryNeed <= 0 {
		t.Fatalf("the warning: %+v", state)
	}
	sizes, err := world.storage.Sizes(t.Context(), nil)
	if err != nil || len(sizes.Largest) == 0 || len(sizes.Runs) != 4 {
		t.Fatalf("the view: %+v, %v", sizes, err)
	}
	if _, err := world.storage.ExpireOldestBlobs(t.Context(), &sidecar.SessionExpireArgs{}); !errors.Is(err, sidecar.ErrSessionStorageUnconfirmed) {
		t.Fatalf("an unconfirmed tap: %v", err)
	}
	if _, err := world.storage.ExpireOldestBlobs(t.Context(), &sidecar.SessionExpireArgs{Confirmed: true, HarnessAncestor: true}); !errors.Is(err, sidecar.ErrSessionStorageUnconfirmed) {
		t.Fatalf("a tap under a harness: %v", err)
	}
	expired, err := world.storage.ExpireOldestBlobs(t.Context(), &sidecar.SessionExpireArgs{Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	after := world.check()
	if float64(after.NetworkUsed) >= 0.7*float64(after.StorageLimit) || after.Warning != "" {
		t.Fatalf("after the tap %+v: %+v", expired, after)
	}
	// the oldest run's blobs went first, the newest run's stayed, and every node stayed
	oldest := testSessionCapRead(t, world.testSessionJournalWorld, runs[0].run.RunId)
	newest := testSessionCapRead(t, world.testSessionJournalWorld, runs[3].run.RunId)
	if states := testSessionCapStates(oldest, sidecar.RecordKindSessionBlob); slices.ContainsFunc(states, func(state sidecar.RecordEntryState) bool { return !state.KeyGone() }) {
		t.Fatalf("the oldest run's blobs: %v", states)
	}
	if states := testSessionCapStates(newest, sidecar.RecordKindSessionBlob); slices.ContainsFunc(states, func(state sidecar.RecordEntryState) bool { return state.KeyGone() }) {
		t.Fatalf("the newest run's blobs: %v", states)
	}
	for _, recorder := range runs {
		if states := testSessionCapStates(testSessionCapRead(t, world.testSessionJournalWorld, recorder.run.RunId), sidecar.RecordKindSessionEntry); slices.ContainsFunc(states,
			func(state sidecar.RecordEntryState) bool { return state != sidecar.RecordEntryLive }) {
			t.Fatalf("a node went with the blobs: %v", states)
		}
	}
}
