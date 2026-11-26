//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-04's reader (DESIGN-COMPUTE §24.6, §24.7, CF-18's first steps, D-CTXH-9, D-CTXH-10) and record_query's session
// rows on sidecartest's streams: a run's nodes verified by writer, chain, parent and same_as, a node another writer
// filed in the run, one off its parent's chain and one whose parent the run does not hold each shown invalid and
// alarmed; a phone that syncs the vault holding every header and no body until it opens a run, then fetching that
// run's alone; record_query returning a session entry's body only when it is named, and a node a tagged sidecar wrote
// as an untrusted stub unless untrusted: include, which taints first. External, on session_journal_test.go's world.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A run's honest nodes verify: every node held, valid, its parent the run's; and a node another writer filed in the
// run, one whose chain hash is not its parent's and its item's, and one naming a parent the run does not hold, each
// read invalid with a bad_entry alarm, while the honest ones stay valid.
func TestSessionReaderVerifiesWritersChainsAndParents(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Read."), "")
	prompt := recorder.message(system, testSessionRebuildUser("Hello."), "")
	recorder.message(prompt, testSessionRebuildAssistant("Hello back.", ""), "")
	honest := recorder.nodes[prompt].journaled

	forge := func(record *sidecar.SidecarRecord, parentNodeId []byte, parentChain []byte, text string, chainOff bool) []byte {
		t.Helper()
		item := []byte(`{"id":"` + sidecar.NewHarnessPiEntryId() + `","message":{"content":` + testSessionJsonString(text) + `,"role":"user","timestamp":1800000000000},"parentId":null,"timestamp":"2027-01-15T08:00:00.000Z","type":"message"}`)
		itemSha256 := testSessionSha256(string(item))
		chain := testSessionChain(parentChain, itemSha256[:])
		if chainOff {
			chain[0] ^= 0xff
		}
		nodeId := sidecar.NewId()
		if _, err := record.Writer().Append(&sidecar.RecordDraft{
			Kind: sidecar.RecordKindSessionEntry, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId, Rides: true,
			Body: &protocol.SessionEntryBody{NodeId: nodeId.Bytes(), ParentNodeId: parentNodeId, Type: uint32(sidecar.SessionNodeMessage),
				Item: item, ItemSha256: itemSha256[:], ChainSha256: chain[:]},
		}); err != nil {
			t.Fatal(err)
		}
		return nodeId.Bytes()
	}
	// off its parent's chain, by the run's own writer
	offChain := forge(world.record, honest.NodeId.Bytes(), honest.ChainSha256[:], "off chain", true)
	// a parent no node of the run is
	orphan := forge(world.record, sidecar.NewId().Bytes(), honest.ChainSha256[:], "orphan", false)
	// another writer's node in the run, its chain honest
	intruder := world.world.device(true)
	intruderRecord := intruder.open()
	intruded := forge(intruderRecord, honest.NodeId.Bytes(), honest.ChainSha256[:], "intruder", false)
	if err := intruderRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	device, _, view := world.openOn(t, recorder.run.RunId)
	invalid := map[string]error{}
	valid := 0
	for _, node := range view.Nodes {
		if node.Body == nil {
			t.Fatalf("a node not held after the run opened: %s", node.State)
		}
		switch nodeId := node.Body.GetNodeId(); {
		case bytes.Equal(nodeId, offChain):
			invalid["off chain"] = node.Invalid
		case bytes.Equal(nodeId, orphan):
			invalid["orphan"] = node.Invalid
		case bytes.Equal(nodeId, intruded):
			invalid["intruder"] = node.Invalid
		default:
			if node.Invalid != nil {
				t.Errorf("an honest node is invalid: %v", node.Invalid)
			}
			valid += 1
		}
	}
	if valid != 3 {
		t.Fatalf("%d honest nodes valid", valid)
	}
	for _, name := range []string{"off chain", "orphan", "intruder"} {
		if err, ok := invalid[name]; !ok || !errors.Is(err, sidecar.ErrSessionNodeInvalid) {
			t.Errorf("the %s node: %v", name, err)
		}
	}
	alarms := 0
	for _, reason := range device.alarmReasons() {
		if reason == sidecar.SidecarRecordAlarmBadEntry {
			alarms += 1
		}
	}
	if alarms != 3 {
		t.Errorf("%d bad_entry alarms for three invalid nodes", alarms)
	}
}

// RecordStreams counting the body files read.
type testSessionCountingStreams struct {
	sidecar.RecordStreams
	stateLock sync.Mutex
	bodyReads int
}

func (self *testSessionCountingStreams) ReadBody(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, version uint64, path string) ([]byte, error) {
	self.stateLock.Lock()
	self.bodyReads += 1
	self.stateLock.Unlock()
	return self.RecordStreams.ReadBody(ctx, repoId, writerSidecarId, version, path)
}

func (self *testSessionCountingStreams) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.bodyReads
}

// A phone that syncs the vault holds every session header and no body: each of its runs' nodes reads deferred, and no
// body file is read. Opening one run fetches that run's bodies alone, each held to its header's commitment as it comes,
// while the other run's stay deferred.
func TestSessionReaderFetchesBodiesOnlyWhenOpened(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	opened := newTestSessionRecorder(t, world)
	system := opened.message("", testSessionRebuildSystem("One."), "")
	opened.message(system, testSessionRebuildUser(strings.Repeat("a long prompt ", 2000)), "")
	other := newTestSessionRecorder(t, world)
	other.message("", testSessionRebuildSystem("Two."), "")
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	phone := world.world.device(true)
	counting := &testSessionCountingStreams{RecordStreams: phone.tap.RecordStreams}
	phone.tap.RecordStreams = counting
	record := phone.open()
	reader := record.SessionReader()
	headers, err := reader.Headers(t.Context(), world.world.vaultId, opened.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range headers.Nodes {
		if node.Body != nil || node.State != sidecar.RecordEntryDeferred {
			t.Fatalf("a header read with its body: %s", node.State)
		}
	}
	if counting.reads() != 0 || len(headers.Nodes) != 2 {
		t.Fatalf("%d body reads in a sync, %d headers", counting.reads(), len(headers.Nodes))
	}
	view, err := reader.Open(t.Context(), world.world.vaultId, opened.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	blobs := len(view.Blobs)
	if blobs == 0 {
		t.Fatal("the long prompt kept no blob")
	}
	if view.Fetched != 2+blobs || counting.reads() != 2+blobs {
		t.Fatalf("opening fetched %d bodies in %d reads, not %d", view.Fetched, counting.reads(), 2+blobs)
	}
	for _, node := range view.Nodes {
		if node.Body == nil || node.State != sidecar.RecordEntryLive || node.Invalid != nil {
			t.Fatalf("an opened node: %s, %v", node.State, node.Invalid)
		}
	}
	untouched, err := reader.Headers(t.Context(), world.world.vaultId, other.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range untouched.Nodes {
		if node.State != sidecar.RecordEntryDeferred {
			t.Fatalf("the other run's node: %s", node.State)
		}
	}
	for _, reason := range phone.alarmReasons() {
		t.Errorf("an alarm: %s", reason)
	}
}

// A device of the world's member that the state admits as tagged, sponsored by the member: it deposits into the vault.
func (self *testRecordWorld) taggedDevice() *testRecordDevice {
	self.t.Helper()
	device := self.device(false)
	delete(self.fixture.Members, device.sidecarId)
	self.fixture.Sponsors[device.sidecarId] = self.memberId
	self.publish()
	return device
}

// record_query returns a session entry's body only when the entry is named: a listing of the run's kinds gives each
// row as a raw stub, and naming the entry gives its body, of the member's own trust.
func TestRecordQuerySessionBodyOnlyWhenNamed(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	recorder.message("", testSessionRebuildSystem("Hello."), "")
	_, record, _ := world.openOn(t, recorder.run.RunId)
	projection, err := sidecar.NewRecordProjection(&sidecar.RecordProjectionArgs{Record: record})
	if err != nil {
		t.Fatal(err)
	}
	page, err := projection.Query(t.Context(), &sidecar.RecordQueryArgs{RunId: &recorder.run.RunId, Kinds: []sidecar.RecordKind{sidecar.RecordKindSessionEntry}})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("the listing: %+v, %v", page, err)
	}
	row := page.Rows[0]
	if !row.Stub || row.StubReason != sidecar.RecordStubRaw || row.Fields != nil {
		t.Fatalf("a session entry listed with its body: %+v", row)
	}
	named, err := projection.Query(t.Context(), &sidecar.RecordQueryArgs{EntryId: &row.EntryId})
	if err != nil || len(named.Rows) != 1 || named.Rows[0].Stub || named.Rows[0].Trust != sidecar.RecordTrustOwn || named.Rows[0].Fields == nil {
		t.Fatalf("the named entry: %+v, %v", named.Rows, err)
	}
}

// A session node a tagged sidecar wrote, deposited and ingested into the vault, is untrusted to record_query even with
// its taint bit clear: named, it returns as an untrusted stub; with untrusted: include it returns its body, the run
// tainted first, and with no way to taint nothing untrusted returns.
func TestRecordQueryUntrustedNodeStubUnlessInclude(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	tagged := world.world.taggedDevice()
	taggedRecord := tagged.open()
	runId := sidecar.NewId()
	world.world.runs.StartRun(runId)
	item := []byte(`{"id":"0000000a","message":{"content":"a cloud agent's text","role":"user","timestamp":1800000000000},"parentId":null,"timestamp":"2027-01-15T08:00:00.000Z","type":"message"}`)
	itemSha256 := testSessionSha256(string(item))
	chain := testSessionChain(nil, itemSha256[:])
	refs, err := taggedRecord.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindSessionEntry, Source: sidecar.RecordSourceObserved, RunId: &runId,
		Body: &protocol.SessionEntryBody{NodeId: sidecar.NewId().Bytes(), Type: uint32(sidecar.SessionNodeMessage), Item: item, ItemSha256: itemSha256[:], ChainSha256: chain[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := taggedRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.record.Ingester().Ingest(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.world.device(true)
	record := reader.open()
	if err := record.Reader().Sync(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Reader().FetchBodies(t.Context(), world.world.vaultId, nil); err != nil {
		t.Fatal(err)
	}
	projection, err := sidecar.NewRecordProjection(&sidecar.RecordProjectionArgs{Record: record})
	if err != nil {
		t.Fatal(err)
	}
	entryId := refs[0].EntryId
	stubbed, err := projection.Query(t.Context(), &sidecar.RecordQueryArgs{EntryId: &entryId})
	if err != nil || len(stubbed.Rows) != 1 {
		t.Fatalf("the named node: %+v, %v", stubbed, err)
	}
	row := stubbed.Rows[0]
	if row.Tainted || row.Trust != sidecar.RecordTrustUntrusted || !row.Stub || row.StubReason != sidecar.RecordStubUntrusted || row.Fields != nil {
		t.Fatalf("a tagged sidecar's node: %+v", row)
	}
	if _, err := projection.Query(t.Context(), &sidecar.RecordQueryArgs{EntryId: &entryId, Untrusted: true}); !errors.Is(err, sidecar.ErrRecordProjectionNoTaint) {
		t.Fatalf("include with no taint: %v", err)
	}
	taints := 0
	included, err := projection.Query(t.Context(), &sidecar.RecordQueryArgs{EntryId: &entryId, Untrusted: true, Taint: func() error {
		taints += 1
		return nil
	}})
	if err != nil || len(included.Rows) != 1 || included.Rows[0].Stub || !included.Tainted || taints != 1 {
		t.Fatalf("include: %+v, %d taints, %v", included, taints, err)
	}
	if !slices.ContainsFunc(included.Rows, func(row *sidecar.RecordQueryRow) bool { return row.Fields != nil }) {
		t.Fatal("the included node has no body")
	}
}
