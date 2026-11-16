//go:build !ios_extension

// SEARCH-M10-28's record documents (§16.10's documents and rule rows; RECORD.md 7.1 to 7.3; DESIGN-DETAILS 15.2.8 to
// 15.2.10): which entries each log indexes, each kind's title and text, a claim's fields 13 and 14, fields 9 and 11
// from the run's first context entry its stream holds and blocked while that entry's ERASE waits for its CUT, the
// reader's stream holding only its own copies and refusing a version it has not read, the keys an ERASE masks until a
// set lists them, and a record log's cards riding a backfill, its erasure ref read first; all on fakes.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The writer of every test entry unless one says otherwise, and the time its seq 0 would stand at.
var (
	testRecordWriterId   = evsTestId("record writer")
	testRecordTimeMillis = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC).UnixMilli()
)

// A fake stream R of a log: its entries, each at its copy's version, read to readTo.
type testRecordStream struct {
	logKind protocol.RepoKind
	refId   Id
	readTo  uint64
	entries []*indexRecordEntry
}

func testNewRecordStream(logKind protocol.RepoKind, label string) *testRecordStream {
	return &testRecordStream{logKind: logKind, refId: evsTestId("stream " + label)}
}

func (self *testRecordStream) LogKind() protocol.RepoKind {
	return self.logKind
}

func (self *testRecordStream) RefId() Id {
	return self.refId
}

func (self *testRecordStream) Entries(ctx context.Context, refVersion uint64) ([]*indexRecordEntry, error) {
	if self.readTo < refVersion {
		return nil, errIndexRecordBehind
	}
	entries := []*indexRecordEntry{}
	for _, entry := range self.entries {
		if entry.version <= refVersion {
			copied := *entry
			entries = append(entries, &copied)
		}
	}
	return entries, nil
}

// Puts entry in R at R's next version, at that version's stream path.
func (self *testRecordStream) add(t testing.TB, entry *indexRecordEntry) *indexRecordEntry {
	t.Helper()
	self.readTo += 1
	path, err := RecordStreamPath(self.readTo)
	if err != nil {
		t.Fatal(err)
	}
	copied := *entry
	copied.version, copied.path = self.readTo, path
	self.entries = append(self.entries, &copied)
	return &copied
}

// An entry labeled label of kind in run (zero for none) at seq in its writer's chain, its time a second a seq after
// testRecordTimeMillis, its body body's bytes (nil for none), one key row of its own.
func testRecordEntry(t testing.TB, label string, kind RecordKind, runId Id, seq uint64, body proto.Message) *indexRecordEntry {
	t.Helper()
	entryId := evsTestId("entry " + label)
	header := &protocol.RecordHeader{
		EntryId: entryId.Bytes(), WriterSidecarId: testRecordWriterId.Bytes(), Seq: seq, Kind: uint32(kind),
		TimeMillis: testRecordTimeMillis + int64(seq)*1000, AgentId: evsTestId("agent").Bytes(),
	}
	if runId != (Id{}) {
		header.RunId = runId.Bytes()
	}
	entry := &indexRecordEntry{entryId: entryId, header: header, slotKeys: []RecordSlotKey{{SlotId: evsTestId("slot " + label)}}}
	if body != nil {
		encoded, err := proto.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		entry.body = encoded
	}
	return entry
}

// A source of stream at epoch, its erasure test from erasures and set.
func testRecordSource(t testing.TB, stream indexRecordStream, epoch uint64, erasures []*RecordStreamErasure, set *protocol.IndexErasureSet) *IndexRecordSource {
	t.Helper()
	source, err := newIndexRecordSource(&indexRecordSourceArgs{
		stream: stream, epoch: epoch, erasures: newIndexRecordErasures(erasures, set), format: DefaultIndexFormatSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// Every document a source gives at refVersion, failing on any error.
func testRecordDocuments(t testing.TB, source *IndexRecordSource, refVersion uint64) []*IndexDocument {
	t.Helper()
	documents := []*IndexDocument{}
	if err := source.IndexDocuments(context.Background(), refVersion, func(document *IndexDocument) error {
		documents = append(documents, document)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return documents
}

// A document's field n as text.
func testRecordField(document *IndexDocument, n int) string {
	return string(document.Fields[n])
}

// The document named name, nil for none.
func testRecordDocumentNamed(documents []*IndexDocument, name string) *IndexDocument {
	for _, document := range documents {
		if string(document.Name) == name {
			return document
		}
	}
	return nil
}

// An ERASE of erasureId naming entries by their note and keys by their rows, complete or not.
func testRecordErase(t testing.TB, erasureId Id, complete bool, version uint64, keys []RecordSlotKey, entryIds ...Id) *RecordStreamErasure {
	t.Helper()
	body := &protocol.ErasureBody{ErasureId: erasureId.Bytes(), Reason: 1}
	for _, entryId := range entryIds {
		body.EntryIds = append(body.EntryIds, entryId.Bytes())
	}
	note, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	erasure := &RecordStreamErasure{Version: version, ErasureId: erasureId, Complete: complete, SealedNote: note}
	for index := range keys {
		erasure.Keys = append(erasure.Keys, &keys[index])
	}
	return erasure
}

// An erasure set listing erasureIds.
func testRecordErasureSet(erasureIds ...Id) *protocol.IndexErasureSet {
	set := &protocol.IndexErasureSet{}
	for _, erasureId := range erasureIds {
		set.Erasures = append(set.Erasures, &protocol.IndexErasure{ErasureId: erasureId.Bytes(), Epoch: 1})
	}
	return set
}

// RECORD.md 7.1's documents row: a vault indexes its coordination entries and one card a run; a team record its cards
// alone; a record repo each entry but class log, raw capture and copy, and no card.
func TestRecordDocumentsByLog(t *testing.T) {
	runId := evsTestId("run")
	entries := []*indexRecordEntry{
		testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "claude-code", AgentLabel: "planner"}),
		testRecordEntry(t, "claim", RecordKindClaim, runId, 2, &protocol.CoordinationBody{Text: "the release notes", ClaimState: 1}),
		testRecordEntry(t, "note", RecordKindNote, Id{}, 3, &protocol.CoordinationBody{Text: "deploys pause friday"}),
		testRecordEntry(t, "change", RecordKindChange, runId, 4, &protocol.ChangeBody{Project: "atlas", Commits: []string{"a1b2c3"}}),
		testRecordEntry(t, "transcript", RecordKindTranscript, runId, 5, &protocol.TranscriptBody{Lines: []byte("{}\n")}),
		testRecordEntry(t, "retention", RecordKindRetention, Id{}, 6, &bridge.Signed{}),
		testRecordEntry(t, "copy", RecordKindCopy, Id{}, 7, &protocol.CopyBody{}),
		testRecordEntry(t, "approval", RecordKindApproval, runId, 8, &protocol.ApprovalRequest{}),
	}
	kinds := func(documents []*IndexDocument) []string {
		names := []string{}
		for _, document := range documents {
			names = append(names, testRecordField(document, indexFieldFirstRegistered))
		}
		return names
	}
	cases := []struct {
		logKind protocol.RepoKind
		want    []string
	}{
		{logKind: protocol.RepoKind_REPO_KIND_VAULT, want: []string{"claim", "note", "run"}},
		{logKind: protocol.RepoKind_REPO_KIND_TEAM_RECORD, want: []string{"run"}},
		{logKind: protocol.RepoKind_REPO_KIND_RECORD, want: []string{"context", "claim", "note", "change", "approval"}},
	}
	for _, c := range cases {
		stream := testNewRecordStream(c.logKind, "by log")
		for _, entry := range entries {
			stream.add(t, entry)
		}
		documents := testRecordDocuments(t, testRecordSource(t, stream, 1, nil, nil), stream.readTo)
		if got := kinds(documents); !slices.Equal(got, c.want) {
			t.Errorf("log %v indexes %v, want %v", c.logKind, got, c.want)
		}
		for _, document := range documents {
			if document.Kind == IndexDocRecord && !strings.HasPrefix(string(document.Name), recordStreamPathPrefix) {
				t.Errorf("an entry document named %q", document.Name)
			}
		}
	}
	if _, err := newIndexRecordSource(&indexRecordSourceArgs{
		stream: testNewRecordStream(protocol.RepoKind_REPO_KIND_DIRECTORY, "directory"), format: DefaultIndexFormatSettings(),
	}); !errors.Is(err, errIndexRecordLogKind) {
		t.Fatalf("a directory's source: %v", err)
	}
}

// RECORD.md 7.2: each kind's title and text, the listed values one a line, numbered enumerations by name; an approval's
// CanonicalAction strings in field order and never its preview; a kind this build does not know indexed as kind-<n>
// with no title or text; and fields 6, 7, 8 and 10 from the header.
func TestRecordEntryTitleAndText(t *testing.T) {
	runId := evsTestId("run")
	action, err := proto.Marshal(&protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_MAIL_SEND), Recipients: []string{"ops@example.com"},
		Preview: "never indexed", Host: "smtp.example.com", Path: "notes/send.md",
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := proto.Marshal(&protocol.ApprovalDecision{ApprovalId: []byte{0xab, 0xcd}, Decision: 1, Channel: 2})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind  RecordKind
		body  proto.Message
		title string
		text  string
	}{
		{kind: RecordKindClaim, body: &protocol.CoordinationBody{Text: "migrate the queue  \nwith a plan", Targets: []string{"repo:alpha"}},
			title: "migrate the queue", text: "migrate the queue  \nwith a plan\nrepo:alpha"},
		{kind: RecordKindCheck, body: &protocol.CoordinationBody{Text: "lint passes", Result: 3, Targets: []string{"pr:12"}},
			title: "lint passes", text: "lint passes\nobjection\npr:12"},
		{kind: RecordKindContext, body: &protocol.ContextBody{Harness: "codex", AgentLabel: "reviewer", Model: "gpt-x", Project: "atlas", PermissionMode: "default"},
			title: "codex reviewer", text: "gpt-x\natlas\ndefault"},
		{kind: RecordKindChange, body: &protocol.ChangeBody{Project: "atlas", Commits: []string{"c0ffee", "decade"}},
			title: "change atlas", text: "c0ffee\ndecade"},
		{kind: RecordKindPermission, body: &protocol.PermissionBody{PermissionMode: "plan", ToolClass: 1, DecidedBy: 4},
			title: "plan", text: "shell\nclassifier"},
		{kind: RecordKindApproval, body: &protocol.ApprovalRequest{CanonicalAction: action, Summary: "agent prose"},
			title: "mail_send", text: "ops@example.com\nsmtp.example.com\nnotes/send.md"},
		{kind: RecordKindApprovalDecision, body: &bridge.Signed{Body: decision},
			title: "approve presence", text: "abcd"},
		{kind: RecordKindRoute, body: &protocol.RouteBody{Event: 1, Kind: 2, TargetSidecarId: []byte{0x01}, TargetPort: 8080, Cidrs: []string{"192.0.2.0/24"}},
			title: "opened expose", text: "01\n8080\n192.0.2.0/24"},
		{kind: RecordKindPublish, body: &protocol.PublishBody{Event: 2, Host: "app.example.com", Audience: 3},
			title: "closed app.example.com", text: "app.example.com\n3"},
		{kind: RecordKindReach, body: &protocol.ReachReceipt{Kind: 3, Relays: []string{"edge-1"}, StreamCount: 4, ByteCount: 4096},
			title: "forward", text: "edge-1\n4\n4096"},
		{kind: RecordKindCoverage, body: &protocol.Coverage{Harness: "claude-code", Version: "2.1", Sources: []string{"hooks"}, Gaps: []string{"downtime:2"}},
			title: "coverage", text: "claude-code\n2.1\nhooks\ndowntime:2"},
		{kind: RecordKindRead, body: &protocol.ReadBody{Purpose: 2}, title: "read", text: "search"},
		{kind: RecordKindErasure, body: &protocol.ErasureBody{ErasureId: []byte{0x0e}, Reason: 3}, title: "erasure", text: "0e\nmoderation"},
		{kind: RecordKind(900), body: &protocol.CoordinationBody{Text: "unknown"}, title: "", text: ""},
	}
	for _, c := range cases {
		stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_RECORD, "kinds")
		entry := stream.add(t, testRecordEntry(t, "kind "+c.kind.String(), c.kind, runId, 1, c.body))
		documents := testRecordDocuments(t, testRecordSource(t, stream, 1, nil, nil), stream.readTo)
		if len(documents) != 1 {
			t.Errorf("kind %v: %d documents", c.kind, len(documents))
			continue
		}
		document := documents[0]
		if testRecordField(document, indexFieldTitle) != c.title || testRecordField(document, indexFieldBody) != c.text {
			t.Errorf("kind %v: title %q text %q, want %q and %q", c.kind, document.Fields[indexFieldTitle], document.Fields[indexFieldBody], c.title, c.text)
		}
		wantKind := c.kind.String()
		if !c.kind.Writable() {
			wantKind = fmt.Sprintf("kind-%d", uint32(c.kind))
		}
		if testRecordField(document, indexFieldFirstRegistered) != wantKind ||
			testRecordField(document, indexFieldFirstRegistered+1) != indexRecordHex(testRecordWriterId.Bytes()) ||
			testRecordField(document, indexFieldFirstRegistered+2) != indexRecordHex(evsTestId("agent").Bytes()) ||
			testRecordField(document, indexFieldFirstRegistered+4) != indexRecordHex(runId.Bytes()) {
			t.Errorf("kind %v: fields 6-10 %q", c.kind, document.Fields[indexFieldFirstRegistered:indexFieldFirstRegistered+5])
		}
		if document.Kind != IndexDocRecord || string(document.Name) != entry.path || document.Version != entry.version || document.Chunk != 0 {
			t.Errorf("kind %v: the document %+v", c.kind, document)
		}
	}
}

// RECORD.md 7.3: a claim's field 13 is its expiry in RFC 3339 UTC to the second and 14 its state by name; a handoff's
// 14 is handed_off; a vault indexes both.
func TestRecordClaimFields(t *testing.T) {
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "claims")
	expires := time.Date(2026, 11, 20, 17, 30, 15, 250e6, time.UTC)
	claim := stream.add(t, testRecordEntry(t, "claim", RecordKindClaim, Id{}, 1,
		&protocol.CoordinationBody{Text: "the queue", ExpiresMillis: expires.UnixMilli(), ClaimState: 2}))
	handoff := stream.add(t, testRecordEntry(t, "handoff", RecordKindHandoff, Id{}, 2, &protocol.CoordinationBody{Text: "over to you"}))
	documents := testRecordDocuments(t, testRecordSource(t, stream, 1, nil, nil), stream.readTo)
	claimDocument, handoffDocument := testRecordDocumentNamed(documents, claim.path), testRecordDocumentNamed(documents, handoff.path)
	if claimDocument == nil || handoffDocument == nil {
		t.Fatalf("documents %d", len(documents))
	}
	if got := testRecordField(claimDocument, indexFieldFirstRegistered+7); got != "2026-11-20T17:30:15Z" {
		t.Fatalf("a claim's field 13 %q", got)
	}
	if got := testRecordField(claimDocument, indexFieldFirstRegistered+8); got != "released" {
		t.Fatalf("a claim's field 14 %q", got)
	}
	if got := testRecordField(handoffDocument, indexFieldFirstRegistered+8); got != "handed_off" {
		t.Fatalf("a handoff's field 14 %q", got)
	}
}

// DESIGN-DETAILS 15.2.8's fields 9 and 11 (QD-782): from the first context entry of the run the stream holds at the
// pin, its newest four session ids; once that entry's erasure has a CUT below the epoch a rebuild reads the next
// context entry, or leaves them empty with none; and before the CUT a builder that applied the ERASE is blocked below
// the document's version, while one that has not reads the entry.
func TestEntryDocumentContextFields(t *testing.T) {
	runId := evsTestId("run")
	build := func(firstKeyGone bool, second bool) *testRecordStream {
		stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_RECORD, "context fields")
		first := testRecordEntry(t, "first context", RecordKindContext, runId, 1,
			&protocol.ContextBody{AgentLabel: "alpha", SessionIds: []string{"s1", "s2", "s3", "s4", "s5"}})
		first.keyGone = firstKeyGone
		if firstKeyGone {
			first.body = nil
		}
		stream.add(t, first)
		if second {
			stream.add(t, testRecordEntry(t, "second context", RecordKindContext, runId, 2, &protocol.ContextBody{AgentLabel: "beta", SessionIds: []string{"s9"}}))
		}
		stream.add(t, testRecordEntry(t, "change", RecordKindChange, runId, 3, &protocol.ChangeBody{Project: "atlas"}))
		return stream
	}
	changeOf := func(documents []*IndexDocument) *IndexDocument {
		for _, document := range documents {
			if testRecordField(document, indexFieldFirstRegistered) == "change" {
				return document
			}
		}
		t.Fatal("no change document")
		return nil
	}
	stream := build(false, true)
	change := changeOf(testRecordDocuments(t, testRecordSource(t, stream, 1, nil, nil), stream.readTo))
	if testRecordField(change, indexFieldFirstRegistered+3) != "alpha" || testRecordField(change, indexFieldFirstRegistered+5) != "s2 s3 s4 s5" {
		t.Fatalf("fields 9 and 11 %q %q", change.Fields[indexFieldFirstRegistered+3], change.Fields[indexFieldFirstRegistered+5])
	}
	erasureId := evsTestId("context erasure")
	firstId := evsTestId("entry first context")
	erase := testRecordErase(t, erasureId, false, 1, nil, firstId)
	// listed: the next context gives the fields
	stream = build(true, true)
	change = changeOf(testRecordDocuments(t, testRecordSource(t, stream, 2, []*RecordStreamErasure{erase}, testRecordErasureSet(erasureId)), stream.readTo))
	if testRecordField(change, indexFieldFirstRegistered+3) != "beta" || testRecordField(change, indexFieldFirstRegistered+5) != "s9" {
		t.Fatalf("after the CUT, fields 9 and 11 %q %q", change.Fields[indexFieldFirstRegistered+3], change.Fields[indexFieldFirstRegistered+5])
	}
	stream = build(true, false)
	change = changeOf(testRecordDocuments(t, testRecordSource(t, stream, 2, []*RecordStreamErasure{erase}, testRecordErasureSet(erasureId)), stream.readTo))
	if testRecordField(change, indexFieldFirstRegistered+3) != "" || testRecordField(change, indexFieldFirstRegistered+5) != "" {
		t.Fatal("with no context left, fields 9 and 11 stay empty")
	}
	// the ERASE applied, its CUT not yet: blocked below the lowest document whose fields read the entry, the second
	// context's own (version 2), and a builder that has not applied it reads the entry
	stream = build(true, true)
	source := testRecordSource(t, stream, 1, []*RecordStreamErasure{erase}, nil)
	err := source.IndexDocuments(context.Background(), stream.readTo, func(document *IndexDocument) error { return nil })
	blocked := &IndexRecordBlockedError{}
	if !errors.As(err, &blocked) || blocked.Version != 2 || !errors.Is(err, errIndexCardBlocked) {
		t.Fatalf("a builder holding the ERASE before its CUT: %v", err)
	}
	if from, err := source.blockedFrom(context.Background(), 2, stream.readTo); err != nil || from != 3 {
		t.Fatalf("blocked from %d above version 2, %v", from, err)
	}
	stream = build(false, true)
	change = changeOf(testRecordDocuments(t, testRecordSource(t, stream, 1, nil, nil), stream.readTo))
	if testRecordField(change, indexFieldFirstRegistered+3) != "alpha" {
		t.Fatal("a builder without the ERASE reads the first context")
	}
}

// One fake log reader: streams and entries as RecordReader holds them, and how often Sync ran.
type testRecordLogReader struct {
	streams []*RecordReadStream
	entries []*RecordReadEntry
	syncs   int
}

func (self *testRecordLogReader) Sync(ctx context.Context, logId Id) error {
	self.syncs += 1
	return nil
}

func (self *testRecordLogReader) Streams(logId Id) ([]*RecordReadStream, bool) {
	return self.streams, true
}

func (self *testRecordLogReader) Entries(logId Id) []*RecordReadEntry {
	return self.entries
}

func (self *testRecordLogReader) EntriesOfKinds(logId Id, from int, kinds ...RecordKind) ([]*RecordReadEntry, int) {
	entries := []*RecordReadEntry{}
	for _, entry := range self.entries {
		if slices.Contains(kinds, entry.Kind()) {
			entries = append(entries, entry)
		}
	}
	return entries, len(self.entries)
}

// The reader's entry of test entry e, with a copy at each of copies.
func testRecordReadEntry(entry *indexRecordEntry, state RecordEntryState, copies ...*RecordEntryCopy) *RecordReadEntry {
	return &RecordReadEntry{EntryId: entry.entryId, Header: &StoredRecordHeader{Header: entry.header}, State: state, Body: entry.body, Copies: copies}
}

// RecordReader's stream: only R's own copies at or below the version asked, every copy's key row, an erased entry's key
// gone, and a version the reader has not read refused.
func TestRecordReaderStreamHoldsItsOwnCopies(t *testing.T) {
	runId := evsTestId("run")
	streamA, streamB := evsTestId("stream sidecar a"), evsTestId("stream sidecar b")
	refA, refB := evsTestId("ref a"), evsTestId("ref b")
	note := testRecordEntry(t, "note", RecordKindNote, runId, 1, &protocol.CoordinationBody{Text: "both streams"})
	tool := testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Bash"})
	reader := &testRecordLogReader{
		streams: []*RecordReadStream{
			{StreamSidecarId: streamA, RefId: refA, Pushes: []*RecordReadPush{{Version: 1}, {Version: 2}}},
			{StreamSidecarId: streamB, RefId: refB, Pushes: []*RecordReadPush{{Version: 1}}},
		},
		entries: []*RecordReadEntry{
			testRecordReadEntry(note, RecordEntryLive,
				&RecordEntryCopy{StreamSidecarId: streamA, Version: 1, Path: "e/0/0/1", SlotId: evsTestId("slot a1")},
				&RecordEntryCopy{StreamSidecarId: streamB, Version: 1, Path: "e/0/0/1", SlotId: evsTestId("slot b1")}),
			testRecordReadEntry(tool, RecordEntryErased, &RecordEntryCopy{StreamSidecarId: streamA, Version: 2, Path: "e/0/0/2", SlotId: evsTestId("slot a2")}),
		},
	}
	stream := newIndexRecordReaderStream(reader, evsTestId("log"), protocol.RepoKind_REPO_KIND_VAULT, streamA, refA)
	entries, err := stream.Entries(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].path != "e/0/0/1" || entries[0].version != 1 || len(entries[0].slotKeys) != 2 {
		t.Fatalf("the note's copy %+v", entries[0])
	}
	if !entries[1].keyGone || entries[1].version != 2 {
		t.Fatalf("an erased entry %+v", entries[1])
	}
	if entries, err := stream.Entries(context.Background(), 1); err != nil || len(entries) != 1 {
		t.Fatalf("at version 1: %d entries, %v", len(entries), err)
	}
	streamOfB := newIndexRecordReaderStream(reader, evsTestId("log"), protocol.RepoKind_REPO_KIND_VAULT, streamB, refB)
	if _, err := streamOfB.Entries(context.Background(), 2); !errors.Is(err, errIndexRecordBehind) {
		t.Fatalf("a version the reader has not read: %v", err)
	}
	if entries, err := streamOfB.Entries(context.Background(), 1); err != nil || len(entries) != 1 || entries[0].path != "e/0/0/1" {
		t.Fatalf("stream b's own copy: %v %v", entries, err)
	}
}

// 15.2.10's masks: an ERASE masks, until a set lists them, the entry document of each copy of an entry it names, by key
// or by note, where the log indexes the entry's kind, and the card of each stream holding a copy of a card source; it
// masks nothing of an entry it does not name.
func TestRecordEraseMaskKeys(t *testing.T) {
	runId, otherRunId := evsTestId("run"), evsTestId("other run")
	streamA, streamB := evsTestId("stream sidecar a"), evsTestId("stream sidecar b")
	refA, refB := evsTestId("ref a"), evsTestId("ref b")
	refKey := bytes.Repeat([]byte{0x5a}, 32)
	note := testRecordEntry(t, "note", RecordKindNote, Id{}, 1, &protocol.CoordinationBody{Text: "two copies"})
	tool := testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Edit"})
	other := testRecordEntry(t, "other", RecordKindToolCall, otherRunId, 3, &protocol.ToolCallBody{ToolName: "Bash"})
	noteKeyA := RecordSlotKey{SlotId: evsTestId("slot note a")}
	entries := []*RecordReadEntry{
		testRecordReadEntry(note, RecordEntryErased,
			&RecordEntryCopy{StreamSidecarId: streamA, Version: 1, Path: "e/0/0/1", SlotId: noteKeyA.SlotId},
			&RecordEntryCopy{StreamSidecarId: streamB, Version: 4, Path: "e/0/0/4", SlotId: evsTestId("slot note b")}),
		testRecordReadEntry(tool, RecordEntryErased, &RecordEntryCopy{StreamSidecarId: streamA, Version: 2, Path: "e/0/0/2", SlotId: evsTestId("slot tool")}),
		testRecordReadEntry(other, RecordEntryLive, &RecordEntryCopy{StreamSidecarId: streamA, Version: 3, Path: "e/0/0/3", SlotId: evsTestId("slot other")}),
	}
	streams := []*RecordReadStream{{StreamSidecarId: streamA, RefId: refA}, {StreamSidecarId: streamB, RefId: refB}}
	erase := testRecordErase(t, evsTestId("erasure"), false, 1, []RecordSlotKey{noteKeyA}, tool.entryId)
	masked, err := indexRecordEraseMaskKeys(refKey, protocol.RepoKind_REPO_KIND_VAULT, erase, entries, streams)
	if err != nil {
		t.Fatal(err)
	}
	key := func(refId Id, name []byte) [indexIdByteCount]byte {
		key, err := indexDocKey(refKey, refId, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	want := [][indexIdByteCount]byte{
		key(refA, []byte("e/0/0/1")), key(refB, []byte("e/0/0/4")), key(refA, indexRunCardName(runId)),
	}
	slices.SortFunc(want, compareIndexKeys)
	if !slices.Equal(masked, want) {
		t.Fatalf("masked %x, want %x", masked, want)
	}
}

// A fake of a log's ERASE reads: every other call refuses.
type testRecordErasureStreams struct {
	RecordStreamsUnavailable
	erasures []*RecordStreamErasure
	reads    int
}

func (self *testRecordErasureStreams) ReadErasures(ctx context.Context, repoId Id, afterVersion uint64) ([]*RecordStreamErasure, error) {
	self.reads += 1
	erasures := []*RecordStreamErasure{}
	for _, erasure := range self.erasures {
		if afterVersion < erasure.Version {
			erasures = append(erasures, erasure)
		}
	}
	return erasures, nil
}

// 15.2.9's backfill row through a record log: the backfill reads the log's erasure ref (the reader synced, its ERASEs
// kept) before the first card it folds at an epoch, a run's card rides the backfill at E * 2^32 + c, and an entry an
// ERASE named whose erasure is complete stays out of the fold.
func TestRecordCardsRideTheBackfill(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, backfillerId := evsTestId("stream writer"), evsTestId("indexer")
	runId := evsTestId("run")
	logId := evsTestId("vault")
	stream := &RecordReadStream{StreamSidecarId: writer, RefId: world.content.refId}
	reader := &testRecordLogReader{streams: []*RecordReadStream{stream}}
	bodies := []proto.Message{
		&protocol.ContextBody{Harness: "claude-code", Title: "Ship the changelog", AgentLabel: "writer"},
		&protocol.ToolCallBody{ToolName: "Bash"},
		&protocol.ToolCallBody{ToolName: "Edit"},
	}
	kinds := []RecordKind{RecordKindContext, RecordKindToolCall, RecordKindToolCall}
	for index, body := range bodies {
		path, err := RecordStreamPath(uint64(index + 1))
		if err != nil {
			t.Fatal(err)
		}
		world.commit(t, writer, nil, testContentChange{path: path, content: []byte("entry")})
		entry := testRecordEntry(t, fmt.Sprintf("backfill %d", index), kinds[index], runId, uint64(index+1), body)
		stream.Pushes = append(stream.Pushes, &RecordReadPush{Version: uint64(index + 1)})
		reader.entries = append(reader.entries, testRecordReadEntry(entry, RecordEntryLive,
			&RecordEntryCopy{StreamSidecarId: writer, Version: uint64(index + 1), Path: path, SlotId: evsTestId(fmt.Sprintf("slot %d", index))}))
	}
	// the Edit call's erasure is complete: erased at any epoch, so out of the fold
	editId := evsTestId("entry backfill 2")
	reader.entries[2].State, reader.entries[2].Body = RecordEntryErased, nil
	streams := &testRecordErasureStreams{erasures: []*RecordStreamErasure{testRecordErase(t, evsTestId("edit erasure"), true, 1, nil, editId)}}
	log, err := newIndexRecordLog(reader, streams, logId, protocol.RepoKind_REPO_KIND_VAULT, nil, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	backfiller := world.backfiller(t, backfillerId, log.cards())
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, backfiller)
	if outcome.committed == nil || outcome.refs[0].h != 3 {
		t.Fatalf("the backfill's h %+v", outcome.refs)
	}
	if reader.syncs != 1 || streams.reads != 1 {
		t.Fatalf("the erasure ref read %d times, the reader synced %d", streams.reads, reader.syncs)
	}
	entries := world.entriesOf(t, backfillerId, string(indexRunCardName(runId)), 0)
	if len(entries) != 1 || entries[0].kind != indexEntryFull || entries[0].version != 3 {
		t.Fatalf("the run's card %+v", entries)
	}
	row := entries[0].entry.row
	if row.fields[indexFieldTitle] != "Ship the changelog" || row.fields[indexFieldFirstRegistered+6] != "Bash:1" ||
		!bytes.Equal(row.refId, world.content.refId.Bytes()) {
		t.Fatalf("the card's row: title %q tools %q", row.fields[indexFieldTitle], row.fields[indexFieldFirstRegistered+6])
	}
}
