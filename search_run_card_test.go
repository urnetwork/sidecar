//go:build !ios_extension

// SEARCH-M10-28's run cards (§16.10's run card row; RECORD.md 7.4; DESIGN-DETAILS 15.6's card tests; FS-80's run card
// and team-record cases): a card per stream, its version E * 2^32 + c and the bound past it, the fold's order, two
// devices folding one stream alike and a gap filled later moving the version, a rebuild writing the same bytes at the
// build's epoch, entries erased at the epoch left out while still counting toward c, a builder holding an ERASE before
// its CUT blocked and one without it folding the entry, a run with every source erased having no card, a team record's
// card holding nothing only the vault holds, and each log's mapping of row and text; all on a fake stream.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The card of runId in stream at its head, at epoch, failing on any error but those the caller reads.
func testRunCard(t testing.TB, stream *testRecordStream, runId Id, epoch uint64, erasures []*RecordStreamErasure, set *protocol.IndexErasureSet) (*IndexDocument, uint64, error) {
	t.Helper()
	erasedAtEpoch := newIndexRecordErasures(erasures, set).erasedAtEpoch
	return searchRunCard(context.Background(), stream, runId, stream.readTo, epoch, erasedAtEpoch, DefaultIndexRecordSettings(), DefaultIndexFormatSettings())
}

// A document's key set and row as a companion push under refId writes them.
func testRunCardPrepared(t testing.TB, document *IndexDocument, refId Id) *indexPreparedDocument {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := document.prepare(normalizer, true, refId, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

// QD-780: two streams of one log holding one run give two cards, one name, two doc_keys and two rows, each under its
// own stream's ref.
func TestCardKeyIsPerStream(t *testing.T) {
	runId := evsTestId("run")
	refKey := bytes.Repeat([]byte{0x2c}, 32)
	contextEntry := testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "claude-code", Title: "Rotate the keys"})
	streamA := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "a")
	streamB := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "b")
	streamA.add(t, contextEntry)
	streamB.add(t, contextEntry)
	cardA, _, err := testRunCard(t, streamA, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cardB, _, err := testRunCard(t, streamB, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(cardA.Name) != string(indexRunCardName(runId)) || !bytes.Equal(cardA.Name, cardB.Name) {
		t.Fatalf("names %q and %q", cardA.Name, cardB.Name)
	}
	keyA, err := indexDocKey(refKey, streamA.refId, cardA.Name, cardA.Chunk)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := indexDocKey(refKey, streamB.refId, cardB.Name, cardB.Chunk)
	if err != nil {
		t.Fatal(err)
	}
	if keyA == keyB {
		t.Fatal("two streams' cards share a doc_key")
	}
	rowA, rowB := testRunCardPrepared(t, cardA, streamA.refId).row, testRunCardPrepared(t, cardB, streamB.refId).row
	if !bytes.Equal(rowA.refId, streamA.refId.Bytes()) || !bytes.Equal(rowB.refId, streamB.refId.Bytes()) {
		t.Fatal("a card's row names another stream's ref")
	}
	if !strings.HasPrefix(rowA.locator, indexRunCardPrefix) || rowA.docKind != indexDocDerived {
		t.Fatalf("the row %+v", rowA)
	}
}

// QD-779: a card's version is E * 2^32 + c, and an epoch or a c at or past 2^32 writes no card.
func TestCardVersion(t *testing.T) {
	bits := DefaultIndexFormatSettings().CardVersionBitCount
	for _, epoch := range []uint64{1, 7, 1023} {
		for _, c := range []uint64{1, 1<<32 - 1} {
			version, err := indexRunCardVersion(epoch, c, bits)
			if err != nil || version != epoch*(1<<32)+c {
				t.Errorf("E %d, c %d: version %d, %v", epoch, c, version, err)
			}
		}
	}
	if _, err := indexRunCardVersion(1, 1<<32, bits); !errors.Is(err, errIndexCardVersionSpace) {
		t.Fatalf("c at 2^32: %v", err)
	}
	if _, err := indexRunCardVersion(1<<32, 1, bits); !errors.Is(err, errIndexCardVersionSpace) {
		t.Fatalf("an epoch at 2^32: %v", err)
	}
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "version")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "codex"}))
	stream.add(t, testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Bash"}))
	card, c, err := testRunCard(t, stream, runId, 7, nil, nil)
	if err != nil || c != 2 || card.Version != 7<<32|2 {
		t.Fatalf("the card's version %d, c %d, %v", card.Version, c, err)
	}
	stream.entries[1].version = 1 << 32
	stream.readTo = 1 << 32
	if _, _, err := testRunCard(t, stream, runId, 7, nil, nil); !errors.Is(err, errIndexCardVersionSpace) {
		t.Fatalf("a stream version at 2^32: %v", err)
	}
	// the build writes no card and holds the stream's pin below the run
	err = testRecordSource(t, stream, 7, nil, nil).IndexDocuments(context.Background(), stream.readTo, func(document *IndexDocument) error { return nil })
	blocked := &IndexRecordBlockedError{}
	if !errors.As(err, &blocked) || blocked.Version != 1 {
		t.Fatalf("a build past the version's bits: %v", err)
	}
}

// QD-783 #3: entries out of seq order in the stream fold in seq order, then entry_id order, so "newest" and "first"
// read the fold and not the stream.
func TestCardFoldOrder(t *testing.T) {
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "order")
	stream.add(t, testRecordEntry(t, "late", RecordKindContext, runId, 5, &protocol.ContextBody{Title: "Late title", Model: "model-late"}))
	stream.add(t, testRecordEntry(t, "early", RecordKindContext, runId, 2, &protocol.ContextBody{Title: "Early title", Model: "model-early"}))
	card, _, err := testRunCard(t, stream, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testRecordField(card, indexFieldTitle) != "Late title" {
		t.Fatalf("the newest context by seq gives the title, got %q", card.Fields[indexFieldTitle])
	}
	if card.StartedSeconds != uint64(testRecordTimeMillis/1000+2) {
		t.Fatalf("started %d, the first entry's by seq", card.StartedSeconds)
	}
	// one seq from two writers: entry_id order decides
	a := testRecordEntry(t, "tie a", RecordKindContext, runId, 9, &protocol.ContextBody{Title: "Tie A"})
	b := testRecordEntry(t, "tie b", RecordKindContext, runId, 9, &protocol.ContextBody{Title: "Tie B"})
	newer := map[bool]string{true: "Tie B", false: "Tie A"}[bytes.Compare(a.entryId[:], b.entryId[:]) < 0]
	stream.add(t, b)
	stream.add(t, a)
	card, _, err = testRunCard(t, stream, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testRecordField(card, indexFieldTitle) != newer {
		t.Fatalf("a tie at one seq gave %q, want %q", card.Fields[indexFieldTitle], newer)
	}
}

// 15.2.8's I12: two devices folding one stream at one epoch write equal documents, whatever order their readers hold
// the entries in; and a stream that later gains the entries of a gap moves c, and the version, past the first fold.
func TestCardIsAFunction(t *testing.T) {
	runId := evsTestId("run")
	entries := []*indexRecordEntry{
		testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "claude-code", Title: "Index the archive"}),
		testRecordEntry(t, "tool 1", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Read", Paths: []string{"docs/b.md"}}),
		testRecordEntry(t, "tool 2", RecordKindToolCall, runId, 3, &protocol.ToolCallBody{ToolName: "Edit", Paths: []string{"docs/a.md"}}),
		testRecordEntry(t, "change", RecordKindChange, runId, 6, &protocol.ChangeBody{Commits: []string{"feedface"}}),
	}
	device := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "one")
	for _, entry := range entries {
		device.add(t, entry)
	}
	other := &testRecordStream{logKind: device.logKind, refId: device.refId, readTo: device.readTo}
	other.entries = slices.Clone(device.entries)
	slices.Reverse(other.entries)
	cardOne, cOne, err := testRunCard(t, device, runId, 3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cardOther, cOther, err := testRunCard(t, other, runId, 3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cOne != cOther || !reflect.DeepEqual(cardOne, cardOther) {
		t.Fatalf("two devices' cards differ:\n%+v\n%+v", cardOne, cardOther)
	}
	preparedOne, preparedOther := testRunCardPrepared(t, cardOne, device.refId), testRunCardPrepared(t, cardOther, other.refId)
	if !slices.Equal(preparedOne.keys, preparedOther.keys) || !reflect.DeepEqual(preparedOne.row, preparedOther.row) {
		t.Fatal("two devices' key sets or rows differ")
	}
	// the gap between seq 3 and seq 6 arrives later, at a higher stream version
	device.add(t, testRecordEntry(t, "tool 4", RecordKindToolCall, runId, 4, &protocol.ToolCallBody{ToolName: "Read"}))
	cardFilled, cFilled, err := testRunCard(t, device, runId, 3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cFilled != 5 || cFilled <= cOne || cardFilled.Version <= cardOne.Version {
		t.Fatalf("c %d after the gap filled, %d before", cFilled, cOne)
	}
}

// FS-80's rebuild: a rebuild at a later epoch writes each card's bytes again, at that epoch's version.
func TestCardRebuild(t *testing.T) {
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "rebuild")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "cursor", Title: "Fix the flaky test"}))
	stream.add(t, testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Bash"}))
	first := testRecordDocuments(t, testRecordSource(t, stream, 4, nil, nil), stream.readTo)
	rebuilt := testRecordDocuments(t, testRecordSource(t, stream, 9, nil, nil), stream.readTo)
	if len(first) != 1 || len(rebuilt) != 1 {
		t.Fatalf("cards %d and %d", len(first), len(rebuilt))
	}
	if first[0].Version != 4<<32|2 || rebuilt[0].Version != 9<<32|2 {
		t.Fatalf("versions %d and %d", first[0].Version, rebuilt[0].Version)
	}
	rebuiltAtFirst := *rebuilt[0]
	rebuiltAtFirst.Version = first[0].Version
	if !reflect.DeepEqual(first[0], &rebuiltAtFirst) {
		t.Fatal("a rebuild wrote other bytes")
	}
}

// 15.2.2's erased at E: an entry an ERASE names whose erasure the set lists, and one whose erasure the set dropped as
// complete, are both left out of the fold, and still count toward c; one whose erasure is neither is not erased.
func TestCardSkipsErasedAtEpoch(t *testing.T) {
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "erased")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "codex"}))
	listed := stream.add(t, testRecordEntry(t, "listed", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Listed"}))
	dropped := stream.add(t, testRecordEntry(t, "dropped", RecordKindToolCall, runId, 3, &protocol.ToolCallBody{ToolName: "Dropped"}))
	stream.add(t, testRecordEntry(t, "kept", RecordKindToolCall, runId, 4, &protocol.ToolCallBody{ToolName: "Kept"}))
	for _, entry := range stream.entries[1:3] {
		entry.keyGone, entry.body = true, nil
	}
	listedId, droppedId := evsTestId("listed erasure"), evsTestId("dropped erasure")
	erasures := []*RecordStreamErasure{
		testRecordErase(t, listedId, false, 1, listed.slotKeys),
		testRecordErase(t, droppedId, true, 2, nil, dropped.entryId),
	}
	card, c, err := testRunCard(t, stream, runId, 5, erasures, testRecordErasureSet(listedId))
	if err != nil {
		t.Fatal(err)
	}
	if got := testRecordField(card, indexFieldFirstRegistered+6); got != "Kept:1" {
		t.Fatalf("the fold's tools %q", got)
	}
	if c != 4 || card.Version != 5<<32|4 {
		t.Fatalf("c %d, version %d", c, card.Version)
	}
	// the dropped erasure is complete with no CUT in the set; the listed one is in the set and pending
	erasures[1].Complete = false
	if _, _, err := testRunCard(t, stream, runId, 5, erasures, testRecordErasureSet(listedId)); !errors.Is(err, errIndexCardBlocked) {
		t.Fatalf("an ERASE whose erasure has no CUT below the epoch: %v", err)
	}
}

// 15.2.10's window between the ERASE and the CUT: a builder that applied the ERASE builds no card and holds the
// stream's pin below the run's first source entry; one that has not folds the entry, at the old epoch the CUT lists.
func TestCardBlockedBeforeTheCut(t *testing.T) {
	runId, otherRunId := evsTestId("run"), evsTestId("other run")
	build := func(applied bool) *testRecordStream {
		stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "blocked")
		stream.add(t, testRecordEntry(t, "other", RecordKindContext, otherRunId, 1, &protocol.ContextBody{Harness: "codex"}))
		stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 2, &protocol.ContextBody{Harness: "claude-code"}))
		erased := testRecordEntry(t, "erased", RecordKindToolCall, runId, 3, &protocol.ToolCallBody{ToolName: "Secret"})
		if applied {
			erased.keyGone, erased.body = true, nil
		}
		stream.add(t, erased)
		return stream
	}
	erasure := testRecordErase(t, evsTestId("pending erasure"), false, 1, nil, evsTestId("entry erased"))
	stream := build(true)
	if _, _, err := testRunCard(t, stream, runId, 1, []*RecordStreamErasure{erasure}, nil); !errors.Is(err, errIndexCardBlocked) {
		t.Fatalf("a builder holding the ERASE: %v", err)
	}
	source := testRecordSource(t, stream, 1, []*RecordStreamErasure{erasure}, nil)
	err := source.IndexDocuments(context.Background(), stream.readTo, func(document *IndexDocument) error { return nil })
	blocked := &IndexRecordBlockedError{}
	if !errors.As(err, &blocked) || blocked.Version != 2 {
		t.Fatalf("the build: %v", err)
	}
	if from, err := source.blockedFrom(context.Background(), 0, stream.readTo); err != nil || from != 2 {
		t.Fatalf("blocked from %d, %v", from, err)
	}
	// the other run is not held: its card is given for its own version
	if cards, err := source.cardsAt(context.Background(), []uint64{1}, stream.readTo); err != nil || len(cards) != 1 {
		t.Fatalf("the other run's card: %d, %v", len(cards), err)
	}
	stream = build(false)
	card, _, err := testRunCard(t, stream, runId, 1, nil, nil)
	if err != nil || testRecordField(card, indexFieldFirstRegistered+6) != "Secret:1" {
		t.Fatalf("a builder without the ERASE: %v", err)
	}
}

// QD-783 #4: a run whose every source entry is erased at the epoch has no card, and the source gives nothing for it.
func TestCardLastEntryErased(t *testing.T) {
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "last")
	only := stream.add(t, testRecordEntry(t, "only", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "codex"}))
	stream.entries[0].keyGone, stream.entries[0].body = true, nil
	erasureId := evsTestId("erasure")
	erasures := []*RecordStreamErasure{testRecordErase(t, erasureId, false, 1, nil, only.entryId)}
	card, c, err := testRunCard(t, stream, runId, 3, erasures, testRecordErasureSet(erasureId))
	if err != nil || card != nil || c != 1 {
		t.Fatalf("an empty fold: %+v, c %d, %v", card, c, err)
	}
	if documents := testRecordDocuments(t, testRecordSource(t, stream, 3, erasures, testRecordErasureSet(erasureId)), stream.readTo); len(documents) != 0 {
		t.Fatalf("documents %d", len(documents))
	}
}

// FS-80's team-record case: a team record's card is built only from its own entries and holds no title, prompt, branch,
// tool or path, even where a context entry carries the vault's fields; the vault's card of the same entries holds them.
func TestCardTeamRecordHoldsNoVaultTitle(t *testing.T) {
	runId := evsTestId("run")
	entries := []*indexRecordEntry{
		testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{
			Harness: "claude-code", Title: "Vault only title", Branch: "feature/vault-only", Project: "atlas",
		}),
		testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Bash", Paths: []string{"vault/only/path.md"}}),
		testRecordEntry(t, "change", RecordKindChange, runId, 3, &protocol.ChangeBody{Commits: []string{"0badc0de"}}),
	}
	team := testNewRecordStream(protocol.RepoKind_REPO_KIND_TEAM_RECORD, "team")
	vault := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "vault")
	for _, entry := range entries {
		team.add(t, entry)
		vault.add(t, entry)
	}
	teamCard, _, err := testRunCard(t, team, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := testRecordField(teamCard, indexFieldBody)
	if testRecordField(teamCard, indexFieldTitle) != "" || testRecordField(teamCard, indexFieldFirstRegistered+6) != "" ||
		strings.Contains(text, "Vault only") || strings.Contains(text, "vault-only") || strings.Contains(text, "vault/only") {
		t.Fatalf("a team record's card holds the vault's: title %q tools %q text %q", teamCard.Fields[indexFieldTitle], teamCard.Fields[indexFieldFirstRegistered+6], text)
	}
	if !strings.Contains(text, "0badc0de") {
		t.Fatalf("a team record's card lost its own commit: %q", text)
	}
	vaultCard, _, err := testRunCard(t, vault, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testRecordField(vaultCard, indexFieldTitle) != "Vault only title" || !strings.Contains(testRecordField(vaultCard, indexFieldBody), "vault/only/path.md") {
		t.Fatal("the vault's card lost its title or paths")
	}
}

// RECORD.md 7.4's vault mapping: fields 6-12 and the text's lines, tools by count then name, commits once each in fold
// order, touched paths from tool calls and changes in byte order, the newest four session ids, and no expiry.
func TestCardVaultMapping(t *testing.T) {
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "vault mapping")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{
		Harness: "claude-code", HarnessVersion: "2.1.0", Model: "opus", Project: "atlas", Branch: "main", Title: "Tidy the docs",
		AgentLabel: "docs-bot", SessionIds: []string{"s1", "s2", "s3", "s4", "s5"},
	}))
	stream.add(t, testRecordEntry(t, "edit 1", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Edit", Paths: []string{"docs/z.md"}}))
	stream.add(t, testRecordEntry(t, "bash", RecordKindToolCall, runId, 3, &protocol.ToolCallBody{ToolName: "Bash"}))
	stream.add(t, testRecordEntry(t, "edit 2", RecordKindToolCall, runId, 4, &protocol.ToolCallBody{ToolName: "Edit", Paths: []string{"docs/a.md"}}))
	stream.add(t, testRecordEntry(t, "change", RecordKindChange, runId, 5, &protocol.ChangeBody{
		Commits: []string{"c1", "c2", "c1"}, Paths: []*protocol.ChangedPath{{Path: "docs/m.md"}, {Path: "docs/a.md"}},
	}))
	stream.add(t, testRecordEntry(t, "coverage", RecordKindCoverage, runId, 6, &protocol.Coverage{Gaps: []string{"downtime"}}))
	card, c, err := testRunCard(t, stream, runId, 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c != 5 {
		t.Fatalf("c %d: a coverage entry is no vault source", c)
	}
	wantFields := map[int]string{
		indexFieldTitle:               "Tidy the docs",
		indexFieldFirstRegistered:     "run",
		indexFieldFirstRegistered + 1: indexRecordHex(testRecordWriterId.Bytes()),
		indexFieldFirstRegistered + 2: indexRecordHex(evsTestId("agent").Bytes()),
		indexFieldFirstRegistered + 3: "docs-bot",
		indexFieldFirstRegistered + 4: indexRecordHex(runId.Bytes()),
		indexFieldFirstRegistered + 5: "s2 s3 s4 s5",
		indexFieldFirstRegistered + 6: "Edit:2 Bash:1",
	}
	for field, want := range wantFields {
		if got := testRecordField(card, field); got != want {
			t.Errorf("field %d %q, want %q", field, got, want)
		}
	}
	wantText := "claude-code 2.1.0\nopus\natlas main\nEdit:2\nBash:1\nc1\nc2\ndocs/a.md\ndocs/m.md\ndocs/z.md"
	if got := testRecordField(card, indexFieldBody); got != wantText {
		t.Fatalf("text %q, want %q", got, wantText)
	}
	if card.ExpiresSeconds != 0 || card.Kind != IndexDocDerived || card.ByteCount != uint64(len(wantText)) {
		t.Fatalf("the card %+v", card)
	}
}

// RECORD.md 7.4's team mapping: harness, model, project, commits, approved action kinds by count, published hosts,
// route targets and gap codes; the row's expires the newest coverage's time while the run is ended, and 0 once a later
// event re-opens it.
func TestCardTeamMapping(t *testing.T) {
	runId := evsTestId("run")
	action := func(kind protocol.SidecarActionKind) proto.Message {
		encoded, err := proto.Marshal(&protocol.CanonicalAction{Kind: uint32(kind)})
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.ApprovalRequest{CanonicalAction: encoded}
	}
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_TEAM_RECORD, "team mapping")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "codex", HarnessVersion: "1.4", Model: "gpt-x", Project: "atlas"}))
	stream.add(t, testRecordEntry(t, "change", RecordKindChange, runId, 2, &protocol.ChangeBody{Commits: []string{"aa11"}}))
	stream.add(t, testRecordEntry(t, "approval 1", RecordKindApproval, runId, 3, action(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_PUBLISH)))
	stream.add(t, testRecordEntry(t, "approval 2", RecordKindApproval, runId, 4, action(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD)))
	stream.add(t, testRecordEntry(t, "approval 3", RecordKindApproval, runId, 5, action(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_PUBLISH)))
	stream.add(t, testRecordEntry(t, "publish", RecordKindPublish, runId, 6, &protocol.PublishBody{Event: 1, Host: "app.example.com"}))
	stream.add(t, testRecordEntry(t, "route", RecordKindRoute, runId, 7, &protocol.RouteBody{Event: 1, TargetSidecarId: []byte{0x0f}, TargetPort: 22, Cidrs: []string{"198.51.100.0/24"}}))
	coverage := stream.add(t, testRecordEntry(t, "coverage", RecordKindCoverage, runId, 8, &protocol.Coverage{Gaps: []string{"downtime:3", "truncation"}}))
	card, _, err := testRunCard(t, stream, runId, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantText := "codex 1.4\ngpt-x\natlas\naa11\npublish:2\nforward:1\napp.example.com\n0f:22\n198.51.100.0/24\ndowntime\ntruncation"
	if got := testRecordField(card, indexFieldBody); got != wantText {
		t.Fatalf("text %q, want %q", got, wantText)
	}
	if card.ExpiresSeconds != uint64(coverage.header.GetTimeMillis()/1000) {
		t.Fatalf("an ended run's expires %d", card.ExpiresSeconds)
	}
	stream.add(t, testRecordEntry(t, "reopened", RecordKindContext, runId, 9, &protocol.ContextBody{Harness: "codex"}))
	card, _, err = testRunCard(t, stream, runId, 1, nil, nil)
	if err != nil || card.ExpiresSeconds != 0 {
		t.Fatalf("a re-opened run's expires %d, %v", card.ExpiresSeconds, err)
	}
}
