//go:build !sidecar_http

// RECORD-M6-09: a ledger's scope governs which runs a writing sidecar copies there; a scoped run's team-bound entries
// land in the ledger as entries of their own, T's projection and never a vault body, and an out-of-scope run's, a
// note's and a run's that began before the scope do not; a scope pushed by a writer that was no admin at its push's
// pin is ignored; and erasing the ledger's copy leaves the team record's entry.

package sidecar_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A team network with one `record` ledger the config names, the world's reader reading it.
type testLedgerWorld struct {
	*testTeamWorld
	ledgerId sidecar.Id
}

func newTestLedgerWorld(t *testing.T) *testLedgerWorld {
	t.Helper()
	world := newTestTeamWorld(t)
	ledgerId, err := world.streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.streams.Grant(ledgerId, world.readerId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	world.fixture.Repos[ledgerId] = &sidecartest.FakeRecordRepoAuth{Readers: []sidecar.Id{world.readerId}}
	world.fixture.Logs.LedgerIds = []sidecar.Id{ledgerId}
	world.publish()
	return &testLedgerWorld{testTeamWorld: world, ledgerId: ledgerId}
}

// Gives device read and write on the ledger, and its administration when admin.
func (self *testLedgerWorld) ledgerWriter(device *testRecordDevice, admin bool) {
	self.t.Helper()
	repo := self.fixture.Repos[self.ledgerId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	repo.Writers = append(repo.Writers, device.sidecarId)
	if admin {
		repo.Admins = append(repo.Admins, device.sidecarId)
	}
	if err := self.streams.Grant(self.ledgerId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
}

// The ledger's entries from writerId as a fresh reader finds them, in the order read.
func (self *testLedgerWorld) ledgerEntries(writerId sidecar.Id) []*sidecar.RecordReadEntry {
	self.t.Helper()
	reader := self.newReader(nil, nil)
	if err := reader.reader.Sync(self.t.Context(), self.ledgerId); err != nil {
		self.t.Fatal(err)
	}
	entries := []*sidecar.RecordReadEntry{}
	for _, entry := range reader.reader.Entries(self.ledgerId) {
		if bytes.Equal(entry.Header.Header.GetWriterSidecarId(), writerId.Bytes()) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// A run's context and one change, in project.
func testLedgerRunDrafts(runId *sidecar.Id, project string) []*sidecar.RecordDraft {
	return []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook, RunId: runId, Body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", AgentLabel: "builder", Project: project, Branch: "feature/secret-branch", Title: "Fix the frobnicator in widget.go"}},
		{Kind: sidecar.RecordKindChange, Source: sidecar.RecordSourceObserved, RunId: runId, Body: &protocol.ChangeBody{
			Project: project, PathCount: 1, EditCount: 1, Capture: 1,
			Paths: []*protocol.ChangedPath{{Path: "widget.go", AfterSha256: bytes.Repeat([]byte{0x5a}, 32), Attribution: 1}}}},
	}
}

// The ref among refs in logId, which must be there once.
func testLedgerRef(t *testing.T, refs []*sidecar.RecordEntryRef, logId sidecar.Id) *sidecar.RecordEntryRef {
	t.Helper()
	var found *sidecar.RecordEntryRef
	for _, ref := range refs {
		if ref.LogId == logId {
			if found != nil {
				t.Fatalf("two entries in log %s", logId)
			}
			found = ref
		}
	}
	if found == nil {
		t.Fatalf("no entry in log %s among %d", logId, len(refs))
	}
	return found
}

// A scoped run's team-bound entries are copied to the ledger as its own entries; an out-of-scope run's are not, nor a
// note, nor the entries of a run that began before this sidecar read the scope. Erasing the ledger's copy leaves the
// team record's entry.
func TestRecordLedgerCopiesAScopedRunAndErasureThereLeavesTheTeamEntry(t *testing.T) {
	ctx := t.Context()
	world := newTestLedgerWorld(t)
	admin := world.adminDevice()
	world.ledgerWriter(admin, true)
	member := world.memberDevice(true)
	world.ledgerWriter(member, false)
	adminRecord := admin.open()
	memberRecord := member.open()
	ledgers := memberRecord.Ledgers()

	// a run that begins before any scope is read is never copied, though its project comes into scope later
	early := sidecar.NewId()
	world.runs.StartRun(early)
	earlyDrafts := testLedgerRunDrafts(&early, "github.com/example/in")
	testRecordAppendAll(t, memberRecord, earlyDrafts[0])

	if _, err := adminRecord.Ledgers().SetScope(&sidecar.RecordLedgerScopeArgs{LogId: world.ledgerId, Projects: []string{"github.com/example/in"}}); err == nil {
		t.Fatal("a scope was set with no confirmation")
	}
	scopeRef, err := adminRecord.Ledgers().SetScope(&sidecar.RecordLedgerScopeArgs{
		LogId: world.ledgerId, Projects: []string{"github.com/example/in"}, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adminRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// a writer that is no admin of the ledger sets no scope
	if _, err := ledgers.SetScope(&sidecar.RecordLedgerScopeArgs{LogId: world.ledgerId, Projects: []string{"github.com/example/out"}, Confirmed: true}); err == nil {
		t.Fatal("a non-admin wrote a ledger scope")
	}
	if err := ledgers.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	scope, ok := ledgers.Scope(world.ledgerId)
	if !ok || scope.EntryId != scopeRef.EntryId || !slices.Equal(scope.Projects, []string{"github.com/example/in"}) {
		t.Fatalf("the governing scope %+v", scope)
	}
	if lines := ledgers.StatusLines(); len(lines) != 1 || !strings.Contains(lines[0], world.ledgerId.String()) {
		t.Fatalf("status lines %q", lines)
	}

	in, out := sidecar.NewId(), sidecar.NewId()
	world.runs.StartRun(in)
	world.runs.StartRun(out)
	var copied []*sidecar.RecordEntryRef
	var teamRefs []*sidecar.RecordEntryRef
	for _, draft := range testLedgerRunDrafts(&in, "github.com/example/in") {
		refs := testRecordAppendAll(t, memberRecord, draft)
		ledgerRef := testLedgerRef(t, refs, world.ledgerId)
		teamRef := testLedgerRef(t, refs, world.teamRecordId)
		if ledgerRef.EntryId == teamRef.EntryId || ledgerRef.Commitment == teamRef.Commitment {
			t.Fatal("the ledger's copy shares the team entry's id or commitment")
		}
		copied = append(copied, ledgerRef)
		teamRefs = append(teamRefs, teamRef)
	}
	for _, draft := range testLedgerRunDrafts(&out, "github.com/example/out") {
		for _, ref := range testRecordAppendAll(t, memberRecord, draft) {
			if ref.LogId == world.ledgerId {
				t.Fatal("an out-of-scope run's entry was copied")
			}
		}
	}
	for _, ref := range testRecordAppendAll(t, memberRecord, earlyDrafts[1]) {
		if ref.LogId == world.ledgerId {
			t.Fatal("a run that began before the scope was copied")
		}
	}
	for _, ref := range testRecordAppendAll(t, memberRecord, testRecordNote(&in, "a note of the scoped run")) {
		if ref.LogId == world.ledgerId {
			t.Fatal("a note was copied to the ledger")
		}
	}
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	entries := world.ledgerEntries(member.sidecarId)
	if len(entries) != 2 || entries[0].EntryId != copied[0].EntryId || entries[1].EntryId != copied[1].EntryId {
		t.Fatalf("%d entries of the member in the ledger", len(entries))
	}
	if entries[0].Kind() != sidecar.RecordKindContext || entries[1].Kind() != sidecar.RecordKindChange ||
		!bytes.Equal(entries[0].Header.Header.GetRunId(), in.Bytes()) || entries[0].Header.Header.GetSeq() != 1 || entries[1].Header.Header.GetSeq() != 2 {
		t.Fatalf("the ledger's copies are %s and %s", entries[0].Kind(), entries[1].Kind())
	}
	// T's projection, never the vault's body: no title, branch or path, and the project of a repo that is not private
	contextBody := &protocol.ContextBody{}
	changeBody := &protocol.ChangeBody{}
	if err := proto.Unmarshal(entries[0].Body, contextBody); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(entries[1].Body, changeBody); err != nil {
		t.Fatal(err)
	}
	if contextBody.GetTitle() != "" || contextBody.GetBranch() != "" || contextBody.GetProject() != "github.com/example/in" ||
		len(changeBody.GetPaths()) != 1 || changeBody.GetPaths()[0].GetPath() != "" || len(changeBody.GetPaths()[0].GetAfterSha256()) != 32 {
		t.Fatalf("the ledger holds a vault body: %v, %v", contextBody, changeBody)
	}
	teamBodies := map[sidecar.Id][]byte{}
	for _, deposited := range world.teamDeposits(member.sidecarId, admin.sidecarId) {
		teamBodies[sidecar.Id(deposited.header.Header.GetEntryId())] = deposited.body
	}
	if !bytes.Equal(teamBodies[teamRefs[0].EntryId], entries[0].Body) || !bytes.Equal(teamBodies[teamRefs[1].EntryId], entries[1].Body) {
		t.Fatal("the ledger's copy is not the team record's projection")
	}

	// the ledger's admin erases the copy there: its key goes, and the team record's entry still opens
	if err := adminRecord.Reader().Sync(ctx, world.ledgerId); err != nil {
		t.Fatal(err)
	}
	result, err := adminRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.ledgerId, EntryIds: []sidecar.Id{copied[0].EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.LogId != world.ledgerId || len(result.Erased) != 1 {
		t.Fatalf("the erasure answered %+v", result)
	}
	if err := adminRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	after := world.ledgerEntries(member.sidecarId)
	if len(after) != 2 || after[0].Body != nil || after[0].State != sidecar.RecordEntryErased || after[1].Body == nil {
		t.Fatalf("after the erasure the ledger's copy is %s", after[0].State)
	}
	stillThere := false
	for _, deposited := range world.teamDeposits(member.sidecarId, admin.sidecarId) {
		if sidecar.Id(deposited.header.Header.GetEntryId()) == teamRefs[0].EntryId && bytes.Equal(deposited.body, entries[0].Body) {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("the ledger's erasure took the team record's entry")
	}
}

// A ledger_scope pushed by a writer that was no admin of the ledger at its push's pin is ignored, though it is the
// newest: the admin's scope keeps governing.
func TestRecordLedgerIgnoresAScopeFromANonAdmin(t *testing.T) {
	ctx := t.Context()
	world := newTestLedgerWorld(t)
	admin := world.adminDevice()
	world.ledgerWriter(admin, true)
	demoted := world.device(false)
	world.ledgerWriter(demoted, true)
	member := world.memberDevice(true)
	world.ledgerWriter(member, false)
	adminRecord := admin.open()
	demotedRecord := demoted.open()

	adminScope, err := adminRecord.Ledgers().SetScope(&sidecar.RecordLedgerScopeArgs{LogId: world.ledgerId, Projects: []string{"github.com/example/in"}, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := adminRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// sealed while still an admin, with evs out of reach; pushed after the config took its administration away
	demoted.tap.setDown(true)
	if _, err := demotedRecord.Ledgers().SetScope(&sidecar.RecordLedgerScopeArgs{LogId: world.ledgerId, Projects: []string{"github.com/example/out"}, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	repo := world.fixture.Repos[world.ledgerId]
	repo.Admins = removeTestId(repo.Admins, demoted.sidecarId)
	world.publish()
	world.clock.Advance(sidecar.DefaultSidecarSettings().Record.PushCoalesce)
	demoted.tap.setDown(false)
	if err := demotedRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if entries := world.ledgerEntries(demoted.sidecarId); len(entries) != 1 || entries[0].Kind() != sidecar.RecordKindLedgerScope {
		t.Fatalf("the demoted writer's scope did not land: %d entries", len(entries))
	}

	memberRecord := member.open()
	ledgers := memberRecord.Ledgers()
	if err := ledgers.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	scope, ok := ledgers.Scope(world.ledgerId)
	if !ok || scope.EntryId != adminScope.EntryId || !slices.Equal(scope.Projects, []string{"github.com/example/in"}) {
		t.Fatalf("the governing scope is %+v, want the admin's", scope)
	}
	out := sidecar.NewId()
	world.runs.StartRun(out)
	for _, draft := range testLedgerRunDrafts(&out, "github.com/example/out") {
		for _, ref := range testRecordAppendAll(t, memberRecord, draft) {
			if ref.LogId == world.ledgerId {
				t.Fatal("a non-admin's scope copied a run")
			}
		}
	}
}
