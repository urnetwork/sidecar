//go:build !sidecar_http

// RECORD-M6-01's team mode on sidecartest's streams and authorization state: RECORD.md section 20's projection case,
// a sponsorless tagged sidecar's kinds in T alone, deposits to T on a fake clock with each flush, a run's V and T
// entries on distinct chains, two ingesters on T, a copy surviving T's erasure, and team mode switching at the
// position of the team record's RepoCreate.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A team network's world: the member's vault and the team record, both in the world's streams.
type testTeamWorld struct {
	*testRecordWorld
	teamRecordId sidecar.Id
}

// The world with a team record the config names, the reader reading it.
func newTestTeamWorld(t *testing.T) *testTeamWorld {
	t.Helper()
	world := newTestRecordWorld(t)
	teamRecordId, err := world.streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.streams.Grant(teamRecordId, world.readerId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	world.fixture.Repos[teamRecordId] = &sidecartest.FakeRecordRepoAuth{Readers: []sidecar.Id{world.readerId}}
	world.fixture.Logs = &sidecar.RecordLogIds{Team: true, TeamRecordId: &teamRecordId}
	world.publish()
	return &testTeamWorld{testRecordWorld: world, teamRecordId: teamRecordId}
}

// A member device, as world.device, that deposits to the team record too.
func (self *testTeamWorld) memberDevice(consented bool) *testRecordDevice {
	self.t.Helper()
	device := self.device(consented)
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Depositors = append(repo.Depositors, device.sidecarId)
	if err := self.streams.Grant(self.teamRecordId, device.sidecarId, sidecartest.RecordStreamsScope{Deposit: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return device
}

// A log admin's device of another member: it reads and writes the team record's stream, and erases there.
func (self *testTeamWorld) adminDevice() *testRecordDevice {
	self.t.Helper()
	device := self.device(false)
	adminMemberId := sidecar.NewId()
	self.fixture.Members[device.sidecarId] = adminMemberId
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	repo.Writers = append(repo.Writers, device.sidecarId)
	if err := self.streams.Grant(self.teamRecordId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return device
}

// A tagged sidecar whose sponsor is gone: no member, no sponsor, a depositor of the team record.
func (self *testTeamWorld) sponsorlessDevice() *testRecordDevice {
	self.t.Helper()
	device := self.device(false)
	delete(self.fixture.Members, device.sidecarId)
	vault := self.fixture.Repos[self.vaultId]
	vault.Depositors = removeTestId(vault.Depositors, device.sidecarId)
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Depositors = append(repo.Depositors, device.sidecarId)
	if err := self.streams.Grant(self.teamRecordId, device.sidecarId, sidecartest.RecordStreamsScope{Deposit: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return device
}

// A list without one id.
func removeTestId(ids []sidecar.Id, id sidecar.Id) []sidecar.Id {
	kept := []sidecar.Id{}
	for _, held := range ids {
		if held != id {
			kept = append(kept, held)
		}
	}
	return kept
}

// One entry a deposit to the team record carries, opened with the deposit's key.
type testTeamDeposited struct {
	header *sidecar.StoredRecordHeader
	body   []byte
}

// Every entry deposited to the team record by depositorId and not consumed, in order, each body opened.
func (self *testTeamWorld) teamDeposits(depositorId sidecar.Id, adminId sidecar.Id) []*testTeamDeposited {
	self.t.Helper()
	deposits, err := self.streams.For(adminId).ReadDeposits(self.t.Context(), self.teamRecordId, depositorId)
	if err != nil {
		self.t.Fatal(err)
	}
	opened := []*testTeamDeposited{}
	for _, deposit := range deposits {
		entries, err := sidecar.RecordDepositBatchParse(deposit.Batch, sidecar.DefaultSidecarSettings().Record.DepositByteCount)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, entry := range entries {
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(entry.Signed, signed); err != nil {
				self.t.Fatal(err)
			}
			header, err := sidecar.ParseStoredRecordHeader(signed.GetBody())
			if err != nil {
				self.t.Fatal(err)
			}
			body, err := sidecar.RecordOpen(header, entry.SealedBody, entry.Key, entry.Salt)
			if err != nil {
				self.t.Fatal(err)
			}
			opened = append(opened, &testTeamDeposited{header: header, body: body})
		}
	}
	return opened
}

// A run of known title, path, branch, project and tool name, in an evs repo.
func testTeamRunDrafts(runId *sidecar.Id) []*sidecar.RecordDraft {
	repoId := sidecar.NewId()
	sha := bytes.Repeat([]byte{0x5a}, 32)
	return []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook, RunId: runId, Body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", HarnessVersion: "2.0.1", AgentLabel: "builder", RepoId: repoId.Bytes(),
			Project: "acme-frobnicator", Branch: "feature/secret-branch", Title: "Fix the frobnicator in widget.go",
			InstructionFiles: []*protocol.InstructionFile{{Scope: 3, Name: "AGENTS.md", Sha256: sha, Size: 10}},
			Truncations:      []string{"notes.md: cut at 1 MiB"},
		}},
		{Kind: sidecar.RecordKindPermission, Source: sidecar.RecordSourceHook, RunId: runId, Body: &protocol.PermissionBody{
			Decision: 2, DecidedBy: 1, ToolClass: 1, ToolName: "Bash", ArgumentsSha256: sha,
		}},
		{Kind: sidecar.RecordKindChange, Source: sidecar.RecordSourceObserved, RunId: runId, Body: &protocol.ChangeBody{
			RepoId: repoId.Bytes(), Project: "acme-frobnicator", PathCount: 1, EditCount: 1, Capture: 1,
			Paths: []*protocol.ChangedPath{{Path: "internal/widget.go", BeforeSha256: sha, AfterSha256: sha, Attribution: 1}},
		}},
	}
}

// RECORD.md section 20's projection case: from a run with a known title, path, branch, project and tool name, T's
// entries hold none of them, each names its vault entry by one ContentRef, and the vault holds them whole, each
// deposit to T copied there.
func TestRecordTeamProjectionHoldsNoRunText(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	vaultEntries := map[sidecar.Id][]byte{}
	for _, draft := range testTeamRunDrafts(&runId) {
		refs, err := record.Writer().Append(draft)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 3 || refs[0].LogId != world.vaultId || refs[1].LogId != world.teamRecordId || refs[2].LogId != world.vaultId {
			t.Fatalf("a %s draft's refs %+v", draft.Kind, refs)
		}
		vaultEntries[refs[0].EntryId] = refs[0].Commitment[:]
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposited := world.teamDeposits(device.sidecarId, admin.sidecarId)
	if len(deposited) != 3 {
		t.Fatalf("%d entries in T", len(deposited))
	}
	for _, entry := range deposited {
		for _, text := range []string{"widget.go", "frobnicator", "secret-branch", "Bash", "AGENTS.md", "notes.md"} {
			if bytes.Contains(entry.body, []byte(text)) {
				t.Errorf("T's %s entry holds %q", entry.header.Kind(), text)
			}
		}
		content := entry.header.Header.GetContent()
		if len(content) != 1 || sidecar.Id(content[0].GetRepoId()) != world.vaultId {
			t.Fatalf("T's %s entry's content refs %v", entry.header.Kind(), content)
		}
		commitment, ok := vaultEntries[sidecar.Id(content[0].GetObjectId())]
		if !ok || !bytes.Equal(commitment, content[0].GetCommitment()) {
			t.Errorf("T's %s entry names no vault entry", entry.header.Kind())
		}
	}
	// the vault holds the run whole, and a copy of each T entry, which opens it
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 6 {
		t.Fatalf("%d entries in the vault", len(stored))
	}
	copies := 0
	for _, entry := range stored {
		if sidecar.RecordKind(entry.header.GetKind()) != sidecar.RecordKindCopy {
			continue
		}
		copies += 1
		body := &protocol.CopyBody{}
		if err := proto.Unmarshal(entry.body, body); err != nil || len(body.GetEntries()) != 1 {
			t.Fatalf("a copy: %v", err)
		}
		opened, err := sidecar.VerifyRecordOpening(body.GetEntries()[0])
		if err != nil || sidecar.Id(opened.Header.Header.GetLogId()) != world.teamRecordId {
			t.Errorf("a copy's opening: %v", err)
		}
	}
	if copies != 3 {
		t.Errorf("%d copies", copies)
	}
	if !bytes.Contains(stored[0].body, []byte("Fix the frobnicator")) {
		t.Error("the vault's context entry lost its title")
	}
}

// A tagged sidecar whose sponsor is gone has no vault: its run kinds and its approval requests go to T alone, a
// projection with no ContentRef and no copy anywhere.
func TestRecordTeamSponsorlessTaggedSidecarWritesTAlone(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.sponsorlessDevice()
	admin := world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	draft := testTeamRunDrafts(&runId)[0]
	refs, err := record.Writer().Append(draft)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].LogId != world.teamRecordId {
		t.Fatalf("refs %+v", refs)
	}
	action := testRecordDnsSet(t, "198.51.100.7")
	request := testRecordParsedRequest(t, world.approvalRequest(device, action.Bytes, "set it", nil))
	ref, err := record.Approvals().FileRequest(request)
	if err != nil || ref.LogId != world.teamRecordId {
		t.Fatalf("the request went to %+v: %v", ref, err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposited := world.teamDeposits(device.sidecarId, admin.sidecarId)
	if len(deposited) != 2 {
		t.Fatalf("%d entries in T", len(deposited))
	}
	if content := deposited[0].header.Header.GetContent(); len(content) != 0 {
		t.Errorf("a projection with no vault names %v", content)
	}
	if !bytes.Equal(deposited[1].body, request.Bytes) {
		t.Error("T's approval is not the request's stored bytes")
	}
	if stored := world.storedEntries(device.sidecarId); len(stored) != 0 {
		t.Errorf("the vault holds %d entries of a sponsorless sidecar", len(stored))
	}
}

// Deposits to T wait DepositInterval on the fake clock while the vault's stream goes at PushCoalesce; the approval
// family and a run's coverage go at once, and Flush, sleep's and exit's, sends what waits.
func TestRecordTeamDepositsCoalesceAndFlush(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	subscribe := func(logId sidecar.Id) chan struct{} {
		commits := make(chan struct{}, 64)
		unsubscribe := world.streams.For(world.readerId).Subscribe(logId, func(repoId sidecar.Id) {
			select {
			case commits <- struct{}{}:
			default:
			}
		})
		t.Cleanup(unsubscribe)
		return commits
	}
	vaultCommits, teamCommits := subscribe(world.vaultId), subscribe(world.teamRecordId)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		record.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	settings := device.settings
	deposits := func() int {
		return len(world.teamDeposits(device.sidecarId, admin.sidecarId))
	}

	testRecordAppendAll(t, record, testTeamRunDrafts(&runId)[0])
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(settings.PushCoalesce)
	testRecordAwaitCommit(t, vaultCommits)
	if count := deposits(); count != 0 {
		t.Fatalf("T took %d entries before DepositInterval", count)
	}
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(settings.DepositInterval - settings.PushCoalesce)
	testRecordAwaitCommit(t, teamCommits)
	if count := deposits(); count != 1 {
		t.Fatalf("T holds %d entries after DepositInterval", count)
	}

	// the approval family goes at once
	testRecordAppendAll(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindApprovalUse, Source: sidecar.RecordSourceObserved, RunId: &runId,
		Body: &protocol.ApprovalUseBody{
			ApprovalId: sidecar.NewId().Bytes(), UseIndex: 1, State: 1,
			PayloadSha256: bytes.Repeat([]byte{0x61}, 32), EffectKey: bytes.Repeat([]byte{0x62}, 32),
		},
	})
	testRecordAwaitCommit(t, teamCommits)
	if count := deposits(); count != 2 {
		t.Fatalf("T holds %d entries after an approval_use", count)
	}
	// and so does a run's end
	testRecordAppendAll(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindCoverage, Source: sidecar.RecordSourceObserved, RunId: &runId,
		Body: &protocol.Coverage{RunId: runId.Bytes(), Harness: "claude-code", Sources: []string{"hooks"}},
	})
	testRecordAwaitCommit(t, teamCommits)
	if count := deposits(); count != 3 {
		t.Fatalf("T holds %d entries after the run's coverage", count)
	}
	// sleep and exit flush what waits
	testRecordAppendAll(t, record, testTeamRunDrafts(&runId)[1])
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count := deposits(); count != 4 {
		t.Fatalf("T holds %d entries after a flush", count)
	}
}

// Appends a draft that must take, whatever its refs.
func testRecordAppendAll(t *testing.T, record *sidecar.SidecarRecord, draft *sidecar.RecordDraft) []*sidecar.RecordEntryRef {
	t.Helper()
	refs, err := record.Writer().Append(draft)
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// A run's V and T entries hold distinct chains: each log's seqs from 1, each entry's prev its own log's.
func TestRecordTeamRunEntriesHoldDistinctChains(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	drafts := testTeamRunDrafts(&runId)
	first := testRecordAppendAll(t, record, drafts[0])
	second := testRecordAppendAll(t, record, drafts[1])
	if first[0].Seq != 1 || first[1].Seq != 1 || first[2].Seq != 2 {
		t.Errorf("the first draft's seqs %d, %d, %d", first[0].Seq, first[1].Seq, first[2].Seq)
	}
	if second[0].Seq != 3 || second[1].Seq != 2 || second[2].Seq != 4 {
		t.Errorf("the second draft's seqs %d, %d, %d", second[0].Seq, second[1].Seq, second[2].Seq)
	}
	if first[1].Leaf == first[0].Leaf || second[1].EntryId == second[0].EntryId {
		t.Error("V's and T's entries share a leaf or an id")
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 4 || !bytes.Equal(stored[1].header.GetPrevSha256(), first[0].Leaf[:]) {
		t.Errorf("the vault's chain: %d entries", len(stored))
	}
}

// Two log admins' devices ingest one depositor's T entries: each writes a copy in its own stream under its own slot
// row, the deposits are consumed once, and a reader of T shows each entry once with both copies.
func TestRecordTeamTwoIngesters(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	first, second := world.adminDevice(), world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	for _, draft := range testTeamRunDrafts(&runId) {
		testRecordAppendAll(t, record, draft)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstRecord, secondRecord := first.open(), second.open()
	for _, ingester := range []*sidecar.SidecarRecord{firstRecord, secondRecord} {
		if err := ingester.Ingester().Ingest(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
	}
	for _, ingester := range []*sidecar.SidecarRecord{firstRecord, secondRecord} {
		if err := ingester.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, ingester := range []*sidecar.SidecarRecord{firstRecord, secondRecord} {
		if err := ingester.Ingester().Ingest(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
	}
	if left := world.teamDeposits(device.sidecarId, first.sidecarId); len(left) != 0 {
		t.Errorf("%d entries left unconsumed", len(left))
	}
	reader := world.newReader(nil, nil)
	if err := reader.reader.Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	entries := reader.reader.Entries(world.teamRecordId)
	if len(entries) != 3 {
		t.Fatalf("a reader of T shows %d entries", len(entries))
	}
	for _, entry := range entries {
		if len(entry.Copies) != 2 || entry.State != sidecar.RecordEntryLive || entry.Body == nil {
			t.Errorf("an entry with %d copies, %s", len(entry.Copies), entry.State)
		}
		if sidecar.Id(entry.Header.Header.GetWriterSidecarId()) != device.sidecarId {
			t.Error("an ingester changed the writer")
		}
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// An ERASE of a T entry's key leaves the author's copy, which still opens the entry: a team-record erasure never
// reaches a copy (RECORD.md section 8).
func TestRecordTeamCopySurvivesATErasure(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	refs := testRecordAppendAll(t, record, testTeamRunDrafts(&runId)[0])
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	adminRecord := admin.open()
	ingest := func() {
		if err := adminRecord.Ingester().Ingest(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
		if err := adminRecord.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	ingest()
	ingest()
	versions, err := world.streams.For(admin.sidecarId).ReadStream(t.Context(), world.teamRecordId, admin.sidecarId, 0)
	if err != nil || len(versions) != 1 {
		t.Fatalf("the ingester's stream: %v", err)
	}
	if _, err := world.streams.For(admin.sidecarId).Erase(t.Context(), world.teamRecordId, &sidecar.RecordStreamErase{
		PushId: sidecar.NewId(), Keys: []*sidecar.RecordSlotKey{{SlotId: versions[0].SlotId, KeyIndex: 0}},
	}); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	if err := reader.reader.Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	entries := reader.reader.Entries(world.teamRecordId)
	if len(entries) != 1 || entries[0].State != sidecar.RecordEntryErased || entries[0].EntryId != refs[1].EntryId {
		t.Fatalf("T after the ERASE: %d entries", len(entries))
	}
	for _, entry := range world.storedEntries(device.sidecarId) {
		if sidecar.RecordKind(entry.header.GetKind()) != sidecar.RecordKindCopy {
			continue
		}
		body := &protocol.CopyBody{}
		if err := proto.Unmarshal(entry.body, body); err != nil {
			t.Fatal(err)
		}
		opened, err := sidecar.VerifyRecordOpening(body.GetEntries()[0])
		if err != nil || sidecar.Id(opened.Header.Header.GetEntryId()) != refs[1].EntryId || len(opened.Body) == 0 {
			t.Fatalf("the copy after T's erasure: %v", err)
		}
		return
	}
	t.Fatal("no copy in the vault")
}

// Team mode follows the config at each position: before the team record's RepoCreate a context entry goes to the vault
// alone; from it, to the vault and T with a copy; and a claim is refused once the directory exists.
func TestRecordTeamModeSwitchesAtTheRepoCreate(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	world.fixture.Logs = &sidecar.RecordLogIds{Team: true}
	world.publish()
	if refs := testRecordAppendAll(t, record, testTeamRunDrafts(&runId)[0]); len(refs) != 1 || refs[0].LogId != world.vaultId {
		t.Fatalf("before the RepoCreate: %+v", refs)
	}
	teamRecordId, err := world.streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	world.fixture.Repos[teamRecordId] = &sidecartest.FakeRecordRepoAuth{Depositors: []sidecar.Id{device.sidecarId}}
	world.fixture.Logs = &sidecar.RecordLogIds{Team: true, TeamRecordId: &teamRecordId}
	world.publish()
	refs := testRecordAppendAll(t, record, testTeamRunDrafts(&runId)[0])
	if len(refs) != 3 || refs[1].LogId != teamRecordId {
		t.Fatalf("from the RepoCreate: %+v", refs)
	}
	directoryId := sidecar.NewId()
	world.fixture.Logs = &sidecar.RecordLogIds{Team: true, TeamRecordId: &teamRecordId, DirectoryId: &directoryId}
	world.publish()
	claim := &sidecar.RecordDraft{Kind: sidecar.RecordKindClaim, Source: sidecar.RecordSourceAgent, RunId: &runId,
		Body: &protocol.CoordinationBody{Text: "taking the widget", ClaimState: 1}}
	if _, err := record.Writer().Append(claim); !errors.Is(err, sidecar.ErrRecordRouteAnnouncement) {
		t.Errorf("a claim with a directory: %v", err)
	}
	note := testRecordNote(&runId, "a note to the team")
	world.fixture.Repos[directoryId] = &sidecartest.FakeRecordRepoAuth{Writers: []sidecar.Id{device.sidecarId}}
	world.publish()
	if refs := testRecordAppendAll(t, record, note); len(refs) != 1 || refs[0].LogId != directoryId {
		t.Errorf("a note with a directory: %+v", refs)
	}
}

// In team mode a request whose approver is not the requester's author, an admin's, goes to T alone, copied to the
// requester's vault; the admin's device finds it pending in T and decides there, and the member device, which reads
// no T, finds that decision undeliverable, so nothing spends (plan-RECORD-deposit-only-decisions).
func TestRecordTeamAdminApprovalGoesToTAlone(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	action := testRecordDnsSet(t, "198.51.100.7")
	adminMemberId := world.fixture.Members[admin.sidecarId]
	request := testRecordParsedRequest(t, world.approvalRequest(device, action.Bytes, "set it", [][]byte{adminMemberId.Bytes()}))
	ref, err := record.Approvals().FileRequest(request)
	if err != nil || ref.LogId != world.teamRecordId {
		t.Fatalf("the admin's request went to %+v: %v", ref, err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposited := world.teamDeposits(device.sidecarId, admin.sidecarId)
	if len(deposited) != 1 || !bytes.Equal(deposited[0].body, request.Bytes) {
		t.Fatalf("T holds %d entries", len(deposited))
	}
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 1 || sidecar.RecordKind(stored[0].header.GetKind()) != sidecar.RecordKindCopy {
		t.Fatalf("the vault holds %d entries", len(stored))
	}
	adminRecord := admin.open()
	for range 2 {
		if err := adminRecord.Ingester().Ingest(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
		if err := adminRecord.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := adminRecord.Approvals().Pending(t.Context())
	if err != nil || len(pending) != 1 || pending[0].LogId != world.teamRecordId || pending[0].Request == nil {
		t.Fatalf("the admin's pending: %d, %v", len(pending), err)
	}
	decided, err := adminRecord.Approvals().FileDecision(t.Context(), world.teamRecordId, admin.decide(pending[0].Request), nil)
	if err != nil || decided.LogId != world.teamRecordId {
		t.Fatalf("the admin's decision: %+v, %v", decided, err)
	}
	if err := adminRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pending, err := adminRecord.Approvals().Pending(t.Context()); err != nil || len(pending) != 0 {
		t.Errorf("still pending: %d, %v", len(pending), err)
	}
	if _, err := record.Approvals().Decision(t.Context(), request.ApprovalId()); !errors.Is(err, sidecar.ErrRecordApprovalUndeliverable) {
		t.Errorf("the member requester's decision: %v", err)
	}

	// with no team record, the same request is refused and stays pending
	personal := newTestRecordWorld(t)
	personalDevice := personal.device(true)
	refused := testRecordParsedRequest(t, personal.approvalRequest(personalDevice, action.Bytes, "set it", [][]byte{sidecar.NewId().Bytes()}))
	if _, err := personalDevice.open().Approvals().FileRequest(refused); !errors.Is(err, sidecar.ErrRecordApprovalTeamRoute) {
		t.Errorf("an admin's request with no team record: %v", err)
	}
}
