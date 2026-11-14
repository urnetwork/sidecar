//go:build !sidecar_http

// record_mirror.go on sidecartest's streams and authorization state (RECORD-M3-10; D-MCP-10): `ur status` naming an
// unmirrored vault, the line clearing once a consented indexer is designated and caught up, and a partial mirror
// named past an hour behind; §16.8's table for the team record, the directory and an other ledger; a depositor
// keeping its deposits until the ingester's mark, and pruning at it; a site loss after which the kept deposits go
// again with equal Signed bytes and chains verifying; deposits refused until the log resumes; a spool at its cap
// counted. External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a test's config says of indexers, and what this device's mirrors cover.
type testRecordMirrorView struct {
	stateLock sync.Mutex
	known     bool
	indexers  []sidecar.Id
	ledgers   []sidecar.Id
	coverage  map[sidecar.Id]*sidecar.RecordMirrorCoverage
}

func (self *testRecordMirrorView) Indexers() ([]sidecar.Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.indexers), self.known
}

func (self *testRecordMirrorView) Ledgers() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.ledgers)
}

func (self *testRecordMirrorView) Coverage(ctx context.Context, logId sidecar.Id) (*sidecar.RecordMirrorCoverage, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.coverage[logId], nil
}

func (self *testRecordMirrorView) designate(indexerId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.indexers = append(self.indexers, indexerId)
}

func (self *testRecordMirrorView) cover(logId sidecar.Id, coverage *sidecar.RecordMirrorCoverage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.coverage[logId] = coverage
}

func newTestRecordMirrorView() *testRecordMirrorView {
	return &testRecordMirrorView{known: true, coverage: map[sidecar.Id]*sidecar.RecordMirrorCoverage{}}
}

// One deposit a test spool keeps.
type testRecordKept struct {
	logId   sidecar.Id
	key     uint64
	deposit []byte
}

// A spool's kept half in memory: the oldest dropped first at its cap, each drop counted, as Spool.Keep does.
type testRecordDepositSpool struct {
	stateLock sync.Mutex
	// 0 for no cap
	byteCount int
	kept      []*testRecordKept
	dropCount int
}

func (self *testRecordDepositSpool) heldByteCountWithLock() int {
	held := 0
	for _, kept := range self.kept {
		held += len(kept.deposit)
	}
	return held
}

func (self *testRecordDepositSpool) Keep(logId sidecar.Id, pushVersion uint64, deposit []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.byteCount {
		for 0 < len(self.kept) && self.byteCount < self.heldByteCountWithLock()+len(deposit) {
			self.kept = self.kept[1:]
			self.dropCount += 1
		}
		if self.byteCount < len(deposit) {
			self.dropCount += 1
			return sidecar.ErrSpoolFull
		}
	}
	self.kept = append(self.kept, &testRecordKept{logId: logId, key: pushVersion, deposit: bytes.Clone(deposit)})
	return nil
}

func (self *testRecordDepositSpool) Kept(logId sidecar.Id, visit func(pushVersion uint64, deposit []byte) error) error {
	kept := func() []*testRecordKept {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.kept)
	}()
	for _, one := range kept {
		if one.logId != logId {
			continue
		}
		if err := visit(one.key, bytes.Clone(one.deposit)); err != nil {
			return err
		}
	}
	return nil
}

func (self *testRecordDepositSpool) PruneKept(logId sidecar.Id, consumedThrough uint64) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	before := len(self.kept)
	self.kept = slices.DeleteFunc(self.kept, func(kept *testRecordKept) bool {
		return kept.logId == logId && kept.key <= consumedThrough
	})
	return before - len(self.kept), nil
}

// The batches kept for logId, in the order kept.
func (self *testRecordDepositSpool) batches(logId sidecar.Id) [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	batches := [][]byte{}
	for _, kept := range self.kept {
		if kept.logId == logId {
			batches = append(batches, bytes.Clone(kept.deposit))
		}
	}
	return batches
}

// The Signed bytes of every entry in batches, in order.
func testRecordBatchSigned(t *testing.T, device *testRecordDevice, batches [][]byte) [][]byte {
	t.Helper()
	signed := [][]byte{}
	for _, batch := range batches {
		entries, err := sidecar.RecordDepositBatchParse(batch, device.settings.DepositByteCount)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			signed = append(signed, entry.Signed)
		}
	}
	return signed
}

// A depositor's record with a spool keeping its deposits.
func (self *testRecordDevice) openKeeping(spool *testRecordDepositSpool) *sidecar.SidecarRecord {
	record := self.open()
	record.Mirrors().Bind(nil, spool)
	return record
}

// Appends each text as a note and flushes, one deposit a call.
func testRecordDepositNotes(t *testing.T, record *sidecar.SidecarRecord, texts ...string) {
	t.Helper()
	for _, text := range texts {
		testRecordAppend(t, record, testRecordNote(nil, text))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func testRecordLinesContain(lines []string, parts ...string) bool {
	return slices.ContainsFunc(lines, func(line string) bool {
		for _, part := range parts {
			if !strings.Contains(line, part) {
				return false
			}
		}
		return true
	})
}

// A network has no mirror by default: the vault is named unmirrored, and an indexer the vault's owner did not consent
// clears nothing. Until a verified state names the indexers, the lines say the mirrors are unknown.
func TestRecordMirrorsNameAnUnmirroredVault(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	other := world.device(false)
	record := device.open()
	if lines := record.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, "mirrors unknown") {
		t.Fatalf("with no view bound: %v", lines)
	}
	view := newTestRecordMirrorView()
	record.Mirrors().Bind(view, nil)
	lines := record.Mirrors().StatusLines(t.Context())
	if !testRecordLinesContain(lines, "unmirrored:", world.vaultId.String(), "(vault)") {
		t.Fatalf("an unmirrored vault is not named: %v", lines)
	}
	// designated, and not one of the author's consented devices: §16.8's table does not name it
	view.designate(other.sidecarId)
	lines = record.Mirrors().StatusLines(t.Context())
	if !testRecordLinesContain(lines, "unmirrored:", world.vaultId.String()) {
		t.Fatalf("an unconsented indexer cleared the line: %v", lines)
	}
	if plan := record.Mirrors().Plan(); len(plan) != 0 {
		t.Fatalf("a device no designation names plans mirrors of %v", plan)
	}
}

// A consented indexer designated and caught up clears the line; behind under an hour it stays clear, and past an hour
// the mirror is named partial, as is any other reason, and a designated device holding no mirror.
func TestRecordMirrorsDesignatedAndCaughtUpClearsTheLine(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	view := newTestRecordMirrorView()
	view.designate(device.sidecarId)
	record.Mirrors().Bind(view, nil)
	if plan := record.Mirrors().Plan(); !slices.Equal(plan, []sidecar.Id{world.vaultId}) {
		t.Fatalf("the designated indexer plans %v", plan)
	}
	lines := record.Mirrors().StatusLines(t.Context())
	if !testRecordLinesContain(lines, world.vaultId.String(), "mirror none") {
		t.Fatalf("a designated device with no mirror: %v", lines)
	}
	view.cover(world.vaultId, &sidecar.RecordMirrorCoverage{})
	if lines := record.Mirrors().StatusLines(t.Context()); len(lines) != 0 {
		t.Fatalf("a caught-up mirror left %v", lines)
	}
	view.cover(world.vaultId, &sidecar.RecordMirrorCoverage{BehindSince: world.clock.Now().Add(-59 * time.Minute)})
	if lines := record.Mirrors().StatusLines(t.Context()); len(lines) != 0 {
		t.Fatalf("a mirror 59 min behind left %v", lines)
	}
	view.cover(world.vaultId, &sidecar.RecordMirrorCoverage{BehindSince: world.clock.Now().Add(-61 * time.Minute)})
	lines = record.Mirrors().StatusLines(t.Context())
	if !testRecordLinesContain(lines, world.vaultId.String(), "mirror partial", "behind its head since") {
		t.Fatalf("a mirror 61 min behind: %v", lines)
	}
	view.cover(world.vaultId, &sidecar.RecordMirrorCoverage{Reasons: []string{"3 objects missing (3 slots)"}})
	lines = record.Mirrors().StatusLines(t.Context())
	if !testRecordLinesContain(lines, "mirror partial", "3 objects missing") {
		t.Fatalf("a mirror missing slots: %v", lines)
	}
}

// §16.8's table for a team's logs: the team record takes an admin's or auditor's indexer, its readers; the directory
// and an other ledger take an admin's alone.
func TestRecordMirrorsFollowTheTableForTeamLogs(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	directoryId := sidecar.NewId()
	ledgerId := sidecar.NewId()
	auditorIndexerId := sidecar.NewId()
	world.fixture.Logs.DirectoryId = &directoryId
	world.fixture.Repos[directoryId] = &sidecartest.FakeRecordRepoAuth{Readers: []sidecar.Id{device.sidecarId, auditorIndexerId}}
	world.fixture.Repos[ledgerId] = &sidecartest.FakeRecordRepoAuth{Readers: []sidecar.Id{auditorIndexerId}}
	teamRecord := world.fixture.Repos[world.teamRecordId]
	teamRecord.Readers = append(teamRecord.Readers, auditorIndexerId)
	world.publish()
	record := device.open()
	view := newTestRecordMirrorView()
	view.ledgers = []sidecar.Id{ledgerId}
	// an auditor's indexer: a reader of the team record and of the others, an admin of none
	view.designate(auditorIndexerId)
	record.Mirrors().Bind(view, nil)
	mirrored := func() map[sidecar.RecordMirrorLogKind]bool {
		logs, ok := record.Mirrors().Logs()
		if !ok {
			t.Fatal("no logs")
		}
		kinds := map[sidecar.RecordMirrorLogKind]bool{}
		for _, log := range logs {
			kinds[log.Kind] = 0 < len(log.MirrorSidecarIds)
		}
		return kinds
	}
	got := mirrored()
	if !got[sidecar.RecordMirrorLogTeamRecord] || got[sidecar.RecordMirrorLogDirectory] || got[sidecar.RecordMirrorLogLedger] || got[sidecar.RecordMirrorLogVault] {
		t.Fatalf("an auditor's indexer mirrors %v", got)
	}
	lines := record.Mirrors().StatusLines(t.Context())
	for _, logId := range []sidecar.Id{directoryId, ledgerId, world.vaultId} {
		if !testRecordLinesContain(lines, "unmirrored:", logId.String()) {
			t.Errorf("log %s is not named unmirrored: %v", logId, lines)
		}
	}
	if testRecordLinesContain(lines, "unmirrored:", world.teamRecordId.String()) {
		t.Errorf("the team record is named unmirrored: %v", lines)
	}
	// an admin's indexer: the directory's and the ledger's admin
	world.fixture.Repos[directoryId].Admins = []sidecar.Id{admin.sidecarId}
	world.fixture.Repos[ledgerId].Admins = []sidecar.Id{admin.sidecarId}
	world.publish()
	view.designate(admin.sidecarId)
	got = mirrored()
	if !got[sidecar.RecordMirrorLogDirectory] || !got[sidecar.RecordMirrorLogLedger] || got[sidecar.RecordMirrorLogVault] {
		t.Fatalf("with an admin's indexer: %v", got)
	}
}

// A depositor keeps each deposit until the ingester's consumed_through passes it, which it learns at its next
// deposit's 200, and prunes at the mark.
func TestRecordMirrorsKeepDepositsUntilTheMark(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	testRecordDepositNotes(t, record, "two")
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept before any ingest", len(kept))
	}
	ingesterRecord := ingester.open()
	testRecordIngest(t, ingesterRecord, world)
	if err := ingesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, ingesterRecord, world)
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left after ingest", len(deposits))
	}
	// a depositor sees no CONSUME: it still keeps both until evs tells it the mark
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept before the mark arrived", len(kept))
	}
	testRecordDepositNotes(t, record, "three")
	kept := spool.batches(world.vaultId)
	if len(kept) != 1 {
		t.Fatalf("%d deposits kept after the mark passed two", len(kept))
	}
	entries, err := sidecar.RecordDepositBatchParse(kept[0], depositor.settings.DepositByteCount)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the kept deposit: %v", err)
	}
	if lines := record.Mirrors().StatusLines(t.Context()); testRecordLinesContain(lines, "not kept") || testRecordLinesContain(lines, "wait to go again") {
		t.Errorf("lines %v", lines)
	}
}

// A deposit left unsettled holds the mark below it, so nothing at or above it is pruned.
func TestRecordIngestMarksBelowADepositItLeaves(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	ingesterRecord := ingester.open()
	testRecordIngest(t, ingesterRecord, world)
	// the first pass writes the entry and leaves the deposit until its own push commits: nothing is consumed, so the
	// next deposit's answer carries no mark
	testRecordDepositNotes(t, record, "two")
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept with nothing consumed", len(kept))
	}
}

// A commit whose answer was lost goes again to the same commit, and is kept once.
func TestRecordMirrorsKeepADepositOnceAcrossALostAnswer(t *testing.T) {
	world := newTestRecordWorld(t)
	world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordAppend(t, record, testRecordNote(nil, "one"))
	depositor.tap.stateLock.Lock()
	depositor.tap.loseNextOutcome = true
	depositor.tap.stateLock.Unlock()
	if err := record.Flush(t.Context()); err == nil {
		t.Fatal("a lost answer read as a commit")
	}
	if kept := spool.batches(world.vaultId); len(kept) != 0 {
		t.Fatalf("%d deposits kept before any answer", len(kept))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if kept := spool.batches(world.vaultId); len(kept) != 1 {
		t.Fatalf("%d deposits kept", len(kept))
	}
	// the same commit handed again, as after a kill between the keep and the plan's removal, keeps nothing more
	reopened := depositor.openKeeping(spool)
	testRecordDepositNotes(t, reopened, "two")
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept after a second deposit", len(kept))
	}
}

// A site loss: the vault is placed afresh, and once the log resumes the depositor deposits what it kept again,
// verbatim. The Signed bytes equal those first deposited, a new device of the author ingests them, and a reader
// verifies the depositor's chain with no alarm.
func TestRecordMirrorsRedepositAfterASiteLoss(t *testing.T) {
	world := newTestRecordWorld(t)
	world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one", "two")
	testRecordDepositNotes(t, record, "three")
	before := spool.batches(world.vaultId)
	if len(before) != 2 {
		t.Fatalf("%d deposits kept", len(before))
	}
	signedBefore := testRecordBatchSigned(t, depositor, before)

	world.streams.LoseSite(world.vaultId)
	if err := record.Mirrors().Resumed(world.vaultId); err != nil {
		t.Fatal(err)
	}
	if lines := record.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, world.vaultId.String(), "wait to go again") {
		t.Fatalf("kept deposits waiting are not named: %v", lines)
	}
	if err := record.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lines := record.Mirrors().StatusLines(t.Context()); testRecordLinesContain(lines, "wait to go again") {
		t.Fatalf("lines after the resume: %v", lines)
	}
	after := spool.batches(world.vaultId)
	if len(after) != 2 || !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
		t.Fatalf("%d deposits kept after the resume, or not the same batches", len(after))
	}
	// a new consented device, since the old ingester's stream went with the site
	ingester := world.device(true)
	deposits := world.waitingDeposits(ingester, depositor.sidecarId)
	if len(deposits) != 2 {
		t.Fatalf("%d deposits in the new ref", len(deposits))
	}
	redeposited := [][]byte{}
	for _, deposit := range deposits {
		redeposited = append(redeposited, deposit.Batch)
	}
	signedAfter := testRecordBatchSigned(t, depositor, redeposited)
	if len(signedAfter) != len(signedBefore) {
		t.Fatalf("%d entries went again, of %d", len(signedAfter), len(signedBefore))
	}
	for i := range signedBefore {
		if !bytes.Equal(signedBefore[i], signedAfter[i]) {
			t.Errorf("entry %d was signed again", i)
		}
	}
	ingesterRecord := ingester.open()
	testRecordIngest(t, ingesterRecord, world)
	if err := ingesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, ingesterRecord, world)
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 3 {
		t.Fatalf("the reader holds %d entries", len(entries))
	}
	for i, entry := range entries {
		if entry.State != sidecar.RecordEntryLive || entry.Body == nil || !bytes.Equal(entry.SignedBytes, signedBefore[i]) {
			t.Errorf("entry %d does not read as first signed", i)
		}
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("the re-deposited chain raised %v", reasons)
	}
	if reasons := ingester.alarmReasons(); len(reasons) != 0 {
		t.Errorf("the ingester raised %v", reasons)
	}
	// the new ref's marks prune the new life's copies, the earlier life's being gone already
	testRecordDepositNotes(t, record, "four")
	if kept := spool.batches(world.vaultId); len(kept) != 1 {
		t.Fatalf("%d deposits kept after the new ref's mark", len(kept))
	}
}

// With no word from the composition, the depositor finds the ref placed afresh at its next commit, which answers a
// version it already passed, and deposits what it kept of the earlier life again, each once.
func TestRecordMirrorsFindARefPlacedAfresh(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	testRecordDepositNotes(t, record, "two")
	world.streams.LoseSite(world.vaultId)
	testRecordDepositNotes(t, record, "three")
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 1 {
		t.Fatalf("%d deposits before the kept ones went again", len(deposits))
	}
	if err := record.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 3 {
		t.Fatalf("%d deposits in the new ref", len(deposits))
	}
	if kept := spool.batches(world.vaultId); len(kept) != 3 {
		t.Fatalf("%d deposits kept", len(kept))
	}
	// a second pass has nothing to send
	if err := record.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 3 {
		t.Fatalf("%d deposits after a second pass", len(deposits))
	}
}

// Re-seed mode mints a depositor no token, so its deposits fail until the log resumes: the kept deposits wait,
// named, and go once evs takes them, those that went before the failure not going twice.
func TestRecordMirrorsWaitForTheLogToResume(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	testRecordDepositNotes(t, record, "two")
	world.streams.LoseSite(world.vaultId)
	if err := record.Mirrors().Resumed(world.vaultId); err != nil {
		t.Fatal(err)
	}
	depositor.tap.setDown(true)
	if err := record.Mirrors().Tend(t.Context()); err == nil {
		t.Fatal("a pass with evs refusing deposits read as done")
	}
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept while waiting", len(kept))
	}
	if lines := record.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, "wait to go again") {
		t.Fatalf("lines %v", lines)
	}
	depositor.tap.setDown(false)
	if err := record.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 2 {
		t.Fatalf("%d deposits in the new ref", len(deposits))
	}
	if kept := spool.batches(world.vaultId); len(kept) != 2 {
		t.Fatalf("%d deposits kept after the resume", len(kept))
	}
}

// A restart in the middle of a resume deposits the earlier life's batches again, never fewer: an ingester reads a
// batch that came twice as the leaves it already wrote.
func TestRecordMirrorsResumeAgainAfterARestart(t *testing.T) {
	world := newTestRecordWorld(t)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	world.streams.LoseSite(world.vaultId)
	if err := record.Mirrors().Resumed(world.vaultId); err != nil {
		t.Fatal(err)
	}
	// the process dies before its pass: the next one still knows the kept deposits wait
	reopened := depositor.openKeeping(spool)
	if lines := reopened.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, "wait to go again") {
		t.Fatalf("a restart forgot the resume: %v", lines)
	}
	if err := reopened.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	ingester := world.device(true)
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 1 {
		t.Fatalf("%d deposits in the new ref", len(deposits))
	}
	ingesterRecord := ingester.open()
	testRecordIngest(t, ingesterRecord, world)
	if err := ingesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, ingesterRecord, world)
	// the same batch handed again, as a kill between a re-deposit and its keep would
	if err := reopened.Mirrors().Resumed(world.vaultId); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Mirrors().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, ingesterRecord, world)
	if err := ingesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, ingesterRecord, world)
	if stored := world.storedEntries(ingester.sidecarId); len(stored) != 1 {
		t.Fatalf("the ingester's stream holds %d entries of one deposited twice", len(stored))
	}
}

// A spool at its cap drops its oldest kept deposit, and one that cannot fit at all is not kept: both are counted, and
// status names what a site loss would now lose.
func TestRecordMirrorsCountADepositTheSpoolCannotKeep(t *testing.T) {
	world := newTestRecordWorld(t)
	world.device(true)
	depositor := world.device(false)
	spool := &testRecordDepositSpool{byteCount: 64}
	record := depositor.openKeeping(spool)
	testRecordDepositNotes(t, record, "one")
	if kept := spool.batches(world.vaultId); len(kept) != 0 {
		t.Fatalf("%d deposits kept past the cap", len(kept))
	}
	if spool.dropCount != 1 {
		t.Fatalf("%d drops counted", spool.dropCount)
	}
	if lines := record.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, world.vaultId.String(), "1 deposits not kept") {
		t.Fatalf("the drop is not named: %v", lines)
	}
	// the count outlives the process
	reopened := depositor.openKeeping(spool)
	if lines := reopened.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, "1 deposits not kept") {
		t.Fatalf("a restart forgot the drop: %v", lines)
	}
}

// With no spool a depositor keeps nothing, and status says so.
func TestRecordMirrorsNameADepositorThatKeepsNothing(t *testing.T) {
	world := newTestRecordWorld(t)
	world.device(true)
	depositor := world.device(false)
	record := depositor.open()
	record.Mirrors().Bind(newTestRecordMirrorView(), nil)
	testRecordDepositNotes(t, record, "one")
	if lines := record.Mirrors().StatusLines(t.Context()); !testRecordLinesContain(lines, world.vaultId.String(), "keeps no deposit") {
		t.Fatalf("lines %v", lines)
	}
}
