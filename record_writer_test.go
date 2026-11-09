//go:build !sidecar_http

// record_writer.go's Append on sidecartest's store, streams, authorization state and run files, with an in-memory
// spool: Append returning with evs down, the journal then draining in seq order; a locked daemon's drafts spooled and
// sealed at unlock in capture order, and once each across a kill mid-drain; taint from the run's fsync on and never
// back, a missing run and an unbound session tainted; kinds no personal log holds refused; a sidecar with no author
// spooling with no_vault counted; a planned push resent unchanged after a kill. External, since sidecartest imports
// the root, and off the sidecar_http leg, whose root lacks what sidecartest's engine suites link.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §16.7's spool as the writer sees it: Append keeps records whether locked or not, and Drain, refused while locked,
// hands taint records first and then the rest in capture order. Rewind puts back what a kill before the drain's cursor
// would deliver again.
type testRecordSpool struct {
	stateLock sync.Mutex
	locked    bool
	full      bool
	segmentId sidecar.Id
	nextIndex uint64
	waiting   []*testRecordSpooled
	consumed  []*testRecordSpooled
}

type testRecordSpooled struct {
	id     sidecar.SpoolRecordId
	record *sidecar.SpoolRecord
}

func newTestRecordSpool() *testRecordSpool {
	return &testRecordSpool{segmentId: sidecar.NewId()}
}

func (self *testRecordSpool) Append(record *sidecar.SpoolRecord) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.full {
		return sidecar.ErrSpoolFull
	}
	id := sidecar.SpoolRecordId{SegmentId: self.segmentId, Index: self.nextIndex}
	self.nextIndex += 1
	self.waiting = append(self.waiting, &testRecordSpooled{
		id:     id,
		record: &sidecar.SpoolRecord{Kind: record.Kind, RunId: record.RunId, Bytes: bytes.Clone(record.Bytes)},
	})
	return nil
}

func (self *testRecordSpool) Drain(ctx context.Context, consume func(id sidecar.SpoolRecordId, record *sidecar.SpoolRecord) error) error {
	ordered := func() []*testRecordSpooled {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.locked {
			return nil
		}
		ordered := []*testRecordSpooled{}
		for _, spooled := range self.waiting {
			if spooled.record.Kind == sidecar.SpoolRecordTaint {
				ordered = append(ordered, spooled)
			}
		}
		for _, spooled := range self.waiting {
			if spooled.record.Kind != sidecar.SpoolRecordTaint {
				ordered = append(ordered, spooled)
			}
		}
		return ordered
	}()
	if ordered == nil && self.isLocked() {
		return fmt.Errorf("spool: %w", sidecar.ErrSidecarStoreLocked)
	}
	for _, spooled := range ordered {
		if err := consume(spooled.id, spooled.record); err != nil {
			return err
		}
		self.stateLock.Lock()
		self.waiting = slices.DeleteFunc(self.waiting, func(waiting *testRecordSpooled) bool { return waiting == spooled })
		self.consumed = append(self.consumed, spooled)
		self.stateLock.Unlock()
	}
	return nil
}

func (self *testRecordSpool) isLocked() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.locked
}

func (self *testRecordSpool) setLocked(locked bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.locked = locked
}

// Puts the last count records drained back in front, as a kill before the drain's cursor passed them would.
func (self *testRecordSpool) rewind(count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	back := self.consumed[len(self.consumed)-count:]
	self.consumed = self.consumed[:len(self.consumed)-count]
	self.waiting = append(slices.Clone(back), self.waiting...)
}

func (self *testRecordSpool) waitingCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.waiting)
}

// evs as a device reaches it, which a test can take down, or have lose the outcome of a push it committed, and which
// keeps every push and deposit it was handed.
type testRecordStreamsTap struct {
	sidecar.RecordStreams

	stateLock       sync.Mutex
	down            bool
	loseNextOutcome bool
	pushes          []*sidecar.RecordStreamPush
	deposits        []*sidecar.RecordStreamDeposit
}

var errTestRecordEvsDown = errors.New("evs unreachable")

func (self *testRecordStreamsTap) isDown() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.down
}

func (self *testRecordStreamsTap) setDown(down bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.down = down
}

func (self *testRecordStreamsTap) loseOutcome() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lose := self.loseNextOutcome
	self.loseNextOutcome = false
	return lose
}

func (self *testRecordStreamsTap) Append(ctx context.Context, repoId sidecar.Id, push *sidecar.RecordStreamPush) (*sidecar.RecordStreamCommit, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pushes = append(self.pushes, push)
	}()
	if self.isDown() {
		return nil, errTestRecordEvsDown
	}
	commit, err := self.RecordStreams.Append(ctx, repoId, push)
	if err == nil && self.loseOutcome() {
		return nil, errTestRecordEvsDown
	}
	return commit, err
}

func (self *testRecordStreamsTap) Deposit(ctx context.Context, repoId sidecar.Id, deposit *sidecar.RecordStreamDeposit) (*sidecar.RecordStreamCommit, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.deposits = append(self.deposits, deposit)
	}()
	if self.isDown() {
		return nil, errTestRecordEvsDown
	}
	commit, err := self.RecordStreams.Deposit(ctx, repoId, deposit)
	if err == nil && self.loseOutcome() {
		return nil, errTestRecordEvsDown
	}
	return commit, err
}

func (self *testRecordStreamsTap) Streams(ctx context.Context, repoId sidecar.Id) ([]*sidecar.RecordStreamHead, error) {
	if self.isDown() {
		return nil, errTestRecordEvsDown
	}
	return self.RecordStreams.Streams(ctx, repoId)
}

func (self *testRecordStreamsTap) ReadStream(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) ([]*sidecar.RecordStreamVersion, error) {
	if self.isDown() {
		return nil, errTestRecordEvsDown
	}
	return self.RecordStreams.ReadStream(ctx, repoId, writerSidecarId, afterVersion)
}

func (self *testRecordStreamsTap) pushCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.pushes)
}

// A personal network with one member and its vault, on one clock.
type testRecordWorld struct {
	t        *testing.T
	clock    *sidecartest.FakeClock
	streams  *sidecartest.FakeRecordStreams
	auth     *sidecartest.FakeRecordAuth
	runs     *sidecartest.FakeRunView
	memberId sidecar.Id
	vaultId  sidecar.Id
	fixture  *sidecartest.FakeRecordAuthFixture
	readerId sidecar.Id
}

func newTestRecordWorld(t *testing.T) *testRecordWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	streams := sidecartest.NewFakeRecordStreams(clock, nil, nil)
	vaultId, err := streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	memberId := sidecar.NewId()
	readerId := sidecar.NewId()
	if err := streams.Grant(vaultId, readerId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	world := &testRecordWorld{
		t:        t,
		clock:    clock,
		streams:  streams,
		auth:     sidecartest.NewFakeRecordAuth(),
		runs:     sidecartest.NewFakeRunView(),
		memberId: memberId,
		vaultId:  vaultId,
		readerId: readerId,
		fixture: &sidecartest.FakeRecordAuthFixture{
			IdentityKeys: map[sidecar.Id][]byte{},
			Members:      map[sidecar.Id]sidecar.Id{},
			Sponsors:     map[sidecar.Id]sidecar.Id{},
			Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{vaultId: {Readers: []sidecar.Id{readerId}}},
			Vaults:       map[sidecar.Id]sidecar.Id{memberId: vaultId},
		},
	}
	world.publish()
	return world
}

// Appends the fixture as the log's next position.
func (self *testRecordWorld) publish() {
	self.fixture.TimeMillis = self.clock.Now().UnixMilli()
	self.auth.Append(self.fixture)
}

// One device of the world's member: consented, it writes its own stream of the vault; not, it deposits there.
type testRecordDevice struct {
	t         *testing.T
	world     *testRecordWorld
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	files     *sidecartest.FakeStore
	store     sidecar.SidecarStore
	spool     *testRecordSpool
	tap       *testRecordStreamsTap
	settings  *sidecar.SidecarRecordSettings

	stateLock sync.Mutex
	locked    bool
	gaps      []string
	alarms    []*sidecar.RecordAlarm
}

func (self *testRecordWorld) device(consented bool) *testRecordDevice {
	self.t.Helper()
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("record", "record")
	if err != nil {
		self.t.Fatal(err)
	}
	device := &testRecordDevice{
		t:         self.t,
		world:     self,
		sidecarId: sidecar.NewId(),
		key:       key,
		files:     files,
		store:     store,
		spool:     newTestRecordSpool(),
		settings:  sidecar.DefaultSidecarSettings().Record,
	}
	device.tap = &testRecordStreamsTap{RecordStreams: self.streams.For(device.sidecarId)}
	self.fixture.IdentityKeys[device.sidecarId] = publicKey
	self.fixture.Members[device.sidecarId] = self.memberId
	repo := self.fixture.Repos[self.vaultId]
	scope := sidecartest.RecordStreamsScope{Read: true, Deposit: true}
	if consented {
		repo.Readers = append(repo.Readers, device.sidecarId)
		repo.Writers = append(repo.Writers, device.sidecarId)
		repo.Consented = append(repo.Consented, device.sidecarId)
		scope.Write = true
	} else {
		repo.Depositors = append(repo.Depositors, device.sidecarId)
		scope.Read = false
	}
	if err := self.streams.Grant(self.vaultId, device.sidecarId, scope); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return device
}

// Sidecar.Sign with this device's key, or ErrSidecarStoreLocked while it is locked.
func (self *testRecordDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	self.stateLock.Lock()
	locked := self.locked
	self.stateLock.Unlock()
	if locked {
		return nil, fmt.Errorf("sign: %w", sidecar.ErrSidecarStoreLocked)
	}
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *testRecordDevice) setLocked(locked bool) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.locked = locked
	}()
	self.spool.setLocked(locked)
}

func (self *testRecordDevice) takeGaps() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	gaps := self.gaps
	self.gaps = nil
	return gaps
}

// One process's life of this device's record, over what its store holds now.
func (self *testRecordDevice) open() *sidecar.SidecarRecord {
	self.t.Helper()
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.key.Public().(ed25519.PublicKey),
		Store:             self.store,
		Sign:              self.sign,
		Spool:             self.spool,
		Runs:              self.world.runs,
		Gap: func(runId sidecar.Id, code string) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.gaps = append(self.gaps, runId.String()+" "+code)
		},
		Streams: self.tap,
		Auth:    func() sidecar.RecordAuthView { return self.world.auth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.alarms = append(self.alarms, alarm)
		},
		Clock:    self.world.clock,
		Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// A note an agent files in run, nil for none.
func testRecordNote(runId *sidecar.Id, text string) *sidecar.RecordDraft {
	return &sidecar.RecordDraft{
		Kind:   sidecar.RecordKindNote,
		Source: sidecar.RecordSourceAgent,
		RunId:  runId,
		Body:   &protocol.CoordinationBody{Text: text},
	}
}

// Appends a draft that must take, answering its one ref.
func testRecordAppend(t *testing.T, record *sidecar.SidecarRecord, draft *sidecar.RecordDraft) *sidecar.RecordEntryRef {
	t.Helper()
	refs, err := record.Writer().Append(draft)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Fatalf("%d refs for one draft", len(refs))
	}
	return refs[0]
}

// One entry as a reader of the vault finds it in a writer's stream: where it sits, its header, and its body opened
// with its slot row.
type testRecordStored struct {
	version  uint64
	path     string
	slotId   sidecar.Id
	keyIndex uint32
	entry    *protocol.RecordEntry
	header   *protocol.RecordHeader
	body     []byte
}

// Every entry of writerId's stream in the vault, in push order, each body opened.
func (self *testRecordWorld) storedEntries(writerId sidecar.Id) []*testRecordStored {
	self.t.Helper()
	reader := self.streams.For(self.readerId)
	versions, err := reader.ReadStream(self.t.Context(), self.vaultId, writerId, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	stored := []*testRecordStored{}
	for _, version := range versions {
		slot, err := reader.ReadSlot(self.t.Context(), self.vaultId, version.SlotId)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, streamEntry := range version.Entries {
			entry := &protocol.RecordEntry{}
			if err := proto.Unmarshal(streamEntry.Entry, entry); err != nil {
				self.t.Fatal(err)
			}
			header, err := sidecar.ParseStoredRecordHeader(entry.GetHeader().GetBody())
			if err != nil {
				self.t.Fatal(err)
			}
			item := &testRecordStored{
				version:  version.Version,
				path:     streamEntry.Path,
				slotId:   sidecar.Id(entry.GetKeySlotId()),
				keyIndex: entry.GetKeyIndex(),
				entry:    entry,
				header:   header.Header,
			}
			for _, row := range slot.Rows {
				if row.KeyIndex == entry.GetKeyIndex() {
					key, salt, err := sidecar.RecordSlotRowSplit(row.Row)
					if err != nil {
						self.t.Fatal(err)
					}
					body, err := sidecar.RecordOpen(header, entry.GetSealedBody(), key, salt)
					if err != nil {
						self.t.Fatal(err)
					}
					item.body = body
				}
			}
			stored = append(stored, item)
		}
	}
	return stored
}

// The note texts of entries, in order.
func testRecordTexts(t *testing.T, stored []*testRecordStored) []string {
	t.Helper()
	texts := []string{}
	for _, item := range stored {
		body := &protocol.CoordinationBody{}
		if err := proto.Unmarshal(item.body, body); err != nil {
			t.Fatal(err)
		}
		texts = append(texts, body.GetText())
	}
	return texts
}

// Append is durable in the journal with evs down: each entry has its seq, nothing reached evs, and once evs is back
// a flush carries them in seq order and leaves no journal record behind.
func TestRecordWriterAppendReturnsWithEvsDown(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	device.tap.setDown(true)
	record := device.open()
	for index := range 3 {
		ref := testRecordAppend(t, record, testRecordNote(nil, fmt.Sprintf("note %d", index)))
		if ref.Spooled || ref.LogId != world.vaultId || ref.Seq != uint64(index+1) {
			t.Fatalf("entry %d: %+v", index, ref)
		}
	}
	if err := record.Flush(t.Context()); err == nil {
		t.Fatal("a flush with evs down reported every entry sent")
	}
	if stored := world.storedEntries(device.sidecarId); len(stored) != 0 {
		t.Fatalf("%d entries reached evs while it was down", len(stored))
	}
	device.tap.setDown(false)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	if got := testRecordTexts(t, stored); !slices.Equal(got, []string{"note 0", "note 1", "note 2"}) {
		t.Fatalf("the stream holds %v", got)
	}
	for index, item := range stored {
		if item.header.GetSeq() != uint64(index+1) || item.path != fmt.Sprintf("e/0/0/%d", index+1) {
			t.Errorf("entry %d is seq %d at %s", index, item.header.GetSeq(), item.path)
		}
	}
	logIds, err := sidecar.NewRecordChainStore(device.store, device.sidecarId).PendingLogIds()
	if err != nil || len(logIds) != 0 {
		t.Errorf("journal records left for %v: %v", logIds, err)
	}
}

// A locked daemon spools its drafts unsealed; at unlock the next Append seals them first, in capture order, each with
// its capture time, and then itself.
func TestRecordWriterSealsTheSpoolInCaptureOrderAfterUnlock(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	device.setLocked(true)
	captureMillis := []int64{}
	for index := range 3 {
		captureMillis = append(captureMillis, world.clock.Now().UnixMilli())
		ref := testRecordAppend(t, record, testRecordNote(nil, fmt.Sprintf("locked %d", index)))
		if !ref.Spooled {
			t.Fatalf("a locked draft was not spooled: %+v", ref)
		}
		world.clock.Advance(time.Second)
	}
	device.setLocked(false)
	ref := testRecordAppend(t, record, testRecordNote(nil, "unlocked"))
	if ref.Spooled || ref.Seq != 4 {
		t.Fatalf("the first draft after unlock: %+v", ref)
	}
	if count := device.spool.waitingCount(); count != 0 {
		t.Fatalf("%d records left in the spool", count)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	if got := testRecordTexts(t, stored); !slices.Equal(got, []string{"locked 0", "locked 1", "locked 2", "unlocked"}) {
		t.Fatalf("the stream holds %v", got)
	}
	for index, millis := range captureMillis {
		if stored[index].header.GetTimeMillis() != millis {
			t.Errorf("spooled entry %d took time %d, not its capture's %d", index, stored[index].header.GetTimeMillis(), millis)
		}
	}
}

// A drain cut short by a kill delivers its last records again: each was sealed once, by its capture id in the journal
// and the mark, so the stream holds each capture once.
func TestRecordWriterSealsASpooledCaptureOnceAcrossAKill(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	device.setLocked(true)
	for index := range 3 {
		testRecordAppend(t, record, testRecordNote(nil, fmt.Sprintf("locked %d", index)))
	}
	device.setLocked(false)
	if err := record.DrainSpool(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the kill: a new life on the same files, and a spool that hands the last two over again
	device.spool.rewind(2)
	record = device.open()
	if err := record.DrainSpool(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := testRecordTexts(t, world.storedEntries(device.sidecarId)); !slices.Equal(got, []string{"locked 0", "locked 1", "locked 2"}) {
		t.Fatalf("the stream holds %v", got)
	}
}

// Section 5.3's tainted row: an entry takes its run's bit at sealing, so entries turn tainted from the run's taint on
// and never back; a run with no readable file is tainted, as is an entry a session files with no run, and only an
// entry no session touched is not.
func TestRecordWriterSealsTaintFromTheRunsFsyncOn(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	testRecordAppend(t, record, testRecordNote(&runId, "before"))
	world.runs.Taint(runId)
	testRecordAppend(t, record, testRecordNote(&runId, "after"))
	world.runs.StartRun(runId)
	testRecordAppend(t, record, testRecordNote(&runId, "rewritten"))
	lostRunId := sidecar.NewId()
	world.runs.StartRun(lostRunId)
	world.runs.LoseRun(lostRunId)
	testRecordAppend(t, record, testRecordNote(&lostRunId, "lost"))
	testRecordAppend(t, record, testRecordNote(nil, "unbound"))
	person := testRecordNote(nil, "person")
	person.NoSession = true
	person.Source = sidecar.RecordSourceApprover
	testRecordAppend(t, record, person)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	want := map[string]bool{"before": false, "after": true, "rewritten": true, "lost": true, "unbound": true, "person": false}
	for index, text := range testRecordTexts(t, stored) {
		if stored[index].header.GetTainted() != want[text] {
			t.Errorf("%s sealed tainted %t", text, stored[index].header.GetTainted())
		}
	}
}

// Section 6.3's Personal none: no personal log holds D's kinds, a copy or T's and R's upkeep, so the writer refuses
// them rather than write them anywhere, and a read receipt is deposited, never appended.
func TestRecordWriterRefusesKindsNoPersonalLogHolds(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	draft := &sidecar.RecordDraft{Kind: sidecar.RecordKindCopy, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.CopyBody{}}
	if _, err := record.Writer().Append(draft); !errors.Is(err, sidecar.ErrRecordRouteTeamOnly) {
		t.Errorf("a copy: %v", err)
	}
	receipt := &sidecar.RecordDraft{
		Kind:      sidecar.RecordKindRead,
		Source:    sidecar.RecordSourceObserved,
		NoSession: true,
		Body:      &protocol.ReadBody{ObjectIds: [][]byte{sidecar.NewId().Bytes()}, Purpose: 1},
	}
	if _, err := record.Writer().Append(receipt); !errors.Is(err, sidecar.ErrRecordRouteReceipt) {
		t.Errorf("a read receipt: %v", err)
	}
	over := testRecordNote(nil, string(bytes.Repeat([]byte{'x'}, 1025)))
	if _, err := record.Writer().Append(over); !errors.Is(err, sidecar.ErrRecordDraftInvalid) {
		t.Errorf("a note past its cap: %v", err)
	}
	if count := device.spool.waitingCount(); count != 0 {
		t.Errorf("%d refused drafts spooled", count)
	}
}

// A sidecar no member's admission names and no sponsor holds has no author: its capture stays in the spool and the
// run's coverage names no_vault, until a log takes it.
func TestRecordWriterSpoolsWithNoAuthor(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	delete(world.fixture.Members, device.sidecarId)
	world.publish()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	ref := testRecordAppend(t, record, testRecordNote(&runId, "orphan"))
	if !ref.Spooled {
		t.Fatalf("an authorless draft: %+v", ref)
	}
	if gaps := device.takeGaps(); !slices.Equal(gaps, []string{runId.String() + " no_vault"}) {
		t.Errorf("gaps %v", gaps)
	}
	// the member's admission arrives: the spooled draft seals into the vault
	world.fixture.Members[device.sidecarId] = world.memberId
	world.publish()
	if err := record.DrainSpool(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := testRecordTexts(t, world.storedEntries(device.sidecarId)); !slices.Equal(got, []string{"orphan"}) {
		t.Fatalf("the stream holds %v", got)
	}
}

// A planned push goes again after a kill exactly as planned: the same push id, slot id and bytes, which evs answers
// with the commit it made, so the stream holds each entry once.
func TestRecordWriterResendsAPlannedPushUnchangedAfterAKill(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	testRecordAppend(t, record, testRecordNote(nil, "one"))
	testRecordAppend(t, record, testRecordNote(nil, "two"))
	// the push commits, and the kill takes its answer
	device.tap.stateLock.Lock()
	device.tap.loseNextOutcome = true
	device.tap.stateLock.Unlock()
	if err := record.Flush(t.Context()); err == nil {
		t.Fatal("a lost outcome flushed clean")
	}
	record = device.open()
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count := device.tap.pushCount(); count != 2 {
		t.Fatalf("%d pushes", count)
	}
	first, second := device.tap.pushes[0], device.tap.pushes[1]
	if first.PushId != second.PushId || first.SlotId != second.SlotId || len(first.Entries) != len(second.Entries) {
		t.Fatalf("the resent push changed: %s/%s, %s/%s", first.PushId, second.PushId, first.SlotId, second.SlotId)
	}
	for index := range first.Entries {
		if first.Entries[index].Path != second.Entries[index].Path || !bytes.Equal(first.Entries[index].Entry, second.Entries[index].Entry) {
			t.Errorf("entry %d changed between attempts", index)
		}
	}
	if got := testRecordTexts(t, world.storedEntries(device.sidecarId)); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("the stream holds %v", got)
	}
}
