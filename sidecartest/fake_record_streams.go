// §23.5's fake of evs's record-class refs behind sidecar.RecordStreams: one world of repos, which each sidecar of a
// test reaches through For, carrying the scope Grant gave it. It keeps §11.8's refs table and §11.12 rather than
// echoing what it is given:
//
//   - a stream takes pushes from its own sidecar alone, at rw, and only creates paths: 409 REF_MODE otherwise;
//   - a deposit goes only to its depositor's own ref, at deposit, creating its id, and a receipt-only depositor's
//     stays within §11.12's 4 KiB and 256 a UTC day per repo, else 429 RESOURCE_EXHAUSTED;
//   - reads of streams, slots and erasures take read, reads of deposits and CONSUME take rw, and an ERASE takes admin,
//     each else 403 SCOPE;
//   - an ERASE takes its keys out of their slots, so a slot read returns no erased row, and one naming no key a slot
//     still holds is 409 NOTHING_TO_ERASE, recorded;
//   - a push id keeps its outcome: a retry of the same statement answers the commit it made, or the refusal recorded
//     against it, so slot ids hold across a retry, and another statement under that id is 409 PUSH_ID_REUSED;
//   - a repo's gate closes on demand, refusing pushes and deposits 412 GATE_CLOSED, recorded, until it opens;
//   - every mutating step passes record_streams.<step>.before and .after around its commit, keyed by the repo, and
//     every time is the injected clock's;
//   - every commit raises the repo's push sequence (§11.10's sequence row) and keeps the value beside its ref, as
//     {evsh_<repo_id>} does for GET .../refs?moved_after (§11.9); RestartSequence models its loss, after which the
//     sequence starts above every earlier value and no ref holds one, so a listing answers every ref;
//   - a stream has a ref id and each of its versions a chain value C_v (§11.8), which a checkpoint's frontier names
//     (RECORD.md section 10.1): the ref id is this fake's own digest of the repo and the writer, standing in for
//     §11.6's keyed one, and C_v is EvsChainNext over this fake's statement digests;
//   - RemoveStreamEntries takes entry files out of a stream as a committed BASE does (§11.8), leaving its versions.
//
// It holds no format code: entries, slot rows, batches and notes are the caller's bytes, kept and returned as they
// came, and nothing is sealed, tokenized or verified. What it does not keep: the pins a push declares, beyond
// GATE_CLOSED on demand; statements and their replay; segments and padding; the storage limit and DIRECTORY_FULL;
// BASE; drop keys; and deposit slots, which the binding keeps beside each deposit.
//
// Safe for concurrent use. Barriers and subscribers run with no lock held.

package sidecartest

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a sidecar's token lets it do on one repo (§7.8), as a test grants it.
type RecordStreamsScope struct {
	// Read the repo's streams, slots and erasures.
	Read bool
	// rw: push its own stream, read deposits and CONSUME them.
	Write   bool
	Deposit bool
	// Its deposits are read receipts, within §11.12's budget.
	ReceiptOnly bool
	// ERASE.
	Admin bool
}

type FakeRecordStreamsSettings struct {
	// §11.12: a receipt-only depositor's deposit is at most this many bytes, else 429. The fake measures the batch as
	// given, which is under its sealed size.
	ReceiptByteCount int
	// §11.12: and at most this many a UTC day per repo, else 429.
	ReceiptDayCount int
	// §11.8's slot bound: rows a push's slot object holds.
	SlotRowCount int
	// Told each rule a caller broke that evs answers with no refusal of its own, as it happens. nil: Violations
	// alone holds them.
	Report func(violation string)
}

func DefaultFakeRecordStreamsSettings() *FakeRecordStreamsSettings {
	return &FakeRecordStreamsSettings{
		ReceiptByteCount: 4 * 1024,
		ReceiptDayCount:  256,
		SlotRowCount:     64,
	}
}

// The world: every repo's refs, slots, erasures and scopes.
type FakeRecordStreams struct {
	clock    Clock
	barriers *BarrierDriver
	settings *FakeRecordStreamsSettings

	stateLock   sync.Mutex
	repos       map[sidecar.Id]*fakeRecordRepo
	subscribers map[sidecar.Id]map[uint64]func(repoId sidecar.Id)
	nextSubId   uint64
	violations  []string
}

// One repo's state.
type fakeRecordRepo struct {
	scopes     map[sidecar.Id]RecordStreamsScope
	gateClosed bool
	streams    map[sidecar.Id]*fakeRecordStream
	deposits   map[sidecar.Id]*fakeRecordDepositRef
	slots      map[sidecar.Id]map[uint32][]byte
	erasures   []*sidecar.RecordStreamErasure
	// what each push id came to, for its retries
	outcomes map[sidecar.Id]*fakeRecordOutcome
	// a receipt-only depositor's deposits by UTC day
	receiptCounts map[fakeRecordReceiptDay]int
	// the push sequence, the value it restarted at, and what each ref's last commit raised it to
	sequence     uint64
	restartedAt  uint64
	refSequences map[FakeRecordRef]uint64
}

// The value a repo's push sequence starts at, as a master's clock in µs × 1,000 would be (§11.10's sequence row): a
// fake's, far above any count a test reaches.
const fakeRecordSequenceStart = uint64(1_000_000_000)

// One ref of a repo, as the push sequence names it.
type FakeRecordRef struct {
	Kind FakeRecordRefKind
	// A stream's writer or a deposit ref's depositor; zero for the erasure ref and a named ref.
	SidecarId sidecar.Id
	// A ref outside the record's, such as the directory's cards ref.
	Name string
}

type FakeRecordRefKind int

const (
	FakeRecordRefStream FakeRecordRefKind = iota + 1
	FakeRecordRefDeposit
	FakeRecordRefErasure
	FakeRecordRefNamed
)

// A repo's push sequence as GET .../refs reads it.
type FakeRecordSequence struct {
	Sequence uint64
	// Values below this predate the sequence's last restart.
	RestartedAt uint64
	// What each ref's last commit raised the sequence to; a ref the cache lost is absent.
	Refs map[FakeRecordRef]uint64
}

// Raises the sequence for a commit of ref and keeps the value beside it.
func (self *fakeRecordRepo) raiseWithLock(ref FakeRecordRef) uint64 {
	self.sequence += 1
	self.refSequences[ref] = self.sequence
	return self.sequence
}

// A writer's stream.
type fakeRecordStream struct {
	version  uint64
	paths    map[string]bool
	versions []*sidecar.RecordStreamVersion
	refId    sidecar.Id
	chain    [sha256.Size]byte
}

// A stream's ref id here: the first 16 bytes of a digest of the repo and the writer. evs's is §11.6's HMAC under
// K_ref, which this fake holds no key for; a frontier only needs it stable and distinct.
func FakeRecordStreamRefId(repoId sidecar.Id, writerSidecarId sidecar.Id) sidecar.Id {
	digest := fakeRecordStatement([]byte("stream ref"), repoId[:], writerSidecarId[:])
	return sidecar.Id(digest[:16])
}

// A depositor's deposit ref: its unconsumed deposits in version order, and every id it ever created.
type fakeRecordDepositRef struct {
	version    uint64
	deposits   []*sidecar.RecordStreamDepositVersion
	depositIds map[sidecar.Id]bool
}

// One push id's outcome and the statement it answered.
type fakeRecordOutcome struct {
	statement [sha256.Size]byte
	commit    *sidecar.RecordStreamCommit
	refusal   *sidecar.RecordStreamRefusal
}

type fakeRecordReceiptDay struct {
	depositorId sidecar.Id
	day         string
}

// clock and settings may be nil, for a fresh clock and the defaults. barriers may be nil outside a schedule.
func NewFakeRecordStreams(clock Clock, barriers *BarrierDriver, settings *FakeRecordStreamsSettings) *FakeRecordStreams {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if settings == nil {
		settings = DefaultFakeRecordStreamsSettings()
	}
	return &FakeRecordStreams{
		clock:       clock,
		barriers:    barriers,
		settings:    settings,
		repos:       map[sidecar.Id]*fakeRecordRepo{},
		subscribers: map[sidecar.Id]map[uint64]func(repoId sidecar.Id){},
	}
}

// A fresh record-class repo, its refs empty and no scope granted.
func (self *FakeRecordStreams) NewRepo(ctx context.Context) (sidecar.Id, error) {
	repoId := sidecar.NewId()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repos[repoId] = &fakeRecordRepo{
		scopes:        map[sidecar.Id]RecordStreamsScope{},
		streams:       map[sidecar.Id]*fakeRecordStream{},
		deposits:      map[sidecar.Id]*fakeRecordDepositRef{},
		slots:         map[sidecar.Id]map[uint32][]byte{},
		outcomes:      map[sidecar.Id]*fakeRecordOutcome{},
		receiptCounts: map[fakeRecordReceiptDay]int{},
		sequence:      fakeRecordSequenceStart,
		restartedAt:   fakeRecordSequenceStart,
		refSequences:  map[FakeRecordRef]uint64{},
	}
	return repoId, nil
}

// The repo's push sequence and each ref's last raise.
func (self *FakeRecordStreams) PushSequence(repoId sidecar.Id) (*FakeRecordSequence, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo, ok := self.repos[repoId]
	if !ok {
		return nil, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	}
	refs := map[FakeRecordRef]uint64{}
	for ref, sequence := range repo.refSequences {
		refs[ref] = sequence
	}
	return &FakeRecordSequence{Sequence: repo.sequence, RestartedAt: repo.restartedAt, Refs: refs}, nil
}

// Raises the repo's push sequence for a commit of a ref this fake does not hold, such as the directory's cards ref,
// calling subscribers with no lock held. 0 for a repo it does not hold.
func (self *FakeRecordStreams) RaiseSequence(repoId sidecar.Id, name string) uint64 {
	var raised uint64
	var callbacks []func(repoId sidecar.Id)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		repo, ok := self.repos[repoId]
		if !ok {
			return
		}
		raised = repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefNamed, Name: name})
		callbacks = self.subscribersWithLock(repoId)
	}()
	for _, callback := range callbacks {
		callback(repoId)
	}
	return raised
}

// Loses the repo's push sequence and every ref's raise, as a Redis loss would (§11.10's loss row): the sequence
// restarts above every earlier value, and until each ref commits again a listing answers every ref.
func (self *FakeRecordStreams) RestartSequence(repoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repo, ok := self.repos[repoId]; ok {
		repo.sequence += fakeRecordSequenceStart
		repo.restartedAt = repo.sequence
		repo.refSequences = map[FakeRecordRef]uint64{}
	}
}

// Sets what sidecarId's token lets it do on repoId, as the access log and §7.8's exchange would.
func (self *FakeRecordStreams) Grant(repoId sidecar.Id, sidecarId sidecar.Id, scope RecordStreamsScope) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo, ok := self.repos[repoId]
	if !ok {
		return fmt.Errorf("no repo %s", repoId)
	}
	repo.scopes[sidecarId] = scope
	return nil
}

// Closes or opens the repo's gate, as an authorization change evs holds and a push's pin predates would (§10.6).
func (self *FakeRecordStreams) SetGateClosed(repoId sidecar.Id, closed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repo, ok := self.repos[repoId]; ok {
		repo.gateClosed = closed
	}
}

// Takes the entry files at paths out of writerSidecarId's stream, as a committed BASE does at expiry (§11.8): the
// versions that created them stay, with their statements' chain values, and hold those entries no longer. A reader
// arriving later finds the pushes and not the files.
func (self *FakeRecordStreams) RemoveStreamEntries(repoId sidecar.Id, writerSidecarId sidecar.Id, paths []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo := self.repos[repoId]
	if repo == nil || repo.streams[writerSidecarId] == nil {
		return
	}
	for _, version := range repo.streams[writerSidecarId].versions {
		version.Entries = slices.DeleteFunc(version.Entries, func(entry *sidecar.RecordStreamEntry) bool {
			return slices.Contains(paths, entry.Path)
		})
	}
}

// Moves the clock, when it is a FakeClock.
func (self *FakeRecordStreams) Advance(duration time.Duration) {
	if clock, ok := self.clock.(*FakeClock); ok {
		clock.Advance(duration)
	}
}

// What sidecarId reaches, carrying its scope.
func (self *FakeRecordStreams) For(sidecarId sidecar.Id) sidecar.RecordStreams {
	return &fakeRecordStreamsClient{world: self, sidecarId: sidecarId}
}

// Each rule a caller broke that evs answers with no refusal of its own, such as a slot id another push holds.
func (self *FakeRecordStreams) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.violations)
}

func (self *FakeRecordStreams) violateWithLock(violation string) {
	self.violations = append(self.violations, violation)
	if self.settings.Report != nil {
		self.settings.Report(violation)
	}
}

// The barrier at a step, when a schedule runs.
func (self *FakeRecordStreams) hit(name string, repoId sidecar.Id) {
	if self.barriers != nil {
		self.barriers.Hit(name, hex.EncodeToString(repoId[:]))
	}
}

// The repo's subscribers, to call once the lock is gone.
func (self *FakeRecordStreams) subscribersWithLock(repoId sidecar.Id) []func(repoId sidecar.Id) {
	callbacks := []func(repoId sidecar.Id){}
	for _, callback := range self.subscribers[repoId] {
		callbacks = append(callbacks, callback)
	}
	return callbacks
}

// A refusal by code, recorded when the code is recordable.
func fakeRecordRefusal(code protocol.EvsRefusalCode) *sidecar.RecordStreamRefusal {
	return &sidecar.RecordStreamRefusal{Code: code, Recorded: sidecar.EvsRefusalRecordable(code)}
}

// A read's refusal, which no push id records.
func fakeRecordReadRefusal(code protocol.EvsRefusalCode) *sidecar.RecordStreamRefusal {
	return &sidecar.RecordStreamRefusal{Code: code}
}

// A digest of a statement's parts, each length-prefixed, so a retry is told from another statement under its id.
func fakeRecordStatement(parts ...[]byte) [sha256.Size]byte {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
		hash.Write(part)
	}
	var statement [sha256.Size]byte
	hash.Sum(statement[:0])
	return statement
}

// A pin's bytes for a statement digest.
func fakeRecordPinBytes(pin *bridge.AuthPin) []byte {
	return append(binary.BigEndian.AppendUint64(nil, pin.GetVersion()), pin.GetChain()...)
}

// A pin's copy.
func fakeRecordClonePin(pin *bridge.AuthPin) *bridge.AuthPin {
	if pin == nil {
		return nil
	}
	return &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())}
}

// The answer a push id already holds for statement, or nil when it holds none.
func (self *fakeRecordRepo) retryAnswerWithLock(pushId sidecar.Id, statement [sha256.Size]byte) (*sidecar.RecordStreamCommit, error, bool) {
	outcome, ok := self.outcomes[pushId]
	if !ok {
		return nil, nil, false
	}
	if outcome.statement != statement {
		return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED), true
	}
	if outcome.refusal != nil {
		return nil, outcome.refusal, true
	}
	commit := *outcome.commit
	return &commit, nil, true
}

// Refuses with code, recording it against the push id when the code is recordable.
func (self *fakeRecordRepo) refuseWithLock(pushId sidecar.Id, statement [sha256.Size]byte, code protocol.EvsRefusalCode) error {
	refusal := fakeRecordRefusal(code)
	if refusal.Recorded {
		self.outcomes[pushId] = &fakeRecordOutcome{statement: statement, refusal: refusal}
	}
	return refusal
}

// Keeps a commit for the push id's retries, and returns a copy.
func (self *fakeRecordRepo) commitWithLock(pushId sidecar.Id, statement [sha256.Size]byte, commit *sidecar.RecordStreamCommit) *sidecar.RecordStreamCommit {
	self.outcomes[pushId] = &fakeRecordOutcome{statement: statement, commit: commit}
	answer := *commit
	return &answer
}

// One sidecar's reach into the world.
type fakeRecordStreamsClient struct {
	world     *FakeRecordStreams
	sidecarId sidecar.Id
}

// Runs a mutating step between its barriers, calling subscribers after the commit with no lock held.
func (self *fakeRecordStreamsClient) mutate(step string, repoId sidecar.Id, commit func() (*sidecar.RecordStreamCommit, error)) (*sidecar.RecordStreamCommit, error) {
	self.world.hit("record_streams."+step+".before", repoId)
	var answer *sidecar.RecordStreamCommit
	var err error
	var callbacks []func(repoId sidecar.Id)
	func() {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		answer, err = commit()
		if err == nil {
			callbacks = self.world.subscribersWithLock(repoId)
		}
	}()
	for _, callback := range callbacks {
		callback(repoId)
	}
	self.world.hit("record_streams."+step+".after", repoId)
	return answer, err
}

// Runs a read under the lock, after its barrier.
func (self *fakeRecordStreamsClient) read(step string, repoId sidecar.Id, read func(repo *fakeRecordRepo, scope RecordStreamsScope) error) error {
	self.world.hit("record_streams."+step, repoId)
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	repo, ok := self.world.repos[repoId]
	if !ok {
		return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	}
	return read(repo, repo.scopes[self.sidecarId])
}

func (self *fakeRecordStreamsClient) Append(ctx context.Context, repoId sidecar.Id, push *sidecar.RecordStreamPush) (*sidecar.RecordStreamCommit, error) {
	return self.mutate("append", repoId, func() (*sidecar.RecordStreamCommit, error) {
		repo, ok := self.world.repos[repoId]
		if !ok {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		if push == nil {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		parts := [][]byte{[]byte("append"), push.WriterSidecarId[:], push.SlotId[:], fakeRecordPinBytes(push.AuthPin)}
		for _, row := range push.SlotRows {
			parts = append(parts, binary.BigEndian.AppendUint32(nil, row.KeyIndex), row.Row)
		}
		for _, entry := range push.Entries {
			parts = append(parts, []byte(entry.Path), entry.Entry)
		}
		statement := fakeRecordStatement(parts...)
		if commit, err, ok := repo.retryAnswerWithLock(push.PushId, statement); ok {
			return commit, err
		}
		if !repo.scopes[self.sidecarId].Write {
			return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		if push.WriterSidecarId != self.sidecarId {
			return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
		}
		if repo.gateClosed {
			return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
		}
		if len(push.Entries) == 0 || self.world.settings.SlotRowCount < len(push.SlotRows) {
			return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		for i, row := range push.SlotRows {
			if 0 < i && row.KeyIndex <= push.SlotRows[i-1].KeyIndex {
				return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			}
		}
		if _, held := repo.slots[push.SlotId]; held {
			self.world.violateWithLock(fmt.Sprintf("push %s reuses slot %s another push holds", push.PushId, push.SlotId))
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
		}
		stream := repo.streams[self.sidecarId]
		if stream == nil {
			refId := FakeRecordStreamRefId(repoId, self.sidecarId)
			stream = &fakeRecordStream{paths: map[string]bool{}, refId: refId, chain: sidecar.EvsChainStart(repoId, refId)}
		}
		created := map[string]bool{}
		for _, entry := range push.Entries {
			if entry.Path == "" || stream.paths[entry.Path] || created[entry.Path] {
				// creates only (§11.8's refs table)
				return nil, repo.refuseWithLock(push.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
			}
			created[entry.Path] = true
		}
		repo.streams[self.sidecarId] = stream
		stream.version += 1
		stream.chain = sidecar.EvsChainNext(stream.chain, push.PushId, statement)
		commit := &sidecar.RecordStreamCommit{Version: stream.version, TimeMillis: self.world.clock.Now().UnixMilli()}
		version := &sidecar.RecordStreamVersion{
			Version:    commit.Version,
			PushId:     push.PushId,
			TimeMillis: commit.TimeMillis,
			AuthPin:    fakeRecordClonePin(push.AuthPin),
			SlotId:     push.SlotId,
			Chain:      bytes.Clone(stream.chain[:]),
		}
		for _, entry := range push.Entries {
			stream.paths[entry.Path] = true
			version.Entries = append(version.Entries, &sidecar.RecordStreamEntry{Path: entry.Path, Entry: bytes.Clone(entry.Entry)})
		}
		stream.versions = append(stream.versions, version)
		rows := map[uint32][]byte{}
		for _, row := range push.SlotRows {
			rows[row.KeyIndex] = bytes.Clone(row.Row)
		}
		repo.slots[push.SlotId] = rows
		repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefStream, SidecarId: self.sidecarId})
		return repo.commitWithLock(push.PushId, statement, commit), nil
	})
}

func (self *fakeRecordStreamsClient) Streams(ctx context.Context, repoId sidecar.Id) ([]*sidecar.RecordStreamHead, error) {
	heads := []*sidecar.RecordStreamHead{}
	err := self.read("streams", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Read {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		for writerId, stream := range repo.streams {
			heads = append(heads, &sidecar.RecordStreamHead{SidecarId: writerId, Version: stream.version, RefId: stream.refId})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(heads, func(a, b *sidecar.RecordStreamHead) int { return bytes.Compare(a.SidecarId[:], b.SidecarId[:]) })
	return heads, nil
}

func (self *fakeRecordStreamsClient) ReadStream(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) ([]*sidecar.RecordStreamVersion, error) {
	versions := []*sidecar.RecordStreamVersion{}
	err := self.read("read_stream", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Read {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		stream := repo.streams[writerSidecarId]
		if stream == nil {
			return nil
		}
		for _, version := range stream.versions {
			if version.Version <= afterVersion {
				continue
			}
			copied := &sidecar.RecordStreamVersion{
				Version:    version.Version,
				PushId:     version.PushId,
				TimeMillis: version.TimeMillis,
				AuthPin:    fakeRecordClonePin(version.AuthPin),
				SlotId:     version.SlotId,
				Chain:      bytes.Clone(version.Chain),
			}
			for _, entry := range version.Entries {
				copied.Entries = append(copied.Entries, &sidecar.RecordStreamEntry{Path: entry.Path, Entry: bytes.Clone(entry.Entry)})
			}
			versions = append(versions, copied)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

func (self *fakeRecordStreamsClient) ReadSlot(ctx context.Context, repoId sidecar.Id, slotId sidecar.Id) (*sidecar.RecordSlot, error) {
	slot := &sidecar.RecordSlot{SlotId: slotId}
	err := self.read("read_slot", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Read {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		rows, ok := repo.slots[slotId]
		if !ok {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		for keyIndex, row := range rows {
			slot.Rows = append(slot.Rows, &sidecar.RecordSlotRow{KeyIndex: keyIndex, Row: bytes.Clone(row)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(slot.Rows, func(a, b *sidecar.RecordSlotRow) int { return cmp.Compare(a.KeyIndex, b.KeyIndex) })
	return slot, nil
}

func (self *fakeRecordStreamsClient) Deposit(ctx context.Context, repoId sidecar.Id, deposit *sidecar.RecordStreamDeposit) (*sidecar.RecordStreamCommit, error) {
	return self.mutate("deposit", repoId, func() (*sidecar.RecordStreamCommit, error) {
		repo, ok := self.world.repos[repoId]
		if !ok {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		if deposit == nil {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		statement := fakeRecordStatement(
			[]byte("deposit"), deposit.DepositorSidecarId[:], deposit.DepositId[:], deposit.Batch,
			fakeRecordPinBytes(deposit.AuthPin),
		)
		if commit, err, ok := repo.retryAnswerWithLock(deposit.PushId, statement); ok {
			return commit, err
		}
		scope := repo.scopes[self.sidecarId]
		if !scope.Deposit {
			return nil, repo.refuseWithLock(deposit.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		if deposit.DepositorSidecarId != self.sidecarId {
			return nil, repo.refuseWithLock(deposit.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
		}
		if repo.gateClosed {
			return nil, repo.refuseWithLock(deposit.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
		}
		if len(deposit.Batch) == 0 {
			return nil, repo.refuseWithLock(deposit.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		now := self.world.clock.Now()
		receiptDay := fakeRecordReceiptDay{depositorId: self.sidecarId, day: now.UTC().Format(time.DateOnly)}
		if scope.ReceiptOnly {
			// §11.12's receipt budget: 429, which refuses nothing and records nothing
			if self.world.settings.ReceiptByteCount < len(deposit.Batch) || self.world.settings.ReceiptDayCount <= repo.receiptCounts[receiptDay] {
				return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
			}
		}
		ref := repo.deposits[self.sidecarId]
		if ref == nil {
			ref = &fakeRecordDepositRef{depositIds: map[sidecar.Id]bool{}}
			repo.deposits[self.sidecarId] = ref
		}
		if ref.depositIds[deposit.DepositId] {
			// creates only (§11.8's refs table)
			return nil, repo.refuseWithLock(deposit.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
		}
		ref.depositIds[deposit.DepositId] = true
		ref.version += 1
		if scope.ReceiptOnly {
			repo.receiptCounts[receiptDay] += 1
		}
		commit := &sidecar.RecordStreamCommit{Version: ref.version, TimeMillis: now.UnixMilli()}
		ref.deposits = append(ref.deposits, &sidecar.RecordStreamDepositVersion{
			Version:    commit.Version,
			PushId:     deposit.PushId,
			TimeMillis: commit.TimeMillis,
			AuthPin:    fakeRecordClonePin(deposit.AuthPin),
			DepositId:  deposit.DepositId,
			Batch:      bytes.Clone(deposit.Batch),
		})
		repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefDeposit, SidecarId: self.sidecarId})
		return repo.commitWithLock(deposit.PushId, statement, commit), nil
	})
}

func (self *fakeRecordStreamsClient) DepositRefs(ctx context.Context, repoId sidecar.Id) ([]*sidecar.RecordStreamHead, error) {
	heads := []*sidecar.RecordStreamHead{}
	err := self.read("deposit_refs", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Write {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		for depositorId, ref := range repo.deposits {
			heads = append(heads, &sidecar.RecordStreamHead{SidecarId: depositorId, Version: ref.version})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(heads, func(a, b *sidecar.RecordStreamHead) int { return bytes.Compare(a.SidecarId[:], b.SidecarId[:]) })
	return heads, nil
}

func (self *fakeRecordStreamsClient) ReadDeposits(ctx context.Context, repoId sidecar.Id, depositorSidecarId sidecar.Id) ([]*sidecar.RecordStreamDepositVersion, error) {
	deposits := []*sidecar.RecordStreamDepositVersion{}
	err := self.read("read_deposits", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Write {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		ref := repo.deposits[depositorSidecarId]
		if ref == nil {
			return nil
		}
		for _, deposit := range ref.deposits {
			copied := *deposit
			copied.AuthPin = fakeRecordClonePin(deposit.AuthPin)
			copied.Batch = bytes.Clone(deposit.Batch)
			deposits = append(deposits, &copied)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return deposits, nil
}

func (self *fakeRecordStreamsClient) Consume(ctx context.Context, repoId sidecar.Id, consume *sidecar.RecordStreamConsume) (*sidecar.RecordStreamCommit, error) {
	return self.mutate("consume", repoId, func() (*sidecar.RecordStreamCommit, error) {
		repo, ok := self.world.repos[repoId]
		if !ok {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		if consume == nil {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		parts := [][]byte{[]byte("consume"), consume.DepositorSidecarId[:]}
		for _, depositId := range consume.DepositIds {
			parts = append(parts, depositId[:])
		}
		statement := fakeRecordStatement(parts...)
		if commit, err, ok := repo.retryAnswerWithLock(consume.PushId, statement); ok {
			return commit, err
		}
		if !repo.scopes[self.sidecarId].Write {
			return nil, repo.refuseWithLock(consume.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		if len(consume.DepositIds) == 0 {
			return nil, repo.refuseWithLock(consume.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		ref := repo.deposits[consume.DepositorSidecarId]
		if ref == nil {
			return nil, repo.refuseWithLock(consume.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
		}
		for _, depositId := range consume.DepositIds {
			held := slices.ContainsFunc(ref.deposits, func(deposit *sidecar.RecordStreamDepositVersion) bool {
				return deposit.DepositId == depositId
			})
			if !held {
				return nil, repo.refuseWithLock(consume.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
			}
		}
		ref.deposits = slices.DeleteFunc(ref.deposits, func(deposit *sidecar.RecordStreamDepositVersion) bool {
			return slices.Contains(consume.DepositIds, deposit.DepositId)
		})
		ref.version += 1
		commit := &sidecar.RecordStreamCommit{Version: ref.version, TimeMillis: self.world.clock.Now().UnixMilli()}
		repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefDeposit, SidecarId: consume.DepositorSidecarId})
		return repo.commitWithLock(consume.PushId, statement, commit), nil
	})
}

func (self *fakeRecordStreamsClient) Erase(ctx context.Context, repoId sidecar.Id, erase *sidecar.RecordStreamErase) (*sidecar.RecordStreamCommit, error) {
	return self.mutate("erase", repoId, func() (*sidecar.RecordStreamCommit, error) {
		repo, ok := self.world.repos[repoId]
		if !ok {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		if erase == nil {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		parts := [][]byte{[]byte("erase"), erase.SealedNote}
		for _, key := range erase.Keys {
			parts = append(parts, key.SlotId[:], binary.BigEndian.AppendUint32(nil, key.KeyIndex))
		}
		statement := fakeRecordStatement(parts...)
		if commit, err, ok := repo.retryAnswerWithLock(erase.PushId, statement); ok {
			return commit, err
		}
		if !repo.scopes[self.sidecarId].Admin {
			return nil, repo.refuseWithLock(erase.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		if len(erase.Keys) == 0 {
			return nil, repo.refuseWithLock(erase.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		heldCount := 0
		for _, key := range erase.Keys {
			if _, held := repo.slots[key.SlotId][key.KeyIndex]; held {
				heldCount += 1
			}
		}
		if heldCount == 0 {
			return nil, repo.refuseWithLock(erase.PushId, statement, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE)
		}
		erasure := &sidecar.RecordStreamErasure{
			Version:         uint64(len(repo.erasures) + 1),
			PushId:          erase.PushId,
			TimeMillis:      self.world.clock.Now().UnixMilli(),
			EraserSidecarId: self.sidecarId,
			SealedNote:      bytes.Clone(erase.SealedNote),
		}
		for _, key := range erase.Keys {
			delete(repo.slots[key.SlotId], key.KeyIndex)
			erasure.Keys = append(erasure.Keys, &sidecar.RecordSlotKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
		}
		repo.erasures = append(repo.erasures, erasure)
		commit := &sidecar.RecordStreamCommit{Version: erasure.Version, TimeMillis: erasure.TimeMillis}
		repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefErasure})
		return repo.commitWithLock(erase.PushId, statement, commit), nil
	})
}

func (self *fakeRecordStreamsClient) ReadErasures(ctx context.Context, repoId sidecar.Id, afterVersion uint64) ([]*sidecar.RecordStreamErasure, error) {
	erasures := []*sidecar.RecordStreamErasure{}
	err := self.read("read_erasures", repoId, func(repo *fakeRecordRepo, scope RecordStreamsScope) error {
		if !scope.Read {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		for _, erasure := range repo.erasures {
			if erasure.Version <= afterVersion {
				continue
			}
			copied := *erasure
			copied.SealedNote = bytes.Clone(erasure.SealedNote)
			copied.Keys = nil
			for _, key := range erasure.Keys {
				copied.Keys = append(copied.Keys, &sidecar.RecordSlotKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
			}
			erasures = append(erasures, &copied)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return erasures, nil
}

func (self *fakeRecordStreamsClient) Subscribe(repoId sidecar.Id, callback func(repoId sidecar.Id)) func() {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	self.world.nextSubId += 1
	subscriberId := self.world.nextSubId
	if self.world.subscribers[repoId] == nil {
		self.world.subscribers[repoId] = map[uint64]func(repoId sidecar.Id){}
	}
	self.world.subscribers[repoId][subscriberId] = callback
	return func() {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		delete(self.world.subscribers[repoId], subscriberId)
	}
}
