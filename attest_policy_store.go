//go:build !ios_extension && !sidecar_http

// The device's compute policy (DESIGN-COMPUTE §5.4, IC-9): the newest verified policy and the highest version anything
// verified has named, kept in the sidecar's own sealed store (§5.9's attest class), so both survive a restart. Every
// reader of the policy reads it here: CTRUST's disclosure registry, INFER's router, SRCH's search line, CONN's
// services line and ENC's profiles; and ATTEST-M12-01's gate and fetcher feed it.
//
//   - Only higher: Offer takes a verified policy only when its version is above the newest held, and never one older
//     than the release's copy, which is the floor a fresh install starts from. An equal version with other bytes is
//     refused as a conflict, since one version has one document.
//   - Persisted first: a newer policy is taken only once its state file has committed, so a crash leaves the old
//     state or the new and a policy is never held that a restart would forget. The highest version seen rises in
//     memory even when its write fails, which only stops more.
//   - Past not_after: the newest policy stays the newest, and answers not current (ComputePolicy.Current); the gate
//     decides what that stops (ATTEST-M12-01).
//   - Before enrollment, or while the keychain is locked, the store's file cannot be read: the release's copy serves
//     alone, nothing new is taken, and the file is read at the first call that can.
//   - The gate's state lives here too (ATTEST-M12-01), in the same file so one commit moves it whole: the newest
//     current ticket taken, and the clock's floor, the instant now never reads earlier than (attest_gate.go).
//
// The state file is reverified as it is read, the policy and the ticket each at the instant it was first taken, so a
// build whose format or pins changed drops what it no longer takes rather than trusting it. Safe for concurrent use: writeLock serializes every
// read and write of the file and is held across that I/O, stateLock guards the snapshot readers take, never across
// I/O, and writeLock is always taken first.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// The component's directory, its file class (§5.9) and its state file.
const (
	computePolicyStoreDirectory = "attest"
	computePolicyStoreClass     = "attest"
	computePolicyStateName      = "policy.state"
	computePolicyStateFormat    = 1
)

// An offered policy that verifies but is older than the newest held.
var ErrComputePolicyStale = errors.New("compute policy older than the newest held")

// An offered policy of the newest held version with other bytes: one version has one document.
var ErrComputePolicyConflict = errors.New("compute policy conflicts with the one held at its version")

// What NewComputePolicyStore builds on.
type ComputePolicyStoreArgs struct {
	// The component's sealed directory. Required.
	Store SidecarStore
	// Required.
	Verifier *ComputePolicyVerifier
	// Required.
	Settings *AttestSettings
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger

	// The release's copy a test stands in, where releaseGiven is set; else the embedded one.
	releaseDocument  []byte
	releaseSignature []byte
	releaseGiven     bool
}

// The state file's content.
type computePolicyStateFile struct {
	Format int `json:"format"`
	// The newest policy taken, and its signature.
	Document  []byte `json:"document,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	// When this device first took it, unix milliseconds.
	AcceptedMs int64 `json:"accepted_ms,omitempty"`
	// The highest version anything verified has named.
	HighestSeen uint64 `json:"highest_seen"`
	// The newest current ticket taken, its file, and when it was taken, unix milliseconds.
	Ticket           []byte `json:"ticket,omitempty"`
	TicketAcceptedMs int64  `json:"ticket_accepted_ms,omitempty"`
	// The instant now never reads earlier than, unix milliseconds.
	ClockFloorMs int64 `json:"clock_floor_ms,omitempty"`
}

// What readers see.
type computePolicyState struct {
	newest *ComputePolicy
	// When this device first took newest, unix milliseconds: for the release's copy, when this process verified it.
	acceptedMs  int64
	highestSeen uint64
	// The newest current ticket taken, or nil, and when it was taken.
	ticket           *ComputePolicyTicket
	ticketAcceptedMs int64
	// The instant now never reads earlier than; zero for none.
	clockFloor time.Time
}

// The newest verified compute policy and the highest version seen, persisted.
type ComputePolicyStore struct {
	store    SidecarStore
	verifier *ComputePolicyVerifier
	settings *AttestSettings
	clock    Clock
	log      Logger
	// The release's copy, verified, or nil.
	release *ComputePolicy

	// Serializes the file's reads and writes, held across their I/O.
	writeLock sync.Mutex
	// Whether the file has been read; guarded by writeLock.
	loaded bool

	stateLock sync.Mutex
	state     computePolicyState
	// What the file holds of the two that rise in memory before they are written, so a rise memory holds and the
	// file does not, its write having failed, is written again at the next call that names it.
	persistedHighestSeen uint64
	persistedClockFloor  time.Time
}

// A store over args, holding the release's copy at once and the file from the first call that can read it.
func NewComputePolicyStore(args *ComputePolicyStoreArgs) (*ComputePolicyStore, error) {
	if args == nil || args.Store == nil || args.Verifier == nil || args.Settings == nil {
		return nil, errors.New("compute policy store: a store, a verifier and settings")
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	self := &ComputePolicyStore{
		store:    args.Store,
		verifier: args.Verifier,
		settings: args.Settings,
		clock:    clock,
		log:      log,
	}
	document, signature := args.releaseDocument, args.releaseSignature
	if !args.releaseGiven {
		var err error
		document, signature, err = computePolicyReleaseCopy()
		if err != nil {
			self.log.Errorf("[attest]the release's copy of the compute policy is unreadable: %s", err)
		}
	}
	now := self.clock.Now()
	if document != nil {
		release, err := self.verifier.Verify(document, signature, now)
		if err != nil {
			self.log.Errorf("[attest]the release's copy of the compute policy is refused: %s", err)
		} else {
			self.release = release
			self.state = computePolicyState{newest: release, acceptedMs: now.UnixMilli(), highestSeen: release.Version}
		}
	}
	self.tryLoad()
	return self, nil
}

// The newest verified policy, or nil where the device holds none: no release's copy and nothing fetched. It may be
// past its not_after; the gate reads that.
func (self *ComputePolicyStore) Newest() *ComputePolicy {
	self.tryLoad()
	return self.snapshot().newest
}

// The highest policy version anything verified has named, a policy or a ticket; 0 where nothing has.
func (self *ComputePolicyStore) HighestSeen() uint64 {
	self.tryLoad()
	return self.snapshot().highestSeen
}

// The release's copy, verified, or nil where this build carries none it takes.
func (self *ComputePolicyStore) Release() *ComputePolicy {
	return self.release
}

// Verifies document and its detached signature, and takes the policy when it is newer than the newest held, once its
// state has committed. Returns the policy taken, or the newest held where the offer is that same document. Refusals:
// what the verifier refuses (ErrComputePolicyRefused), ErrComputePolicyStale for an older version,
// ErrComputePolicyConflict for the held version with other bytes, and the store's error while its file cannot be
// read or written, which takes nothing.
func (self *ComputePolicyStore) Offer(document []byte, signature []byte) (*ComputePolicy, error) {
	now := self.now()
	policy, err := self.verifier.Verify(document, signature, now)
	if err != nil {
		return nil, err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil {
		// what it names still counts, in memory, which only stops more
		self.raiseHighestSeen(policy.Version)
		return nil, err
	}
	state := self.snapshot()
	if state.newest != nil {
		switch {
		case policy.Version < state.newest.Version:
			return nil, fmt.Errorf("%w: version %d, holding %d", ErrComputePolicyStale, policy.Version, state.newest.Version)
		case policy.Version == state.newest.Version:
			if bytes.Equal(policy.document, state.newest.document) {
				return state.newest, nil
			}
			return nil, fmt.Errorf("%w: version %d", ErrComputePolicyConflict, policy.Version)
		}
	}
	next := state
	next.newest = policy
	next.acceptedMs = now.UnixMilli()
	next.highestSeen = max(state.highestSeen, policy.Version)
	versionKey := strconv.FormatUint(policy.Version, 10)
	testHookBarrier("attest_policy_store.commit.before", versionKey)
	if err := self.writeStateWithWriteLock(next); err != nil {
		self.raiseHighestSeen(policy.Version)
		return nil, err
	}
	self.setState(next)
	testHookBarrier("attest_policy_store.commit.after", versionKey)
	return policy, nil
}

// Records that something verified named version, persisting it where it rises. The rise holds in memory even when
// the write fails, whose error is returned: a device that cannot record a newer version still does no remote work
// under an older one.
func (self *ComputePolicyStore) noteVersionSeen(version uint64) error {
	if persistedHighestSeen, _ := self.persisted(); version <= persistedHighestSeen {
		return nil
	}
	self.raiseHighestSeen(version)
	versionKey := strconv.FormatUint(version, 10)
	testHookBarrier("attest_policy_store.seen.raised", versionKey)
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil {
		return err
	}
	state := self.snapshot()
	// a commit that read the state before the rise above may have written it back without it
	state.highestSeen = max(state.highestSeen, version)
	testHookBarrier("attest_policy_store.seen.before", versionKey)
	if err := self.writeStateWithWriteLock(state); err != nil {
		return err
	}
	self.setState(state)
	testHookBarrier("attest_policy_store.seen.after", versionKey)
	return nil
}

// The newest policy and when this device first took it, unix milliseconds.
func (self *ComputePolicyStore) newestAccepted() (*ComputePolicy, int64) {
	self.tryLoad()
	state := self.snapshot()
	return state.newest, state.acceptedMs
}

// The time and one snapshot the gate judges by, so the policy, the version seen and the ticket it reads agree.
func (self *ComputePolicyStore) judged() (time.Time, computePolicyState) {
	self.tryLoad()
	state := self.snapshot()
	now := self.clock.Now()
	if now.Before(state.clockFloor) {
		now = state.clockFloor
	}
	return now, state
}

// The time the store and the gate judge at: the device's clock, but never earlier than the clock's floor (§5.4's
// clock rule, attest_gate.go).
func (self *ComputePolicyStore) now() time.Time {
	self.tryLoad()
	now := self.clock.Now()
	if floor := self.snapshot().clockFloor; now.Before(floor) {
		return floor
	}
	return now
}

// The newest current ticket taken, or nil. It may have lapsed since; the gate judges that.
func (self *ComputePolicyStore) heldTicket() *ComputePolicyTicket {
	self.tryLoad()
	return self.snapshot().ticket
}

// Takes ticket, verified and current, where it is newer than the one held, raising the clock's floor to its start and
// the highest version seen to what it names, in one commit; returns the ticket held after. An older one changes
// nothing. The store's error, while its file cannot be written, takes nothing but what memory holds of the version
// and the floor, which only stop more.
func (self *ComputePolicyStore) keepTicket(ticket *ComputePolicyTicket) (*ComputePolicyTicket, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil {
		self.raiseHighestSeen(ticket.PolicyVersion)
		self.raiseClockFloorInMemory(ticket.NotBefore)
		return nil, err
	}
	state := self.snapshot()
	if state.ticket != nil && !ticket.newerThan(state.ticket) {
		return state.ticket, nil
	}
	next := state
	next.ticket = ticket
	next.ticketAcceptedMs = self.clock.Now().UnixMilli()
	next.highestSeen = max(next.highestSeen, ticket.PolicyVersion)
	if next.clockFloor.Before(ticket.NotBefore) {
		next.clockFloor = ticket.NotBefore
	}
	startKey := strconv.FormatInt(ticket.NotBefore.UnixMilli(), 10)
	testHookBarrier("attest_policy_store.ticket.before", startKey)
	if err := self.writeStateWithWriteLock(next); err != nil {
		self.raiseHighestSeen(ticket.PolicyVersion)
		self.raiseClockFloorInMemory(ticket.NotBefore)
		return nil, err
	}
	self.setState(next)
	testHookBarrier("attest_policy_store.ticket.after", startKey)
	return ticket, nil
}

// Raises the clock's floor to floor, persisting it where it rises; in memory even when the write fails, whose error
// is returned.
func (self *ComputePolicyStore) raiseClockFloor(floor time.Time) error {
	if _, persistedClockFloor := self.persisted(); !persistedClockFloor.Before(floor) {
		return nil
	}
	self.raiseClockFloorInMemory(floor)
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil {
		return err
	}
	state := self.snapshot()
	// as noteVersionSeen: a commit that read the state before the rise may have written it back without it
	if state.clockFloor.Before(floor) {
		state.clockFloor = floor
	}
	if err := self.writeStateWithWriteLock(state); err != nil {
		return err
	}
	self.setState(state)
	return nil
}

// Raises the clock's floor in memory alone.
func (self *ComputePolicyStore) raiseClockFloorInMemory(floor time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.clockFloor.Before(floor) {
		self.state.clockFloor = floor
	}
}

// A copy of the state.
func (self *ComputePolicyStore) snapshot() computePolicyState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

// Replaces the state with one a commit wrote, keeping the highest version seen and the clock's floor no lower than
// memory holds: those rise in memory before their writer takes writeLock, so a commit that read the state before a
// rise must not take it back. The writer of the rise writes it once it holds writeLock.
func (self *ComputePolicyStore) setState(state computePolicyState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state.highestSeen = max(state.highestSeen, self.state.highestSeen)
	if state.clockFloor.Before(self.state.clockFloor) {
		state.clockFloor = self.state.clockFloor
	}
	self.state = state
}

// What the file holds of the highest version seen and the clock's floor, as far as this store has read or written it.
func (self *ComputePolicyStore) persisted() (uint64, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.persistedHighestSeen, self.persistedClockFloor
}

// Raises the highest version seen in memory alone.
func (self *ComputePolicyStore) raiseHighestSeen(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state.highestSeen = max(self.state.highestSeen, version)
}

// Reads the file where it has not been read and no other call holds the file: a reader never waits on a write.
func (self *ComputePolicyStore) tryLoad() {
	if !self.writeLock.TryLock() {
		return
	}
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil && !errors.Is(err, ErrSidecarStoreLocked) {
		self.log.Warningf("[attest]the compute policy's state is unreadable: %s", err)
	}
}

// Reads the file once: the policy it holds, reverified at the instant it was taken, merged with the release's copy,
// the higher version newest; the highest seen the most of the file's, memory's and the newest's.
func (self *ComputePolicyStore) loadWithWriteLock() error {
	if self.loaded {
		return nil
	}
	data, err := computePolicyReadStoreFile(self.store, computePolicyStateName, self.settings.StateMaxByteCount)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		self.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	file, err := decodeComputePolicyStateFile(data)
	if err != nil {
		// unreadable by this build: start from the release's copy, which drops what it named
		self.log.Errorf("[attest]the compute policy's state does not decode, and is dropped: %s", err)
		self.loaded = true
		return nil
	}
	var persisted *ComputePolicy
	if file.Document != nil {
		persisted, err = self.verifier.Verify(file.Document, file.Signature, time.UnixMilli(file.AcceptedMs))
		if err != nil {
			self.log.Errorf("[attest]the compute policy held is refused by this build, and is dropped: %s", err)
			persisted = nil
		}
	}
	var ticket *ComputePolicyTicket
	if file.Ticket != nil {
		ticket, err = self.verifier.VerifyTicket(file.Ticket, time.UnixMilli(file.TicketAcceptedMs))
		if err != nil {
			self.log.Errorf("[attest]the freshness ticket held is refused by this build, and is dropped: %s", err)
			ticket = nil
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if persisted != nil && (self.state.newest == nil || self.state.newest.Version < persisted.Version) {
		self.state.newest = persisted
		self.state.acceptedMs = file.AcceptedMs
	}
	self.state.highestSeen = max(self.state.highestSeen, file.HighestSeen)
	if self.state.newest != nil {
		self.state.highestSeen = max(self.state.highestSeen, self.state.newest.Version)
	}
	if ticket != nil && (self.state.ticket == nil || ticket.newerThan(self.state.ticket)) {
		self.state.ticket = ticket
		self.state.ticketAcceptedMs = file.TicketAcceptedMs
		self.state.highestSeen = max(self.state.highestSeen, ticket.PolicyVersion)
	}
	if floor := time.UnixMilli(file.ClockFloorMs).UTC(); 0 < file.ClockFloorMs && self.state.clockFloor.Before(floor) {
		self.state.clockFloor = floor
	}
	self.persistedHighestSeen = file.HighestSeen
	if 0 < file.ClockFloorMs {
		self.persistedClockFloor = time.UnixMilli(file.ClockFloorMs).UTC()
	}
	self.loaded = true
	return nil
}

// Commits state as the file, whole.
func (self *ComputePolicyStore) writeStateWithWriteLock(state computePolicyState) error {
	file := &computePolicyStateFile{
		Format:      computePolicyStateFormat,
		HighestSeen: state.highestSeen,
	}
	if state.newest != nil {
		file.Document = state.newest.document
		file.Signature = state.newest.signature
		file.AcceptedMs = state.acceptedMs
	}
	if state.ticket != nil {
		file.Ticket = state.ticket.file
		file.TicketAcceptedMs = state.ticketAcceptedMs
	}
	if !state.clockFloor.IsZero() {
		file.ClockFloorMs = state.clockFloor.UnixMilli()
	}
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := computePolicyWriteStoreFile(self.store, computePolicyStateName, data); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.persistedHighestSeen = state.highestSeen
	self.persistedClockFloor = state.clockFloor
	return nil
}

// The state file's content, exactly one document of this format, or an error.
func decodeComputePolicyStateFile(data []byte) (*computePolicyStateFile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	file := &computePolicyStateFile{}
	if err := decoder.Decode(file); err != nil {
		return nil, errors.New("not a state file")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("bytes after the state")
	}
	if file.Format != computePolicyStateFormat || (file.Document == nil) != (file.Signature == nil) {
		return nil, errors.New("not this format's state")
	}
	return file, nil
}

// The whole of name, at most maxByteCount bytes, read to its end so every chunk is authenticated.
func computePolicyReadStoreFile(store SidecarStore, name string, maxByteCount int) ([]byte, error) {
	reader, err := store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < len(data) {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxByteCount)
	}
	return data, nil
}

// Replaces name with data, durably, whole or not at all.
func computePolicyWriteStoreFile(store SidecarStore, name string, data []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}
