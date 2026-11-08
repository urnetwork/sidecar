// §6.4's stops and alarms rows and D-TRUST-10, held for one network by one HeadStopState: the head check
// state reconcile runs on (rpc_headcheck_state.go), the forks reported to it, witnessed_at
// (rpc_headcheck_witness.go), and the revocations this device signed that no peer has yet been seen to
// hold (rpc_headcheck_revoker.go). The Sidecar builds it and passes it in. The transport (PROTO-M2-03)
// runs every HeadCheck step through it, and ConfigLog's forks and KEYS's and EVS1's pin refusals reach it
// through ReportFork, so a fork found anywhere is this one stop.
//
// What stops sealing new content, as SealAllowed answers (§6.4's stops and FORK rows):
//
//   - a fork, at once: in the affected group for a generation, epoch or ref fork, and in every shared
//     group for an auth fork; until the peer that showed it, or the prover a proof's fork names, is
//     revoked or parked, the denial any compromised device can cause. A fork no peer showed, as
//     ConfigLog's own, stays;
//   - proof of withholding, at once, in shared groups, until api serves the withheld entries;
//   - no consistent witness at witness_bound_hours, in shared groups only.
//
// A shared group is one with another member's devices (SharedGroup). Own groups only alarm, so a
// personal network, all of whose groups are its own, never stops for want of a witness, for withholding
// or for an auth fork. A fork in a group's own pins stops that group wherever it is, as §6.4's FORK row
// says of the affected repo.
//
// Alarms (§6.4's alarms row) go to Alarm as head_alarm events, with kind fork, withheld, unverified or
// unwitnessed, both pins as Evidence encoded as §6.5 does, and the peer's sidecar_id where one showed it.
// Each fact alarms once: the facts persist, so a restart raises nothing again.
//
// Persisted in authlog/ (§5.9) as one sealed file: witnessed_at and the pin it witnessed, the UNVERIFIED
// pins, a withheld tip with the proof this device verified, the fork pin it relays, the forks, and the
// revocations it tracks. Fetches in flight do not persist; the next exchange or round starts them again.
//
// No connect type appears here, so the file builds on every leg. Safe for concurrent use. Nothing is
// called out while stateLock is held: sources are read, alarms raised, rounds requested and the store
// written only after it is released. Engine steps run one at a time under stepLock, which a source must
// therefore never wait on: a source may call ReportFork, never a step.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §6.4's fixed times and ServiceSettings.witness_bound_hours' range (§7.9, D-TRUST-10).
const (
	// The alarm with no consistent witness: a protocol constant fixed by owner decision 129, neither a
	// setting nor per-network config (plan-PROTO-small-readings.md's reading 3).
	HeadCheckUnwitnessedAlarmTimeout = 24 * time.Hour
	// How long a revocation this device signed goes unwitnessed before it alarms (§6.4's revoker row),
	// fixed as the 24 h alarm is.
	HeadCheckRevocationAlarmTimeout = 1 * time.Hour
	// witness_bound_hours' least and greatest values and its default (§7.9's ServiceSettings).
	WitnessBoundMinHours     = 24
	WitnessBoundMaxHours     = 168
	WitnessBoundDefaultHours = 72
)

// authlog/'s file and its format.
const (
	headStopFileName             = "headcheck"
	headStopDocumentVersion      = 1
	headStopDocumentMaxByteCount = 1024 * 1024
)

var (
	// What every HeadStopError wraps.
	ErrHeadStop = errors.New("sealing stopped")
	// A HeadStopStateEnv missing what HeadStopState cannot run without.
	errHeadStopEnv = errors.New("invalid head stop env")
	// authlog/'s file does not decode as this format, which nothing may read as a fresh state: that
	// would drop the stops it held.
	errHeadStopDocument = errors.New("head stop state does not decode")
)

// Why sealing stopped.
type HeadStopCause string

const (
	HeadStopFork        HeadStopCause = "fork"
	HeadStopWithheld    HeadStopCause = "withheld"
	HeadStopUnwitnessed HeadStopCause = "unwitnessed"
)

// What SealAllowed refuses with. It wraps ErrHeadStop.
type HeadStopError struct {
	Cause   HeadStopCause
	GroupId Id
	// When the cause began: the fork's report, the proof's verification, or the last consistent
	// witness, which on a device never witnessed is when this state began.
	Since time.Time
}

// Names the cause, the group and the time, opaque ids only (I-13).
func (self *HeadStopError) Error() string {
	return fmt.Sprintf("%s in group %s: %s since %s", ErrHeadStop, self.GroupId, self.Cause, self.Since.UTC().Format(time.RFC3339))
}

// ErrHeadStop.
func (self *HeadStopError) Unwrap() error {
	return ErrHeadStop
}

// What NewHeadStopState takes. Every field is required.
type HeadStopStateEnv struct {
	// This device and its network.
	SidecarId Id
	NetworkId Id
	// What HeadCheck reads; the auth source's Pin and ChainAt are this device's own pins.
	Sources *HeadCheckSources
	// authlog/, where the state persists (§5.9).
	Store    SidecarStore
	Settings *SidecarProtocolSettings
	Clock    Clock
	Log      Logger
	// ServiceSettings.witness_bound_hours as this device's newest state holds it, and whether it could
	// read the config head that holds it.
	WitnessBoundHours func() (hours uint32, known bool)
	// Whether a group holds another member's devices, which makes it shared (§6.4's stops row).
	SharedGroup func(groupId Id) bool
	// Takes each head_alarm, on whatever goroutine raised it. It must not block, as
	// SidecarEventFunction's rule says.
	Alarm func(event SidecarEvent)
	// Asks the transport for a HeadCheck round now: the revoker's retries. It must not block.
	RequestRound func()
}

// Refuses an env missing a field.
func (self *HeadStopStateEnv) validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: none", errHeadStopEnv)
	case self.Store == nil || self.Settings == nil || self.Clock == nil || self.Log == nil:
		return fmt.Errorf("%w: no store, settings, clock or log", errHeadStopEnv)
	case self.WitnessBoundHours == nil || self.SharedGroup == nil || self.Alarm == nil || self.RequestRound == nil:
		return fmt.Errorf("%w: a function missing", errHeadStopEnv)
	}
	return self.Sources.validate()
}

// One fork that stops sealing.
type headStopFork struct {
	fork HeadFork
	at   time.Time
}

// Whether two forks are one stop: the same kind, group and peer.
func (self *headStopFork) sameStop(fork HeadFork) bool {
	samePeer := (self.fork.PeerId == nil) == (fork.PeerId == nil) && (fork.PeerId == nil || *self.fork.PeerId == *fork.PeerId)
	return self.fork.Kind == fork.Kind && self.fork.GroupId == fork.GroupId && samePeer
}

// Where the run loop last parked: its passes so far, and the change count it had seen when it armed
// its wait. A schedule moves the clock only once the loop has seen every change, so the loop never arms
// a wait from a reading the clock has already moved past.
type headStopLoopMark struct {
	passes uint64
	seen   uint64
}

// One network's stops, alarms and witness state.
type HeadStopState struct {
	ctx    context.Context
	cancel context.CancelFunc
	env    *HeadStopStateEnv
	done   chan struct{}
	// counts the changes that may move a deadline the run loop waits for
	changed  *MonitorValue[uint64]
	loopMark *MonitorValue[headStopLoopMark]

	// held across one engine step, never while waiting on anything but the sources' reads
	stepLock sync.Mutex

	stateLock sync.Mutex
	state     headCheckState
	// zero until the first consistent witness
	witnessedAt time.Time
	witnessPin  *bridge.AuthPin
	// when the unwitnessed clock started on a device never witnessed: this state's first start
	unwitnessedSince   time.Time
	unwitnessedAlarmed bool
	forks              []*headStopFork
	revocations        []*headStopRevocation
	// bumped at each change, so a slower write of an older one never lands over a newer
	version uint64

	persistLock      sync.Mutex
	persistedVersion uint64
}

// Loads the network's state from authlog/, or starts one whose unwitnessed clock starts now, and starts
// its run loop, which raises the 24 h alarm and runs the revoker. A file that does not decode is an
// error, never a fresh state.
func NewHeadStopState(ctx context.Context, env *HeadStopStateEnv) (*HeadStopState, error) {
	if err := env.validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &HeadStopState{
		ctx:      cancelCtx,
		cancel:   cancel,
		env:      env,
		done:     make(chan struct{}),
		changed:  NewMonitorValue[uint64](0),
		loopMark: NewMonitorValue(headStopLoopMark{}),
	}
	fresh, err := self.load()
	if err != nil {
		cancel()
		return nil, err
	}
	if fresh {
		self.unwitnessedSince = env.Clock.Now()
		self.version = 1
		self.persist()
	}
	// the run loop's first pass raises what came due while this device was down and, for each revocation
	// still unwitnessed, asks for the round the revoker owes at each start
	go self.run()
	return self, nil
}

// Stops the run loop and waits for it. A step already running finishes.
func (self *HeadStopState) Close() {
	self.cancel()
	<-self.done
}

// What a step reads of this device now.
func (self *HeadStopState) mine() *headCheckMine {
	return &headCheckMine{
		sidecarId: self.env.SidecarId,
		networkId: self.env.NetworkId,
		sources:   self.env.Sources,
		settings:  self.env.Settings,
		now:       self.env.Clock.Now(),
	}
}

// Whether new content may be sealed in the group now: nil, or a HeadStopError naming the cause. It runs
// where new content is sealed, after GkmClient.EnsureWritable's commits and rotations, so one check
// covers evs_ and record_ (KEYS-M2-22 and EVS1's push path add the call). Rotations, Removes and
// revocations never call it: they only shrink exposure, and owner decision 129 has them never stop.
func (self *HeadStopState) SealAllowed(groupId Id) error {
	testHookBarrier("rpc.seal_stop", groupId.String())
	shared := self.env.SharedGroup(groupId)
	bound := self.witnessBound()
	now := self.env.Clock.Now()

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, fork := range self.forks {
		if (fork.fork.Kind == HeadForkAuth && shared) || (fork.fork.Kind != HeadForkAuth && fork.fork.GroupId == groupId) {
			return &HeadStopError{Cause: HeadStopFork, GroupId: groupId, Since: fork.at}
		}
	}
	if !shared {
		return nil
	}
	if self.state.withheld != nil {
		return &HeadStopError{Cause: HeadStopWithheld, GroupId: groupId, Since: self.state.withheld.since}
	}
	if since := self.lastWitnessWithLock(); !now.Before(since.Add(bound)) {
		return &HeadStopError{Cause: HeadStopUnwitnessed, GroupId: groupId, Since: since}
	}
	return nil
}

// Takes a fork found outside HeadCheck: ConfigLog's ErrConfigFork as an auth fork, KEYS's and EVS1's pin
// refusals as generation, epoch and ref forks. It alarms once and stops sealing at once in what it is
// in, as a fork HeadCheck finds does. A kind this does not know stops as an auth fork, the widest stop.
func (self *HeadStopState) ReportFork(fork HeadFork) {
	if fork.Kind < HeadForkAuth || HeadForkRef < fork.Kind {
		self.env.Log.Warningf("[headcheck] a fork of unknown kind %d stops as an auth fork", fork.Kind)
		fork.Kind = HeadForkAuth
	}
	now := self.env.Clock.Now()
	added := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.addForkWithLock(fork, now) {
			return false
		}
		self.version += 1
		return true
	}()
	if added {
		self.afterChange([]SidecarEvent{headStopForkAlarm(fork)})
	}
}

// Adds fork unless the same stop is held, copying its evidence.
func (self *HeadStopState) addForkWithLock(fork HeadFork, at time.Time) bool {
	for _, held := range self.forks {
		if held.sameStop(fork) {
			return false
		}
	}
	forkCopy := fork
	forkCopy.Local = bytes.Clone(fork.Local)
	forkCopy.Remote = bytes.Clone(fork.Remote)
	if fork.PeerId != nil {
		peerId := *fork.PeerId
		forkCopy.PeerId = &peerId
	}
	self.forks = append(self.forks, &headStopFork{fork: forkCopy, at: at})
	return true
}

// A fork's head_alarm.
func headStopForkAlarm(fork HeadFork) SidecarEvent {
	return headStopAlarm(SidecarHeadAlarmFork, fork.PeerId, fork.Local, fork.Remote)
}

// A head_alarm of kind with its two pins and, when one showed it, the peer.
func headStopAlarm(kind SidecarHeadAlarm, peerId *Id, local []byte, remote []byte) SidecarEvent {
	event := SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: kind, Evidence: [2][]byte{bytes.Clone(local), bytes.Clone(remote)}}
	if peerId != nil {
		peerIdCopy := *peerId
		event.SidecarId = &peerIdCopy
	}
	return event
}

// Runs one engine step: the transition on a snapshot of the state, with no stateLock held while it
// reads the sources, then commits what it returns, with the step's forks, withheld tip and new
// UNVERIFIED pins, and after unlocking persists and alarms.
func (self *HeadStopState) step(transition func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error)) (headCheckStep, error) {
	self.stepLock.Lock()
	defer self.stepLock.Unlock()
	mine := self.mine()
	state := func() headCheckState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.state
	}()
	next, step, err := transition(state, mine)
	if err != nil {
		return headCheckStep{}, err
	}
	var myPinBytes []byte
	if myPin := self.env.Sources.Auth.Pin(); myPin != nil {
		myPinBytes = headCheckEvidence(myPin)
	}
	alarms := func() []SidecarEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := self.state
		self.state = next
		alarms := []SidecarEvent{}
		for _, fork := range step.forks {
			if self.addForkWithLock(fork, mine.now) {
				alarms = append(alarms, headStopForkAlarm(fork))
			}
		}
		if withheld := step.withheld; withheld != nil && (previous.withheld == nil || !headCheckPinEqual(previous.withheld.pin, withheld.pin)) {
			alarms = append(alarms, headStopAlarm(SidecarHeadAlarmWithheld, &withheld.peerId, myPinBytes, headCheckEvidence(withheld.pin)))
		}
		for _, held := range step.unverified {
			peerId := held.peerId()
			alarms = append(alarms, headStopAlarm(SidecarHeadAlarmUnverified, &peerId, myPinBytes, headCheckEvidence(held.pin)))
		}
		self.version += 1
		return alarms
	}()
	self.afterChange(alarms)
	return step, nil
}

// Reconciles a peer's HeadCheck or HeadCheckResult (headCheckReconcile).
func (self *HeadStopState) reconcile(peerId Id, message headCheckMessage) (headCheckStep, error) {
	return self.step(func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error) {
		return headCheckReconcile(state, mine, peerId, message)
	})
}

// Judges the fetches once FetchAuth has returned or its deadline passed (headCheckFetched).
func (self *HeadStopState) fetched() headCheckStep {
	step, _ := self.step(func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error) {
		next, step := headCheckFetched(state, mine)
		return next, step, nil
	})
	return step
}

// Takes what a proof request for pin came to (headCheckProved).
func (self *HeadStopState) proved(pin *bridge.AuthPin, proverId Id, proof [][]byte, verified bool) headCheckStep {
	step, _ := self.step(func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error) {
		next, step := headCheckProved(state, mine, pin, proverId, proof, verified)
		return next, step, nil
	})
	return step
}

// Takes what a forward read came to (headCheckCaughtUp).
func (self *HeadStopState) caughtUp(act headCheckAct, outcome HeadCheckCatchUp) headCheckStep {
	step, _ := self.step(func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error) {
		return state, headCheckCaughtUp(mine, act, outcome), nil
	})
	return step
}

// Each HeadCheckInterval and at each start (headCheckRound), and drops the forks whose peer is now
// revoked or parked.
func (self *HeadStopState) round() headCheckStep {
	step, _ := self.step(func(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep, error) {
		next, step := headCheckRound(state, mine)
		return next, step, nil
	})
	self.sweepForks()
	return step
}

// Drops each fork whose peer this device's state now holds revoked or parked: the denial a fork costs
// lasts until then (§6.4's FORK row).
func (self *HeadStopState) sweepForks() {
	peerIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		peerIds := []Id{}
		for _, fork := range self.forks {
			if fork.fork.PeerId != nil {
				peerIds = append(peerIds, *fork.fork.PeerId)
			}
		}
		return peerIds
	}()
	settled := map[Id]bool{}
	for _, peerId := range peerIds {
		peer := self.env.Sources.Peers.HeadCheckPeer(peerId)
		settled[peerId] = peer.Revoked || peer.Parked
	}
	dropped := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		count := len(self.forks)
		self.forks = slices.DeleteFunc(self.forks, func(fork *headStopFork) bool {
			return fork.fork.PeerId != nil && settled[*fork.fork.PeerId]
		})
		if len(self.forks) == count {
			return false
		}
		self.version += 1
		return true
	}()
	if dropped {
		self.afterChange(nil)
	}
}

// What this device's HeadCheck to peerId carries of the relay rows (headCheckState.relayed).
func (self *HeadStopState) relayed(peerId Id) (*bridge.AuthPin, []*protocol.UnverifiedPin) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.relayed(peerId)
}

// The proof this device verified for its withheld tip, which it serves while it sends that tip as
// proven (§6.4's proven row); nil when it holds none.
func (self *HeadStopState) servedProof() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.withheld == nil {
		return nil
	}
	return slices.Clone(self.state.withheld.proof)
}

// After any change: persists it, raises its alarms, and wakes the run loop, whose deadlines it may have
// moved. Called with no lock held.
func (self *HeadStopState) afterChange(alarms []SidecarEvent) {
	self.persist()
	for _, alarm := range alarms {
		self.env.Alarm(alarm)
	}
	self.changed.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// Raises the alarms that are due and requests the rounds that are, then waits for the next or for a
// change, until Close.
func (self *HeadStopState) run() {
	defer close(self.done)
	for pass := uint64(1); ; pass += 1 {
		seen, changed := self.changed.Get()
		next := self.tick()
		var wake <-chan time.Time
		if !next.IsZero() {
			wake = self.env.Clock.After(next.Sub(self.env.Clock.Now()))
		}
		self.loopMark.Set(headStopLoopMark{passes: pass, seen: seen})
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		case <-wake:
		}
	}
}

// One pass of the run loop: the 24 h alarm (rpc_headcheck_witness.go) and the revoker
// (rpc_headcheck_revoker.go). Each pass moves every deadline it passes forward, so a pass never finds
// the same one due again. Answers the next deadline, zero for none.
func (self *HeadStopState) tick() time.Time {
	now := self.env.Clock.Now()
	var myPinBytes []byte
	if myPin := self.env.Sources.Auth.Pin(); myPin != nil {
		myPinBytes = headCheckEvidence(myPin)
	}
	alarms := []SidecarEvent{}
	requestRound := false
	next := time.Time{}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		witnessAlarms, witnessNext := self.witnessTickWithLock(now, myPinBytes)
		revokerAlarms, revokerNext, revokerRound := self.revokerTickWithLock(now, myPinBytes)
		alarms = append(witnessAlarms, revokerAlarms...)
		requestRound = revokerRound
		next = headStopEarliest(witnessNext, revokerNext)
		if len(alarms) == 0 && !revokerRound {
			return false
		}
		self.version += 1
		return true
	}()
	if changed {
		self.persist()
		for _, alarm := range alarms {
			self.env.Alarm(alarm)
		}
	}
	if requestRound {
		self.env.RequestRound()
	}
	return next
}

// The earlier of two deadlines, a zero one being none.
func headStopEarliest(a time.Time, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}

// authlog/'s file: the state as JSON, sealed by the store.
type headStopDocument struct {
	Version            int                          `json:"version"`
	WitnessedAtMs      int64                        `json:"witnessed_at_ms,omitempty"`
	WitnessPin         []byte                       `json:"witness_pin,omitempty"`
	UnwitnessedSinceMs int64                        `json:"unwitnessed_since_ms"`
	UnwitnessedAlarmed bool                         `json:"unwitnessed_alarmed,omitempty"`
	Unverified         []headStopUnverifiedDocument `json:"unverified,omitempty"`
	Withheld           *headStopProvenDocument      `json:"withheld,omitempty"`
	Forked             *headStopProvenDocument      `json:"forked,omitempty"`
	Forks              []headStopForkDocument       `json:"forks,omitempty"`
	Revocations        []headStopRevocationDocument `json:"revocations,omitempty"`
}

// One UNVERIFIED pin, its AuthPin as §6.5 encodes it.
type headStopUnverifiedDocument struct {
	Pin     []byte `json:"pin"`
	Path    []Id   `json:"path"`
	Direct  bool   `json:"direct,omitempty"`
	SinceMs int64  `json:"since_ms"`
}

// A withheld tip with its proof, or the fork pin relayed.
type headStopProvenDocument struct {
	Pin     []byte   `json:"pin"`
	Proof   [][]byte `json:"proof,omitempty"`
	PeerId  Id       `json:"peer_id"`
	SinceMs int64    `json:"since_ms"`
}

// One fork.
type headStopForkDocument struct {
	Kind    int    `json:"kind"`
	GroupId Id     `json:"group_id"`
	Local   []byte `json:"local"`
	Remote  []byte `json:"remote"`
	PeerId  *Id    `json:"peer_id,omitempty"`
	AtMs    int64  `json:"at_ms"`
}

// One revocation tracked.
type headStopRevocationDocument struct {
	Position uint64 `json:"position"`
	SinceMs  int64  `json:"since_ms"`
	Alarmed  bool   `json:"alarmed,omitempty"`
}

// A time from its document form, where zero is none.
func headStopTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// A time in its document form, where none is zero.
func headStopMs(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.UnixMilli()
}

// An AuthPin from its document form, nil for one that does not decode to §7.9's shape.
func headStopPin(pinBytes []byte) *bridge.AuthPin {
	pin := &bridge.AuthPin{}
	if proto.Unmarshal(pinBytes, pin) != nil || !headCheckPinValid(pin) {
		return nil
	}
	return pin
}

// The state as its document.
func (self *HeadStopState) documentWithLock() *headStopDocument {
	document := &headStopDocument{
		Version:            headStopDocumentVersion,
		WitnessedAtMs:      headStopMs(self.witnessedAt),
		UnwitnessedSinceMs: headStopMs(self.unwitnessedSince),
		UnwitnessedAlarmed: self.unwitnessedAlarmed,
	}
	if self.witnessPin != nil {
		document.WitnessPin = headCheckEvidence(self.witnessPin)
	}
	for _, held := range self.state.unverified {
		document.Unverified = append(document.Unverified, headStopUnverifiedDocument{
			Pin:     headCheckEvidence(held.pin),
			Path:    slices.Clone(held.path),
			Direct:  held.direct,
			SinceMs: headStopMs(held.since),
		})
	}
	proven := func(proven *headCheckProven) *headStopProvenDocument {
		if proven == nil {
			return nil
		}
		return &headStopProvenDocument{Pin: headCheckEvidence(proven.pin), Proof: slices.Clone(proven.proof), PeerId: proven.peerId, SinceMs: headStopMs(proven.since)}
	}
	document.Withheld = proven(self.state.withheld)
	document.Forked = proven(self.state.forked)
	for _, fork := range self.forks {
		document.Forks = append(document.Forks, headStopForkDocument{
			Kind:    int(fork.fork.Kind),
			GroupId: fork.fork.GroupId,
			Local:   fork.fork.Local,
			Remote:  fork.fork.Remote,
			PeerId:  fork.fork.PeerId,
			AtMs:    headStopMs(fork.at),
		})
	}
	for _, revocation := range self.revocations {
		document.Revocations = append(document.Revocations, headStopRevocationDocument{
			Position: revocation.position,
			SinceMs:  headStopMs(revocation.since),
			Alarmed:  revocation.alarmed,
		})
	}
	return document
}

// Writes the newest state to authlog/, unless a newer one is written already. A write that fails is
// logged and tried again at the next change; the state in memory still stops what it stops.
func (self *HeadStopState) persist() {
	document, version := func() (*headStopDocument, uint64) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.documentWithLock(), self.version
	}()
	self.persistLock.Lock()
	defer self.persistLock.Unlock()
	if version <= self.persistedVersion {
		return
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		self.env.Log.Errorf("[headcheck] encode: %v", err)
		return
	}
	write := func() error {
		writer, err := self.env.Store.Create(headStopFileName)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		return writer.Commit()
	}
	if err := write(); err != nil {
		self.env.Log.Warningf("[headcheck] persist: %v", err)
		return
	}
	self.persistedVersion = version
}

// Reads authlog/'s file into the state, and answers true when there is none. A file that does not
// decode exactly, or holds a pin, path or fork off its shape, is errHeadStopDocument.
func (self *HeadStopState) load() (bool, error) {
	reader, err := self.env.Store.Open(headStopFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, headStopDocumentMaxByteCount+1))
	if err != nil {
		return false, err
	}
	if headStopDocumentMaxByteCount < len(encoded) {
		return false, fmt.Errorf("%w: past its size", errHeadStopDocument)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	document := &headStopDocument{}
	if err := decoder.Decode(document); err != nil {
		return false, fmt.Errorf("%w: %w", errHeadStopDocument, err)
	}
	if document.Version != headStopDocumentVersion {
		return false, fmt.Errorf("%w: version %d", errHeadStopDocument, document.Version)
	}
	malformed := func(what string) error {
		return fmt.Errorf("%w: %s", errHeadStopDocument, what)
	}

	self.witnessedAt = headStopTime(document.WitnessedAtMs)
	self.unwitnessedSince = headStopTime(document.UnwitnessedSinceMs)
	self.unwitnessedAlarmed = document.UnwitnessedAlarmed
	if len(document.WitnessPin) != 0 {
		if self.witnessPin = headStopPin(document.WitnessPin); self.witnessPin == nil {
			return false, malformed("witness pin")
		}
	}
	if self.witnessedAt.IsZero() && self.unwitnessedSince.IsZero() {
		return false, malformed("no witness and no start")
	}
	if HeadCheckMaxUnverifiedCount < len(document.Unverified) {
		return false, malformed("unverified past its cap")
	}
	for _, held := range document.Unverified {
		pin := headStopPin(held.Pin)
		if pin == nil || len(held.Path) == 0 || HeadCheckMaxPathCount < len(held.Path) || slices.Contains(held.Path, self.env.SidecarId) {
			return false, malformed("unverified pin")
		}
		self.state.unverified = append(self.state.unverified, &headCheckUnverified{pin: pin, path: held.Path, direct: held.Direct, since: headStopTime(held.SinceMs)})
	}
	slices.SortFunc(self.state.unverified, func(a *headCheckUnverified, b *headCheckUnverified) int {
		return headCheckPinCompare(a.pin, b.pin)
	})
	proven := func(document *headStopProvenDocument) (*headCheckProven, error) {
		if document == nil {
			return nil, nil
		}
		pin := headStopPin(document.Pin)
		if pin == nil {
			return nil, malformed("proven pin")
		}
		return &headCheckProven{pin: pin, proof: document.Proof, peerId: document.PeerId, since: headStopTime(document.SinceMs)}, nil
	}
	if self.state.withheld, err = proven(document.Withheld); err != nil {
		return false, err
	}
	if self.state.forked, err = proven(document.Forked); err != nil {
		return false, err
	}
	for _, fork := range document.Forks {
		kind := HeadForkKind(fork.Kind)
		if kind < HeadForkAuth || HeadForkRef < kind {
			return false, malformed("fork kind")
		}
		self.forks = append(self.forks, &headStopFork{
			fork: HeadFork{Kind: kind, GroupId: fork.GroupId, Local: fork.Local, Remote: fork.Remote, PeerId: fork.PeerId},
			at:   headStopTime(fork.AtMs),
		})
	}
	for _, revocation := range document.Revocations {
		since := headStopTime(revocation.SinceMs)
		self.revocations = append(self.revocations, &headStopRevocation{
			position: revocation.Position,
			since:    since,
			alarmed:  revocation.Alarmed,
			// the revoker retries at each start
			nextRound: self.env.Clock.Now(),
		})
	}
	return false, nil
}
