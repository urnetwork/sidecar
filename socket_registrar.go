//go:build !sidecar_http && !ios_extension

// The client's half of §9.5 (R-SOCK-1, D-SOCK-3, D-SOCK-13): the registrar, which holds every Listen of one network's
// sidecar as the client's full set and keeps it registered at the sockets service, one call at a time per client.
//
// The set. Each Listen is one entry. An edge name (tls/, smtp/, ur/) is one registration in the clear. Any other name
// goes only as its token path with its 152 B seal (D-SOCK-13), under each key the K_sock ring has a listener register:
// both through a rotation's 10 min overlap by this device's clock, then the newest alone (§9.4,
// plan-SOCK-ksock-rotation). A blinded name with no ring never leaves in any form: its Listen is refused. Every entry
// carries a claim, a §6 Signed by the identity key over (network_id, name or token path, listen_id, protocol,
// app_mode), made once per path and kept, so a rotation signs only its new path. Registrations sort by name key, and a
// set of more than 1,024 goes as pages under one set_version, each page the whole set within its range, so what a page
// lacks there unlistens at once and nothing outside it is touched.
//
// When it calls. A round sends the whole set: a sweep from the start of all keys in pages of at most 1,024, each page
// cut from the set as it stands when that page goes, under the round's one set_version. A change (a Listen, an
// unlisten, serving, draining, new rows under a new ring or identity key, a rotation's overlap ending), a SocketHint
// on topic sock and a new generation each ask for a round at once, after any round in progress; otherwise a round goes
// every HeartbeatInterval ± Jitter, carrying each entry's in-flight count. Between rounds an entry whose count moved
// from what the service last saw by max(EagerReportMinMove, EagerReportMoveFraction of its max_streams) has its own
// page sent alone, under a set_version of its own, at most one such page every EagerReportInterval (§9.5, §9.7). A
// hint changes nothing by itself, since the answer is authoritative (§9.5); a forced drain is only handed to the entry
// it names, for SOCK-M5-11's listener, a drain being a denial a server may originate (I-4).
//
// set_version is millisecond time, raised past the last one used, so a restarted daemon's first set is newer than what
// it sent before, and a stale refusal's stored value is jumped past at once (plan reading 11).
//
// What an answer does. ok keeps the lease. Any other status, an unknown one included, means the entry holds no lease:
// it leaves the set, its first verdict answers the Listen waiting on it, and a later one ends it, which closes it with
// its streams (§9.5's revoked). A refusal of a rotation's previous path stops only that path. A failed call keeps every
// entry, since lease expiry stops tickets and not streams (§9.5): the registrar waits out retry_after_ms when the
// service gives one, the 45 s lease outlasting a late page, else a doubling backoff, then sends the whole set again.
// Each answer that refuses nothing leaves the newest ticket keys, the service's clock offset, the urnetwork-edge
// network id and §20's stop for admission (§9.6's steps 1, 3, 4 and 5).
//
// socketRegistrarState is the logic, with every input, the time included, an argument, and nothing that locks, waits,
// signs or calls out, so its tests step it by hand. socketRegistrar wraps it with the lock, the run loop, the making
// of rows and the delivery of verdicts, which happen outside the lock. Nothing here logs a name (I-13). Safe for
// concurrent use. connect legs only: §9's bodies name connect.Id, and the sidecar_http leg runs no component (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"reflect"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §9.5's bounds on a registration's weight, a relative share.
const (
	socketRegistrationMinWeight = 1
	socketRegistrationMaxWeight = 1000
)

var (
	// A second Listen of a name this client registers: §9.5 holds one lease per client and name.
	errSocketNameRegistered = errors.New("socket name already registered")
	// A field §9.5 refuses, or a name with no owner to use it: a reserved first segment has none (§9.4).
	errSocketRegistrationInvalid = errors.New("invalid socket registration")
	// An application or share/ name with no K_sock ring to blind it under, so it cannot leave the device in any form
	// (D-SOCK-13): the verified config head has not given a ring yet.
	errSocketNoKeyRing = fmt.Errorf("%w: no socket key ring yet", ErrSocketUnavailable)
	// The registrar closed before the service answered for the entry.
	errSocketRegistrarClosed = fmt.Errorf("socket registrar closed: %w", net.ErrClosed)
	// The entry was unlistened before the service answered for it.
	errSocketRegistrationRemoved = errors.New("socket registration removed")
)

// SidecarApi.SocketRegistrations, or a test's stand-in.
type socketRegistrationsFunction func(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error)

// Sidecar.Sign, or a test's stand-in.
type socketSignFunction func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)

// What one Listen registers (§9.5). The caller fills §9.5's defaults, since a zero here is not one: protocol "tcp",
// weight 100, max_streams 256, and app_mode "http" on tls/.
type socketRegistrationArgs struct {
	// Folded to its canonical form. A reserved first segment is refused.
	Name     string
	ListenId Id
	Protocol string
	Version  int
	Alpns    []string
	// tls/: "http" or "raw". Any other name: "".
	AppMode string
	// 1 to 1000.
	Weight int
	// At least 1.
	MaxStreams int
	Exclusive  bool
	Affinity   bool
	// The entry starts not serving, so its lease takes no ticket until SetServing: an smtp/ receiver's until its key
	// is published (§15.5).
	NotServing bool
	// Called on the registrar's goroutine once the service ends an entry it had taken: the entry has left the set,
	// and the listener closes it with its streams (§9.5). Never for the first verdict, which verdict answers. Must
	// not block. nil: nothing to tell.
	Ended func(status SocketRegistrationStatus)
	// Called on the registrar's goroutine when a SOCKET_HINT_DRAIN names this listen (§9.5's forced drain). Must not
	// block. nil: nothing to tell.
	DrainHinted func()
}

// One Listen as the registrar holds it: what it registers, fixed at add, and its state, which the registrar's lock
// guards.
type socketRegistrarEntry struct {
	listenId   Id
	name       string
	namespace  SocketNamespace
	protocol   string
	version    int
	alpns      []string
	appMode    string
	weight     int
	maxStreams int
	exclusive  bool
	affinity   bool
	owner      *socketRegistration

	serving  bool
	draining bool
	inflight int
	// the in-flight count the service last saw, and since when an eager report has been wanted, zero for none
	reportedInflight int
	eagerSince       time.Time

	// an edge name's one row, or a blinded name's one under each key its ring registered when they were made, newest
	// first
	rows []*socketRegistrarRow
	// for a blinded name, the ring the rows were made under
	rowsRing *SocketKeyRing
	// the epochs the rows were made at (socketRegistrarState)
	ringEpoch     uint64
	identityEpoch uint64
	// the service refused the previous key's path, which is not sent again
	previousRefused bool
	// how many rows the newest round meant to send, so a rotation's overlap ending asks for a round
	sentRowCount int
	// the service has given its first verdict
	answered bool
}

// One registration of an entry: its key and what proves it.
type socketRegistrarRow struct {
	// what the set sorts and pages by (SocketRegistration.NameKey): an edge name's bytes, or a token path
	nameKey []byte
	// a blinded name's token path and seal; nil for an edge name
	tokenPath  []byte
	sealedName []byte
	// a marshaled bridge.Signed over the SocketRegistrationClaim (§9.5), and the identity epoch it was signed at
	claim         []byte
	identityEpoch uint64
}

// The entry args describe, or the refusal §9.4 or §9.5 makes of it. The name is canonical from here on.
func newSocketRegistrarEntry(args *socketRegistrationArgs) (*socketRegistrarEntry, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no registration", errSocketRegistrationInvalid)
	}
	name, namespace, err := ParseSocketName(args.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSocketRegistrationInvalid, err)
	}
	appModeValid := args.AppMode == ""
	if namespace == SocketNamespaceTls {
		appModeValid = args.AppMode == "http" || args.AppMode == "raw"
	}
	switch {
	case namespace == SocketNamespaceReserved:
		return nil, fmt.Errorf("%w: a reserved name has no owner", errSocketRegistrationInvalid)
	case args.ListenId == (Id{}):
		return nil, fmt.Errorf("%w: no listen id", errSocketRegistrationInvalid)
	case args.Protocol == "" || args.Version < 0:
		return nil, fmt.Errorf("%w: no protocol, or a negative version", errSocketRegistrationInvalid)
	case args.Weight < socketRegistrationMinWeight || socketRegistrationMaxWeight < args.Weight:
		return nil, fmt.Errorf("%w: a weight outside 1-1000", errSocketRegistrationInvalid)
	case args.MaxStreams < 1:
		return nil, fmt.Errorf("%w: max_streams below 1", errSocketRegistrationInvalid)
	case !appModeValid:
		return nil, fmt.Errorf("%w: an app_mode the namespace does not take", errSocketRegistrationInvalid)
	}
	return &socketRegistrarEntry{
		listenId:   args.ListenId,
		name:       name,
		namespace:  namespace,
		protocol:   args.Protocol,
		version:    args.Version,
		alpns:      slices.Clone(args.Alpns),
		appMode:    args.AppMode,
		weight:     args.Weight,
		maxStreams: args.MaxStreams,
		exclusive:  args.Exclusive,
		affinity:   args.Affinity,
		serving:    !args.NotServing,
	}, nil
}

// Whether the name goes only as its token path (D-SOCK-13).
func (self *socketRegistrarEntry) blinded() bool {
	return self.namespace.blinded()
}

// Puts rows made under ring at ringEpoch and identityEpoch on the entry.
func (self *socketRegistrarEntry) setRows(rows []*socketRegistrarRow, ring *SocketKeyRing, ringEpoch uint64, identityEpoch uint64) {
	self.rows = rows
	self.rowsRing = nil
	if self.blinded() {
		self.rowsRing = ring
	}
	self.ringEpoch = ringEpoch
	self.identityEpoch = identityEpoch
	self.previousRefused = false
}

// The rows the set holds for the entry at nowMs: the newest, and through a rotation's overlap the previous path,
// unless the service refused it.
func (self *socketRegistrarEntry) sendRows(nowMs int64) []*socketRegistrarRow {
	if _, dual := self.dualUntilMs(nowMs); dual {
		return self.rows[:2]
	}
	return self.rows[:min(len(self.rows), 1)]
}

// When the entry stops sending its previous path, and whether it sends one at nowMs.
func (self *socketRegistrarEntry) dualUntilMs(nowMs int64) (int64, bool) {
	if self.rowsRing == nil || len(self.rows) < 2 || self.previousRefused {
		return 0, false
	}
	untilMs, ok := self.rowsRing.RegisterBothUntilMs()
	return untilMs, ok && nowMs < untilMs
}

// row as one registration, with the entry's flags and in-flight count as they stand.
func (self *socketRegistrarEntry) registration(row *socketRegistrarRow) *SocketRegistration {
	listenId := connect.Id(self.listenId)
	registration := &SocketRegistration{
		NameToken:  row.tokenPath,
		SealedName: row.sealedName,
		ListenId:   &listenId,
		Protocol:   self.protocol,
		Version:    self.version,
		Alpn:       slices.Clone(self.alpns),
		AppMode:    self.appMode,
		Weight:     self.weight,
		MaxStreams: self.maxStreams,
		Exclusive:  self.exclusive,
		Affinity:   self.affinity,
		Serving:    self.serving,
		Draining:   self.draining,
		Inflight:   self.inflight,
		Claim:      row.claim,
	}
	if row.tokenPath == nil {
		registration.Name = self.name
	}
	return registration
}

// The rows of entry, each sealed and claimed: an edge name's one, or a blinded name's one under each key ring registers
// at nowMs, newest first. A row of reuse with the same key, claimed at identityEpoch, is kept as it is, so a new ring
// signs only its new paths. It signs, so it runs outside every lock.
func makeSocketRegistrarRows(networkId Id, sign socketSignFunction, entry *socketRegistrarEntry, ring *SocketKeyRing, nowMs int64, reuse []*socketRegistrarRow, identityEpoch uint64) ([]*socketRegistrarRow, error) {
	reused := func(nameKey []byte) *socketRegistrarRow {
		for _, row := range reuse {
			if row.identityEpoch == identityEpoch && bytes.Equal(row.nameKey, nameKey) {
				return row
			}
		}
		return nil
	}
	if !entry.blinded() {
		if row := reused([]byte(entry.name)); row != nil {
			return []*socketRegistrarRow{row}, nil
		}
		claim, err := signSocketRegistrationClaim(networkId, sign, entry, nil)
		if err != nil {
			return nil, err
		}
		return []*socketRegistrarRow{{nameKey: []byte(entry.name), claim: claim, identityEpoch: identityEpoch}}, nil
	}
	if ring == nil {
		return nil, errSocketNoKeyRing
	}
	rows := []*socketRegistrarRow{}
	for _, keys := range ring.RegisterKeys(nowMs) {
		tokenPath, err := keys.TokenPath(entry.name)
		if err != nil {
			return nil, err
		}
		if row := reused(tokenPath); row != nil {
			rows = append(rows, row)
			continue
		}
		sealedName, err := keys.Seal(entry.name)
		if err != nil {
			return nil, err
		}
		claim, err := signSocketRegistrationClaim(networkId, sign, entry, tokenPath)
		if err != nil {
			return nil, err
		}
		rows = append(rows, &socketRegistrarRow{
			nameKey:       tokenPath,
			tokenPath:     tokenPath,
			sealedName:    sealedName,
			claim:         claim,
			identityEpoch: identityEpoch,
		})
	}
	return rows, nil
}

// §9.5's claim over entry's name, or over tokenPath for a blinded one: a marshaled §6 Signed by the identity key,
// purpose socket-registration, which Find hands a dialer with each ticket to check against this sidecar's Hello
// binding (§9.6).
func signSocketRegistrationClaim(networkId Id, sign socketSignFunction, entry *socketRegistrarEntry, tokenPath []byte) ([]byte, error) {
	claim := &protocol.SocketRegistrationClaim{
		NetworkId: networkId.Bytes(),
		ListenId:  entry.listenId.Bytes(),
		Protocol:  entry.protocol,
		AppMode:   entry.appMode,
	}
	if tokenPath == nil {
		claim.Name = entry.name
	} else {
		claim.NameToken = tokenPath
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(claim)
	if err != nil {
		return nil, err
	}
	signed, err := sign(SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body, nil)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// What the newest answer that refused nothing gave for admitting tickets (§9.6): the keys a ticket verifies under
// (step 1), the service's clock against this device's (step 4), the urnetwork-edge network (steps 3 and 6) and §20's
// stop (step 5). A copy, which a listener reads without the registrar's lock.
type socketAdmissionState struct {
	// an answer has come; until one, a listener admits nothing
	known      bool
	ticketKeys []*SocketTicketKey
	// the service's clock less this device's, in milliseconds, at the newest answer giving server_time
	serverTimeOffsetMillis int64
	// nil until an answer names it
	urnetworkEdge  *Id
	streamsStopped bool
}

// The service's clock at now by this device's clock and the newest offset: what a ticket's expiry is held to (§9.6's
// step 4), and VerifySocketTicket's nowMillis.
func (self *socketAdmissionState) serverNowMillis(now time.Time) uint64 {
	millis := now.UnixMilli() + self.serverTimeOffsetMillis
	if millis < 0 {
		return 0
	}
	return uint64(millis)
}

// A copy sharing nothing.
func (self *socketAdmissionState) clone() *socketAdmissionState {
	clone := *self
	clone.ticketKeys = make([]*SocketTicketKey, 0, len(self.ticketKeys))
	for _, ticketKey := range self.ticketKeys {
		keyClone := *ticketKey
		keyClone.PublicKey = bytes.Clone(ticketKey.PublicKey)
		clone.ticketKeys = append(clone.ticketKeys, &keyClone)
	}
	if self.urnetworkEdge != nil {
		urnetworkEdge := *self.urnetworkEdge
		clone.urnetworkEdge = &urnetworkEdge
	}
	return &clone
}

// One row of the set as a page carries it.
type socketRegistrarSendRow struct {
	entry *socketRegistrarEntry
	row   *socketRegistrarRow
	// a rotation's previous path
	previous bool
}

// The whole set, going as a sweep of pages under one set_version.
type socketRegistrarRound struct {
	setVersion uint64
	// where the next page starts, nil for the first, which starts at the start of all keys
	keyStart []byte
	// a page has carried a registration, so the service may hold leases once the round is done
	sentAny bool
}

// One page to send, and what its answer is read against.
type socketRegistrarCall struct {
	args *SocketRegistrationsArgs
	// the rows of args.Registrations, in order, and the in-flight count each carried
	rows      []*socketRegistrarSendRow
	inflights []int
	// the round the page is of, nil for an eager page, and where the page ends, nil at the end of all keys
	round  *socketRegistrarRound
	keyEnd []byte
	// the attachment it goes through, so an answer to an attachment that has ended changes nothing
	attachmentSeq uint64
}

// What an owner of an entry is to hear, outside the lock.
type socketRegistrarEffect struct {
	owner  *socketRegistration
	status SocketRegistrationStatus
	// the entry's first verdict, which answers the Listen waiting on it; else the end of a lease the service took
	first bool
	// a SOCKET_HINT_DRAIN named the entry
	drain bool
}

// The registrar's logic: every input, the time included, is an argument, and nothing here locks, waits, signs or calls
// out. Not safe for concurrent use: socketRegistrar holds it under its lock.
type socketRegistrarState struct {
	settings *SidecarSocketSettings
	// a uniform draw from [0, 1), for jitter
	random func() float64

	// by listen id, and the listen id holding each canonical name
	entries         map[Id]*socketRegistrarEntry
	listenIdsByName map[string]Id
	// the newest K_sock ring, nil until one is set, and the epochs that say which rows are current: a new ring makes
	// every blinded name's rows again, and a new identity key every row's claim
	ring          *SocketKeyRing
	ringEpoch     uint64
	identityEpoch uint64
	// some entry's rows are not current, and when the registrar may next try to make them, after a failure
	rowsStale bool
	remakeAt  time.Time

	// a generation is attached, and how many have been, so an answer to an earlier one changes nothing
	attached      bool
	attachmentSeq uint64

	// the newest set_version used: millisecond time, raised past each one before
	setVersion uint64
	// the round in progress, nil between rounds
	round *socketRegistrarRound
	// the whole set is to go at once, after any round in progress
	roundPending bool
	// when the next heartbeat round is due, zero while none runs
	heartbeatAt time.Time
	// the service may hold leases from a call before: rounds go on, an empty set included, until an empty set lands
	serverMayHold bool
	// no call before this, after a failure, a stale refusal or retry_after_ms
	retryAt time.Time
	// failures and stale refusals in a row, for the backoff
	failureCount int
	staleCount   int
	// when the last eager page went
	lastEagerAt time.Time

	admission socketAdmissionState
	// what a hint has for owners: forced drains
	effects []*socketRegistrarEffect
}

// A state with no entries, no ring and no generation.
func newSocketRegistrarState(settings *SidecarSocketSettings, random func() float64) *socketRegistrarState {
	return &socketRegistrarState{
		settings:        settings,
		random:          random,
		entries:         map[Id]*socketRegistrarEntry{},
		listenIdsByName: map[string]Id{},
	}
}

// Adds entry, whose rows are made, and asks for the set. A name or listen id already held is refused.
func (self *socketRegistrarState) addEntry(entry *socketRegistrarEntry) error {
	if _, found := self.listenIdsByName[entry.name]; found {
		return errSocketNameRegistered
	}
	if _, found := self.entries[entry.listenId]; found {
		return fmt.Errorf("%w: a listen id held already", errSocketRegistrationInvalid)
	}
	self.entries[entry.listenId] = entry
	self.listenIdsByName[entry.name] = entry.listenId
	if !self.rowsCurrent(entry) {
		self.rowsStale = true
	}
	self.roundPending = true
	return nil
}

// Takes entry out of the set without asking for a round: the service holds no lease for it.
func (self *socketRegistrarState) dropEntry(entry *socketRegistrarEntry) {
	delete(self.entries, entry.listenId)
	delete(self.listenIdsByName, entry.name)
}

// Unlistens: the entry leaves the set, which goes at once without it (§9.5). False when it was not there.
func (self *socketRegistrarState) removeEntry(listenId Id) bool {
	entry := self.entries[listenId]
	if entry == nil {
		return false
	}
	self.dropEntry(entry)
	self.roundPending = true
	return true
}

// False keeps the lease and takes no tickets (§9.5). True when it changed the set.
func (self *socketRegistrarState) setServing(listenId Id, serving bool) bool {
	entry := self.entries[listenId]
	if entry == nil || entry.serving == serving {
		return false
	}
	entry.serving = serving
	self.roundPending = true
	return true
}

// No new tickets, issued ones accepted (§9.5). True when it changed the set.
func (self *socketRegistrarState) setDraining(listenId Id, draining bool) bool {
	entry := self.entries[listenId]
	if entry == nil || entry.draining == draining {
		return false
	}
	entry.draining = draining
	self.roundPending = true
	return true
}

// The entry's in-flight count, which every later call carries. True when it asks for an eager report, which only an
// entry the service has answered for asks: until then the round that adds it carries its count.
func (self *socketRegistrarState) setInflight(listenId Id, inflight int, now time.Time) bool {
	entry := self.entries[listenId]
	if entry == nil || inflight < 0 {
		return false
	}
	entry.inflight = inflight
	if entry.eagerSince.IsZero() && entry.answered && self.eagerMoved(entry) {
		entry.eagerSince = now
		return true
	}
	return false
}

// Whether the entry's count has moved from what the service last saw by §9.5's eager amount.
func (self *socketRegistrarState) eagerMoved(entry *socketRegistrarEntry) bool {
	move := entry.inflight - entry.reportedInflight
	if move < 0 {
		move = -move
	}
	return self.settings.EagerReportMinMove <= move &&
		self.settings.EagerReportMoveFraction*float64(entry.maxStreams) <= float64(move)
}

// A newer ring: blinded names' rows are made again under it.
func (self *socketRegistrarState) setRing(ring *SocketKeyRing) {
	self.ring = ring
	self.ringEpoch += 1
	self.rowsStale = true
	self.remakeAt = time.Time{}
}

// A new identity key: every claim is signed again.
func (self *socketRegistrarState) newIdentity() {
	self.identityEpoch += 1
	self.rowsStale = true
	self.remakeAt = time.Time{}
}

// Whether the entry's rows were made under the newest identity key and, for a blinded name, the newest ring.
func (self *socketRegistrarState) rowsCurrent(entry *socketRegistrarEntry) bool {
	return entry.identityEpoch == self.identityEpoch && (!entry.blinded() || entry.ringEpoch == self.ringEpoch)
}

// Puts rows made at ringEpoch and identityEpoch on entry and asks for the set, unless the entry has gone or a newer
// ring or key has come meanwhile, whose own remake follows.
func (self *socketRegistrarState) installRows(entry *socketRegistrarEntry, rows []*socketRegistrarRow, ring *SocketKeyRing, ringEpoch uint64, identityEpoch uint64) {
	if self.entries[entry.listenId] != entry || ringEpoch != self.ringEpoch || identityEpoch != self.identityEpoch {
		return
	}
	entry.setRows(rows, ring, ringEpoch, identityEpoch)
	self.roundPending = true
}

// Once a remake has run: whether any entry's rows are still not current, and if the remake failed, when to try again.
func (self *socketRegistrarState) settleRows(now time.Time, failed bool) {
	self.rowsStale = false
	for _, entry := range self.entries {
		if !self.rowsCurrent(entry) {
			self.rowsStale = true
			break
		}
	}
	if failed {
		self.remakeAt = now.Add(self.settings.RetryMaxInterval)
	}
}

// A generation is attached: the whole set goes at once on its token, with nothing left over from the one before.
func (self *socketRegistrarState) attach() uint64 {
	self.attached = true
	self.attachmentSeq += 1
	self.round = nil
	self.retryAt = time.Time{}
	self.failureCount = 0
	self.staleCount = 0
	self.roundPending = 0 < len(self.entries) || self.serverMayHold
	return self.attachmentSeq
}

// The generation of attachmentSeq ended. False when a later one had replaced it.
func (self *socketRegistrarState) detach(attachmentSeq uint64) bool {
	if !self.attached || self.attachmentSeq != attachmentSeq {
		return false
	}
	self.attached = false
	self.round = nil
	return true
}

// A notice on topic sock: the whole set goes at once, and a forced drain is handed to the entry it names. The hint
// changes no lease itself, since the answer is authoritative (§9.5).
func (self *socketRegistrarState) hint(drainListenId *Id) {
	if 0 < len(self.entries) || self.serverMayHold {
		self.roundPending = true
	}
	if drainListenId == nil {
		return
	}
	if entry := self.entries[*drainListenId]; entry != nil {
		self.effects = append(self.effects, &socketRegistrarEffect{owner: entry.owner, drain: true})
	}
}

// What hints have left for owners, taken.
func (self *socketRegistrarState) takeEffects() []*socketRegistrarEffect {
	effects := self.effects
	self.effects = nil
	return effects
}

// A set_version past every one used: millisecond time, raised past the last when the clock has not moved past it.
// False once no larger one exists.
func (self *socketRegistrarState) nextSetVersion(nowMs int64) (uint64, bool) {
	if self.setVersion == math.MaxUint64 {
		return 0, false
	}
	setVersion := uint64(max(nowMs, 0))
	if setVersion <= self.setVersion {
		setVersion = self.setVersion + 1
	}
	self.setVersion = setVersion
	return setVersion, true
}

// Past every set_version, which only stale answers that kept raising it can do: wait out sock-5's 5 min, after which
// the service holds no set for this client, and start again from millisecond time.
func (self *socketRegistrarState) startOver(now time.Time) {
	self.setVersion = 0
	self.round = nil
	self.roundPending = true
	self.retryAt = now.Add(self.settings.RetryAfterMaxWait)
}

// interval ± Jitter, drawn uniformly.
func (self *socketRegistrarState) jittered(interval time.Duration) time.Duration {
	return time.Duration(float64(interval) * (1 + self.settings.Jitter*(2*self.random()-1)))
}

// The wait after count failures in a row: RetryInterval, doubling to RetryMaxInterval, jittered.
func (self *socketRegistrarState) backoff(count int) time.Duration {
	wait := self.settings.RetryInterval
	for i := 1; i < count && wait < self.settings.RetryMaxInterval; i += 1 {
		wait *= 2
	}
	return self.jittered(min(wait, self.settings.RetryMaxInterval))
}

// The set at nowMs, sorted by name key, as every page and eager report cuts it. A row whose key an earlier row holds,
// which only an HMAC collision could make, is left out, since a page holds one entry per key.
func (self *socketRegistrarState) sendRows(nowMs int64) []*socketRegistrarSendRow {
	rows := []*socketRegistrarSendRow{}
	for _, entry := range self.entries {
		for index, row := range entry.sendRows(nowMs) {
			rows = append(rows, &socketRegistrarSendRow{entry: entry, row: row, previous: 0 < index})
		}
	}
	slices.SortFunc(rows, func(a *socketRegistrarSendRow, b *socketRegistrarSendRow) int {
		if order := bytes.Compare(a.row.nameKey, b.row.nameKey); order != 0 {
			return order
		}
		if a.previous != b.previous {
			if a.previous {
				return 1
			}
			return -1
		}
		return bytes.Compare(a.entry.listenId[:], b.entry.listenId[:])
	})
	return slices.CompactFunc(rows, func(a *socketRegistrarSendRow, b *socketRegistrarSendRow) bool {
		return bytes.Equal(a.row.nameKey, b.row.nameKey)
	})
}

// Whether a round is due: asked for, a heartbeat, or an entry whose rows to send changed since the newest round, as
// when a rotation's overlap ends.
func (self *socketRegistrarState) roundDue(now time.Time, nowMs int64) bool {
	if self.roundPending || !self.heartbeatAt.IsZero() && !now.Before(self.heartbeatAt) {
		return true
	}
	for _, entry := range self.entries {
		if len(entry.sendRows(nowMs)) != entry.sentRowCount {
			return true
		}
	}
	return false
}

// The call to make at now, or none and when to look again, zero for no time: only a change wakes it then. Never
// answers a time at or before now.
func (self *socketRegistrarState) next(now time.Time) (*socketRegistrarCall, time.Time) {
	if !self.attached {
		return nil, time.Time{}
	}
	if now.Before(self.retryAt) {
		return nil, self.retryAt
	}
	nowMs := now.UnixMilli()
	if self.round == nil && self.roundDue(now, nowMs) {
		self.roundPending = false
		if len(self.entries) == 0 && !self.serverMayHold {
			// nothing is registered and nothing is left to unlisten, so heartbeats stop
			self.heartbeatAt = time.Time{}
		} else {
			setVersion, ok := self.nextSetVersion(nowMs)
			if !ok {
				self.startOver(now)
				return nil, self.retryAt
			}
			for _, entry := range self.entries {
				entry.sentRowCount = len(entry.sendRows(nowMs))
			}
			self.round = &socketRegistrarRound{setVersion: setVersion}
		}
	}
	if self.round != nil {
		return self.roundCall(nowMs), time.Time{}
	}

	eagerEntry, eagerAt := self.eagerEntry(now)
	if eagerEntry != nil {
		call, ok := self.eagerCall(eagerEntry, now, nowMs)
		if !ok {
			self.startOver(now)
			return nil, self.retryAt
		}
		if call != nil {
			return call, time.Time{}
		}
	}
	wakeAt := self.heartbeatAt
	soonest := func(at time.Time) {
		if now.Before(at) && (wakeAt.IsZero() || at.Before(wakeAt)) {
			wakeAt = at
		}
	}
	soonest(eagerAt)
	for _, entry := range self.entries {
		if untilMs, dual := entry.dualUntilMs(nowMs); dual {
			soonest(time.UnixMilli(untilMs))
		}
	}
	if self.rowsStale {
		soonest(self.remakeAt)
	}
	return nil, wakeAt
}

// The round's next page: the whole set as it stands within [the round's cursor, the key after the page's last
// entry), at most SocketRegistrationPageMaxEntryCount entries, the last page running to the end of all keys.
func (self *socketRegistrarState) roundCall(nowMs int64) *socketRegistrarCall {
	rows := self.sendRows(nowMs)
	start := 0
	if self.round.keyStart != nil {
		start, _ = slices.BinarySearchFunc(rows, self.round.keyStart, func(sendRow *socketRegistrarSendRow, key []byte) int {
			return bytes.Compare(sendRow.row.nameKey, key)
		})
	}
	end := min(start+SocketRegistrationPageMaxEntryCount, len(rows))
	var keyEnd []byte
	if end < len(rows) {
		keyEnd = rows[end].row.nameKey
	}
	if start < end {
		self.round.sentAny = true
	}
	return self.pageCall(rows[start:end], self.round.keyStart, keyEnd, self.round.setVersion, self.round)
}

// The entry whose eager page goes next, the longest waiting, or none and when one may go: at most one each
// EagerReportInterval. An entry whose count has moved back drops out.
func (self *socketRegistrarState) eagerEntry(now time.Time) (*socketRegistrarEntry, time.Time) {
	var eager *socketRegistrarEntry
	for _, entry := range self.entries {
		if entry.eagerSince.IsZero() {
			continue
		}
		if !self.eagerMoved(entry) {
			entry.eagerSince = time.Time{}
			continue
		}
		if eager == nil || entry.eagerSince.Before(eager.eagerSince) ||
			entry.eagerSince.Equal(eager.eagerSince) && bytes.Compare(entry.listenId[:], eager.listenId[:]) < 0 {
			eager = entry
		}
	}
	if eager == nil {
		return nil, time.Time{}
	}
	if eagerAt := self.lastEagerAt.Add(self.settings.EagerReportInterval); now.Before(eagerAt) {
		return nil, eagerAt
	}
	return eager, time.Time{}
}

// The entry's own page alone (§9.5): the page a round from the start would cut around it now, so the whole set within
// its range, under a set_version of its own. None when the entry sends no row; false once no set_version is left.
func (self *socketRegistrarState) eagerCall(entry *socketRegistrarEntry, now time.Time, nowMs int64) (*socketRegistrarCall, bool) {
	rows := self.sendRows(nowMs)
	index := slices.IndexFunc(rows, func(sendRow *socketRegistrarSendRow) bool {
		return sendRow.entry == entry && !sendRow.previous
	})
	if index < 0 {
		entry.eagerSince = time.Time{}
		return nil, true
	}
	setVersion, ok := self.nextSetVersion(nowMs)
	if !ok {
		return nil, false
	}
	start := index - index%SocketRegistrationPageMaxEntryCount
	end := min(start+SocketRegistrationPageMaxEntryCount, len(rows))
	var keyStart []byte
	if 0 < start {
		keyStart = rows[start].row.nameKey
	}
	var keyEnd []byte
	if end < len(rows) {
		keyEnd = rows[end].row.nameKey
	}
	self.lastEagerAt = now
	return self.pageCall(rows[start:end], keyStart, keyEnd, setVersion, nil), true
}

// One page's call: page's rows as registrations within [keyStart, keyEnd), nil being the start or the end of all keys.
func (self *socketRegistrarState) pageCall(page []*socketRegistrarSendRow, keyStart []byte, keyEnd []byte, setVersion uint64, round *socketRegistrarRound) *socketRegistrarCall {
	args := &SocketRegistrationsArgs{
		SetVersion:    setVersion,
		KeyStart:      bytes.Clone(keyStart),
		KeyEnd:        bytes.Clone(keyEnd),
		Registrations: make([]*SocketRegistration, 0, len(page)),
	}
	inflights := make([]int, 0, len(page))
	for _, sendRow := range page {
		args.Registrations = append(args.Registrations, sendRow.entry.registration(sendRow.row))
		inflights = append(inflights, sendRow.entry.inflight)
	}
	return &socketRegistrarCall{
		args:          args,
		rows:          slices.Clone(page),
		inflights:     inflights,
		round:         round,
		keyEnd:        bytes.Clone(keyEnd),
		attachmentSeq: self.attachmentSeq,
	}
}

// Applies the answer to call, sent at sentAt and answered at receivedAt, and says what owners are to hear. An answer
// to an attachment that has ended changes nothing: the next attachment sends the whole set.
func (self *socketRegistrarState) finish(call *socketRegistrarCall, result *SocketRegistrationsResult, err error, sentAt time.Time, receivedAt time.Time) []*socketRegistrarEffect {
	if !self.attached || call.attachmentSeq != self.attachmentSeq {
		return nil
	}
	if err != nil {
		retryAfterMs := uint32(0)
		var apiErr *SidecarApiError
		if errors.As(err, &apiErr) {
			retryAfterMs = apiErr.RetryAfterMs
		}
		self.fail(receivedAt, retryAfterMs)
		return nil
	}
	if result == nil {
		self.fail(receivedAt, 0)
		return nil
	}
	if result.Error != nil {
		switch result.Error.Code {
		case SocketErrorCodeStale:
			self.stale(receivedAt, result.SetVersion)
		case SocketErrorCodeUnavailable:
			self.fail(receivedAt, result.Error.RetryAfterMs)
		default:
			// invalid, or a code this client does not know: the page cannot go as it is, so the set goes again after a
			// backoff
			self.fail(receivedAt, 0)
		}
		return nil
	}
	if len(result.Statuses) != len(call.rows) {
		self.fail(receivedAt, 0)
		return nil
	}

	self.failureCount = 0
	self.staleCount = 0
	self.updateAdmission(result, sentAt, receivedAt)
	effects := []*socketRegistrarEffect{}
	for index, sendRow := range call.rows {
		entry := sendRow.entry
		if self.entries[entry.listenId] != entry {
			// unlistened meanwhile
			continue
		}
		current := 0 < len(entry.rows) && entry.rows[0] == sendRow.row
		previous := 1 < len(entry.rows) && entry.rows[1] == sendRow.row
		if !current && !previous {
			// its rows were made again meanwhile, and the round that asked for answers for the new ones
			continue
		}
		status := result.Statuses[index]
		switch {
		case status == SocketRegistrationStatusOk && previous:
		case status == SocketRegistrationStatusOk:
			entry.reportedInflight = call.inflights[index]
			if !self.eagerMoved(entry) {
				entry.eagerSince = time.Time{}
			} else if entry.eagerSince.IsZero() {
				// it moved again while the call was out
				entry.eagerSince = receivedAt
			}
			if !entry.answered {
				entry.answered = true
				effects = append(effects, &socketRegistrarEffect{owner: entry.owner, status: status, first: true})
			}
		case previous:
			// a refused previous path stops alone: the newest decides the entry (plan-SOCK-ksock-rotation)
			entry.previousRefused = true
		default:
			// no lease, whatever the status says, an unknown one included
			self.dropEntry(entry)
			effects = append(effects, &socketRegistrarEffect{owner: entry.owner, status: status, first: !entry.answered})
		}
	}
	if call.round != nil && call.round == self.round {
		if call.keyEnd != nil {
			self.round.keyStart = call.keyEnd
		} else {
			self.serverMayHold = self.round.sentAny
			self.round = nil
			self.heartbeatAt = time.Time{}
			if 0 < len(self.entries) || self.serverMayHold {
				self.heartbeatAt = receivedAt.Add(self.jittered(self.settings.HeartbeatInterval))
			}
		}
	}
	return effects
}

// A failed call: the set goes again after retry_after_ms, when given, up to RetryAfterMaxWait, else after a doubling
// backoff. No entry changes, since lease expiry stops tickets and not streams (§9.5).
func (self *socketRegistrarState) fail(now time.Time, retryAfterMs uint32) {
	self.round = nil
	self.roundPending = true
	if 0 < retryAfterMs {
		self.retryAt = now.Add(min(time.Duration(retryAfterMs)*time.Millisecond, self.settings.RetryAfterMaxWait))
		return
	}
	self.failureCount += 1
	self.retryAt = now.Add(self.backoff(self.failureCount))
}

// A page older than the stored set: jump past the stored set_version the answer returns, at once the first time, then
// after a backoff, so a service that keeps answering stale cannot make the registrar spin.
func (self *socketRegistrarState) stale(now time.Time, storedSetVersion uint64) {
	self.round = nil
	self.roundPending = true
	self.setVersion = max(self.setVersion, storedSetVersion)
	self.staleCount += 1
	if 1 < self.staleCount {
		self.retryAt = now.Add(self.backoff(self.staleCount - 1))
	}
}

// Keeps what an answer that refused nothing gives admission, in place of what the one before gave. A server_time of
// 0, or past an int64, is none given, and the offset before stands.
func (self *socketRegistrarState) updateAdmission(result *SocketRegistrationsResult, sentAt time.Time, receivedAt time.Time) {
	self.admission.known = true
	ticketKeys := []*SocketTicketKey{}
	for _, ticketKey := range result.TicketKeys {
		if ticketKey != nil {
			keyClone := *ticketKey
			keyClone.PublicKey = bytes.Clone(ticketKey.PublicKey)
			ticketKeys = append(ticketKeys, &keyClone)
		}
	}
	self.admission.ticketKeys = ticketKeys
	if 0 < result.ServerTimeMillis && result.ServerTimeMillis <= math.MaxInt64 {
		// the service read its clock somewhere in the call: the midpoint halves the error the round trip leaves
		midpointMillis := sentAt.UnixMilli() + (receivedAt.UnixMilli()-sentAt.UnixMilli())/2
		self.admission.serverTimeOffsetMillis = int64(result.ServerTimeMillis) - midpointMillis
	}
	self.admission.urnetworkEdge = nil
	if result.UrnetworkEdge != nil {
		urnetworkEdge := Id(*result.UrnetworkEdge)
		self.admission.urnetworkEdge = &urnetworkEdge
	}
	self.admission.streamsStopped = result.StreamsStopped
}

// One Listen's registration as its listener holds it (SOCK-M5-11): its verdict, its flags, its load, and its end.
type socketRegistration struct {
	registrar   *socketRegistrar
	listenId    Id
	ended       func(status SocketRegistrationStatus)
	drainHinted func()

	// closed once the service's first verdict is in, or the entry or the registrar ends without one
	verdictDone   chan struct{}
	verdictOnce   sync.Once
	verdictStatus SocketRegistrationStatus
	verdictErr    error
}

// The service's first verdict on the entry: ok, or the refusal that took it out of the set, which a Listen returns
// as its error. A failed call is no verdict, since the registrar keeps trying, so this waits until ctx ends, the entry
// is removed or the registrar closes, each an error.
func (self *socketRegistration) verdict(ctx context.Context) (SocketRegistrationStatus, error) {
	select {
	case <-self.verdictDone:
		return self.verdictStatus, self.verdictErr
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Sets the verdict, the first time only.
func (self *socketRegistration) resolve(status SocketRegistrationStatus, err error) {
	self.verdictOnce.Do(func() {
		self.verdictStatus = status
		self.verdictErr = err
		close(self.verdictDone)
	})
}

// §9.9's SetServing: false keeps the lease and takes no tickets (§9.5).
func (self *socketRegistration) setServing(serving bool) {
	self.registrar.update(func(state *socketRegistrarState) bool {
		return state.setServing(self.listenId, serving)
	})
}

// Drain's flag: no new tickets, issued ones accepted (§9.5).
func (self *socketRegistration) setDraining(draining bool) {
	self.registrar.update(func(state *socketRegistrarState) bool {
		return state.setDraining(self.listenId, draining)
	})
}

// The entry's streams in flight, which each later call reports, early when they moved enough.
func (self *socketRegistration) setInflight(inflight int) {
	now := self.registrar.clock.Now()
	self.registrar.update(func(state *socketRegistrarState) bool {
		return state.setInflight(self.listenId, inflight, now)
	})
}

// Unlistens: the entry leaves the set, which goes at once without it (§9.5), and a wait for its verdict ends.
func (self *socketRegistration) remove() {
	self.registrar.update(func(state *socketRegistrarState) bool {
		return state.removeEntry(self.listenId)
	})
	self.resolve("", errSocketRegistrationRemoved)
}

// What newSocketRegistrar takes.
type socketRegistrarArgs struct {
	// The sidecar's network, which every claim names.
	NetworkId Id
	Settings  *SidecarSocketSettings
	// Sidecar.Sign.
	Sign socketSignFunction
	// nil is real time.
	Clock Clock
	// nil is the default logger.
	Log Logger
	// A uniform draw from [0, 1) for jitter. nil is math/rand/v2's.
	Random func() float64
}

// The attached generation's call and the context it ends with.
type socketRegistrarAttachment struct {
	ctx           context.Context
	registrations socketRegistrationsFunction
	seq           uint64
}

// The registrar: the state behind its lock, and the loop that makes its calls. See the file header.
type socketRegistrar struct {
	ctx       context.Context
	cancel    context.CancelFunc
	networkId Id
	settings  *SidecarSocketSettings
	sign      socketSignFunction
	clock     Clock
	log       Logger
	// a count each change bumps, read with its channel armed at the same instant
	wakes *MonitorValue[uint64]
	// how many times the loop has gone to wait, having nothing left to do at that time: what a schedule reads before
	// it moves the clock
	waitCount *MonitorValue[uint64]
	// closed once run has returned
	done chan struct{}

	stateLock sync.Mutex
	state     *socketRegistrarState
	// nil while no generation is attached
	attachment *socketRegistrarAttachment
	// the identity key claims are signed by, nil before the first attachment
	identityPublicKey []byte
	closed            bool
}

// A running registrar for args, ended by close or by ctx.
func newSocketRegistrar(ctx context.Context, args *socketRegistrarArgs) (*socketRegistrar, error) {
	if args == nil || args.Settings == nil || args.Sign == nil || args.NetworkId == (Id{}) {
		return nil, fmt.Errorf("%w: a registrar needs its network, settings and Sign", errInvalidSettings)
	}
	if err := checkSettingsNumbers("Sockets", reflect.ValueOf(args.Settings).Elem(), false); err != nil {
		return nil, err
	}
	if err := args.Settings.validate(); err != nil {
		return nil, err
	}
	random := args.Random
	if random == nil {
		random = rand.Float64
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &socketRegistrar{
		ctx:       cancelCtx,
		cancel:    cancel,
		networkId: args.NetworkId,
		settings:  args.Settings,
		sign:      args.Sign,
		clock:     clockOrReal(args.Clock),
		log:       loggerOrDefault(args.Log),
		wakes:     NewMonitorValue[uint64](0),
		waitCount: NewMonitorValue[uint64](0),
		done:      make(chan struct{}),
		state:     newSocketRegistrarState(args.Settings, random),
	}
	go self.run()
	return self, nil
}

// Asks the loop to look again.
func (self *socketRegistrar) wake() {
	self.wakes.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// Runs change on the state under the lock and wakes the loop when it says so.
func (self *socketRegistrar) update(change func(state *socketRegistrarState) bool) bool {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return change(self.state)
	}()
	if changed {
		self.wake()
	}
	return changed
}

// Adds one Listen to the set, which goes at once. Its rows are made here, outside the lock, so a claim that cannot be
// signed, as while Locked, or a blinded name with no ring refuses the Listen at once.
func (self *socketRegistrar) add(args *socketRegistrationArgs) (*socketRegistration, error) {
	entry, err := newSocketRegistrarEntry(args)
	if err != nil {
		return nil, err
	}
	owner := &socketRegistration{
		registrar:   self,
		listenId:    entry.listenId,
		ended:       args.Ended,
		drainHinted: args.DrainHinted,
		verdictDone: make(chan struct{}),
	}
	entry.owner = owner
	var ring *SocketKeyRing
	var ringEpoch, identityEpoch uint64
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ring = self.state.ring
		ringEpoch = self.state.ringEpoch
		identityEpoch = self.state.identityEpoch
		return self.closed
	}()
	if closed {
		return nil, errSocketRegistrarClosed
	}
	rows, err := makeSocketRegistrarRows(self.networkId, self.sign, entry, ring, self.clock.Now().UnixMilli(), nil, identityEpoch)
	if err != nil {
		return nil, err
	}
	entry.setRows(rows, ring, ringEpoch, identityEpoch)
	err = func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return errSocketRegistrarClosed
		}
		return self.state.addEntry(entry)
	}()
	if err != nil {
		return nil, err
	}
	self.wake()
	return owner, nil
}

// Installs the newest K_sock ring of this network's verified config head (§7.9): blinded names' rows are made again
// under it, signing only paths not claimed before, and the set goes at once. A ring of another network is refused.
func (self *socketRegistrar) setKeyRing(ring *SocketKeyRing) error {
	if ring == nil || ring.Current().networkId != self.networkId {
		return fmt.Errorf("%w: a socket key ring of another network", errInvalidSettings)
	}
	self.update(func(state *socketRegistrarState) bool {
		state.setRing(ring)
		return true
	})
	return nil
}

// Follows one client generation: calls go through registrations until ctx ends or a later attach replaces it, and the
// whole set goes at once. identityPublicKey is the generation's identity key, and a new one has every claim signed
// again. The answer names the attachment for detach.
func (self *socketRegistrar) attach(ctx context.Context, registrations socketRegistrationsFunction, identityPublicKey []byte) uint64 {
	attachmentSeq := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.identityPublicKey != nil && !bytes.Equal(self.identityPublicKey, identityPublicKey) {
			self.state.newIdentity()
		}
		self.identityPublicKey = bytes.Clone(identityPublicKey)
		attachmentSeq := self.state.attach()
		self.attachment = &socketRegistrarAttachment{ctx: ctx, registrations: registrations, seq: attachmentSeq}
		return attachmentSeq
	}()
	self.wake()
	return attachmentSeq
}

// The generation attach answered attachmentSeq for has ended. A later one is left as it is.
func (self *socketRegistrar) detach(attachmentSeq uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.detach(attachmentSeq) {
		self.attachment = nil
	}
}

// A notice on topic sock (§6.8), on the push's goroutine, so it never blocks.
func (self *socketRegistrar) hint(notice PushNotice) {
	if notice.Topic != PushTopicSock {
		return
	}
	var drainListenId *Id
	if notice.Kind == uint32(protocol.MessageType_SOCKET_HINT) && 0 < len(notice.Hint) {
		socketHint := &protocol.SocketHint{}
		if proto.Unmarshal(notice.Hint, socketHint) == nil && socketHint.GetKind() == protocol.SocketHintKind_SOCKET_HINT_DRAIN {
			if listenId, err := IdFromBytes(socketHint.GetListenId()); err == nil {
				drainListenId = &listenId
			}
		}
	}
	self.update(func(state *socketRegistrarState) bool {
		state.hint(drainListenId)
		return true
	})
}

// A copy of what the newest answer gave admission (§9.6).
func (self *socketRegistrar) admission() *socketAdmissionState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.admission.clone()
}

// Ends the loop and answers every Listen still waiting for its verdict. The service's leases lapse in 45 s (§9.5).
func (self *socketRegistrar) close() {
	owners := func() []*socketRegistration {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		self.state.detach(self.state.attachmentSeq)
		self.attachment = nil
		owners := []*socketRegistration{}
		for _, entry := range self.state.entries {
			owners = append(owners, entry.owner)
		}
		return owners
	}()
	self.cancel()
	<-self.done
	for _, owner := range owners {
		owner.resolve("", errSocketRegistrarClosed)
	}
}

// The loop: subscribe, remake what a new ring or key left stale, hand hints' effects on, then make the one call due or
// wait for a change or the next time the state names. One call at a time, by construction.
func (self *socketRegistrar) run() {
	defer close(self.done)
	for {
		_, wakeChanged := self.wakes.Get()
		if self.ctx.Err() != nil {
			return
		}
		now := self.clock.Now()
		self.remake(now)
		self.deliver(func() []*socketRegistrarEffect {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.state.takeEffects()
		}())

		var call *socketRegistrarCall
		var attachment *socketRegistrarAttachment
		var wakeAt time.Time
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			call, wakeAt = self.state.next(now)
			attachment = self.attachment
		}()
		if call != nil && attachment != nil {
			result, sentAt, receivedAt, err := self.send(attachment, call)
			effects := func() []*socketRegistrarEffect {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.state.finish(call, result, err, sentAt, receivedAt)
			}()
			self.logAnswer(call, result, err)
			self.deliver(effects)
			continue
		}

		stop := func() bool { return false }
		if !wakeAt.IsZero() {
			stop = self.clock.AfterFunc(wakeAt.Sub(now), self.wake)
		}
		self.waitCount.Update(func(count uint64) uint64 {
			return count + 1
		})
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-wakeChanged:
			stop()
		}
	}
}

// One call through attachment, bounded by RequestTimeout on the registrar's clock, between barriers (§22.4): the
// answer is where a page's set_version becomes the stored one.
func (self *socketRegistrar) send(attachment *socketRegistrarAttachment, call *socketRegistrarCall) (*SocketRegistrationsResult, time.Time, time.Time, error) {
	callCtx, cancel := context.WithCancel(attachment.ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.RequestTimeout, cancel)
	defer stop()
	sentAt := self.clock.Now()
	testHookBarrier("socket.registrations.before", "")
	result, err := attachment.registrations(callCtx, call.args)
	testHookBarrier("socket.registrations.after", "")
	return result, sentAt, self.clock.Now(), err
}

// Makes again, outside the lock, the rows of each entry a new ring or identity key left stale, and installs them. A
// failure, as a Locked sidecar's signing, leaves the old rows going and tries again after RetryMaxInterval.
func (self *socketRegistrar) remake(now time.Time) {
	type remakeJob struct {
		entry *socketRegistrarEntry
		reuse []*socketRegistrarRow
		rows  []*socketRegistrarRow
		err   error
	}
	jobs := []*remakeJob{}
	var ring *SocketKeyRing
	var ringEpoch, identityEpoch uint64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.state.rowsStale || now.Before(self.state.remakeAt) {
			return
		}
		ring = self.state.ring
		ringEpoch = self.state.ringEpoch
		identityEpoch = self.state.identityEpoch
		for _, entry := range self.state.entries {
			if !self.state.rowsCurrent(entry) {
				jobs = append(jobs, &remakeJob{entry: entry, reuse: slices.Clone(entry.rows)})
			}
		}
		if len(jobs) == 0 {
			self.state.rowsStale = false
		}
	}()
	if len(jobs) == 0 {
		return
	}
	failed := false
	for _, job := range jobs {
		// an entry's name, namespace and claim fields are fixed at add, so they are read here without the lock
		job.rows, job.err = makeSocketRegistrarRows(self.networkId, self.sign, job.entry, ring, now.UnixMilli(), job.reuse, identityEpoch)
		if job.err != nil {
			failed = true
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, job := range jobs {
			if job.err == nil {
				self.state.installRows(job.entry, job.rows, ring, ringEpoch, identityEpoch)
			}
		}
		self.state.settleRows(now, failed)
	}()
	if failed {
		self.log.Warningf("[sockets]registrations' rows could not be made again; the old ones go on\n")
	}
}

// Hands effects to their owners, on this goroutine, outside every lock.
func (self *socketRegistrar) deliver(effects []*socketRegistrarEffect) {
	for _, effect := range effects {
		switch {
		case effect.drain:
			if effect.owner.drainHinted != nil {
				effect.owner.drainHinted()
			}
		case effect.first:
			effect.owner.resolve(effect.status, nil)
		case effect.owner.ended != nil:
			effect.owner.ended(effect.status)
		}
	}
}

// What a call came to, in counts and codes: never a name (I-13), and a code the service sent only when it is one.
func (self *socketRegistrar) logAnswer(call *socketRegistrarCall, result *SocketRegistrationsResult, err error) {
	switch {
	case err != nil:
		self.log.Warningf("[sockets]registrations failed: %s\n", err)
	case result == nil:
	case result.Error != nil && result.Error.Code != SocketErrorCodeStale && result.Error.Code != SocketErrorCodeUnavailable:
		code := "unknown"
		if isSidecarApiCode(string(result.Error.Code)) {
			code = string(result.Error.Code)
		}
		self.log.Errorf("[sockets]a registrations page of %d entries refused: %s\n", len(call.rows), code)
	case self.log.V(2).Enabled():
		self.log.Infof("[sockets]a registrations page of %d entries answered\n", len(call.rows))
	}
}
