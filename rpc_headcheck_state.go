// §6.4's HeadCheck rows as a pure machine (D-PROTO-14, D-PROTO-17): a device's head check state, with a
// peer's message or the outcome of an act it asked for, goes in; the new state, the acts to run and
// what was found come out. Nothing here does I/O or blocks. The state's own fields and the sources'
// reads (rpc_headcheck_sources.go) are all it reads, so every row runs on fakes while §7.9, §10 and §11
// are unfinished. The transport (PROTO-M2-03) runs the acts with no lock held and feeds each outcome
// back; HeadStopState (PROTO-M2-04) persists the state and turns what was found into alarms and stops.
//
// The rows, as the machine holds them:
//
//   - auth: a peer's pin at a position this device keeps must carry the same A there, else a fork,
//     after which this device sends the peer's pin as proven. Ahead of it, the entries come from api
//     through the pin; failing that by HeadCheckFetchTimeout, from the peer's HeadCheckProof, which,
//     verified, is proof of withholding: sealing stops at once in shared groups, the tip rides on as
//     proven and the stop lasts until api serves it. With neither the pin is UNVERIFIED, the peer its
//     claimant, until this device reaches it, the claimant withdraws it or is revoked or parked; and if
//     api later serves another A at that position, it is the fork the auth row says.
//   - proven: the same rows, except that a conflict no proof shows is UNVERIFIED, not a fork.
//   - relay: each relayed copy gets the sender appended to its path and is ignored if the path then
//     holds this device or more than eight. Unless this device already holds that pin, the copy is held
//     UNVERIFIED at once, never as its pin, while the auth rows try to resolve it, and it clears when this
//     device reaches it or a sidecar on its path is revoked or parked (rpc_headcheck_relay.go).
//   - gens, refs: at the same position, the same commitment, else a fork; the lower side reads up,
//     through its source, and the higher does nothing.
//   - groups: at the same epoch, the same epoch_authenticator, else a fork.
//   - vetoes: each goes to the auth source, which acts by §7.9's precedence rule.
//
// Positions compare wherever this device keeps a digest, not only at its own n: a conflict at any kept
// position is the same fork (I-16), so a peer behind it on another chain forks too.
//
// A witness never refreshes a pin it did not reconcile: witnessDecision is §6.4's witness row exactly,
// and is asked only once an exchange's acts have run.
//
// A state is a value. Every transition copies what it changes and leaves its argument as it was, so a
// caller commits the result or drops it. Not safe for concurrent use: one network's transitions run one
// at a time, under HeadStopState's lock.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A message that breaks §6.5's bounds or shapes, or names another network. The transport answers
	// Error{INVALID_ARGUMENT}, and nothing in it counts, a witness least of all.
	errHeadCheckMalformed = errors.New("head check message malformed")
	// A message from a sidecar this device's state does not hold admitted and standing, or from itself.
	errHeadCheckPeer = errors.New("head check from no standing peer")
	// This device holds no verified state, so it has nothing to compare.
	errHeadCheckNoState = errors.New("head check with no verified state")
)

// What a fork is in, which says what it stops (§6.4's FORK row).
type HeadForkKind int

const (
	// The authorization log: stops sealing in every shared group.
	HeadForkAuth HeadForkKind = 1
	// A repo's generation chain (§10.5): stops its group.
	HeadForkGen HeadForkKind = 2
	// An MLS epoch (§10.4): stops the group.
	HeadForkGroup HeadForkKind = 3
	// A ref's chain (§11.8): stops the group of the ref's repo.
	HeadForkRef HeadForkKind = 4
)

// A fork, with the evidence §6.4's FORK row alarms with.
type HeadFork struct {
	Kind HeadForkKind
	// The group a gen, group or ref fork stops. Zero for auth.
	GroupId Id
	// This device's pin and the conflicting one, each encoded as §6.5 does (an AuthPin, GenHead,
	// GroupHead or RefHead), deterministically.
	Local  []byte
	Remote []byte
	// The peer whose pin forks, or the prover a proof's fork names. Nil for a fork no peer showed, as
	// ConfigLog's own.
	PeerId *Id
}

// The fields HeadCheck and HeadCheckResult share (§6.5: the same fields and numbers), as their
// generated getters read them.
type headCheckMessage interface {
	GetNetworkId() []byte
	GetAuth() *bridge.AuthPin
	GetGroups() []*protocol.GroupHead
	GetGens() []*protocol.GenHead
	GetRefs() []*protocol.RefHead
	GetVetoes() [][]byte
	GetProven() *bridge.AuthPin
	GetUnverified() []*protocol.UnverifiedPin
}

// One UNVERIFIED pin this device holds (§6.4's relay row).
type headCheckUnverified struct {
	pin *bridge.AuthPin
	// The claimant, then each relayer, ending with the peer this device took it from. Never empty,
	// never this device, at most HeadCheckMaxPathCount.
	path []Id
	// Held from the claimant's own auth pin, where api serving another A later is a fork. False for a
	// proven pin or a relayed copy, where a conflict stays UNVERIFIED.
	direct bool
	// When this device first held it.
	since time.Time
}

// The peer this device took the pin from: the path's last.
func (self *headCheckUnverified) peerId() Id {
	return self.path[len(self.path)-1]
}

// A pin this device sends as HeadCheck.proven: a withheld tip, or the pin an auth fork is with.
type headCheckProven struct {
	pin *bridge.AuthPin
	// For a withheld tip, the proof this device verified, which it serves while it holds the tip.
	// Empty for a fork.
	proof [][]byte
	// The peer that served the proof, or whose pin forks.
	peerId Id
	since  time.Time
}

// A pin past this device's that it is fetching from api (§6.4's auth row).
type headCheckFetch struct {
	pin *bridge.AuthPin
	// Who claimed it, whom an unserved fetch asks for a proof: the peer that sent it, or a relayed
	// copy's claimant.
	claimantId Id
	// The path it is held under if no one resolves it.
	path []Id
	// From a peer's own auth pin, where a conflict is a fork; else a conflict is UNVERIFIED.
	direct bool
	// When api must have served it by, after which the claimant is asked.
	deadline time.Time
	asked    bool
}

// What the machine keeps for one network between exchanges. HeadStopState persists unverified,
// withheld and forked; fetches live in memory and start again after a restart, at the next exchange or
// round.
type headCheckState struct {
	// Highest first, unique by pin, at most HeadCheckMaxUnverifiedCount, HeadCheckMaxUnverifiedPeerCount
	// of them taken from one peer.
	unverified []*headCheckUnverified
	// Proof of withholding (§6.4): api withholds the entries through this pin, which its proof chains to.
	// Sealing in shared groups stops until api serves them.
	withheld *headCheckProven
	// The first pin an auth fork was with, sent as proven while no tip is withheld. HeadStopState holds
	// the fork's stop; this is only what the relay carries, until the fork's peer is revoked or parked.
	forked *headCheckProven
	// Highest first, unique by pin, at most HeadCheckMaxUnverifiedCount.
	fetches []*headCheckFetch
}

// A copy sharing nothing a transition changes.
func (self headCheckState) clone() headCheckState {
	next := headCheckState{
		unverified: make([]*headCheckUnverified, 0, len(self.unverified)),
		fetches:    make([]*headCheckFetch, 0, len(self.fetches)),
	}
	for _, held := range self.unverified {
		heldCopy := *held
		heldCopy.path = slices.Clone(held.path)
		next.unverified = append(next.unverified, &heldCopy)
	}
	provenCopy := func(proven *headCheckProven) *headCheckProven {
		if proven == nil {
			return nil
		}
		copied := *proven
		copied.proof = slices.Clone(proven.proof)
		return &copied
	}
	next.withheld = provenCopy(self.withheld)
	next.forked = provenCopy(self.forked)
	for _, fetch := range self.fetches {
		fetchCopy := *fetch
		fetchCopy.path = slices.Clone(fetch.path)
		next.fetches = append(next.fetches, &fetchCopy)
	}
	return next
}

// What the machine reads of this device: who it is, its sources, its settings and the time.
type headCheckMine struct {
	sidecarId Id
	networkId Id
	sources   *HeadCheckSources
	settings  *SidecarProtocolSettings
	now       time.Time
}

// The kinds of act a transition asks the transport to run.
type headCheckActKind int

const (
	// Fetch the entries through pin from api with HeadCheckAuthSource.FetchAuth, trying until
	// deadline, then feed headCheckFetched.
	headCheckActFetch headCheckActKind = 1
	// Send peerId HeadCheckProofRequest{after}, check what it answers with VerifyAuthProof, then feed
	// headCheckProved.
	headCheckActAskProof headCheckActKind = 2
	// Read gen/ up to gen with HeadCheckGenSource.CatchUpGen, then feed headCheckCaughtUp.
	headCheckActCatchUpGen headCheckActKind = 3
	// Read the ref's statements up to ref with HeadCheckRefSource.CatchUpRef, then feed
	// headCheckCaughtUp.
	headCheckActCatchUpRef headCheckActKind = 4
	// Hand veto, from peerId, to HeadCheckAuthSource.HoldVeto.
	headCheckActHoldVeto headCheckActKind = 5
)

// One act. Which fields are set follows its kind.
type headCheckAct struct {
	kind     headCheckActKind
	peerId   Id
	pin      *bridge.AuthPin
	deadline time.Time
	after    uint64
	gen      *protocol.GenHead
	ref      *protocol.RefHead
	veto     []byte
}

// What one transition found and asks for.
type headCheckStep struct {
	// In order, each with no lock held.
	acts []headCheckAct
	// For HeadStopState.ReportFork: each alarms, and stops sealing in what it is in.
	forks []HeadFork
	// Proof of withholding this transition took up: alarm withheld and stop in shared groups at once.
	withheld *headCheckProven
	// Set when api served the withheld tip, which ends that stop.
	served bool
	// UNVERIFIED pins first held here, each of which alarms.
	unverified []*headCheckUnverified
	// Whether a field forked, for witnessDecision.
	forked bool
}

// How a pin stands against this device's chain.
type headCheckRelation int

const (
	// It is this device's pin.
	headCheckRelationSame headCheckRelation = 1
	// Behind this device's pin, on its chain at a position it keeps.
	headCheckRelationOnChain headCheckRelation = 2
	// Behind it, at a position this device keeps no digest for, so neither on its chain nor off it.
	headCheckRelationUnkept headCheckRelation = 3
	// At a position this device keeps, with another digest: a fork, or UNVERIFIED where no proof shows it.
	headCheckRelationConflict headCheckRelation = 4
	// Past this device's pin.
	headCheckRelationAhead headCheckRelation = 5
)

// pin against myPin, reading the digests behind it from auth.
func headCheckRelate(auth HeadCheckAuthSource, myPin *bridge.AuthPin, pin *bridge.AuthPin) headCheckRelation {
	switch {
	case myPin.GetVersion() < pin.GetVersion():
		return headCheckRelationAhead
	case myPin.GetVersion() == pin.GetVersion():
		if bytes.Equal(myPin.GetChain(), pin.GetChain()) {
			return headCheckRelationSame
		}
		return headCheckRelationConflict
	}
	chain, kept := auth.ChainAt(pin.GetVersion())
	switch {
	case !kept:
		return headCheckRelationUnkept
	case bytes.Equal(chain, pin.GetChain()):
		return headCheckRelationOnChain
	}
	return headCheckRelationConflict
}

// Whether two pins are one: the same position and digest.
func headCheckPinEqual(a *bridge.AuthPin, b *bridge.AuthPin) bool {
	return a.GetVersion() == b.GetVersion() && bytes.Equal(a.GetChain(), b.GetChain())
}

// Highest first: the higher position, then the lower digest, so two holders order alike.
func headCheckPinCompare(a *bridge.AuthPin, b *bridge.AuthPin) int {
	switch {
	case a.GetVersion() > b.GetVersion():
		return -1
	case a.GetVersion() < b.GetVersion():
		return 1
	}
	return bytes.Compare(a.GetChain(), b.GetChain())
}

// A copy of an AuthPin's two fields, dropping anything unknown it carried.
func headCheckPinCopy(pin *bridge.AuthPin) *bridge.AuthPin {
	return &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())}
}

// message encoded as §6.5 does, deterministically, for a fork's or an alarm's evidence.
func headCheckEvidence(message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		// a message of known bytes and integers always encodes
		panic(err)
	}
	return encoded
}

// This device's pin at version, as a fork's local evidence. myPin when version is its own.
func headCheckLocalPin(auth HeadCheckAuthSource, myPin *bridge.AuthPin, version uint64) *bridge.AuthPin {
	if version == myPin.GetVersion() {
		return headCheckPinCopy(myPin)
	}
	chain, _ := auth.ChainAt(version)
	return &bridge.AuthPin{Version: version, Chain: bytes.Clone(chain)}
}

// Whether a pin has the shape §7.9 gives it: a 32-byte digest.
func headCheckPinValid(pin *bridge.AuthPin) bool {
	return pin != nil && len(pin.GetChain()) == headCheckDigestByteCount
}

// Whether every id is an Id's 16 bytes.
func headCheckIdsValid(idBytesList ...[]byte) bool {
	for _, idBytes := range idBytesList {
		if len(idBytes) != len(Id{}) {
			return false
		}
	}
	return true
}

// Refuses a message past §6.5's bounds or off its shapes, or of another network. Each list item must
// name a well-formed id and digest, and none may repeat, since a repeat would be compared twice.
func headCheckValidate(mine *headCheckMine, message headCheckMessage) error {
	malformed := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", errHeadCheckMalformed, fmt.Sprintf(format, a...))
	}
	switch {
	case !bytes.Equal(message.GetNetworkId(), mine.networkId.Bytes()):
		return malformed("another network")
	case !headCheckPinValid(message.GetAuth()):
		return malformed("auth pin")
	case message.GetProven() != nil && !headCheckPinValid(message.GetProven()):
		return malformed("proven pin")
	case HeadCheckMaxListCount < len(message.GetGroups()), HeadCheckMaxListCount < len(message.GetGens()),
		HeadCheckMaxListCount < len(message.GetRefs()):
		return malformed("a list past %d", HeadCheckMaxListCount)
	case HeadCheckMaxVetoCount < len(message.GetVetoes()):
		return malformed("vetoes past %d", HeadCheckMaxVetoCount)
	case HeadCheckMaxUnverifiedSendCount < len(message.GetUnverified()):
		return malformed("unverified past %d", HeadCheckMaxUnverifiedSendCount)
	}
	groupIds := map[string]bool{}
	for _, group := range message.GetGroups() {
		authenticatorByteCount := len(group.GetEpochAuthenticator())
		if !headCheckIdsValid(group.GetGroupId()) || authenticatorByteCount == 0 ||
			headCheckMaxAuthenticatorByteCount < authenticatorByteCount || groupIds[string(group.GetGroupId())] {
			return malformed("group head")
		}
		groupIds[string(group.GetGroupId())] = true
	}
	genIds := map[string]bool{}
	for _, gen := range message.GetGens() {
		if !headCheckIdsValid(gen.GetGroupId()) || len(gen.GetCommitment()) != headCheckDigestByteCount ||
			genIds[string(gen.GetGroupId())] {
			return malformed("gen head")
		}
		genIds[string(gen.GetGroupId())] = true
	}
	refIds := map[string]bool{}
	for _, ref := range message.GetRefs() {
		refKey := string(ref.GetRepoId()) + string(ref.GetRefId())
		if !headCheckIdsValid(ref.GetRepoId(), ref.GetRefId()) || len(ref.GetChain()) != headCheckDigestByteCount ||
			refIds[refKey] {
			return malformed("ref head")
		}
		refIds[refKey] = true
	}
	for _, veto := range message.GetVetoes() {
		if len(veto) == 0 {
			return malformed("empty veto")
		}
	}
	// a path too long is a copy the relay row ignores, not a malformed message; one with no claimant is
	for _, relayedCopy := range message.GetUnverified() {
		if !headCheckPinValid(relayedCopy.GetPin()) || len(relayedCopy.GetPath()) == 0 ||
			!headCheckIdsValid(relayedCopy.GetPath()...) {
			return malformed("unverified pin")
		}
	}
	return nil
}

// Whether a sidecar is one §6.4's rows hear from: admitted, neither revoked nor parked. A suspended one
// still answers, and counts as no witness (witnessDecision).
func headCheckStanding(peer HeadCheckPeer) bool {
	return peer.Admitted && !peer.Revoked && !peer.Parked
}

// Reconciles one HeadCheck or HeadCheckResult from peerId against state: §6.4's auth, proven, relay,
// gens, groups, refs and vetoes rows, in that order. A message this refuses changes nothing and
// counts for nothing.
func headCheckReconcile(state headCheckState, mine *headCheckMine, peerId Id, message headCheckMessage) (headCheckState, headCheckStep, error) {
	if err := headCheckValidate(mine, message); err != nil {
		return state, headCheckStep{}, err
	}
	if peerId == mine.sidecarId || !headCheckStanding(mine.sources.Peers.HeadCheckPeer(peerId)) {
		return state, headCheckStep{}, errHeadCheckPeer
	}
	auth := mine.sources.Auth
	myPin := auth.Pin()
	if !headCheckPinValid(myPin) {
		return state, headCheckStep{}, errHeadCheckNoState
	}
	next := state.clone()
	step := headCheckStep{}

	// auth: the peer's own pin
	peerPin := message.GetAuth()
	peerRelation := headCheckRelate(auth, myPin, peerPin)
	switch peerRelation {
	case headCheckRelationConflict:
		next.authFork(mine, myPin, peerPin, peerId, &step)
	case headCheckRelationAhead:
		next.fetch(mine, myPin, peerPin, peerId, []Id{peerId}, true, &step)
	}

	// proven: as the auth rows, but a conflict no proof shows is UNVERIFIED
	if proven := message.GetProven(); proven != nil {
		switch headCheckRelate(auth, myPin, proven) {
		case headCheckRelationConflict:
			next.hold(mine, &headCheckUnverified{pin: headCheckPinCopy(proven), path: []Id{peerId}, since: mine.now}, &step)
		case headCheckRelationAhead:
			next.fetch(mine, myPin, proven, peerId, []Id{peerId}, false, &step)
		}
	}

	// relay: the sender appended, then held UNVERIFIED unless this device already holds the pin
	for _, relayedCopy := range message.GetUnverified() {
		if HeadCheckMaxPathCount < len(relayedCopy.GetPath())+1 {
			continue
		}
		path := make([]Id, 0, len(relayedCopy.GetPath())+1)
		for _, idBytes := range relayedCopy.GetPath() {
			path = append(path, Id(idBytes))
		}
		path = append(path, peerId)
		if slices.Contains(path, mine.sidecarId) {
			continue
		}
		pin := relayedCopy.GetPin()
		switch headCheckRelate(auth, myPin, pin) {
		case headCheckRelationSame, headCheckRelationOnChain:
			continue
		case headCheckRelationAhead:
			next.fetch(mine, myPin, pin, path[0], path, false, &step)
		}
		next.hold(mine, &headCheckUnverified{pin: headCheckPinCopy(pin), path: path, since: mine.now}, &step)
	}

	// a claim the peer made itself and no longer makes, now that it is on this device's chain
	if peerRelation == headCheckRelationSame || peerRelation == headCheckRelationOnChain {
		next.unverified = slices.DeleteFunc(next.unverified, func(held *headCheckUnverified) bool {
			return len(held.path) == 1 && held.path[0] == peerId && !headCheckPinEqual(held.pin, peerPin) &&
				!(message.GetProven() != nil && headCheckPinEqual(held.pin, message.GetProven()))
		})
	}

	// gens: same generation, same C_g; else the lower side reads up
	for _, gen := range message.GetGens() {
		groupId := Id(gen.GetGroupId())
		myGen, held := mine.sources.Gens.GenHead(groupId)
		switch {
		case !held:
		case myGen.GetGeneration() == gen.GetGeneration():
			if !bytes.Equal(myGen.GetCommitment(), gen.GetCommitment()) {
				step.fork(HeadFork{Kind: HeadForkGen, GroupId: groupId, Local: headCheckEvidence(myGen), Remote: headCheckEvidence(gen), PeerId: &peerId})
			}
		case myGen.GetGeneration() < gen.GetGeneration():
			step.acts = append(step.acts, headCheckAct{kind: headCheckActCatchUpGen, peerId: peerId, gen: proto.CloneOf(gen)})
		}
	}

	// groups: same epoch, same epoch_authenticator
	for _, group := range message.GetGroups() {
		groupId := Id(group.GetGroupId())
		myGroup, held := mine.sources.Groups.GroupHead(groupId)
		if held && myGroup.GetEpoch() == group.GetEpoch() && !bytes.Equal(myGroup.GetEpochAuthenticator(), group.GetEpochAuthenticator()) {
			step.fork(HeadFork{Kind: HeadForkGroup, GroupId: groupId, Local: headCheckEvidence(myGroup), Remote: headCheckEvidence(group), PeerId: &peerId})
		}
	}

	// refs: same version, same chain; else the lower side reads up
	for _, ref := range message.GetRefs() {
		myRef, held := mine.sources.Refs.RefHead(Id(ref.GetRepoId()), Id(ref.GetRefId()))
		switch {
		case !held:
		case myRef.Head.GetVersion() == ref.GetVersion():
			if !bytes.Equal(myRef.Head.GetChain(), ref.GetChain()) {
				step.fork(HeadFork{Kind: HeadForkRef, GroupId: myRef.GroupId, Local: headCheckEvidence(myRef.Head), Remote: headCheckEvidence(ref), PeerId: &peerId})
			}
		case myRef.Head.GetVersion() < ref.GetVersion():
			step.acts = append(step.acts, headCheckAct{kind: headCheckActCatchUpRef, peerId: peerId, ref: proto.CloneOf(ref)})
		}
	}

	// vetoes: each to the auth source, which acts by §7.9's precedence rule
	for _, veto := range message.GetVetoes() {
		step.acts = append(step.acts, headCheckAct{kind: headCheckActHoldVeto, peerId: peerId, veto: bytes.Clone(veto)})
	}
	return next, step, nil
}

// Records a fork found here.
func (self *headCheckStep) fork(fork HeadFork) {
	self.forks = append(self.forks, fork)
	self.forked = true
}

// An auth fork with peerId's pin: alarm and stop, and relay that pin as proven, unless an earlier fork's
// pin is relayed already.
func (self *headCheckState) authFork(mine *headCheckMine, myPin *bridge.AuthPin, pin *bridge.AuthPin, peerId Id, step *headCheckStep) {
	local := headCheckLocalPin(mine.sources.Auth, myPin, pin.GetVersion())
	step.fork(HeadFork{Kind: HeadForkAuth, Local: headCheckEvidence(local), Remote: headCheckEvidence(pin), PeerId: &peerId})
	if self.forked == nil {
		self.forked = &headCheckProven{pin: headCheckPinCopy(pin), peerId: peerId, since: mine.now}
	}
}

// Starts fetching pin from api, claimed by claimantId, unless this device already is; and asks the
// claimant for a proof once api is past due. Fetches stay at most HeadCheckMaxUnverifiedCount, the
// lowest going first.
func (self *headCheckState) fetch(mine *headCheckMine, myPin *bridge.AuthPin, pin *bridge.AuthPin, claimantId Id, path []Id, direct bool, step *headCheckStep) {
	for _, fetch := range self.fetches {
		if headCheckPinEqual(fetch.pin, pin) {
			fetch.askIfDue(mine, myPin, step)
			return
		}
	}
	fetch := &headCheckFetch{
		pin:        headCheckPinCopy(pin),
		claimantId: claimantId,
		path:       slices.Clone(path),
		direct:     direct,
		deadline:   mine.now.Add(mine.settings.HeadCheckFetchTimeout),
	}
	self.fetches = append(self.fetches, fetch)
	slices.SortFunc(self.fetches, func(a *headCheckFetch, b *headCheckFetch) int {
		return headCheckPinCompare(a.pin, b.pin)
	})
	if HeadCheckMaxUnverifiedCount < len(self.fetches) {
		dropped := self.fetches[HeadCheckMaxUnverifiedCount]
		self.fetches = self.fetches[:HeadCheckMaxUnverifiedCount]
		if dropped == fetch {
			return
		}
	}
	step.acts = append(step.acts, headCheckAct{kind: headCheckActFetch, peerId: claimantId, pin: headCheckPinCopy(pin), deadline: fetch.deadline})
}

// Asks the claimant for a proof once api is past due, once.
func (self *headCheckFetch) askIfDue(mine *headCheckMine, myPin *bridge.AuthPin, step *headCheckStep) {
	if self.asked || mine.now.Before(self.deadline) {
		return
	}
	self.asked = true
	step.acts = append(step.acts, headCheckAct{kind: headCheckActAskProof, peerId: self.claimantId, pin: headCheckPinCopy(self.pin), after: myPin.GetVersion()})
}

// The fetch of pin, or nil.
func (self *headCheckState) fetchOf(pin *bridge.AuthPin) *headCheckFetch {
	for _, fetch := range self.fetches {
		if headCheckPinEqual(fetch.pin, pin) {
			return fetch
		}
	}
	return nil
}

// Drops the fetch of pin, if any.
func (self *headCheckState) dropFetch(pin *bridge.AuthPin) {
	self.fetches = slices.DeleteFunc(self.fetches, func(fetch *headCheckFetch) bool {
		return headCheckPinEqual(fetch.pin, pin)
	})
}

// After api has served what it will (FetchAuth returned, or its deadline passed): judges every pending
// fetch against this device's pin now. One reached clears what was waiting on it; one api answered with
// another A is a fork for a peer's own pin and UNVERIFIED for a relayed one; one still ahead asks its
// claimant for a proof once past due. The withheld tip ends its stop once served, and is a fork naming
// its prover if api answers another A there.
func headCheckFetched(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep) {
	auth := mine.sources.Auth
	myPin := auth.Pin()
	if !headCheckPinValid(myPin) {
		return state, headCheckStep{}
	}
	next := state.clone()
	step := headCheckStep{}
	pending := next.fetches[:0]
	for _, fetch := range next.fetches {
		switch headCheckRelate(auth, myPin, fetch.pin) {
		case headCheckRelationAhead:
			fetch.askIfDue(mine, myPin, &step)
			pending = append(pending, fetch)
		case headCheckRelationConflict:
			if fetch.direct {
				next.authFork(mine, myPin, fetch.pin, fetch.claimantId, &step)
			} else {
				next.hold(mine, &headCheckUnverified{pin: fetch.pin, path: fetch.path, since: mine.now}, &step)
			}
		case headCheckRelationUnkept:
			// past it with its digest already dropped, which can neither clear nor fork a pin
			if !fetch.direct {
				next.hold(mine, &headCheckUnverified{pin: fetch.pin, path: fetch.path, since: mine.now}, &step)
			}
		}
	}
	next.fetches = pending
	next.servedOrForked(mine, myPin, &step)
	next.sweep(mine, myPin, &step)
	return next, step
}

// Ends a withheld tip's stop once api serves it, or turns it into a fork naming its prover if api
// answers another A at that position (§6.4's FORK row).
func (self *headCheckState) servedOrForked(mine *headCheckMine, myPin *bridge.AuthPin, step *headCheckStep) {
	if self.withheld == nil {
		return
	}
	switch headCheckRelate(mine.sources.Auth, myPin, self.withheld.pin) {
	case headCheckRelationSame, headCheckRelationOnChain, headCheckRelationUnkept:
		self.withheld = nil
		step.served = true
	case headCheckRelationConflict:
		withheld := self.withheld
		self.withheld = nil
		step.served = true
		self.authFork(mine, myPin, withheld.pin, withheld.peerId, step)
	}
}

// After a HeadCheckProof was asked for pin from proverId: verified says whether VerifyAuthProof took
// proof. A verified proof of a pin still ahead is proof of withholding; anything else, an error, a
// NOT_FOUND or a proof that does not verify, leaves the pin UNVERIFIED, the prover its claimant.
func headCheckProved(state headCheckState, mine *headCheckMine, pin *bridge.AuthPin, proverId Id, proof [][]byte, verified bool) (headCheckState, headCheckStep) {
	auth := mine.sources.Auth
	myPin := auth.Pin()
	if !headCheckPinValid(myPin) {
		return state, headCheckStep{}
	}
	if headCheckRelate(auth, myPin, pin) != headCheckRelationAhead {
		// reached or answered by api meanwhile, which the fetch rows judge
		return headCheckFetched(state, mine)
	}
	next := state.clone()
	step := headCheckStep{}
	fetch := next.fetchOf(pin)
	next.dropFetch(pin)
	if verified {
		withheld := &headCheckProven{pin: headCheckPinCopy(pin), proof: slices.Clone(proof), peerId: proverId, since: mine.now}
		// the highest tip is the one relayed; a lower one is api's to serve along the way
		if next.withheld == nil || headCheckPinCompare(pin, next.withheld.pin) < 0 {
			next.withheld = withheld
		}
		next.unverified = slices.DeleteFunc(next.unverified, func(held *headCheckUnverified) bool {
			return headCheckPinEqual(held.pin, pin)
		})
		step.withheld = withheld
		return next, step
	}
	// with no fetch to say how it was claimed, a later conflict stays UNVERIFIED, the lesser denial
	held := &headCheckUnverified{pin: headCheckPinCopy(pin), path: []Id{proverId}, since: mine.now}
	if fetch != nil {
		held.path = slices.Clone(fetch.path)
		held.direct = fetch.direct
	}
	next.hold(mine, held, &step)
	return next, step
}

// After a forward read asked by headCheckActCatchUpGen or headCheckActCatchUpRef: a forked read is a
// fork of that gen or ref, with this device's pin as the source holds it now. A read that reached or
// went unserved changes nothing here.
func headCheckCaughtUp(mine *headCheckMine, act headCheckAct, outcome HeadCheckCatchUp) headCheckStep {
	step := headCheckStep{}
	if outcome != HeadCheckCatchUpForked {
		return step
	}
	peerId := act.peerId
	switch act.kind {
	case headCheckActCatchUpGen:
		groupId := Id(act.gen.GetGroupId())
		local := []byte{}
		if myGen, held := mine.sources.Gens.GenHead(groupId); held {
			local = headCheckEvidence(myGen)
		}
		step.fork(HeadFork{Kind: HeadForkGen, GroupId: groupId, Local: local, Remote: headCheckEvidence(act.gen), PeerId: &peerId})
	case headCheckActCatchUpRef:
		fork := HeadFork{Kind: HeadForkRef, Local: []byte{}, Remote: headCheckEvidence(act.ref), PeerId: &peerId}
		if myRef, held := mine.sources.Refs.RefHead(Id(act.ref.GetRepoId()), Id(act.ref.GetRefId())); held {
			fork.GroupId = myRef.GroupId
			fork.Local = headCheckEvidence(myRef.Head)
		}
		step.fork(fork)
	}
	return step
}

// Each HeadCheckInterval, and at each start: drops what a revocation or this device's own progress
// settled, asks each claimant api is past due for, and retries the auth rows for the highest UNVERIFIED
// pin past this device's and for the withheld tip, so each clears once api serves it (§6.4's auth row).
func headCheckRound(state headCheckState, mine *headCheckMine) (headCheckState, headCheckStep) {
	auth := mine.sources.Auth
	myPin := auth.Pin()
	if !headCheckPinValid(myPin) {
		return state, headCheckStep{}
	}
	next := state.clone()
	step := headCheckStep{}
	next.sweep(mine, myPin, &step)
	for _, fetch := range next.fetches {
		fetch.askIfDue(mine, myPin, &step)
	}
	if next.withheld != nil && next.fetchOf(next.withheld.pin) == nil {
		next.fetch(mine, myPin, next.withheld.pin, next.withheld.peerId, []Id{next.withheld.peerId}, false, &step)
	}
	for _, held := range next.unverified {
		if headCheckRelate(auth, myPin, held.pin) != headCheckRelationAhead {
			continue
		}
		if next.fetchOf(held.pin) == nil {
			next.fetch(mine, myPin, held.pin, held.path[0], held.path, held.direct, &step)
		}
		break
	}
	return next, step
}

// Drops UNVERIFIED pins this device has reached, those with a revoked or parked sidecar on their path,
// and a fork's proven pin once its peer is revoked or parked, the denial §6.4's FORK row bounds. A pin a
// peer claimed itself that api now answers with another A is the auth row's fork.
func (self *headCheckState) sweep(mine *headCheckMine, myPin *bridge.AuthPin, step *headCheckStep) {
	peers := mine.sources.Peers
	settled := func(sidecarId Id) bool {
		peer := peers.HeadCheckPeer(sidecarId)
		return peer.Revoked || peer.Parked
	}
	forks := []*headCheckUnverified{}
	self.unverified = slices.DeleteFunc(self.unverified, func(held *headCheckUnverified) bool {
		if slices.ContainsFunc(held.path, settled) {
			return true
		}
		switch headCheckRelate(mine.sources.Auth, myPin, held.pin) {
		case headCheckRelationSame, headCheckRelationOnChain:
			return true
		case headCheckRelationConflict:
			if held.direct {
				forks = append(forks, held)
				return true
			}
		}
		return false
	})
	for _, held := range forks {
		self.authFork(mine, myPin, held.pin, held.path[0], step)
	}
	if self.forked != nil && settled(self.forked.peerId) {
		self.forked = nil
	}
}

// §6.4's witness row, exactly, as one exchange answers it once its acts have run. Every field must hold
// for the exchange to count.
type headCheckWitnessQuestion struct {
	// The peer as this device's state holds it: admitted, and neither revoked, parked nor suspended.
	peer HeadCheckPeer
	// This device's pin after reconciliation, and the peer's: the same pin.
	myPin   *bridge.AuthPin
	peerPin *bridge.AuthPin
	// Neither side sends proven or unverified.
	peerSendsProven     bool
	peerSendsUnverified bool
	sendsProven         bool
	sendsUnverified     bool
	// No field forked.
	forked bool
	// This device holds no UNVERIFIED pin.
	holdsUnverified bool
}

// Whether the exchange counts as a consistent witness. A peer that stays behind, or is ahead with
// entries this device could not fetch, holds another pin, and never counts.
func witnessDecision(question headCheckWitnessQuestion) bool {
	return question.peer.Admitted && !question.peer.Revoked && !question.peer.Parked && !question.peer.Suspended &&
		headCheckPinValid(question.myPin) && headCheckPinValid(question.peerPin) &&
		headCheckPinEqual(question.myPin, question.peerPin) &&
		!question.peerSendsProven && !question.peerSendsUnverified &&
		!question.sendsProven && !question.sendsUnverified &&
		!question.forked && !question.holdsUnverified
}

// A consistent witness (FI-10): who, and exactly the pin it compared, which is all it refreshes.
type headCheckWitness struct {
	peerId Id
	pin    *bridge.AuthPin
	at     time.Time
}

// The witness an exchange with peerId makes, or nil: witnessDecision over state after the exchange's
// acts have run, message being what the peer sent and forked whether any of the exchange's steps found
// a fork.
func headCheckWitnessFor(state headCheckState, mine *headCheckMine, peerId Id, message headCheckMessage, forked bool) *headCheckWitness {
	myPin := mine.sources.Auth.Pin()
	_, unverified := state.relayed(peerId)
	question := headCheckWitnessQuestion{
		peer:                mine.sources.Peers.HeadCheckPeer(peerId),
		myPin:               myPin,
		peerPin:             message.GetAuth(),
		peerSendsProven:     message.GetProven() != nil,
		peerSendsUnverified: len(message.GetUnverified()) != 0,
		sendsProven:         state.withheld != nil || state.forked != nil,
		sendsUnverified:     len(unverified) != 0,
		forked:              forked,
		holdsUnverified:     len(state.unverified) != 0,
	}
	if !witnessDecision(question) {
		return nil
	}
	return &headCheckWitness{peerId: peerId, pin: headCheckPinCopy(myPin), at: mine.now}
}
