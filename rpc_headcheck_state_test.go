// §6.4's HeadCheck rows on fakes of their sources, each row beside its positive twin: auth, proven,
// gens, groups, refs and vetoes, the fetch, proof and catch-up outcomes, refusals, and §6.4's witness
// row as a truth table with FI-10's three clauses as properties. The relay row's own tests are in
// rpc_headcheck_relay_test.go. Time is a value each step is handed, so nothing waits.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var errTestHeadCheckNoIo = errors.New("a pure head check step asked for I/O")

// The digest at version on the chain named chain.
func testHeadDigest(chain string, version uint64) []byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s/%d", chain, version))
	return sum[:]
}

// An authorization chain: main's digests through forkAfter, then its own.
type testHeadChain struct {
	name      string
	forkAfter uint64
}

// The chain every honest device is on.
var testMainChain = testHeadChain{name: "main", forkAfter: math.MaxUint64}

// A chain that leaves main after forkAfter.
func testForkChain(forkAfter uint64) testHeadChain {
	return testHeadChain{name: "fork", forkAfter: forkAfter}
}

// A_version on this chain.
func (self testHeadChain) digest(version uint64) []byte {
	if version <= self.forkAfter {
		return testHeadDigest("main", version)
	}
	return testHeadDigest(self.name, version)
}

// (version, A_version) on this chain.
func (self testHeadChain) pin(version uint64) *bridge.AuthPin {
	return &bridge.AuthPin{Version: version, Chain: self.digest(version)}
}

// One device's sources, held in memory. Its acts refuse: a pure step must not call them. Its pin and
// digests are safe for concurrent use, since HeadStopState's run loop reads the pin as a test moves it;
// a test sets the rest before anything else reads them.
type testHeadCheckDevice struct {
	sidecarId Id
	networkId Id

	stateLock sync.Mutex
	pin       *bridge.AuthPin
	// the digests kept, from keptFrom to the pin
	chains map[uint64][]byte
	gens   map[Id]*protocol.GenHead
	groups map[Id]*protocol.GroupHead
	refs   map[[2]Id]HeadCheckRef
	peers  map[Id]HeadCheckPeer
	vetoes [][]byte
}

// A device on main at version 10, keeping every digest from 1.
func newTestHeadCheckDevice(sidecarId Id) *testHeadCheckDevice {
	device := &testHeadCheckDevice{
		sidecarId: sidecarId,
		networkId: Id{0x4e, 0x45, 0x54},
		gens:      map[Id]*protocol.GenHead{},
		groups:    map[Id]*protocol.GroupHead{},
		refs:      map[[2]Id]HeadCheckRef{},
		peers:     map[Id]HeadCheckPeer{},
	}
	device.follow(testMainChain, 1, 10)
	return device
}

// Keeps chain's digests from keptFrom through version, at which its pin now stands.
func (self *testHeadCheckDevice) follow(chain testHeadChain, keptFrom uint64, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.chains = map[uint64][]byte{}
	for k := keptFrom; k <= version; k += 1 {
		self.chains[k] = chain.digest(k)
	}
	self.pin = chain.pin(version)
}

// Admits each peer, standing.
func (self *testHeadCheckDevice) admit(peerIds ...Id) {
	for _, peerId := range peerIds {
		self.peers[peerId] = HeadCheckPeer{Admitted: true}
	}
}

// What the machine reads of this device at now.
func (self *testHeadCheckDevice) mine(now time.Time) *headCheckMine {
	return &headCheckMine{
		sidecarId: self.sidecarId,
		networkId: self.networkId,
		sources:   &HeadCheckSources{Auth: self, Gens: self, Groups: self, Refs: self, Peers: self},
		settings:  DefaultSidecarProtocolSettings(),
		now:       now,
	}
}

// A HeadCheck from a peer at pin, of this device's network.
func (self *testHeadCheckDevice) message(pin *bridge.AuthPin) *protocol.HeadCheck {
	return &protocol.HeadCheck{NetworkId: self.networkId.Bytes(), Auth: proto.CloneOf(pin)}
}

// The pin.
func (self *testHeadCheckDevice) Pin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pin
}

// Clears the pin, as a device with no verified state has none.
func (self *testHeadCheckDevice) forget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pin = nil
}

// A kept digest.
func (self *testHeadCheckDevice) ChainAt(version uint64) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chain, kept := self.chains[version]
	return chain, kept
}

// The vetoes set.
func (self *testHeadCheckDevice) Vetoes() [][]byte {
	return self.vetoes
}

// Refuses.
func (self *testHeadCheckDevice) FetchAuth(ctx context.Context, through *bridge.AuthPin) error {
	return errTestHeadCheckNoIo
}

// Refuses.
func (self *testHeadCheckDevice) VerifyAuthProof(ctx context.Context, entries [][]byte, through *bridge.AuthPin) error {
	return errTestHeadCheckNoIo
}

// Refuses.
func (self *testHeadCheckDevice) AuthProof(after uint64) ([][]byte, error) {
	return nil, errTestHeadCheckNoIo
}

// Refuses.
func (self *testHeadCheckDevice) HoldVeto(ctx context.Context, signedVeto []byte) error {
	return errTestHeadCheckNoIo
}

// Every gen pin, for any peer.
func (self *testHeadCheckDevice) GenHeads(peerSidecarId Id) []*protocol.GenHead {
	gens := []*protocol.GenHead{}
	for _, gen := range self.gens {
		gens = append(gens, gen)
	}
	return gens
}

// One gen pin.
func (self *testHeadCheckDevice) GenHead(groupId Id) (*protocol.GenHead, bool) {
	gen, held := self.gens[groupId]
	return gen, held
}

// Refuses.
func (self *testHeadCheckDevice) CatchUpGen(ctx context.Context, through *protocol.GenHead) (HeadCheckCatchUp, error) {
	return HeadCheckCatchUpUnserved, errTestHeadCheckNoIo
}

// Every epoch pin, for any peer.
func (self *testHeadCheckDevice) GroupHeads(peerSidecarId Id) []*protocol.GroupHead {
	groups := []*protocol.GroupHead{}
	for _, group := range self.groups {
		groups = append(groups, group)
	}
	return groups
}

// One epoch pin.
func (self *testHeadCheckDevice) GroupHead(groupId Id) (*protocol.GroupHead, bool) {
	group, held := self.groups[groupId]
	return group, held
}

// Every ref pin, for any peer.
func (self *testHeadCheckDevice) RefHeads(peerSidecarId Id) []*protocol.RefHead {
	refs := []*protocol.RefHead{}
	for _, ref := range self.refs {
		refs = append(refs, ref.Head)
	}
	return refs
}

// One ref pin.
func (self *testHeadCheckDevice) RefHead(repoId Id, refId Id) (HeadCheckRef, bool) {
	ref, held := self.refs[[2]Id{repoId, refId}]
	return ref, held
}

// Refuses.
func (self *testHeadCheckDevice) CatchUpRef(ctx context.Context, through *protocol.RefHead) (HeadCheckCatchUp, error) {
	return HeadCheckCatchUpUnserved, errTestHeadCheckNoIo
}

// A peer as set, or the zero peer.
func (self *testHeadCheckDevice) HeadCheckPeer(sidecarId Id) HeadCheckPeer {
	return self.peers[sidecarId]
}

var (
	testHeadSelf  = Id{0x5e}
	testHeadPeer  = Id{0x01}
	testHeadPeerB = Id{0x02}
	testHeadPeerC = Id{0x03}
	testHeadGroup = Id{0x6a}
	testHeadRepo  = Id{0x7a}
	testHeadRef   = Id{0x7b}
	testHeadStart = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
)

// A device admitting the three test peers.
func newTestHeadCheckWorld() *testHeadCheckDevice {
	device := newTestHeadCheckDevice(testHeadSelf)
	device.admit(testHeadPeer, testHeadPeerB, testHeadPeerC)
	return device
}

// Reconciles message from peerId on device at now, failing the test on a refusal.
func testReconcile(t *testing.T, device *testHeadCheckDevice, state headCheckState, peerId Id, message *protocol.HeadCheck, now time.Time) (headCheckState, headCheckStep) {
	t.Helper()
	next, step, err := headCheckReconcile(state, device.mine(now), peerId, message)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	return next, step
}

// The acts of one kind in step.
func testActs(step headCheckStep, kind headCheckActKind) []headCheckAct {
	acts := []headCheckAct{}
	for _, act := range step.acts {
		if act.kind == kind {
			acts = append(acts, act)
		}
	}
	return acts
}

// Whether state holds pin UNVERIFIED.
func testHolds(state headCheckState, pin *bridge.AuthPin) bool {
	for _, held := range state.unverified {
		if headCheckPinEqual(held.pin, pin) {
			return true
		}
	}
	return false
}

// The witness an exchange with message makes now, nil for none.
func testWitness(device *testHeadCheckDevice, state headCheckState, peerId Id, message *protocol.HeadCheck, forked bool) *headCheckWitness {
	return headCheckWitnessFor(state, device.mine(testHeadStart), peerId, message, forked)
}

func TestHeadCheckSamePinIsAWitness(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(step.forks) != 0 || len(step.acts) != 0 || step.forked {
		t.Fatalf("step %+v", step)
	}
	witness := testWitness(device, state, testHeadPeer, message, step.forked)
	if witness == nil || witness.peerId != testHeadPeer || !headCheckPinEqual(witness.pin, testMainChain.pin(10)) {
		t.Fatalf("witness %+v", witness)
	}
}

func TestHeadCheckSamePositionOtherDigestForks(t *testing.T) {
	device := newTestHeadCheckWorld()
	forkPin := testForkChain(7).pin(10)
	message := device.message(forkPin)
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(step.forks) != 1 || !step.forked {
		t.Fatalf("forks %+v", step.forks)
	}
	fork := step.forks[0]
	if fork.Kind != HeadForkAuth || fork.PeerId == nil || *fork.PeerId != testHeadPeer {
		t.Fatalf("fork %+v", fork)
	}
	// both pins as evidence, as §6.5 encodes them
	if !bytes.Equal(fork.Local, headCheckEvidence(testMainChain.pin(10))) || !bytes.Equal(fork.Remote, headCheckEvidence(forkPin)) {
		t.Error("evidence is not the two pins")
	}
	// the pin it forks with rides on as proven
	proven, _ := state.relayed(testHeadPeerB)
	if !headCheckPinEqual(proven, forkPin) {
		t.Errorf("proven %v", proven)
	}
	if testWitness(device, state, testHeadPeer, message, step.forked) != nil {
		t.Error("a fork witnessed")
	}
}

func TestHeadCheckPeerBehindOnChainAsksNothing(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(6))
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(step.forks) != 0 || len(step.acts) != 0 {
		t.Fatalf("step %+v", step)
	}
	// it fetches or asks me; until then it holds another pin, and counts for nothing
	if testWitness(device, state, testHeadPeer, message, step.forked) != nil {
		t.Error("a peer behind witnessed")
	}
}

func TestHeadCheckPeerBehindOnAnotherChainForks(t *testing.T) {
	device := newTestHeadCheckWorld()
	forkPin := testForkChain(4).pin(6)
	_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(forkPin), testHeadStart)
	if len(step.forks) != 1 || step.forks[0].Kind != HeadForkAuth {
		t.Fatalf("forks %+v", step.forks)
	}
	// the local evidence is this device's digest at the peer's position, not its own pin
	if !bytes.Equal(step.forks[0].Local, headCheckEvidence(testMainChain.pin(6))) {
		t.Error("local evidence")
	}
}

func TestHeadCheckPeerBehindPastWhatIsKeptJudgesNothing(t *testing.T) {
	device := newTestHeadCheckWorld()
	device.follow(testMainChain, 5, 10)
	_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(testForkChain(1).pin(3)), testHeadStart)
	if len(step.forks) != 0 || len(step.acts) != 0 {
		t.Fatalf("step %+v", step)
	}
}

func TestHeadCheckPeerAheadIsFetchedAndCountsOnceServed(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	message := device.message(peerPin)
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	fetches := testActs(step, headCheckActFetch)
	if len(fetches) != 1 || !headCheckPinEqual(fetches[0].pin, peerPin) {
		t.Fatalf("acts %+v", step.acts)
	}
	if want := testHeadStart.Add(10 * time.Minute); !fetches[0].deadline.Equal(want) {
		t.Errorf("deadline %v, want %v", fetches[0].deadline, want)
	}
	// ahead with entries not yet fetched: no witness
	if testWitness(device, state, testHeadPeer, message, step.forked) != nil {
		t.Error("an unfetched peer witnessed")
	}

	// api serves through 14, and the entries chain to the peer's A
	device.follow(testMainChain, 1, 14)
	state, step = headCheckFetched(state, device.mine(testHeadStart.Add(time.Minute)))
	if len(state.fetches) != 0 || len(state.unverified) != 0 || len(step.acts) != 0 || len(step.forks) != 0 {
		t.Fatalf("state %+v step %+v", state, step)
	}
	if testWitness(device, state, testHeadPeer, message, false) == nil {
		t.Error("a peer caught up to did not witness")
	}
}

func TestHeadCheckPeerAheadOnAnotherChainForksOnceServed(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testForkChain(12).pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	// api serves main through 14: the peer's A at 14 is another
	device.follow(testMainChain, 1, 14)
	state, step := headCheckFetched(state, device.mine(testHeadStart.Add(time.Minute)))
	if len(step.forks) != 1 || step.forks[0].Kind != HeadForkAuth || *step.forks[0].PeerId != testHeadPeer {
		t.Fatalf("forks %+v", step.forks)
	}
	if len(state.fetches) != 0 || state.forked == nil {
		t.Fatalf("state %+v", state)
	}
}

func TestHeadCheckUnservedFetchAsksForAProofAtTheDeadline(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)

	// api still silent before the deadline: nothing more yet
	state, step := headCheckFetched(state, device.mine(testHeadStart.Add(9*time.Minute)))
	if len(step.acts) != 0 {
		t.Fatalf("asked early: %+v", step.acts)
	}
	state, step = headCheckFetched(state, device.mine(testHeadStart.Add(10*time.Minute)))
	asks := testActs(step, headCheckActAskProof)
	if len(asks) != 1 || asks[0].peerId != testHeadPeer || asks[0].after != 10 || !headCheckPinEqual(asks[0].pin, peerPin) {
		t.Fatalf("acts %+v", step.acts)
	}
	// once asked, not again
	_, step = headCheckFetched(state, device.mine(testHeadStart.Add(11*time.Minute)))
	if len(step.acts) != 0 {
		t.Errorf("asked twice: %+v", step.acts)
	}
}

func TestHeadCheckVerifiedProofIsWithholdingUntilServed(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	proof := [][]byte{[]byte("entry 11"), []byte("entry 12")}
	state, step := headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, proof, true)
	if step.withheld == nil || !headCheckPinEqual(step.withheld.pin, peerPin) || len(step.unverified) != 0 {
		t.Fatalf("step %+v", step)
	}
	if state.withheld == nil || len(state.withheld.proof) != 2 || len(state.fetches) != 0 {
		t.Fatalf("state %+v", state)
	}
	// the tip rides on as proven
	if proven, _ := state.relayed(testHeadPeerB); !headCheckPinEqual(proven, peerPin) {
		t.Errorf("proven %v", proven)
	}

	// each round asks api again; once it serves, the stop ends
	state, step = headCheckRound(state, device.mine(testHeadStart.Add(time.Hour)))
	if fetches := testActs(step, headCheckActFetch); len(fetches) != 1 || !headCheckPinEqual(fetches[0].pin, peerPin) {
		t.Fatalf("acts %+v", step.acts)
	}
	device.follow(testMainChain, 1, 15)
	state, step = headCheckFetched(state, device.mine(testHeadStart.Add(time.Hour+time.Minute)))
	if !step.served || state.withheld != nil || len(step.forks) != 0 {
		t.Fatalf("step %+v state %+v", step, state)
	}
}

func TestHeadCheckWithheldTipApiAnswersOtherwiseForksNamingTheProver(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testForkChain(12).pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	state, _ = headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, [][]byte{[]byte("forged")}, true)
	// api answers with another entry at the proof's positions
	device.follow(testMainChain, 1, 14)
	state, step := headCheckFetched(state, device.mine(testHeadStart.Add(time.Hour)))
	if !step.served || len(step.forks) != 1 || *step.forks[0].PeerId != testHeadPeer || step.forks[0].Kind != HeadForkAuth {
		t.Fatalf("step %+v", step)
	}
	if state.withheld != nil || state.forked == nil {
		t.Fatalf("state %+v", state)
	}
}

func TestHeadCheckNoProofLeavesThePinUnverified(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	message := device.message(peerPin)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	state, step := headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, nil, false)
	if len(step.unverified) != 1 || step.withheld != nil {
		t.Fatalf("step %+v", step)
	}
	held := state.unverified[0]
	if !headCheckPinEqual(held.pin, peerPin) || len(held.path) != 1 || held.path[0] != testHeadPeer || !held.direct {
		t.Fatalf("held %+v", held)
	}
	// holding it, this device counts no witness, even a peer at its own pin
	if testWitness(device, state, testHeadPeerB, device.message(testMainChain.pin(10)), false) != nil {
		t.Error("witnessed while holding an UNVERIFIED pin")
	}
	// and relays it with the claimant as its path
	_, unverified := state.relayed(testHeadPeerB)
	if len(unverified) != 1 || !bytes.Equal(unverified[0].GetPath()[0], testHeadPeer.Bytes()) {
		t.Errorf("relayed %+v", unverified)
	}
}

func TestHeadCheckUnverifiedPinClearsWhenReached(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	state, _ = headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, nil, false)
	// each round retries the highest pin past this device's
	state, step := headCheckRound(state, device.mine(testHeadStart.Add(time.Hour)))
	if fetches := testActs(step, headCheckActFetch); len(fetches) != 1 || fetches[0].peerId != testHeadPeer {
		t.Fatalf("acts %+v", step.acts)
	}
	device.follow(testMainChain, 1, 14)
	state, _ = headCheckFetched(state, device.mine(testHeadStart.Add(time.Hour+time.Minute)))
	if len(state.unverified) != 0 {
		t.Fatalf("still held %+v", state.unverified)
	}
}

func TestHeadCheckUnverifiedClaimApiLaterContradictsIsAFork(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testForkChain(12).pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	state, _ = headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, nil, false)
	device.follow(testMainChain, 1, 14)
	state, step := headCheckRound(state, device.mine(testHeadStart.Add(time.Hour)))
	if len(step.forks) != 1 || *step.forks[0].PeerId != testHeadPeer || len(state.unverified) != 0 {
		t.Fatalf("step %+v state %+v", step, state)
	}
}

func TestHeadCheckClaimantWithdrawsTheClaim(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerPin := testMainChain.pin(14)
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(peerPin), testHeadStart)
	state, _ = headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), peerPin, testHeadPeer, nil, false)

	// still claiming a pin past this device's: the claim stands
	state, _ = testReconcile(t, device, state, testHeadPeer, device.message(testMainChain.pin(15)), testHeadStart.Add(time.Hour))
	if !testHolds(state, peerPin) {
		t.Fatal("a claim still made was dropped")
	}
	// back on this device's chain, claiming nothing past it: withdrawn
	state, _ = testReconcile(t, device, state, testHeadPeer, device.message(testMainChain.pin(10)), testHeadStart.Add(2*time.Hour))
	if testHolds(state, peerPin) {
		t.Fatal("a withdrawn claim held")
	}
}

func TestHeadCheckProvenConflictIsUnverifiedNotAFork(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	conflicting := testForkChain(7).pin(9)
	message.Proven = conflicting
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(step.forks) != 0 || step.forked {
		t.Fatalf("a proven conflict forked: %+v", step.forks)
	}
	if !testHolds(state, conflicting) || len(step.unverified) != 1 {
		t.Fatalf("state %+v", state)
	}
	// the same conflict as the peer's own pin is a fork: the positive twin
	_, step = testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(conflicting), testHeadStart)
	if len(step.forks) != 1 {
		t.Fatalf("own pin conflict: %+v", step.forks)
	}
	// a peer sending proven never counts
	if testWitness(device, headCheckState{}, testHeadPeer, message, false) != nil {
		t.Error("a peer sending proven witnessed")
	}
}

func TestHeadCheckProvenAheadFollowsTheAuthRows(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	tip := testMainChain.pin(16)
	message.Proven = tip
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if fetches := testActs(step, headCheckActFetch); len(fetches) != 1 || !headCheckPinEqual(fetches[0].pin, tip) {
		t.Fatalf("acts %+v", step.acts)
	}
	if testHolds(state, tip) {
		t.Fatal("held before the auth rows ran")
	}
	// api withholds it too; the peer serves the proof it verified: this device stops at once
	state, step = headCheckFetched(state, device.mine(testHeadStart.Add(10*time.Minute)))
	if asks := testActs(step, headCheckActAskProof); len(asks) != 1 || asks[0].peerId != testHeadPeer {
		t.Fatalf("acts %+v", step.acts)
	}
	proved, step := headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), tip, testHeadPeer, [][]byte{[]byte("e")}, true)
	if step.withheld == nil || proved.withheld == nil {
		t.Fatal("no withholding")
	}
	// with the proof dropped, it is UNVERIFIED, relayed with the peer as claimant and not direct
	unproved, step := headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), tip, testHeadPeer, nil, false)
	if len(step.unverified) != 1 || !testHolds(unproved, tip) || unproved.unverified[0].direct {
		t.Fatalf("state %+v", unproved)
	}
}

func TestHeadCheckGens(t *testing.T) {
	device := newTestHeadCheckWorld()
	commitment := testHeadDigest("c", 5)
	device.gens[testHeadGroup] = &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 5, Commitment: commitment}
	cases := []struct {
		name       string
		gen        *protocol.GenHead
		fork       bool
		catchUpGen bool
	}{
		{name: "same", gen: &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 5, Commitment: commitment}},
		{name: "same g, other C_g", gen: &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 5, Commitment: testHeadDigest("other", 5)}, fork: true},
		{name: "peer higher", gen: &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 7, Commitment: testHeadDigest("c", 7)}, catchUpGen: true},
		{name: "peer lower", gen: &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 3, Commitment: testHeadDigest("c", 3)}},
		{name: "not mine", gen: &protocol.GenHead{GroupId: Id{0x99}.Bytes(), Generation: 5, Commitment: testHeadDigest("x", 5)}},
	}
	for _, c := range cases {
		message := device.message(testMainChain.pin(10))
		message.Gens = []*protocol.GenHead{c.gen}
		_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		if forked := len(step.forks) == 1 && step.forks[0].Kind == HeadForkGen && step.forks[0].GroupId == testHeadGroup; forked != c.fork || step.forked != c.fork {
			t.Errorf("%s: forks %+v", c.name, step.forks)
		}
		if catchUp := len(testActs(step, headCheckActCatchUpGen)) == 1; catchUp != c.catchUpGen {
			t.Errorf("%s: acts %+v", c.name, step.acts)
		}
	}
}

func TestHeadCheckGenCatchUp(t *testing.T) {
	device := newTestHeadCheckWorld()
	device.gens[testHeadGroup] = &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 5, Commitment: testHeadDigest("c", 5)}
	act := headCheckAct{kind: headCheckActCatchUpGen, peerId: testHeadPeer, gen: &protocol.GenHead{GroupId: testHeadGroup.Bytes(), Generation: 7, Commitment: testHeadDigest("c", 7)}}
	// a lower side catching up without conflict, the ledger's "advances independently" case
	if step := headCheckCaughtUp(device.mine(testHeadStart), act, HeadCheckCaughtUp); len(step.forks) != 0 {
		t.Errorf("caught up forked: %+v", step.forks)
	}
	if step := headCheckCaughtUp(device.mine(testHeadStart), act, HeadCheckCatchUpUnserved); len(step.forks) != 0 {
		t.Errorf("unserved forked: %+v", step.forks)
	}
	step := headCheckCaughtUp(device.mine(testHeadStart), act, HeadCheckCatchUpForked)
	if len(step.forks) != 1 || step.forks[0].Kind != HeadForkGen || step.forks[0].GroupId != testHeadGroup || !step.forked {
		t.Fatalf("forks %+v", step.forks)
	}
}

func TestHeadCheckGroups(t *testing.T) {
	device := newTestHeadCheckWorld()
	authenticator := testHeadDigest("epoch", 3)
	device.groups[testHeadGroup] = &protocol.GroupHead{GroupId: testHeadGroup.Bytes(), Epoch: 3, EpochAuthenticator: authenticator}
	cases := []struct {
		name  string
		group *protocol.GroupHead
		fork  bool
	}{
		{name: "same", group: &protocol.GroupHead{GroupId: testHeadGroup.Bytes(), Epoch: 3, EpochAuthenticator: authenticator}},
		{name: "same epoch, other authenticator", group: &protocol.GroupHead{GroupId: testHeadGroup.Bytes(), Epoch: 3, EpochAuthenticator: testHeadDigest("other", 3)}, fork: true},
		{name: "another epoch", group: &protocol.GroupHead{GroupId: testHeadGroup.Bytes(), Epoch: 4, EpochAuthenticator: testHeadDigest("epoch", 4)}},
	}
	for _, c := range cases {
		message := device.message(testMainChain.pin(10))
		message.Groups = []*protocol.GroupHead{c.group}
		_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		if forked := len(step.forks) == 1 && step.forks[0].Kind == HeadForkGroup; forked != c.fork {
			t.Errorf("%s: forks %+v", c.name, step.forks)
		}
	}
}

func TestHeadCheckRefs(t *testing.T) {
	device := newTestHeadCheckWorld()
	chain := testHeadDigest("ref", 20)
	device.refs[[2]Id{testHeadRepo, testHeadRef}] = HeadCheckRef{
		Head:    &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: testHeadRef.Bytes(), Version: 20, Chain: chain},
		GroupId: testHeadGroup,
	}
	cases := []struct {
		name    string
		ref     *protocol.RefHead
		fork    bool
		catchUp bool
	}{
		{name: "same", ref: &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: testHeadRef.Bytes(), Version: 20, Chain: chain}},
		{name: "same version, other chain", ref: &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: testHeadRef.Bytes(), Version: 20, Chain: testHeadDigest("fork", 20)}, fork: true},
		{name: "peer higher", ref: &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: testHeadRef.Bytes(), Version: 25, Chain: testHeadDigest("ref", 25)}, catchUp: true},
		{name: "peer lower", ref: &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: testHeadRef.Bytes(), Version: 15, Chain: testHeadDigest("ref", 15)}},
	}
	for _, c := range cases {
		message := device.message(testMainChain.pin(10))
		message.Refs = []*protocol.RefHead{c.ref}
		_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		// a ref's fork stops the group its repo seals under
		if forked := len(step.forks) == 1 && step.forks[0].Kind == HeadForkRef && step.forks[0].GroupId == testHeadGroup; forked != c.fork {
			t.Errorf("%s: forks %+v", c.name, step.forks)
		}
		if catchUp := len(testActs(step, headCheckActCatchUpRef)) == 1; catchUp != c.catchUp {
			t.Errorf("%s: acts %+v", c.name, step.acts)
		}
	}
	act := headCheckAct{kind: headCheckActCatchUpRef, peerId: testHeadPeer, ref: cases[2].ref}
	if step := headCheckCaughtUp(device.mine(testHeadStart), act, HeadCheckCaughtUp); len(step.forks) != 0 {
		t.Errorf("caught up forked: %+v", step.forks)
	}
	if step := headCheckCaughtUp(device.mine(testHeadStart), act, HeadCheckCatchUpForked); len(step.forks) != 1 || step.forks[0].GroupId != testHeadGroup {
		t.Errorf("a ref that does not extend the pin: %+v", step.forks)
	}
}

func TestHeadCheckVetoesGoToTheAuthSource(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	message.Vetoes = [][]byte{[]byte("veto a"), []byte("veto b")}
	_, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	holds := testActs(step, headCheckActHoldVeto)
	if len(holds) != 2 || !bytes.Equal(holds[0].veto, []byte("veto a")) || holds[1].peerId != testHeadPeer {
		t.Fatalf("acts %+v", step.acts)
	}
	// a veto is no fork, and changes nothing a witness reads
	if testWitness(device, headCheckState{}, testHeadPeer, message, step.forked) == nil {
		t.Error("a veto cost the witness")
	}
}

func TestHeadCheckRefusesMalformedMessages(t *testing.T) {
	device := newTestHeadCheckWorld()
	good := func() *protocol.HeadCheck {
		return device.message(testMainChain.pin(10))
	}
	groupHead := func(groupId Id) *protocol.GroupHead {
		return &protocol.GroupHead{GroupId: groupId.Bytes(), Epoch: 1, EpochAuthenticator: testHeadDigest("e", 1)}
	}
	cases := []struct {
		name   string
		adjust func(message *protocol.HeadCheck)
	}{
		{name: "another network", adjust: func(message *protocol.HeadCheck) { message.NetworkId = Id{0x99}.Bytes() }},
		{name: "no auth pin", adjust: func(message *protocol.HeadCheck) { message.Auth = nil }},
		{name: "short digest", adjust: func(message *protocol.HeadCheck) { message.Auth.Chain = message.Auth.Chain[:31] }},
		{name: "short proven", adjust: func(message *protocol.HeadCheck) { message.Proven = &bridge.AuthPin{Version: 11} }},
		{name: "17 groups", adjust: func(message *protocol.HeadCheck) {
			for i := range 17 {
				message.Groups = append(message.Groups, groupHead(Id{byte(i + 1)}))
			}
		}},
		{name: "a repeated group", adjust: func(message *protocol.HeadCheck) {
			message.Groups = []*protocol.GroupHead{groupHead(testHeadGroup), groupHead(testHeadGroup)}
		}},
		{name: "five vetoes", adjust: func(message *protocol.HeadCheck) {
			message.Vetoes = [][]byte{{1}, {2}, {3}, {4}, {5}}
		}},
		{name: "five unverified", adjust: func(message *protocol.HeadCheck) {
			for i := range 5 {
				message.Unverified = append(message.Unverified, &protocol.UnverifiedPin{Pin: testMainChain.pin(uint64(20 + i)), Path: [][]byte{testHeadPeerB.Bytes()}})
			}
		}},
		{name: "a pathless copy", adjust: func(message *protocol.HeadCheck) {
			message.Unverified = []*protocol.UnverifiedPin{{Pin: testMainChain.pin(20)}}
		}},
		{name: "a short id on a path", adjust: func(message *protocol.HeadCheck) {
			message.Unverified = []*protocol.UnverifiedPin{{Pin: testMainChain.pin(20), Path: [][]byte{{1, 2, 3}}}}
		}},
		{name: "a short gen commitment", adjust: func(message *protocol.HeadCheck) {
			message.Gens = []*protocol.GenHead{{GroupId: testHeadGroup.Bytes(), Generation: 1, Commitment: []byte{1}}}
		}},
	}
	for _, c := range cases {
		message := good()
		c.adjust(message)
		state, step, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), testHeadPeer, message)
		if !errors.Is(err, errHeadCheckMalformed) || len(state.unverified) != 0 || len(step.acts) != 0 {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
	if _, _, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), testHeadPeer, good()); err != nil {
		t.Errorf("the well-formed twin: %v", err)
	}
}

func TestHeadCheckRefusesPeersWithoutStanding(t *testing.T) {
	device := newTestHeadCheckWorld()
	device.peers[testHeadPeerB] = HeadCheckPeer{Admitted: true, Revoked: true}
	device.peers[testHeadPeerC] = HeadCheckPeer{Admitted: true, Parked: true}
	stranger := Id{0x44}
	// a forking pin from any of them changes nothing
	message := device.message(testForkChain(5).pin(10))
	for _, peerId := range []Id{testHeadPeerB, testHeadPeerC, stranger, testHeadSelf} {
		_, step, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), peerId, message)
		if !errors.Is(err, errHeadCheckPeer) || len(step.forks) != 0 {
			t.Errorf("%s: err %v", peerId, err)
		}
	}
	// a suspended peer still answers: suspension gates witnessing, not identity
	device.peers[testHeadPeer] = HeadCheckPeer{Admitted: true, Suspended: true}
	if _, step, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), testHeadPeer, message); err != nil || len(step.forks) != 1 {
		t.Errorf("suspended: err %v forks %+v", err, step.forks)
	}
	// with no verified state there is nothing to compare
	device.forget()
	if _, _, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), testHeadPeer, device.message(testMainChain.pin(10))); !errors.Is(err, errHeadCheckNoState) {
		t.Errorf("no state: err %v", err)
	}
}

func TestHeadCheckResultReconcilesAsHeadCheck(t *testing.T) {
	device := newTestHeadCheckWorld()
	result := &protocol.HeadCheckResult{NetworkId: device.networkId.Bytes(), Auth: testForkChain(8).pin(10)}
	_, step, err := headCheckReconcile(headCheckState{}, device.mine(testHeadStart), testHeadPeer, result)
	if err != nil || len(step.forks) != 1 {
		t.Fatalf("err %v forks %+v", err, step.forks)
	}
}

func TestHeadCheckStateIsAValue(t *testing.T) {
	device := newTestHeadCheckWorld()
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(testMainChain.pin(14)), testHeadStart)
	before := len(state.fetches)
	_, _ = headCheckProved(state, device.mine(testHeadStart.Add(10*time.Minute)), testMainChain.pin(14), testHeadPeer, nil, false)
	if len(state.fetches) != before || len(state.unverified) != 0 {
		t.Error("a transition changed its argument")
	}
}

// Every combination of the witness row's clauses: only all of them together count.
func TestWitnessDecisionTruthTable(t *testing.T) {
	samePin := testMainChain.pin(10)
	for bits := 0; bits < 1<<10; bits += 1 {
		bit := func(n int) bool {
			return bits&(1<<n) != 0
		}
		question := headCheckWitnessQuestion{
			peer:                HeadCheckPeer{Admitted: !bit(0), Revoked: bit(1), Parked: bit(2), Suspended: bit(3)},
			myPin:               samePin,
			peerPin:             samePin,
			peerSendsProven:     bit(5),
			peerSendsUnverified: bit(6),
			sendsProven:         bit(7),
			sendsUnverified:     bit(8),
			forked:              bit(9),
		}
		if bit(4) {
			question.peerPin = testMainChain.pin(9)
		}
		for _, holds := range []bool{false, true} {
			question.holdsUnverified = holds
			want := bits == 0 && !holds
			if got := witnessDecision(question); got != want {
				t.Errorf("bits %010b holds %v: %v", bits, holds, got)
			}
		}
	}
	// same position, other digest: never the same pin
	if witnessDecision(headCheckWitnessQuestion{peer: HeadCheckPeer{Admitted: true}, myPin: samePin, peerPin: testForkChain(5).pin(10)}) {
		t.Error("a forked pin witnessed")
	}
	if witnessDecision(headCheckWitnessQuestion{peer: HeadCheckPeer{Admitted: true}}) {
		t.Error("no pins witnessed")
	}
}

// FI-10, first clause: a witness names exactly the state it compared, this device's pin at the exchange.
func TestWitnessNamesExactlyTheStateCompared(t *testing.T) {
	device := newTestHeadCheckWorld()
	for version := uint64(1); version <= 30; version += 1 {
		device.follow(testMainChain, 1, version)
		message := device.message(testMainChain.pin(version))
		state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		witness := testWitness(device, state, testHeadPeer, message, step.forked)
		if witness == nil || !headCheckPinEqual(witness.pin, device.Pin()) || witness.peerId != testHeadPeer || !witness.at.Equal(testHeadStart) {
			t.Fatalf("at %d: witness %+v", version, witness)
		}
	}
}

// FI-10, second clause: a stale peer cannot manufacture freshness. A peer at any pin but this device's,
// behind on its chain or anywhere off it, makes no witness.
func TestStalePeerCannotMakeFreshness(t *testing.T) {
	device := newTestHeadCheckWorld()
	device.follow(testMainChain, 1, 20)
	for version := uint64(1); version <= 40; version += 1 {
		for _, chain := range []testHeadChain{testMainChain, testForkChain(version / 2)} {
			pin := chain.pin(version)
			if headCheckPinEqual(pin, device.Pin()) {
				continue
			}
			message := device.message(pin)
			state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
			if testWitness(device, state, testHeadPeer, message, step.forked) != nil {
				t.Fatalf("a peer at %d on %s witnessed", version, chain.name)
			}
		}
	}
}

// FI-10, third clause: a ref forked under one unchanged epoch alarms, and the exchange reads
// unwitnessed, however the rest of the message agrees.
func TestForkUnderOneEpochAlarmsOrReadsUnwitnessed(t *testing.T) {
	device := newTestHeadCheckWorld()
	authenticator := testHeadDigest("epoch", 3)
	device.groups[testHeadGroup] = &protocol.GroupHead{GroupId: testHeadGroup.Bytes(), Epoch: 3, EpochAuthenticator: authenticator}
	for version := uint64(1); version <= 16; version += 1 {
		device.refs[[2]Id{testHeadRepo, Id{byte(version)}}] = HeadCheckRef{
			Head:    &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: Id{byte(version)}.Bytes(), Version: version, Chain: testHeadDigest("ref", version)},
			GroupId: testHeadGroup,
		}
	}
	for forked := uint64(1); forked <= 16; forked += 1 {
		message := device.message(testMainChain.pin(10))
		message.Groups = []*protocol.GroupHead{{GroupId: testHeadGroup.Bytes(), Epoch: 3, EpochAuthenticator: authenticator}}
		for version := uint64(1); version <= 16; version += 1 {
			chain := testHeadDigest("ref", version)
			if version == forked {
				chain = testHeadDigest("fork", version)
			}
			message.Refs = append(message.Refs, &protocol.RefHead{RepoId: testHeadRepo.Bytes(), RefId: Id{byte(version)}.Bytes(), Version: version, Chain: chain})
		}
		state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		if len(step.forks) != 1 || step.forks[0].Kind != HeadForkRef {
			t.Fatalf("ref %d: forks %+v", forked, step.forks)
		}
		if testWitness(device, state, testHeadPeer, message, step.forked) != nil {
			t.Fatalf("ref %d forked and witnessed", forked)
		}
	}
}
