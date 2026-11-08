// §6.4's relay row: paths and their bounds, the 64-pin and 4-per-peer caps, what a device sends, and a
// copy cleared by a revocation on its path; then FS-17's chains on pure machines, each device a fake
// with its own state, messages built from what each would send.

package sidecar

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What device sends peerId: its pin and what its state relays.
func testHeadCheckOut(device *testHeadCheckDevice, state headCheckState, peerId Id) *protocol.HeadCheck {
	message := device.message(device.Pin())
	message.Proven, message.Unverified = state.relayed(peerId)
	return message
}

// A path of count synthetic sidecars, none of them a test device.
func testHeadPath(count int) [][]byte {
	path := [][]byte{}
	for i := range count {
		path = append(path, Id{0xa0, byte(i)}.Bytes())
	}
	return path
}

func TestHeadCheckRelayAppendsTheSender(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	claimant := Id{0xc1}
	pin := testMainChain.pin(30)
	message.Unverified = []*protocol.UnverifiedPin{{Pin: pin, Path: [][]byte{claimant.Bytes()}}}
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(state.unverified) != 1 || len(step.unverified) != 1 {
		t.Fatalf("state %+v", state)
	}
	held := state.unverified[0]
	if len(held.path) != 2 || held.path[0] != claimant || held.path[1] != testHeadPeer || held.direct {
		t.Fatalf("path %v", held.path)
	}
	// held at once, and the auth rows try to resolve it from api, then from its claimant
	fetches := testActs(step, headCheckActFetch)
	if len(fetches) != 1 || fetches[0].peerId != claimant {
		t.Fatalf("acts %+v", step.acts)
	}
	_, step = headCheckFetched(state, device.mine(testHeadStart.Add(10*time.Minute)))
	if asks := testActs(step, headCheckActAskProof); len(asks) != 1 || asks[0].peerId != claimant {
		t.Fatalf("acts %+v", step.acts)
	}
	// the peer that relayed it never counts
	if testWitness(device, state, testHeadPeer, message, false) != nil {
		t.Error("a relayer witnessed")
	}
}

func TestHeadCheckRelayOfAPinReachedHoldsNothing(t *testing.T) {
	device := newTestHeadCheckWorld()
	message := device.message(testMainChain.pin(10))
	message.Unverified = []*protocol.UnverifiedPin{
		{Pin: testMainChain.pin(10), Path: testHeadPath(1)},
		{Pin: testMainChain.pin(4), Path: testHeadPath(1)},
	}
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(state.unverified) != 0 {
		t.Fatalf("held %+v", state.unverified)
	}
	// a conflict at a kept position stays UNVERIFIED, never a fork
	message.Unverified = []*protocol.UnverifiedPin{{Pin: testForkChain(2).pin(4), Path: testHeadPath(1)}}
	state, step := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(state.unverified) != 1 || len(step.forks) != 0 {
		t.Fatalf("state %+v forks %+v", state, step.forks)
	}
}

// Paths that come to 7 and 8 sidecars once the sender is appended are kept, 9 is ignored, and so is any
// path holding this device.
func TestHeadCheckRelayPathBounds(t *testing.T) {
	device := newTestHeadCheckWorld()
	cases := []struct {
		received int
		kept     bool
	}{
		{received: 6, kept: true},
		{received: 7, kept: true},
		{received: 8, kept: false},
		{received: 20, kept: false},
	}
	for _, c := range cases {
		message := device.message(testMainChain.pin(10))
		message.Unverified = []*protocol.UnverifiedPin{{Pin: testMainChain.pin(30), Path: testHeadPath(c.received)}}
		state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
		if kept := len(state.unverified) == 1; kept != c.kept {
			t.Errorf("received %d: kept %v", c.received, kept)
		}
		if c.kept && len(state.unverified[0].path) != c.received+1 {
			t.Errorf("received %d: path %d", c.received, len(state.unverified[0].path))
		}
	}
	for _, at := range []int{0, 3} {
		path := testHeadPath(5)
		path[at] = testHeadSelf.Bytes()
		message := device.message(testMainChain.pin(10))
		message.Unverified = []*protocol.UnverifiedPin{{Pin: testMainChain.pin(30), Path: path}}
		if state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart); len(state.unverified) != 0 {
			t.Errorf("self at %d: held", at)
		}
	}
}

func TestHeadCheckRelayCapsKeepTheHighest(t *testing.T) {
	device := newTestHeadCheckWorld()
	peerIds := []Id{}
	for i := range 20 {
		peerId := Id{0xb0, byte(i)}
		device.admit(peerId)
		peerIds = append(peerIds, peerId)
	}
	state := headCheckState{}
	// each peer relays four copies per exchange, twice, each pin its own
	version := uint64(100)
	for round := range 2 {
		for _, peerId := range peerIds {
			message := device.message(testMainChain.pin(10))
			for range 4 {
				version += 1
				message.Unverified = append(message.Unverified, &protocol.UnverifiedPin{Pin: testForkChain(9).pin(version), Path: testHeadPath(1)})
			}
			state, _ = testReconcile(t, device, state, peerId, message, testHeadStart.Add(time.Duration(round)*time.Hour))
		}
	}
	if len(state.unverified) != HeadCheckMaxUnverifiedCount {
		t.Fatalf("held %d", len(state.unverified))
	}
	peerCounts := map[Id]int{}
	for i, held := range state.unverified {
		peerCounts[held.peerId()] += 1
		if 0 < i && headCheckPinCompare(state.unverified[i-1].pin, held.pin) >= 0 {
			t.Fatalf("not highest first at %d", i)
		}
	}
	for peerId, count := range peerCounts {
		if HeadCheckMaxUnverifiedPeerCount < count {
			t.Errorf("%s: %d taken", peerId, count)
		}
	}
	// the 64 kept are the highest: each peer's second four, of the last 16 peers
	if lowest := state.unverified[len(state.unverified)-1].pin.GetVersion(); lowest != version-63 {
		t.Errorf("lowest kept %d, want %d", lowest, version-63)
	}
}

func TestHeadCheckRelayFourFromOnePeerKeepsItsHighest(t *testing.T) {
	device := newTestHeadCheckWorld()
	state := headCheckState{}
	for version := uint64(20); version < 30; version += 1 {
		message := device.message(testMainChain.pin(10))
		message.Unverified = []*protocol.UnverifiedPin{{Pin: testForkChain(9).pin(version), Path: testHeadPath(1)}}
		state, _ = testReconcile(t, device, state, testHeadPeer, message, testHeadStart)
	}
	if len(state.unverified) != 4 || state.unverified[0].pin.GetVersion() != 29 || state.unverified[3].pin.GetVersion() != 26 {
		t.Fatalf("held %+v", state.unverified)
	}
	// a lower copy from that peer now is no longer held, so nothing alarms
	message := device.message(testMainChain.pin(10))
	message.Unverified = []*protocol.UnverifiedPin{{Pin: testForkChain(9).pin(15), Path: testHeadPath(1)}}
	if _, step := testReconcile(t, device, state, testHeadPeer, message, testHeadStart); len(step.unverified) != 0 {
		t.Errorf("an evicted copy alarmed: %+v", step.unverified)
	}
	// another peer's copies have their own four
	message.Unverified = []*protocol.UnverifiedPin{{Pin: testForkChain(9).pin(15), Path: testHeadPath(1)}}
	if state, _ = testReconcile(t, device, state, testHeadPeerB, message, testHeadStart); len(state.unverified) != 5 {
		t.Errorf("held %d", len(state.unverified))
	}
}

func TestHeadCheckSendsFourHighestTheReceiverKeeps(t *testing.T) {
	state := headCheckState{}
	at := func(version uint64, path []Id) *headCheckUnverified {
		return &headCheckUnverified{pin: testForkChain(9).pin(version), path: path}
	}
	// synthetic relayers, none of them a test peer
	r := func(n byte) Id {
		return Id{0xd0, n}
	}
	state.unverified = []*headCheckUnverified{
		at(60, []Id{r(1), testHeadPeerB}),                            // holds the receiver: left out
		at(50, []Id{r(1), r(2), r(3), r(4), r(5), r(6), r(7), r(8)}), // 9 once appended: left out
		at(40, []Id{r(1)}),
		at(30, []Id{r(1), r(2), r(3), r(4), r(5), r(6), r(7)}), // 8 once appended: sent
		at(20, []Id{r(2)}),
		at(15, []Id{r(3)}),
		at(10, []Id{r(4)}),
	}
	_, unverified := state.relayed(testHeadPeerB)
	versions := []uint64{}
	for _, relayedCopy := range unverified {
		versions = append(versions, relayedCopy.GetPin().GetVersion())
	}
	if len(versions) != 4 || versions[0] != 40 || versions[1] != 30 || versions[2] != 20 || versions[3] != 15 {
		t.Fatalf("sent %v", versions)
	}
	if !bytes.Equal(unverified[1].GetPath()[6], r(7).Bytes()) {
		t.Error("the path is not sent as held")
	}
	if pins := state.unverifiedPins(); len(pins) != 7 || !bytes.Equal(pins[0], headCheckEvidence(testForkChain(9).pin(60))) {
		t.Errorf("status pins %d", len(pins))
	}
}

func TestHeadCheckRelayedCopyClearsOnARevocationOnItsPath(t *testing.T) {
	device := newTestHeadCheckWorld()
	relayer := Id{0xa0, 1}
	message := device.message(testMainChain.pin(10))
	message.Unverified = []*protocol.UnverifiedPin{{Pin: testMainChain.pin(30), Path: [][]byte{Id{0xa0, 0}.Bytes(), relayer.Bytes()}}}
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, message, testHeadStart)
	if len(state.unverified) != 1 {
		t.Fatal("not held")
	}
	// suspension is not enough: only a revocation or a park clears a path
	device.peers[relayer] = HeadCheckPeer{Admitted: true, Suspended: true}
	if state, _ = headCheckRound(state, device.mine(testHeadStart.Add(time.Hour))); len(state.unverified) != 1 {
		t.Fatal("a suspension cleared it")
	}
	device.peers[relayer] = HeadCheckPeer{Admitted: true, Revoked: true}
	if state, _ = headCheckRound(state, device.mine(testHeadStart.Add(2*time.Hour))); len(state.unverified) != 0 {
		t.Fatal("a revocation on its path left it")
	}
	// relayed again through the revoked sidecar, it is not held
	if state, _ = testReconcile(t, device, state, testHeadPeer, message, testHeadStart.Add(3*time.Hour)); len(state.unverified) != 0 {
		t.Fatal("held through a revoked relayer")
	}
	// a parked claimant does the same
	device.peers[relayer] = HeadCheckPeer{Admitted: true}
	device.peers[Id{0xa0, 0}] = HeadCheckPeer{Admitted: true, Parked: true}
	if state, _ = testReconcile(t, device, state, testHeadPeer, message, testHeadStart.Add(4*time.Hour)); len(state.unverified) != 0 {
		t.Fatal("held from a parked claimant")
	}
}

func TestHeadCheckForkProvenClearsWhenItsPeerIsRevoked(t *testing.T) {
	device := newTestHeadCheckWorld()
	state, _ := testReconcile(t, device, headCheckState{}, testHeadPeer, device.message(testForkChain(5).pin(10)), testHeadStart)
	if proven, _ := state.relayed(testHeadPeerB); proven == nil {
		t.Fatal("no proven")
	}
	device.peers[testHeadPeer] = HeadCheckPeer{Admitted: true, Revoked: true}
	state, _ = headCheckRound(state, device.mine(testHeadStart.Add(time.Hour)))
	if proven, _ := state.relayed(testHeadPeerB); proven != nil {
		t.Fatal("proven outlived its peer's revocation")
	}
}

// FS-17's chains on pure machines. A desktop holder R holds a tip api withholds from X, Y and W.
type testHeadChainWorld struct {
	devices map[Id]*testHeadCheckDevice
	states  map[Id]headCheckState
	now     time.Time
}

var (
	testHeadR = Id{0x52}
	testHeadX = Id{0x58}
	testHeadY = Id{0x59}
	testHeadW = Id{0x57}
)

// R at main 20, the rest at main 10, every device admitting every other.
func newTestHeadChainWorld() *testHeadChainWorld {
	world := &testHeadChainWorld{devices: map[Id]*testHeadCheckDevice{}, states: map[Id]headCheckState{}, now: testHeadStart}
	ids := []Id{testHeadR, testHeadX, testHeadY, testHeadW}
	for _, sidecarId := range ids {
		device := newTestHeadCheckDevice(sidecarId)
		for _, other := range ids {
			if other != sidecarId {
				device.admit(other)
			}
		}
		world.devices[sidecarId] = device
		world.states[sidecarId] = headCheckState{}
	}
	world.devices[testHeadR].follow(testMainChain, 1, 20)
	return world
}

// to reconciles what from sends it, and returns the step.
func (self *testHeadChainWorld) send(t *testing.T, from Id, to Id) (*protocol.HeadCheck, headCheckStep) {
	t.Helper()
	message := testHeadCheckOut(self.devices[from], self.states[from], to)
	state, step := testReconcile(t, self.devices[to], self.states[to], from, message, self.now)
	self.states[to] = state
	return message, step
}

// to's fetch of from's claim goes unserved to its deadline; then from answers the proof request, with
// what it holds, verified only when it holds one.
func (self *testHeadChainWorld) proveFrom(t *testing.T, from Id, to Id, pin *bridge.AuthPin) headCheckStep {
	t.Helper()
	self.now = self.now.Add(10 * time.Minute)
	state, step := headCheckFetched(self.states[to], self.devices[to].mine(self.now))
	self.states[to] = state
	if asks := testActs(step, headCheckActAskProof); len(asks) != 1 || asks[0].peerId != from {
		t.Fatalf("%s did not ask %s: %+v", to, from, step.acts)
	}
	proof := [][]byte{}
	verified := false
	if from == testHeadR {
		proof, verified = [][]byte{[]byte("R's entries")}, true
	} else if withheld := self.states[from].withheld; withheld != nil {
		proof, verified = withheld.proof, true
	}
	state, step = headCheckProved(self.states[to], self.devices[to].mine(self.now), pin, from, proof, verified)
	self.states[to] = state
	return step
}

func TestHeadCheckFs17RelayedProofStopsAtEachHop(t *testing.T) {
	world := newTestHeadChainWorld()
	tip := testMainChain.pin(20)

	// R to X: X fetches, api withholds, R's proof verifies, and X holds proof of withholding
	world.send(t, testHeadR, testHeadX)
	if step := world.proveFrom(t, testHeadR, testHeadX, tip); step.withheld == nil {
		t.Fatal("X: no withholding")
	}
	// X to Y: X sends proven; Y verifies the proof X serves and stops at once too
	message, _ := world.send(t, testHeadX, testHeadY)
	if !headCheckPinEqual(message.GetProven(), tip) {
		t.Fatalf("X sent proven %v", message.GetProven())
	}
	if step := world.proveFrom(t, testHeadX, testHeadY, tip); step.withheld == nil {
		t.Fatal("Y: no withholding")
	}
	// Y to W: the same, so W stops at its next HeadCheck with Y
	message, _ = world.send(t, testHeadY, testHeadW)
	if step := world.proveFrom(t, testHeadY, testHeadW, tip); step.withheld == nil {
		t.Fatal("W: no withholding")
	}
	// X and Y never count as W's witnesses, though W sits at their pins
	for _, peerId := range []Id{testHeadX, testHeadY} {
		message = testHeadCheckOut(world.devices[peerId], world.states[peerId], testHeadW)
		if headCheckWitnessFor(world.states[testHeadW], world.devices[testHeadW].mine(world.now), peerId, message, false) != nil {
			t.Errorf("%s witnessed for W", peerId)
		}
	}
}

func TestHeadCheckFs17ProofDroppedRelaysUnverified(t *testing.T) {
	world := newTestHeadChainWorld()
	tip := testMainChain.pin(20)

	// R's kept entries do not reach back to X's n: R answers NOT_FOUND, and X holds the tip UNVERIFIED
	world.send(t, testHeadR, testHeadX)
	world.now = world.now.Add(10 * time.Minute)
	state, _ := headCheckFetched(world.states[testHeadX], world.devices[testHeadX].mine(world.now))
	state, step := headCheckProved(state, world.devices[testHeadX].mine(world.now), tip, testHeadR, nil, false)
	world.states[testHeadX] = state
	if len(step.unverified) != 1 {
		t.Fatal("X holds nothing")
	}
	// X sends it with R as its claimant; W, relaying it, holds it too, with the path R, X
	message, step := world.send(t, testHeadX, testHeadW)
	if len(message.GetUnverified()) != 1 || !bytes.Equal(message.GetUnverified()[0].GetPath()[0], testHeadR.Bytes()) {
		t.Fatalf("X sent %+v", message.GetUnverified())
	}
	held := world.states[testHeadW].unverified
	if len(held) != 1 || len(held[0].path) != 2 || held[0].path[0] != testHeadR || held[0].path[1] != testHeadX || len(step.unverified) != 1 {
		t.Fatalf("W holds %+v", held)
	}
	// X counts as no one's witness, and W counts no one while it holds the pin, Y at its pin included
	message = testHeadCheckOut(world.devices[testHeadY], world.states[testHeadY], testHeadW)
	if headCheckWitnessFor(world.states[testHeadW], world.devices[testHeadW].mine(world.now), testHeadY, message, false) != nil {
		t.Error("W counted Y while holding an UNVERIFIED pin")
	}
	// W relays it on to Y with its own name on the path
	message, _ = world.send(t, testHeadW, testHeadY)
	if path := world.states[testHeadY].unverified[0].path; len(path) != 3 || path[2] != testHeadW {
		t.Fatalf("Y holds %v", path)
	}
	// R's revocation clears every copy whose path holds it
	for _, sidecarId := range []Id{testHeadW, testHeadY} {
		world.devices[sidecarId].peers[testHeadR] = HeadCheckPeer{Admitted: true, Revoked: true}
		state, _ := headCheckRound(world.states[sidecarId], world.devices[sidecarId].mine(world.now.Add(time.Hour)))
		if len(state.unverified) != 0 {
			t.Errorf("%s still holds a copy from a revoked claimant", sidecarId)
		}
	}
}

func TestHeadCheckFs17PeerThatCatchesUpWitnesses(t *testing.T) {
	world := newTestHeadChainWorld()
	// W at R's pin once api serves: R counts, then
	message, _ := world.send(t, testHeadR, testHeadW)
	world.devices[testHeadW].follow(testMainChain, 1, 20)
	state, _ := headCheckFetched(world.states[testHeadW], world.devices[testHeadW].mine(world.now.Add(time.Minute)))
	if headCheckWitnessFor(state, world.devices[testHeadW].mine(world.now), testHeadR, message, false) == nil {
		t.Error("a peer caught up to did not witness")
	}
	// a parked peer at W's pin counts for no one
	world.devices[testHeadW].peers[testHeadX] = HeadCheckPeer{Admitted: true, Parked: true}
	parked := world.devices[testHeadW].message(testMainChain.pin(20))
	if headCheckWitnessFor(state, world.devices[testHeadW].mine(world.now), testHeadX, parked, false) != nil {
		t.Error("a parked peer witnessed")
	}
}
