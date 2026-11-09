//go:build !sidecar_http && !js

// HeadCheck's transport between dispatchers (PROTO-M2-03): exchanges reconcile both ways and witness,
// lists rotate so a ref fork past one message's 16 shows within ceil(refs/16) exchanges, a message at
// its caps is two envelopes, proofs serve at exactly 64 KiB and answer NOT_FOUND one entry over, a
// phone's 64 KiB serves, an api silent past HeadCheckFetchTimeout moves to a proof request, the first
// exchange per hour starts one HeadCheck, a read_only peer answers, and a suspended peer passes Hello
// and answers but witnesses nothing. Sources are in memory, on synthetic chains, on the sides' clocks.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The size every synthetic entry is marshalled to, so a proof's byte count is entries × this.
const testHeadEntryByteCount = 1024

// One network's authorization log as api holds it: a chain's entries through a tip, which api withholds
// from a device past a position.
type testHeadCheckApi struct {
	networkId Id

	stateLock     sync.Mutex
	chain         testHeadChain
	tip           uint64
	withheldAfter map[Id]uint64
}

func newTestHeadCheckApi(networkId Id, chain testHeadChain, tip uint64) *testHeadCheckApi {
	return &testHeadCheckApi{networkId: networkId, chain: chain, tip: tip, withheldAfter: map[Id]uint64{}}
}

// The last position api serves the device.
func (self *testHeadCheckApi) servedTip(sidecarId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if withheldAfter, withheld := self.withheldAfter[sidecarId]; withheld {
		return min(self.tip, withheldAfter)
	}
	return self.tip
}

func (self *testHeadCheckApi) withhold(sidecarId Id, after uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.withheldAfter[sidecarId] = after
}

func (self *testHeadCheckApi) serve(sidecarId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.withheldAfter, sidecarId)
}

// Entry n of chain, marshalled to exactly testHeadEntryByteCount: its body names the chain that wrote it,
// padded.
func testHeadEntry(networkId Id, chain testHeadChain, n uint64) []byte {
	name := chain.name
	if n <= chain.forkAfter {
		name = "main"
	}
	entry := &bridge.AuthEntry{
		NetworkId: networkId.Bytes(),
		N:         n,
		PrevChain: chain.digest(n - 1),
		Kind:      bridge.AuthEntryKindTick,
		TimeMs:    int64(n),
		Body:      []byte(name + "/"),
	}
	for padding := 0; ; padding += 1 {
		entry.Body = append([]byte(name+"/"), bytes.Repeat([]byte{'p'}, padding)...)
		encoded, err := proto.Marshal(entry)
		if err != nil {
			panic(err)
		}
		if len(encoded) == testHeadEntryByteCount {
			return encoded
		}
		if testHeadEntryByteCount < len(encoded) {
			panic("a synthetic entry cannot reach its size")
		}
	}
}

// A device's sources with working acts: its authorization view over a testHeadCheckApi, its pins, and
// who stands. The pure engine's device holds the pins; this adds the I/O.
type testHeadCheckSourceDevice struct {
	*testHeadCheckDevice
	api *testHeadCheckApi

	actLock sync.Mutex
	// the chain the device holds and the position it keeps from
	chain    testHeadChain
	keptFrom uint64
	// what its proofs serve from, in entry bytes
	retainByteCount int
	heldVetoes      [][]byte
	// what gen/ and the refs' statements hold past the pins
	storeGens  map[Id]*protocol.GenHead
	storeRefs  map[[2]Id]*protocol.RefHead
	fetchCount int
}

func newTestHeadCheckSourceDevice(sidecarId Id, networkId Id, api *testHeadCheckApi, chain testHeadChain, version uint64) *testHeadCheckSourceDevice {
	device := newTestHeadCheckDevice(sidecarId)
	device.networkId = networkId
	device.follow(chain, 1, version)
	return &testHeadCheckSourceDevice{
		testHeadCheckDevice: device,
		api:                 api,
		chain:               chain,
		keptFrom:            1,
		retainByteCount:     HeadCheckMaxProofByteCount,
		storeGens:           map[Id]*protocol.GenHead{},
		storeRefs:           map[[2]Id]*protocol.RefHead{},
	}
}

func (self *testHeadCheckSourceDevice) sources() *HeadCheckSources {
	return &HeadCheckSources{Auth: self, Gens: self, Groups: self, Refs: self, Peers: self}
}

// Applies what api serves past the pin, if api's chain is the device's at its pin.
func (self *testHeadCheckSourceDevice) FetchAuth(ctx context.Context, through *bridge.AuthPin) error {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	self.fetchCount += 1
	served := self.api.servedTip(self.sidecarId)
	pin := self.Pin()
	if served <= pin.GetVersion() {
		return nil
	}
	if !bytes.Equal(self.api.chain.digest(pin.GetVersion()), pin.GetChain()) {
		return errors.New("synthetic fork at the pin")
	}
	self.chain = self.api.chain
	self.follow(self.chain, self.keptFrom, served)
	return nil
}

// Checks entries chain from the pin to through, each digest its chain's.
func (self *testHeadCheckSourceDevice) VerifyAuthProof(ctx context.Context, entries [][]byte, through *bridge.AuthPin) error {
	at := self.Pin()
	for _, entryBytes := range entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return ErrHeadCheckProofInvalid
		}
		name, _, _ := bytes.Cut(entry.GetBody(), []byte("/"))
		if entry.GetN() != at.GetVersion()+1 || !bytes.Equal(entry.GetPrevChain(), at.GetChain()) {
			return ErrHeadCheckProofInvalid
		}
		at = &bridge.AuthPin{Version: entry.GetN(), Chain: testHeadDigest(string(name), entry.GetN())}
	}
	if !headCheckPinEqual(at, through) {
		return ErrHeadCheckProofInvalid
	}
	return nil
}

// The kept entries after after through the pin, within the retain bytes.
func (self *testHeadCheckSourceDevice) AuthProof(after uint64) ([][]byte, error) {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	pin := self.Pin()
	if pin.GetVersion() <= after {
		return [][]byte{}, nil
	}
	if after+1 < self.keptFrom {
		return nil, ErrHeadCheckProofNotFound
	}
	entries := [][]byte{}
	for n := after + 1; n <= pin.GetVersion(); n += 1 {
		entries = append(entries, testHeadEntry(self.networkId, self.chain, n))
	}
	if self.retainByteCount < headCheckProofByteCount(entries) {
		return nil, ErrHeadCheckProofNotFound
	}
	return entries, nil
}

func (self *testHeadCheckSourceDevice) HoldVeto(ctx context.Context, signedVeto []byte) error {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	self.heldVetoes = append(self.heldVetoes, bytes.Clone(signedVeto))
	return nil
}

func (self *testHeadCheckSourceDevice) CatchUpGen(ctx context.Context, through *protocol.GenHead) (HeadCheckCatchUp, error) {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	stored, ok := self.storeGens[Id(through.GetGroupId())]
	switch {
	case !ok || stored.GetGeneration() != through.GetGeneration():
		return HeadCheckCatchUpUnserved, nil
	case !bytes.Equal(stored.GetCommitment(), through.GetCommitment()):
		return HeadCheckCatchUpForked, nil
	}
	self.gens[Id(through.GetGroupId())] = proto.CloneOf(stored)
	return HeadCheckCaughtUp, nil
}

func (self *testHeadCheckSourceDevice) CatchUpRef(ctx context.Context, through *protocol.RefHead) (HeadCheckCatchUp, error) {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	key := [2]Id{Id(through.GetRepoId()), Id(through.GetRefId())}
	stored, ok := self.storeRefs[key]
	switch {
	case !ok || stored.GetVersion() != through.GetVersion():
		return HeadCheckCatchUpUnserved, nil
	case !bytes.Equal(stored.GetChain(), through.GetChain()):
		return HeadCheckCatchUpForked, nil
	}
	ref := self.refs[key]
	self.refs[key] = HeadCheckRef{Head: proto.CloneOf(stored), GroupId: ref.GroupId}
	return HeadCheckCaughtUp, nil
}

// Every ref pin in a stable order, which the rotation walks.
func (self *testHeadCheckSourceDevice) RefHeads(peerSidecarId Id) []*protocol.RefHead {
	refs := self.testHeadCheckDevice.RefHeads(peerSidecarId)
	slices.SortFunc(refs, func(a *protocol.RefHead, b *protocol.RefHead) int {
		return bytes.Compare(append(slices.Clone(a.GetRepoId()), a.GetRefId()...), append(slices.Clone(b.GetRepoId()), b.GetRefId()...))
	})
	return refs
}

// Peers as set, under the source lock, since the run loops read them.
func (self *testHeadCheckSourceDevice) HeadCheckPeer(sidecarId Id) HeadCheckPeer {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	return self.peers[sidecarId]
}

func (self *testHeadCheckSourceDevice) setPeer(sidecarId Id, peer HeadCheckPeer) {
	self.actLock.Lock()
	defer self.actLock.Unlock()
	self.peers[sidecarId] = peer
}

// One side of a HeadCheck world: its dispatcher, sources, stop state and transport, with the alarms it
// raised and the candidates its rounds read.
type testHeadCheckSide struct {
	*testRpcSide
	source *testHeadCheckSourceDevice
	stop   *HeadStopState
	detach func()

	stateLock  sync.Mutex
	alarms     []SidecarEvent
	candidates []HeadCheckCandidate
	// each alarm as raised, for a test that waits on one
	alarmEvents chan SidecarEvent
}

// Waits until the side's transport has finished count exchanges, either way, in all.
func (self *testHeadCheckSide) awaitExchanges(count uint64) {
	transport := self.subprotocol.headCheck.Load()
	for {
		exchangeCount, notify := transport.exchangeCount.Get()
		if count <= exchangeCount {
			return
		}
		select {
		case <-notify:
		case <-time.After(testSubprotocolAwaitTimeout):
			panic(fmt.Sprintf("%d exchanges of %d", exchangeCount, count))
		}
	}
}

// Waits until the side's transport has finished count rounds.
func (self *testHeadCheckSide) awaitRounds(count uint64) {
	transport := self.subprotocol.headCheck.Load()
	for {
		roundCount, notify := transport.roundCount.Get()
		if count <= roundCount {
			return
		}
		select {
		case <-notify:
		case <-time.After(testSubprotocolAwaitTimeout):
			panic(fmt.Sprintf("%d rounds of %d", roundCount, count))
		}
	}
}

// The HeadCheck requests the side sent, decoded once whole.
func (self *testHeadCheckSide) sentHeadChecks(t *testing.T) []*protocol.HeadCheck {
	t.Helper()
	messages := []*protocol.HeadCheck{}
	bodies := map[uint64][]byte{}
	for _, envelope := range self.sent() {
		if envelope.Type != uint32(protocol.MessageType_HEAD_CHECK) || envelope.Flags&EnvelopeFlagResponse != 0 {
			continue
		}
		bodies[envelope.RequestId] = append(bodies[envelope.RequestId], envelope.Body...)
		if envelope.Flags&EnvelopeFlagMore != 0 {
			continue
		}
		message := &protocol.HeadCheck{}
		if err := proto.Unmarshal(bodies[envelope.RequestId], message); err != nil {
			t.Fatal(err)
		}
		delete(bodies, envelope.RequestId)
		messages = append(messages, message)
	}
	return messages
}

func (self *testHeadCheckSide) alarmsOf(kind SidecarHeadAlarm) []SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []SidecarEvent{}
	for _, alarm := range self.alarms {
		if alarm.HeadAlarm == kind {
			alarms = append(alarms, alarm)
		}
	}
	return alarms
}

// A network of sides on admissions, each with HeadCheck attached on a shared api.
type testHeadCheckWorld struct {
	t    *testing.T
	pair *testRpcPair
	api  *testHeadCheckApi
	// who the network admits, so each side's peer state and api's identity lookup read them
	sides []*testHeadCheckSide
}

func newTestHeadCheckWorldOf(t *testing.T, tip uint64) *testHeadCheckWorld {
	pair := newTestRpcPair(t)
	pair.authority = newTestAdmissionAuthority()
	return &testHeadCheckWorld{t: t, pair: pair, api: newTestHeadCheckApi(pair.networkId, testMainChain, tip)}
}

// Adds a side at version on chain, admitted, with HeadCheck attached; every side admits every other.
func (self *testHeadCheckWorld) add(chain testHeadChain, version uint64, adjust func(settings *SidecarProtocolSettings)) *testHeadCheckSide {
	t := self.t
	identity := newTestRpcIdentity()
	self.pair.authority.admit(identity.sidecarId, identity.identitySeed, nil)
	rpcSide := self.pair.add(identity, adjust)
	source := newTestHeadCheckSourceDevice(identity.sidecarId, self.pair.networkId, self.api, chain, version)
	side := &testHeadCheckSide{testRpcSide: rpcSide, source: source, alarmEvents: make(chan SidecarEvent, 64)}
	var transportRequestRound func()
	stop, err := NewHeadStopState(t.Context(), &HeadStopStateEnv{
		SidecarId: identity.sidecarId,
		NetworkId: self.pair.networkId,
		Sources:   source.sources(),
		Store:     newTestHeadStopStore(),
		Settings:  rpcSide.settings,
		Clock:     rpcSide.clock,
		Log:       NewNoopLogger(),
		WitnessBoundHours: func() (uint32, bool) {
			return WitnessBoundDefaultHours, true
		},
		SharedGroup: func(groupId Id) bool { return true },
		Alarm: func(event SidecarEvent) {
			func() {
				side.stateLock.Lock()
				defer side.stateLock.Unlock()
				side.alarms = append(side.alarms, event)
			}()
			select {
			case side.alarmEvents <- event:
			default:
			}
		},
		RequestRound: func() {
			if transportRequestRound != nil {
				transportRequestRound()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop.Close)
	side.stop = stop
	detach, err := rpcSide.subprotocol.AttachHeadCheck(&HeadCheckEnv{
		Stop: stop,
		Candidates: func() []HeadCheckCandidate {
			side.stateLock.Lock()
			defer side.stateLock.Unlock()
			return slices.Clone(side.candidates)
		},
		Identity: func(ctx context.Context, sidecarId Id) (*SidecarIdentityRecord, error) {
			for _, other := range self.sides {
				if other.sidecarId == sidecarId {
					return &SidecarIdentityRecord{SidecarId: sidecarId, Binding: other.binding}, nil
				}
			}
			return nil, errors.New("no such sidecar")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(detach)
	side.detach = detach
	transportRequestRound = rpcSide.subprotocol.headCheck.Load().requestRound
	for _, other := range self.sides {
		other.source.setPeer(side.sidecarId, HeadCheckPeer{Admitted: true})
		source.setPeer(other.sidecarId, HeadCheckPeer{Admitted: true})
	}
	self.sides = append(self.sides, side)
	return side
}

// Both sides at the same pin with nothing else to compare: an exchange counts as a witness on each
// side, once the responder's acts have run.
func TestHeadCheckExchangeWitnessesBothWays(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	witnessed, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId))
	if err != nil || !witnessed {
		t.Fatalf("witnessed %t: %v", witnessed, err)
	}
	if a.stop.WitnessedAt() != a.clock.Now() {
		t.Errorf("the initiator's witnessed_at %s", a.stop.WitnessedAt())
	}
	b.awaitExchanges(1)
	if b.stop.WitnessedAt() != b.clock.Now() {
		t.Errorf("the responder's witnessed_at %s", b.stop.WitnessedAt())
	}
}

// A ref fork past one message's 16 shows within ceil(refs/16) exchanges: 40 shared refs, the 37th forked
// at the same version, show at the third, and no message carries more than 16.
func TestHeadCheckRotationShowsARefForkWithinCeilExchanges(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	repoId := NewId()
	groupId := NewId()
	refIds := []Id{}
	for i := 0; i < 40; i += 1 {
		refId := Id{0x10, byte(i)}
		refIds = append(refIds, refId)
		head := &protocol.RefHead{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: 7, Chain: testHeadDigest("ref", uint64(i))}
		a.source.refs[[2]Id{repoId, refId}] = HeadCheckRef{Head: head, GroupId: groupId}
		forked := proto.CloneOf(head)
		if i == 36 {
			forked.Chain = testHeadDigest("forked ref", uint64(i))
		}
		b.source.refs[[2]Id{repoId, refId}] = HeadCheckRef{Head: forked, GroupId: groupId}
	}
	for exchange := 1; exchange <= 3; exchange += 1 {
		if _, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId)); err != nil {
			t.Fatal(err)
		}
		b.awaitExchanges(uint64(exchange))
		forks := b.alarmsOf(SidecarHeadAlarmFork)
		if exchange < 3 && len(forks) != 0 {
			t.Fatalf("a fork at exchange %d, before its ref was sent", exchange)
		}
		if exchange == 3 && len(forks) != 1 {
			t.Fatalf("%d forks at exchange 3", len(forks))
		}
	}
	for _, message := range a.sentHeadChecks(t) {
		if HeadCheckMaxListCount < len(message.Refs) {
			t.Errorf("%d refs in one message", len(message.Refs))
		}
	}
	if err := b.stop.SealAllowed(groupId); !errors.Is(err, ErrHeadStop) {
		t.Errorf("the forked ref's group still seals: %v", err)
	}
}

// A HeadCheck at its list caps, with four vetoes and four 8-hop pins, is two envelopes, each within the
// envelope's limit.
func TestHeadCheckAtItsCapsIsTwoEnvelopes(t *testing.T) {
	message := &protocol.HeadCheck{
		NetworkId: NewId().Bytes(),
		Auth:      testMainChain.pin(1000),
		Proven:    testMainChain.pin(1001),
	}
	for i := 0; i < HeadCheckMaxListCount; i += 1 {
		message.Groups = append(message.Groups, &protocol.GroupHead{GroupId: NewId().Bytes(), Epoch: 1 << 40, EpochAuthenticator: bytes.Repeat([]byte{0xa1}, headCheckMaxAuthenticatorByteCount)})
		message.Gens = append(message.Gens, &protocol.GenHead{GroupId: NewId().Bytes(), Generation: 1 << 40, Commitment: testHeadDigest("gen", uint64(i))})
		message.Refs = append(message.Refs, &protocol.RefHead{RepoId: NewId().Bytes(), RefId: NewId().Bytes(), Version: 1 << 40, Chain: testHeadDigest("ref", uint64(i))})
	}
	for i := 0; i < HeadCheckMaxVetoCount; i += 1 {
		message.Vetoes = append(message.Vetoes, bytes.Repeat([]byte{byte(i)}, 250))
	}
	for i := 0; i < HeadCheckMaxUnverifiedSendCount; i += 1 {
		path := [][]byte{}
		for range HeadCheckMaxPathCount {
			path = append(path, NewId().Bytes())
		}
		message.Unverified = append(message.Unverified, &protocol.UnverifiedPin{Pin: testMainChain.pin(uint64(2000 + i)), Path: path})
	}
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	envelopes, err := chunkBody(&protocol.Envelope{Version: WireVersionMajor, Type: uint32(protocol.MessageType_HEAD_CHECK), RequestId: 1, TimeoutMs: 10000}, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 2 {
		t.Errorf("%d B in %d envelopes", len(body), len(envelopes))
	}
	for _, envelope := range envelopes {
		if size := proto.Size(envelope); MaxEnvelopeByteCount < size {
			t.Errorf("an envelope of %d B", size)
		}
	}
}

// A proof serves exactly 64 KiB of entries, and one entry over answers NOT_FOUND, from a phone's 64 KiB
// retain as from the transport's own cap over a source that keeps more.
func TestHeadCheckProofAtItsCap(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 200)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 200, nil)
	ask := func(after uint64) ([]byte, error) {
		body, err := proto.Marshal(&protocol.HeadCheckProofRequest{After: after})
		if err != nil {
			t.Fatal(err)
		}
		return a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, body, nil)
	}
	entryCount := uint64(HeadCheckMaxProofByteCount / testHeadEntryByteCount)
	answer, err := ask(200 - entryCount)
	if err != nil {
		t.Fatalf("exactly 64 KiB: %v", err)
	}
	proof := &protocol.HeadCheckProof{}
	if err := proto.Unmarshal(answer, proof); err != nil {
		t.Fatal(err)
	}
	if uint64(len(proof.Entries)) != entryCount || headCheckProofByteCount(proof.Entries) != HeadCheckMaxProofByteCount {
		t.Errorf("%d entries, %d B", len(proof.Entries), headCheckProofByteCount(proof.Entries))
	}
	if _, err := ask(200 - entryCount - 1); func() protocol.ErrorCode { code, _ := SubprotocolErrorCode(err); return code }() != protocol.ErrorCode_ERR_NOT_FOUND {
		t.Errorf("one entry over, from a 64 KiB retain: %v", err)
	}
	// a source that keeps more is still cut at the cap
	b.source.actLock.Lock()
	b.source.retainByteCount = 4 * HeadCheckMaxProofByteCount
	b.source.actLock.Unlock()
	if _, err := ask(200 - entryCount - 1); func() protocol.ErrorCode { code, _ := SubprotocolErrorCode(err); return code }() != protocol.ErrorCode_ERR_NOT_FOUND {
		t.Errorf("one entry over the transport's cap: %v", err)
	}
}

// api silent past HeadCheckFetchTimeout moves to a proof request: a peer ahead whose entries api
// withholds from this device is fetched at once and halfway, then asked at the deadline, and its proof,
// verified, is proof of withholding, which stops sealing in shared groups until api serves.
func TestHeadCheckSilentApiMovesToAProofRequest(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 20)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 20, nil)
	world.api.withhold(a.sidecarId, 10)
	if _, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	if len(testSentOfTypeRpc(a.testRpcSide, protocol.MessageType_HEAD_CHECK_PROOF_REQUEST)) != 0 {
		t.Fatalf("a proof asked before the deadline")
	}
	a.clock.Advance(a.settings.HeadCheckFetchTimeout)
	event := testAwait(t, a.alarmEvents, "withheld alarm")
	for event.HeadAlarm != SidecarHeadAlarmWithheld {
		event = testAwait(t, a.alarmEvents, "withheld alarm")
	}
	if event.SidecarId == nil || *event.SidecarId != b.sidecarId {
		t.Errorf("withheld names %v", event.SidecarId)
	}
	if fetchCount := func() int { a.source.actLock.Lock(); defer a.source.actLock.Unlock(); return a.source.fetchCount }(); fetchCount < 2 {
		t.Errorf("%d fetches before the proof", fetchCount)
	}
	if len(testSentOfTypeRpc(a.testRpcSide, protocol.MessageType_HEAD_CHECK_PROOF_REQUEST)) != 1 {
		t.Errorf("proof requests %d", len(testSentOfTypeRpc(a.testRpcSide, protocol.MessageType_HEAD_CHECK_PROOF_REQUEST)))
	}
	if err := a.stop.SealAllowed(NewId()); !errors.Is(err, ErrHeadStop) {
		t.Errorf("a shared group seals under withholding: %v", err)
	}
	// api serves: the next round ends the stop
	world.api.serve(a.sidecarId)
	a.subprotocol.headCheck.Load().requestRound()
	a.awaitRounds(2)
	if err := a.stop.SealAllowed(NewId()); err != nil {
		t.Errorf("served, and still stopped: %v", err)
	}
}

// A read_only device answers HeadCheck as any admitted sidecar does.
func TestHeadCheckReadOnlyPeerAnswers(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	world.pair.authority.edit(b.sidecarId, func(row *bridge.SidecarRow) {
		row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	})
	witnessed, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId))
	if err != nil || !witnessed {
		t.Errorf("a read_only peer: witnessed %t: %v", witnessed, err)
	}
}

// A suspended peer passes Hello, since suspension gates grants and witnessing, not identity, and
// answers HeadCheck, but its exchange is no witness.
func TestHeadCheckSuspendedPeerPassesHelloAndWitnessesNothing(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	a.source.setPeer(b.sidecarId, HeadCheckPeer{Admitted: true, Suspended: true})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("a suspended peer's Hello: %v", err)
	}
	witnessed, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId))
	if err != nil {
		t.Fatalf("a suspended peer did not answer: %v", err)
	}
	if witnessed || !a.stop.WitnessedAt().IsZero() {
		t.Errorf("a suspended peer witnessed")
	}
}

// A peer not standing in the responder's state is refused PERMISSION_DENIED and changes nothing.
func TestHeadCheckRefusesAPeerWithoutStanding(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	b.source.setPeer(a.sidecarId, HeadCheckPeer{Admitted: true, Parked: true})
	_, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId))
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("a parked peer: %v", err)
	}
}

// What a side sent of messageType, requests only.
func testSentOfTypeRpc(side *testRpcSide, messageType protocol.MessageType) []*protocol.Envelope {
	envelopes := []*protocol.Envelope{}
	for _, envelope := range side.sent() {
		if envelope.Type == uint32(messageType) && envelope.Flags&EnvelopeFlagResponse == 0 {
			envelopes = append(envelopes, envelope)
		}
	}
	return envelopes
}
