//go:build !sidecar_http && !js

// Hello's feature bits (PROTO-M10-01): what SetFeatures sets rides Hello and HelloResult alike, bit 1
// only toward the peers it names; bits this release does not implement are refused; a receiver records a
// peer's bits, ignores those it does not know, and grants nothing by one, its own bit 0 alone deciding
// what a control contract carries to it.
//
// The asking role beside bit 1 (owner decision 609, which removed PROTO-M10-04's and PROTO-M10-06's
// marking, windows, keepalive and warm pairs): bit 1 marks nothing, so a Hello carrying it is one Hello and
// one HelloResult and a search on a standing Hello runs none first; nothing keeps a pair warm, so an app
// host in the foreground with its indexer named sends no Ping and its Hello stands HelloCacheTimeout and
// no longer; and HeadCheck's round counts the named first-choice own indexer in the foreground only, each
// round, with no Hello standing before it.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// The type of each envelope in envelopes, in order.
func testEnvelopeTypes(envelopes []*protocol.Envelope) []string {
	types := []string{}
	for _, envelope := range envelopes {
		types = append(types, protocol.MessageType(envelope.Type).String())
	}
	return types
}

// When the Hello on record with peerId ends, and false with none on record.
func testSessionExpireTime(subprotocol *Subprotocol, peerId connect.Id) (time.Time, bool) {
	subprotocol.stateLock.Lock()
	defer subprotocol.stateLock.Unlock()
	identity, ok := subprotocol.sourceIdIdentities[peerId]
	return identity.expireTime, ok
}

// Bit 1 marks nothing: a search on a Hello that stands, verified before the app asked the indexer, runs no
// Hello first, and a Hello carrying the bit is one Hello answered by one HelloResult.
func TestBitOneMarksNothing(t *testing.T) {
	app, indexer, runs := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	if identity, _ := indexer.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != 0 {
		t.Fatalf("the app's first Hello carried %#x", identity.Features)
	}
	if err := app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(indexer.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	sentBefore := len(app.sent())
	if _, err := app.subprotocol.Call(t.Context(), Id(indexer.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil); err != nil {
		t.Fatal(err)
	}
	<-runs
	if types := testEnvelopeTypes(app.sent()[sentBefore:]); !slices.Equal(types, []string{"SEARCH"}) {
		t.Errorf("a search on a standing Hello sent %v", types)
	}

	app.subprotocol.forgetPeer(indexer.clientId)
	appBefore, indexerBefore := len(app.sent()), len(indexer.sent())
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	if identity, _ := indexer.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != SubprotocolFeatureAsksSearch {
		t.Errorf("the indexer read the app's features %#x", identity.Features)
	}
	if types := testEnvelopeTypes(app.sent()[appBefore:]); !slices.Equal(types, []string{"HELLO"}) {
		t.Errorf("the app's bit-1 Hello sent %v", types)
	}
	if types := testEnvelopeTypes(indexer.sent()[indexerBefore:]); !slices.Equal(types, []string{"HELLO_RESULT"}) {
		t.Errorf("the indexer answered a bit-1 Hello with %v", types)
	}
}

// Nothing keeps a pair warm: an app host in the foreground, its first-choice own indexer named and a bit-1
// Hello standing, sends nothing for 55 minutes, and the Hello stands HelloCacheTimeout from its
// verification and no longer, on both sides.
func TestTheAskingRoleKeepsNoPairWarm(t *testing.T) {
	pair := newTestRpcPair(t)
	app := pair.add(nil, nil)
	indexer := pair.add(nil, nil)
	if err := indexer.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(indexer.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	app.subprotocol.SetSearchIndexer(indexer.sidecarId)
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	verifiedAt := app.clock.Now()
	for _, c := range []struct {
		side   *testRpcSide
		peerId connect.Id
	}{{side: app, peerId: indexer.clientId}, {side: indexer, peerId: app.clientId}} {
		if expireTime, ok := testSessionExpireTime(c.side.subprotocol, c.peerId); !ok || !expireTime.Equal(verifiedAt.Add(c.side.settings.HelloCacheTimeout)) {
			t.Errorf("the Hello ends at %s (%t), want HelloCacheTimeout after %s", expireTime, ok, verifiedAt)
		}
	}
	appBefore, indexerBefore := len(app.sent()), len(indexer.sent())
	for range 55 {
		indexer.clock.Advance(time.Minute)
		app.clock.Advance(time.Minute)
	}
	if types := testEnvelopeTypes(app.sent()[appBefore:]); len(types) != 0 {
		t.Errorf("the app sent %v in 55 minutes", types)
	}
	if types := testEnvelopeTypes(indexer.sent()[indexerBefore:]); len(types) != 0 {
		t.Errorf("the indexer sent %v in 55 minutes", types)
	}
	if app.subprotocol.peerVerified(indexer.clientId) || indexer.subprotocol.peerVerified(app.clientId) {
		t.Errorf("a Hello stood past HelloCacheTimeout")
	}
	if _, standing := app.subprotocol.sessionTime(indexer.clientId); standing {
		t.Errorf("the session reads as standing past HelloCacheTimeout")
	}
}

// HeadCheck's round reads the named indexer only in the foreground, and the zero Id names none.
func TestTheSearchIndexerCountsOnlyInTheForeground(t *testing.T) {
	pair := newTestRpcPair(t)
	app := pair.add(nil, nil)
	indexerId := NewId()
	app.subprotocol.SetSearchIndexer(indexerId)
	if sidecarId, ok := app.subprotocol.foregroundSearchIndexer(); ok {
		t.Errorf("%s counted in the background", sidecarId)
	}
	app.subprotocol.SetForeground(true)
	if sidecarId, ok := app.subprotocol.foregroundSearchIndexer(); !ok || sidecarId != indexerId {
		t.Errorf("counted %s (%t), want the named indexer", sidecarId, ok)
	}
	app.subprotocol.SetSearchIndexer(Id{})
	if sidecarId, ok := app.subprotocol.foregroundSearchIndexer(); ok {
		t.Errorf("%s counted with none named", sidecarId)
	}
	app.subprotocol.SetSearchIndexer(indexerId)
	app.subprotocol.SetForeground(false)
	if sidecarId, ok := app.subprotocol.foregroundSearchIndexer(); ok {
		t.Errorf("%s counted back in the background", sidecarId)
	}
}

// In the foreground, HeadCheck's round counts the first-choice indexer among its own picks, the others
// staying random; in the background the indexer is one candidate among the rest.
func TestHeadCheckRoundCountsTheIndexer(t *testing.T) {
	indexerId := NewId()
	candidates := []HeadCheckCandidate{{SidecarId: indexerId, Own: true}}
	peers := testHeadCheckPeerMap{indexerId: {Admitted: true}}
	for range 6 {
		sidecarId := NewId()
		candidates = append(candidates, HeadCheckCandidate{SidecarId: sidecarId, Own: true, SharesRepo: true})
		peers[sidecarId] = HeadCheckPeer{Admitted: true}
	}
	for seed := uint64(1); seed <= 20; seed += 1 {
		picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, DefaultSidecarProtocolSettings().HeadCheckRoundOtherMemberCount, testSeededRandom(seed), &indexerId)
		if len(picks) != 4 || picks[0] != indexerId {
			t.Errorf("seed %d: picks %v", seed, picks)
		}
	}
	// without it, the indexer shares no repo and loses to six that do
	for seed := uint64(1); seed <= 20; seed += 1 {
		if picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, DefaultSidecarProtocolSettings().HeadCheckRoundOtherMemberCount, testSeededRandom(seed), nil); slices.Contains(picks, indexerId) {
			t.Errorf("seed %d: the indexer picked in the background", seed)
		}
	}
}

// Each foreground round of an app host exchanges a HeadCheck with the first-choice own indexer it named by
// sidecar_id, no Hello with it standing before the round, and fills its other picks from the rest.
func TestHeadCheckRoundsReachTheNamedIndexer(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	app := world.add(testMainChain, 10, nil)
	peers := []*testHeadCheckSide{}
	for range 8 {
		peers = append(peers, world.add(testMainChain, 10, nil))
	}
	indexer := peers[len(peers)-1]
	var checkedLock sync.Mutex
	checked := map[connect.Id]int{}
	app.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == app.testRpcSide && envelope.Type == uint32(protocol.MessageType_HEAD_CHECK) &&
			envelope.Flags&(EnvelopeFlagResponse|EnvelopeFlagMore) == 0 {
			checkedLock.Lock()
			defer checkedLock.Unlock()
			checked[to.clientId] += 1
		}
		return envelope
	})
	candidates := []HeadCheckCandidate{}
	for _, peer := range peers {
		candidates = append(candidates, HeadCheckCandidate{SidecarId: peer.sidecarId, Own: true, SharesRepo: true})
	}
	app.stateLock.Lock()
	app.candidates = candidates
	app.stateLock.Unlock()
	app.subprotocol.SetSearchIndexer(indexer.sidecarId)
	app.subprotocol.SetForeground(true)
	// the round at start may have run before the candidates were set
	app.awaitRounds(1)
	rounds, _ := app.subprotocol.headCheck.Load().roundCount.Get()
	func() {
		checkedLock.Lock()
		defer checkedLock.Unlock()
		checked = map[connect.Id]int{}
	}()
	roundCount := 6
	for i := range roundCount {
		app.clock.Advance(app.settings.HeadCheckInterval)
		app.awaitRounds(rounds + uint64(i) + 1)
	}
	checkedLock.Lock()
	defer checkedLock.Unlock()
	if checked[indexer.clientId] != roundCount {
		t.Errorf("the named indexer was checked in %d of %d rounds", checked[indexer.clientId], roundCount)
	}
	total := 0
	for _, count := range checked {
		total += count
	}
	if want := roundCount * app.settings.HeadCheckRoundPeerCount; total != want {
		t.Errorf("%d HeadChecks in %d rounds, want %d", total, roundCount, want)
	}
}

// Bit 0 rides Hello and HelloResult alike, and bit 1 only toward the peers asksSearch names.
func TestFeaturesRideHelloAndHelloResult(t *testing.T) {
	pair := newTestRpcPair(t)
	app := pair.add(nil, nil)
	indexer := pair.add(nil, nil)
	other := pair.add(nil, nil)
	if err := indexer.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(indexer.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []*testRpcSide{indexer, other} {
		if err := app.subprotocol.EnsureHello(t.Context(), Id(peer.clientId)); err != nil {
			t.Fatal(err)
		}
	}
	if identity, _ := indexer.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != SubprotocolFeatureAsksSearch {
		t.Errorf("the indexer read the app's features %#x", identity.Features)
	}
	if identity, _ := other.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != 0 {
		t.Errorf("another peer read the app's features %#x", identity.Features)
	}
	if identity, _ := app.subprotocol.PeerIdentity(Id(indexer.clientId)); identity.Features != SubprotocolFeatureServesSearch {
		t.Errorf("the app read the indexer's HelloResult features %#x", identity.Features)
	}
}

// A bit this release does not implement, and bit 1 toward every peer, are refused.
func TestSetFeaturesRefusesBitsItMayNotSend(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	for _, features := range []uint64{1 << 2, 1 << 63, SubprotocolFeatureAsksSearch, SubprotocolFeatureServesSearch | SubprotocolFeatureAsksSearch} {
		if err := a.subprotocol.SetFeatures(features, nil); !errors.Is(err, errSubprotocolFeatures) {
			t.Errorf("%#x: %v", features, err)
		}
	}
	if err := a.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Errorf("bit 0: %v", err)
	}
}

// A receiver keeps a peer's bits, unknown ones included, refuses nothing for them, and grants nothing by
// them: a peer claiming bit 0 makes this side serve no SEARCH on control, which its own bit decides.
func TestUnknownBitsAreIgnoredAndBitsGrantNothing(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == a && envelope.Type == uint32(protocol.MessageType_HELLO) {
			hello := &protocol.Hello{}
			proto.Unmarshal(envelope.Body, hello)
			hello.Features = SubprotocolFeatureServesSearch | 1<<9 | 1<<40
			envelope.Body, _ = proto.Marshal(hello)
		}
		return envelope
	})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("unknown bits refused: %v", err)
	}
	if identity, _ := b.subprotocol.PeerIdentity(Id(a.clientId)); identity.Features != SubprotocolFeatureServesSearch|1<<9|1<<40 {
		t.Errorf("recorded %#x", identity.Features)
	}
	ran := make(chan struct{}, 1)
	if _, err := b.subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		ran <- struct{}{}
		return testSearchReply(t, request)
	}, nil); err != nil {
		t.Fatal(err)
	}
	a.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("SEARCH on control to a side without its own bit 0: %v", err)
	}
	select {
	case <-ran:
		t.Errorf("a peer's bit opened SEARCH on control")
	default:
	}
}
