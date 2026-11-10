//go:build !sidecar_http && !js

// HeadCheck's schedule (PROTO-M2-03): the first RPC with a peer each HeadCheckInterval starts one
// exchange; rounds pick at most two of other members and the rest own, sharing a repo first, on a
// seeded draw; rounds run at start and each interval; and the revoker's request runs one at once.

package sidecar

import (
	"context"
	mathrand "math/rand/v2"
	"slices"
	"testing"
)

// The first RPC with a peer each HeadCheckInterval starts one HeadCheck beside it: two calls start one,
// and a call an interval later starts another.
func TestHeadCheckFirstExchangePerIntervalTriggersOnce(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	transport := a.subprotocol.headCheck.Load()
	before, _ := transport.exchangeCount.Get()
	for range 2 {
		if _, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil); err != nil {
			t.Fatal(err)
		}
	}
	a.awaitExchanges(before + 1)
	if count := len(a.sentHeadChecks(t)); count != 1 {
		t.Errorf("%d HeadChecks for two calls", count)
	}
	// the round at start, so the interval runs from it
	a.awaitRounds(1)
	a.clock.Advance(a.settings.HeadCheckInterval)
	b.clock.Advance(b.settings.HeadCheckInterval)
	a.awaitRounds(2)
	before, _ = transport.exchangeCount.Get()
	if _, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil); err != nil {
		t.Fatal(err)
	}
	a.awaitExchanges(before + 1)
	if count := len(a.sentHeadChecks(t)); count != 2 {
		t.Errorf("%d HeadChecks after an interval", count)
	}
}

// Rounds pick at most HeadCheckRoundOtherMemberCount of other members and fill the rest with own
// devices, those sharing a repo first; fewer candidates make fewer picks; a seed repeats its picks; and
// a peer not standing or suspended is never picked.
func TestHeadCheckRoundPicks(t *testing.T) {
	peers := map[Id]HeadCheckPeer{}
	candidates := []HeadCheckCandidate{}
	addCandidate := func(own bool, sharesRepo bool, peer HeadCheckPeer) Id {
		sidecarId := NewId()
		peers[sidecarId] = peer
		candidates = append(candidates, HeadCheckCandidate{SidecarId: sidecarId, Own: own, SharesRepo: sharesRepo})
		return sidecarId
	}
	standing := HeadCheckPeer{Admitted: true}
	otherSharing := []Id{addCandidate(false, true, standing), addCandidate(false, true, standing)}
	addCandidate(false, false, standing)
	addCandidate(false, true, HeadCheckPeer{Admitted: true, Suspended: true})
	ownSharing := addCandidate(true, true, standing)
	addCandidate(true, false, standing)
	addCandidate(true, false, standing)
	revoked := addCandidate(true, true, HeadCheckPeer{Admitted: true, Revoked: true})
	parked := addCandidate(true, true, HeadCheckPeer{Admitted: true, Parked: true})
	selfId := addCandidate(true, true, standing)
	peerState := testHeadCheckPeerMap(peers)

	random := testSeededRandom(1)
	picks := headCheckRoundPicks(candidates, peerState, selfId, 4, random)
	if len(picks) != 4 {
		t.Fatalf("%d picks", len(picks))
	}
	// the two others are the two sharing a repo, then own ones, the sharing one first
	if !slices.Contains(otherSharing, picks[0]) || !slices.Contains(otherSharing, picks[1]) || picks[2] != ownSharing {
		t.Errorf("picks %v", picks)
	}
	for _, pick := range picks {
		if pick == revoked || pick == parked || pick == selfId || peers[pick].Suspended {
			t.Errorf("picked %s", pick)
		}
	}
	if repeat := headCheckRoundPicks(candidates, peerState, selfId, 4, testSeededRandom(1)); !slices.Equal(repeat, picks) {
		t.Errorf("a seed repeated %v as %v", picks, repeat)
	}
	// fewer candidates than picks
	few := []HeadCheckCandidate{candidates[0], candidates[4]}
	if picks := headCheckRoundPicks(few, peerState, selfId, 4, random); len(picks) != 2 {
		t.Errorf("%d picks of two candidates", len(picks))
	}
	// others alone: at most two
	others := candidates[:3]
	if picks := headCheckRoundPicks(others, peerState, selfId, 4, random); len(picks) != HeadCheckRoundOtherMemberCount {
		t.Errorf("%d picks of other members only", len(picks))
	}
}

// A round runs at each start and each HeadCheckInterval with its picks, resolving a pick with no
// standing Hello through api's binding, checked against its admission.
func TestHeadCheckRoundsRunAtStartAndEachInterval(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	a.stateLock.Lock()
	a.candidates = []HeadCheckCandidate{{SidecarId: b.sidecarId, Own: true, SharesRepo: true}}
	a.stateLock.Unlock()
	// the round at start may have run before the candidates were set
	a.awaitRounds(1)
	sentCount := len(a.sentHeadChecks(t))
	a.clock.Advance(a.settings.HeadCheckInterval)
	a.awaitRounds(2)
	if count := len(a.sentHeadChecks(t)); count != sentCount+1 {
		t.Errorf("%d HeadChecks after a round with a pick, %d before", count, sentCount)
	}
	if a.stop.WitnessedAt() != a.clock.Now() {
		t.Errorf("the round did not witness: %s", a.stop.WitnessedAt())
	}
}

// A revocation this device signed asks for a round at once, and the round's peer, holding a pin past it,
// clears it.
func TestHeadCheckRevokerRoundClearsTheRevocation(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	a.stateLock.Lock()
	a.candidates = []HeadCheckCandidate{{SidecarId: b.sidecarId, Own: true, SharesRepo: true}}
	a.stateLock.Unlock()
	a.awaitRounds(1)
	rounds, _ := a.subprotocol.headCheck.Load().roundCount.Get()
	a.clock.Advance(a.settings.HeadCheckTimeout)
	a.stop.TrackRevocation(9)
	a.awaitRounds(rounds + 1)
	if positions := a.stop.UnwitnessedRevocations(); len(positions) != 0 {
		t.Errorf("unwitnessed %v", positions)
	}
}

// A peer state from a map.
type testHeadCheckPeerMap map[Id]HeadCheckPeer

func (self testHeadCheckPeerMap) HeadCheckPeer(sidecarId Id) HeadCheckPeer {
	return self[sidecarId]
}

// A draw in [0, n) from a seeded generator.
func testSeededRandom(seed uint64) func(n int) int {
	generator := mathrand.New(mathrand.NewPCG(seed, seed+1))
	return func(n int) int {
		return generator.IntN(n)
	}
}
