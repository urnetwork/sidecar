//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-33: the order, DESIGN-DETAILS 7.6's search_remote_order_test.go list: H over fixed ids with its bytes here,
// the own indexer that answered last first, another member's indexer sticky by what it served, and two devices of one
// member starting at one indexer.

import (
	"slices"
	"testing"
	"time"
)

// H(a, b), the first 8 bytes of SHA-256("UR search rendezvous 1" || a || b), big-endian, over fixed ids; computed
// apart from this code.
func TestRendezvousVector(t *testing.T) {
	var a, b Id
	for i := range a {
		a[i], b[i] = byte(i+1), byte(i+17)
	}
	if got := searchRemoteRendezvous(a, b); got != 0x840daa463c391ddf {
		t.Errorf("H(a, b) %#x", got)
	}
	if got := searchRemoteRendezvous(b, a); got != 0xfb397625759b0979 {
		t.Errorf("H(b, a) %#x", got)
	}
}

// The own indexer that answered last within RemoteOnlineTimeout goes first, whatever H says; past it, H decides.
func TestOwnOrderPutsTheLastAnswerFirst(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	testSearchRemoteMoreOwn(t, team, "dana nas two")
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	view, err := fixture.client.orderView([]Id{team.danaVault})
	if err != nil {
		t.Fatal(err)
	}
	own, _ := fixture.client.candidatesFor(view, team.danaVault, map[Id]bool{}, fixture.clock.Now())
	if len(own) != 2 {
		t.Fatalf("own %v", own)
	}
	byHash := own[0]
	later := own[1]
	func() {
		fixture.client.stateLock.Lock()
		defer fixture.client.stateLock.Unlock()
		fixture.client.healthWithLock(later).answeredAt = fixture.clock.Now()
	}()
	view, _ = fixture.client.orderView([]Id{team.danaVault})
	own, _ = fixture.client.candidatesFor(view, team.danaVault, map[Id]bool{}, fixture.clock.Now())
	if own[0] != later {
		t.Errorf("the one that answered last is not first: %v", own)
	}
	fixture.clock.advance(fixture.settings.RemoteOnlineTimeout)
	view, _ = fixture.client.orderView([]Id{team.danaVault})
	own, _ = fixture.client.candidatesFor(view, team.danaVault, map[Id]bool{}, fixture.clock.Now())
	if own[0] != byHash {
		t.Errorf("past RemoteOnlineTimeout the hash decides: %v", own)
	}
}

// otherKey: another member's indexer that served a repo of the search's scope within RemoteServedTimeout stays first,
// over the one H would put first; with no memory, H by the member decides.
func TestAnotherMembersIndexerIsSticky(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	view, err := fixture.client.orderView([]Id{team.teamRepo})
	if err != nil {
		t.Fatal(err)
	}
	others := []Id{team.net.owner.sidecarId, team.agent.sidecarId}
	searchRemoteSortBy(others, view.otherKey)
	last := others[len(others)-1]
	if err := fixture.world.state.NoteServed(last, team.teamRepo); err != nil {
		t.Fatal(err)
	}
	view, _ = fixture.client.orderView([]Id{team.teamRepo})
	searchRemoteSortBy(others, view.otherKey)
	if others[0] != last {
		t.Errorf("the indexer that served the scope is not first: %v", others)
	}
}

// Two devices of one member start at one other member's indexer: otherKey hashes the member, not the device.
func TestTwoDevicesOfAMemberStartAtOneIndexer(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	phone := newTestSearchRemoteAsker(t, team, team.danaPhone)
	laptop := newTestSearchRemoteAsker(t, team, team.danaLaptop)
	others := func(fixture *testSearchRemoteAsker) []Id {
		view, err := fixture.client.orderView([]Id{team.teamRepo})
		if err != nil {
			t.Fatal(err)
		}
		ids := []Id{team.net.owner.sidecarId, team.agent.sidecarId}
		searchRemoteSortBy(ids, view.otherKey)
		return ids
	}
	if a, b := others(phone), others(laptop); !slices.Equal(a, b) {
		t.Errorf("the member's devices start apart: %v, %v", a, b)
	}
}

// usable: a skipped indexer, a refused repo and a dropped indexer are each passed over until their time or change.
func TestUsableSkipsRefusalsAndDrops(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	state := team.net.log.State()
	now := fixture.clock.Now()
	nas := team.danaNas.sidecarId
	if !fixture.client.usable(state, nas, team.danaVault, map[Id]bool{}, now) {
		t.Fatal("not usable at first")
	}
	func() {
		fixture.client.stateLock.Lock()
		defer fixture.client.stateLock.Unlock()
		health := fixture.client.healthWithLock(nas)
		health.skipUntil = now.Add(time.Minute)
	}()
	if fixture.client.usable(state, nas, team.danaVault, map[Id]bool{}, now) {
		t.Error("a skipped indexer is usable")
	}
	if !fixture.client.usable(state, nas, team.danaVault, map[Id]bool{}, now.Add(time.Minute)) {
		t.Error("a skip outlived its time")
	}
	func() {
		fixture.client.stateLock.Lock()
		defer fixture.client.stateLock.Unlock()
		health := fixture.client.healthWithLock(nas)
		health.dropped, health.droppedAs = true, searchRemoteDropMark(state, nas)
	}()
	if fixture.client.usable(state, nas, team.danaVault, map[Id]bool{}, now.Add(time.Minute)) {
		t.Error("a dropped indexer is usable")
	}
	if err := fixture.world.state.SetDistrustUntil(nas, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if fixture.client.usable(state, nas, team.danaVault, map[Id]bool{}, now.Add(2*time.Minute)) {
		t.Error("a distrusted indexer is usable")
	}
	if fixture.client.usable(state, nas, team.danaVault, map[Id]bool{nas: true}, now) {
		t.Error("a tried indexer is usable")
	}
}
