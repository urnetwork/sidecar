// §9.7's affinity branch in pure form (SOCK-M6-01): rendezvous stability under membership change, the 1.25 × mean
// est skip, opt-in on the listener, and the score's bytes, which the Redis store's script repeats with redis.sha1hex.

package socketsservice

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

// A listener that honors affinity keys.
func testAffinityCandidate(index int) *SocketCandidate {
	candidate := testCandidate(index)
	candidate.Affinity = true
	return candidate
}

// A keyed Find, key standing for one visitor's keyed /24.
func testAffinityRequest(key []byte) *SocketPickRequest {
	request := testRequest()
	request.AffinityKey = key
	return request
}

// A key per visitor, fixed.
func testAffinityKey(visitor int) []byte {
	return binary.BigEndian.AppendUint64([]byte("visitor-key-"), uint64(visitor))
}

// The score is SHA-1 over the key and the listener's id in lowercase hex: what a script's redis.sha1hex(key .. id)
// gives, as bytes.
func TestAffinityScoreIsTheScriptsHash(t *testing.T) {
	listenerClientId := testId(0x2a)
	key := []byte("a keyed /24")
	want := sha1.Sum([]byte("a keyed /24" + hex.EncodeToString(listenerClientId[:])))
	if got := SocketAffinityScore(key, listenerClientId); got != want {
		t.Fatalf("score %x, want %x", got, want)
	}
	if SocketAffinityScore([]byte("another key"), listenerClientId) == want {
		t.Fatal("two keys score one listener alike")
	}
}

// One key reaches one listener on every Find while nothing moves, and its backup is the next in its order.
func TestAffinityKeyReachesTheSameListener(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	candidates := []*SocketCandidate{}
	for index := range 8 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	for visitor := range 50 {
		first := PickSocketListeners(candidates, testAffinityRequest(testAffinityKey(visitor)), settings)
		if first.Outcome != SocketPickFound || first.Primary == nil || first.Backup == nil || first.Primary == first.Backup {
			t.Fatalf("visitor %d: %+v", visitor, first)
		}
		for draw := range 5 {
			request := testAffinityRequest(testAffinityKey(visitor))
			request.FirstDraw = uint32(draw * 7919)
			request.SecondDraw = uint32(draw * 104729)
			again := PickSocketListeners(candidates, request, settings)
			if again.Primary != first.Primary || again.Backup != first.Backup {
				t.Fatalf("visitor %d moved with the draws", visitor)
			}
		}
	}
}

// Rendezvous stability: a listener joining takes only keys it now ranks first for, and a listener leaving moves only
// the keys it held, so every other key keeps its listener.
func TestAffinityIsStableUnderMembershipChange(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	candidates := []*SocketCandidate{}
	for index := range 10 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	primaryOf := func(candidates []*SocketCandidate, visitor int) *SocketCandidate {
		return PickSocketListeners(candidates, testAffinityRequest(testAffinityKey(visitor)), settings).Primary
	}
	before := map[int]*SocketCandidate{}
	for visitor := range 2000 {
		before[visitor] = primaryOf(candidates, visitor)
	}

	joined := append(append([]*SocketCandidate{}, candidates...), testAffinityCandidate(10))
	movedCount := 0
	for visitor := range 2000 {
		after := primaryOf(joined, visitor)
		if after != before[visitor] {
			movedCount += 1
			if after.ListenerClientId != testId(10) {
				t.Fatalf("visitor %d moved to a listener that was there before", visitor)
			}
		}
	}
	if movedCount == 0 || 2000*2/11 < movedCount {
		t.Fatalf("a joining listener took %d of 2,000 keys", movedCount)
	}

	left := append([]*SocketCandidate{}, candidates[:3]...)
	left = append(left, candidates[4:]...)
	for visitor := range 2000 {
		after := primaryOf(left, visitor)
		if before[visitor].ListenerClientId != testId(3) && after != before[visitor] {
			t.Fatalf("visitor %d moved though its listener stayed", visitor)
		}
		if after.ListenerClientId == testId(3) {
			t.Fatalf("visitor %d reached a listener that left", visitor)
		}
	}
}

// Keys spread over a group: each of ten equal listeners takes its tenth of 10,000 keys within 20%.
func TestAffinitySpreadsKeys(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	candidates := []*SocketCandidate{}
	for index := range 10 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	counts := map[*SocketCandidate]int{}
	for visitor := range 10000 {
		counts[PickSocketListeners(candidates, testAffinityRequest(testAffinityKey(visitor)), settings).Primary] += 1
	}
	for _, candidate := range candidates {
		if count := counts[candidate]; count < 800 || 1200 < count {
			t.Errorf("listener %v took %d of 10,000 keys", candidate.ListenerClientId, count)
		}
	}
}

// A key's first listener once full, its est at ⌈1.25 × (the sum of est + 1) / n⌉, is skipped for its next, one below
// that stands, and a full listener is no backup either.
func TestAffinitySkipsAListenerAboveTheBound(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	key := testAffinityKey(7)
	order := func(candidates []*SocketCandidate) []*SocketCandidate {
		ranked := []*SocketCandidate{}
		remaining := append([]*SocketCandidate{}, candidates...)
		for 0 < len(remaining) {
			best := 0
			for index, candidate := range remaining {
				score := SocketAffinityScore(key, candidate.ListenerClientId)
				bestScore := SocketAffinityScore(key, remaining[best].ListenerClientId)
				if string(score[:]) > string(bestScore[:]) {
					best = index
				}
			}
			ranked = append(ranked, remaining[best])
			remaining = append(remaining[:best], remaining[best+1:]...)
		}
		return ranked
	}
	candidates := []*SocketCandidate{}
	for index := range 4 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	ranked := order(candidates)
	// est 40, 20, 20, 0: the capacity is ⌈1.25 × 81 / 4⌉ = 26, so the first ranked is full
	testLoad(ranked[0], 40)
	testLoad(ranked[1], 20)
	testLoad(ranked[2], 20)
	testLoad(ranked[3], 0)
	result := PickSocketListeners(candidates, testAffinityRequest(key), settings)
	if result.Primary != ranked[1] || result.Backup != ranked[2] {
		t.Fatalf("a full listener: primary %v, backup %v", result.Primary.ListenerClientId, result.Backup.ListenerClientId)
	}
	// est 25, 25, 30, 0: the capacity is 26, so the first two stand and the third is full
	testLoad(ranked[0], 25)
	testLoad(ranked[1], 25)
	testLoad(ranked[2], 30)
	result = PickSocketListeners(candidates, testAffinityRequest(key), settings)
	if result.Primary != ranked[0] || result.Backup != ranked[1] {
		t.Fatal("a listener below its capacity was skipped")
	}
	// est 5, 5, 5, 0: the capacity is ⌈1.25 × 16 / 4⌉ = 5 exactly, so all three are full and the last stands alone
	testLoad(ranked[0], 5)
	testLoad(ranked[1], 5)
	testLoad(ranked[2], 5)
	result = PickSocketListeners(candidates, testAffinityRequest(key), settings)
	if result.Primary != ranked[3] || result.Backup != nil {
		t.Fatal("a listener at its capacity exactly took the key")
	}
	// est 20, 40, 20, 20: the capacity is ⌈1.25 × 101 / 4⌉ = 32, so the second ranked is no backup
	testLoad(ranked[0], 20)
	testLoad(ranked[1], 40)
	testLoad(ranked[2], 20)
	testLoad(ranked[3], 20)
	result = PickSocketListeners(candidates, testAffinityRequest(key), settings)
	if result.Primary != ranked[0] || result.Backup != ranked[2] {
		t.Fatal("a listener above the bound was the backup")
	}
	// a looser bound keeps the first ranked however loaded
	settings.AffinityLoadPercent = 1000
	testLoad(ranked[0], 200)
	result = PickSocketListeners(candidates, testAffinityRequest(key), settings)
	if result.Primary != ranked[0] {
		t.Fatal("the bound's percent is not read from settings")
	}
}

// Opt-in on the listener: only listeners registered with affinity take part, and with none the pick is P2C's, the
// same as without a key.
func TestAffinityIsTheListenersToOptIn(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	mixed := []*SocketCandidate{testCandidate(1), testAffinityCandidate(2), testCandidate(3), testAffinityCandidate(4)}
	for visitor := range 200 {
		result := PickSocketListeners(mixed, testAffinityRequest(testAffinityKey(visitor)), settings)
		if !result.Primary.Affinity || (result.Backup != nil && !result.Backup.Affinity) {
			t.Fatalf("visitor %d reached a listener that did not opt in", visitor)
		}
	}
	none := []*SocketCandidate{testCandidate(1), testCandidate(2), testCandidate(3)}
	for visitor := range 50 {
		request := testAffinityRequest(testAffinityKey(visitor))
		request.FirstDraw = uint32(visitor * 31)
		request.SecondDraw = uint32(visitor * 17)
		keyed := PickSocketListeners(none, request, settings)
		request.AffinityKey = nil
		unkeyed := PickSocketListeners(none, request, settings)
		if keyed.Primary != unkeyed.Primary || keyed.Backup != unkeyed.Backup {
			t.Fatalf("visitor %d: a key changed a pick with no listener that opted in", visitor)
		}
	}
}

// Step 1's filter runs before the branch: a key never reaches a listener the filter refuses, nor one past its
// max_streams, and a group the filter empties answers as without a key.
func TestAffinityRunsAfterTheFilter(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	key := testAffinityKey(3)
	candidates := []*SocketCandidate{}
	for index := range 6 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	first := PickSocketListeners(candidates, testAffinityRequest(key), settings).Primary
	first.Draining = true
	if result := PickSocketListeners(candidates, testAffinityRequest(key), settings); result.Primary == first || result.Backup == first {
		t.Fatal("a draining listener took a keyed Find")
	}
	first.Draining = false
	testLoad(first, first.MaxStreams)
	if result := PickSocketListeners(candidates, testAffinityRequest(key), settings); result.Primary == first {
		t.Fatal("a full listener took a keyed Find")
	}
	for _, candidate := range candidates {
		candidate.Serving = false
	}
	if result := PickSocketListeners(candidates, testAffinityRequest(key), settings); result.Outcome != SocketPickNoListener {
		t.Fatalf("a group with nothing serving answered %v", result.Outcome)
	}
}

// The pick changes nothing it was given, as P2C's does not.
func TestAffinityChangesNothing(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	candidates := []*SocketCandidate{testAffinityCandidate(1), testAffinityCandidate(2)}
	key := testAffinityKey(1)
	request := testAffinityRequest(key)
	before := fmt.Sprintf("%+v %+v %x", *candidates[0], *candidates[1], request.AffinityKey)
	PickSocketListeners(candidates, request, settings)
	if after := fmt.Sprintf("%+v %+v %x", *candidates[0], *candidates[1], request.AffinityKey); after != before {
		t.Fatal("the pick changed its arguments")
	}
}

// The branch at scale (SOCK.md reading 15): a keyed Find ranks its whole group, here 10,000 listeners that opted in.
func BenchmarkPickSocketAffinity(b *testing.B) {
	settings := DefaultSocketSchedulerSettings()
	candidates := []*SocketCandidate{}
	for index := range 10000 {
		candidates = append(candidates, testAffinityCandidate(index))
	}
	request := testAffinityRequest(testAffinityKey(1))
	b.ReportAllocs()
	for b.Loop() {
		PickSocketListeners(candidates, request, settings)
	}
}
