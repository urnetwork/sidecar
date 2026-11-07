//go:build sidecar_testhooks

// Fault schedules on reassembly's barriers (§22.8): each holds one step at the point its name gives and
// lets another step past it, so the order under test is chosen and never left to the scheduler. A barrier
// runs with no state lock held, which is what lets the step let past it take the lock.

package sidecar

import (
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Holds the first goroutine that reaches name with key until the returned release runs, and closes held
// once it is there. Later arrivals pass. Removed with the test.
func testHoldBarrier(t *testing.T, name string, key string) (held chan struct{}, release func()) {
	t.Helper()
	held = make(chan struct{})
	released := make(chan struct{})
	var taken atomic.Bool
	SetTestHooks(&TestHooks{
		Barrier: func(barrierName string, barrierKey string) {
			if barrierName == name && barrierKey == key && taken.CompareAndSwap(false, true) {
				close(held)
				<-released
			}
		},
	})
	t.Cleanup(func() { SetTestHooks(nil) })
	return held, func() { close(released) }
}

// What a held offer came back with.
type testOfferResult struct {
	whole *protocol.Envelope
	err   error
}

// Offers envelope on its own goroutine, its result arriving on the channel.
func testOfferAsync(reassembly *testReassembly, source Id, envelope *protocol.Envelope) chan testOfferResult {
	offered := make(chan testOfferResult, 1)
	go func() {
		whole, err := reassembly.reassembler.offer(source, envelope)
		offered <- testOfferResult{whole: whole, err: err}
	}()
	return offered
}

// A final chunk held before it reaches its group, while the group's deadline passes and the sweep takes
// it: the chunk then finds no group and is dropped, so a body never completes after its reservation went
// back, and nothing is given back twice.
func TestFinalChunkLosesToTheSweep(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(MaxEnvelopeBodyByteCount+1))
	reassembly.offerPending(t, testPeerA, envelopes[0])

	held, release := testHoldBarrier(t, "envelope.reassembly_complete.before", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, envelopes[1])
	<-held
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.reassembler.expire()
	reassembly.requireEmpty(t)
	release()

	result := <-offered
	if result.whole != nil || !errors.Is(result.err, errReassemblyDropped) {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	reassembly.requireEmpty(t)
}

// The other order: the chunk is through and holding its completed body when the sweep runs, which finds
// nothing, so the body is whole and the budget was released once.
func TestSweepAfterCompletionFindsNothing(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	reassembly := newDefaultTestReassembly(t)
	body := testEnvelopeBody(MaxEnvelopeBodyByteCount + 1)
	envelopes := testChunks(t, testEnvelopeHeader(), body)
	reassembly.offerPending(t, testPeerA, envelopes[0])

	held, release := testHoldBarrier(t, "envelope.reassembly_complete.after", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, envelopes[1])
	<-held
	reassembly.requireEmpty(t)
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.reassembler.expire()
	release()

	result := <-offered
	if result.err != nil || !slices.Equal(result.whole.GetBody(), body) {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	reassembly.requireEmpty(t)
	if stats := reassembly.reassembler.currentStats(); stats.expiredCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// Two first chunks of one key, the second landing in the gap after the first took the budget and before
// its group went in: the later insert replaces the earlier group, which gives its bytes back, so one
// reservation stands and not two. offer's order rule keeps a real peer out of this gap, and nothing here
// relies on that.
func TestRacingFirstChunksLeaveOneGroup(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	first := testFirstChunk(t, 1, 5000)
	held, release := testHoldBarrier(t, "envelope.reassembly_reserve", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, first)
	<-held
	reassembly.offerPending(t, testPeerA, first)
	release()

	if result := <-offered; result.whole != nil || result.err != nil {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	if held := reassembly.heldByteCount(); held != 5000 {
		t.Fatalf("holds %d B", held)
	}
}

// A first chunk that read the peer's caps with room, held there while the peer fills them: it reads them
// again as it goes in, is refused, and gives back what it took from the budget.
func TestCapsAreReadAgainAsAGroupGoesIn(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyPeerCount = 1
	reassembly := newTestReassembly(t, settings, 128*1024*1024)
	held, release := testHoldBarrier(t, "envelope.reassembly_reserve", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, testFirstChunk(t, 1, 5000))
	<-held
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 2, 6000))
	release()

	if result := <-offered; result.whole != nil || !errors.Is(result.err, errReassemblyExhausted) {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	if held := reassembly.heldByteCount(); held != 6000 {
		t.Fatalf("holds %d B", held)
	}
}

// run drops a group only once its clock fires a wait, never because a group arrived, so whoever moves
// the clock decides every sweep. The group goes in already due here, its deadline read before the clock
// moved: run wakes for it and must leave it to the clock, so the sweep the test calls is what takes it.
func TestRunSweepsOnlyWhenItsClockFires(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	reassembly := newDefaultTestReassembly(t)
	held, release := testHoldBarrier(t, "envelope.reassembly_reserve", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, testFirstChunk(t, 1, 5000))
	<-held
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	release()
	if result := <-offered; result.whole != nil || result.err != nil {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	// a group not yet due, so a run that swept as it woke still reaches a wait after the sweep
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 2, 6000))
	reassembly.clock.awaitWaitCount(1)
	if held := reassembly.heldByteCount(); held != 5000+6000 {
		t.Fatalf("holds %d B before the clock fired", held)
	}

	reassembly.reassembler.expire()
	if held := reassembly.heldByteCount(); held != 6000 {
		t.Fatalf("holds %d B after the sweep", held)
	}
	if stats := reassembly.reassembler.currentStats(); stats.expiredCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// close running in the same gap: the group finds the reassembler closed, so it is refused and nothing
// stays reserved with no owner to give it back.
func TestCloseInTheGapLeavesNoReservation(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	held, release := testHoldBarrier(t, "envelope.reassembly_reserve", testPeerA.String())
	offered := testOfferAsync(reassembly, testPeerA, testFirstChunk(t, 1, 5000))
	<-held
	reassembly.reassembler.close()
	release()

	if result := <-offered; result.whole != nil || !errors.Is(result.err, errReassemblyExhausted) {
		t.Fatalf("whole %v, err %v", result.whole != nil, result.err)
	}
	reassembly.requireEmpty(t)
}
