//go:build !sidecar_http && !js

// SubprotocolStream's deadlines against a clock that moves while a deadline's wait is being set, timed off
// the clock but not yet on it (stream_conn.go's header). When each Read and Write timed and set its own wait,
// a clock moved to the deadline between the two set the wait late, a whole offset past the deadline, and with
// nothing to move the clock again the call waited on past its deadline: what sidecartest's
// TestStreamReadDeadlineRunsOnTheNetsClock met under load. stream_conn_deadline_hooks_test.go holds a call at
// each step of its own wait.

package sidecar

import (
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// How far past the clock the tests here set a deadline: an offset no loop of a dispatcher waits for, so the
// wait timed for it is the deadline's own.
const testStreamDeadlineOffset = 1234 * time.Millisecond

// A stream from b to a, with both sides. Its ends close as the test ends, after any hold set later lets go, so
// a test failing while a write is held never leaves Close waiting on that write.
func testStreamDeadlineSides(t *testing.T) (a *testRpcSide, b *testRpcSide, opened *SubprotocolStream, accepted *SubprotocolStream) {
	t.Helper()
	_, a, b = newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted = testStreamOpen(t, b, a, incomings, nil)
	t.Cleanup(func() {
		opened.Close()
		accepted.Close()
	})
	return a, b, opened, accepted
}

// Holds the first wait of timeout that clock times, between its timing and its setting, until the returned
// release runs, closing held once it is there. A test that fails while the wait is held lets it go as it
// ends.
func testHoldClockWait(t *testing.T, clock *testEnvelopeClock, timeout time.Duration) (held chan struct{}, release func()) {
	t.Helper()
	held = make(chan struct{})
	released := make(chan struct{})
	release = sync.OnceFunc(func() {
		close(released)
	})
	t.Cleanup(release)
	var taken atomic.Bool
	clock.setOnAfter(func(afterTimeout time.Duration) {
		if afterTimeout == timeout && taken.CompareAndSwap(false, true) {
			close(held)
			<-released
		}
	})
	t.Cleanup(func() {
		clock.setOnAfter(nil)
	})
	return held, release
}

// The clock reaches a read's deadline while the deadline's wait is being set: the read ends with
// os.ErrDeadlineExceeded. The goroutine sets the deadline and then reads, so whichever step times a wait for
// the deadline is the one held, the deadline's set here and, before, the read's own wait, which then hung.
func TestStreamReadDeadlinePassedWhileItsWaitIsSet(t *testing.T) {
	a, _, _, accepted := testStreamDeadlineSides(t)
	held, release := testHoldClockWait(t, a.clock, testStreamDeadlineOffset)
	readErr := make(chan error, 1)
	go func() {
		if err := accepted.SetReadDeadline(a.clock.Now().Add(testStreamDeadlineOffset)); err != nil {
			readErr <- err
			return
		}
		_, err := accepted.Read(make([]byte, 8))
		readErr <- err
	}()
	testAwait(t, held, "a wait timed for the read's deadline")
	a.clock.Advance(testStreamDeadlineOffset)
	release()
	if err := testAwait(t, readErr, "the read past its deadline"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read past its deadline: %v", err)
	}
}

// What a write ended with.
type testStreamWriteResult struct {
	n   int
	err error
}

// TestStreamReadDeadlinePassedWhileItsWaitIsSet for Write: the write comes after its deadline has passed, so it
// sends nothing. Before, the write sent the window's worth and then timed its own wait, which then hung.
func TestStreamWriteDeadlinePassedWhileItsWaitIsSet(t *testing.T) {
	_, b, opened, _ := testStreamDeadlineSides(t)
	held, release := testHoldClockWait(t, b.clock, testStreamDeadlineOffset)
	written := make(chan testStreamWriteResult, 1)
	go func() {
		if err := opened.SetWriteDeadline(b.clock.Now().Add(testStreamDeadlineOffset)); err != nil {
			written <- testStreamWriteResult{err: err}
			return
		}
		// past any window the reader grants, so a write let through would wait for one
		n, err := opened.Write(make([]byte, 4*1024*1024))
		written <- testStreamWriteResult{n: n, err: err}
	}()
	testAwait(t, held, "a wait timed for the write's deadline")
	b.clock.Advance(testStreamDeadlineOffset)
	release()
	if result := testAwait(t, written, "the write past its deadline"); result.n != 0 || !errors.Is(result.err, os.ErrDeadlineExceeded) {
		t.Fatalf("the write past its deadline: %d B, %v", result.n, result.err)
	}
}

// On a clock that sets waits for a time, as sidecartest's FakeClock does, a deadline's wait is set for the deadline
// itself and none by a timeout, so no move of the clock beside the set makes it late (QD-1425); a cleared deadline,
// or one already passed, sets none. The stream here is bare: nothing but its deadlines runs.
func TestStreamDeadlineSetsItsWaitForItsTime(t *testing.T) {
	clock := newTestClockAt()
	stream := &SubprotocolStream{
		subprotocol: &Subprotocol{clock: clock},
		state:       &streamState{phase: streamPhaseOpen},
		changed:     make(chan struct{}),
	}
	read := clock.Now().Add(time.Second)
	write := clock.Now().Add(2 * time.Second)
	for _, err := range []error{
		stream.SetReadDeadline(read),
		stream.SetWriteDeadline(write),
		stream.SetReadDeadline(time.Time{}),
		stream.SetWriteDeadline(clock.Now()),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if times, timeoutCount := clock.asked(); !slices.EqualFunc(times, []time.Time{read, write}, time.Time.Equal) || timeoutCount != 0 {
		t.Fatalf("waits for a time set for %v, %d set by a timeout", times, timeoutCount)
	}
}
