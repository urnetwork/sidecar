//go:build sidecar_testhooks && !sidecar_http && !js

// SubprotocolStream's deadlines on the barriers around a call's wait (§22.8): stream.read_wait and
// stream.write_wait hold a Read or a Write once it has read its deadline against the clock and subscribed to
// the stream's changes, and before it waits, so the deadline's wait fires, or the clock passes the deadline,
// in the order the test chooses rather than the scheduler's. stream_conn_deadline_test.go moves the clock
// while the deadline's own wait is set, which needs no tag.

package sidecar

import (
	"errors"
	"os"
	"sync"
	"testing"
)

// Holds every goroutine that reaches name with key until the test lets it go: each arrival comes on the
// answered channel as the function that releases it. Whatever is still held is let go as the test ends.
func testHoldBarrierArrivals(t *testing.T, name string, key string) chan func() {
	t.Helper()
	arrivals := make(chan func(), 16)
	ended := make(chan struct{})
	SetTestHooks(&TestHooks{
		Barrier: func(barrierName string, barrierKey string) {
			if barrierName != name || barrierKey != key {
				return
			}
			released := make(chan struct{})
			release := sync.OnceFunc(func() {
				close(released)
			})
			select {
			case arrivals <- release:
			case <-ended:
				return
			}
			select {
			case <-released:
			case <-ended:
			}
		},
	})
	t.Cleanup(func() {
		close(ended)
		SetTestHooks(nil)
	})
	return arrivals
}

// A read's deadline wait fires once the read has read its deadline, still to come, and before it waits:
// held at stream.read_wait.before, the read is already subscribed to the change the wait makes as it fires,
// so once let go it ends at once with os.ErrDeadlineExceeded rather than waiting on.
func TestStreamReadDeadlineFiringBeforeTheReadWaitsEndsIt(t *testing.T) {
	a, _, _, accepted := testStreamDeadlineSides(t)
	if err := accepted.SetReadDeadline(a.clock.Now().Add(testStreamDeadlineOffset)); err != nil {
		t.Fatal(err)
	}
	arrivals := testHoldBarrierArrivals(t, "stream.read_wait.before", accepted.barrierKey)
	readErr := make(chan error, 1)
	go func() {
		_, err := accepted.Read(make([]byte, 8))
		readErr <- err
	}()
	release := testAwait(t, arrivals, "the read at its wait")
	a.clock.Advance(testStreamDeadlineOffset)
	release()
	if err := testAwait(t, readErr, "the read past its deadline"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read past its deadline: %v", err)
	}
}

// TestStreamReadDeadlineFiringBeforeTheReadWaitsEndsIt for Write: the write has sent the window's worth and is
// held at stream.write_wait.before as it is about to wait for a window, and ends with what it sent and
// os.ErrDeadlineExceeded.
func TestStreamWriteDeadlineFiringBeforeTheWriteWaitsEndsIt(t *testing.T) {
	_, b, opened, _ := testStreamDeadlineSides(t)
	if err := opened.SetWriteDeadline(b.clock.Now().Add(testStreamDeadlineOffset)); err != nil {
		t.Fatal(err)
	}
	arrivals := testHoldBarrierArrivals(t, "stream.write_wait.before", opened.barrierKey)
	data := make([]byte, 4*1024*1024)
	written := make(chan testStreamWriteResult, 1)
	go func() {
		// past any window the reader grants, and nothing reads it
		n, err := opened.Write(data)
		written <- testStreamWriteResult{n: n, err: err}
	}()
	release := testAwait(t, arrivals, "the write at its wait")
	b.clock.Advance(testStreamDeadlineOffset)
	release()
	result := testAwait(t, written, "the write past its deadline")
	if result.n <= 0 || len(data) <= result.n || !errors.Is(result.err, os.ErrDeadlineExceeded) {
		t.Fatalf("the write past its deadline: %d of %d B, %v", result.n, len(data), result.err)
	}
}

// A read waits with no deadline when one is set, and the clock reaches it while the deadline's wait is being
// set, which sets that wait late, past the deadline. The set reads the deadline against the clock once its
// wait is set and wakes the read, which ends with os.ErrDeadlineExceeded rather than waiting for the late
// wait. The read is held twice at stream.read_wait.before: waiting with no deadline, and again once the set
// has woken it to look at its new deadline, which has not yet passed.
func TestStreamReadDeadlinePassedWhileItsWaitIsSetWakesAWaitingRead(t *testing.T) {
	a, _, _, accepted := testStreamDeadlineSides(t)
	arrivals := testHoldBarrierArrivals(t, "stream.read_wait.before", accepted.barrierKey)
	readErr := make(chan error, 1)
	go func() {
		_, err := accepted.Read(make([]byte, 8))
		readErr <- err
	}()
	releaseFirst := testAwait(t, arrivals, "the read waiting with no deadline")

	held, releaseSet := testHoldClockWait(t, a.clock, testStreamDeadlineOffset)
	setErr := make(chan error, 1)
	go func() {
		setErr <- accepted.SetReadDeadline(a.clock.Now().Add(testStreamDeadlineOffset))
	}()
	// the set has woken the read's first wait and timed its own, which it has not set
	testAwait(t, held, "the deadline's wait timed")
	releaseFirst()
	releaseSecond := testAwait(t, arrivals, "the read waiting on its new deadline")
	a.clock.Advance(testStreamDeadlineOffset)
	releaseSet()
	if err := testAwait(t, setErr, "the set"); err != nil {
		t.Fatal(err)
	}
	releaseSecond()
	if err := testAwait(t, readErr, "the read past its deadline"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read past its deadline: %v", err)
	}
}
