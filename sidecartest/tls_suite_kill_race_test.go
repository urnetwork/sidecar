//go:build sidecar_testhooks

// The kill switch test's helpers (tls_suite_test.go) against the two interleavings that end as that test ended under
// make check's load (tip-check at e9a511cd), its Find of the lifted host answering no_listener. In each the engine
// judges tls/443/blog's lease while the kill holds, refuses it and removes it for cause (DESIGN-DETAILS 13.2.3), as
// the engine must, so after the lift the name has no listener. The log does not say which of the two ran.
//
//   - The kill's wait (writeKill): the engine's kill reader was in a read when the wait took its count, the read
//     ended without the kill, the wait then sent its Find, and the read the kill's event asked for landed while that
//     Find was between its kill check (Find's step 2) and its listener check (step 7), which refused the picked
//     listener. Here a read of another network's hash is parked across the kill's write, the read of the network's
//     hash the event asks for is parked until the wait's first Find is held at sockets.find.pick.before, and only
//     then lands, before the Find goes on.
//   - The publish's sweep (publish): the revocation sweep the publish's load queued ran late, after the engine had
//     read the kill, and its listener check refused the lease. Here the sweep is held at sockets.sweep.claimed until
//     publish waits for it, or else until the kill has reached the engine.
//
// The barriers are why this file needs the sidecar_testhooks build.

package sidecartest_test

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The kill's wait ends with the engine's kill set as the kill left it and the listener's lease where it was, though
// the engine's read of the kill landed while the wait's own Find was in flight; the lift then lets the engine's Find
// of the name through to the listener.
func TestTlsSuiteKillWaitKeepsTheListenersLeaseThroughAKillReadMidFind(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	redis := edge.net.Fakes().Redis
	barriers := edge.net.Barriers()
	networkId := sidecar.Id(edge.networkId)
	otherNetworkId := sidecar.NewId()
	const pickSite = "sockets.find.pick.before"

	// the engine's kill reader past the network's first read, which the publish's page asked for: two reads of another
	// network's hash, the second asked for once the first ended, so it began after the page's ask, and the network's
	// read was in it or before it
	for range 2 {
		reads, _ := edge.engine.KillReads()
		edge.engine.KillChanged(connect.Id(otherNetworkId))
		tlsSuiteAwait(t, "the engine's kill read", edge.engine.KillReads, reads)
	}
	// the engine's next read of the other network's hash, parked across the kill's write, and its next read of the
	// network's, parked until the wait's Find is held
	park := func(networkId sidecar.Id) <-chan struct{} {
		fired, err := edge.net.Faults().Add(&sidecartest.FaultPlan{
			Op:        sidecartest.FaultOpRedis,
			KeyPrefix: sidecar.TlsKillKey(networkId),
			Result:    sidecartest.Delay,
			Delay:     sidecartest.DelayInNetwork,
			Actor:     socketSuiteEngine,
		})
		if err != nil {
			t.Fatal(err)
		}
		return fired
	}
	otherRead := park(otherNetworkId)
	killRead := park(networkId)
	edge.engine.KillChanged(connect.Id(otherNetworkId))
	select {
	case <-otherRead:
	case <-time.After(tlsSuiteGuard):
		t.Fatal("the engine never read the other network's hash")
	}
	if err := barriers.Arm(pickSite, "", 0); err != nil {
		t.Fatal(err)
	}

	edgeChanges, _ := edge.service.KillChanges()
	driven := make(chan struct{})
	go func() {
		defer close(driven)
		ctx, cancel := context.WithTimeout(edge.ctx, tlsSuiteGuard)
		defer cancel()
		held := false
		fail := func(format string, args ...any) {
			t.Errorf(format, args...)
			// let the wait go on to fail on its own guard rather than hang
			redis.DeliverDelayed()
			if held {
				barriers.Release(pickSite)
			}
		}
		// tlsedge took the kill, so its event came, and with it the wait's count: the other network's read ends now,
		// after that count, and without the kill
		if !tlsSuiteAwaitWithin(ctx, edge.service.KillChanges, edgeChanges) {
			fail("tlsedge's kill change never came")
			return
		}
		redis.DeliverDelayed()
		select {
		case <-killRead:
		case <-ctx.Done():
			fail("the engine never read the network's hash after the kill's event")
			return
		}
		if err := barriers.AwaitHeld(ctx, pickSite, ""); err != nil {
			fail("the wait sent no Find: %v", err)
			return
		}
		held = true
		// the Find passed the kill check with no kill: the engine's read of the kill lands now, before its pick
		reads, _ := edge.engine.KillReads()
		redis.DeliverDelayed()
		if !tlsSuiteAwaitWithin(ctx, edge.engine.KillReads, reads) {
			fail("the engine's read of the kill never ended")
			return
		}
		if err := barriers.Release(pickSite); err != nil {
			t.Errorf("%v", err)
		}
	}()
	// the test's ctx ends before its cleanups run, which ends a schedule the wait's failure left
	t.Cleanup(func() { <-driven })
	edge.kill("blog", time.Time{})
	<-driven
	if removals := edge.store.OpCount("RemoveEntries"); removals != 0 {
		t.Fatalf("a Find in the kill's wait removed the listener's lease (%d removals)", removals)
	}
	if code, _ := edge.edgeFind("tls/443/blog"); code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("the engine's Find of a killed host answered %q", code)
	}

	edge.lift("blog")
	if code, _ := edge.edgeFind("tls/443/blog"); code != "" {
		t.Fatalf("the engine's Find of a lifted host answered %q", code)
	}
}

// The publish's sweep ends before the test goes on, so no kill can meet it. Held once it has claimed the network, the
// sweep is let go once publish waits for it, or else once the kill has reached the engine's kill set, which is where a
// publish that returned without it left it. The listener's lease outlives the kill, and the lift lets the engine's
// Find of the name through to the listener.
func TestTlsSuitePublishEndsItsSweepBeforeAKillCanMeetIt(t *testing.T) {
	edge := newTlsSuiteEdgeBare(t)
	barriers := edge.net.Barriers()
	const claimedSite = "sockets.sweep.claimed"
	if err := barriers.Arm(claimedSite, "", 0); err != nil {
		t.Fatal(err)
	}
	// publish's reads of the engine's sweep count: the first takes its count before the load, the next is its wait
	reads := sidecar.NewMonitorValue(0)
	sweeps := edge.sweeps
	edge.sweeps = func() (int, chan struct{}) {
		reads.Update(func(count int) int { return count + 1 })
		return sweeps()
	}
	killed := make(chan struct{})
	driven := make(chan struct{})
	go func() {
		defer close(driven)
		ctx, cancel := context.WithTimeout(edge.ctx, tlsSuiteGuard)
		defer cancel()
		if err := barriers.AwaitHeld(ctx, claimedSite, ""); err != nil {
			t.Errorf("the publish's load queued no sweep: %v", err)
			return
		}
		// let go on publish's wait or the kill's end, and on the test's end too, which the engine's close needs
		moved := func() bool {
			for {
				count, changed := reads.Get()
				if 2 <= count {
					return true
				}
				select {
				case <-changed:
				case <-killed:
					return true
				case <-ctx.Done():
					return false
				}
			}
		}()
		if !moved {
			t.Errorf("publish neither waited for its sweep nor returned")
		}
		if err := barriers.Release(claimedSite); err != nil {
			t.Errorf("%v", err)
		}
	}()
	// the test's ctx ends before its cleanups run, which ends a schedule a failure left
	t.Cleanup(func() { <-driven })
	edge.publish("blog")
	edge.kill("blog", time.Time{})
	close(killed)
	<-driven
	tlsSuiteAwait(t, "the publish's sweep", edge.engine.Sweeps, 0)
	if removals := edge.store.OpCount("RemoveEntries"); removals != 0 {
		t.Errorf("the publish's sweep removed the listener's lease after the kill (%d removals)", removals)
	}
	if code, _ := edge.edgeFind("tls/443/blog"); code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("the engine's Find of a killed host answered %q", code)
	}

	edge.lift("blog")
	if code, _ := edge.edgeFind("tls/443/blog"); code != "" {
		t.Fatalf("the engine's Find of a lifted host answered %q", code)
	}
}

// Waits until counts rises past past: false when ctx ends first. For a goroutine of the test's own, which must not
// end the test with Fatal as tlsSuiteAwait does.
func tlsSuiteAwaitWithin[T int | uint64](ctx context.Context, counts func() (T, chan struct{}), past T) bool {
	for {
		count, changed := counts()
		if past < count {
			return true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}
