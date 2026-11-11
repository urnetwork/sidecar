// A bridge to private fixtures for socketsservice_test, which is a separate package because sidecartest
// imports this one for FakeSocketStore, so a test of this package importing sidecartest would be a cycle
// (connect/CODESTYLE.md:37).

package socketsservice

import (
	"context"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// Waits until at least count probes have finished, each with its next wait armed.
func (self *SocketsService) AwaitProbes(ctx context.Context, count int) error {
	for {
		finished, update := self.probeCount.Get()
		if count <= finished {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// How many clients hold a bucket.
func (self *SocketControlBound) BucketCount() int {
	return self.bucketCount()
}

// Running and waiting calls.
func (self *SocketFairQueue) Counts() (int, int) {
	return self.counts()
}

// Waits until exactly count calls are waiting.
func (self *SocketFairQueue) AwaitWaiting(ctx context.Context, count int) error {
	for {
		waiting, update := self.waitingMonitor.Get()
		if waiting == count {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// The owner registered for namespace.
func (self *SocketsService) LookupNamespace(namespace sidecar.SocketNamespace) (SocketNamespaceHooks, bool) {
	return self.namespaces.lookup(namespace)
}

// Fixes the draws a pick takes, in order, the last repeating, so a test chooses which listener is primary.
func (self *SocketsService) SetDrawsForTest(draws ...uint32) {
	var stateLock sync.Mutex
	index := 0
	self.draw = func() uint32 {
		stateLock.Lock()
		defer stateLock.Unlock()
		draw := draws[min(index, len(draws)-1)]
		index += 1
		return draw
	}
}

// Adds clientId to the removed-client set at the engine's now, as SOCK-M5-07's ClientRemoved does first.
func (self *SocketsService) NoteClientRemovedForTest(clientId connect.Id) {
	self.removedClients.add(clientId, self.clock.Now())
}

// Replaces networkId's kills, as SOCK-M5-07's KillChanged does once it has read the network's {tes_} hash.
func (self *SocketsService) SetKillsForTest(networkId connect.Id, entries []*sidecar.TlsKillEntry) {
	self.killSet.set(networkId, entries)
}

// How many tickets the engine has signed.
func (self *SocketsService) SignedTicketCount() int64 {
	return self.signedCount.Load()
}

// How many claim signatures the engine has checked, a memo's hit checking none.
func (self *SocketsService) ClaimVerifyCount() int64 {
	return self.claimVerifyCount.Load()
}
