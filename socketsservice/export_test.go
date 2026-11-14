// A bridge to private fixtures for socketsservice_test, which is a separate package because sidecartest
// imports this one for FakeSocketStore, so a test of this package importing sidecartest would be a cycle
// (connect/CODESTYLE.md:37).

package socketsservice

import (
	"context"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
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

// Adds clientId to the removed-client set at the engine's now, as ClientRemoved does first.
func (self *SocketsService) NoteClientRemovedForTest(clientId connect.Id) {
	self.removedClients.add(clientId, self.clock.Now())
}

// Replaces networkId's kills, as the kills reader does once it has read the network's {tes_} hash.
func (self *SocketsService) SetKillsForTest(networkId connect.Id, entries []*sidecar.TlsKillEntry) {
	self.killSet.set(networkId, entries)
}

// Queues a sweep of networkId at position, as the gate's OnNarrowed does.
func (self *SocketsService) QueueSweepForTest(networkId connect.Id, position uint64) {
	self.queueSweep(networkId, position)
}

// Waits until value reaches at least count.
func awaitCount[T int | uint64](ctx context.Context, value *sidecar.MonitorValue[T], count T) error {
	for {
		current, update := value.Get()
		if count <= current {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Waits until at least count sweeps have ended, each with its network free again.
func (self *SocketsService) AwaitSweeps(ctx context.Context, count int) error {
	return awaitCount(ctx, self.sweeps.doneCount, count)
}

// How many sweeps have ended.
func (self *SocketsService) SweepCount() int {
	return self.sweeps.doneCount.Value()
}

// Waits until at least count removed clients' store work has ended.
func (self *SocketsService) AwaitRemovals(ctx context.Context, count int) error {
	return awaitCount(ctx, self.removals.finishedClientIds, count)
}

// Waits until the kills reader has finished at least count rounds.
func (self *SocketsService) AwaitKillReads(ctx context.Context, count int) error {
	return awaitCount(ctx, self.killSet.readCount, count)
}

// How many rounds the kills reader has finished.
func (self *SocketsService) KillReadCount() int {
	return self.killSet.readCount.Value()
}

// Waits until the gate has taken in at least count loads.
func (self *SocketProjectionGate) AwaitLoads(ctx context.Context, count uint64) error {
	return awaitCount(ctx, self.loadCount, count)
}

// How many loads the gate has taken in.
func (self *SocketProjectionGate) LoadCount() uint64 {
	return self.loadCount.Value()
}

// Waits until at least count resubscription checks have finished.
func (self *SocketProjectionGate) AwaitResyncs(ctx context.Context, count uint64) error {
	return awaitCount(ctx, self.resyncCount, count)
}

// Waits until the over-limit poll has finished at least count reads, each with its next wait armed.
func (self *SocketProjectionGate) AwaitOverLimitReads(ctx context.Context, count int) error {
	return awaitCount(ctx, self.overLimit.readCount, count)
}

// How many reads the over-limit poll has finished.
func (self *SocketProjectionGate) OverLimitReadCount() int {
	return self.overLimit.readCount.Value()
}

// Waits until the key set has finished at least count reads of its file, each with its next wait armed.
func (self *SocketTicketKeySet) AwaitReads(ctx context.Context, count int) error {
	return awaitCount(ctx, self.readCount, count)
}

// Reads the key file now, as the reread does.
func (self *SocketTicketKeySet) ReloadForTest() {
	self.reload()
}

// Whether an entry may narrow, the sweep's table.
func SocketEntryMayNarrowForTest(entry *bridge.AuthEntry) bool {
	return socketEntryMayNarrow(entry)
}

// How many tickets the engine has signed.
func (self *SocketsService) SignedTicketCount() int64 {
	return self.signedCount.Load()
}

// How many claim signatures the engine has checked, a memo's hit checking none.
func (self *SocketsService) ClaimVerifyCount() int64 {
	return self.claimVerifyCount.Load()
}

// Runs the worker's reload and let-go step now.
func (self *SocketProjectionGate) ReloadBehindForTest() {
	self.reloadBehind()
}

// How many networks the gate follows.
func (self *SocketProjectionGate) NetworkCountForTest() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.networks)
}
