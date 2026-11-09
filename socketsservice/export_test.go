// A bridge to private fixtures for socketsservice_test, which is a separate package because sidecartest
// imports this one for FakeSocketStore, so a test of this package importing sidecartest would be a cycle
// (connect/CODESTYLE.md:37).

package socketsservice

import (
	"context"

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
