//go:build !ios_extension && !sidecar_http

// The poller's owner cache for the external tests (package sidecar_test), which cannot reach it.

package sidecar

// Whether the poller holds an owner for the socket identity: what a test of the cache's trim reads.
func (self *ListenersPoller) OwnerCachedForTest(identity uint64) bool {
	return self.ownerCached(identity)
}
