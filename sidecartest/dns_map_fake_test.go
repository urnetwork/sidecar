package sidecartest

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The fake holds the custom-host map store's contract (D-TEST-2).
func TestFakeDnsCustomHostMapStorePassesItsSuite(t *testing.T) {
	stores := map[string]*FakeDnsCustomHostMapStore{}
	clock := NewFakeClock(DefaultClockStart())
	RunDnsCustomHostMapStoreSuite(t, &DnsCustomHostMapStoreSubject{
		// one fake for every root, as the deployment's applied rows are one; each root's versions apart
		Store: &fakeDnsMapStoreByRoot{stores: stores},
		NewRoot: func(ctx context.Context) (string, error) {
			root := "r" + sidecar.NewId().String()[24:] + ".example."
			stores[root] = NewFakeDnsCustomHostMapStore()
			return root, nil
		},
		Raise: func(ctx context.Context, root string, hosts []string) (uint64, error) {
			store := stores[root]
			state, _ := store.CustomHostMapState(ctx, root)
			version := uint64(len(state.Versions) + 1)
			store.Raise(version, hosts, clock.Now())
			return version, nil
		},
		HostReady: func(ctx context.Context, root string, host string) (bool, error) {
			_, ready := stores[root].Ready(host)
			return ready, nil
		},
	})
}
