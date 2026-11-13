//go:build !js && !sidecar_http && !ios_extension

// FuzzTlsEdgeLogin: the front's statement check is total and passes only the genuine statement (§22.6's typed Signed
// rule). Not on js: testing.F reads its corpus directory before it runs a seed, and js has no directory to open, so
// TestTlsEdgeLoginSeedsVerifyOnlyTheGenuine carries the same seeds on that leg.

package sidecar

import (
	"testing"
)

func FuzzTlsEdgeLogin(f *testing.F) {
	world := newTlsEdgeLoginTestWorld(f)
	f.Add(world.genuine)
	for _, seed := range world.seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		testTlsEdgeLoginVerifiesOnlyTheGenuine(t, world, value)
	})
}
