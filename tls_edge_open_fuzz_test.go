//go:build !js

// FuzzTlsEdgeOpen: decoding is total (§22.6). Not on js: testing.F reads its corpus directory before it runs a seed, and
// js has no directory to open, so TestTlsEdgeOpenSeedsDecodeTotally carries the same seeds on that leg.

package sidecar

import (
	"testing"
)

func FuzzTlsEdgeOpen(f *testing.F) {
	for _, metadata := range testTlsEdgeOpenSeeds(f) {
		f.Add(metadata)
	}
	f.Fuzz(func(t *testing.T, metadata []byte) {
		testTlsEdgeOpenDecodesTotally(t, metadata)
	})
}
