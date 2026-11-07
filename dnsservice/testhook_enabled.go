//go:build sidecar_testhooks

// The sidecar_testhooks half of this package's test seams: each forwards to the root's entry point.

package dnsservice

import (
	"github.com/urnetwork/sidecar"
)

// Forwards to the root's hook.
func testHookSecret(kind string, secret []byte) {
	sidecar.TestHookSecret(kind, secret)
}

// Forwards to the root's hook.
func testHookBarrier(name string, key string) {
	sidecar.TestHookBarrier(name, key)
}
