//go:build sidecar_testhooks

// The sidecar_testhooks build of this package's test seams, forwarding to the entry points the root
// declares only under the tag. The root's testhook_enabled.go holds the hooks themselves.

package smtpproof

import (
	"github.com/urnetwork/sidecar"
)

// Forwards to the installed hook, which receives its own copy of the key.
func testHookSecret(kind string, secret []byte) {
	sidecar.TestHookSecret(kind, secret)
}

// Blocks for as long as the installed hook does.
func testHookBarrier(name string, key string) {
	sidecar.TestHookBarrier(name, key)
}
