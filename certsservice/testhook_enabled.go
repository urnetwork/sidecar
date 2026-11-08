//go:build sidecar_testhooks

// The sidecar_testhooks build of this package's test seams, forwarding to the root's.

package certsservice

import (
	"github.com/urnetwork/sidecar"
)

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {
	sidecar.TestHookBarrier(name, key)
}
