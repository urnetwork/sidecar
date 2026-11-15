//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a
// release build blocks nowhere, and forwarding in testhook_enabled.go (CONTRACTS.md C-13).

package dropverify

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
