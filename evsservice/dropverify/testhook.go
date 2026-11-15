//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a
// release build keeps no key and blocks nowhere, and forwarding in testhook_enabled.go (CONTRACTS.md C-13).

package dropverify

// See the root's testHookSecret. Verify holds no key: the seam stays for the package's hygiene.
func testHookSecret(kind string, secret []byte) {}

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
