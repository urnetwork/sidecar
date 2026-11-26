//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a release build
// keeps no key and blocks nowhere, and forwarding in testhook_enabled.go (C-13). The engine creates no key of its own,
// so its testHookSecret has no caller yet; it stays beside testHookBarrier, as the root's rule pairs them, for the
// areas whose handlers derive one (K_P's signer, the settlement tag's MAC).

package computeservice

// See the root's testHookSecret.
func testHookSecret(kind string, secret []byte) {}

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
