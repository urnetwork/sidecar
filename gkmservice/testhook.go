//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a release build
// keeps no key and blocks nowhere, and forwarding in testhook_enabled.go. gkm holds no key of its own, so its
// testHookSecret has no caller today; it stays beside testHookBarrier, as the root's rule pairs them.

package gkmservice

// See the root's testHookSecret.
func testHookSecret(kind string, secret []byte) {}

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
