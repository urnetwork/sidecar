//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a
// release build keeps no key and blocks nowhere, and forwarding in testhook_enabled.go. tlsedge's keys
// are the daily visitor keys (visitor_key.go); its barriers sit where the name map, the kill set and
// the caps change.

package tlsedgeservice

// See the root's testHookSecret.
func testHookSecret(kind string, secret []byte) {}

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
