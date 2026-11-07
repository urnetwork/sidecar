//go:build !sidecar_testhooks

// This package's test seams, as the root's testhook.go describes: empty in every release build, so a
// call costs only its arguments. testhook_enabled.go is the sidecar_testhooks half.

package dnsservice

// At every key load: reports the key to the privacy harness (§22.7). See the root's testHookSecret.
func testHookSecret(kind string, secret []byte) {}

// At every linearization point and the steps around it. See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
