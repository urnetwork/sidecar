//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a
// release build keeps no key and blocks nowhere, and forwarding in testhook_enabled.go. certs creates,
// derives and unwraps no key, so it has no testHookSecret: a CSR and an attestation are public.

package certsservice

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
