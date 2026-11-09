//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a
// release build keeps no key and blocks nowhere, and forwarding in testhook_enabled.go. certs creates,
// derives and unwraps no key today, since a CSR and an attestation are public; testHookSecret is here for
// the first that does, the ACME account keys TLS-M5-15 loads.

package certsservice

// See the root's testHookSecret.
func testHookSecret(kind string, secret []byte) {}

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
