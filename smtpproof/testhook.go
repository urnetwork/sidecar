//go:build !sidecar_testhooks

// Test seams at every key and every linearization point (§22.4), with the contract the root's
// testhook.go documents. The root's pair is unexported, so this module keeps its own under the same
// names and tag. This is the untagged build, every release leg included: both functions are empty,
// a call costs only its arguments, and nothing here keeps a key or blocks. TestHooksEmptyWithoutTag
// reads this file's source, so these bodies stay empty. testhook_enabled.go is the tagged build.

package smtpproof

// At every key creation and derivation, as soon as the bytes exist: reports the key to the privacy
// harness. kind names the key as SPEC.md does, such as "tls13_hs". secret is borrowed for the call.
func testHookSecret(kind string, secret []byte) {}

// At every linearization point and the steps around it, named <file prefix>.<step>. key is an opaque
// id or empty, never a secret or content. The tagged build may block here, so call it with no state
// lock held.
func testHookBarrier(name string, key string) {}
