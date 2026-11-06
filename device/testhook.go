//go:build !sidecar_testhooks

// Test seams for the device role (§22.4). This is the untagged build, which is every release leg:
// both functions are empty, so a call costs only its arguments, and nothing here keeps a key or
// blocks. testhook_enabled.go is the sidecar_testhooks build, and make check fails a release leg
// built with that tag. TestHooksEmptyWithoutTag reads this file's source, so these bodies stay
// empty.
//
// This is the root's pair with one difference. A package other than the root forwards its tagged
// pair to the root's TestHookSecret and TestHookBarrier, but this package may not import the root
// (§4.4, D-SDK-20), so its tagged file has its own SetTestHooks, and sidecartest installs on both.
//
// The call-site contract is the root's testhook.go, repeated here because a mistake in a call site
// is a mistake in a device process's key handling.

package device

// At every key creation, derivation and unwrap: reports the key to the privacy harness, which scans
// every capture for it (§22.7). Call it as soon as the bytes exist, before their first use. kind is
// a literal naming the key as its section does. secret is the key itself, borrowed for the call:
// neither build changes it or keeps a reference to it, so the caller may zero or reuse it on return.
func testHookSecret(kind string, secret []byte) {}

// At every linearization point and at the steps before and after it: marks a named protocol step
// where a fault schedule can hold this goroutine and release it in the order the schedule chooses
// (§22.8). Schedules run on these and on fake clocks, never on sleeps.
//
// name is a literal, <file prefix>.<step> such as "route.pin_swap", with .before and .after for the
// steps around a point, and schedules match that literal, so it stays stable. key says which
// instance of the step this is, such as a client id. It is an opaque id or empty, never a secret, a
// path or other content (I-13).
//
// The tagged build may block here for as long as a schedule holds the barrier, so call it with no
// state lock held, or a held barrier stalls everything waiting on that lock.
func testHookBarrier(name string, key string) {}
