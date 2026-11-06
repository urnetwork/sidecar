//go:build !sidecar_testhooks

// Test seams at every key and every linearization point (§22.4). This is the untagged build, which
// is every release leg: both functions are empty, so a call costs only its arguments, and nothing
// here keeps a key or blocks. Keep arguments cheap and free of side effects for that reason.
// testhook_enabled.go is the sidecar_testhooks build, and make check fails a release leg built with
// that tag. TestHooksEmptyWithoutTag reads this file's source, so these bodies stay empty.
//
// A package other than the root cannot call these. One that needs them keeps its own unexported
// pair under these names and this tag: empty in its testhook.go, and in its tagged file forwarding
// to TestHookSecret and TestHookBarrier, which the root declares only under the tag. An untagged
// build therefore exports nothing for tests.

package sidecar

// At every key creation, derivation and unwrap, from M0's mls_* on: reports the key to the privacy
// harness, which scans every capture for it. A key that never passes through here is a key the
// harness cannot catch leaking (§22.7).
//
// Call it as soon as the bytes exist, before their first use. kind is a literal naming the key as
// its section does, such as "K_sock". secret is the key itself, borrowed for the call: neither build
// changes it or keeps a reference to it, so the caller may zero or reuse it on return.
func testHookSecret(kind string, secret []byte) {}

// At every linearization point and at the steps before and after it: marks a named protocol step
// where a fault schedule can hold this goroutine and release it in the order the schedule chooses
// (§22.8). Schedules run on these and on fake clocks, never on sleeps.
//
// name is a literal, <file prefix>.<step> such as "evs.head_cas", with .before and .after for the
// steps around a point. The sections describe their barriers in prose, so this literal is the name
// schedules match, and it stays stable. key says which instance of the step this is, such as a repo
// id, so a schedule can hold one repo's step and not another's. It is an opaque id or empty, never
// a secret, a path or other content (I-13).
//
// The tagged build may block here for as long as a schedule holds the barrier, so call it with no
// state lock held, or a held barrier stalls everything waiting on that lock.
func testHookBarrier(name string, key string) {}
