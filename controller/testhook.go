//go:build !sidecar_testhooks

// This package's half of the test seams, which the root's testhook.go describes: empty here, so a release build
// blocks nowhere, and forwarding in testhook_enabled.go (CONTRACTS C-13). The ledger creates no key of its own, so
// only testHookBarrier has callers: at the linearization points of §9.7's handoff and settlement, where a fault
// schedule stops a producer, the broker or the worker on either side of a step.

package controller

// See the root's testHookBarrier.
func testHookBarrier(name string, key string) {}
