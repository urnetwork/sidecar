//go:build sidecar_testhooks

// The sidecar_testhooks build of the test seams. testhook.go documents the call-site contract and
// why this file has an installer of its own; this one adds what sidecartest installs.
//
// Hooks are process-wide because a call site names no instance. Everything here is safe for
// concurrent use. With nothing installed, the hooks do nothing.

package device

import (
	"bytes"
	"sync/atomic"
)

// What sidecartest installs. A nil field leaves that hook empty.
type TestHooks struct {
	// Receives its own copy of each key, which it may keep.
	Secret func(kind string, secret []byte)
	// Runs on the calling goroutine, and returning releases it, so blocking holds the caller at
	// the barrier.
	Barrier func(name string, key string)
}

var activeTestHooks atomic.Pointer[TestHooks]

// Replaces the process's hooks. nil removes them. A call already inside the earlier hooks finishes
// there.
func SetTestHooks(hooks *TestHooks) {
	activeTestHooks.Store(hooks)
}

// Copies the key, so a caller zeroing it on return cannot blank what the harness scans for.
func testHookSecret(kind string, secret []byte) {
	hooks := activeTestHooks.Load()
	if hooks != nil && hooks.Secret != nil {
		hooks.Secret(kind, bytes.Clone(secret))
	}
}

// Blocks for as long as the installed hook does.
func testHookBarrier(name string, key string) {
	hooks := activeTestHooks.Load()
	if hooks != nil && hooks.Barrier != nil {
		hooks.Barrier(name, key)
	}
}
