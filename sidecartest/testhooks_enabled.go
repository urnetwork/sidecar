//go:build sidecar_testhooks

// Installs on every seam in this module: the root's, which every package but device/ forwards to, and
// device/'s own, since device/ may not import the root (testhook.go).

package sidecartest

import (
	"sync/atomic"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// Whether this build links the hooks.
const HooksLinked = true

// Hooks are process-wide, so at most one installation runs at a time, and two tests installing at once
// is a bug the second one hears about.
var testHooksInstalled atomic.Bool

// Sends every hook call in the process to secret and barrier, either of which may be nil, until remove
// runs. Fails while another installation stands.
func InstallTestHooks(secret func(kind string, secret []byte), barrier func(name string, key string)) (remove func(), err error) {
	if !testHooksInstalled.CompareAndSwap(false, true) {
		return nil, ErrHooksInstalled
	}
	sidecar.SetTestHooks(&sidecar.TestHooks{Secret: secret, Barrier: barrier})
	device.SetTestHooks(&device.TestHooks{Secret: secret, Barrier: barrier})
	return func() {
		sidecar.SetTestHooks(nil)
		device.SetTestHooks(nil)
		testHooksInstalled.Store(false)
	}, nil
}
