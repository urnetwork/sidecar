//go:build sidecar_testhooks

// The sidecar_testhooks build's switch for 5d (check_gate.go), which D-TEST-6's revocation suite turns off so that
// readers' own checks are what refuses a revoked writer (I-5). make check fails a release leg built with the tag.

package evsservice

import (
	"sync/atomic"
)

// Whether 5d is off in this test process.
var evsGateOff atomic.Bool

// Turns 5d off, or back on, for every engine in the process.
func SwitchGateOffForTest(off bool) {
	evsGateOff.Store(off)
}

// Whether a test turned 5d off.
func evsGateSwitchedOff() bool {
	return evsGateOff.Load()
}
