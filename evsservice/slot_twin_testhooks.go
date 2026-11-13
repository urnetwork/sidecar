//go:build sidecar_testhooks

// The sidecar_testhooks build's switch for the slot twins (slot_twin.go): a twin test breaks one rule for every engine
// and evacuator in the process, and puts it back when it ends.

package evsservice

import (
	"sync/atomic"
)

// The rule a test broke, evsSlotTwinNone for none.
var evsSlotTwinSwitched atomic.Int64

// Breaks rule, or with evsSlotTwinNone none, for every engine and evacuator in the process.
func switchSlotTwinForTest(rule evsSlotTwin) {
	evsSlotTwinSwitched.Store(int64(rule))
}

// Whether a test broke rule.
func evsSlotTwinBreaks(rule evsSlotTwin) bool {
	return evsSlotTwin(evsSlotTwinSwitched.Load()) == rule
}
