//go:build !sidecar_testhooks

// A release build keeps every slot rule (slot_twin.go): no switch exists that could break one.

package evsservice

// Never.
func evsSlotTwinBreaks(rule evsSlotTwin) bool {
	return false
}
