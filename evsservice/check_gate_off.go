//go:build !sidecar_testhooks

// A release build always runs 5d (check_gate.go): no switch exists that could turn it off.

package evsservice

// Never.
func evsGateSwitchedOff() bool {
	return false
}
