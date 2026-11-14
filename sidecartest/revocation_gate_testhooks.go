//go:build sidecar_testhooks

// The revocation suite's gate switch on a sidecar_testhooks build (QD-338): Net.SetEvsGate exists only here, so a
// release leg carries no way to turn evs's 5d off.

package sidecartest

import (
	"context"
)

// Turns evs's gate (5d) on or off for the process, through the switch the package linking evs's engine registered
// (SetEvsGateSwitch), until the Net closes, which turns it on again. ErrEvsGateFixed with no switch registered.
func (self *Net) SetEvsGate(on bool) error {
	return setEvsGate(self, on)
}

func setEvsGate(net *Net, on bool) error {
	switchGate := evsGateSwitch.Load()
	if switchGate == nil {
		return ErrEvsGateFixed
	}
	(*switchGate)(!on)
	if !on {
		context.AfterFunc(net.Context(), func() { (*switchGate)(false) })
	}
	return nil
}
