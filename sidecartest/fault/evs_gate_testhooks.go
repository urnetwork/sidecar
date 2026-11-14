//go:build sidecar_testhooks

// evs's gate switch for the revocation suite (TEST-M2-12; D-TEST-6, QD-338): sidecartest links no engine, so the
// package that links evs's registers its switch, and Net.SetEvsGate turns 5d off through it in any binary linking
// this package. A release leg links neither the tag nor the switch.

package fault

import (
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = sidecartest.SetEvsGateSwitch(evsservice.SwitchGateOffForTest)
