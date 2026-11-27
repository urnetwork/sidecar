//go:build !ios_extension && !sidecar_http && !js

package model

// §16.5's default budgets have one source (CACL-M12-05; DESIGN-COMPUTE §16.4): the broker's ledger settings carry the
// device's BudgetSettings' values, so the broker and the device never apply two defaults.

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

// Each default budget the broker applies is the device's.
func TestComputeLedgerBudgetsAreTheDevices(t *testing.T) {
	broker, device := DefaultComputeLedgerSettings(), sidecar.DefaultBudgetSettings()
	for name, pair := range map[string][2]uint64{
		"agent day":     {uint64(broker.DefaultAgentDayNanoUsd), device.AgentDayNanoUsd},
		"agent month":   {uint64(broker.DefaultAgentMonthNanoUsd), device.AgentMonthNanoUsd},
		"device day":    {uint64(broker.DefaultDeviceDayNanoUsd), device.DeviceDayNanoUsd},
		"device month":  {uint64(broker.DefaultDeviceMonthNanoUsd), device.DeviceMonthNanoUsd},
		"ceiling's day": {uint64(broker.DefaultDeviceCeilingDayNanoUsd), device.DeviceCeilingDayNanoUsd},
	} {
		if pair[0] != pair[1] {
			t.Errorf("the %s budget is %d at the broker and %d on the device", name, pair[0], pair[1])
		}
	}
	// the names the broker's budget lines take are the device's
	for _, pair := range [][2]string{
		{ComputeBudgetAgent, sidecar.ComputeBudgetNameAgent}, {ComputeBudgetTagged, sidecar.ComputeBudgetNameTagged},
		{ComputeBudgetDevice, sidecar.ComputeBudgetNameDevice}, {ComputeBudgetCeiling, sidecar.ComputeBudgetNameCeiling},
	} {
		if pair[0] != pair[1] {
			t.Errorf("a budget named %s at the broker and %s on the device", pair[0], pair[1])
		}
	}
}
