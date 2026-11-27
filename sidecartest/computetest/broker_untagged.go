//go:build !sidecar_testhooks

// The untagged build's half of broker_testhooks.go: no seam into the engine's handlers, admission checks or table
// stores is linked, so a test that plants a handler or a check is refused with ErrBrokerPlantUnlinked, rather than
// served a broker that never runs it, and the admissions read the Env's tables (503 on T2, which holds none).

package computetest

import (
	"github.com/urnetwork/sidecar/computeservice"
)

// Refuses planted's handlers and checks; false, since this build plants no table stand-in.
func brokerPlant(deps *computeservice.ComputeEngineDeps, planted *brokerPlanted) (bool, error) {
	if 0 < len(planted.handlers) || 0 < len(planted.admissionChecks) {
		return false, ErrBrokerPlantUnlinked
	}
	return false, nil
}
