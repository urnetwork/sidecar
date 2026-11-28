//go:build sidecar_testhooks

// computetest.Broker's half of computeservice's sidecar_testhooks seam (engine_testhooks.go): a test's handlers by
// route name and its admission checks, and the tables' stand-ins, planted into the engine's deps before it is built, so
// each runs behind the whole guard. broker_untagged.go is the untagged build's half.

package computetest

import (
	"github.com/urnetwork/sidecar/computeservice"
)

// Plants planted into deps: true, since the stand-ins this build plants are answered from then on.
func brokerPlant(deps *computeservice.ComputeEngineDeps, planted *brokerPlanted) (bool, error) {
	test := &computeservice.ComputeEngineTestDeps{
		Handlers:        planted.handlers,
		AdmissionChecks: planted.admissionChecks,
	}
	// a nil pointer stays a nil interface, so an Env's tables are read where no stand-in is given
	if planted.abuseHolds != nil {
		test.AbuseHolds = planted.abuseHolds
	}
	if planted.catalogVersions != nil {
		test.CatalogVersions = planted.catalogVersions
	}
	if err := computeservice.SetComputeEngineTestDeps(deps, test); err != nil {
		return false, err
	}
	return true, nil
}
