//go:build sidecar_testhooks

// The engine's sidecar_testhooks seam for computetest.Broker (CTEST-M12-01, DESIGN-COMPUTE §18): what a test outside
// this package plants behind the whole guard, which this package's own tests set through ComputeEngineDeps' unexported
// fields (engine_fixture_test.go). It sets a deps' handlers to the registered ones with a test's own over them by route
// name, the shape an area registers through registerComputeRoutes, a test's admission checks after the registered
// ones, and compute_abuse_hold's and compute_catalog_version's stores in place of their tables. Every step of the guard
// still runs in front of a planted handler: nothing here skips one. Only the sidecar_testhooks build has it, and make
// check fails a release leg built with that tag, so no shipped broker serves a planted handler.

package computeservice

import (
	"fmt"
	"slices"
)

// compute_abuse_hold's reader, as an admission takes it (abuse_hold.go).
type ComputeAbuseHoldStoreForTest = computeAbuseHoldStore

// compute_catalog_version's reader and writer, as the catalog takes it (broker_catalog.go).
type ComputeCatalogVersionStoreForTest = computeCatalogVersionStore

// What a test outside the package plants (see the file header). Each field left empty plants nothing.
type ComputeEngineTestDeps struct {
	// Handlers by design route name, each served in place of the registered handler of that name; every other route
	// keeps the registered one, or answers not_built.
	Handlers map[string]ComputeHandler
	// Checks run on every admission route after the registered ones.
	AdmissionChecks []ComputeAdmissionCheck
	// compute_abuse_hold's rows in place of the table over the Env.
	AbuseHolds ComputeAbuseHoldStoreForTest
	// compute_catalog_version's rows in place of the table over the Env.
	CatalogVersions ComputeCatalogVersionStoreForTest
}

// Sets test on deps, for NewComputeEngine to read: an error, deps unchanged, for a handler that names no design route
// or is nil, as registerComputeRoutes refuses the same.
func SetComputeEngineTestDeps(deps *ComputeEngineDeps, test *ComputeEngineTestDeps) error {
	if deps == nil || test == nil {
		return fmt.Errorf("compute engine test deps: nothing to set")
	}
	designNames := []string{}
	for _, route := range computeRouteDesign() {
		designNames = append(designNames, route.Name)
	}
	handlers := registeredComputeRouteHandlers()
	for name, handler := range test.Handlers {
		if !slices.Contains(designNames, name) {
			return fmt.Errorf("compute engine test deps: %q is not one of §14.3's routes", name)
		}
		if handler == nil {
			return fmt.Errorf("compute engine test deps: %q with no handler", name)
		}
		handlers[name] = handler
	}
	for _, check := range test.AdmissionChecks {
		if check == nil {
			return fmt.Errorf("compute engine test deps: a nil admission check")
		}
	}
	deps.testHandlers = handlers
	deps.testAdmissionChecks = slices.Clone(test.AdmissionChecks)
	if test.AbuseHolds != nil {
		deps.testAbuseHoldStore = test.AbuseHolds
	}
	if test.CatalogVersions != nil {
		deps.testCatalogStore = test.CatalogVersions
	}
	return nil
}
