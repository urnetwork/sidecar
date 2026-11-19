// SEARCH-M10-39's registrations (§22.7, §22.8): S11 and S12 on T2, and the search rows of the privacy harness, its
// query canaries and, with an indexer answering, the relay's frame sizes of remote searches (FS-83). The tests build
// under sidecar_testhooks, which their remote team and search worlds need; these registrations build without it, so
// every binary that links sidecartest sees them, as a gate's sweep reads them.

package sidecartest

const searchScenariosPackage = "github.com/urnetwork/sidecar/sidecartest"

var (
	_ = RegisterScenario("S11", "", ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: searchScenariosPackage, Name: "TestScenarioS11", Tags: "sidecar_testhooks"})
	_ = RegisterScenario("S12", "", ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: searchScenariosPackage, Name: "TestScenarioS12", Tags: "sidecar_testhooks"})
	_ = RegisterPrivacyAssert("query-canaries", &PrivacyAssertTest{Repo: "sidecar", Package: searchScenariosPackage, Name: "TestPrivacySearchQueryCanaries", Tags: "sidecar_testhooks"})
	_ = RegisterPrivacyAssert("request-traces", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest/fault", Name: "TestFs83", Tags: "sidecar_testhooks"})
)
