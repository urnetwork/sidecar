// The rules behind make check and make size (§4.7, §4.9, §18.10, §22.4). With no hosted CI, policy
// lives in Go tests, one leg per shipped build, as in sdk/dependency_boundary_test.go.
//
// Every file but this one is a _test.go file under the sidecar_check tag. Nothing here ships, no leg
// links it, and go test ./... passes over it, because these tests run the go command and fetch
// govulncheck and the vulnerability database. make check runs them with -count=1: the go test cache
// does not see what a child go list reads, so a cached pass would hide a new violation.
//
// Each rule is a function over a repository, which is how a real checkout and a planted fixture
// (fixture_test.go) are checked by one code path. A row of §4.7's fails-on block therefore has a
// test that reads this checkout and a test that plants the violation in a fixture; failsOnRows in
// rows_test.go names both, and TestEveryRowHasARuleAndAPlantedViolation holds the list.
//
// The tests read the same on a release branch, where the root module is .../sidecar/v2026 in v2026/
// beside the nested modules (§4.9): module paths come from go.mod, and no quoted first-party path
// appears here for the release's sed to rewrite.
package check
