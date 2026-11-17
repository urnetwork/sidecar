//go:build sidecar_check

// The release rewrite rule's planted violations (hygiene_rewrite_test.go), read in development, where
// tip-check runs, and on the release tree, where a line stands as the rewrite left it; the lines it
// lets through, which the release versions or keeps unversioned by design; and the untagged rule's
// reading of a path in an escaped string, which both rules read alike.

package check

import (
	"testing"
)

// run.sh's exact pass versions the root's path, which gives the line the /vN its subpackage pass
// skips, so the subpackage keeps its development path: sidecartest/search_oracle_test.go's allow-list
// did (QD-1003). A Makefile's line goes the same way.
func TestHygieneFailsOnALineNamingTheRootBesideASubpackage(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("paths.go", "package sidecar\n\nvar paths = []string{\"@module@\", \"@module@/protocol\"}\n")
	fixture.write("Makefile", "build:\n\tgo build \"@module@\" \"@module@/protocol/bridge\"\n")
	wantFindings(t, fixture.open().unversionedReleasePathFindings(t),
		"paths.go:3: the release's rewrite leaves \"@module@/protocol\" without /v2026",
		"Makefile:2: the release's rewrite leaves \"@module@/protocol/bridge\" without /v2026")

	fixture.toRelease()
	wantFindings(t, fixture.openRelease().unversionedReleasePathFindings(t),
		"v2026/paths.go:3: the release's rewrite leaves \"@module@/protocol\" without /v2026",
		"v2026/Makefile:2: the release's rewrite leaves \"@module@/protocol/bridge\" without /v2026")
}

// A line already holding /vN is one the subpackage pass skips whole, so a subpackage's path there keeps
// its development spelling, and so does smtpproof's in the root module, which no later pass reaches.
func TestHygieneFailsOnASubpackageOnALineHoldingAVersion(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("paths.go", "package sidecar\n\nvar paths = []string{\"@module@/protocol\", \"example.com/x/v2\"}\n\n// \"@module@/smtpproof\" beside example.com/x/v2\n")
	wantFindings(t, fixture.open().unversionedReleasePathFindings(t),
		"paths.go:3: the release's rewrite leaves \"@module@/protocol\" without /v2026",
		"paths.go:5: the release's rewrite leaves \"@module@/smtpproof\" without /v2026")
}

// The control: one path a line; the root's exact path beside a /vN, which its exact pass reaches;
// smtpproof's beside one below cli/, which sidecar_cli_release_edit's exact pass reaches; cli's own
// path beside one, which stays as it is by design; and paths in escaped strings, which the subpackage
// pass versions ahead of the backslash, as sidecartest/search_oracle_test.go's planted source holds
// them.
func TestHygieneAllowsPathsTheReleaseVersions(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("paths.go", "package sidecar\n\nvar paths = []string{\n\t\"@module@\",\n\t\"@module@/protocol\",\n}\n\n"+
		"var root = []string{\"@module@\", \"example.com/x/v2\"}\n\n"+
		"const source = \"import \\\"@module@\\\"\\nimport \\\"@module@/protocol\\\"\"\n")
	fixture.write("cli/paths.go", "package main\n\nvar paths = []string{\"@module@/smtpproof\", \"example.com/x/v2\"}\n\n"+
		"var module = []string{\"@module@/cli\", \"example.com/x/v2\"}\n")
	wantFindings(t, fixture.open().unversionedReleasePathFindings(t))
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t))

	fixture.toRelease()
	wantFindings(t, fixture.openRelease().unversionedReleasePathFindings(t))
}

// A path in an escaped string, as a test's planted source holds one: the subpackage pass versions it
// ahead of the backslash, so a cli path there is one nothing provides as well.
func TestHygieneFailsOnAnEscapedQuotedPathOfCli(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("source_test.go", "package sidecar\n\nconst source = \"import \\\"@module@/cli\\\"\"\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t),
		"source_test.go:3: the release's rewrite makes this \"@module@/v2026/cli\", which nothing provides")
}
