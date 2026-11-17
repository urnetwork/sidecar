//go:build sidecar_check

// Rules that read files the release moves, read on a release tree: what the real release fixture's make
// check found apart from the development layout (QD-1003). The root module and its testdata/ go into
// v2026/, smtpproof into smtpproof/v2026/, and cli and mlsinterop stay where they were.

package check

import (
	"testing"
)

// mlsinterop's fuzz targets name their seeds in the root's testdata/fuzz/, a directory above their own,
// which a version branch moves into v2026/ beside mlsinterop. The registry finds them there, as
// mlsinterop's tests do, and not at the top, where the release's make check found none.
func TestFuzzRegistryReadsANestedModulesSeedsOnAReleaseTree(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows+"      - {name: FuzzPlantedPeer, package: mlsinterop, seeds: [../testdata/fuzz/planted_peer]}\n")
	plantFuzzTargets(fixture)
	fixture.write("mlsinterop/peer_fuzz_test.go", "package mlsinterop\n\nimport \"testing\"\n\nfunc FuzzPlantedPeer(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n")
	fixture.write("testdata/fuzz/planted_peer/seed", "go test fuzz v1\n[]byte(\"seed\")\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t))

	fixture.toRelease()
	wantFindings(t, fixture.openRelease().fuzzRegistryFindings(t))
	fixture.remove("v2026/testdata/fuzz/planted_peer/seed")
	wantFindings(t, fixture.openRelease().fuzzRegistryFindings(t), "FuzzPlantedPeer's seeds ../testdata/fuzz/planted_peer hold no file")
}

// §4's evidence paths on a release tree: the root module's in v2026/, smtpproof's in smtpproof/v2026/,
// where the release's make check did not look for smtpproof/go.mod, and cli's at the top.
func TestRepoEvidencePathsAreFoundOnAReleaseTree(t *testing.T) {
	fixture := newFixture(t)
	fixture.toRelease()
	release := fixture.openRelease()
	for _, relativePath := range []string{"sidecar.go", "protocol/doc.go", "smtpproof/go.mod", "smtpproof/doc.go", "cli/go.mod", "mlsinterop/go.mod"} {
		if !release.repositoryPathExists(relativePath) {
			t.Errorf("%s is not found on the release tree", relativePath)
		}
	}
	for _, relativePath := range []string{"smtpproof/absent.go", "absent.go"} {
		if release.repositoryPathExists(relativePath) {
			t.Errorf("%s is found on the release tree, which does not hold it", relativePath)
		}
	}
}
