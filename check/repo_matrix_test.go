//go:build sidecar_check

// §4's ids, each mapped to what holds it in this repository: a rule of failsOnRows, a test of this
// package or a path. Most point at rows make check already runs, so this proves §4 closed rather than
// rebuilding it, and TestEveryRepoIdHasEvidence fails an id the design names and the matrix does not,
// and a rule, test or path the matrix names that does not exist, as TestEveryRowHasARuleAndAPlantedViolation
// does for the rows. What §4 holds in other repositories (build's release and branch tools, server's
// lock) is theirs to show; each id here also has evidence in this one.

package check

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// One thing that holds an id. Exactly one field is set.
type repoEvidence struct {
	// a failsOnRows item, word for word
	rule string
	// a test this package declares
	test string
	// a file or directory, relative to the repository's top; a root module file is read in v2026/ on a
	// release tree
	path string
	// for a withdrawn id: what withdrew it
	withdrawn string
}

// §4.2's requirements, §4.13's decisions and §4.14's questions.
var repoMatrix = map[string][]repoEvidence{
	"R-REPO-1": {
		{path: "cli/main.go"}, {path: "sidecar.go"},
		{rule: "server, sdk, sn or an unlisted module in a leg's go list -deps"},
		{rule: "a client package importing a <svc>service"},
	},
	"R-REPO-2": {
		{rule: "a first-party require §4.7's imports bullet does not name"},
		{rule: "connect requiring sidecar (R-REPO-2)"},
		{rule: "server, sdk, sn or an unlisted module in a leg's go list -deps"},
	},
	"R-REPO-3": {
		{path: "go.mod"}, {path: "sidecar.go"}, {path: "protocol"}, {path: "cli/main.go"},
		{rule: "the root importing a package of this module other than protocol and protocol/bridge"},
	},
	"R-REPO-4": {
		{path: "mls_group.go"}, {path: "mls_treekem.go"}, {path: "smtpproof/go.mod"},
		{test: "TestX9ReadyForMain"},
	},
	"R-REPO-5": {
		{rule: "a parent importing its child (R-REPO-5)"},
		{path: ".githooks/commit-msg"},
	},
	"R-REPO-6": {
		{rule: "go and tool lines other than §4.7's"},
		{rule: "replaces other than §4.7's"},
		{rule: "a shared module's version other than connect's, sdk's and server's"},
		{rule: "CgoFiles anywhere in this repository, except keychain_darwin.go"},
	},
	"R-REPO-7": {
		{path: "LICENSE"}, {path: "NOTICE"},
		{test: "TestHygieneReleaseBinary"},
		{test: "TestToReleaseAndTheReleaseStepAreOneTransformation"},
	},
	"R-REPO-8": {
		{path: "README.md"}, {path: "design"},
		{test: "TestX9ReadyForMain"},
	},
	"D-REPO-1": {
		{path: "go.mod"},
		{rule: "registry conflicts"}, {rule: "stale generated code"},
		{test: "TestNoQuotedFirstPartyPathHere"}, {test: "TestRulesPassAReleaseTree"},
	},
	"D-REPO-2": {
		{rule: "the root importing a package of this module other than protocol and protocol/bridge"},
		{rule: "protocol beyond std, protobuf and protocol/bridge, or protocol/bridge beyond std and protobuf"},
		{rule: "device beyond connect and protocol/bridge (§4.4, D-SDK-20)"},
		{rule: "the root module requiring any module of this repository"},
		{rule: "a package beside cli's, mlsinterop's or sidecarctl's own, or a file naming one, which the release's rewrite would break (§4.9)"},
	},
	"D-REPO-3": {
		{path: "host_service.go"},
		{rule: "a client package importing a <svc>service"},
		{rule: "a client or cli leg linking a <svc>service, or any shipped leg linking sidecartest"},
	},
	"D-REPO-4": {
		{path: "Makefile"},
		{rule: "CgoFiles on a leg, keychain_darwin.go outside §5.10's fallback leg included"},
		{test: "TestSizeVerdictsHoldTheirLimits"},
		{test: "TestEveryRowHasARuleAndAPlantedViolation"},
	},
	"D-REPO-5": {
		{rule: "a connect proto that is not additive against connect's main, or no main to compare (D-REPO-5)"},
		{rule: "a connect shape §4.6 rejects, defers or leaves for later (C1, C2, C4, C6b, C7, C10, C17)"},
		{test: "TestX9ReadyForMain"},
	},
	"D-REPO-6": {
		{rule: "a first-party require §4.7's imports bullet does not name"},
		{test: "TestToReleaseAndTheReleaseStepAreOneTransformation"},
		{test: "TestX9ReadyForMain"},
	},
	"D-REPO-7": {
		{path: "LICENSE"}, {path: "CODESTYLE.md"}, {path: ".githooks/commit-msg"},
		{rule: "a license §4.7 refuses, or a row its module's files do not back, word for word, beside every package a leg links"},
		{test: "TestHygieneReleaseBinary"},
	},
	"D-REPO-8": {{withdrawn: "owner decision 117: no scrub, archive, filtered clone or path allowlist"}},
	"D-REPO-9": {{withdrawn: "owner decision 118: no private mirrors"}},
	"Q-REPO-1": {
		{path: "host_service.go"},
		{rule: "a client package importing a <svc>service"},
	},
	"Q-REPO-2": {
		{rule: "a connect shape §4.6 rejects, defers or leaves for later (C1, C2, C4, C6b, C7, C10, C17)"},
		{test: "TestX9RowsAreSection46"},
	},
	"Q-REPO-3": {
		{rule: "protocol beyond std, protobuf and protocol/bridge, or protocol/bridge beyond std and protobuf"},
	},
	"Q-REPO-4": {
		{path: "README.md"}, {path: "design"}, {path: "LICENSE"},
	},
	"Q-REPO-5": {
		{rule: "the root module requiring any module of this repository"},
		{path: "smtpproof/go.mod"}, {path: "cli/go.mod"},
	},
}

// The R-REPO, D-REPO and Q-REPO ids §4 names, in order of first appearance.
func repoIdsInDesign(t *testing.T, repository *repository) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repository.topDirectory, "design", "source", "sections", "04-REPO.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, match := range regexp.MustCompile(`\b[RDQ]-REPO-[0-9]+\b`).FindAll(data, -1) {
		if !slices.Contains(ids, string(match)) {
			ids = append(ids, string(match))
		}
	}
	return ids
}

// A path of the repository: the root module's own first, which a release tree holds in v2026/, then
// the top, where the nested modules and the documents stay.
func (self *repository) repositoryPathExists(relativePath string) bool {
	for _, directory := range []string{self.moduleDirectory, self.topDirectory} {
		if _, err := os.Stat(filepath.Join(directory, filepath.FromSlash(relativePath))); err == nil {
			return true
		}
	}
	return false
}

func TestEveryRepoIdHasEvidence(t *testing.T) {
	repository := openThisCheckout(t)
	designIds := repoIdsInDesign(t, repository)
	if len(designIds) == 0 {
		t.Fatal("§4 names no R-REPO, D-REPO or Q-REPO id, so nothing was read")
	}
	items := map[string]bool{}
	for _, entry := range failsOnRows {
		items[entry.item] = true
	}
	tests := declaredTests(t)
	for _, id := range designIds {
		if len(repoMatrix[id]) == 0 {
			t.Errorf("%s is in §4 and has no evidence in repoMatrix", id)
		}
	}
	for id, evidences := range repoMatrix {
		if !slices.Contains(designIds, id) {
			t.Errorf("repoMatrix maps %s, which §4 does not name", id)
		}
		for _, evidence := range evidences {
			set := 0
			for _, value := range []string{evidence.rule, evidence.test, evidence.path, evidence.withdrawn} {
				if value != "" {
					set += 1
				}
			}
			if set != 1 {
				t.Errorf("%s has evidence %+v, which names not exactly one thing", id, evidence)
				continue
			}
			switch {
			case evidence.rule != "" && !items[evidence.rule]:
				t.Errorf("%s names the rule %q, which no row of failsOnRows holds", id, evidence.rule)
			case evidence.test != "" && !tests[evidence.test]:
				t.Errorf("%s names the test %s, which this package does not declare", id, evidence.test)
			case evidence.path != "" && !repository.repositoryPathExists(evidence.path):
				t.Errorf("%s names the path %s, which this repository does not hold", id, evidence.path)
			}
		}
		withdrawn := slices.ContainsFunc(evidences, func(evidence repoEvidence) bool { return evidence.withdrawn != "" })
		if withdrawn && len(evidences) != 1 {
			t.Errorf("%s is withdrawn and still names evidence", id)
		}
	}
}
