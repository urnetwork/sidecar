//go:build sidecar_check

// DESIGN-COMPUTE §3.3's placement (CARCH-M11-01): where compute's code lives and what each place may import. These read
// every Go file's syntax, as the layering rules do, so an import behind a tag no leg sets is in scope too.
//
//   - The root's compute families, the files §3.3's table puts in the root by prefix, import connect and the root
//     only: of the first-party modules, connect and this module's root, protocol and protocol/bridge, never server,
//     sdk, computeservice or searchsigner (owner rule 2). Third-party modules and std are the dependency rows' to hold.
//   - computeservice/, the broker and orchestrator, and searchsigner/, the search payer key's engine on hosts of its
//     own, may import the root and operator-core, never server or sdk (§3.3, §14.2), and searchsigner/ imports nothing
//     of computeservice/, which is its separation from the broker (§21.5, D-CSRV-1).
//   - sidecar/model, controller, work and handler, the server-hosted code owner decision 594 places there, never import
//     server or sdk either: server hosts them, through operator-core's Env.
//
// isEnginePackage counts searchsigner/ as an engine by name (§14.2 calls it one, and check/ otherwise counts only a
// directory ending in service), so the client rule refuses every client import of it as it does computeservice's.

package check

import (
	"path"
	"slices"
	"strings"
	"testing"
)

// The root's compute families by file prefix, §3.3's table: harness_, infer_, attest_, gateway_, compute_, enclave_,
// ssh_, git_, websearch_ (the web search §3.3 writes as search_, whose prefix §16.10's index search already holds; C-37),
// fetch_, calendar_, oauth_, listeners_, safety_, skill_, and the families the plan adds for the components' settings
// and their files: session_ (§24), disclosure_ (§2.8), budget_ and models_ (§16.4); and support_, §28's support skill and
// its support log. CSURF's page Worker rule reads the same list.
var computeRootFamilyPrefixes = []string{
	"attest_", "budget_", "calendar_", "compute_", "disclosure_", "enclave_", "fetch_", "gateway_", "git_", "harness_",
	"infer_", "listeners_", "models_", "oauth_", "safety_", "session_", "skill_", "ssh_", "support_", "websearch_",
}

// Compute's root files no family prefix names: the compute policy's settings, in the acl_ family (§16; CACL).
var computeRootFamilyFiles = []string{"acl_compute_settings.go"}

// The server engines compute adds (§14.2).
const (
	computeServicePackage = "computeservice"
	searchSignerPackage   = "searchsigner"
)

// The server-hosted packages of owner decision 594.
var serverHostedPackages = []string{"model", "controller", "work", "handler"}

// True for a root file of a compute family.
func isComputeRootFile(file *sourceFile) bool {
	if file.packageName != "." {
		return false
	}
	name := path.Base(file.path)
	return slices.Contains(computeRootFamilyFiles, name) ||
		slices.ContainsFunc(computeRootFamilyPrefixes, func(prefix string) bool { return strings.HasPrefix(name, prefix) })
}

// True for a path of one of URnetwork's modules, which the first-party rules bind.
func isFirstPartyPath(importPath string) bool {
	return strings.HasPrefix(importPath, urnetworkPrefix) || strings.HasPrefix(importPath, urfoundationPrefix)
}

// §3.3's placement over every bound file.
func (self *repository) computePlacementFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		first, _, _ := strings.Cut(file.packageName, "/")
		computeRoot := isComputeRootFile(file)
		engine := first == computeServicePackage || first == searchSignerPackage
		serverHosted := slices.Contains(serverHostedPackages, first)
		if !computeRoot && !engine && !serverHosted {
			continue
		}
		for _, site := range file.imports() {
			base := firstPartyBase(site.importPath)
			relative, ours := repositoryRelative(site.importPath)
			switch {
			case computeRoot:
				allowed := !isFirstPartyPath(base) || underPath(base, connectBasePath) ||
					(ours && slices.Contains([]string{".", "protocol", "protocol/bridge"}, relative))
				if !allowed {
					findings = append(findings, findingf("%s:%d: the compute file %s imports %s, and §3.3 lets the root's compute families import connect and the root only",
						self.displayPath(file.path), site.line, path.Base(file.path), site.importPath))
				}
			case underPath(base, serverBasePath) || underPath(base, sdkBasePath):
				findings = append(findings, findingf("%s:%d: %s imports %s, which hosts it: owner rule 2 and owner decision 594 keep server and sdk out of sidecar",
					self.displayPath(file.path), site.line, file.packageName, site.importPath))
			case first == searchSignerPackage && ours && underPath(relative, computeServicePackage):
				findings = append(findings, findingf("%s:%d: %s imports %s, and the search signer stands apart from the broker (§21.5)",
					self.displayPath(file.path), site.line, file.packageName, site.importPath))
			}
		}
	}
	return findings
}

// §3.3's placement over this checkout.
func TestComputePlacement(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "compute placement", repository.computePlacementFindings(t))
}

func TestComputePlacementFailsOnAnInferFileImportingServer(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("infer_planted.go", "package sidecar\n\nimport _ \"@server@/model\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t), "infer_planted.go:3: the compute file infer_planted.go imports @server@/model")
}

// No leg compiles this file, so only the syntax rule can see it.
func TestComputePlacementFailsOnAComputeFileImportingSdk(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("harness_planted.go", "//go:build never_set\n\npackage sidecar\n\nimport _ \"@sdk@\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t), "harness_planted.go:5: the compute file harness_planted.go imports @sdk@")
}

// Connect and the root only: operator-core, which other root files reach for the host seams, is no compute family's.
func TestComputePlacementFailsOnAComputeFileImportingOperatorCore(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("acl_compute_settings.go", "package sidecar\n\nimport _ \"@operator-core@\"\n")
	fixture.write("acl_planted.go", "package sidecar\n\nimport _ \"@operator-core@\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t), "acl_compute_settings.go:3: the compute file acl_compute_settings.go imports @operator-core@")
}

func TestComputePlacementFailsOnSearchsignerImportingComputeservice(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("computeservice/broker.go", "package computeservice\n")
	fixture.write("searchsigner/signer.go", "package searchsigner\n\nimport _ \"@module@/computeservice\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t), "searchsigner/signer.go:3: searchsigner imports @module@/computeservice")
}

func TestComputePlacementFailsOnTheBrokerImportingServer(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("computeservice/ledger/ledger.go", "package ledger\n\nimport _ \"@server@/model\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t), "computeservice/ledger/ledger.go:3: computeservice/ledger imports @server@/model")
}

func TestComputePlacementFailsOnAServerHostedPackageImportingServer(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("controller/compute_ledger.go", "package controller\n\nimport _ \"@server@\"\n")
	fixture.write("work/compute_settle.go", "package work\n\nimport _ \"@sdk@\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t),
		"controller/compute_ledger.go:3: controller imports @server@",
		"work/compute_settle.go:3: work imports @sdk@")
}

// What §3.3 allows: a compute file over connect, the root's protocols, std and a third party's module; the engines over
// the root and operator-core; the broker over the signer's package, which only the signer's separation binds; and a
// root file of no compute family, which the root's own rule binds.
func TestComputePlacementAllowsWhatSection33Allows(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("infer_planted.go", "package sidecar\n\nimport (\n\t_ \"context\"\n\n\t_ \"@connect@\"\n\t_ \"@connect@/protocol\"\n\t_ \"@module@/protocol\"\n\t_ \"@module@/protocol/bridge\"\n\t_ \"github.com/ebitengine/purego\"\n)\n")
	fixture.write("searchsigner/signer.go", "package searchsigner\n\nimport (\n\t_ \"@module@\"\n\t_ \"@operator-core@\"\n)\n")
	fixture.write("computeservice/broker.go", "package computeservice\n\nimport (\n\t_ \"@module@\"\n\t_ \"@module@/searchsigner\"\n\t_ \"@operator-core@\"\n)\n")
	fixture.write("model/compute_account.go", "package model\n\nimport _ \"@operator-core@\"\n")
	fixture.write("host_planted.go", "package sidecar\n\nimport _ \"@operator-core@\"\n")
	wantFindings(t, fixture.open().computePlacementFindings(t))
}

// §14.2's search signer is an engine by name, so a client importing it is refused as for any <svc>service.
func TestLayeringFailsOnTheRootImportingTheSearchSigner(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("searchsigner/signer.go", "package searchsigner\n")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"@module@/searchsigner\"\n")
	wantFindings(t, fixture.open().clientEngineImportFindings(t), "the client package . imports @module@/searchsigner")
}

// And the engine legs list it as they list each <svc>service, so server's build of it is read like theirs.
func TestLegsPickUpTheSearchSignerAsAnEngine(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("searchsigner/signer.go", "package searchsigner\n\nimport _ \"@module@\"\n")
	repository := fixture.open()
	closure := repository.closure(t, repository.leg(t, "engines linux/amd64"))
	if !slices.ContainsFunc(closure, func(listed *listedPackage) bool { return listed.ImportPath == repository.modulePath+"/searchsigner" }) {
		t.Errorf("the engine leg's closure lacks the search signer")
	}
}
