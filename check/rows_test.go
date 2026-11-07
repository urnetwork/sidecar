//go:build sidecar_check

// §4.7's fails-on block, row by row, over this checkout. failsOnRows is the index: every rule, the
// switch it stands behind if the design starts it later, and the tests that plant its violation.
// TestEveryRowHasARuleAndAPlantedViolation reads this package's own test names, so a rule
// cannot sit here unproven.

package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// One item of the block, or of the rules that bind it (§4.4, §18.10, CODESTYLE).
type failsOnRow struct {
	// deps, layering, legs, cgo or hygiene, then size for make size's
	row  string
	item string
	rule func(self *repository, t testing.TB) []string
	// names the switch when §4.18 starts the item after M0
	switched func(switches *rowSwitches) *bool
	// the test that runs the item over this checkout, where a rule needs more than a repository
	checkoutTest string
	// tests that plant this item's violation
	plantedTests []string
}

// The rules a checkout must hold, in the block's order.
var failsOnRows = []failsOnRow{
	{
		row: "deps", item: "server, sdk, sn or an unlisted module in a leg's go list -deps",
		rule: (*repository).legModuleFindings,
		plantedTests: []string{
			"TestDepsFailsOnServerInALeg", "TestDepsFailsOnSdkInALeg", "TestDepsFailsOnSnInALeg",
			"TestDepsFailsOnAnEngineLinkingGoRedis", "TestDepsFailsOnAnUnlistedModuleInALeg", "TestDepsFailsOnAModuleOutsideItsRowsLegs",
			"TestDepsFailsOnAnUnreadableDependenciesFile",
		},
	},
	{
		row: "deps", item: "a listed module no leg links",
		rule:         (*repository).staleRowFindings,
		plantedTests: []string{"TestDepsFailsOnAStaleRow"},
	},
	{
		row: "deps", item: "the root module requiring any module of this repository",
		rule:         (*repository).rootRequireFindings,
		plantedTests: []string{"TestDepsFailsOnTheRootRequiringSmtpproof", "TestDepsFailsOnTheRootRequiringCli"},
	},
	{
		row: "deps", item: "a first-party require §4.7's imports bullet does not name",
		rule:         (*repository).firstPartyRequireFindings,
		plantedTests: []string{"TestDepsFailsOnANestedModuleRequiringProxy", "TestDepsFailsOnARequireNoPackageReaches"},
	},
	{
		row: "deps", item: "a module outside §4.7's table, or one no leg reads",
		rule:         (*repository).moduleSetFindings,
		plantedTests: []string{"TestDepsFailsOnAFifthModule", "TestDepsFailsOnAnAlternateModuleFile", "TestDepsFailsOnAModuleNoLegReads"},
	},
	{
		row: "deps", item: "from M10, a leg selecting a golang.org/x/text other than normalizer 1's",
		rule: func(self *repository, t testing.TB) []string {
			return rowOff(self.report, self.settings.switches.xTextIsNormalizerOnes, "xTextIsNormalizerOnes", self.xTextFindings(t))
		},
		switched: func(switches *rowSwitches) *bool {
			return &switches.xTextIsNormalizerOnes
		},
		plantedTests: []string{
			"TestDepsFailsOnAnOlderXText", "TestDepsFailsOnANewerXText", "TestDepsFailsOnASiblingLegsXText",
			"TestDepsFailsOnAReplacedXText",
		},
	},
	{
		row: "deps", item: "a shared module's version other than connect's, sdk's and server's",
		rule:         (*repository).sharedVersionFindings,
		plantedTests: []string{"TestDepsFailsOnASharedVersionMismatch", "TestDepsFailsOnAMissingSibling"},
	},
	{
		row: "deps", item: "a license §4.7 refuses, or a row its module's files do not back",
		rule: (*repository).licenseRowFindings,
		plantedTests: []string{
			"TestDepsFailsOnARefusedLicenseId", "TestDepsFailsOnAnUnlicensedModule", "TestDepsFailsOnAGplFileUnderAnMitRow",
			"TestDepsFailsOnAnAdvertisingClauseUnderAnMitRow", "TestDepsFailsOnARefusedLicenseAtOneVersionOfTwo",
			"TestDepsFailsOnAnX11RowOverPlainMit", "TestDepsFailsOnAnX11ClauseWithoutMitsText",
			"TestDepsFailsOnASecondAdvertisingClauseUnderAnX11Row", "TestDepsFailsOnAnotherClauseUnderAnX11Row",
		},
	},

	{
		row: "layering", item: "the root importing a package of this module other than protocol and protocol/bridge",
		rule: (*repository).rootImportFindings,
		plantedTests: []string{
			"TestLayeringFailsOnTheRootImportingDevice", "TestLayeringFailsOnAnImportNoLegCompiles",
			"TestLayeringFailsOnAnInternalTestImport", "TestLayeringFailsOnANonTestFileClaimingTheExternalPackage",
		},
	},
	{
		row: "layering", item: "protocol beyond std, protobuf and protocol/bridge, or protocol/bridge beyond std and protobuf",
		rule: (*repository).protocolImportFindings,
		plantedTests: []string{
			"TestLayeringFailsOnProtocolImportingTheRoot", "TestLayeringFailsOnProtocolImportingConnect",
			"TestLayeringFailsOnBridgeImportingProtocol", "TestLayeringFailsOnANameThatOnlySharesProtobufsPrefix",
		},
	},
	{
		row: "layering", item: "a client package importing a <svc>service",
		rule: (*repository).clientEngineImportFindings,
		plantedTests: []string{
			"TestLayeringFailsOnTheRootImportingAnEngine", "TestLayeringFailsOnANewPackageImportingAnEngine",
			"TestLayeringFailsOnCliImportingAnEngine",
		},
	},
	{
		row: "layering", item: "a client or cli leg linking a <svc>service, or any shipped leg linking sidecartest",
		rule:         (*repository).legEngineFindings,
		plantedTests: []string{"TestLayeringFailsOnAnEngineThroughSidecartest", "TestLayeringFailsOnAnEngineLinkingSidecartest"},
	},
	{
		row: "layering", item: "device beyond connect and protocol/bridge (§4.4, D-SDK-20)",
		rule: (*repository).deviceImportFindings,
		plantedTests: []string{
			"TestLayeringFailsOnDeviceImportingTheRoot", "TestLayeringFailsOnDeviceImportingProtocol",
			"TestLayeringFailsOnDevicesTaggedHookFileImportingTheRoot",
		},
	},
	{
		row: "layering", item: "a parent importing its child (R-REPO-5)",
		rule:         (*repository).parentImportFindings,
		plantedTests: []string{"TestLayeringFailsOnAParentImportingItsChild"},
	},
	{
		row: "layering", item: "generated protobuf outside protocol and protocol/bridge (§4.9)",
		rule:         (*repository).protoHomeFindings,
		plantedTests: []string{"TestLayeringFailsOnAPbGoOutsideProtocol"},
	},

	{
		row: "legs", item: "an sdk leg with no leg here",
		rule:         (*repository).sdkLegRowFindings,
		plantedTests: []string{"TestLegsFailsOnAnSdkLegWithNoLegHere", "TestLegsFailsOnAnSdkTableItCannotFind"},
	},
	{
		row: "legs", item: "the ios_extension leg's deps including the root package or protocol",
		rule: func(self *repository, t testing.TB) []string {
			return rowOff(self.report, self.settings.switches.iosExtensionLinksNoRoot, "iosExtensionLinksNoRoot", self.iosExtensionFindings(t))
		},
		switched: func(switches *rowSwitches) *bool {
			return &switches.iosExtensionLinksNoRoot
		},
		plantedTests: []string{
			"TestLegsFailsOnIosExtensionLinkingTheRoot", "TestLegsFailsOnIosExtensionLinkingProtocol",
			"TestLegsFailsOnTheMacExtensionSlice", "TestLegsFailsOnIosExtensionLinkingAnythingElseOfOurs",
		},
	},
	{
		row: "legs", item: "the sidecar_http js leg's deps including any connect or gVisor package",
		rule: func(self *repository, t testing.TB) []string {
			return rowOff(self.report, self.settings.switches.sidecarHttpLinksNoConnect, "sidecarHttpLinksNoConnect", self.sidecarHttpFindings(t))
		},
		switched: func(switches *rowSwitches) *bool {
			return &switches.sidecarHttpLinksNoConnect
		},
		plantedTests: []string{
			"TestLegsFailsOnSidecarHttpLinkingConnect", "TestLegsFailsOnSidecarHttpLinkingGvisor",
			"TestLegsFailsOnSidecarHttpThroughProtocol",
		},
	},
	{
		row: "legs", item: "a host_*.go file on the sidecar_http leg (§18.10)",
		rule:         (*repository).hostFileFindings,
		plantedTests: []string{"TestLegsFailsOnAHostFileWithoutTheTag"},
	},
	{
		row: "legs", item: "net/rpc or template packages on ios, android or js",
		rule: (*repository).pruningFindings,
		plantedTests: []string{
			"TestLegsFailsOnNetRpcOnIos", "TestLegsFailsOnTextTemplateOnAndroid", "TestLegsFailsOnHtmlTemplateOnJs",
			"TestLegsFailsOnATemplateSubpackage",
		},
	},
	{
		row: "legs", item: "a dynamic reflect lookup in shipped code (§18.10)",
		rule: (*repository).reflectLookupFindings,
		plantedTests: []string{
			"TestLegsFailsOnADynamicReflectLookup", "TestLegsFailsOnAReflectMethodsIterator", "TestLegsFailsOnAReflectMethodExpression",
		},
	},
	{
		row: "legs", item: "a leg that does not compile, on each leg this host has the toolchain for (§22.4's T1)",
		rule: (*repository).legCompileFindings,
		plantedTests: []string{
			"TestLegsFailsOnAFileOnlyWindowsCompiles", "TestLegsFailsOnATestOnlyJsCompiles",
			"TestLegsFailsOnACliFileOnlyWindowsArm64Compiles", "TestLegsFailsOnAPageWorkerFileThatDoesNotCompile",
			"TestLegsFailsOnAnEngineFileOnlyArm64Compiles", "TestLegsFailsOnACgoFileThisHostCompiles",
			"TestLegsFailsOnAFileOnlyAndroidCompiles",
		},
	},

	{
		row: "cgo", item: "CgoFiles anywhere in this repository, except keychain_darwin.go",
		rule: (*repository).cgoSourceFindings,
		plantedTests: []string{
			"TestCgoFailsOnACgoFileInTheRoot", "TestCgoFailsOnACgoFileNoLegCompiles", "TestCgoFailsOnAKeychainFileInTheWrongPackage",
		},
	},
	{
		row: "cgo", item: "CgoFiles on a leg, keychain_darwin.go outside §5.10's fallback leg included",
		rule: (*repository).cgoLegFindings,
		plantedTests: []string{
			"TestCgoFailsOnACgoFileOnALeg", "TestCgoFailsOnTheKeychainFileOutsideTheFallbackLeg",
			"TestCgoFailsOnAKeychainFileInAnotherPackageOnTheFallbackLeg", "TestCgoFailsOnANewThirdPartyCgoFile",
		},
	},

	{
		row: "hygiene", item: "replaces other than §4.7's",
		rule: (*repository).replaceFindings,
		plantedTests: []string{
			"TestHygieneFailsOnAnExtraReplace", "TestHygieneFailsOnAMovedReplace", "TestHygieneFailsOnAMissingReplace",
			"TestHygieneFailsOnANestedModuleNotRepeatingAReplace", "TestHygieneFailsOnAVersionedReplace",
			"TestHygieneFailsOnAReleaseBranchExtraReplace",
		},
	},
	{
		row: "hygiene", item: "go and tool lines other than §4.7's",
		rule:         (*repository).moduleLineFindings,
		plantedTests: []string{"TestHygieneFailsOnAnotherGoLine", "TestHygieneFailsOnAnExtraToolLine"},
	},
	{
		row: "hygiene", item: "a go.work file",
		rule:         (*repository).workFileFindings,
		plantedTests: []string{"TestHygieneFailsOnAGoWorkFile"},
	},
	{
		row: "hygiene", item: "a package beside cli's or mlsinterop's own, which the release's rewrite would break (§4.9)",
		rule:         (*repository).untaggedSubpackageFindings,
		plantedTests: []string{"TestHygieneFailsOnASubpackageOfCli", "TestHygieneFailsOnASubpackageOfMlsinterop"},
	},
	{
		row: "hygiene", item: "a path the go command refuses in a module zip, which makes a tag no consumer can download (§4.9)",
		rule: (*repository).moduleZipFindings,
		plantedTests: []string{
			"TestHygieneFailsOnAReservedWindowsName", "TestHygieneFailsOnACharacterAModuleZipRefuses",
			"TestHygieneFailsOnATrailingDot", "TestHygieneFailsOnAPathInANestedModule",
			"TestHygieneFailsOnTwoPathsThatDifferOnlyInCase",
		},
	},
	{
		row: "hygiene", item: "registry conflicts",
		rule: (*repository).registryFindings,
		plantedTests: []string{
			"TestHygieneFailsOnTwoFilesDeclaringOneMessage", "TestHygieneFailsOnAConflictWithConnect",
			"TestHygieneFailsOnAProtoRegisteredOutsideItsPath", "TestHygieneFailsOnAnotherProtoPackage",
		},
	},
	{
		row: "hygiene", item: "stale generated code",
		rule: (*repository).staleGeneratedFindings,
		plantedTests: []string{
			"TestHygieneFailsOnAProtoEditedAfterGeneration", "TestHygieneFailsOnAHandEditedPbGo", "TestHygieneFailsOnAMissingPbGo",
			"TestHygieneFailsOnAnOrphanPbGo", "TestHygieneFailsOnAnotherPluginVersion", "TestHygieneFailsOnAStalePbGoOnAReleaseBranch",
			"TestHygieneFailsOnGeneratedCodeItCannotRegenerate", "TestHygieneFailsOnAMissingProtoc",
		},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: the leg's tags",
		rule: func(self *repository, t testing.TB) []string {
			return self.legTagFindings()
		},
		plantedTests: []string{"TestHygieneFailsOnAReleaseLegWithTheHooksTag", "TestHygieneFailsOnAReleaseLegWithTheLeakTag"},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: the caller's GOFLAGS",
		rule: func(self *repository, t testing.TB) []string {
			return callerGoflagsFindings(os.Getenv("GOFLAGS"))
		},
		plantedTests: []string{"TestHygieneFailsOnTheHooksTagInGoflags"},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: a file it compiles that answers to the tag",
		rule: (*repository).legHookFileFindings,
		plantedTests: []string{
			"TestHygieneFailsOnALegLinkingTheRootHookFile", "TestHygieneFailsOnALegLinkingAPackagesHookFile",
			"TestHygieneFailsOnAHookFileAnotherConstraintLetsIn", "TestHygieneFailsOnALegLinkingAFileTheRulesSkip",
			"TestHygieneFailsOnACgoFileAnsweringToTheTag", "TestHygieneFailsOnALegLinkingACgoFileTheRulesSkip",
			"TestHygieneFailsOnAPlusBuildLineTheRulesDoNotRead",
		},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: a package's hook pair",
		rule: (*repository).hookPairFindings,
		plantedTests: []string{
			"TestHygieneFailsOnAPackagesHookWithABody", "TestHygieneFailsOnAPackagesHookWithNoTag",
			"TestHygieneFailsOnAPackagesHookHeldInAVariable", "TestHygieneFailsOnAPackagesHalfMissing",
			"TestHygieneFailsOnAPackagesTaggedHalfNotForwarding", "TestHygieneFailsOnAHookPairInANestedModule",
			"TestHygieneFailsOnAnEntryPointWithoutTheTag", "TestHygieneFailsOnAnEntryPointOutsideTheRoot",
			"TestHygieneFailsOnAHookWithAnotherSignature", "TestHygieneFailsOnADeviceEntryPoint",
			"TestHygieneFailsOnADeviceInstallerWithoutTheTag", "TestHygieneFailsOnADeviceHookWithABody",
			"TestHygieneFailsOnAHookBodyBesideAnEmptyHalf", "TestHygieneFailsOnATaggedHalfBesideOneForwarding",
			"TestHygieneFailsOnAHookWithNoBodyOfItsOwn", "TestHygieneFailsOnAHookDeclaredAsAMethod",
			"TestHygieneFailsOnAnEntryPointDeclaredAsAMethod", "TestHygieneFailsOnAHookHeldInAField",
			"TestHygieneFailsOnAHookPassedAsAParameter", "TestHygieneFailsOnAHookShadowedByALocal",
		},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: a Makefile's build line",
		rule: (*repository).makefileTagFindings,
		plantedTests: []string{
			"TestHygieneFailsOnAMakefileBuildingWithTheTag", "TestHygieneFailsOnAMakefileBuildingBesideATest",
			"TestHygieneFailsOnGomobileBindingWithTheTag", "TestHygieneFailsOnAConsumerMakefileBuildingWithTheTag",
			"TestHygieneFailsOnAMissingConsumerMakefile",
		},
	},
	{
		row: "hygiene", item: "a release leg built with sidecar_testhooks: what the artifact says of itself",
		checkoutTest: "TestHygieneReleaseBinary",
		plantedTests: []string{"TestHygieneFailsOnABinaryBuiltWithTheTag", "TestHygieneFailsOnABinaryItCannotRead"},
	},
	{
		row: "hygiene", item: "govulncheck findings",
		checkoutTest: "TestHygieneGovulncheck",
		plantedTests: []string{"TestHygieneFailsOnAVulnerableCallOnALeg", "TestHygieneFailsOnAnUnreachableVulnDatabase"},
	},

	{
		row: "size", item: "the ios_extension leg adding over §18.10's 1 MiB",
		checkoutTest: "TestSizeVerdictsHoldTheirLimits",
		plantedTests: []string{"TestSizeFailsOnADeviceRoleOverItsLimit"},
	},
	{
		row: "size", item: "the sidecar_http js leg past §18.10's goal and miss rule",
		checkoutTest: "TestSizeVerdictsHoldTheirLimits",
		plantedTests: []string{"TestSizeFailsOnSidecarHttpOverItsGoal", "TestSizeFailsOnSidecarHttpOverItsMissGate"},
	},
}

// One repository over this checkout for every test here, so each closure is listed once.
var thisCheckout = sync.OnceValues(func() (*repository, error) {
	return openRepository("..", defaultCheckSettings(), defaultBuildLegs())
})

// What this run did not enforce or leaned on, for the end of make check's output. A run that passes
// says so too: a switched-off row or a license exception should not need a failure to be seen.
var (
	runReportLock  sync.Mutex
	runReportLines = map[string]bool{}
)

// This checkout, reporting to the test's log and to the end of the run.
func openThisCheckout(t testing.TB) *repository {
	t.Helper()
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	repository.listAllLegs()
	repository.report = func(format string, arguments ...any) {
		t.Logf(format, arguments...)
		runReportLock.Lock()
		defer runReportLock.Unlock()
		runReportLines[findingf(format, arguments...)] = true
	}
	return repository
}

// Runs the tests, then prints the run's report. make check runs this package in go test's local
// directory mode, which is what lets a passing run's output through.
func TestMain(m *testing.M) {
	code := m.Run()
	lines := slices.Sorted(maps.Keys(runReportLines))
	for _, line := range lines {
		fmt.Println("make check:", line)
	}
	os.Exit(code)
}

// Runs one block row of failsOnRows over this checkout.
func runRow(t *testing.T, row string) {
	t.Helper()
	repository := openThisCheckout(t)
	matched := false
	for _, entry := range failsOnRows {
		if entry.row == row && entry.rule != nil {
			matched = true
			failFindings(t, row, entry.rule(repository, t))
		}
	}
	if !matched {
		t.Fatalf("no rule is in the %s row", row)
	}
}

func TestDeps(t *testing.T) {
	runRow(t, "deps")
}

func TestLayering(t *testing.T) {
	runRow(t, "layering")
}

func TestLegs(t *testing.T) {
	runRow(t, "legs")
}

func TestCgo(t *testing.T) {
	runRow(t, "cgo")
}

func TestHygiene(t *testing.T) {
	runRow(t, "hygiene")
}

// §4.7's last hygiene item. It reaches the module proxy and vuln.go.dev, so a host without them
// fails this rather than passing it.
func TestHygieneGovulncheck(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "govulncheck", repository.vulnFindings(repository.installGovulncheck(t)))
}

// §22.4's last reading: the artifact's own build info. make check builds ur for this host, as the
// release would, and reads it; RELEASE_BINARIES on the make line adds the release's real artifacts.
func TestHygieneReleaseBinary(t *testing.T) {
	repository := openThisCheckout(t)
	binaryPath := filepath.Join(t.TempDir(), "ur")
	if _, err := runGo(repository.module(t, "cli").directory, goEnvironment("CGO_ENABLED=0"), "build", "-o", binaryPath, "."); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "hygiene", releaseBinaryFindings(binaryPath))
	for _, artifact := range strings.Fields(os.Getenv("RELEASE_BINARIES")) {
		failFindings(t, "hygiene", releaseBinaryFindings(artifact))
	}
}

// The tests a package declares, read off its own source, for the index below.
func declaredTests(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]bool{}
	fileSet := token.NewFileSet()
	for _, file := range files {
		syntax, err := parser.ParseFile(fileSet, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range syntax.Decls {
			if funcDecl, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(funcDecl.Name.Name, "Test") {
				tests[funcDecl.Name.Name] = true
			}
		}
	}
	return tests
}

// Every row has a rule and at least one planted test that exists, and every test named for a
// failure is on some row, both ways, so the index cannot drift from what actually runs.
func TestEveryRowHasARuleAndAPlantedViolation(t *testing.T) {
	tests := declaredTests(t)
	indexed := map[string]bool{}
	for _, entry := range failsOnRows {
		if entry.rule == nil && !tests[entry.checkoutTest] {
			t.Errorf("%s has no rule and no test that reads this checkout", entry.item)
		}
		if len(entry.plantedTests) == 0 {
			t.Errorf("%s has no planted test", entry.item)
		}
		for _, name := range entry.plantedTests {
			indexed[name] = true
			if !tests[name] {
				t.Errorf("%s names %s, which does not exist", entry.item, name)
			}
		}
	}
	planted := regexp.MustCompile(`^Test[A-Za-z]+FailsOn`)
	for name := range tests {
		if planted.MatchString(name) && !indexed[name] {
			t.Errorf("%s is on no row", name)
		}
	}
	for _, row := range []string{"deps", "layering", "legs", "cgo", "hygiene", "size"} {
		if !slices.ContainsFunc(failsOnRows, func(entry failsOnRow) bool { return entry.row == row }) {
			t.Errorf("no rule is in the %s row", row)
		}
	}
}

// §4.18's late rows each stand behind a named switch, and a switch off under a row that holds is a
// rule nobody is enforcing for no reason. A row that does not hold yet may stay off, and says so.
func TestRowsThatStartLaterHoldNow(t *testing.T) {
	repository := openThisCheckout(t)
	switched := 0
	for _, entry := range failsOnRows {
		if entry.switched == nil {
			continue
		}
		switched += 1
		switchOn := entry.switched(&repository.settings.switches)
		if *switchOn {
			continue
		}
		*switchOn = true
		findings := entry.rule(repository, t)
		*switchOn = false
		if len(findings) == 0 {
			t.Errorf("%s holds, so its switch should be on", entry.item)
		}
	}
	if switched != 3 {
		t.Errorf("%d rows stand behind a switch; §4.18 starts three in make check", switched)
	}
}

// Each switch governs its own row, in a run with the row's violation planted: off, the row passes
// and reports the finding; on, the row fails on it.
func TestEachSwitchGovernsItsRow(t *testing.T) {
	for _, c := range []struct {
		item  string
		plant func(fixture *fixture)
		legs  []string
	}{
		{
			item: "the sidecar_http js leg's deps including any connect or gVisor package",
			plant: func(fixture *fixture) {
				fixture.edit("connect_require.go", "//go:build !sidecar_http\n\n", "")
			},
			legs: []string{sidecarHttpLegName},
		},
		{
			item: "the ios_extension leg's deps including the root package or protocol",
			plant: func(fixture *fixture) {
				fixture.write("device/device.go", "package device\n\nimport _ \"@module@\"\n")
			},
			legs: []string{iosExtensionLegName},
		},
		{
			item: "from M10, a leg selecting a golang.org/x/text other than normalizer 1's",
			plant: func(fixture *fixture) {
				fixture.writeSibling("sdk/js/go.mod", "module @sdk@/js\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.41.0\n")
			},
			legs: []string{"root linux/amd64"},
		},
	} {
		index := slices.IndexFunc(failsOnRows, func(entry failsOnRow) bool { return entry.item == c.item })
		if index < 0 {
			t.Fatalf("no row reads %q", c.item)
		}
		entry := failsOnRows[index]
		fixture := newFixture(t)
		fixture.keepLegs(c.legs...)
		c.plant(fixture)

		*entry.switched(&fixture.settings.switches) = false
		repository := fixture.open()
		reports := []string{}
		repository.report = func(format string, arguments ...any) {
			reports = append(reports, findingf(format, arguments...))
		}
		if findings := entry.rule(repository, t); len(findings) != 0 {
			t.Errorf("%s: off, the row failed on %v", c.item, findings)
		}
		if len(reports) < 2 {
			t.Errorf("%s: off, the row reported %v, which lacks its finding", c.item, reports)
		}

		*entry.switched(&fixture.settings.switches) = true
		if findings := entry.rule(fixture.open(), t); len(findings) == 0 {
			t.Errorf("%s: on, the row passed its planted violation", c.item)
		}
	}
}

// A switch off stops the row failing and says so; it does not silence the rule.
func TestASwitchedOffRowReportsWhatItWouldFailOn(t *testing.T) {
	reports := []string{}
	report := func(format string, arguments ...any) {
		reports = append(reports, findingf(format, arguments...))
	}
	findings := rowOff(report, false, "xTextIsNormalizerOnes", []string{"root selects v0.42.0"})
	if len(findings) != 0 {
		t.Errorf("a switched-off row returned %v", findings)
	}
	if !slices.ContainsFunc(reports, func(line string) bool { return strings.Contains(line, "root selects v0.42.0") }) {
		t.Errorf("reports %v lack the finding", reports)
	}
	if findings := rowOff(report, true, "xTextIsNormalizerOnes", []string{"root selects v0.42.0"}); len(findings) != 1 {
		t.Errorf("a switched-on row returned %v", findings)
	}
}

// A quoted first-party path here would be rewritten by the release's sed, and a fixture or table
// would then name a module nothing provides, so make check at release would fail on its own tests.
func TestNoQuotedFirstPartyPathHere(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"` + regexp.QuoteMeta(urnetworkPrefix))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if location := pattern.FindIndex(data); location != nil {
			t.Errorf("%s holds a quoted first-party path at byte %d", file, location[0])
		}
	}
}

// go test's own limit is 10 minutes a package, and smtpproof's circuit tests pass it on a loaded
// machine, which fails make check on the clock and says nothing about the code. So every go test the
// Makefile runs names its limit, and a new one cannot quietly fall back to the default.
func TestMakefileNamesEveryGoTestsTimeout(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for index, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, command := range shellCommandEndPattern.Split(line, -1) {
			if !goTestCommandPattern.MatchString(command) || strings.HasPrefix(strings.TrimSpace(command), "echo") {
				continue
			}
			found += 1
			if !strings.Contains(command, "-timeout") {
				t.Errorf("Makefile:%d: this go test falls back to the 10 minute default: %s", index+1, strings.TrimSpace(command))
			}
		}
	}
	if found == 0 {
		t.Errorf("the Makefile holds no go test, so nothing here read it")
	}
}
