//go:build sidecar_check

// The deps row's planted violations. Each starts from the clean fixture, so what it finds is what it
// planted. TestFixtureIsClean is that control, over every rule at once.

package check

import (
	"slices"
	"strings"
	"testing"
)

// Every rule finds nothing on the clean tree, on the real leg table.
func TestFixtureIsClean(t *testing.T) {
	repository := newFixture(t).open()
	repository.listAllLegs()
	for _, entry := range failsOnRows {
		if entry.rule != nil {
			failFindings(t, entry.item, entry.rule(repository, t))
		}
	}
}

// Plants a root file linking the first-party module at modulePath, provided at sibling.
func plantLinkedModule(t *testing.T, modulePath string, importPath string, sibling string) *repository {
	t.Helper()
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.requireLocal(modulePath, "v0.0.0", sibling)
	fixture.write("planted.go", "package sidecar\n\nimport _ \""+importPath+"\"\n")
	return fixture.open()
}

func TestDepsFailsOnServerInALeg(t *testing.T) {
	repository := plantLinkedModule(t, "@server@", "@server@/model", "server")
	wantFindings(t, repository.legModuleFindings(t), "root linux/amd64 links @server@/model, from server")
}

func TestDepsFailsOnSdkInALeg(t *testing.T) {
	repository := plantLinkedModule(t, "@sdk@", "@sdk@", "sdk")
	wantFindings(t, repository.legModuleFindings(t), "root linux/amd64 links @sdk@, from sdk")
}

func TestDepsFailsOnSnInALeg(t *testing.T) {
	repository := plantLinkedModule(t, "@sn@", "@sn@", "sn")
	wantFindings(t, repository.legModuleFindings(t), "root linux/amd64 links @sn@, from sn")
}

// §4.5: a row in dependencies.yml is no way round ServiceHost. An engine gets these from its host.
func TestDepsFailsOnAnEngineLinkingGoRedis(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("engines linux/amd64")
	fixture.writeSibling("goredis/go.mod", "module github.com/redis/go-redis/v9\n\ngo 1.27.3\n")
	fixture.writeSibling("goredis/redis.go", "package redis\n")
	fixture.requireLocal("github.com/redis/go-redis/v9", "v9.23.0", "goredis")
	fixture.edit("dependencies.yml", "modules:\n", "modules:\n  - module: github.com/redis/go-redis/v9\n    spdx: BSD-2-Clause\n    reason: a listing is no way round the rule\n    leg: [engine]\n")
	fixture.write("evsservice/engine.go", "package evsservice\n\nimport _ \"github.com/redis/go-redis/v9\"\n")
	wantFindings(t, fixture.open().legModuleFindings(t), "engines linux/amd64 links github.com/redis/go-redis/v9, from go-redis")
}

func TestDepsFailsOnAnUnlistedModuleInALeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.writeSibling("unlisted/go.mod", "module example.com/unlisted\n\ngo 1.27.3\n")
	fixture.writeSibling("unlisted/unlisted.go", "package unlisted\n")
	fixture.requireLocal("example.com/unlisted", "v1.0.0", "unlisted")
	fixture.edit("cli/go.mod", "replace @module@ => ..", "require example.com/unlisted v1.0.0\n\nreplace example.com/unlisted => ../../unlisted\n\nreplace @module@ => ..")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"example.com/unlisted\"\n")
	wantFindings(t, fixture.open().legModuleFindings(t),
		"cli linux/amd64 links example.com/unlisted, and dependencies.yml does not list example.com/unlisted")
}

func TestDepsFailsOnAModuleOutsideItsRowsLegs(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.edit("dependencies.yml", "reason: the fixture's glog\n    leg: [client, engine, cli, test]", "reason: the fixture's glog\n    leg: [cli]")
	wantFindings(t, fixture.open().legModuleFindings(t), "root linux/amd64 is a client leg and links @glog@, whose row names [cli]")
}

// planted spares a row the stale check and nothing else: once a leg links the module its files are
// read like any other's, so a row that said planned cannot wave a license through.
func TestDepsReadsAPlannedRowsFilesOnceItIsLinked(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"google.golang.org/protobuf/proto\"\n")
	fixture.edit("dependencies.yml", "spdx: BSD-3-Clause", "spdx: MIT")
	repository := fixture.open()
	reports := []string{}
	repository.report = func(format string, arguments ...any) {
		reports = append(reports, findingf(format, arguments...))
	}
	wantFindings(t, repository.legModuleFindings(t))
	wantFindings(t, reports, "a leg links google.golang.org/protobuf, whose row can drop planned")
	wantFindings(t, repository.licenseRowFindings(t), "google.golang.org/protobuf says MIT, and its license text lacks")
}

// Every way the file can stray from its one shape fails, rather than dropping a row in silence. Each
// is planted in a fixture and read through the leg rule, so the rule, not just its parser, fails on it.
func TestDepsFailsOnAnUnreadableDependenciesFile(t *testing.T) {
	row := "  - module: example.com/a\n    spdx: MIT\n    reason: a reason\n    leg: [client]\n"
	for _, c := range []struct {
		missing bool
		content string
		want    string
	}{
		{missing: true, want: "reading dependencies.yml"},
		{content: "", want: "no modules: list"},
		{content: "modules:\n  - module: example.com/a\n", want: "needs module, spdx, reason and leg"},
		{content: "modules:\n" + row + row, want: "listed twice"},
		{content: "modules:\n" + row + "    license: MIT\n", want: "unknown field license"},
		{content: "modules:\n" + row + "stray\n", want: "cannot read"},
		{content: "modules:\n" + strings.Replace(row, "[client]", "client", 1), want: "not a [list]"},
		{content: "modules:\n" + strings.Replace(row, "[client]", "[server]", 1), want: "server is not a leg"},
		{content: "modules:\n" + strings.Replace(row, "a reason", "a: reason", 1), want: "holds ': '"},
		{content: "modules:\n" + row + "    planned: no\n", want: "planned is true or absent"},
	} {
		fixture := newFixture(t)
		fixture.keepLegs("root linux/amd64")
		if c.missing {
			fixture.remove("dependencies.yml")
		} else {
			fixture.write("dependencies.yml", c.content)
		}
		findings := fixture.open().legModuleFindings(t)
		if !slices.ContainsFunc(findings, func(finding string) bool { return strings.Contains(finding, c.want) }) {
			t.Errorf("%q: findings %v lack %q", c.content, findings, c.want)
		}
	}
}

func TestDepsFailsOnAStaleRow(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.edit("dependencies.yml", "modules:\n", "modules:\n  - module: example.com/gone\n    spdx: MIT\n    reason: left the tree\n    leg: [client]\n")
	wantFindings(t, fixture.open().staleRowFindings(t), "no leg links example.com/gone")
}

func TestDepsFailsOnTheRootRequiringSmtpproof(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "require @connect@ v0.0.0", "require @connect@ v0.0.0\n\nrequire @module@/smtpproof v0.0.0")
	wantFindings(t, fixture.open().rootRequireFindings(t), "the root module requires @module@/smtpproof")
}

func TestDepsFailsOnTheRootRequiringCli(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "require @connect@ v0.0.0", "require @connect@ v0.0.0\n\nrequire @module@/cli v0.0.0 // indirect")
	wantFindings(t, fixture.open().rootRequireFindings(t), "the root module requires @module@/cli")
}

func TestDepsFailsOnANestedModuleRequiringProxy(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("cli/go.mod", "require @connect@ v0.0.0 // indirect", "require @connect@ v0.0.0 // indirect\n\nrequire @proxy@ v0.0.0 // indirect")
	wantFindings(t, fixture.open().firstPartyRequireFindings(t), "cli requires @proxy@, proxy")
}

// A require nothing imports reaches no leg's closure, and still enters consumers' graphs.
func TestDepsFailsOnARequireNoPackageReaches(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "require @connect@ v0.0.0", "require @connect@ v0.0.0\n\nrequire "+urnetworkPrefix+"goidenticons v0.0.0 // indirect")
	wantFindings(t, fixture.open().firstPartyRequireFindings(t), "a first-party module §4.7 does not name")
}

func TestDepsFailsOnAFifthModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("tools/go.mod", "module @module@/tools\n\ngo 1.27.3\n")
	wantFindings(t, fixture.open().moduleSetFindings(t),
		"no leg reads the module @module@/tools",
		"tools is the module @module@/tools, which is not in §4.7's table")
}

// -modfile can point a build at one of these, and no leg would see what it requires.
func TestDepsFailsOnAnAlternateModuleFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("alt.go.mod", "module @module@/alt\n\ngo 1.27.3\n")
	wantFindings(t, fixture.open().moduleSetFindings(t),
		". is the module @module@/alt, which is not in §4.7's table",
		"no leg reads the module @module@/alt")
}

func TestDepsFailsOnAModuleNoLegReads(t *testing.T) {
	fixture := newFixture(t)
	fixture.legs = slices.DeleteFunc(fixture.legs, func(leg *buildLeg) bool { return leg.moduleName == "mlsinterop" })
	wantFindings(t, fixture.open().moduleSetFindings(t), "no leg reads the module @module@/mlsinterop")
}

// A fake x/text at the version given, in place of the real one, keeps these tests offline. The
// replace is itself a finding, so each want lists it after what the test is about.
func plantXText(t *testing.T, version string) *repository {
	t.Helper()
	fixture := newFixture(t)
	fixture.writeSibling("faketext/go.mod", "module golang.org/x/text\n\ngo 1.27.3\n")
	fixture.requireLocal(xTextBasePath, version, "faketext")
	fixture.edit("cli/go.mod", "replace @module@ => ..", "require golang.org/x/text "+version+" // indirect\n\nreplace golang.org/x/text => ../../faketext\n\nreplace @module@ => ..")
	return fixture.open()
}

func TestDepsFailsOnAnOlderXText(t *testing.T) {
	wantFindings(t, plantXText(t, "v0.42.0").xTextFindings(t),
		". selects golang.org/x/text v0.42.0, and normalizer 1's is v0.43.0",
		". replaces golang.org/x/text with ../faketext",
		"cli selects golang.org/x/text v0.42.0, and normalizer 1's is v0.43.0",
		"cli replaces golang.org/x/text with ../../faketext")
}

// Normalizer 1 is one version, not a floor: another is another normalizer (§11.14).
func TestDepsFailsOnANewerXText(t *testing.T) {
	wantFindings(t, plantXText(t, "v0.44.0").xTextFindings(t),
		". selects golang.org/x/text v0.44.0, and normalizer 1's is v0.43.0",
		". replaces golang.org/x/text with ../faketext",
		"cli selects golang.org/x/text v0.44.0, and normalizer 1's is v0.43.0",
		"cli replaces golang.org/x/text with ../../faketext")
}

func TestDepsFailsOnAReplacedXText(t *testing.T) {
	wantFindings(t, plantXText(t, "v0.43.0").xTextFindings(t),
		". replaces golang.org/x/text with ../faketext",
		"cli replaces golang.org/x/text with ../../faketext")
}

// gomobile's legs build under sdk/build, so a sidecar module's own selection does not reach them.
func TestDepsFailsOnASiblingLegsXText(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("sdk/build/go.mod", "module @sdk@/build\n\ngo 1.27.3\n\nrequire golang.org/x/text v0.41.0\n")
	wantFindings(t, fixture.open().xTextFindings(t), "sdk/build requires golang.org/x/text v0.41.0")
}

func TestDepsFailsOnASharedVersionMismatch(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("shared/go.mod", "module example.com/shared\n\ngo 1.27.3\n")
	fixture.writeSibling("shared/shared.go", "package shared\n")
	fixture.requireLocal("example.com/shared", "v1.0.0", "shared")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"example.com/shared\"\n")
	fixture.writeSibling("server/go.mod", "module @server@\n\ngo 1.27.3\n\nrequire example.com/shared v1.1.0\n")
	wantFindings(t, fixture.open().sharedVersionFindings(t), "links example.com/shared v1.0.0, and server requires v1.1.0")
}

// A rule that cannot read a sibling has not passed.
func TestDepsFailsOnAMissingSibling(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.remove("../server/go.mod")
	wantFindings(t, fixture.open().sharedVersionFindings(t), "reading server's requirements")
}

func TestDepsFailsOnARefusedLicenseId(t *testing.T) {
	for _, id := range []string{"GPL-3.0-only", "AGPL-3.0-only", "LGPL-2.1-only", "SSPL-1.0", "BUSL-1.1", "LicenseRef-custom", "Unlicense"} {
		fixture := newFixture(t)
		fixture.keepLegs("root linux/amd64")
		fixture.edit("dependencies.yml", "spdx: BSD-3-Clause", "spdx: "+id)
		wantFindings(t, fixture.open().licenseRowFindings(t), "google.golang.org/protobuf is "+id+", which §4.7 does not allow")
	}
}

func TestDepsFailsOnAnUnlicensedModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.remove("../glog/LICENSE")
	wantFindings(t, fixture.open().licenseRowFindings(t), "@glog@ has no license file, and §4.7 refuses the unlicensed")
}

// The id in the row is a claim; the file is the fact.
func TestDepsFailsOnAGplFileUnderAnMitRow(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("connect/sctp/LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n")
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"github.com/pion/sctp says MIT, and its license text lacks",
		"github.com/pion/sctp's license text has \"gnu general public license\"")
}

// tlshacks's case: MIT's words and one more clause make a custom license.
func TestDepsFailsOnAnAdvertisingClauseUnderAnMitRow(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("connect/sctp/LICENSE", fixtureMitLicense+"The name(s) of the copyright holders shall not be used in advertising.\n")
	wantFindings(t, fixture.open().licenseRowFindings(t), "github.com/pion/sctp's license text has \"shall not be used in advertising\"")
}

// An exception covers one version: a bump is a new license to read. The exception is the real
// settings' own, so this holds the one that stands, through the rule that reads it: at its version
// the module passes, and at the next it fails.
func TestDepsFailsOnAnExceptionAtAnotherVersion(t *testing.T) {
	exception, standing := defaultCheckSettings().licenseExceptions["src.agwa.name/tlshacks"]
	if !standing || exception.version != "v0.0.4" {
		t.Fatalf("the tlshacks exception is %+v, not the v0.0.4 one this test holds", exception)
	}
	tlshacksFixture := func(version string) *fixture {
		fixture := newFixture(t)
		fixture.keepLegs("root linux/amd64")
		fixture.settings.licenseExceptions = map[string]licenseException{"src.agwa.name/tlshacks": exception}
		fixture.writeSibling("tlshacks/go.mod", "module src.agwa.name/tlshacks\n\ngo 1.27.3\n")
		fixture.writeSibling("tlshacks/LICENSE", fixtureMitLicense+"The name(s) of the copyright holders shall not be used in advertising.\n")
		fixture.writeSibling("tlshacks/tlshacks.go", "package tlshacks\n")
		fixture.requireLocal("src.agwa.name/tlshacks", version, "tlshacks")
		fixture.write("tlshacks.go", "package sidecar\n\nimport _ \"src.agwa.name/tlshacks\"\n")
		fixture.edit("dependencies.yml", "modules:\n", "modules:\n  - module: src.agwa.name/tlshacks\n    spdx: X11\n    reason: parses a ClientHello\n    leg: [client]\n")
		return fixture
	}
	wantFindings(t, tlshacksFixture("v0.0.4").open().licenseRowFindings(t))
	wantFindings(t, tlshacksFixture("v0.0.5").open().licenseRowFindings(t),
		"src.agwa.name/tlshacks is X11, which §4.7 does not allow, at v0.0.5",
		"src.agwa.name/tlshacks's license text has \"shall not be used in advertising\", at v0.0.5")
}

// One module at two versions, each with its own license file: the root's legs link the first and
// mlsinterop's the second. mlsinterop requires nothing of the root, so it selects versions of its own,
// and its test leg is the table's last, which is what a rule keeping one version per module would read.
func newVersionSkewFixture(t *testing.T, spdx string, rootVersion string, rootLicense string, mlsinteropVersion string, mlsinteropLicense string) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "tests mlsinterop linux/amd64")
	for directory, license := range map[string]string{"skewed-root": rootLicense, "skewed-mlsinterop": mlsinteropLicense} {
		fixture.writeSibling(directory+"/go.mod", "module example.com/skewed\n\ngo 1.27.3\n")
		fixture.writeSibling(directory+"/LICENSE", license)
		fixture.writeSibling(directory+"/skewed.go", "package skewed\n")
	}
	fixture.requireLocal("example.com/skewed", rootVersion, "skewed-root")
	fixture.write("skewed.go", "package sidecar\n\nimport _ \"example.com/skewed\"\n")
	fixture.edit("mlsinterop/go.mod", "go 1.27.3\n", "go 1.27.3\n\nrequire example.com/skewed "+mlsinteropVersion+"\n\nreplace example.com/skewed => ../../skewed-mlsinterop\n")
	fixture.write("mlsinterop/skewed.go", "package mlsinterop\n\nimport _ \"example.com/skewed\"\n")
	fixture.edit("dependencies.yml", "modules:\n", "modules:\n  - module: example.com/skewed\n    spdx: "+spdx+"\n    reason: two modules of this repository select it apart\n    leg: [client, test]\n")
	return fixture
}

// A relicensed release on a shipped leg is not cleared by an older copy on a test leg.
func TestDepsFailsOnARefusedLicenseAtOneVersionOfTwo(t *testing.T) {
	fixture := newVersionSkewFixture(t, "MIT", "v1.1.0", fixtureMitLicense+"Business Source License 1.1\n", "v1.0.0", fixtureMitLicense)
	wantFindings(t, fixture.open().licenseRowFindings(t), "example.com/skewed's license text has \"business source license\", at v1.1.0")
}

// An exception names one version, so another leg's version does not pass because of it.
func TestDepsFailsOnAnExceptionCoveringOneVersionOfTwo(t *testing.T) {
	licenseText := fixtureMitLicense + "The name(s) of the copyright holders shall not be used in advertising.\n"
	fixture := newVersionSkewFixture(t, "X11", "v0.0.5", licenseText, "v0.0.4", licenseText)
	fixture.settings.licenseExceptions = map[string]licenseException{
		"example.com/skewed": {version: "v0.0.4", spdx: "X11", question: "example.md"},
	}
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/skewed is X11, which §4.7 does not allow, at v0.0.5",
		"example.com/skewed's license text has \"shall not be used in advertising\", at v0.0.5")
}

// The control: two versions that each back the row pass.
func TestDepsAllowsTwoVersionsThatBothBackTheRow(t *testing.T) {
	fixture := newVersionSkewFixture(t, "MIT", "v1.1.0", fixtureMitLicense, "v1.0.0", fixtureMitLicense)
	wantFindings(t, fixture.open().licenseRowFindings(t))
}

func TestDepsFailsOnAStaleLicenseException(t *testing.T) {
	fixture := newFixture(t)
	fixture.settings.licenseExceptions = map[string]licenseException{
		"example.com/left": {version: "v1.0.0", spdx: "X11", question: "example.md"},
	}
	wantFindings(t, fixture.open().licenseExceptionFindings(t), "the license exception for example.com/left has no matching row")
}
