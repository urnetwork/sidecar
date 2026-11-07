//go:build sidecar_check

// The deps row's planted violations. Each starts from the clean fixture, so what it finds is what it
// planted. TestFixtureIsClean is that control, over every rule at once.

package check

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	wantFindings(t, repository.licenseRowFindings(t),
		"google.golang.org/protobuf says MIT, and none of its license files holds MIT's text",
		"google.golang.org/protobuf's LICENSE holds words beyond MIT")
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
		"github.com/pion/sctp says MIT, and none of its license files holds MIT's text, at v1.0.0",
		"github.com/pion/sctp's LICENSE has \"gnu general public license\", at v1.0.0",
		"github.com/pion/sctp's LICENSE holds words beyond MIT, so it is another license or a custom one: it leaves MIT at \"gnu general public license version 3 29 june 2007\", at v1.0.0")
}

// MIT's words and X11's clause are X11, not MIT, so under an MIT row the clause makes a custom
// license: it passes only where the row says X11.
func TestDepsFailsOnAnAdvertisingClauseUnderAnMitRow(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("connect/sctp/LICENSE", fixtureMitLicense+"\n"+fixtureX11Clause)
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"github.com/pion/sctp's LICENSE has \"shall not be used in advertising\", at v1.0.0",
		"github.com/pion/sctp's LICENSE holds words beyond MIT, so it is another license or a custom one: it leaves MIT at \"except as contained in this notice the name s of the above\", at v1.0.0")
}

// One module, example.com/licensed, under the row spdx, with files laid out from its top and the
// root linking each package named, "" for the module's own.
func newLicensedModuleFixture(t *testing.T, spdx string, files map[string]string, linkedPackages ...string) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("licensed/go.mod", "module example.com/licensed\n\ngo 1.27.3\n")
	for name, content := range files {
		fixture.writeSibling("licensed/"+name, content)
	}
	imports := []string{}
	for _, linkedPackage := range linkedPackages {
		directory := path.Join("licensed", linkedPackage)
		fixture.writeSibling(directory+"/package.go", "package "+path.Base(directory)+"\n")
		imports = append(imports, "import _ \""+path.Join("example.com", directory)+"\"\n")
	}
	fixture.requireLocal("example.com/licensed", "v1.0.0", "licensed")
	fixture.write("licensed.go", "package sidecar\n\n"+strings.Join(imports, ""))
	fixture.edit("dependencies.yml", "modules:\n", "modules:\n  - module: example.com/licensed\n    spdx: "+spdx+"\n    reason: a module under the license planted\n    leg: [client]\n")
	return fixture
}

// One module with an X11 row, linked by the root, under the license text given.
func newX11Fixture(t *testing.T, licenseText string) *fixture {
	t.Helper()
	return newLicensedModuleFixture(t, "X11", map[string]string{"LICENSE": licenseText}, "")
}

// The control: X11 is MIT's text plus only its no-advertising clause (QD-240), at any version.
func TestDepsAllowsAnX11Module(t *testing.T) {
	wantFindings(t, newX11Fixture(t, fixtureMitLicense+"\n"+fixtureX11Clause).open().licenseRowFindings(t))
}

// Plain MIT under an X11 row is a claim the files do not back.
func TestDepsFailsOnAnX11RowOverPlainMit(t *testing.T) {
	wantFindings(t, newX11Fixture(t, fixtureMitLicense).open().licenseRowFindings(t),
		"example.com/licensed says X11, and none of its license files holds X11's text, at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond X11, so it is another license or a custom one: it leaves X11 at the end of the file, at v1.0.0")
}

// The clause alone is not X11: the rest is MIT's text.
func TestDepsFailsOnAnX11ClauseWithoutMitsText(t *testing.T) {
	wantFindings(t, newX11Fixture(t, "Copyright (c) 2026 Example\n\n"+fixtureX11Clause).open().licenseRowFindings(t),
		"example.com/licensed says X11, and none of its license files holds X11's text, at v1.0.0",
		"example.com/licensed's LICENSE has \"shall not be used in advertising\", at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond X11")
}

// Only the clause X11 holds passes: another advertising sentence beside it is a custom term.
func TestDepsFailsOnASecondAdvertisingClauseUnderAnX11Row(t *testing.T) {
	licenseText := fixtureMitLicense + "\n" + fixtureX11Clause + "\nThis Software shall not be used in advertising for any product.\n"
	wantFindings(t, newX11Fixture(t, licenseText).open().licenseRowFindings(t),
		"example.com/licensed's LICENSE has \"shall not be used in advertising\", at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond X11, so it is another license or a custom one: it leaves X11 at \"this software shall not be used in advertising for any product\", at v1.0.0")
}

// Nor does X11's clause clear any other.
func TestDepsFailsOnAnotherClauseUnderAnX11Row(t *testing.T) {
	licenseText := fixtureMitLicense + "\n" + fixtureX11Clause + "\nThe Software shall be used for Good, not Evil.\n"
	wantFindings(t, newX11Fixture(t, licenseText).open().licenseRowFindings(t),
		"example.com/licensed's LICENSE has \"shall be used for good, not evil\", at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond X11, so it is another license or a custom one: it leaves X11 at \"the software shall be used for good not evil\", at v1.0.0")
}

// BSD-4-Clause's advertising clause, the clause that turned BSD's license into a custom one, and no
// phrase a rule might list: every word of BSD-3-Clause's text is there besides it.
func TestDepsFailsOnABsd4ClauseUnderABsd3Row(t *testing.T) {
	bsd4 := strings.Replace(fixtureBsd3License, "   * Neither the name",
		"   * All advertising materials mentioning features or use of this software\nmust display the following acknowledgement: This product includes software\ndeveloped by Example Authors.\n   * Neither the name", 1)
	fixture := newLicensedModuleFixture(t, "BSD-3-Clause", map[string]string{"LICENSE": bsd4}, "")
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/licensed says BSD-3-Clause, and none of its license files holds BSD-3-Clause's text, at v1.0.0",
		"example.com/licensed's LICENSE has \"all advertising materials mentioning features or use of this software\", at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond BSD-3-Clause, so it is another license or a custom one: it leaves BSD-3-Clause at \"all advertising materials mentioning features or use of this software must display\", at v1.0.0")
}

// A restriction in words no list holds, beside every word of MIT's text, is a custom license.
func TestDepsFailsOnAnAddedRestrictionUnderAnMitRow(t *testing.T) {
	restricted := strings.Replace(fixtureMitLicense, "THE SOFTWARE IS PROVIDED",
		"The Software may not be used by or on behalf of any military organization.\n\nTHE SOFTWARE IS PROVIDED", 1)
	fixture := newLicensedModuleFixture(t, "MIT", map[string]string{"LICENSE": restricted}, "")
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/licensed says MIT, and none of its license files holds MIT's text, at v1.0.0",
		"example.com/licensed's LICENSE holds words beyond MIT, so it is another license or a custom one: it leaves MIT at \"may not be used by or on behalf of any military organization\", at v1.0.0")
}

// A package's own license file binds that package, and the leg links it under the module's row.
func TestDepsFailsOnAGplFileBesideALinkedPackage(t *testing.T) {
	fixture := newLicensedModuleFixture(t, "MIT", map[string]string{
		"LICENSE":     fixtureMitLicense,
		"gpl/LICENSE": "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n",
	}, "", "gpl")
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/licensed's gpl/LICENSE has \"gnu general public license\", at v1.0.0",
		"example.com/licensed's gpl/LICENSE holds words beyond MIT")
}

// And so does one in a directory above it, below the module's top.
func TestDepsFailsOnAGplFileAboveALinkedPackage(t *testing.T) {
	fixture := newLicensedModuleFixture(t, "MIT", map[string]string{
		"LICENSE":             fixtureMitLicense,
		"third_party/COPYING": "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n",
	}, "", "third_party/vendored")
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/licensed's third_party/COPYING has \"gnu general public license\", at v1.0.0",
		"example.com/licensed's third_party/COPYING holds words beyond MIT")
}

// The control: a license file over a directory no leg links says nothing about what ships.
func TestDepsAllowsALicenseFileOverNothingALegLinks(t *testing.T) {
	fixture := newLicensedModuleFixture(t, "MIT", map[string]string{
		"LICENSE":        fixtureMitLicense,
		"tools/LICENSE":  "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n",
		"tools/tools.go": "package tools\n",
	}, "")
	wantFindings(t, fixture.open().licenseRowFindings(t))
}

// A license's id is shown by any of its files: a nested BSD-3-Clause file backs that id of the row.
func TestDepsAllowsARowsLicensesSpreadOverItsFiles(t *testing.T) {
	fixture := newLicensedModuleFixture(t, "MIT AND BSD-3-Clause", map[string]string{
		"LICENSE":        fixtureMitLicense,
		"snappy/LICENSE": fixtureBsd3License,
	}, "", "snappy")
	wantFindings(t, fixture.open().licenseRowFindings(t))
}

// What a module says of which file each license covers passes once someone has read it into
// licenseNotes, and only in the words they read.
func TestDepsAllowsAModulesNote(t *testing.T) {
	files := map[string]string{"LICENSE": fixtureMitLicense + "\n------\n\nFiles: snappy/*\n\n" + fixtureBsd3License}
	fixture := newLicensedModuleFixture(t, "MIT AND BSD-3-Clause", files, "")
	wantFindings(t, fixture.open().licenseRowFindings(t), "example.com/licensed's LICENSE holds words beyond MIT AND BSD-3-Clause, so it is another license or a custom one: it leaves MIT AND BSD-3-Clause at \"files snappy")
	fixture.settings.licenseNotes = map[string]licenseNote{"example.com/licensed": {why: "names what each license covers", passages: []string{"Files: snappy/*"}}}
	wantFindings(t, fixture.open().licenseRowFindings(t))
}

func TestDepsFailsOnANoteThatNoLongerMatches(t *testing.T) {
	files := map[string]string{"LICENSE": fixtureMitLicense + "\nFiles: snappy/* and everything else\n\n" + fixtureBsd3License}
	fixture := newLicensedModuleFixture(t, "MIT AND BSD-3-Clause", files, "")
	fixture.settings.licenseNotes = map[string]licenseNote{"example.com/licensed": {why: "names what each license covers", passages: []string{"Files: snappy/*"}}}
	wantFindings(t, fixture.open().licenseRowFindings(t), "it leaves MIT AND BSD-3-Clause at \"and everything else")
}

// A license's own words quoted on their own pass, as connect's file quotes MPL-2.0's sections 6 and
// 7 below its notice, and an excerpt alone does not show the license.
func TestDepsAllowsALicensesOwnExcerpt(t *testing.T) {
	texts, err := licenseTexts()
	if err != nil {
		t.Fatal(err)
	}
	excerpt, err := os.ReadFile(filepath.Join(licenseTextsDirectory, "MPL-2.0", "excerpt-sections-6-7.txt"))
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultCheckSettings()
	row := &dependencyRow{module: "example.com/licensed", spdx: "MPL-2.0"}
	file := func(text string) []*linkedLicenseFile {
		return []*linkedLicenseFile{{name: "LICENSE", top: true, words: licenseWords(text)}}
	}
	wantFindings(t, settings.licenseFindings(row, file(fixtureMplLicense+"\n"+string(excerpt)), texts))
	wantFindings(t, settings.licenseFindings(row, file(string(excerpt)), texts), "says MPL-2.0, and none of its license files holds MPL-2.0's text")
}

// Each of §4.7's licenses has a text, every text is one of §4.7's, and each text, with its parts left
// to each copy filled in, reads as that license both with and without the parts a copy may leave out.
func TestEveryAllowedLicenseHasItsText(t *testing.T) {
	texts, err := licenseTexts()
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultCheckSettings()
	for _, id := range settings.allowedLicenses {
		if !slices.ContainsFunc(texts[id], func(text *licenseText) bool { return text.backs }) {
			t.Errorf("%s has no text or notice in %s", id, licenseTextsDirectory)
		}
	}
	for id := range texts {
		if !slices.Contains(settings.allowedLicenses, id) {
			t.Errorf("%s has a text in %s, and §4.7 does not allow it", id, licenseTextsDirectory)
		}
	}
	variablePattern := regexp.MustCompile(`<<[^>]*>>`)
	optionalPattern := regexp.MustCompile(`\[\[|\]\]`)
	for id := range texts {
		for _, name := range []string{"text", "notice"} {
			data, err := os.ReadFile(filepath.Join(licenseTextsDirectory, id, name+".txt"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			filled := variablePattern.ReplaceAllString(string(data), "Example Authors")
			for _, instance := range []string{optionalPattern.ReplaceAllString(filled, ""), dropLicenseOptionals(filled)} {
				row := &dependencyRow{module: "example.com/" + id, spdx: id}
				findings := settings.licenseFindings(row, []*linkedLicenseFile{{name: name, top: true, words: licenseWords(instance)}}, texts)
				if len(findings) != 0 {
					t.Errorf("%s's %s does not read as itself: %v", id, name, findings)
				}
			}
		}
	}
}

// A text with every [[...]] part and its words taken out.
func dropLicenseOptionals(text string) string {
	result := strings.Builder{}
	depth := 0
	for index := 0; index < len(text); index++ {
		switch {
		case strings.HasPrefix(text[index:], "[["):
			depth += 1
			index += 1
		case strings.HasPrefix(text[index:], "]]") && depth > 0:
			depth -= 1
			index += 1
		case depth == 0:
			result.WriteByte(text[index])
		}
	}
	return result.String()
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
	wantFindings(t, fixture.open().licenseRowFindings(t),
		"example.com/skewed's LICENSE has \"business source license\", at v1.1.0",
		"example.com/skewed's LICENSE holds words beyond MIT, so it is another license or a custom one: it leaves MIT at \"business source license 1 1\", at v1.1.0")
}

// The control: two versions that each back the row pass.
func TestDepsAllowsTwoVersionsThatBothBackTheRow(t *testing.T) {
	fixture := newVersionSkewFixture(t, "MIT", "v1.1.0", fixtureMitLicense, "v1.0.0", fixtureMitLicense)
	wantFindings(t, fixture.open().licenseRowFindings(t))
}
