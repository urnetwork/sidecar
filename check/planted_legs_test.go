//go:build sidecar_check

// The legs row's planted violations, and the proof that a leg reads its own configuration.

package check

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

const (
	iosExtensionLegName = "gomobile ios/arm64 extension"
	macExtensionLegName = "gomobile macos/arm64 extension"
	sidecarHttpLegName  = "sidecar_http js/wasm"
)

func TestLegsFailsOnIosExtensionLinkingTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName)
	fixture.write("device/device.go", "package device\n\nimport _ \"@module@\"\n")
	wantFindings(t, fixture.open().iosExtensionFindings(t), iosExtensionLegName+" links @module@")
}

func TestLegsFailsOnIosExtensionLinkingProtocol(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName)
	fixture.write("device/device.go", "package device\n\nimport _ \"@module@/protocol\"\n")
	wantFindings(t, fixture.open().iosExtensionFindings(t), iosExtensionLegName+" links @module@/protocol")
}

// §4.9: device/ and protocol/bridge only.
func TestLegsFailsOnIosExtensionLinkingAnythingElseOfOurs(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName)
	fixture.write("device/device.go", "package device\n\nimport _ \"@module@/mcp\"\n")
	fixture.write("mcp/mcp.go", "package mcp\n")
	wantFindings(t, fixture.open().iosExtensionFindings(t), iosExtensionLegName+" links @module@/mcp")
}

// sdk/build/Makefile:153 builds the extension's macOS slices too; a file only they compile is seen.
func TestLegsFailsOnTheMacExtensionSlice(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	fixture.write("device/device.go", "package device\n")
	fixture.write("device/device_mac.go", "//go:build darwin && !ios\n\npackage device\n\nimport _ \"@module@\"\n")
	wantFindings(t, fixture.open().iosExtensionFindings(t), macExtensionLegName+" links @module@")
}

// protocol/bridge and device share the root's and protocol's path prefix, and are what the leg is
// for: exact matches, and the leg picks device/ up by its landing.
func TestLegsAllowIosExtensionItsOwnPackages(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName)
	fixture.write("device/device.go", "package device\n\nimport (\n\t_ \"@connect@\"\n\t_ \"@module@/protocol/bridge\"\n)\n")
	repository := fixture.open()
	wantFindings(t, repository.iosExtensionFindings(t))
	closure := repository.closure(t, repository.legs[0])
	if !slices.ContainsFunc(closure, func(listed *listedPackage) bool { return listed.ImportPath == repository.modulePath+"/device" }) {
		t.Errorf("the leg's closure lacks device")
	}
}

func TestLegsFailsOnSidecarHttpLinkingConnect(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.edit("connect_require.go", "//go:build !sidecar_http\n\n", "")
	wantFindings(t, fixture.open().sidecarHttpFindings(t),
		"links github.com/pion/sctp",
		"links @connect@",
		"links gvisor.dev/gvisor/pkg/tcpip")
}

func TestLegsFailsOnSidecarHttpLinkingGvisor(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("planted.go", "//go:build sidecar_http\n\npackage sidecar\n\nimport _ \"gvisor.dev/gvisor/pkg/tcpip\"\n")
	wantFindings(t, fixture.open().sidecarHttpFindings(t), "links gvisor.dev/gvisor/pkg/tcpip")
}

// §4.7 reads the leg over the root and protocol, and the root need not import protocol yet.
func TestLegsFailsOnSidecarHttpThroughProtocol(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("protocol/planted.go", "package protocol\n\nimport _ \"@connect@/protocol\"\n")
	findings := fixture.open().sidecarHttpFindings(t)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.HasSuffix(finding, fixtureTokens.Replace("links @connect@/protocol"))
	}) {
		t.Errorf("findings %v lack connect/protocol", findings)
	}
}

func TestLegsFailsOnAHostFileWithoutTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("host_service.go", "package sidecar\n")
	wantFindings(t, fixture.open().hostFileFindings(t), "compiles host_service.go, which must carry !sidecar_http")
}

func TestLegsAllowsAHostFileWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("host_service.go", "//go:build !sidecar_http\n\npackage sidecar\n")
	wantFindings(t, fixture.open().hostFileFindings(t))
}

// Plants one import behind a constraint and reads the pruning rule on ios, android and js legs.
func plantPruningBreaker(t *testing.T, constraintLine string, importPath string) []string {
	t.Helper()
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "gomobile ios/arm64", "gomobile android/arm64", "js/wasm", sidecarHttpLegName)
	fixture.write("planted.go", "//go:build "+constraintLine+"\n\npackage sidecar\n\nimport _ \""+importPath+"\"\n")
	return fixture.open().pruningFindings(t)
}

// net/rpc brings both template packages with it (sdk/build/mobile_method_pruning_test.go:16).
func TestLegsFailsOnNetRpcOnIos(t *testing.T) {
	wantFindings(t, plantPruningBreaker(t, "ios", "net/rpc"),
		"gomobile ios/arm64 links text/template/parse",
		"gomobile ios/arm64 links text/template",
		"gomobile ios/arm64 links html/template",
		"gomobile ios/arm64 links net/rpc")
}

func TestLegsFailsOnTextTemplateOnAndroid(t *testing.T) {
	wantFindings(t, plantPruningBreaker(t, "android", "text/template"),
		"gomobile android/arm64 links text/template/parse",
		"gomobile android/arm64 links text/template")
}

func TestLegsFailsOnHtmlTemplateOnJs(t *testing.T) {
	findings := plantPruningBreaker(t, "js && sidecar_http", "html/template")
	for _, want := range []string{"links html/template", "links text/template"} {
		if !slices.ContainsFunc(findings, func(finding string) bool { return strings.HasSuffix(finding, want) }) {
			t.Errorf("findings %v lack %q", findings, want)
		}
	}
}

// A package under a breaker counts: net/rpc/jsonrpc pulls the same weight.
func TestLegsFailsOnATemplateSubpackage(t *testing.T) {
	wantFindings(t, plantPruningBreaker(t, "ios", "net/rpc/jsonrpc"),
		"gomobile ios/arm64 links text/template/parse",
		"gomobile ios/arm64 links text/template",
		"gomobile ios/arm64 links html/template",
		"gomobile ios/arm64 links net/rpc",
		"gomobile ios/arm64 links net/rpc/jsonrpc")
}

// The row names ios, android and js. A desktop leg may link these.
func TestLegsAllowTemplatesOnADesktopLeg(t *testing.T) {
	wantFindings(t, plantPruningBreaker(t, "linux && !android", "text/template"))
}

func TestLegsFailsOnADynamicReflectLookup(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\nimport \"reflect\"\n\nfunc planted(value any, name string) {\n\treflect.ValueOf(value).MethodByName(name)\n}\n")
	wantFindings(t, fixture.open().reflectLookupFindings(t), "planted.go:6: a dynamic reflect lookup, MethodByName")
}

// A marker package behind each part of a leg's configuration: a runner that dropped GOOS, a tag,
// cgo or -test would read the wrong set, and the caller's own environment must not reach the leg.
func TestLegsReadTheirOwnBuildConfiguration(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOOS", "plan9")
	t.Setenv("GOFLAGS", "-tags=sdk_mobile_bind")
	fixture := newFixture(t)
	fixture.writeSibling("marks/go.mod", "module example.com/marks\n\ngo 1.27.3\n")
	for _, mark := range []string{"browser", "mobile", "native", "testonly"} {
		fixture.writeSibling("marks/"+mark+"/"+mark+".go", "package "+mark+"\n")
	}
	fixture.requireLocal("example.com/marks", "v1.0.0", "marks")
	fixture.write("mark_js.go", "//go:build js\n\npackage sidecar\n\nimport _ \"example.com/marks/browser\"\n")
	fixture.write("mark_mobile.go", "//go:build sdk_mobile_bind\n\npackage sidecar\n\nimport _ \"example.com/marks/mobile\"\n")
	fixture.write("mark_cgo.go", "//go:build cgo\n\npackage sidecar\n\nimport _ \"example.com/marks/native\"\n")
	fixture.write("mark_test.go", "package sidecar\n\nimport _ \"example.com/marks/testonly\"\n")
	repository := fixture.open()
	for _, c := range []struct {
		name string
		want []string
	}{
		{name: "root linux/amd64", want: []string{}},
		{name: "js/wasm", want: []string{"example.com/marks/browser"}},
		{name: "cgo linux/amd64", want: []string{"example.com/marks/native"}},
		{name: "gomobile android/arm64", want: []string{"example.com/marks/mobile", "example.com/marks/native"}},
		{name: "tests linux/amd64", want: []string{"example.com/marks/testonly"}},
		{name: "tests js/wasm", want: []string{"example.com/marks/browser", "example.com/marks/testonly"}},
	} {
		found := []string{}
		for _, listed := range repository.closure(t, repository.leg(t, c.name)) {
			if strings.HasPrefix(listed.ImportPath, "example.com/marks/") {
				found = append(found, listed.ImportPath)
			}
		}
		slices.Sort(found)
		if !slices.Equal(found, c.want) {
			t.Errorf("%s: found %v, want %v", c.name, found, c.want)
		}
	}
}

// A leg that lists nothing has not passed: neither a module this checkout lacks, nor patterns that
// match nothing, nor a pattern go list resolved to something else.
func TestLegsFailOnAClosureThatCannotBeRead(t *testing.T) {
	fixture := newFixture(t)
	repository := fixture.open()
	for _, leg := range []*buildLeg{
		{name: "absent module", moduleName: "absent", goos: "linux", goarch: "amd64", patterns: allPatterns, class: classClient},
		{name: "no pattern exists", moduleName: ".", goos: "linux", goarch: "amd64", patterns: []string{"./device"}, class: classClient},
	} {
		if packages, err := repository.listLeg(leg); err == nil {
			t.Errorf("%s listed %d packages", leg.name, len(packages))
		}
	}
	fixture.write("protocol/bridge/planted.go", "this is not Go\n")
	if packages, err := fixture.open().listLeg(fixture.legs[0]); err == nil {
		t.Errorf("a package that does not parse listed %d packages", len(packages))
	}
}

// The engine legs are the one place an empty closure is right, until the first engine lands.
func TestLegsPickUpAnEngineWhenItLands(t *testing.T) {
	fixture := newFixture(t)
	repository := fixture.open()
	if closure := repository.closure(t, repository.leg(t, "engines linux/amd64")); len(closure) != 0 {
		t.Errorf("the engine leg holds %d packages before any engine", len(closure))
	}
	fixture.write("evsservice/engine.go", "package evsservice\n\nimport _ \"@module@\"\n")
	repository = fixture.open()
	closure := repository.closure(t, repository.leg(t, "engines linux/amd64"))
	if !slices.ContainsFunc(closure, func(listed *listedPackage) bool { return listed.ImportPath == repository.modulePath+"/evsservice" }) {
		t.Errorf("the engine leg's closure lacks the engine")
	}
}

func TestLegsFailsOnAnSdkLegWithNoLegHere(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("sdk/dependency_boundary_test.go", `package sdk

var messagingBoundaryLegs = []messagingBoundaryLeg{
	{name: "root linux/amd64", environment: []string{"GOOS=linux", "GOARCH=amd64"}, patterns: []string{"./..."}},
	{name: "new freebsd", environment: []string{"GOOS=freebsd", "GOARCH=amd64"}, patterns: []string{"./..."}},
	{name: "wrong cgo", environment: []string{"GOOS=js", "GOARCH=wasm", "CGO_ENABLED=1"}, patterns: []string{"./..."}},
	{name: "new tag", environment: []string{"GOOS=linux", "GOARCH=amd64"}, tags: "sdk_new_tag"},
}
`)
	wantFindings(t, fixture.open().sdkLegRowFindings(t),
		"sdk's leg \"new freebsd\" has no leg here",
		"sdk's leg \"wrong cgo\" has no leg here",
		"sdk's leg \"new tag\" has no leg here")
}

// sdk's file is sdk's to change, and the mirror fails rather than pass when it cannot read the table.
func TestLegsFailsOnAnSdkTableItCannotFind(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("sdk/dependency_boundary_test.go", "package sdk\n\nvar renamedLegs = []int{}\n")
	wantFindings(t, fixture.open().sdkLegRowFindings(t), "no longer declares messagingBoundaryLegs")
}

// A body that does not compile, behind whatever constraint a test plants it with.
const plantedUncompiledBody = "func planted() int {\n\treturn undeclared\n}\n"

// The compile rule over the fixture's legs. Each finding must hold the planted error in the planted
// file, so a leg failing on anything else does not stand in for the plant.
func plantedCompileFindings(t *testing.T, fixture *fixture, plantedFile string) []string {
	t.Helper()
	findings := fixture.open().legCompileFindings(t)
	for _, finding := range findings {
		if !strings.Contains(finding, plantedFile+":") || !strings.Contains(finding, "undefined: undeclared") {
			t.Errorf("a finding lacks the error planted in %s:\n%s", plantedFile, finding)
		}
	}
	return findings
}

// Every go test make check runs is on this host's system, so only a compile sees the windows legs.
func TestLegsFailsOnAFileOnlyWindowsCompiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "root windows/amd64", "tests windows/amd64")
	fixture.write("planted_windows.go", "package sidecar\n\n"+plantedUncompiledBody)
	wantFindings(t, plantedCompileFindings(t, fixture, "planted_windows.go"),
		"root windows/amd64 does not compile",
		"tests windows/amd64 does not compile")
}

// A test leg compiles its tests, and the shipped leg beside it builds none.
func TestLegsFailsOnATestOnlyJsCompiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("js/wasm", "tests js/wasm")
	fixture.write("planted_js_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc TestPlanted(t *testing.T) {\n\t_ = undeclared\n}\n")
	wantFindings(t, plantedCompileFindings(t, fixture, "planted_js_test.go"), "tests js/wasm does not compile")
}

// The CLI's six release targets each compile, so a file only one of them builds is caught there.
func TestLegsFailsOnACliFileOnlyWindowsArm64Compiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli windows/amd64", "cli windows/arm64")
	fixture.write("cli/planted_windows_arm64.go", "package main\n\n"+plantedUncompiledBody)
	wantFindings(t, plantedCompileFindings(t, fixture, "planted_windows_arm64.go"), "cli windows/arm64 does not compile")
}

// The page Worker's leg builds files no other leg does.
func TestLegsFailsOnAPageWorkerFileThatDoesNotCompile(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("js/wasm", sidecarHttpLegName)
	fixture.write("planted_http.go", "//go:build sidecar_http\n\npackage sidecar\n\n"+plantedUncompiledBody)
	wantFindings(t, plantedCompileFindings(t, fixture, "planted_http.go"), sidecarHttpLegName+" does not compile")
}

// server runs the engines on arm64 as well as amd64.
func TestLegsFailsOnAnEngineFileOnlyArm64Compiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("engines linux/amd64", "engines linux/arm64")
	fixture.write("evsservice/engine.go", "package evsservice\n\nimport _ \"@module@\"\n")
	fixture.write("evsservice/engine_arm64.go", "package evsservice\n\n"+plantedUncompiledBody)
	wantFindings(t, plantedCompileFindings(t, fixture, "engine_arm64.go"), "engines linux/arm64 does not compile")
}

// A cgo leg compiles on a host with its system's C toolchain, and fails there. Each other one is
// reported as not compiled, never passed in silence, so the rule switched off fails this on any host.
func TestLegsFailsOnACgoFileThisHostCompiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cgo darwin/arm64", "gomobile ios/arm64", "cgo linux/amd64", "gomobile android/arm64")
	fixture.write("planted_cgo.go", "//go:build cgo\n\npackage sidecar\n\n"+plantedUncompiledBody)
	repository := fixture.open()
	reports := []string{}
	repository.report = func(format string, arguments ...any) {
		reports = append(reports, findingf(format, arguments...))
	}
	findings := repository.legCompileFindings(t)
	wants := []string{}
	for _, leg := range repository.legs {
		if leg.compilesOn(runtime.GOOS, runtime.GOARCH) {
			wants = append(wants, leg.name+" does not compile")
			continue
		}
		if !slices.ContainsFunc(reports, func(line string) bool { return strings.HasPrefix(line, leg.name+" is not compiled") }) {
			t.Errorf("%s went uncompiled and unreported: %v", leg.name, reports)
		}
	}
	slices.Sort(wants)
	wantFindings(t, findings, wants...)
	for _, finding := range findings {
		if !strings.Contains(finding, "planted_cgo.go:") {
			t.Errorf("a finding lacks the planted file:\n%s", finding)
		}
	}
}
