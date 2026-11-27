//go:build sidecar_check

// DESIGN-COMPUTE §15.4's and §1.2's browser legs (CSURF-M11-02), as CO-48 leaves them until DESIGN.md's fold: compute
// stays off the sidecar_http leg, the page Worker as DESIGN.md builds it today (§18.8: "the page Worker gets no
// compute"), and off sdk.wasm, the sdk's js build, whose Sidecar links no sidecar core. ur.io's page Worker moves to a
// leg of its own that links the Harness (CO-48, HARN-M13-01), whose rule HARN-M13-01 adds here; the key origin's page
// CSP gains compute's host with ur.io's Harness (HARN-M13-04), so nothing here holds the CSP free of it. Whether `ur
// native-host` relays compute to the extension was compute-plan-native-host-compute, answered no (QD-1253): it relays
// none, and nothing is built for it.
//
//   - The sidecar_http leg compiles no root file of a compute family (§3.3's prefixes, compute_placement_test.go's
//     list), read off the root package's files as the leg compiles them, but for the record's session format, which
//     every leg that reads the vault needs (computeBrowserLegRecordFiles).
//   - sdk.wasm's leg, GOOS=js with no tag as sdk/js's Makefile builds it, compiles no file of the sdk's root package
//     that declares §15.3's surface: one of its types, a method of one, or one of Sidecar's compute accessors.

package check

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The root's compute files the page Worker compiles by design: context history's session format and the hashing of a
// session body's addresses on export (CTXH-M11-01, CTXH-M11-05; DESIGN-COMPUTE §24.5, §24.9). RECORD.md section 9's
// exports run on every leg that reads the vault, the page Worker's among them, and a member's vault holds kinds 54 and
// 55 from their Harness runs on other devices: record_export.go hashes their bodies through session_export_pii.go,
// and a leg without it refuses to export one. Neither is a compute surface.
var computeBrowserLegRecordFiles = []string{"session_format.go", "session_export_pii.go"}

// §15.3's sdk surface: its types, and Sidecar's accessors that make or reach them.
var computeSdkSurfaceTypes = []string{
	"SidecarHarness", "SidecarHarnessListener", "SidecarRemoteHarnesses", "SidecarCompute", "SidecarModels",
	"SidecarEnclaves", "SidecarSshSession", "SidecarSshListener", "SidecarAgents", "SidecarCalendar", "SidecarConnections",
	"SidecarConnectHost", "SidecarListeners", "SidecarLocalInferenceHost", "SidecarAutoApprovals", "SidecarSupport",
	"SidecarSafetyClassifierHost",
}

var computeSdkSurfaceAccessors = []string{
	"NewHarness", "RemoteHarnesses", "Compute", "Models", "Enclaves", "OpenSsh", "Agents", "Calendar", "Connections",
	"SetConnectHost", "Listeners", "Disclosures", "AckDisclosure", "AckNetworkDisclosure", "SetLocalInferenceHost",
	"AutoApprovals", "Support", "SetSafetyClassifierHost",
}

// sdk.wasm's build: sdk/js's Makefile, CGO_ENABLED=0 GOOS=js GOARCH=wasm with no tag.
const (
	sdkWasmGoos   = "js"
	sdkWasmGoarch = "wasm"
)

// True for a root file name of a compute family: §3.3's prefixes and the files no prefix names.
func isComputeRootFileName(name string) bool {
	return slices.Contains(computeRootFamilyFiles, name) ||
		slices.ContainsFunc(computeRootFamilyPrefixes, func(prefix string) bool { return strings.HasPrefix(name, prefix) })
}

// The browser legs' findings: the sidecar_http leg compiling a root compute file, and sdk.wasm compiling a file of §15.3's
// sdk surface.
func (self *repository) computeBrowserLegFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(sidecarHttpTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if listed.ImportPath != self.modulePath {
				continue
			}
			for _, goFile := range slices.Concat(listed.GoFiles, listed.CgoFiles) {
				if isComputeRootFileName(goFile) && !slices.Contains(computeBrowserLegRecordFiles, goFile) {
					findings = append(findings, findingf("%s compiles %s, a compute family's, which must carry !%s: the page Worker gets no compute (DESIGN-COMPUTE §15.4, §1.2)",
						leg.name, goFile, sidecarHttpTag))
				}
			}
		}
	}
	findings = append(findings, self.sdkWasmComputeFindings()...)
	slices.Sort(findings)
	return findings
}

// sdk.wasm compiling a file of the sdk's root package that declares §15.3's surface. A sibling sdk this cannot read is
// a finding, since a rule that read nothing has not passed.
func (self *repository) sdkWasmComputeFindings() []string {
	directory := self.siblingPath("sdk")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return []string{findingf("reading sdk's root package for sdk.wasm's leg: %v", err)}
	}
	context := build.Default
	context.GOOS = sdkWasmGoos
	context.GOARCH = sdkWasmGoarch
	context.BuildTags = nil
	context.CgoEnabled = false
	findings := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, parser.SkipObjectResolution)
		if err != nil {
			findings = append(findings, findingf("reading sdk/%s for sdk.wasm's leg: %v", name, err))
			continue
		}
		declared := computeSdkSurfaceDeclared(syntax)
		if declared == "" {
			continue
		}
		match, err := context.MatchFile(directory, name)
		if err != nil {
			findings = append(findings, findingf("matching sdk/%s for sdk.wasm's leg: %v", name, err))
			continue
		}
		if match {
			findings = append(findings, findingf("sdk.wasm compiles sdk/%s, which declares §15.3's %s and must carry !js: sdk.wasm links no compute (DESIGN-COMPUTE §15.4, owner decision 197)",
				name, declared))
		}
	}
	return findings
}

// The first piece of §15.3's sdk surface a file declares, "" for none: one of its types, a method of one, or one of
// Sidecar's compute accessors.
func computeSdkSurfaceDeclared(syntax *ast.File) string {
	if syntax.Name.Name != "sdk" {
		return ""
	}
	for _, declaration := range syntax.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok && slices.Contains(computeSdkSurfaceTypes, typeSpec.Name.Name) {
					return typeSpec.Name.Name
				}
			}
		case *ast.FuncDecl:
			if typed.Recv == nil || len(typed.Recv.List) == 0 {
				continue
			}
			receiver := typed.Recv.List[0].Type
			if star, ok := receiver.(*ast.StarExpr); ok {
				receiver = star.X
			}
			identifier, ok := receiver.(*ast.Ident)
			if !ok {
				continue
			}
			switch {
			case slices.Contains(computeSdkSurfaceTypes, identifier.Name):
				return identifier.Name + "." + typed.Name.Name
			case identifier.Name == "Sidecar" && slices.Contains(computeSdkSurfaceAccessors, typed.Name.Name):
				return "Sidecar." + typed.Name.Name
			}
		}
	}
	return ""
}

// The browser legs over this checkout and its sibling sdk.
func TestComputeStaysOffTheSidecarHttpLeg(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "compute browser legs", repository.computeBrowserLegFindings(t))
}

// A root compute file with no !sidecar_http is compiled into the page Worker and found; the session format's files
// are not.
func TestComputeBrowserLegFailsOnAComputeFileWithoutTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("harness_planted.go", "//go:build !ios_extension\n\npackage sidecar\n")
	fixture.write("acl_compute_settings.go", "package sidecar\n")
	fixture.write("session_format.go", "//go:build !ios_extension\n\npackage sidecar\n")
	wantFindings(t, fixture.open().computeBrowserLegFindings(t),
		"sidecar_http js/wasm compiles acl_compute_settings.go, a compute family's, which must carry !sidecar_http",
		"sidecar_http js/wasm compiles harness_planted.go, a compute family's, which must carry !sidecar_http")
}

// Its twin: the tag keeps each off the leg, and a root file of no compute family stays on it.
func TestComputeBrowserLegAllowsAComputeFileWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.write("harness_planted.go", "//go:build !ios_extension && !sidecar_http\n\npackage sidecar\n")
	fixture.write("infer_planted_js.go", "//go:build !ios_extension && !sidecar_http\n\npackage sidecar\n")
	fixture.write("record_planted.go", "package sidecar\n")
	wantFindings(t, fixture.open().computeBrowserLegFindings(t))
}

// An sdk file declaring §15.3's surface with no !js is compiled into sdk.wasm and found, whichever piece it declares;
// with !js, or declaring none, it is not.
func TestComputeBrowserLegFailsOnAnSdkComputeShellOnTheJsLeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(sidecarHttpLegName)
	fixture.writeSibling("sdk/sidecar_harness.go", "//go:build !ios_extension\n\npackage sdk\n\ntype SidecarHarness struct{}\n")
	fixture.writeSibling("sdk/sidecar_planted.go", "package sdk\n\ntype Sidecar struct{}\n\nfunc (self *Sidecar) Support() {}\n")
	fixture.writeSibling("sdk/sidecar_listeners.go", "//go:build !ios_extension && !js\n\npackage sdk\n\ntype SidecarListeners struct{}\n")
	fixture.writeSibling("sdk/sidecar_mail_planted.go", "package sdk\n\nfunc (self *Sidecar) GetMail() {}\n")
	wantFindings(t, fixture.open().computeBrowserLegFindings(t),
		"sdk.wasm compiles sdk/sidecar_harness.go, which declares §15.3's SidecarHarness and must carry !js",
		"sdk.wasm compiles sdk/sidecar_planted.go, which declares §15.3's Sidecar.Support and must carry !js")
}
