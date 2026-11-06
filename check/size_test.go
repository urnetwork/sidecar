//go:build sidecar_check

// make size (§4.9, §18.10): what the device role adds to the ios_extension leg, and how big the
// sidecar_http js leg is, both unstripped. These hold the verdicts and the measuring; make check
// proves the verdicts, and make size, under the sidecar_size tag, runs the builds (size_gate_test.go).
//
// A program that only imports a package links its init functions and little else, because the
// linker drops whatever nothing reaches. A blank import of device would measure almost nothing, and
// would keep measuring it however much device grew. So each program here keeps a package's whole
// exported surface alive by naming it, and the size is what that surface really costs. It names
// methods directly rather than reaching them through reflect, which would turn the linker's method
// pruning off and measure a binary nobody ships (§18.10).

package check

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// §18.10: fails when the device role adds over the limit, so exactly the limit passes.
func (self *checkSettings) iosExtensionSizeFindings(baselineByteCount int64, withSidecarByteCount int64) []string {
	addedByteCount := withSidecarByteCount - baselineByteCount
	if addedByteCount > self.iosExtensionAddedMaxByteCount {
		return []string{findingf("the device role adds %d B to the ios_extension leg, over the %d B limit (D-SDK-20)", addedByteCount, self.iosExtensionAddedMaxByteCount)}
	}
	return nil
}

// §18.10's goal and miss rule. Within the goal passes. Past it, the leg may ship only under the
// sdk.wasm gate and only with the slip recorded, which is Gn-in's to do at M4's entry and this
// file's to read; a build past the miss gate fails regardless, since §18.10 leaves nothing above it
// but never a hosted sidecar.
func (self *checkSettings) sidecarHttpSizeFindings(byteCount int64) []string {
	if byteCount <= self.sidecarHttpGoalByteCount {
		return nil
	}
	if byteCount > self.sidecarHttpMissByteCount {
		return []string{findingf("the sidecar_http js leg is %d B unstripped, over the %d B sdk.wasm gate that §18.10's miss rule leaves", byteCount, self.sidecarHttpMissByteCount)}
	}
	if !self.sidecarHttpGoalSlipRecorded {
		return []string{findingf("the sidecar_http js leg is %d B unstripped, over the %d B goal, and no Gn-in has recorded the slip (D-SDK-19)", byteCount, self.sidecarHttpGoalByteCount)}
	}
	return nil
}

// One package's exported surface on a leg, as expressions naming it under alias. Generic functions
// and methods of generic types have no value to name until instantiated, so they are left out.
func (self *repository) exportedSurface(leg *buildLeg, importPath string, alias string) ([]string, error) {
	directory, err := self.legDirectory(leg)
	if err != nil {
		return nil, err
	}
	arguments := []string{"list", "-json=Dir,GoFiles"}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	output, err := runGo(directory, leg.environment(), append(arguments, importPath)...)
	if err != nil {
		return nil, err
	}
	listed := &listedPackage{}
	if err := json.Unmarshal(output, listed); err != nil {
		return nil, fmt.Errorf("reading go list for %s: %w", importPath, err)
	}
	expressions := []string{}
	fileSet := token.NewFileSet()
	for _, goFile := range listed.GoFiles {
		syntax, err := parser.ParseFile(fileSet, filepath.Join(listed.Dir, goFile), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, decl := range syntax.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if !typed.Name.IsExported() || typed.Type.TypeParams != nil {
					continue
				}
				if typed.Recv == nil {
					expressions = append(expressions, alias+"."+typed.Name.Name)
					continue
				}
				receiver := typed.Recv.List[0].Type
				if star, ok := receiver.(*ast.StarExpr); ok {
					receiver = star.X
				}
				if name, ok := receiver.(*ast.Ident); ok && name.IsExported() {
					expressions = append(expressions, "(*"+alias+"."+name.Name+")."+typed.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch specTyped := spec.(type) {
					case *ast.TypeSpec:
						if specTyped.Name.IsExported() && specTyped.TypeParams == nil {
							expressions = append(expressions, "(*"+alias+"."+specTyped.Name.Name+")(nil)")
						}
					case *ast.ValueSpec:
						if typed.Tok != token.VAR {
							continue
						}
						for _, name := range specTyped.Names {
							if name.IsExported() {
								expressions = append(expressions, "&"+alias+"."+name.Name)
							}
						}
					}
				}
			}
		}
	}
	slices.Sort(expressions)
	return expressions, nil
}

// Source for a program keeping the whole exported surface of each package alive.
func (self *repository) sizeProbeSource(leg *buildLeg, importPaths []string) (string, error) {
	source := strings.Builder{}
	source.WriteString("package main\n\nimport (\n")
	keptExpressions := []string{}
	for index, importPath := range importPaths {
		alias := fmt.Sprintf("kept%d", index)
		expressions, err := self.exportedSurface(leg, importPath, alias)
		if err != nil {
			return "", err
		}
		if len(expressions) == 0 {
			// a package with nothing exported is imported for its init alone
			alias = "_"
		}
		fmt.Fprintf(&source, "\t%s %q\n", alias, importPath)
		keptExpressions = append(keptExpressions, expressions...)
	}
	source.WriteString(")\n\nvar keep = []any{\n")
	for _, expression := range keptExpressions {
		fmt.Fprintf(&source, "\t%s,\n", expression)
	}
	source.WriteString("}\n\nfunc main() {\n\tprintln(len(keep))\n}\n")
	return source.String(), nil
}

// Builds a program over importPaths on the leg, unstripped, and returns its size. The program lives
// in an overlay inside the leg's module, so its build list is the leg's and the tree stays untouched.
func (self *repository) measureSizeProbe(t testing.TB, leg *buildLeg, environment []string, importPaths []string) int64 {
	t.Helper()
	directory, err := self.legDirectory(leg)
	if err != nil {
		t.Fatal(err)
	}
	source, err := self.sizeProbeSource(leg, importPaths)
	if err != nil {
		t.Fatal(err)
	}
	probeDirectory := t.TempDir()
	probePath := filepath.Join(probeDirectory, "main.go")
	if err := os.WriteFile(probePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := writeOverlay(t, probeDirectory, filepath.Join(directory, "checksizeprobe", "main.go"), probePath)
	binaryPath := filepath.Join(probeDirectory, "probe")
	arguments := []string{"build", "-overlay=" + overlayPath, "-o", binaryPath}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	if _, err := runGo(directory, environment, append(arguments, "./checksizeprobe")...); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// The leg's environment with the C toolchain ios needs: the linker refuses ios/arm64 without cgo,
// so a build needs Xcode's clang, and a host without it fails the gate rather than skipping it.
func (self *repository) iosBuildEnvironment(leg *buildLeg) ([]string, error) {
	xcrun := func(arguments ...string) (string, error) {
		output, err := exec.Command("xcrun", append([]string{"--sdk", "iphoneos"}, arguments...)...).Output()
		if err != nil {
			return "", fmt.Errorf("xcrun %v: %w", arguments, err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	clang, err := xcrun("--find", "clang")
	if err != nil {
		return nil, err
	}
	sdkPath, err := xcrun("--show-sdk-path")
	if err != nil {
		return nil, err
	}
	flags := "-isysroot " + sdkPath + " -arch arm64 -miphoneos-version-min=" + self.settings.iosMinimumVersion
	return append(leg.environment(), "CC="+clang, "CGO_CFLAGS="+flags, "CGO_LDFLAGS="+flags), nil
}

// The packages the device role brings to the ios_extension leg (§4.9): protocol/bridge, and device
// once it exists.
func (self *repository) deviceRolePackages(t testing.TB, leg *buildLeg) []string {
	t.Helper()
	patterns, err := self.legPatterns(leg)
	if err != nil {
		t.Fatal(err)
	}
	importPaths := []string{}
	for _, pattern := range patterns {
		importPaths = append(importPaths, self.modulePath+"/"+strings.TrimPrefix(pattern, "./"))
	}
	return importPaths
}

// What the iOS extension links before sidecar is in it: connect's API. Kept whole on both sides of
// the comparison, because sdk's extension uses it with or without sidecar, and a call from device
// into connect adds nothing the extension does not already carry.
func (self *repository) iosExtensionBaselinePackages(t testing.TB) []string {
	t.Helper()
	packages := []string{}
	for _, require := range self.module(t, ".").file.Require {
		if firstPartyBase(require.Path) == connectBasePath {
			packages = append(packages, require.Path, require.Path+"/protocol")
		}
	}
	return packages
}

// Measures the ios_extension leg: the baseline, then the baseline with the device role.
func (self *repository) measureIosExtension(t testing.TB) (baselineByteCount int64, withSidecarByteCount int64) {
	t.Helper()
	leg := self.leg(t, "gomobile ios/arm64 extension")
	environment, err := self.iosBuildEnvironment(leg)
	if err != nil {
		t.Fatalf("the ios_extension gate needs Xcode: %v", err)
	}
	baselinePackages := self.iosExtensionBaselinePackages(t)
	baselineByteCount = self.measureSizeProbe(t, leg, environment, baselinePackages)
	withSidecarByteCount = self.measureSizeProbe(t, leg, environment, slices.Concat(baselinePackages, self.deviceRolePackages(t, leg)))
	return baselineByteCount, withSidecarByteCount
}

// Measures the sidecar_http js leg: the root and protocol, which §18.10's main imports. That main,
// sdk/js/cmd/sidecarwasm, belongs to sdk and links less than this whole surface, so this reads high.
func (self *repository) measureSidecarHttp(t testing.TB) int64 {
	t.Helper()
	leg := self.leg(t, "sidecar_http js/wasm")
	return self.measureSizeProbe(t, leg, leg.environment(), []string{self.modulePath, self.modulePath + "/protocol", self.modulePath + "/protocol/bridge"})
}

// The verdicts at their edges: §18.10 fails over the limit, so the limit itself passes.
func TestSizeVerdictsHoldTheirLimits(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.iosExtensionSizeFindings(10*1024*1024, 10*1024*1024))
	wantFindings(t, settings.iosExtensionSizeFindings(10*1024*1024, 11*1024*1024))
	wantFindings(t, settings.sidecarHttpSizeFindings(41943040))
	if settings.sidecarHttpGoalByteCount != 41943040 || settings.sidecarHttpMissByteCount != 74965628 || settings.iosExtensionAddedMaxByteCount != 1048576 {
		t.Errorf("the settings stray from §18.10: %d, %d, %d", settings.sidecarHttpGoalByteCount, settings.sidecarHttpMissByteCount, settings.iosExtensionAddedMaxByteCount)
	}
}

func TestSizeFailsOnADeviceRoleOverItsLimit(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.iosExtensionSizeFindings(10*1024*1024, 11*1024*1024+1), "adds 1048577 B to the ios_extension leg")
}

// Past the goal fails until a Gn-in records the slip, and the record is what lets it through.
func TestSizeFailsOnSidecarHttpOverItsGoal(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.sidecarHttpSizeFindings(41943041), "no Gn-in has recorded the slip")
	settings.sidecarHttpGoalSlipRecorded = true
	wantFindings(t, settings.sidecarHttpSizeFindings(41943041))
	wantFindings(t, settings.sidecarHttpSizeFindings(74965628))
}

// Nothing goes past the sdk.wasm gate: §18.10's miss rule is the last line, recorded or not.
func TestSizeFailsOnSidecarHttpOverItsMissGate(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.sidecarHttpSizeFindings(74965629), "over the 74965628 B sdk.wasm gate")
	settings.sidecarHttpGoalSlipRecorded = true
	wantFindings(t, settings.sidecarHttpSizeFindings(74965629), "over the 74965628 B sdk.wasm gate")
}

// Names every exported kind, and no generic, unexported or constant one.
func TestSizeProbeKeepsTheWholeExportedSurface(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", `package device

type Bridge struct{}

func (self *Bridge) Open() {}

func (self Bridge) Close() {}

func (self *Bridge) hidden() {}

func NewBridge() *Bridge { return nil }

func Generic[T any]() {}

type Box[T any] struct{}

func (self *Box[T]) Get() {}

type Reader interface{ Read() }

var Table = map[string]int{}

const Limit = 1

func hidden() {}
`)
	repository := fixture.open()
	surface, err := repository.exportedSurface(repository.leg(t, "gomobile ios/arm64 extension"), repository.modulePath+"/device", "kept")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"&kept.Table", "(*kept.Bridge)(nil)", "(*kept.Bridge).Close", "(*kept.Bridge).Open", "(*kept.Reader)(nil)", "kept.NewBridge"}
	if !slices.Equal(surface, want) {
		t.Errorf("surface %v, want %v", surface, want)
	}
}
