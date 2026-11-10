//go:build sidecar_check

// make size (§4.9, §18.10, DESIGN-DETAILS 4.2.3): what the forwarding leg adds to the ios_extension leg,
// stripped as sdk/build/Makefile ships it, and how big the sidecar_http js leg is, unstripped as §18.10's
// goal reads. These hold the verdicts and the measuring; make check proves the verdicts, and make size,
// under the sidecar_size tag, runs the builds (size_gate_test.go).
//
// A program that only imports a package links its init functions and little else, because the
// linker drops whatever nothing reaches. A blank import of device would measure almost nothing, and
// would keep measuring it however much device grew. So each program here keeps a package's whole
// exported surface alive by naming it, and the size is what that surface really costs. It names
// methods directly rather than reaching them through reflect, which would turn the linker's method
// pruning off and measure a binary nobody ships (§18.10). Of the root the ios_extension probe keeps
// only what the VPN component calls, the exported surface of bridge_forward*.go (BRIDGE-M8-05), and
// imports the rest for its init functions and package variables, which no dead-code pass removes
// and which the leg's tags are there to bound.

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
	"strconv"
	"strings"
	"testing"
)

// DESIGN-DETAILS 4.2.3: fails when the forwarding leg adds over the limit, so exactly the limit passes. The limit is
// proposed until question details-4-ios-forwarding-budget is answered, and the finding says so.
func (self *checkSettings) iosExtensionSizeFindings(baselineByteCount int64, withSidecarByteCount int64) []string {
	addedByteCount := withSidecarByteCount - baselineByteCount
	if addedByteCount > self.iosExtensionAddedMaxByteCount {
		return []string{findingf("the forwarding leg adds %d B to the ios_extension leg, stripped, over the %d B limit "+
			"(DESIGN-DETAILS 4.2.3, D-SDK-20; proposed until question details-4-ios-forwarding-budget is answered)",
			addedByteCount, self.iosExtensionAddedMaxByteCount)}
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

// One package a size probe imports, and of its files the ones whose exported surface it keeps alive; nil keeps
// every file's.
type sizeProbePackage struct {
	importPath string
	keepsFile  func(goFile string) bool
}

// The package with its whole exported surface kept.
func wholeSizeProbePackage(importPath string) sizeProbePackage {
	return sizeProbePackage{importPath: importPath}
}

// One package's exported surface on a leg, as expressions naming it under alias, from the files keepsFile takes, or
// every file when it is nil. Generic functions and methods of generic types have no value to name until
// instantiated, so they are left out.
func (self *repository) exportedSurface(leg *buildLeg, importPath string, alias string, keepsFile func(goFile string) bool) ([]string, error) {
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
		if keepsFile != nil && !keepsFile(goFile) {
			continue
		}
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

// Source for a program keeping the exported surface of each package alive, as its sizeProbePackage says.
func (self *repository) sizeProbeSource(leg *buildLeg, packages []sizeProbePackage) (string, error) {
	source := strings.Builder{}
	source.WriteString("package main\n\nimport (\n")
	keptExpressions := []string{}
	for index, probePackage := range packages {
		alias := fmt.Sprintf("kept%d", index)
		expressions, err := self.exportedSurface(leg, probePackage.importPath, alias, probePackage.keepsFile)
		if err != nil {
			return "", err
		}
		if len(expressions) == 0 {
			// a package with nothing kept is imported for its init alone
			alias = "_"
		}
		fmt.Fprintf(&source, "\t%s %q\n", alias, probePackage.importPath)
		keptExpressions = append(keptExpressions, expressions...)
	}
	source.WriteString(")\n\nvar keep = []any{\n")
	for _, expression := range keptExpressions {
		fmt.Fprintf(&source, "\t%s,\n", expression)
	}
	source.WriteString("}\n\nfunc main() {\n\tprintln(len(keep))\n}\n")
	return source.String(), nil
}

// Builds a program over packages on the leg with linkerFlags, none for an unstripped build, and returns its size. The
// program lives in an overlay inside the leg's module, so its build list is the leg's and the tree stays untouched.
func (self *repository) measureSizeProbe(t testing.TB, leg *buildLeg, environment []string, linkerFlags string, packages []sizeProbePackage) int64 {
	t.Helper()
	directory, err := self.legDirectory(leg)
	if err != nil {
		t.Fatal(err)
	}
	source, err := self.sizeProbeSource(leg, packages)
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
	if linkerFlags != "" {
		arguments = append(arguments, "-ldflags="+linkerFlags)
	}
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

// True for a root file of the VPN component's entry points, the Forwarder and its signer (BRIDGE-M8-05), whose
// exported surface is the root's part of the forwarding leg (DESIGN-DETAILS 4.2.3).
func isForwardingEntryFile(goFile string) bool {
	return strings.HasPrefix(goFile, "bridge_forward") && !strings.HasSuffix(goFile, "_test.go")
}

// What the forwarding leg brings to the ios_extension leg (DESIGN-DETAILS 4.2.3): device's and protocol/bridge's whole
// surface, each once it exists, and the root with only bridge_forward*.go's kept, which links of protocol what the
// root reaches and every list file's init. Until BRIDGE-M8-05 lands its files the root is imported for its init
// functions and package variables alone, the part of its cost no caller can avoid.
func (self *repository) iosExtensionProbePackages() []sizeProbePackage {
	packages := []sizeProbePackage{}
	for _, directory := range []string{"device", "protocol/bridge"} {
		if _, err := os.Stat(filepath.Join(self.moduleDirectory, filepath.FromSlash(directory))); err == nil {
			packages = append(packages, wholeSizeProbePackage(self.modulePath+"/"+directory))
		}
	}
	return append(packages, sizeProbePackage{importPath: self.modulePath, keepsFile: isForwardingEntryFile})
}

// What the iOS extension links before sidecar is in it: connect's API. Kept whole on both sides of
// the comparison, because sdk's extension uses it with or without sidecar, and a call from device
// into connect adds nothing the extension does not already carry.
func (self *repository) iosExtensionBaselinePackages(t testing.TB) []sizeProbePackage {
	t.Helper()
	packages := []sizeProbePackage{}
	for _, require := range self.module(t, ".").file.Require {
		if firstPartyBase(require.Path) == connectBasePath {
			packages = append(packages, wholeSizeProbePackage(require.Path), wholeSizeProbePackage(require.Path+"/protocol"))
		}
	}
	return packages
}

// Measures the ios_extension leg: the baseline, then the baseline with the forwarding leg, both stripped as the
// extension ships.
func (self *repository) measureIosExtension(t testing.TB) (baselineByteCount int64, withSidecarByteCount int64) {
	t.Helper()
	leg := self.leg(t, "gomobile ios/arm64 extension")
	environment, err := self.iosBuildEnvironment(leg)
	if err != nil {
		t.Fatalf("the ios_extension gate needs Xcode: %v", err)
	}
	baselinePackages := self.iosExtensionBaselinePackages(t)
	linkerFlags := self.settings.iosExtensionLinkerFlags
	baselineByteCount = self.measureSizeProbe(t, leg, environment, linkerFlags, baselinePackages)
	withSidecarByteCount = self.measureSizeProbe(t, leg, environment, linkerFlags, slices.Concat(baselinePackages, self.iosExtensionProbePackages()))
	return baselineByteCount, withSidecarByteCount
}

// Measures the sidecar_http js leg, unstripped: the root and protocol, which §18.10's main imports. That main,
// sdk/js/cmd/sidecarwasm, belongs to sdk and links less than this whole surface, so this reads high.
func (self *repository) measureSidecarHttp(t testing.TB) int64 {
	t.Helper()
	leg := self.leg(t, "sidecar_http js/wasm")
	return self.measureSizeProbe(t, leg, leg.environment(), "", []sizeProbePackage{
		wholeSizeProbePackage(self.modulePath), wholeSizeProbePackage(self.modulePath + "/protocol"),
		wholeSizeProbePackage(self.modulePath + "/protocol/bridge"),
	})
}

// The linker flags sdk/build/Makefile's ios_extension bind passes, read from its -ldflags line: the block that names
// the tag, up to the next blank line.
func sdkIosExtensionLinkerFlags(makefile string) ([]string, error) {
	lines := strings.Split(makefile, "\n")
	for index, line := range lines {
		if !strings.Contains(line, "-tags") || !strings.Contains(line, iosExtensionTag) {
			continue
		}
		// gomobile bind's block runs from its command to the first line that ends no continuation
		start := index
		for start > 0 && strings.HasSuffix(strings.TrimSpace(lines[start-1]), "\\") {
			start -= 1
		}
		end := index
		for end < len(lines)-1 && strings.HasSuffix(strings.TrimSpace(lines[end]), "\\") {
			end += 1
		}
		for _, blockLine := range lines[start : end+1] {
			_, rest, found := strings.Cut(blockLine, "-ldflags")
			if !found {
				continue
			}
			quoted := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "="))
			quoted, _, _ = strings.Cut(strings.TrimPrefix(quoted, "\""), "\"")
			return strings.Fields(quoted), nil
		}
		return nil, fmt.Errorf("the ios_extension bind passes no -ldflags")
	}
	return nil, fmt.Errorf("no gomobile bind names the %s tag", iosExtensionTag)
}

// The verdicts at their edges: §18.10 and DESIGN-DETAILS 4.2.3 fail over the limit, so the limit itself passes.
func TestSizeVerdictsHoldTheirLimits(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.iosExtensionSizeFindings(34*1024*1024, 34*1024*1024))
	wantFindings(t, settings.iosExtensionSizeFindings(34*1024*1024, 34*1024*1024+6291456))
	wantFindings(t, settings.sidecarHttpSizeFindings(41943040))
	if settings.sidecarHttpGoalByteCount != 41943040 || settings.sidecarHttpMissByteCount != 74965628 || settings.iosExtensionAddedMaxByteCount != 6291456 {
		t.Errorf("the settings stray from §18.10 and DESIGN-DETAILS 4.2.3: %d, %d, %d", settings.sidecarHttpGoalByteCount, settings.sidecarHttpMissByteCount, settings.iosExtensionAddedMaxByteCount)
	}
	if settings.iosExtensionLinkerFlags != "-s -w" {
		t.Errorf("the ios_extension builds take %q, not sdk/build/Makefile's -s -w", settings.iosExtensionLinkerFlags)
	}
}

// One byte past 6 MiB fails, and says the limit is proposed.
func TestSizeFailsOnAForwardingLegOverItsLimit(t *testing.T) {
	settings := defaultCheckSettings()
	wantFindings(t, settings.iosExtensionSizeFindings(34*1024*1024, 34*1024*1024+6291457),
		"adds 6291457 B to the ios_extension leg, stripped, over the 6291456 B limit")
	findings := settings.iosExtensionSizeFindings(0, 6291457)
	if len(findings) != 1 || !strings.Contains(findings[0], "proposed until question details-4-ios-forwarding-budget is answered") {
		t.Errorf("the finding does not say its limit is proposed: %v", findings)
	}
}

// make size measures the binary sdk ships, so its flags are the ios_extension bind's own: a bind that stopped
// stripping would ship what the gate never read.
func TestSizeGateStripsAsSdkShips(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	makefilePath := repository.siblingPath("sdk/build/Makefile")
	data, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("no sdk/build/Makefile to read the extension's flags from: %v", err)
	}
	flags, err := sdkIosExtensionLinkerFlags(string(data))
	if err != nil {
		t.Fatalf("%s: %v", makefilePath, err)
	}
	for _, flag := range strings.Fields(repository.settings.iosExtensionLinkerFlags) {
		if !slices.Contains(flags, flag) {
			t.Errorf("make size builds with %s, which sdk/build/Makefile's ios_extension bind does not pass (it passes %v)", flag, flags)
		}
	}
}

// The reading takes the -ldflags of the bind block that names the tag, and no other block's.
func TestSizeGateReadsTheExtensionBindsFlags(t *testing.T) {
	makefile := "build_ios:\n\tgomobile bind \\\n\t\t-tags sdk_mobile_bind \\\n\t\t-ldflags \"-X a=b\" \\\n\t\t./pkg\n\n" +
		"build_extension:\n\tgomobile bind \\\n\t\t-target ios \\\n\t\t-tags sdk_mobile_bind,ios_extension \\\n\t\t-ldflags \"-s -w -buildid=\" \\\n\t\t./pkg\n"
	flags, err := sdkIosExtensionLinkerFlags(makefile)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []string{"-s", "-w", "-buildid="}) {
		t.Errorf("flags %v", flags)
	}
	if _, err := sdkIosExtensionLinkerFlags("build_extension:\n\tgomobile bind -tags sdk_mobile_bind,ios_extension ./pkg\n"); err == nil {
		t.Errorf("a bind with no -ldflags read as flags")
	}
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
	surface, err := repository.exportedSurface(repository.leg(t, "gomobile ios/arm64 extension"), repository.modulePath+"/device", "kept", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"&kept.Table", "(*kept.Bridge)(nil)", "(*kept.Bridge).Close", "(*kept.Bridge).Open", "(*kept.Reader)(nil)", "kept.NewBridge"}
	if !slices.Equal(surface, want) {
		t.Errorf("surface %v, want %v", surface, want)
	}
}

// Of the root the probe keeps bridge_forward*.go's exported surface alone, and imports the root blank while no such
// file exists, so its init functions and package variables are still measured.
func TestSizeProbeKeepsOnlyTheForwardingFilesOfTheRoot(t *testing.T) {
	fixture := newFixture(t)
	repository := fixture.open()
	leg := repository.leg(t, iosExtensionLegName)
	source, err := repository.sizeProbeSource(leg, repository.iosExtensionProbePackages())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, "\t_ "+strconv.Quote(repository.modulePath)+"\n") {
		t.Errorf("with no forwarding file the root is not imported blank:\n%s", source)
	}
	fixture.write("bridge_forward.go", "package sidecar\n\ntype Forwarder struct{}\n\nfunc NewForwarder() *Forwarder { return nil }\n\nfunc (self *Forwarder) Close() {}\n")
	fixture.write("config_lookup.go", "package sidecar\n\nfunc ConfigLookup() {}\n")
	repository = fixture.open()
	surface, err := repository.exportedSurface(leg, repository.modulePath, "kept", isForwardingEntryFile)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"(*kept.Forwarder)(nil)", "(*kept.Forwarder).Close", "kept.NewForwarder"}
	if !slices.Equal(surface, want) {
		t.Errorf("surface %v, want %v", surface, want)
	}
}
