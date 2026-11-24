//go:build sidecar_check

// §4.7's legs: every build this repository ships, and the test builds beside them, each read through
// go list -deps. A leg's closure is what the deps, legs, cgo and hook rows read, so a leg that names
// the wrong environment would pass them all; TestLegsReadTheirOwnBuildConfiguration holds that. Each
// leg also compiles, in legs_compile_test.go.

package check

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The value of dependencies.yml's leg field a closure answers to (§4.7).
const (
	classClient = "client"
	classEngine = "engine"
	classCli    = "cli"
	classTest   = "test"
)

// One build, as go list -deps resolves it.
type buildLeg struct {
	name string
	// "." for the root module, else its relativeName
	moduleName string
	goos       string
	goarch     string
	cgoEnabled bool
	tags       []string
	// also lists what the package's tests import
	test bool
	// each relative to the module. An explicit ./<directory> that does not exist yet is dropped, so
	// device/ joins its legs by landing; ./... takes whatever is there.
	patterns []string
	// dependencies.yml's leg
	class string
	// a build people run. sidecar_testhooks may touch no such leg
	ships bool
	// §5.10's darwin fallback leg, the one place keychain_darwin.go may be a cgo file
	keychainFallback bool
	// an ios leg whose cgo builds against the iOS simulator's SDK, as gomobile builds an iossimulator
	// slice; its GOOS, GOARCH and tags are the iPhone slice's
	iosSimulator bool
}

// True for the tag.
func (self *buildLeg) hasTag(tag string) bool {
	return slices.Contains(self.tags, tag)
}

// GOOS and the rest, as KEY=value, after what goEnvironment clears.
func (self *buildLeg) environment() []string {
	cgo := "0"
	if self.cgoEnabled {
		cgo = "1"
	}
	return goEnvironment("GOOS="+self.goos, "GOARCH="+self.goarch, "CGO_ENABLED="+cgo)
}

// The packages a client links: sdk imports the root and protocol in sidecar-role files, and device
// and protocol/bridge in device files (§18.10).
var clientPatterns = []string{".", "./protocol", "./protocol/bridge", "./device"}

// The packages Apple's network extensions link (D-SDK-20; DESIGN-DETAILS 4.2.3): device and protocol/bridge whole, and
// the root and protocol as the forwarding leg's list leaves them, every other file of theirs carrying !ios_extension.
var iosExtensionPatterns = []string{".", "./protocol", "./protocol/bridge", "./device"}

// Everything in a module, for the legs that build or test all of it.
var allPatterns = []string{"./..."}

// The tags gomobile adds beside a bind's own (golang.org/x/mobile's cmd/gomobile/env.go, platformTags): ios
// on the iPhone and simulator slices, and macos on a macOS slice's binding step, which gobind runs with
// GOOS=ios. Android's is android, which GOOS=android sets itself, so the Android legs carry none, and the
// macOS compile legs carry none, their archives compiling without it.
const (
	gomobileIosTag   = "ios"
	gomobileMacosTag = "macos"
)

// Every leg. This mirrors sdk/dependency_boundary_test.go:98-123, which
// sdkLegRowFindings holds both ways for the gomobile legs, and adds §4.7's sidecar_http js leg and
// the CLI's six release targets, then a leg for each module nothing else reads. The gomobile legs are
// every target sdk/build/Makefile binds (QD-908): the Android bind's, the Apple bind's and the network
// extension's, each with gomobile's tag for its platform. gomobile runs a macOS slice in two
// configurations and fails the bind if either fails (QD-997), so each has two legs, named for the step
// each models: the binding step's, gobind's type-check with GOOS=ios and the bind's tags plus macos,
// on which desktop files also select (QD-991), and the compile's, GOOS=darwin with the bind's tags
// alone, as the archive the slice links compiles. Each row's cgo is explicit where sdk leaves it to the
// host, because a leg is what it names on any machine.
func defaultBuildLegs() []*buildLeg {
	clientLeg := func(name string, goos string, goarch string, cgoEnabled bool, tags ...string) *buildLeg {
		return &buildLeg{
			name: name, moduleName: ".", goos: goos, goarch: goarch, cgoEnabled: cgoEnabled, tags: tags,
			patterns: clientPatterns, class: classClient, ships: true,
		}
	}
	deviceLeg := func(name string, goos string, goarch string, platformTags ...string) *buildLeg {
		return &buildLeg{
			name: name, moduleName: ".", goos: goos, goarch: goarch, cgoEnabled: true,
			tags:     slices.Concat([]string{mobileBindTag, iosExtensionTag}, platformTags),
			patterns: iosExtensionPatterns, class: classClient, ships: true,
		}
	}
	simulatorLeg := func(leg *buildLeg) *buildLeg {
		leg.iosSimulator = true
		return leg
	}
	cliLeg := func(goos string, goarch string) *buildLeg {
		return &buildLeg{
			name: "cli " + goos + "/" + goarch, moduleName: "cli", goos: goos, goarch: goarch,
			patterns: allPatterns, class: classCli, ships: true,
		}
	}
	keychainFallbackLeg := func(goarch string) *buildLeg {
		return &buildLeg{
			name: "cli darwin/" + goarch + " keychain fallback", moduleName: "cli", goos: "darwin", goarch: goarch,
			cgoEnabled: true, patterns: allPatterns, class: classCli, ships: true, keychainFallback: true,
		}
	}
	testLeg := func(name string, moduleName string, goos string, goarch string, cgoEnabled bool) *buildLeg {
		return &buildLeg{
			name: name, moduleName: moduleName, goos: goos, goarch: goarch, cgoEnabled: cgoEnabled,
			test: true, patterns: allPatterns, class: classTest,
		}
	}
	return []*buildLeg{
		// sdk's shipped builds, on what sidecar gives them
		clientLeg("root linux/amd64", "linux", "amd64", false),
		clientLeg("root windows/amd64", "windows", "amd64", false),
		clientLeg("root darwin/arm64", "darwin", "arm64", false),
		clientLeg("js/wasm", "js", "wasm", false),
		clientLeg("cgo linux/amd64", "linux", "amd64", true),
		clientLeg("cgo windows/amd64", "windows", "amd64", true),
		clientLeg("cgo darwin/arm64", "darwin", "arm64", true),
		clientLeg("gomobile android/arm64", "android", "arm64", true, mobileBindTag),
		clientLeg("gomobile android/arm", "android", "arm", true, mobileBindTag),
		clientLeg("gomobile android/amd64", "android", "amd64", true, mobileBindTag),
		clientLeg("gomobile ios/arm64", "ios", "arm64", true, mobileBindTag, gomobileIosTag),
		simulatorLeg(clientLeg("gomobile iossimulator/arm64", "ios", "arm64", true, mobileBindTag, gomobileIosTag)),
		clientLeg("gomobile macos/arm64 binding step", "ios", "arm64", true, mobileBindTag, gomobileMacosTag),
		clientLeg("gomobile macos/arm64 compile", "darwin", "arm64", true, mobileBindTag),
		clientLeg("gomobile macos/amd64 binding step", "ios", "amd64", true, mobileBindTag, gomobileMacosTag),
		clientLeg("gomobile macos/amd64 compile", "darwin", "amd64", true, mobileBindTag),
		deviceLeg("gomobile ios/arm64 extension", "ios", "arm64", gomobileIosTag),
		simulatorLeg(deviceLeg("gomobile iossimulator/arm64 extension", "ios", "arm64", gomobileIosTag)),
		deviceLeg("gomobile macos/arm64 extension binding step", "ios", "arm64", gomobileMacosTag),
		deviceLeg("gomobile macos/arm64 extension compile", "darwin", "arm64"),
		deviceLeg("gomobile macos/amd64 extension binding step", "ios", "amd64", gomobileMacosTag),
		deviceLeg("gomobile macos/amd64 extension compile", "darwin", "amd64"),

		// §4.7's page Worker leg, over the root and protocol, which §18.10's main imports
		{
			name: "sidecar_http js/wasm", moduleName: ".", goos: "js", goarch: "wasm",
			tags:     []string{sidecarHttpTag},
			patterns: []string{".", "./protocol", "./protocol/bridge"}, class: classClient, ships: true,
		},

		// the CLI's six release targets, from cli/ (§4.10's three systems on amd64 and arm64)
		cliLeg("darwin", "amd64"),
		cliLeg("darwin", "arm64"),
		cliLeg("linux", "amd64"),
		cliLeg("linux", "arm64"),
		cliLeg("windows", "amd64"),
		cliLeg("windows", "arm64"),

		// §5.10's darwin fallback, which the release does not build unless purego or the bundle fails
		keychainFallbackLeg("amd64"),
		keychainFallbackLeg("arm64"),

		// what server links: the root module's engines on server's two targets, and the prover it
		// injects (server/cli/api/Makefile:15-16)
		{
			name: "engines linux/amd64", moduleName: ".", goos: "linux", goarch: "amd64",
			patterns: []string{"engines"}, class: classEngine, ships: true,
		},
		{
			name: "engines linux/arm64", moduleName: ".", goos: "linux", goarch: "arm64",
			patterns: []string{"engines"}, class: classEngine, ships: true,
		},
		{
			name: "smtpproof linux/amd64", moduleName: "smtpproof", goos: "linux", goarch: "amd64",
			patterns: allPatterns, class: classEngine, ships: true,
		},

		// sdk's test: true rows, and the modules no build ships
		testLeg("tests linux/amd64", ".", "linux", "amd64", false),
		testLeg("tests windows/amd64", ".", "windows", "amd64", false),
		testLeg("tests darwin/arm64", ".", "darwin", "arm64", false),
		testLeg("tests js/wasm", ".", "js", "wasm", false),
		testLeg("tests cgo linux/amd64", ".", "linux", "amd64", true),
		testLeg("tests cgo windows/amd64", ".", "windows", "amd64", true),
		testLeg("tests cgo darwin/arm64", ".", "darwin", "arm64", true),
		testLeg("tests cli linux/amd64", "cli", "linux", "amd64", false),
		testLeg("tests smtpproof linux/amd64", "smtpproof", "linux", "amd64", false),
		testLeg("tests mlsinterop linux/amd64", "mlsinterop", "linux", "amd64", false),
	}
}

// Lists every leg at once, so a rule that reads them all waits for the slowest rather than the sum.
// Each is still listed once; a failure comes back through closure.
func (self *repository) listAllLegs() {
	waitGroup := sync.WaitGroup{}
	for _, leg := range self.legs {
		waitGroup.Go(func() {
			self.closureOnce(leg)
		})
	}
	waitGroup.Wait()
}

// The legs that ship, for the rows §4.7 words as a release leg's.
func (self *repository) shippedLegs() []*buildLeg {
	legs := []*buildLeg{}
	for _, leg := range self.legs {
		if leg.ships {
			legs = append(legs, leg)
		}
	}
	return legs
}

// The leg of that name, or a test failure.
func (self *repository) leg(t testing.TB, name string) *buildLeg {
	t.Helper()
	for _, leg := range self.legs {
		if leg.name == name {
			return leg
		}
	}
	t.Fatalf("no leg is named %s", name)
	return nil
}

// One package of a closure, as go list -json reports it.
type listedPackage struct {
	ImportPath string
	Name       string
	Dir        string
	Standard   bool
	Module     *struct {
		Path    string
		Version string
		Dir     string
	}
	GoFiles  []string
	CgoFiles []string
	Imports  []string
}

// The fields a rule reads, which keeps the listing small.
const listedPackageFields = "ImportPath,Name,Dir,Standard,Module,GoFiles,CgoFiles,Imports"

// A closure, listed once however many rules read it.
type legClosureOnce struct {
	once     sync.Once
	packages []*listedPackage
	err      error
}

// The leg's go list -deps. A leg with nothing to list, such as the engine legs before the first
// engine lands, has an empty closure, and that is the only way a closure is empty.
func (self *repository) closure(t testing.TB, leg *buildLeg) []*listedPackage {
	t.Helper()
	once := self.closureOnce(leg)
	if once.err != nil {
		t.Fatal(once.err)
	}
	return once.packages
}

// The leg's once, listed by the time this returns.
func (self *repository) closureOnce(leg *buildLeg) *legClosureOnce {
	once := func() *legClosureOnce {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		once, ok := self.closureLegOnces[leg.name]
		if !ok {
			once = &legClosureOnce{}
			self.closureLegOnces[leg.name] = once
		}
		return once
	}()
	once.once.Do(func() {
		once.packages, once.err = self.listLeg(leg)
	})
	return once
}

// The directory a leg runs in, or an error for a module this checkout does not hold.
func (self *repository) legDirectory(leg *buildLeg) (string, error) {
	modules, err := self.modulesOnce()
	if err != nil {
		return "", err
	}
	for _, module := range modules {
		if module.relativeName == leg.moduleName {
			return module.directory, nil
		}
	}
	return "", fmt.Errorf("%s: no module %s in this checkout", leg.name, leg.moduleName)
}

// A leg's patterns as they stand in this checkout: the engines in place of the word, and an
// explicit directory only where it exists. The rest, ./..., are the go command's.
func (self *repository) legPatterns(leg *buildLeg) ([]string, error) {
	directory, err := self.legDirectory(leg)
	if err != nil {
		return nil, err
	}
	patterns := []string{}
	for _, pattern := range leg.patterns {
		switch {
		case pattern == "engines":
			entries, err := os.ReadDir(directory)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if entry.IsDir() && isEngineDirectory(entry.Name()) {
					patterns = append(patterns, "./"+entry.Name()+"/...")
				}
			}
		case strings.HasPrefix(pattern, "./") && !strings.HasSuffix(pattern, "..."):
			if _, err := os.Stat(filepath.Join(directory, filepath.FromSlash(pattern))); err == nil {
				patterns = append(patterns, pattern)
			}
		default:
			patterns = append(patterns, pattern)
		}
	}
	return patterns, nil
}

// Lists a leg. Only stdout is read as the listing, and a go list error fails the leg rather than
// shrinking it. Each package a pattern names must then be in the closure, so a wrong directory or
// environment cannot pass by listing nothing.
func (self *repository) listLeg(leg *buildLeg) ([]*listedPackage, error) {
	directory, err := self.legDirectory(leg)
	if err != nil {
		return nil, err
	}
	patterns, err := self.legPatterns(leg)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		if leg.class == classEngine {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: no pattern of %v exists in %s", leg.name, leg.patterns, directory)
	}
	arguments := []string{"list", "-deps", "-json=" + listedPackageFields}
	if leg.test {
		arguments = append(arguments, "-test")
	}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	arguments = append(arguments, patterns...)
	output, err := runGo(directory, leg.environment(), arguments...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", leg.name, err)
	}
	packages := []*listedPackage{}
	seen := map[string]bool{}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		listed := &listedPackage{}
		if err := decoder.Decode(listed); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: reading go list: %w", leg.name, err)
		}
		// a test variant prints as "path [path.test]", and its package is the path
		listed.ImportPath, _, _ = strings.Cut(listed.ImportPath, " ")
		if seen[listed.ImportPath] {
			continue
		}
		seen[listed.ImportPath] = true
		packages = append(packages, listed)
	}
	for _, pattern := range patterns {
		if strings.Contains(pattern, "...") {
			continue
		}
		wanted := self.modulePathOf(leg.moduleName)
		if pattern != "." {
			wanted += "/" + strings.TrimPrefix(pattern, "./")
		}
		if !seen[wanted] {
			return nil, fmt.Errorf("%s: the closure lacks %s, which its pattern names", leg.name, wanted)
		}
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("%s: go list resolved nothing", leg.name)
	}
	return packages, nil
}

// The module path of a module by its relativeName, on a release branch too.
func (self *repository) modulePathOf(relativeName string) string {
	modules, err := self.modulesOnce()
	if err != nil {
		return ""
	}
	for _, module := range modules {
		if module.relativeName == relativeName {
			return module.file.Module.Path
		}
	}
	return ""
}

// One row of sdk's leg table, read from its syntax.
type sdkLeg struct {
	name        string
	environment []string
	tags        string
}

// sdk's table as it stands, from the sibling checkout. The file holding it is sdk's own, so a table
// this cannot find fails: that says the mirror above can no longer be checked, which is not a pass.
func readSdkLegs(fileName string) ([]sdkLeg, error) {
	fileSet := token.NewFileSet()
	syntax, err := parser.ParseFile(fileSet, fileName, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var table *ast.CompositeLit
	for _, decl := range syntax.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec := spec.(*ast.ValueSpec)
			if len(valueSpec.Names) == 1 && valueSpec.Names[0].Name == "messagingBoundaryLegs" && len(valueSpec.Values) == 1 {
				table, _ = valueSpec.Values[0].(*ast.CompositeLit)
			}
		}
	}
	if table == nil {
		return nil, fmt.Errorf("%s no longer declares messagingBoundaryLegs", fileName)
	}
	legs := []sdkLeg{}
	for _, element := range table.Elts {
		literal, ok := element.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("%s: an unreadable row in messagingBoundaryLegs", fileName)
		}
		leg := sdkLeg{}
		for _, field := range literal.Elts {
			pair, ok := field.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := pair.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "name":
				leg.name, _ = stringLiteral(pair.Value)
			case "tags":
				leg.tags, _ = stringLiteral(pair.Value)
			case "environment":
				list, ok := pair.Value.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, value := range list.Elts {
					if text, ok := stringLiteral(value); ok {
						leg.environment = append(leg.environment, text)
					}
				}
			}
		}
		legs = append(legs, leg)
	}
	return legs, nil
}

// The text of a string literal expression.
func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(literal.Value)
	return text, err == nil
}

// §4.7's legs line points at sdk's table, so a row added there must not go unread here.
func (self *repository) sdkLegRowFindings(t testing.TB) []string {
	t.Helper()
	sdkLegs, err := readSdkLegs(self.siblingPath("sdk/dependency_boundary_test.go"))
	if err != nil {
		return []string{err.Error()}
	}
	if len(sdkLegs) == 0 {
		return []string{"sdk's table has no rows"}
	}
	return sdkLegFindings(sdkLegs, self.legs)
}

// Each sdk leg with no leg here that builds the same GOOS, GOARCH and tags, with cgo where sdk's row
// says; and each gomobile leg here, one built with sdk_mobile_bind, that is no row of sdk's by name
// building as it does, since sdk's table is the one list of what gomobile binds and check/ adds no
// gomobile target of its own (QD-908). The name is what tells a simulator slice from the iPhone's,
// which build alike.
func sdkLegFindings(sdkLegs []sdkLeg, legs []*buildLeg) []string {
	builds := func(sdkRow sdkLeg, leg *buildLeg) bool {
		values := map[string]string{}
		for _, entry := range sdkRow.environment {
			key, value, _ := strings.Cut(entry, "=")
			values[key] = value
		}
		wantedTags := []string{}
		if sdkRow.tags != "" {
			wantedTags = strings.Split(sdkRow.tags, ",")
		}
		slices.Sort(wantedTags)
		legTags := slices.Clone(leg.tags)
		slices.Sort(legTags)
		if leg.goos != values["GOOS"] || leg.goarch != values["GOARCH"] || !slices.Equal(legTags, wantedTags) {
			return false
		}
		cgo, cgoNamed := values["CGO_ENABLED"]
		return !cgoNamed || (cgo == "1") == leg.cgoEnabled
	}
	findings := []string{}
	for _, sdkRow := range sdkLegs {
		if !slices.ContainsFunc(legs, func(leg *buildLeg) bool { return builds(sdkRow, leg) }) {
			findings = append(findings, findingf("sdk's leg %q has no leg here", sdkRow.name))
		}
	}
	for _, leg := range legs {
		if !leg.hasTag(mobileBindTag) {
			continue
		}
		if !slices.ContainsFunc(sdkLegs, func(sdkRow sdkLeg) bool { return sdkRow.name == leg.name && builds(sdkRow, leg) }) {
			findings = append(findings, findingf("the gomobile leg %q is no leg of sdk's table building as it does, and check/ adds no gomobile target of its own", leg.name))
		}
	}
	return findings
}
