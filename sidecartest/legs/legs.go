// The every-leg runner (TEST-M1-07; D-TEST-1, D-TEST-15): §22.4's T1 "on all §4.7 legs", where a vector
// must be byte-equal on every leg. Run builds each leg's test binaries with go test -c and runs them
// where the leg can run: darwin/arm64 natively, linux in a container, js/wasm and the sidecar_http leg
// under Node through Go's wasm exec script, windows/amd64 compiled only until an attested runner
// exists, and the gomobile legs by SDK-M10-06's cells, which run them elsewhere. Each leg reports pass,
// fail, compiled or not run, and only pass counts: a leg that cannot run says so and never turns green
// (plan-TEST-small-readings reading 7).
//
// The legs mirror check/'s defaultBuildLegs by name, and check/legs_table_test.go holds the two tables
// together, since check/ is tagged and cannot be imported. One toolchain builds every leg (D-TEST-15).
//
// Each test binary runs with SIDECAR_LEG set to its leg's name, so a vector mismatch names the leg it
// happened on (sidecartest/vector).

package legs

import (
	"slices"
)

// How a leg's tests run on this host.
type Runner string

const (
	// the host runs the binaries itself
	RunnerNative Runner = "native"
	// a linux container runs them, the platform's own or emulated
	RunnerContainer Runner = "container"
	// Node runs the wasm through Go's wasm exec script
	RunnerNode Runner = "node"
	// no attested runner: the leg compiles and reads compiled, which is no pass
	RunnerCompileOnly Runner = "compile-only"
	// another harness runs the leg (SDK-M10-06's cells): here it reads not run
	RunnerCells Runner = "cells"
	// this host cannot build the leg at all: it reads not run with its reason
	RunnerNone Runner = "none"
)

// One leg: a build check/ knows by the same name, and how its tests run here.
type Leg struct {
	// check/'s name for the build
	Name string
	// the module the leg's packages are in, "." for the root
	Module string
	Goos   string
	Goarch string
	Cgo    bool
	Tags   []string
	// the packages whose tests run, relative to the module
	Packages []string
	Runner   Runner
	// why a leg reads compiled or not run, for its report
	Why string
}

// Whether the leg builds with tag.
func (self *Leg) HasTag(tag string) bool {
	return slices.Contains(self.Tags, tag)
}

// The root's packages a client leg links (check/'s clientPatterns), and every package of a module.
var (
	allPackages     = []string{"./..."}
	httpLegPackages = []string{".", "./protocol", "./protocol/bridge"}
	enginePackages  = []string{"./...service/..."}
)

// Every leg whose tests run: check/'s test legs, its sidecar_http js leg, the engines on linux/arm64,
// and the gomobile legs, each with the runner this host has for it. A darwin/arm64 host runs its own
// legs natively and linux/arm64 in a container without emulation.
func DefaultLegs() []*Leg {
	return []*Leg{
		{Name: "tests darwin/arm64", Module: ".", Goos: "darwin", Goarch: "arm64", Packages: allPackages, Runner: RunnerNative},
		{Name: "tests cgo darwin/arm64", Module: ".", Goos: "darwin", Goarch: "arm64", Cgo: true, Packages: allPackages, Runner: RunnerNative},
		{Name: "tests linux/amd64", Module: ".", Goos: "linux", Goarch: "amd64", Packages: allPackages, Runner: RunnerContainer},
		{Name: "engines linux/arm64", Module: ".", Goos: "linux", Goarch: "arm64", Packages: enginePackages, Runner: RunnerContainer},
		{Name: "tests js/wasm", Module: ".", Goos: "js", Goarch: "wasm", Packages: allPackages, Runner: RunnerNode},
		{Name: "sidecar_http js/wasm", Module: ".", Goos: "js", Goarch: "wasm", Tags: []string{"sidecar_http"}, Packages: httpLegPackages, Runner: RunnerNode},
		{Name: "tests windows/amd64", Module: ".", Goos: "windows", Goarch: "amd64", Packages: allPackages, Runner: RunnerCompileOnly, Why: "no attested windows runner"},
		{Name: "tests cgo linux/amd64", Module: ".", Goos: "linux", Goarch: "amd64", Cgo: true, Packages: allPackages, Runner: RunnerNone, Why: "no C toolchain for linux/amd64 on this host"},
		{Name: "tests cgo windows/amd64", Module: ".", Goos: "windows", Goarch: "amd64", Cgo: true, Packages: allPackages, Runner: RunnerNone, Why: "no C toolchain for windows/amd64 on this host"},
		{Name: "tests cli linux/amd64", Module: "cli", Goos: "linux", Goarch: "amd64", Packages: allPackages, Runner: RunnerContainer},
		{Name: "tests smtpproof linux/amd64", Module: "smtpproof", Goos: "linux", Goarch: "amd64", Packages: allPackages, Runner: RunnerContainer},
		{Name: "tests mlsinterop linux/amd64", Module: "mlsinterop", Goos: "linux", Goarch: "amd64", Packages: allPackages, Runner: RunnerContainer},
		{Name: "tests sidecarctl linux/amd64", Module: "sidecarctl", Goos: "linux", Goarch: "amd64", Packages: allPackages, Runner: RunnerContainer},
		{Name: "gomobile android/arm64", Module: ".", Goos: "android", Goarch: "arm64", Cgo: true, Tags: []string{"sdk_mobile_bind"}, Packages: allPackages, Runner: RunnerCells, Why: "SDK-M10-06's cells run it"},
		{Name: "gomobile ios/arm64", Module: ".", Goos: "ios", Goarch: "arm64", Cgo: true, Tags: []string{"sdk_mobile_bind"}, Packages: allPackages, Runner: RunnerCells, Why: "SDK-M10-06's cells run it"},
		{Name: "gomobile ios/arm64 extension", Module: ".", Goos: "ios", Goarch: "arm64", Cgo: true, Tags: []string{"sdk_mobile_bind", "ios_extension"}, Packages: []string{"./protocol/bridge", "./device"}, Runner: RunnerCells, Why: "SDK-M10-06's cells run it"},
		{Name: "gomobile macos/arm64", Module: ".", Goos: "darwin", Goarch: "arm64", Cgo: true, Tags: []string{"sdk_mobile_bind"}, Packages: allPackages, Runner: RunnerCells, Why: "SDK-M10-06's cells run it"},
		{Name: "gomobile macos/arm64 extension", Module: ".", Goos: "darwin", Goarch: "arm64", Cgo: true, Tags: []string{"sdk_mobile_bind", "ios_extension"}, Packages: []string{"./protocol/bridge", "./device"}, Runner: RunnerCells, Why: "SDK-M10-06's cells run it"},
	}
}

// The legs whose name is one of names, in the table's order.
func LegsNamed(legs []*Leg, names ...string) []*Leg {
	named := []*Leg{}
	for _, leg := range legs {
		if slices.Contains(names, leg.Name) {
			named = append(named, leg)
		}
	}
	return named
}
