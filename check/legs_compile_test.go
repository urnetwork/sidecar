//go:build sidecar_check

// §22.4's T1 runs the sidecar on every §4.7 leg, and the other rows read each leg through go list,
// which resolves a leg's files but compiles none of them. Every go test make check runs is on this
// host's system, so a file only windows builds, or a test only js builds, could break its leg and
// pass every row. Each leg therefore compiles here, with go list -export: every package the leg
// builds, its tests as well on a test leg, compiled and linked into nothing. Each leg compiles once,
// and the reflect rule (legrows_test.go) reads the same compile's export data.
//
// cgo needs a C compiler for the leg's target, and a host has one for its own system at most. A
// darwin host compiles every darwin leg, and the ios legs through Xcode, whose absence fails them as
// it fails make size; any other host compiles the cgo legs of its own GOOS and GOARCH. A cgo leg no
// toolchain here reaches compiles with cgo off instead. For this repository's files that differs
// only where a file reads the cgo tag, since the cgo row leaves them no cgo file on such a leg; std's
// and third parties' cgo halves go uncompiled. The run's report names each such leg, rather than
// passing it as compiled. Without this, a file only android builds would compile nowhere: no other
// leg has its system. Running each leg's tests is T1's runner, not this rule.

package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// True when a host of hostGoos and hostGoarch compiles the leg. Every leg with cgo off does. A cgo
// leg needs its target's C toolchain, which clang is for every darwin arch and Xcode's SDK for ios.
func (self *buildLeg) compilesOn(hostGoos string, hostGoarch string) bool {
	if !self.cgoEnabled {
		return true
	}
	if hostGoos == "darwin" {
		return self.goos == "darwin" || self.goos == "ios"
	}
	return self.goos == hostGoos && self.goarch == hostGoarch
}

// One package of a compiled leg, as go list -export reports it.
type exportedPackage struct {
	ImportPath string
	Dir        string
	// the compiler's export data, which go/types reads through an importer
	Export   string
	GoFiles  []string
	CgoFiles []string
}

// The fields the rules read, which keeps the listing small.
const exportedPackageFields = "ImportPath,Dir,Export,GoFiles,CgoFiles"

// What compiling one leg left.
type legExport struct {
	// every package the leg builds, its tests' on a test leg
	packages []*exportedPackage
	// the finding, when the leg did not compile, with the go command's own account of what failed
	failure string
}

// A leg compiled, once however many rules read it.
type legExportOnce struct {
	once   sync.Once
	export *legExport
}

// The leg compiled as this host compiles it: as it builds where this host has its toolchain, else with
// cgo off.
func (self *repository) exportLeg(leg *buildLeg) *legExport {
	once := func() *legExportOnce {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		once, ok := self.exportLegOnces[leg.name]
		if !ok {
			once = &legExportOnce{}
			self.exportLegOnces[leg.name] = once
		}
		return once
	}()
	once.once.Do(func() {
		once.export = self.compileLeg(leg, !leg.compilesOn(runtime.GOOS, runtime.GOARCH))
	})
	return once.export
}

// Says that this host compiles the leg with cgo off, for a rule that reads it compiled.
func (self *repository) reportCgoOff(leg *buildLeg) {
	self.report("%s compiles with cgo off: its cgo needs a C toolchain for %s/%s, which this %s/%s host does not have",
		leg.name, leg.goos, leg.goarch, runtime.GOOS, runtime.GOARCH)
}

// Compiles one leg as it builds: what it ships, and on a test leg its tests too, with cgo off when
// cgoOff says this host cannot build its cgo. It runs off the test's goroutine, so what goes wrong
// comes back as the failure.
func (self *repository) compileLeg(leg *buildLeg, cgoOff bool) *legExport {
	failed := func(format string, arguments ...any) *legExport {
		return &legExport{failure: findingf(format, arguments...)}
	}
	directory, err := self.legDirectory(leg)
	if err != nil {
		return failed("%v", err)
	}
	patterns, err := self.legPatterns(leg)
	if err != nil {
		return failed("%v", err)
	}
	if len(patterns) == 0 {
		// as listLeg reads it: only an engine leg before the first engine has nothing to build
		if leg.class == classEngine {
			return &legExport{}
		}
		return failed("%s: no pattern of %v exists in %s", leg.name, leg.patterns, directory)
	}
	environment := leg.environment()
	switch {
	case cgoOff:
		environment = append(environment, "CGO_ENABLED=0")
	case leg.cgoEnabled && leg.goos == "ios":
		environment, err = self.iosBuildEnvironment(leg)
		if err != nil {
			return failed("%s compiles only with Xcode: %v", leg.name, err)
		}
	}
	arguments := []string{"list", "-deps", "-export", "-json=" + exportedPackageFields}
	if leg.test {
		arguments = append(arguments, "-test")
	}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	output, err := runGo(directory, environment, append(arguments, patterns...)...)
	if err != nil {
		if cgoOff {
			return failed("%s does not compile with cgo off: %v", leg.name, err)
		}
		return failed("%s does not compile: %v", leg.name, err)
	}
	export := &legExport{}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		listed := &exportedPackage{}
		if err := decoder.Decode(listed); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return failed("%s: reading go list: %v", leg.name, err)
		}
		export.packages = append(export.packages, listed)
	}
	return export
}

// Every leg, some at once: as it builds where this host has its toolchain, else with cgo off and a
// report line saying so.
func (self *repository) legCompileFindings(t testing.TB) []string {
	t.Helper()
	for _, leg := range self.legs {
		if !leg.compilesOn(runtime.GOOS, runtime.GOARCH) {
			self.reportCgoOff(leg)
		}
	}
	slots := make(chan struct{}, max(self.settings.legCompileConcurrency, 1))
	findingLock := sync.Mutex{}
	findings := []string{}
	waitGroup := sync.WaitGroup{}
	for _, leg := range self.legs {
		waitGroup.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			failure := self.exportLeg(leg).failure
			if failure == "" {
				return
			}
			func() {
				findingLock.Lock()
				defer findingLock.Unlock()
				findings = append(findings, failure)
			}()
		})
	}
	waitGroup.Wait()
	slices.Sort(findings)
	return findings
}

// Which host compiles which leg as it builds, read off the table: every leg with cgo off on any
// host, and a cgo leg only on a host of its own system.
func TestLegsCompileWhereTheirToolchainIs(t *testing.T) {
	for _, c := range []struct {
		hostGoos   string
		hostGoarch string
		// the legs such a host compiles with cgo off
		want []string
	}{
		{
			hostGoos: "darwin", hostGoarch: "arm64",
			want: []string{
				"cgo linux/amd64", "cgo windows/amd64", "gomobile android/arm64", "tests cgo linux/amd64", "tests cgo windows/amd64",
			},
		},
		{
			hostGoos: "linux", hostGoarch: "amd64",
			want: []string{
				"cgo windows/amd64", "cgo darwin/arm64", "gomobile android/arm64", "gomobile ios/arm64",
				"gomobile ios/arm64 extension", "gomobile macos/arm64", "gomobile macos/arm64 extension",
				"cli darwin/amd64 keychain fallback", "cli darwin/arm64 keychain fallback",
				"tests cgo windows/amd64", "tests cgo darwin/arm64",
			},
		},
		{
			hostGoos: "linux", hostGoarch: "arm64",
			want: []string{
				"cgo linux/amd64", "cgo windows/amd64", "cgo darwin/arm64", "gomobile android/arm64", "gomobile ios/arm64",
				"gomobile ios/arm64 extension", "gomobile macos/arm64", "gomobile macos/arm64 extension",
				"cli darwin/amd64 keychain fallback", "cli darwin/arm64 keychain fallback",
				"tests cgo linux/amd64", "tests cgo windows/amd64", "tests cgo darwin/arm64",
			},
		},
	} {
		cgoOffLegs := []string{}
		for _, leg := range defaultBuildLegs() {
			if !leg.compilesOn(c.hostGoos, c.hostGoarch) {
				cgoOffLegs = append(cgoOffLegs, leg.name)
				if !leg.cgoEnabled {
					t.Errorf("a %s/%s host cannot compile %s as it builds, though its cgo is off", c.hostGoos, c.hostGoarch, leg.name)
				}
			}
		}
		if !slices.Equal(cgoOffLegs, c.want) {
			t.Errorf("a %s/%s host compiles %v with cgo off, want %v", c.hostGoos, c.hostGoarch, cgoOffLegs, c.want)
		}
	}
}
