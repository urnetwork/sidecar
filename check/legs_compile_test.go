//go:build sidecar_check

// §22.4's T1 runs the sidecar on every §4.7 leg, and the other rows read each leg through go list,
// which resolves a leg's files but compiles none of them. Every go test make check runs is on this
// host's system, so a file only windows builds, or a test only js builds, could break its leg and
// pass every row. Each leg therefore compiles here, with go list -export: every package the leg
// builds, its tests as well on a test leg, compiled and linked into nothing.
//
// cgo needs a C compiler for the leg's target, and a host has one for its own system at most. A
// darwin host compiles every darwin leg, and the ios legs through Xcode, whose absence fails them as
// it fails make size; any other host compiles the cgo legs of its own GOOS and GOARCH. A cgo leg no
// toolchain here reaches compiles with cgo off instead, which is every file of ours the leg builds
// but those behind the cgo tag, since the cgo row leaves this repository no cgo file there; std's
// and third parties' cgo halves go uncompiled. The run's report names each such leg, rather than
// passing it as compiled. Without this, a file only android builds would compile nowhere: no other
// leg has its system. Running each leg's tests is T1's runner, not this rule.

package check

import (
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

// Compiles one leg as it builds: what it ships, and on a test leg its tests too, with cgo off when
// cgoOff says this host cannot build its cgo. A finding carries the go command's own account of
// what failed. It runs off the test's goroutine, so what goes wrong comes back as a finding.
func (self *repository) compileLeg(leg *buildLeg, cgoOff bool) []string {
	directory, err := self.legDirectory(leg)
	if err != nil {
		return []string{err.Error()}
	}
	patterns, err := self.legPatterns(leg)
	if err != nil {
		return []string{err.Error()}
	}
	if len(patterns) == 0 {
		// as listLeg reads it: only an engine leg before the first engine has nothing to build
		if leg.class == classEngine {
			return nil
		}
		return []string{findingf("%s: no pattern of %v exists in %s", leg.name, leg.patterns, directory)}
	}
	environment := leg.environment()
	switch {
	case cgoOff:
		environment = append(environment, "CGO_ENABLED=0")
	case leg.cgoEnabled && leg.goos == "ios":
		environment, err = self.iosBuildEnvironment(leg)
		if err != nil {
			return []string{findingf("%s compiles only with Xcode: %v", leg.name, err)}
		}
	}
	arguments := []string{"list", "-export", "-f={{.ImportPath}}"}
	if leg.test {
		arguments = append(arguments, "-test")
	}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	if _, err := runGo(directory, environment, append(arguments, patterns...)...); err != nil {
		if cgoOff {
			return []string{findingf("%s does not compile with cgo off: %v", leg.name, err)}
		}
		return []string{findingf("%s does not compile: %v", leg.name, err)}
	}
	return nil
}

// Every leg, some at once: as it builds where this host has its toolchain, else with cgo off and a
// report line saying so.
func (self *repository) legCompileFindings(t testing.TB) []string {
	t.Helper()
	for _, leg := range self.legs {
		if !leg.compilesOn(runtime.GOOS, runtime.GOARCH) {
			self.report("%s compiles with cgo off: its cgo needs a C toolchain for %s/%s, which this %s/%s host does not have",
				leg.name, leg.goos, leg.goarch, runtime.GOOS, runtime.GOARCH)
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
			legFindings := self.compileLeg(leg, !leg.compilesOn(runtime.GOOS, runtime.GOARCH))
			func() {
				findingLock.Lock()
				defer findingLock.Unlock()
				findings = append(findings, legFindings...)
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
