//go:build sidecar_check

// The cgo row's planted violations, and §5.10's one exception.

package check

import (
	"testing"
)

// A root file that needs cgo.
const plantedCgoSource = "package sidecar\n\n// int planted(void);\nimport \"C\"\n"

func TestCgoFailsOnACgoFileInTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", plantedCgoSource)
	wantFindings(t, fixture.open().cgoSourceFindings(t), "planted.go:4: imports C")
}

// Under CGO_ENABLED=0 every CLI target drops this file, so only the syntax reading sees it.
func TestCgoFailsOnACgoFileNoLegCompiles(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/planted.go", "//go:build freebsd\n\npackage main\n\nimport \"C\"\n")
	wantFindings(t, fixture.open().cgoSourceFindings(t), "cli/planted.go:5: imports C")
}

// The name alone is no pass: §4.4 puts the keychain in cli/ or the root.
func TestCgoFailsOnAKeychainFileInTheWrongPackage(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("protocol/keychain_darwin.go", "package protocol\n\nimport \"C\"\n")
	wantFindings(t, fixture.open().cgoSourceFindings(t), "protocol/keychain_darwin.go:3: imports C")
}

func TestCgoFailsOnACgoFileOnALeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "cgo linux/amd64", "cli linux/amd64")
	fixture.write("planted.go", plantedCgoSource)
	wantFindings(t, fixture.open().cgoLegFindings(t), "cgo linux/amd64 compiles the cgo file planted.go in @module@")
}

// §5.10's file builds on darwin without a mobile tag, and the sdk's cgo darwin leg is such a build,
// so a keychain file reaching it is found: the exception is one leg, not one name.
func TestCgoFailsOnTheKeychainFileOutsideTheFallbackLeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cgo darwin/arm64", "cli darwin/arm64 keychain fallback")
	fixture.write("keychain_darwin.go", "//go:build darwin && !ios && !sdk_mobile_bind\n\npackage sidecar\n\nimport \"C\"\n")
	wantFindings(t, fixture.open().cgoLegFindings(t), "cgo darwin/arm64 compiles the cgo file keychain_darwin.go in @module@")
}

func TestCgoAllowsTheKeychainFileOnTheFallbackLeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli darwin/arm64 keychain fallback", "cli darwin/arm64", "cgo linux/amd64", "gomobile macos/arm64")
	fixture.write("cli/keychain_darwin.go", "//go:build darwin && !ios && !sdk_mobile_bind\n\npackage main\n\nimport \"C\"\n")
	repository := fixture.open()
	wantFindings(t, repository.cgoSourceFindings(t))
	wantFindings(t, repository.cgoLegFindings(t))
	fallback := repository.closure(t, repository.leg(t, "cli darwin/arm64 keychain fallback"))
	cgoFiles := 0
	for _, listed := range fallback {
		if !listed.Standard {
			cgoFiles += len(listed.CgoFiles)
		}
	}
	if cgoFiles != 1 {
		t.Errorf("the fallback leg compiled %d cgo files, want the keychain's", cgoFiles)
	}
}

// §4.7's row binds this repository's packages; a third party's file is read by a person once, in
// settings, or it fails. std's cgo is left alone, which the clean fixture's cgo legs show.
func TestCgoFailsOnANewThirdPartyCgoFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cgo linux/amd64")
	fixture.writeSibling("thirdparty/go.mod", "module example.com/thirdparty\n\ngo 1.27.3\n")
	fixture.writeSibling("thirdparty/native.go", "package thirdparty\n\nimport \"C\"\n")
	fixture.requireLocal("example.com/thirdparty", "v1.0.0", "thirdparty")
	fixture.write("planted.go", "package sidecar\n\nimport _ \"example.com/thirdparty\"\n")
	wantFindings(t, fixture.open().cgoLegFindings(t), "compiles the third-party cgo file native.go in example.com/thirdparty")

	fixture.settings.thirdPartyCgoFiles["example.com/thirdparty/native.go"] = "read by a person"
	wantFindings(t, fixture.open().cgoLegFindings(t))
}
