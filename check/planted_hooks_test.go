//go:build sidecar_check

// The planted violations of the rule that fails a release leg built with sidecar_testhooks, across
// the root and the per-package hook pairs testhook.go has other packages keep.

package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A package's pair, as testhook.go tells a package to keep it.
const (
	packageHookUntagged = `//go:build !sidecar_testhooks

package evsservice

func testHookSecret(kind string, secret []byte) {}

func testHookBarrier(name string, key string) {}
`
	packageHookTagged = `//go:build sidecar_testhooks

package evsservice

import "@module@"

func testHookSecret(kind string, secret []byte) {
	sidecar.TestHookSecret(kind, secret)
}

func testHookBarrier(name string, key string) {
	sidecar.TestHookBarrier(name, key)
}
`
)

// A fixture whose evsservice keeps a correct pair.
func newHookFixture(t *testing.T) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.write("evsservice/engine.go", "package evsservice\n\nimport _ \"@module@\"\n")
	fixture.write("evsservice/testhook.go", packageHookUntagged)
	fixture.write("evsservice/testhook_enabled.go", packageHookTagged)
	return fixture
}

// The control: the root's pair and a correct package pair pass every reading.
func TestHygieneAllowsAPackagesHookPair(t *testing.T) {
	fixture := newHookFixture(t)
	repository := fixture.open()
	wantFindings(t, repository.hookPairFindings(t))
	wantFindings(t, repository.legHookFileFindings(t))
	wantFindings(t, repository.legTagFindings())
}

func TestHygieneFailsOnAReleaseLegWithTheHooksTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64", "tests linux/amd64")
	for _, leg := range fixture.legs {
		leg.tags = append(leg.tags, sidecarTestHooksTag)
	}
	// the test leg may carry the tag: that is how the hooks are exercised
	wantFindings(t, fixture.open().legTagFindings(), "cli linux/amd64 is a release leg built with sidecar_testhooks")
}

func TestHygieneFailsOnAReleaseLegWithTheLeakTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.legs[0].tags = append(fixture.legs[0].tags, sidecarLeakTestTag)
	wantFindings(t, fixture.open().legTagFindings(), "cli linux/amd64 is a release leg built with sidecar_leaktest")
}

// The legs clear GOFLAGS so each stays what it names, and that must not hide the caller's tag.
func TestHygieneFailsOnTheHooksTagInGoflags(t *testing.T) {
	wantFindings(t, callerGoflagsFindings("-trimpath -tags=other,sidecar_testhooks"), "GOFLAGS carries sidecar_testhooks")
	wantFindings(t, callerGoflagsFindings("--tags=sidecar_leaktest"), "GOFLAGS carries sidecar_leaktest")
	wantFindings(t, callerGoflagsFindings("'-tags=other sidecar_testhooks'"), "GOFLAGS carries sidecar_testhooks")
	wantFindings(t, callerGoflagsFindings("-trimpath -tags=sidecar_testhooks_extra"))
	wantFindings(t, callerGoflagsFindings(""))
}

func TestHygieneFailsOnALegLinkingTheRootHookFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.legs[0].tags = append(fixture.legs[0].tags, sidecarTestHooksTag)
	wantFindings(t, fixture.open().legHookFileFindings(t), "cli linux/amd64 links testhook_enabled.go in @module@, which answers to sidecar_testhooks")
}

// The per-package half, read off the leg's own file list, whatever the file is called.
func TestHygieneFailsOnALegLinkingAPackagesHookFile(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.keepLegs("engines linux/amd64")
	fixture.legs[0].tags = append(fixture.legs[0].tags, sidecarTestHooksTag)
	fixture.remove("evsservice/testhook_enabled.go")
	fixture.write("evsservice/hooks_on.go", packageHookTagged)
	wantFindings(t, fixture.open().legHookFileFindings(t),
		"engines linux/amd64 links testhook_enabled.go in @module@, which answers",
		"engines linux/amd64 links hooks_on.go in @module@/evsservice, which answers")
}

// No leg asks for the tag here, and the file still ships: || lets it in.
func TestHygieneFailsOnAHookFileAnotherConstraintLetsIn(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.keepLegs("engines linux/amd64")
	fixture.edit("evsservice/testhook_enabled.go", "//go:build sidecar_testhooks", "//go:build sidecar_testhooks || linux")
	fixture.remove("evsservice/testhook.go")
	wantFindings(t, fixture.open().legHookFileFindings(t), "links testhook_enabled.go in @module@/evsservice, which answers to sidecar_testhooks")
}

func TestHygieneFailsOnAPackagesHookWithABody(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook.go", "func testHookSecret(kind string, secret []byte) {}", "func testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/testhook.go: testHookSecret has a body in the untagged build")
}

// Halves split by system are each one system's release, so each is held to the rule. The empty one
// is read last here, which is the order a rule keeping one half per name would be fooled by.
func TestHygieneFailsOnAHookBodyBesideAnEmptyHalf(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.remove("evsservice/testhook.go")
	linuxHalf := strings.Replace(packageHookUntagged, "!sidecar_testhooks", "!sidecar_testhooks && linux", 1)
	linuxHalf = strings.Replace(linuxHalf, "func testHookSecret(kind string, secret []byte) {}", "func testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}", 1)
	fixture.write("evsservice/testhook_linux.go", linuxHalf)
	fixture.write("evsservice/testhook_other.go", strings.Replace(packageHookUntagged, "!sidecar_testhooks", "!sidecar_testhooks && !linux", 1))
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/testhook_linux.go: testHookSecret has a body in the untagged build")
}

// The same on the tagged side: one half forwarding says nothing of the other.
func TestHygieneFailsOnATaggedHalfBesideOneForwarding(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.remove("evsservice/testhook_enabled.go")
	linuxHalf := strings.Replace(packageHookTagged, "sidecar_testhooks", "sidecar_testhooks && linux", 1)
	linuxHalf = strings.Replace(linuxHalf, "sidecar.TestHookSecret(kind, secret)", "println(kind)", 1)
	fixture.write("evsservice/testhook_enabled_linux.go", linuxHalf)
	fixture.write("evsservice/testhook_enabled_other.go", strings.Replace(packageHookTagged, "sidecar_testhooks", "sidecar_testhooks && !linux", 1))
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/testhook_enabled_linux.go: testHookSecret does not forward to the root's TestHookSecret")
}

// The control: halves split by system pass when each one is right.
func TestHygieneAllowsHookHalvesSplitBySystem(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.remove("evsservice/testhook.go")
	fixture.remove("evsservice/testhook_enabled.go")
	fixture.write("evsservice/testhook_linux.go", strings.Replace(packageHookUntagged, "!sidecar_testhooks", "!sidecar_testhooks && linux", 1))
	fixture.write("evsservice/testhook_other.go", strings.Replace(packageHookUntagged, "!sidecar_testhooks", "!sidecar_testhooks && !linux", 1))
	fixture.write("evsservice/testhook_enabled_linux.go", strings.Replace(packageHookTagged, "sidecar_testhooks", "sidecar_testhooks && linux", 1))
	fixture.write("evsservice/testhook_enabled_other.go", strings.Replace(packageHookTagged, "sidecar_testhooks", "sidecar_testhooks && !linux", 1))
	wantFindings(t, fixture.open().hookPairFindings(t))
}

// A declaration with no body runs what go:linkname or assembly puts behind it, which is not empty.
func TestHygieneFailsOnAHookWithNoBodyOfItsOwn(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook.go", "func testHookSecret(kind string, secret []byte) {}", "func testHookSecret(kind string, secret []byte)")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/testhook.go: testHookSecret has no body of its own in the untagged build")
}

// A method of the hook's name is a hook no pair rule reads, whatever its receiver, and it needs no tag
// to reach a release.
func TestHygieneFailsOnAHookDeclaredAsAMethod(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.write("evsservice/planted.go", "package evsservice\n\ntype keys struct{}\n\nfunc (self *keys) testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/planted.go: testHookSecret is a method, so no pair holds it empty in a release build")
}

// The same for what may only exist under the tag: a method can install hooks as well as a function.
func TestHygieneFailsOnAnEntryPointDeclaredAsAMethod(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\ntype keys struct{}\n\nfunc (self *keys) SetTestHooks(hooks any) {}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "planted.go: SetTestHooks exists outside the root's tagged file")
}

// With no constraint at all the one body is in every build, the release's included.
func TestHygieneFailsOnAPackagesHookWithNoTag(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook.go", "//go:build !sidecar_testhooks\n\n", "")
	wantFindings(t, fixture.open().hookPairFindings(t),
		"evsservice keeps testHookBarrier with no empty half",
		"evsservice keeps testHookSecret with no empty half",
		"evsservice/testhook.go: testHookBarrier builds with and without sidecar_testhooks",
		"evsservice/testhook.go: testHookSecret builds with and without sidecar_testhooks")
}

// A function variable can be set at run time, in a release, and looks empty until it is.
func TestHygieneFailsOnAPackagesHookHeldInAVariable(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook.go", "func testHookSecret(kind string, secret []byte) {}", "var testHookSecret = func(kind string, secret []byte) {}")
	wantFindings(t, fixture.open().hookPairFindings(t),
		"evsservice keeps testHookSecret with no empty half",
		"evsservice/testhook.go: testHookSecret is not a function")
}

func TestHygieneFailsOnAPackagesHalfMissing(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.remove("evsservice/testhook_enabled.go")
	wantFindings(t, fixture.open().hookPairFindings(t),
		"evsservice keeps testHookBarrier with no half under sidecar_testhooks",
		"evsservice keeps testHookSecret with no half under sidecar_testhooks")
}

// A package's tagged half forwards and keeps nothing of its own: the root is where a key copy is
// made and where the harness looks.
func TestHygieneFailsOnAPackagesTaggedHalfNotForwarding(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook_enabled.go", "sidecar.TestHookSecret(kind, secret)", "println(kind)")
	wantFindings(t, fixture.open().hookPairFindings(t), "testHookSecret does not forward to the root's TestHookSecret")
}

// A package in a nested module keeps its pair the same way, and the walk crosses modules.
func TestHygieneFailsOnAHookPairInANestedModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("smtpproof/testhook.go", "//go:build !sidecar_testhooks\n\npackage smtpproof\n\nfunc testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}\n\nfunc testHookBarrier(name string, key string) {}\n")
	findings := fixture.open().hookPairFindings(t)
	wantFindings(t, findings,
		"smtpproof keeps testHookBarrier with no half under sidecar_testhooks",
		"smtpproof keeps testHookSecret with no half under sidecar_testhooks",
		"smtpproof/testhook.go: testHookSecret has a body in the untagged build")
}

func TestHygieneFailsOnAnEntryPointWithoutTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\nfunc SetTestHooks(hooks any) {}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "planted.go: SetTestHooks exists outside the root's tagged file")
}

// testhook.go has a package keep an unexported pair; only the root exports entry points.
func TestHygieneFailsOnAnEntryPointOutsideTheRoot(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.write("evsservice/planted.go", "//go:build sidecar_testhooks\n\npackage evsservice\n\ntype TestHooks struct{}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/planted.go: TestHooks exists outside the root's tagged file")
}

// A pair and an installer of device's own, as testhook.go has it: nothing to forward to, and no finding.
func TestHygieneAllowsDevicesOwnInstaller(t *testing.T) {
	fixture := newFixture(t)
	writeDeviceHooks(fixture)
	wantFindings(t, fixture.open().hookPairFindings(t))
}

// Its installer is the two names it needs: the entry points stay the root's.
func TestHygieneFailsOnADeviceEntryPoint(t *testing.T) {
	fixture := newFixture(t)
	writeDeviceHooks(fixture)
	fixture.write("device/planted.go", "//go:build sidecar_testhooks\n\npackage device\n\nfunc TestHookSecret(kind string, secret []byte) {}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "device/planted.go: TestHookSecret exists outside the root's tagged file")
}

// The exception is for the tagged file: an untagged installer ships.
func TestHygieneFailsOnADeviceInstallerWithoutTheTag(t *testing.T) {
	fixture := newFixture(t)
	writeDeviceHooks(fixture)
	fixture.edit("device/testhook_enabled.go", "//go:build sidecar_testhooks", "//go:build !sidecar_http")
	findings := fixture.open().hookPairFindings(t)
	wantFindings(t, findings,
		"device keeps testHookBarrier with no half under sidecar_testhooks",
		"device keeps testHookSecret with no half under sidecar_testhooks",
		"device/testhook_enabled.go: SetTestHooks exists outside the root's tagged file",
		"device/testhook_enabled.go: TestHooks exists outside the root's tagged file",
		"device/testhook_enabled.go: testHookBarrier builds with and without sidecar_testhooks",
		"device/testhook_enabled.go: testHookSecret builds with and without sidecar_testhooks")
}

// And its empty half stays empty, as every other package's does.
func TestHygieneFailsOnADeviceHookWithABody(t *testing.T) {
	fixture := newFixture(t)
	writeDeviceHooks(fixture)
	fixture.edit("device/testhook.go", "func testHookSecret(kind string, secret []byte) {}", "func testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}")
	wantFindings(t, fixture.open().hookPairFindings(t), "device/testhook.go: testHookSecret has a body in the untagged build")
}

func writeDeviceHooks(fixture *fixture) {
	fixture.write("device/testhook.go", "//go:build !sidecar_testhooks\n\npackage device\n\nfunc testHookSecret(kind string, secret []byte) {}\n\nfunc testHookBarrier(name string, key string) {}\n")
	fixture.write("device/testhook_enabled.go", "//go:build sidecar_testhooks\n\npackage device\n\ntype TestHooks struct{}\n\nfunc SetTestHooks(hooks *TestHooks) {}\n\nfunc testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}\n\nfunc testHookBarrier(name string, key string) {\n\tprintln(name)\n}\n")
}

func TestHygieneFailsOnAHookWithAnotherSignature(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.edit("evsservice/testhook.go", "func testHookBarrier(name string, key string) {}", "func testHookBarrier(name string) {}")
	wantFindings(t, fixture.open().hookPairFindings(t), "testHookBarrier(name string) is not §22.4's signature")
}

// go build follows an import into testdata, where the walks do not go, so a leg can link a file no
// source rule has read. That fails whatever the file says: the rules cannot vouch for it.
func TestHygieneFailsOnALegLinkingAFileTheRulesSkip(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.write("testdata/planted/planted.go", "package planted\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/testdata/planted\"\n")
	wantFindings(t, fixture.open().legHookFileFindings(t), "cli linux/amd64 links planted.go in @module@/testdata/planted, which no source rule read")
}

// A cgo file is compiled as surely as any other, and the keychain's is the one a shipped leg holds,
// so its constraint is read as every other file's is.
func TestHygieneFailsOnACgoFileAnsweringToTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli darwin/arm64 keychain fallback")
	fixture.write("cli/keychain_darwin.go", "//go:build (darwin && !ios && !sdk_mobile_bind) || sidecar_testhooks\n\npackage main\n\nimport \"C\"\n")
	wantFindings(t, fixture.open().legHookFileFindings(t),
		"cli darwin/arm64 keychain fallback links keychain_darwin.go in @module@/cli, which answers to sidecar_testhooks")
}

// The same for a cgo file in a directory the walks skip.
func TestHygieneFailsOnALegLinkingACgoFileTheRulesSkip(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli darwin/arm64 keychain fallback")
	fixture.write("testdata/planted/keychain_darwin.go", "package planted\n\nimport \"C\"\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/testdata/planted\"\n")
	wantFindings(t, fixture.open().legHookFileFindings(t),
		"cli darwin/arm64 keychain fallback links keychain_darwin.go in @module@/testdata/planted, which no source rule read")
}

func TestHygieneFailsOnAMakefileBuildingWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("Makefile", "# tests run under sidecar_testhooks too\ncheck:\n\t$(GO) test -tags sidecar_testhooks .\n\tgo test -tags sidecar_leaktest .\n")
	fixture.write("cli/Makefile", "build:\n\tenv CGO_ENABLED=0 go build -tags sidecar_testhooks -o ur\n\t$(GO) build -tags sidecar_leaktest -o ur\n\tGOFLAGS=-tags=sidecar_testhooks gomobile bind\n")
	wantFindings(t, fixture.open().makefileTagFindings(t),
		"cli/Makefile:2: builds with sidecar_testhooks",
		"cli/Makefile:3: builds with sidecar_leaktest",
		"cli/Makefile:4: builds with sidecar_testhooks")
}

// go test excuses its own command and no other on the line, on either side of it.
func TestHygieneFailsOnAMakefileBuildingBesideATest(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/Makefile", "build:\n\tgo build -tags sidecar_testhooks -o ur . && go test .\n\t$(GO) test -tags sidecar_testhooks . ; go build -tags sidecar_leaktest -o ur .\n\tgo test -tags sidecar_testhooks . | tee test.log\n")
	wantFindings(t, fixture.open().makefileTagFindings(t),
		"cli/Makefile:2: builds with sidecar_testhooks",
		"cli/Makefile:3: builds with sidecar_leaktest")
}

// Each leg that ships is built somewhere, and sdk's c-shared and wasm builds and server's services
// are as much a release as gomobile's.
func TestHygieneFailsOnAConsumerMakefileBuildingWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("sdk/cgo/Makefile", "build:\n\tgo build -buildmode=c-shared -tags sidecar_testhooks\n")
	fixture.writeSibling("sdk/js/Makefile", "build:\n\tGOOS=js GOARCH=wasm go build -tags sidecar_leaktest\n")
	fixture.writeSibling("server/cli/api/Makefile", "build:\n\tgo build -tags sidecar_testhooks\n")
	wantFindings(t, fixture.open().makefileTagFindings(t),
		"sdk/cgo/Makefile:2: builds with sidecar_testhooks",
		"sdk/js/Makefile:2: builds with sidecar_leaktest",
		"server/cli/api/Makefile:2: builds with sidecar_testhooks")
}

// A build this rule cannot read has not been shown clean.
func TestHygieneFailsOnAMissingConsumerMakefile(t *testing.T) {
	fixture := newFixture(t)
	if err := os.Remove(filepath.Join(fixture.directory, "server", "cli", "api", "Makefile")); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, fixture.open().makefileTagFindings(t), "no Makefile under server/cli")
}

// gomobile's legs are built by sdk's Makefile, and the leg table here would never see this.
func TestHygieneFailsOnGomobileBindingWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeSibling("sdk/build/Makefile", "build_ios:\n\tgomobile bind -tags sdk_mobile_bind,sidecar_testhooks\n")
	findings := fixture.open().makefileTagFindings(t)
	wantFindings(t, findings, "Makefile:2: builds with sidecar_testhooks")
}

// Builds the fixture's ur, with or without the tag, as a release step would.
func buildFixtureBinary(t *testing.T, fixture *fixture, tags string) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "ur")
	arguments := []string{"build", "-o", binaryPath}
	if tags != "" {
		arguments = append(arguments, "-tags="+tags)
	}
	if _, err := runGo(filepath.Join(fixture.directory, "sidecar", "cli"), goEnvironment("CGO_ENABLED=0"), append(arguments, ".")...); err != nil {
		t.Fatal(err)
	}
	return binaryPath
}

// The artifact says how it was built, whatever config produced it, and with -s and -w too.
func TestHygieneFailsOnABinaryBuiltWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	wantFindings(t, releaseBinaryFindings(buildFixtureBinary(t, fixture, "")))
	wantFindings(t, releaseBinaryFindings(buildFixtureBinary(t, fixture, "other,"+sidecarTestHooksTag)), "was built with sidecar_testhooks")
}

// An unreadable artifact has not passed.
func TestHygieneFailsOnABinaryItCannotRead(t *testing.T) {
	fixture := newFixture(t)
	wantFindings(t, releaseBinaryFindings(filepath.Join(fixture.directory, "sidecar", "go.mod")), "go.mod")
}
