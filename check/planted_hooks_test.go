//go:build sidecar_check

// The planted violations of the rule that fails a release leg built with sidecar_testhooks, across
// the root and the per-package hook pairs testhook.go has other packages keep.

package check

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// The legs set GOFLAGS so each stays what it names, and that must not hide the host's tag. A tag is
// read as a whole word, quoted or not.
func TestHygieneFailsOnTheHooksTagInGoflags(t *testing.T) {
	wantFindings(t, goflagsTagFindings("here", "-trimpath -tags=other,sidecar_testhooks"), "GOFLAGS in here carries sidecar_testhooks")
	wantFindings(t, goflagsTagFindings("here", "--tags=sidecar_leaktest"), "GOFLAGS in here carries sidecar_leaktest")
	wantFindings(t, goflagsTagFindings("here", "'-tags=other sidecar_testhooks'"), "GOFLAGS in here carries sidecar_testhooks")
	wantFindings(t, goflagsTagFindings("here", "-trimpath -tags=sidecar_testhooks_extra"))
	wantFindings(t, goflagsTagFindings("here", ""))
}

// This test's environment with none of the host's go configuration in it: no GOFLAGS, GOENV or
// GOROOT, and a home of its own, which holds the default go env file. Then extra.
//
// The home starts with go telemetry off. Otherwise the go command starts a telemetry process that
// outlives it and writes under the home, which races the home's cleanup when the test ends.
func plantedHostEnvironment(t *testing.T, extra ...string) []string {
	t.Helper()
	environment := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains([]string{"GOFLAGS", "GOENV", "GOROOT", "HOME", "XDG_CONFIG_HOME"}, name) {
			environment = append(environment, entry)
		}
	}
	home := t.TempDir()
	// os.UserConfigDir's answer for that home on darwin, then on every other unix
	for _, configDir := range []string{filepath.Join(home, "Library", "Application Support"), filepath.Join(home, ".config")} {
		telemetryDir := filepath.Join(configDir, "go", "telemetry")
		if err := os.MkdirAll(telemetryDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(telemetryDir, "mode"), []byte("off"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return append(append(environment, "HOME="+home), extra...)
}

// A go env file holding content, as go env -w leaves one.
func plantedGoEnvFile(t *testing.T, filePath string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The control: a host whose GOFLAGS carry other tags, in every place, passes.
func TestHygieneAllowsAHostWhoseGoflagsCarryNoUnshippableTag(t *testing.T) {
	repository := newFixture(t).open()
	goEnvPath := filepath.Join(t.TempDir(), "env")
	plantedGoEnvFile(t, goEnvPath, "GOFLAGS=-tags=other\n")
	wantFindings(t, repository.hostGoflagsFindings(plantedHostEnvironment(t, "GOENV="+goEnvPath, "GOFLAGS=-trimpath -tags=another")))
}

func TestHygieneFailsOnTheHooksTagInTheGoflagsVariable(t *testing.T) {
	repository := newFixture(t).open()
	wantFindings(t, repository.hostGoflagsFindings(plantedHostEnvironment(t, "GOFLAGS=-tags=sidecar_testhooks")),
		"GOFLAGS in the environment carries sidecar_testhooks")
}

// go env -w GOFLAGS=-tags=sidecar_testhooks: every build on this host carries the tag, and the
// variable says nothing.
func TestHygieneFailsOnTheHooksTagInTheGoEnvFile(t *testing.T) {
	repository := newFixture(t).open()
	goEnvPath := filepath.Join(t.TempDir(), "env")
	plantedGoEnvFile(t, goEnvPath, "GOFLAGS=-tags=sidecar_testhooks\n")
	wantFindings(t, repository.hostGoflagsFindings(plantedHostEnvironment(t, "GOENV="+goEnvPath)),
		"GOFLAGS in the go env file "+goEnvPath+" carries sidecar_testhooks")
}

// lowgo sets the variable, which hides the file from the go command make check runs under, and not
// from a release step that runs without lowgo.
func TestHygieneFailsOnTheHooksTagInAGoEnvFileTheVariableHides(t *testing.T) {
	repository := newFixture(t).open()
	goEnvPath := filepath.Join(t.TempDir(), "env")
	plantedGoEnvFile(t, goEnvPath, "GOFLAGS=-tags=sidecar_testhooks\n")
	environment := plantedHostEnvironment(t, "GOENV="+goEnvPath, "GOFLAGS=-trimpath")
	effective, err := runGo(repository.moduleDirectory, append(slices.Clone(environment), "GOTOOLCHAIN=local"), "env", "GOFLAGS")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(effective)) != "-trimpath" {
		t.Fatalf("the variable did not hide the file: go env GOFLAGS is %q", effective)
	}
	wantFindings(t, repository.hostGoflagsFindings(environment), "GOFLAGS in the go env file "+goEnvPath+" carries sidecar_testhooks")
}

// GOENV moved or off here does not move it for a release step that leaves GOENV alone.
func TestHygieneFailsOnTheHooksTagInTheDefaultGoEnvFile(t *testing.T) {
	repository := newFixture(t).open()
	environment := plantedHostEnvironment(t, "GOENV=off")
	defaultPath, err := runGo(repository.moduleDirectory, append(slices.Clone(environment), "GOTOOLCHAIN=local", "GOENV="), "env", "GOENV")
	if err != nil {
		t.Fatal(err)
	}
	goEnvPath := strings.TrimSpace(string(defaultPath))
	plantedGoEnvFile(t, goEnvPath, "GOFLAGS=-tags=sidecar_leaktest\n")
	wantFindings(t, repository.hostGoflagsFindings(environment), "GOFLAGS in the go env file "+goEnvPath+" carries sidecar_leaktest")
}

// GOROOT's go.env is read beneath every user file, GOENV=off included.
func TestHygieneFailsOnTheHooksTagInGorootsGoEnv(t *testing.T) {
	repository := newFixture(t).open()
	goroot := t.TempDir()
	plantedGoEnvFile(t, filepath.Join(goroot, "go.env"), "GOFLAGS=-tags=sidecar_testhooks\n")
	wantFindings(t, repository.hostGoflagsFindings(plantedHostEnvironment(t, "GOROOT="+goroot, "GOENV=off")),
		"GOFLAGS in "+filepath.Join(goroot, "go.env")+" carries sidecar_testhooks")
}

// A place this cannot read has not passed.
func TestHygieneFailsOnAGoflagsSourceItCannotRead(t *testing.T) {
	repository := newFixture(t).open()
	wantFindings(t, repository.hostGoflagsFindings(plantedHostEnvironment(t, "GOROOT="+filepath.Join(t.TempDir(), "absent"))),
		"reading where this host's go command takes GOFLAGS from")
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

// The go command still honors a // +build line in a file with no //go:build line, and this one ships
// on every linux leg, so the rules refuse to read the tree rather than read the file as unconstrained.
func TestHygieneFailsOnAPlusBuildLineTheRulesDoNotRead(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.write("planted.go", "// +build sidecar_testhooks linux\n\npackage sidecar\n\nfunc planted() {}\n")
	repository := fixture.open()
	closure := repository.closure(t, repository.legs[0])
	rootIndex := slices.IndexFunc(closure, func(listed *listedPackage) bool { return listed.ImportPath == repository.modulePath })
	if rootIndex < 0 || !slices.Contains(closure[rootIndex].GoFiles, "planted.go") {
		t.Fatalf("the linux leg does not link planted.go, so this plants nothing")
	}
	_, err := repository.sourceFilesOnce()
	if err == nil || !strings.Contains(err.Error(), "planted.go") || !strings.Contains(err.Error(), "// +build line with no //go:build line") {
		t.Errorf("the tree read as %v", err)
	}
	// with the //go:build line gofmt writes beside it, the hook file rule reads the file and fails it
	fixture.write("planted.go", "//go:build sidecar_testhooks || linux\n// +build sidecar_testhooks linux\n\npackage sidecar\n\nfunc planted() {}\n")
	wantFindings(t, fixture.open().legHookFileFindings(t), "root linux/amd64 links planted.go in @module@, which answers to sidecar_testhooks")
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

// A field of the hook's name is a variable by another route: anything in the package can set it in
// a release, and a call through it reaches no pair.
func TestHygieneFailsOnAHookHeldInAField(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.write("evsservice/planted.go", "package evsservice\n\ntype keys struct {\n\ttestHookSecret func(kind string, secret []byte)\n}\n\nfunc (self *keys) derive(secret []byte) {\n\tself.testHookSecret(\"k\", secret)\n}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/planted.go: testHookSecret is a field or parameter, so it can hold something in a release build")
}

// So is a parameter: the caller decides what the hook is.
func TestHygieneFailsOnAHookPassedAsAParameter(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.write("evsservice/planted.go", "package evsservice\n\nfunc derive(secret []byte, testHookBarrier func(name string, key string)) {\n\ttestHookBarrier(\"derive\", \"\")\n}\n")
	wantFindings(t, fixture.open().hookPairFindings(t), "evsservice/planted.go: testHookBarrier is a field or parameter, so it can hold something in a release build")
}

// And a local of the hook's name shadows the package's pair for every call after it.
func TestHygieneFailsOnAHookShadowedByALocal(t *testing.T) {
	fixture := newHookFixture(t)
	fixture.write("evsservice/planted.go", "package evsservice\n\nfunc derive(secret []byte) {\n\ttestHookSecret := func(kind string, secret []byte) {\n\t\tprintln(kind)\n\t}\n\ttestHookSecret(\"k\", secret)\n\tvar testHookBarrier = func(name string, key string) {}\n\ttestHookBarrier(\"derive\", \"\")\n}\n")
	wantFindings(t, fixture.open().hookPairFindings(t),
		"evsservice/planted.go: testHookBarrier is a local variable, so it can hold something in a release build",
		"evsservice/planted.go: testHookSecret is a local variable, so it can hold something in a release build")
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

// The control: a host whose go configuration adds no unshippable tag builds a ur that says none.
func TestHygieneAllowsTheUrThisHostBuilds(t *testing.T) {
	fixture := newFixture(t)
	wantFindings(t, hostBinaryFindings(t, filepath.Join(fixture.directory, "sidecar", "cli"), plantedHostEnvironment(t, "GOFLAGS=-tags=other")))
}

// The ur make check builds is built as this host builds, so a go env file's tag is in it. Built
// under the rules' own environment, as it was, it could never carry one.
func TestHygieneFailsOnAUrThisHostBuildsWithTheTag(t *testing.T) {
	fixture := newFixture(t)
	goEnvPath := filepath.Join(t.TempDir(), "env")
	plantedGoEnvFile(t, goEnvPath, "GOFLAGS=-tags=sidecar_testhooks\n")
	wantFindings(t, hostBinaryFindings(t, filepath.Join(fixture.directory, "sidecar", "cli"), plantedHostEnvironment(t, "GOENV="+goEnvPath)),
		"was built with sidecar_testhooks")
}

// A go command that adds the tag itself leaves GOFLAGS clean everywhere, and its artifact still
// says how it was built.
func TestHygieneFailsOnAGoCommandThatAddsTheTag(t *testing.T) {
	fixture := newFixture(t)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	wrapperDirectory := t.TempDir()
	wrapper := "#!/bin/sh\nif [ \"$1\" = build ]; then\n\tshift\n\texec " + realGo + " build -tags=sidecar_leaktest \"$@\"\nfi\nexec " + realGo + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(wrapperDirectory, "go"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	environment := plantedHostEnvironment(t)
	repository := fixture.open()
	wantFindings(t, repository.hostGoflagsFindings(environment))
	wantFindings(t, hostBinaryFindings(t, filepath.Join(fixture.directory, "sidecar", "cli"), environment), "was built with sidecar_leaktest")
}

// A host whose go configuration cannot build ur has shown nothing about what it builds.
func TestHygieneFailsOnAUrThisHostCannotBuild(t *testing.T) {
	fixture := newFixture(t)
	wantFindings(t, hostBinaryFindings(t, filepath.Join(fixture.directory, "sidecar", "cli"), plantedHostEnvironment(t, "GOFLAGS=-sidecar-check-no-such-flag")),
		"building ur as this host builds")
}

// The root's protocol package as a leg lists it on a release branch, where cli takes the root at
// its tag: a copy in a module cache of the checkout's files, after edit when one is given.
func plantedTaggedCopy(t *testing.T, repository *repository, edit func(directory string)) *listedPackage {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "modcache", "root@v2026.11.6-1234567")
	directory := filepath.Join(cache, "protocol")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repository.moduleDirectory, "protocol", "doc.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "doc.go"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(directory)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	listed := &listedPackage{ImportPath: sidecarBasePath + releaseSuffix + "/protocol", Name: "protocol", Dir: directory}
	listed.Module = &struct {
		Path    string
		Version string
		Dir     string
	}{Path: sidecarBasePath + releaseSuffix, Version: "v2026.11.6-1234567", Dir: cache}
	for _, entry := range entries {
		listed.GoFiles = append(listed.GoFiles, entry.Name())
	}
	return listed
}

// What the source walks read, by path, as the rule keys it.
func sourceFilesByPath(t *testing.T, repository *repository) map[string]*sourceFile {
	t.Helper()
	bySourcePath := map[string]*sourceFile{}
	for _, file := range repository.sourceFiles(t) {
		bySourcePath[file.path] = file
	}
	return bySourcePath
}

// The tag holds this checkout's tree, so a copy of it reads as the checkout and passes.
func TestHygieneReadsATaggedCopyOfThisRepositoryAsTheCheckout(t *testing.T) {
	repository := newFixture(t).open()
	listed := plantedTaggedCopy(t, repository, nil)
	failFindings(t, "hygiene", repository.linkedFileFindings(t, "cli linux/amd64", listed, sourceFilesByPath(t, repository)))
}

// A copy that is not the checkout's tree is a leg linking what no rule here read.
func TestHygieneFailsOnATaggedCopyThatIsNotTheCheckouts(t *testing.T) {
	repository := newFixture(t).open()
	listed := plantedTaggedCopy(t, repository, func(directory string) {
		if err := os.WriteFile(filepath.Join(directory, "doc.go"), []byte("//go:build "+sidecarTestHooksTag+" || !"+sidecarTestHooksTag+"\n\npackage protocol\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	wantFindings(t, repository.linkedFileFindings(t, "cli linux/amd64", listed, sourceFilesByPath(t, repository)),
		"cli linux/amd64 links doc.go in @module@/v2026/protocol from "+listed.Dir+", which is not this checkout's protocol/doc.go")
}

func TestHygieneFailsOnATaggedCopyHoldingAFileTheCheckoutLacks(t *testing.T) {
	repository := newFixture(t).open()
	listed := plantedTaggedCopy(t, repository, func(directory string) {
		if err := os.WriteFile(filepath.Join(directory, "extra.go"), []byte("package protocol\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	wantFindings(t, repository.linkedFileFindings(t, "cli linux/amd64", listed, sourceFilesByPath(t, repository)),
		"cli linux/amd64 links extra.go in @module@/v2026/protocol, which no source rule read")
}
