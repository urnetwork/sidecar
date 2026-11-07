//go:build sidecar_check

// make check also runs at release (§4.7), from a tree that does not look like this one: the root
// module is .../sidecar/v2026 in v2026/, smtpproof is .../sidecar/smtpproof/v2026 in smtpproof/v2026/,
// cli and mlsinterop stay put, and every quoted path of ours has been rewritten (§4.9). These apply
// build/all/run.sh's transformation to a fixture and read the result, so the rules are shown to work
// where they will next be run. A real dry run of the same steps over this tree is the release
// fixture's job (§22.4), which the consumer wiring brings.

package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The year in the release's module paths.
const releaseSuffix = "/v2026"

// The go_mod_fork steps, in the order §4.9 gives them, on connect and glog as earlier release steps
// leave them and on this repository: every module's quoted paths rewritten, smtpproof's before the
// root's, each tree moved into v2026/ beside its nested modules, and the relative replaces rebased.
// connect and glog keep a local replace here, where a release has their tags in a proxy.
func (self *fixture) toRelease() {
	self.t.Helper()
	top := filepath.Join(self.directory, "sidecar")
	smtpproofPath := sidecarBasePath + "/smtpproof"
	version := "@v2026.11.6"

	rewrite := func(directory string, modulePaths ...string) {
		err := filepath.WalkDir(directory, func(walkPath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			if !strings.HasSuffix(entry.Name(), ".go") && entry.Name() != "Makefile" {
				return nil
			}
			data, err := os.ReadFile(walkPath)
			if err != nil {
				return err
			}
			content := string(data)
			for _, modulePath := range modulePaths {
				content = releaseRewritePath(content, modulePath, releaseSuffix)
			}
			return os.WriteFile(walkPath, []byte(content), 0o600)
		})
		if err != nil {
			self.t.Fatal(err)
		}
	}
	rewrite(filepath.Join(self.directory, "glog"), glogBasePath)
	rewrite(filepath.Join(self.directory, "connect"), connectBasePath, glogBasePath)
	rewrite(top, smtpproofPath, sidecarBasePath, connectBasePath, glogBasePath)

	// moves a tree into v2026/, leaving what holds its own go.mod where it is
	move := func(directory string) {
		versioned := filepath.Join(directory, strings.TrimPrefix(releaseSuffix, "/"))
		entries, err := os.ReadDir(directory)
		if err != nil {
			self.t.Fatal(err)
		}
		if err := os.Mkdir(versioned, 0o700); err != nil {
			self.t.Fatal(err)
		}
		for _, entry := range entries {
			if _, err := os.Stat(filepath.Join(directory, entry.Name(), "go.mod")); err == nil {
				continue
			}
			if err := os.Rename(filepath.Join(directory, entry.Name()), filepath.Join(versioned, entry.Name())); err != nil {
				self.t.Fatal(err)
			}
		}
	}
	move(filepath.Join(self.directory, "glog"))
	move(filepath.Join(self.directory, "connect"))
	move(top)
	move(filepath.Join(top, "smtpproof"))

	edit := func(goModPath string, arguments ...string) {
		if _, err := runGo(filepath.Dir(goModPath), goEnvironment(), append(append([]string{"mod", "edit"}, arguments...), goModPath)...); err != nil {
			self.t.Fatal(err)
		}
	}
	edit(filepath.Join(self.directory, "glog", "v2026", "go.mod"), "-module="+glogBasePath+releaseSuffix)
	edit(filepath.Join(self.directory, "connect", "v2026", "go.mod"), "-module="+connectBasePath+releaseSuffix,
		"-droprequire="+glogBasePath, "-require="+glogBasePath+releaseSuffix+version)

	// the sibling edits of a module whose directory climbs to the siblings with climbs
	siblings := func(climbs string) []string {
		return []string{
			"-droprequire=" + connectBasePath, "-droprequire=" + glogBasePath,
			"-dropreplace=" + connectBasePath, "-dropreplace=" + glogBasePath,
			"-require=" + connectBasePath + releaseSuffix + version, "-require=" + glogBasePath + releaseSuffix + version,
			"-replace=" + connectBasePath + releaseSuffix + "=" + climbs + "connect/v2026",
			"-replace=" + glogBasePath + releaseSuffix + "=" + climbs + "glog/v2026",
			"-replace=" + sctpBasePath + "=" + climbs + "connect/sctp",
			"-replace=" + gvisorBasePath + "=" + climbs + "gvisor",
		}
	}
	edit(filepath.Join(top, "v2026", "go.mod"), append(siblings("../../"), "-module="+sidecarBasePath+releaseSuffix)...)
	edit(filepath.Join(top, "smtpproof", "v2026", "go.mod"), append(siblings("../../../"),
		"-module="+smtpproofPath+releaseSuffix, "-dropreplace="+sidecarBasePath, "-replace="+sidecarBasePath+releaseSuffix+"=../../v2026")...)
	edit(filepath.Join(top, "mlsinterop", "go.mod"), append(siblings("../../"),
		"-dropreplace="+sidecarBasePath, "-replace="+sidecarBasePath+releaseSuffix+"=../v2026")...)
	edit(filepath.Join(top, "cli", "go.mod"), append(siblings("../../"),
		"-droprequire="+sidecarBasePath, "-droprequire="+smtpproofPath, "-dropreplace="+sidecarBasePath, "-dropreplace="+smtpproofPath,
		"-require="+sidecarBasePath+releaseSuffix+version, "-require="+smtpproofPath+releaseSuffix+version,
		"-replace="+sidecarBasePath+releaseSuffix+"=../v2026", "-replace="+smtpproofPath+releaseSuffix+"=../smtpproof/v2026")...)
}

// A repository over the fixture's release tree.
func (self *fixture) openRelease() *repository {
	self.t.Helper()
	repository, err := openRepository(filepath.Join(self.directory, "sidecar", "v2026"), self.settings, self.legs)
	if err != nil {
		self.t.Fatal(err)
	}
	repository.report = self.t.Logf
	return repository
}

// Every rule still reads a clean release tree as clean, with the legs on the rewritten paths.
func TestRulesPassAReleaseTree(t *testing.T) {
	fixture := newFixture(t)
	fixture.toRelease()
	repository := fixture.openRelease()
	if repository.releaseSuffix != releaseSuffix {
		t.Fatalf("the release suffix reads %q", repository.releaseSuffix)
	}
	repository.listAllLegs()
	for _, entry := range failsOnRows {
		if entry.rule != nil {
			failFindings(t, entry.item, entry.rule(repository, t))
		}
	}
}

// And still fires there: a rule keyed to the development spelling would pass a release in silence.
func TestRulesFireOnAReleaseTree(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n\nimport _ \"@module@\"\n")
	fixture.write("protocol/bridge/planted.go", "package bridge\n\nimport _ \"@module@/protocol\"\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/evsservice\"\n")
	fixture.write("evsservice/engine.go", "package evsservice\n")
	fixture.write("evsservice/testhook.go", "//go:build !sidecar_testhooks\n\npackage evsservice\n\nfunc testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}\n\nfunc testHookBarrier(name string, key string) {}\n")
	fixture.write("evsservice/testhook_enabled.go", "//go:build sidecar_testhooks\n\npackage evsservice\n\nimport \"@module@\"\n\nfunc testHookSecret(kind string, secret []byte) {\n\tsidecar.TestHookSecret(kind, secret)\n}\n\nfunc testHookBarrier(name string, key string) {\n\tsidecar.TestHookBarrier(name, key)\n}\n")
	fixture.keepLegs(iosExtensionLegName)
	fixture.toRelease()
	repository := fixture.openRelease()
	wantFindings(t, repository.iosExtensionFindings(t), iosExtensionLegName+" links @module@/v2026", iosExtensionLegName+" links @module@/v2026/protocol")
	wantFindings(t, repository.deviceImportFindings(t), "v2026/device/device.go:3: device imports @module@/v2026")
	wantFindings(t, repository.protocolImportFindings(t), "v2026/protocol/bridge/planted.go:3: protocol/bridge imports @module@/v2026/protocol")
	wantFindings(t, repository.clientEngineImportFindings(t), "the client package cli imports @module@/v2026/evsservice")
	wantFindings(t, repository.hookPairFindings(t), "v2026/evsservice/testhook.go: testHookSecret has a body in the untagged build")
}

func TestHygieneFailsOnAReleaseBranchExtraReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.toRelease()
	data, err := os.ReadFile(filepath.Join(fixture.directory, "sidecar", "v2026", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.write("v2026/go.mod", string(data)+"\nreplace golang.org/x/net => ../../net\n")
	wantFindings(t, fixture.openRelease().replaceFindings(t), ".: replace golang.org/x/net => ../../net is not one of §4.7's")
}

// By sidecar's release step connect has moved into connect/v2026/, and the rules still read it.
func TestRulesReadASiblingMovedOnARelease(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.toRelease()
	file, err := fixture.openRelease().siblingModuleFile("connect")
	if err != nil {
		t.Fatal(err)
	}
	if file.Module.Path != connectBasePath+releaseSuffix {
		t.Errorf("read the module %s", file.Module.Path)
	}
}

// The first-party spelling a rule compares on, and what must not be taken for one.
func TestFirstPartyPathsCompareWithoutTheirReleaseElements(t *testing.T) {
	for input, want := range map[string]string{
		sidecarBasePath + releaseSuffix:                            sidecarBasePath,
		sidecarBasePath + releaseSuffix + "/protocol/bridge":       sidecarBasePath + "/protocol/bridge",
		sidecarBasePath + "/smtpproof" + releaseSuffix + "/prover": sidecarBasePath + "/smtpproof/prover",
		connectBasePath + releaseSuffix + "/protocol":              connectBasePath + "/protocol",
		"github.com/pion/dtls/v3":                                  "github.com/pion/dtls/v3",
		"gopkg.in/yaml.v3":                                         "gopkg.in/yaml.v3",
	} {
		if got := firstPartyBase(input); got != want {
			t.Errorf("%s reads as %s, want %s", input, got, want)
		}
	}
	for _, input := range []string{sidecarBasePath + "-extra", sidecarBasePath + "x/protocol"} {
		if _, ours := repositoryRelative(input); ours {
			t.Errorf("%s reads as this repository's", input)
		}
	}
}

// The release's real shape: connect's and glog's replaces gone for tagged requires, gVisor on the
// urnetwork fork at a version (build/all/run.sh:1546-1551), which the fixture's tree cannot reach. A rule reading §4.7's development list
// would fail its own release.
func TestHygieneAllowsTheReleaseStepsReplaces(t *testing.T) {
	module := &repositoryModule{relativeName: ".", file: &moduleFile{}}
	addReplace := func(old string, newPath string, version string) {
		replace := struct {
			Old struct {
				Path    string
				Version string
			}
			New struct {
				Path    string
				Version string
			}
		}{}
		replace.Old.Path = old
		replace.New.Path = newPath
		replace.New.Version = version
		module.file.Replace = append(module.file.Replace, replace)
	}
	addReplace(gvisorBasePath, gvisorReleaseFork, "v0.0.0-20260909230408-9b1144b679cb")
	addReplace(sctpBasePath, "../../connect/sctp", "")
	wantFindings(t, replaceFindingsRelease(module))

	addReplace(glogBasePath, "example.com/glog", "v1.0.0")
	wantFindings(t, replaceFindingsRelease(module), "is not a rebased local path")
}

// Committed files carry the rewritten paths on a release branch and are never regenerated (§4.9),
// so a fresh run must go through the rewrite before it can be compared.
func TestHygieneFailsOnAStalePbGoOnAReleaseBranch(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.toRelease()
	wantFindings(t, fixture.openRelease().staleGeneratedFindings(t))

	fixture.edit("v2026/protocol/bridge/signed.proto", "bytes body = 1;", "bytes body = 1;\n  bytes more = 2;")
	wantFindings(t, fixture.openRelease().staleGeneratedFindings(t), "protocol/bridge/signed.pb.go is stale")
}
