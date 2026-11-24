//go:build sidecar_check

// make check also runs at release (§4.7), from a tree that does not look like this one: the root
// module is .../sidecar/v2026 in v2026/, smtpproof is .../sidecar/smtpproof/v2026 in smtpproof/v2026/,
// cli and mlsinterop stay put, third_party/'s forks stay at the top beside v2026/, and every quoted
// path of ours has been rewritten (§4.9). These apply build/all/run.sh's transformation to a fixture
// and read the result, so the rules are shown to work where they will next be run.
// release_step_test.go holds this to run.sh's own functions, and a real dry run of them over this
// tree is the release fixture's job (§22.4): build/all's TestSidecarReleaseFixture.

package check

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The year in the release's module paths.
const releaseSuffix = "/v2026"

// What stays beside the module on a version branch, out of every consumer's module cache: the
// documents, and third_party/, whose forks are modules of their own that every development replace
// names at the top (QD-920, owner decision 278). These are the arguments run.sh's
// sidecar_release_edit gives go_mod_fork.
var releaseDocumentPattern = regexp.MustCompile(`^(design|research_notes|third_party|DESIGN.*|HANDOFF\.md|FEEDBACK-SYSTEM\.md)$`)

// The go_mod_fork steps, in the order §4.9 gives them, on connect, glog and operator-core as earlier
// release steps leave them and on this repository: every module's quoted paths rewritten in run.sh's
// order, smtpproof's before the root's and coretest's before operator-core's, each module's exact
// pass before its subpackage pass, and the nested modules' own passes after (releaseRewriteRepository);
// each tree moved into v2026/ beside its nested modules, and the relative replaces rebased. connect,
// glog and operator-core keep a local replace here, where a release has their tags in a proxy.
// QD-193's forks stay at the top, so a moved module's replace of one climbs out of its version
// directory, and cli's and mlsinterop's stand.
func (self *fixture) toRelease() {
	self.t.Helper()
	top := filepath.Join(self.directory, "sidecar")
	smtpproofPath := sidecarBasePath + "/smtpproof"
	version := "@v2026.11.6"

	// each .go file and Makefile below directory through edit, which takes the file's slash path from it
	rewrite := func(directory string, edit func(relativePath string, content string) string) {
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
			relativePath, err := filepath.Rel(directory, walkPath)
			if err != nil {
				return err
			}
			return os.WriteFile(walkPath, []byte(edit(filepath.ToSlash(relativePath), string(data))), 0o600)
		})
		if err != nil {
			self.t.Fatal(err)
		}
	}
	// the siblings' release edits, each module's exact pass then its subpackage pass, in run.sh's order
	rewrite(filepath.Join(self.directory, "glog"), func(relativePath string, content string) string {
		return releaseRewritePath(content, glogBasePath, releaseSuffix)
	})
	rewrite(filepath.Join(self.directory, "connect"), func(relativePath string, content string) string {
		return releaseRewritePath(releaseRewritePath(content, connectBasePath, releaseSuffix), glogBasePath, releaseSuffix)
	})
	rewrite(filepath.Join(self.directory, "operator-core"), func(relativePath string, content string) string {
		content = releaseRewriteSubpackages(content, operatorCoreTestBasePath, releaseSuffix)
		for _, modulePath := range []string{operatorCoreBasePath, connectBasePath, glogBasePath} {
			content = releaseRewritePath(content, modulePath, releaseSuffix)
		}
		return content
	})
	rewrite(top, func(relativePath string, content string) string {
		return releaseRewriteRepository(content, relativePath, releaseSuffix)
	})

	// moves a tree into v2026/, leaving what holds its own go.mod where it is, and the documents. As
	// go_mod_fork_prepare's zsh `for f in *` does, a dotfile stays, so a checkout's .git keeps its place.
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
			if releaseDocumentPattern.MatchString(entry.Name()) || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			if err := os.Rename(filepath.Join(directory, entry.Name()), filepath.Join(versioned, entry.Name())); err != nil {
				self.t.Fatal(err)
			}
		}
	}
	move(filepath.Join(self.directory, "glog"))
	move(filepath.Join(self.directory, "connect"))
	move(filepath.Join(self.directory, "operator-core"))
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

	// connect's and glog's tags in a module whose directory climbs to the siblings with climbs, with
	// sctp's and gVisor's replaces climbing with the move
	connectSiblings := func(climbs string) []string {
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
	// operator-core's own release step, which run.sh runs after connect's and before this repository's
	// (owner decision 251)
	edit(filepath.Join(self.directory, "operator-core", "v2026", "go.mod"),
		append(connectSiblings("../../"), "-module="+operatorCoreBasePath+releaseSuffix)...)

	// the sibling edits of each module here: those, and operator-core's tag, which run.sh's edits give
	// every module of this repository in place of its development require and replace
	siblings := func(climbs string) []string {
		return append(connectSiblings(climbs),
			"-droprequire="+operatorCoreBasePath, "-dropreplace="+operatorCoreBasePath,
			"-require="+operatorCoreBasePath+releaseSuffix+version,
			"-replace="+operatorCoreBasePath+releaseSuffix+"="+climbs+"operator-core/v2026")
	}
	// each fork a module replaces, reached from its go.mod's directory by climbs to the repository's top
	forks := func(goModPath string, climbs string) []string {
		file, err := readModuleFile(goModPath)
		if err != nil {
			self.t.Fatal(err)
		}
		arguments := []string{}
		for _, replace := range file.Replace {
			if directory, fork := forkReplaces[replace.Old.Path]; fork {
				arguments = append(arguments, "-replace="+replace.Old.Path+"="+climbs+directory)
			}
		}
		return arguments
	}
	rootGoMod := filepath.Join(top, "v2026", "go.mod")
	edit(rootGoMod, slices.Concat(siblings("../../"), forks(rootGoMod, "../"), []string{"-module=" + sidecarBasePath + releaseSuffix})...)
	smtpproofGoMod := filepath.Join(top, "smtpproof", "v2026", "go.mod")
	edit(smtpproofGoMod, slices.Concat(siblings("../../../"), forks(smtpproofGoMod, "../../"), []string{
		"-module=" + smtpproofPath + releaseSuffix, "-droprequire=" + sidecarBasePath, "-dropreplace=" + sidecarBasePath,
		"-require=" + sidecarBasePath + releaseSuffix + version, "-replace=" + sidecarBasePath + releaseSuffix + "=../../v2026"})...)
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

// QD-193's forks as this repository holds them (§4.7): each a module of its own under its upstream
// path in third_party/, which the root requires and every module of this repository replaces, a
// nested one from one level up, since Go does not inherit a replace.
func (self *fixture) writeForks() {
	self.t.Helper()
	appendTo := func(name string, text string) {
		data, err := os.ReadFile(filepath.Join(self.directory, "sidecar", filepath.FromSlash(name)))
		if err != nil {
			self.t.Fatal(err)
		}
		self.write(name, string(data)+text)
	}
	for _, old := range slices.Sorted(maps.Keys(forkReplaces)) {
		directory := forkReplaces[old]
		self.write(directory+"/go.mod", "module "+old+"\n\ngo 1.27.4\n")
		self.write(directory+"/fork.go", "package fork\n")
		appendTo("go.mod", "\nrequire "+old+" v0.0.0\n\nreplace "+old+" => ./"+directory+"\n")
		for _, nested := range []string{"cli", "smtpproof", "mlsinterop"} {
			appendTo(nested+"/go.mod", "\nreplace "+old+" => ../"+directory+"\n")
		}
	}
}

// run.sh's release step over the fixture, as release_step_test.go's twin runs it, tidy and get
// skipped. patch, when given, changes the functions' text first.
func (self *fixture) runReleaseStep(patch func(string) string) {
	self.t.Helper()
	functions := releaseStepFunctions(self.t)
	if patch != nil {
		functions = patch(functions)
	}
	command := exec.Command("zsh", "-c", releaseStepHarness, "release-step", functions, releaseStepSed(self.t),
		releaseStepInternalVersion, releaseStepVersion, releaseStepGvisorVersion)
	command.Dir = filepath.Join(self.directory, "sidecar")
	command.Env = goEnvironment()
	if output, err := command.CombinedOutput(); err != nil {
		self.t.Fatalf("run.sh's functions failed on the fixture: %v\n%s", err, output)
	}
}

// Where a release tree's replaces of QD-193's forks miss them, top being the repository's top on the
// version branch. Each module of this repository replaces each fork with the climb from its own
// directory to the top, then third_party/X: the root's in v2026/ and cli's and mlsinterop's read
// ../third_party/X, smtpproof's in smtpproof/v2026/ ../../third_party/X, and each reaches a go.mod
// that declares the fork's upstream path.
func releaseForkFindings(top string) []string {
	findings := []string{}
	modules := []struct {
		name   string
		climbs string
	}{
		{name: "v2026", climbs: "../"},
		{name: "smtpproof/v2026", climbs: "../../"},
		{name: "cli", climbs: "../"},
		{name: "mlsinterop", climbs: "../"},
	}
	for _, module := range modules {
		directory := filepath.Join(top, filepath.FromSlash(module.name))
		file, err := readModuleFile(filepath.Join(directory, "go.mod"))
		if err != nil {
			findings = append(findings, findingf("%s: %v", module.name, err))
			continue
		}
		_, replaces := moduleTerms(file)
		for _, old := range slices.Sorted(maps.Keys(forkReplaces)) {
			want := module.climbs + forkReplaces[old]
			target, found := replaces[old]
			if !found {
				findings = append(findings, findingf("%s: no replace of %s", module.name, old))
				continue
			}
			if target != want {
				findings = append(findings, findingf("%s: replace %s => %s, and the release's is %s", module.name, old, target, want))
			}
			forkGoMod := filepath.Join(directory, filepath.FromSlash(target), "go.mod")
			if _, err := os.Stat(forkGoMod); err != nil {
				findings = append(findings, findingf("%s: replace %s => %s reaches no go.mod", module.name, old, target))
				continue
			}
			forkFile, err := readModuleFile(forkGoMod)
			if err != nil {
				findings = append(findings, findingf("%s: replace %s => %s: %v", module.name, old, target, err))
			} else if forkFile.Module.Path != old {
				findings = append(findings, findingf("%s: replace %s => %s reaches the module %s", module.name, old, target, forkFile.Module.Path))
			}
		}
	}
	switch _, err := os.Stat(filepath.Join(top, "v2026", "third_party")); {
	case err == nil:
		findings = append(findings, "v2026/third_party: the forks moved into the root module's tree")
	case !errors.Is(err, fs.ErrNotExist):
		findings = append(findings, findingf("v2026/third_party: %v", err))
	}
	return findings
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
	fixture.write("mail_planted.go", "package sidecar\n\nimport _ \"@module@/mcp\"\n")
	fixture.write("mcp/mcp.go", "package mcp\n")
	fixture.write("protocol/bridge/planted.go", "package bridge\n\nimport _ \"@module@/protocol\"\n")
	fixture.write("cli/planted.go", "package main\n\nimport _ \"@module@/evsservice\"\n")
	fixture.write("evsservice/engine.go", "package evsservice\n")
	fixture.write("evsservice/testhook.go", "//go:build !sidecar_testhooks\n\npackage evsservice\n\nfunc testHookSecret(kind string, secret []byte) {\n\tprintln(kind)\n}\n\nfunc testHookBarrier(name string, key string) {}\n")
	fixture.write("evsservice/testhook_enabled.go", "//go:build sidecar_testhooks\n\npackage evsservice\n\nimport \"@module@\"\n\nfunc testHookSecret(kind string, secret []byte) {\n\tsidecar.TestHookSecret(kind, secret)\n}\n\nfunc testHookBarrier(name string, key string) {\n\tsidecar.TestHookBarrier(name, key)\n}\n")
	fixture.keepLegs(iosExtensionLegName)
	fixture.toRelease()
	repository := fixture.openRelease()
	wantFindings(t, repository.iosExtensionFindings(t),
		iosExtensionLegName+" compiles mail_planted.go, which is not on check/testdata/ios_extension_leg.txt",
		iosExtensionLegName+" links @module@/v2026/mcp")
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

// QD-193's forks stay at the repository's top beside v2026/, as the documents do (QD-920, owner
// decision 278), so every module's replace of one reaches it after the step: the root's and
// smtpproof's climb out of their version directories, and cli's and mlsinterop's stand, which is what
// sidecar_cli_release_edit's tidy needs. toRelease and run.sh's functions each leave that layout, and
// leave it alike, and the release layout's replace rule reads both as clean.
func TestReleaseKeepsTheForksBesideTheModule(t *testing.T) {
	described := newFixture(t)
	described.writeReleaseInputs()
	described.writeForks()
	described.toRelease()
	released := newFixture(t)
	released.writeReleaseInputs()
	released.writeForks()
	released.runReleaseStep(nil)
	describedTop := filepath.Join(described.directory, "sidecar")
	releasedTop := filepath.Join(released.directory, "sidecar")
	failFindings(t, "toRelease", releaseForkFindings(describedTop))
	failFindings(t, "run.sh", releaseForkFindings(releasedTop))
	failFindings(t, "release step", releaseStepFindings(t, describedTop, releasedTop))
	wantFindings(t, described.openRelease().replaceFindings(t))
	wantFindings(t, released.openRelease().replaceFindings(t))
}

// The step as it stood before QD-920, which moved third_party/ into v2026/ with the rest of the tree:
// the root's replace still reaches its fork, which moved with it, and smtpproof's walks to
// v2026/third_party/, but cli's and mlsinterop's reach nothing, which is where their tidy stopped the
// release.
func TestReleaseForkFindingsFireWhenTheForksMoveIntoTheModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeReleaseInputs()
	fixture.writeForks()
	kept := " 'third_party'"
	fixture.runReleaseStep(func(functions string) string {
		if strings.Count(functions, kept) != 1 {
			t.Fatal("sidecar_release_edit's go_mod_fork arguments changed, so this plants nothing")
		}
		return strings.Replace(functions, kept, "", 1)
	})
	wantFindings(t, releaseForkFindings(filepath.Join(fixture.directory, "sidecar")),
		"v2026: replace github.com/emersion/go-smtp => ./third_party/go-smtp, and the release's is ../third_party/go-smtp",
		"v2026: replace github.com/google/go-sev-guest => ./third_party/go-sev-guest, and the release's is ../third_party/go-sev-guest",
		"v2026: replace github.com/google/go-tdx-guest => ./third_party/go-tdx-guest, and the release's is ../third_party/go-tdx-guest",
		"v2026: replace github.com/mjl-/mox => ./third_party/mox, and the release's is ../third_party/mox",
		"smtpproof/v2026: replace github.com/emersion/go-smtp => ../../v2026/third_party/go-smtp, and the release's is ../../third_party/go-smtp",
		"smtpproof/v2026: replace github.com/google/go-sev-guest => ../../v2026/third_party/go-sev-guest, and the release's is ../../third_party/go-sev-guest",
		"smtpproof/v2026: replace github.com/google/go-tdx-guest => ../../v2026/third_party/go-tdx-guest, and the release's is ../../third_party/go-tdx-guest",
		"smtpproof/v2026: replace github.com/mjl-/mox => ../../v2026/third_party/mox, and the release's is ../../third_party/mox",
		"cli: replace github.com/emersion/go-smtp => ../third_party/go-smtp reaches no go.mod",
		"cli: replace github.com/google/go-sev-guest => ../third_party/go-sev-guest reaches no go.mod",
		"cli: replace github.com/google/go-tdx-guest => ../third_party/go-tdx-guest reaches no go.mod",
		"cli: replace github.com/mjl-/mox => ../third_party/mox reaches no go.mod",
		"mlsinterop: replace github.com/emersion/go-smtp => ../third_party/go-smtp reaches no go.mod",
		"mlsinterop: replace github.com/google/go-sev-guest => ../third_party/go-sev-guest reaches no go.mod",
		"mlsinterop: replace github.com/google/go-tdx-guest => ../third_party/go-tdx-guest reaches no go.mod",
		"mlsinterop: replace github.com/mjl-/mox => ../third_party/mox reaches no go.mod",
		"v2026/third_party: the forks moved into the root module's tree")
}
