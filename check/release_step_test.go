//go:build sidecar_check

// toRelease and build/all/run.sh must describe one transformation, or release_test.go proves its
// rules on a tree no release produces. This runs run.sh's real functions over a fixture and toRelease
// over its twin, then compares what each leaves. tidy and get need published modules, so they are
// skipped here: build/all's TestSidecarReleaseFixture runs them against tags in a file proxy.

package check

import (
	"bytes"
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

const (
	// the fixture's tag, which toRelease writes as v2026.11.6
	releaseStepVersion = "2026.11.6"
	// what the version sed writes, with the + binaries carry
	releaseStepInternalVersion = "2026.11.6+1234567"
	releaseStepGvisorVersion   = "v0.0.0-20260909230408-9b1144b679cb"
)

// The functions run.sh's edits call, in the order they are defined.
var releaseStepFunctionNames = []string{
	"go_mod_edit_module", "go_mod_edit_require", "go_mod_edit_gvisor", "go_mod_drop_require", "go_edit_require",
	"go_edit_require_subpackages", "go_mod_fork_rebase_local_replaces", "go_mod_fork_prepare", "go_mod_fork_tidy",
	"go_mod_fork", "sidecar_release_edit", "smtpproof_release_edit", "sidecar_cli_release_edit",
}

// The edits, in the order sidecar_release_publish runs them, without its commits and tags.
const releaseStepHarness = `
set -eu
eval "$1"
BUILD_SED="$2"
WARP_VERSION="$3"
EXTERNAL_WARP_VERSION="$4"
GVISOR_GO_VERSION="$5"
GO_MOD_VERSION=2026
GO_MOD_SUFFIX=/v2026
go() {
    case "$1 $2" in
        'mod tidy'|'get -t') return 0 ;;
    esac
    command go "$@"
}
sidecar_release_edit
(cd smtpproof && smtpproof_release_edit)
sidecar_cli_release_edit
`

// The directory holding run.sh: the build sibling in development, and on a release branch the build
// repository this checkout is a submodule of, which is the siblings' directory itself.
func releaseScriptDirectory(t testing.TB) string {
	t.Helper()
	repository := openThisCheckout(t)
	for _, candidate := range []string{repository.siblingPath("build/all"), filepath.Join(repository.siblingsDirectory, "all")} {
		if _, err := os.Stat(filepath.Join(candidate, "run.sh")); err == nil {
			return candidate
		}
	}
	t.Fatal("no build/all/run.sh beside this checkout, and a rule that did not run has not passed")
	return ""
}

// Each named function's text, as it stands in run.sh.
func releaseStepFunctions(t testing.TB) string {
	t.Helper()
	script, err := os.ReadFile(filepath.Join(releaseScriptDirectory(t), "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, name := range releaseStepFunctionNames {
		matches := regexp.MustCompile(`(?ms)^`+regexp.QuoteMeta(name)+` \(\) \{\n.*?^\}\n`).FindAll(script, -1)
		if len(matches) != 1 {
			t.Fatalf("run.sh defines %s %d times, want once", name, len(matches))
		}
		source.Write(matches[0])
	}
	return source.String()
}

// GNU sed, which run.sh's rewrites need: gsed on the release host, sed on Linux.
func releaseStepSed(t testing.TB) string {
	t.Helper()
	for _, name := range []string{"gsed", "sed"} {
		if path, err := exec.LookPath(name); err == nil {
			if output, err := exec.Command(path, "--version").CombinedOutput(); err == nil && bytes.Contains(output, []byte("GNU sed")) {
				return path
			}
		}
	}
	t.Fatal("no GNU sed, and a rule that did not run has not passed")
	return ""
}

// What both twins start from beyond the fixture: the declaration the sed fills, and the documents
// that stay out of the module.
func (self *fixture) writeReleaseInputs() {
	self.t.Helper()
	self.write("sidecar.go", "package sidecar\n\nvar Version string = \"\"\n\nfunc Sidecar() {}\n")
	self.write("LICENSE", fixtureMplLicense)
	for _, name := range []string{"DESIGN.md", "DESIGN-REVIEW1.md", "HANDOFF.md", "FEEDBACK-SYSTEM.md", "design/source/a.md", "research_notes/a.md"} {
		self.write(name, "a document\n")
	}
}

// The twins: the fixture toRelease left, and the one run.sh's functions left.
func releaseTwins(t *testing.T) (described string, released string) {
	t.Helper()
	describedFixture := newFixture(t)
	describedFixture.writeReleaseInputs()
	describedFixture.toRelease()
	releasedFixture := newFixture(t)
	releasedFixture.writeReleaseInputs()
	command := exec.Command("zsh", "-c", releaseStepHarness, "release-step", releaseStepFunctions(t), releaseStepSed(t),
		releaseStepInternalVersion, releaseStepVersion, releaseStepGvisorVersion)
	command.Dir = filepath.Join(releasedFixture.directory, "sidecar")
	command.Env = goEnvironment()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run.sh's functions failed on the fixture: %v\n%s", err, output)
	}
	return filepath.Join(describedFixture.directory, "sidecar"), filepath.Join(releasedFixture.directory, "sidecar")
}

// A module's requires, path to version, and its replaces, path to target.
func moduleTerms(file *moduleFile) (map[string]string, map[string]string) {
	requires := map[string]string{}
	for _, require := range file.Require {
		requires[require.Path] = require.Version
	}
	replaces := map[string]string{}
	for _, replace := range file.Replace {
		replaces[replace.Old.Path] = strings.TrimSpace(replace.New.Path + " " + replace.New.Version)
	}
	return requires, replaces
}

// Where one go.mod's transformation differs. toRelease keeps a local replace for what a release
// takes from a tag, because a fixture has no proxy, and a local gVisor where run.sh pins the fork;
// those are the only replaces that may differ. run.sh may hold a tag toRelease does not, which its
// tidy prunes when the module does not import it.
func releaseModuleFindings(name string, described *moduleFile, released *moduleFile) []string {
	findings := []string{}
	if described.Module.Path != released.Module.Path {
		findings = append(findings, findingf("%s: toRelease names the module %s, and run.sh %s", name, described.Module.Path, released.Module.Path))
	}
	describedRequires, describedReplaces := moduleTerms(described)
	releasedRequires, releasedReplaces := moduleTerms(released)
	for path, version := range describedRequires {
		if releasedRequires[path] != version {
			findings = append(findings, findingf("%s: toRelease requires %s %s, and run.sh leaves %q", name, path, version, releasedRequires[path]))
		}
	}
	for path, version := range releasedRequires {
		if _, shared := describedRequires[path]; shared {
			continue
		}
		if firstPartyBase(path) == path || version != "v"+releaseStepVersion {
			findings = append(findings, findingf("%s: run.sh requires %s %s, which is not a tag of this release", name, path, version))
		}
	}
	for old, target := range releasedReplaces {
		switch {
		case old == gvisorBasePath && strings.HasPrefix(target, gvisorReleaseFork+" "):
		case describedReplaces[old] != target:
			findings = append(findings, findingf("%s: run.sh replaces %s => %s, and toRelease %q", name, old, target, describedReplaces[old]))
		}
	}
	for old, target := range describedReplaces {
		if _, shared := releasedReplaces[old]; shared {
			continue
		}
		if !strings.HasSuffix(old, releaseSuffix) || !strings.HasPrefix(target, "../") {
			findings = append(findings, findingf("%s: toRelease keeps replace %s => %s, which is not a tag's stand-in", name, old, target))
		}
	}
	return findings
}

// Every file under directory but the go.mods, by slash path from it.
func releaseTreeFiles(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(directory, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || entry.Name() == "go.mod" {
			return walkErr
		}
		relative, err := filepath.Rel(directory, walkPath)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(walkPath)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Where the twins differ: each module, then every other file by path and bytes, so a moved file or a
// rewritten import shows. The version sed is run.sh's alone, so it is read and then set aside.
func releaseStepFindings(t *testing.T, described string, released string) []string {
	t.Helper()
	findings := []string{}
	for _, name := range []string{"v2026", "smtpproof/v2026", "cli", "mlsinterop"} {
		describedFile, err := readModuleFile(filepath.Join(described, filepath.FromSlash(name), "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		releasedFile, err := readModuleFile(filepath.Join(released, filepath.FromSlash(name), "go.mod"))
		if err != nil {
			findings = append(findings, findingf("%s: run.sh left no go.mod: %v", name, err))
			continue
		}
		findings = append(findings, releaseModuleFindings(name, describedFile, releasedFile)...)
	}
	describedFiles := releaseTreeFiles(t, described)
	releasedFiles := releaseTreeFiles(t, released)
	versionFile := "v2026/sidecar.go"
	filled := []byte(`Version string = "` + releaseStepInternalVersion + `"`)
	if !bytes.Contains(releasedFiles[versionFile], filled) {
		findings = append(findings, findingf("%s: run.sh did not fill the version", versionFile))
	}
	releasedFiles[versionFile] = bytes.ReplaceAll(releasedFiles[versionFile], filled, []byte(`Version string = ""`))
	names := slices.Sorted(maps.Keys(describedFiles))
	for _, name := range names {
		content, present := releasedFiles[name]
		switch {
		case !present:
			findings = append(findings, findingf("%s: toRelease leaves this file, and run.sh does not", name))
		case !bytes.Equal(content, describedFiles[name]):
			findings = append(findings, findingf("%s: the two rewrites differ", name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(releasedFiles)) {
		if _, present := describedFiles[name]; !present {
			findings = append(findings, findingf("%s: run.sh leaves this file, and toRelease does not", name))
		}
	}
	return findings
}

func TestToReleaseAndTheReleaseStepAreOneTransformation(t *testing.T) {
	described, released := releaseTwins(t)
	failFindings(t, "release step", releaseStepFindings(t, described, released))
}

// Each difference this exists to catch, planted on run.sh's twin, so the pass above means something.
func TestReleaseStepFindingsCatchEachKindOfDifference(t *testing.T) {
	described, released := releaseTwins(t)
	edit := func(name string, change func(string) string) func() {
		path := filepath.Join(released, filepath.FromSlash(name))
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(change(string(original))), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name   string
		change func(string) string
		want   string
	}{
		{"cli/main.go", func(text string) string {
			return strings.ReplaceAll(text, "smtpproof"+releaseSuffix, strings.TrimPrefix(releaseSuffix, "/")+"/smtpproof")
		}, "the two rewrites differ"},
		{"cli/go.mod", func(text string) string { return text + "\nreplace " + sidecarBasePath + " => ..\n" }, "run.sh replaces"},
		{"v2026/go.mod", func(text string) string {
			return strings.Replace(text, "module "+sidecarBasePath+releaseSuffix, "module "+sidecarBasePath, 1)
		}, "toRelease names the module"},
		{"smtpproof/v2026/go.mod", func(text string) string { return text + "\nrequire " + connectBasePath + " v0.0.0\n" }, "not a tag of this release"},
		{"v2026/sidecar.go", func(text string) string {
			return strings.Replace(text, releaseStepInternalVersion, "", 1)
		}, "did not fill the version"},
	}
	for _, entry := range cases {
		restore := edit(entry.name, entry.change)
		wantFindings(t, releaseStepFindings(t, described, released), entry.want)
		restore()
	}
	strayFile := filepath.Join(released, "v2026", "DESIGN.md")
	if err := os.WriteFile(strayFile, []byte("a document\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, releaseStepFindings(t, described, released), "run.sh leaves this file")
}
