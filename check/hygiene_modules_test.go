//go:build sidecar_check

// §4.7's hygiene row, the module files: replaces other than §4.7's, and the go and tool lines of its
// block. A replace is the one go.mod line that decides where code comes from without showing in a
// version, and Go does not inherit one, so each module's list is checked on its own. Beside them, a
// go.work, and the one shape §4.9's release needs of the modules it never tags: one package each,
// which no file names by its path.

package check

import (
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Where the root's sibling replaces point, from the root's own directory (§4.7).
var siblingReplaces = map[string]string{
	connectBasePath: "../connect",
	sctpBasePath:    "../connect/sctp",
	glogBasePath:    "../glog",
	gvisorBasePath:  "../gvisor",
}

// The modules of this repository a nested module may replace, and what they are relative to it.
var repositoryReplaces = map[string]string{
	sidecarBasePath:                "..",
	sidecarBasePath + "/smtpproof": "../smtpproof",
}

// §4.7's replaces, development layout: the four siblings exactly, one level further up in a nested
// module, which may also point at this repository's own modules.
func replaceFindingsDevelopment(module *repositoryModule) []string {
	findings := []string{}
	targets := map[string]string{}
	for _, replace := range module.file.Replace {
		old := replace.Old.Path
		if replace.Old.Version != "" || replace.New.Version != "" {
			findings = append(findings, findingf("%s: replace %s pins a version, and §4.7's do not", module.relativeName, old))
		}
		targets[old] = replace.New.Path
	}
	for old, target := range siblingReplaces {
		if module.relativeName != "." {
			target = "../" + target
		}
		got, found := targets[old]
		if !found {
			findings = append(findings, findingf("%s: no replace for %s, which §4.7 has it repeat", module.relativeName, old))
			continue
		}
		if got != target {
			findings = append(findings, findingf("%s: replace %s => %s, and §4.7's is %s", module.relativeName, old, got, target))
		}
		delete(targets, old)
	}
	for old, got := range targets {
		target, own := repositoryReplaces[old]
		if !own || module.relativeName == "." {
			findings = append(findings, findingf("%s: replace %s => %s is not one of §4.7's", module.relativeName, old, got))
			continue
		}
		if got != target {
			findings = append(findings, findingf("%s: replace %s => %s, and §4.7's is %s", module.relativeName, old, got, target))
		}
	}
	slices.Sort(findings)
	return findings
}

// A moved sibling's last element, such as /v2026.
var versionElementSuffixPattern = regexp.MustCompile(`/v[0-9]+$`)

// §4.7's replaces, release layout. The release step drops connect's and glog's for tagged requires
// (build/all/run.sh:1546-1549), points gVisor at the urnetwork fork (:1551) and rebases what stays
// (:1568), so each may be absent, and a path may climb further, but nothing else may appear.
func replaceFindingsRelease(module *repositoryModule) []string {
	findings := []string{}
	for _, replace := range module.file.Replace {
		old := firstPartyBase(replace.Old.Path)
		newPath := replace.New.Path
		_, sibling := siblingReplaces[old]
		_, own := repositoryReplaces[old]
		if !sibling && !own {
			findings = append(findings, findingf("%s: replace %s => %s is not one of §4.7's", module.relativeName, replace.Old.Path, newPath))
			continue
		}
		if old == gvisorBasePath && firstPartyBase(newPath) == gvisorReleaseFork {
			continue
		}
		if replace.New.Version != "" || !strings.HasPrefix(newPath, "../") {
			findings = append(findings, findingf("%s: replace %s => %s %s is not a rebased local path", module.relativeName, replace.Old.Path, newPath, replace.New.Version))
			continue
		}
		if sibling {
			want := strings.TrimPrefix(siblingReplaces[old], "../")
			target := versionElementSuffixPattern.ReplaceAllString(path.Clean(newPath), "")
			if !strings.HasSuffix(target, "/"+want) {
				findings = append(findings, findingf("%s: replace %s => %s does not end at %s", module.relativeName, replace.Old.Path, newPath, want))
			}
		}
	}
	return findings
}

// Every module's replaces.
func (self *repository) replaceFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, module := range self.modules(t) {
		if self.releaseSuffix != "" {
			findings = append(findings, replaceFindingsRelease(module)...)
			continue
		}
		findings = append(findings, replaceFindingsDevelopment(module)...)
	}
	return findings
}

// §4.7's block: go 1.27.3 on every module, and the root's one tool line, whose requirements would
// otherwise enter every consumer's graph.
func (self *repository) moduleLineFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, module := range self.modules(t) {
		if module.file.Go != self.settings.goVersion {
			findings = append(findings, findingf("%s: go %s, and §4.7's is %s", module.relativeName, module.file.Go, self.settings.goVersion))
		}
		tools := []string{}
		for _, tool := range module.file.Tool {
			tools = append(tools, tool.Path)
		}
		wantTools := []string{}
		if module.relativeName == "." {
			wantTools = []string{self.settings.protocGenGoTool}
		}
		if !slices.Equal(tools, wantTools) {
			findings = append(findings, findingf("%s: tool lines %v, and §4.7's are %v", module.relativeName, tools, wantTools))
		}
	}
	return findings
}

// A go.work file would change what a developer's builds resolve while every rule here, which runs
// with GOWORK=off, sees none of it.
func (self *repository) workFileFindings(t testing.TB) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(self.topDirectory, "go.work*"))
	if err != nil {
		t.Fatal(err)
	}
	findings := []string{}
	for _, match := range matches {
		findings = append(findings, findingf("%s changes what builds resolve, out of the rules' sight", self.displayPath(match)))
	}
	return findings
}

// The modules a release leaves unversioned in place, never tagged (§4.9), sidecarctl among them
// (C-23).
var untaggedModuleNames = []string{"cli", "mlsinterop", "sidecarctl"}

// A quoted path of this repository, as the release's rewrite finds one, up to what ends a path: a
// Makefile's go install path@version, say, or a second word in the quotes.
var quotedRepositoryPathPattern = regexp.MustCompile(`"(` + regexp.QuoteMeta(sidecarBasePath) + `[^"\s@]*)`)

// cli, mlsinterop and sidecarctl each stay one package, and no file names one by its path. The release
// rewrites every quoted path under the root's to .../sidecar/v2026 in every .go file and Makefile
// (build/all/run.sh's go_edit_require_subpackages, which sidecar_release_edit runs), and these modules
// keep their unversioned paths. So a package beside a module's own is one the rewrite would import
// as nothing provides, and so is the module's own package wherever a file names it: an external test
// of mlsinterop, in package mlsinterop_test, would import .../sidecar/v2026/mlsinterop. Each file is
// read as the rewrite leaves it, which on a release branch is as it stands.
func (self *repository) untaggedSubpackageFindings(t testing.TB) []string {
	t.Helper()
	packageNames := map[string]bool{}
	filePaths := []string{}
	for _, file := range self.sourceFiles(t) {
		filePaths = append(filePaths, file.path)
		for _, name := range untaggedModuleNames {
			if strings.HasPrefix(file.packageName, name+"/") {
				packageNames[file.packageName] = true
			}
		}
	}
	findings := []string{}
	for _, packageName := range slices.Sorted(maps.Keys(packageNames)) {
		module, _, _ := strings.Cut(packageName, "/")
		findings = append(findings, findingf("%s: a package beside %s's own, which the release's rewrite would import as one under .../sidecar/v2026 that nothing provides", packageName, module))
	}
	// the rewrite's other files, which find(1) names by -iname 'Makefile'
	err := filepath.WalkDir(self.topDirectory, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skippedDirectoryNames[entry.Name()] && walkPath != self.topDirectory {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(entry.Name(), "Makefile") {
			filePaths = append(filePaths, walkPath)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	suffix := self.releaseSuffix
	if suffix == "" {
		suffix = releaseSuffix
	}
	for _, filePath := range filePaths {
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		// smtpproof's pass runs before the root's, as sidecar_release_edit has it
		rewritten := releaseRewritePath(string(data), sidecarBasePath+"/smtpproof", suffix)
		rewritten = releaseRewritePath(rewritten, sidecarBasePath, suffix)
		for index, line := range strings.Split(rewritten, "\n") {
			for _, match := range quotedRepositoryPathPattern.FindAllStringSubmatch(line, -1) {
				quotedPath := match[1]
				base := firstPartyBase(quotedPath)
				for _, name := range untaggedModuleNames {
					if underPath(base, sidecarBasePath+"/"+name) && quotedPath != base {
						findings = append(findings, findingf("%s:%d: the release's rewrite makes this %q, which nothing provides: %s keeps its unversioned path", self.displayPath(filePath), index+1, quotedPath, name))
					}
				}
			}
		}
	}
	return findings
}
