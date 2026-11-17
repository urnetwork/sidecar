//go:build sidecar_check

// §4.7's hygiene row, the release's rewrite of this repository's quoted paths (§4.9). build/all/run.sh
// rewrites them in every .go file and Makefile with seds that read a line at a time, and a path a line
// keeps in its development spelling names, on a version branch, a package no tag provides. The seds'
// model is releaseRewriteRepository, which release_step_test.go holds to run.sh's own functions.

package check

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A file the release's seds rewrite, as the model leaves it.
type releaseRewrittenFile struct {
	// its slash path from the repository's top
	displayPath string
	rewritten   string
}

// Each file the release's seds rewrite that the rules read, as the model leaves it: every .go file of
// every module, and every Makefile, which find(1) names by -iname 'Makefile'. testdata/, third_party/
// and the documents stay out, as they do of every rule here. On a release branch the files already
// carry the rewrite, and the model changes none of what it left.
func (self *repository) releaseRewrittenFiles(t testing.TB) []*releaseRewrittenFile {
	t.Helper()
	filePaths := []string{}
	for _, file := range self.sourceFiles(t) {
		filePaths = append(filePaths, file.path)
	}
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
	files := []*releaseRewrittenFile{}
	for _, filePath := range filePaths {
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		displayPath := self.displayPath(filePath)
		files = append(files, &releaseRewrittenFile{
			displayPath: displayPath,
			rewritten:   releaseRewriteRepository(string(data), displayPath, suffix),
		})
	}
	return files
}

// A quoted path of this repository that the release's rewrite leaves without its /vN: on a line naming
// the root beside a subpackage, whose exact pass gives the line the /vN that the subpackage pass then
// skips, or on a line already holding one. On a version branch it names the development module, which
// no tag provides: the search oracle's allow-list did, and the release's make check then read the
// oracle's own import of .../v2026/protocol as index code (QD-1003). cli's and mlsinterop's paths stay
// unversioned by design (§4.9), and what the rewrite does to them is the untagged rule's.
func (self *repository) unversionedReleasePathFindings(t testing.TB) []string {
	t.Helper()
	suffix := self.releaseSuffix
	if suffix == "" {
		suffix = releaseSuffix
	}
	// the root's and smtpproof's tags, and the modules that keep their development paths
	keptPaths := []string{sidecarBasePath + suffix, sidecarBasePath + "/smtpproof" + suffix}
	for _, name := range untaggedModuleNames {
		keptPaths = append(keptPaths, sidecarBasePath+"/"+name)
	}
	findings := []string{}
	for _, file := range self.releaseRewrittenFiles(t) {
		for index, line := range strings.Split(file.rewritten, "\n") {
			for _, match := range quotedRepositoryPathPattern.FindAllStringSubmatch(line, -1) {
				quotedPath := match[1]
				if slices.ContainsFunc(keptPaths, func(keptPath string) bool { return underPath(quotedPath, keptPath) }) {
					continue
				}
				findings = append(findings, findingf("%s:%d: the release's rewrite leaves %q without %s, a path no module of the release has", file.displayPath, index+1, quotedPath, suffix))
			}
		}
	}
	return findings
}
