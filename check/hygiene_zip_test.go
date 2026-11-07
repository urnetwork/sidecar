//go:build sidecar_check

// The go command refuses a whole module zip over one path it does not take, so such a path in a
// tagged tree makes the tag a module no consumer can download, and a release that pushed the tag
// has burned its version. §22.4's release fixture found testdata/fuzz/FuzzParseSocketAddress/nul
// that way; this finds it in make check. The rules are the go command's own: golang.org/x/mod's
// CheckFilePath for each path, and its zip's case-insensitive collision check over a module's paths.
// They are written out here, from the copy the go command vendors, because the root module takes no
// dependency for a check. TestModuleZipRuleAgreesWithTheGoCommand holds the two to each other.
//
// Each path is read as the zip of the module holding it names it: from the nearest directory with a
// go.mod, as the go command leaves every such directory out of its parent's zip, testdata's
// included. A path in no module, such as a design document beside a release branch's v2026/, is
// read from the top. It is in no zip, and a Windows checkout cannot hold it either.

package check

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The path elements Windows reserves, matched without case on the part before the first dot.
var windowsReservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

// The ASCII punctuation a module's file path may hold, beside ASCII letters and digits. The go
// command leaves out the characters shells and some systems give a meaning: " ' * < > ? ` | : \
const moduleFilePunctuation = "!#$%&()+,-.=@[]^_{}~ "

// Why the go command refuses a slash path, from its module's root, in a module zip; empty when it
// takes it.
func moduleFilePathProblem(filePath string) string {
	if !utf8.ValidString(filePath) {
		return "it is not UTF-8"
	}
	if filePath == "go.mod" {
		return ""
	}
	if strings.ToLower(filePath) == "go.mod" {
		return "a module's go.mod is spelled in lower case"
	}
	for _, element := range strings.Split(filePath, "/") {
		if element == "" {
			return "it has an empty element"
		}
		if strings.Count(element, ".") == len(element) {
			return fmt.Sprintf("its element %q is only dots", element)
		}
		if strings.HasSuffix(element, ".") {
			return fmt.Sprintf("its element %q ends in a dot", element)
		}
		for _, character := range element {
			allowed := false
			if character < utf8.RuneSelf {
				allowed = '0' <= character && character <= '9' || 'A' <= character && character <= 'Z' ||
					'a' <= character && character <= 'z' || strings.ContainsRune(moduleFilePunctuation, character)
			} else {
				allowed = unicode.IsLetter(character)
			}
			if !allowed {
				return fmt.Sprintf("its element %q holds %q", element, character)
			}
		}
		short, _, _ := strings.Cut(element, ".")
		for _, reserved := range windowsReservedNames {
			if strings.EqualFold(short, reserved) {
				return fmt.Sprintf("its element %q is %s, which Windows reserves", element, reserved)
			}
		}
	}
	return ""
}

// A key two strings share exactly when strings.EqualFold holds between them: each rune becomes the
// least rune of its case orbit.
func caseFoldKey(text string) string {
	var key strings.Builder
	for _, character := range text {
		least := character
		for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
			least = min(least, next)
		}
		key.WriteRune(least)
	}
	return key.String()
}

// What the go command refuses in one module's zip: each path on its own, then any two paths, files
// or the directories holding them, that differ only in case. relativePaths are slash paths from the
// module's root, and each finding names its path through display.
func moduleZipPathFindings(relativePaths []string, display func(relativePath string) string) []string {
	findings := []string{}
	keyPaths := map[string]string{}
	collided := map[string]bool{}
	for _, relativePath := range slices.Sorted(slices.Values(relativePaths)) {
		if problem := moduleFilePathProblem(relativePath); problem != "" {
			findings = append(findings, findingf("%s: a module zip may not hold this path: %s", display(relativePath), problem))
			continue
		}
		for name := relativePath; name != "."; name = path.Dir(name) {
			key := caseFoldKey(name)
			other, present := keyPaths[key]
			if !present {
				keyPaths[key] = name
				continue
			}
			if other != name && !collided[key] {
				collided[key] = true
				findings = append(findings, findingf("%s: a module zip may not hold this path: %q differs from %q only in case", display(relativePath), name, other))
			}
			break
		}
	}
	return findings
}

// Every file a module zip of this checkout could hold, by slash path from the top directory. Where
// the top is a git work tree's, git's tracked and unignored files, which is what a tag's zip is made
// of, and which hold both of two paths differing in case where a case-insensitive file system holds
// one. Elsewhere, such as a fixture, what is on disk. Links are left out, as a zip leaves them out.
func (self *repository) zipCandidatePaths() ([]string, error) {
	candidates := []string{}
	if self.isGitTop() {
		command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
		command.Dir = self.topDirectory
		output, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("git ls-files in %s: %w", self.topDirectory, err)
		}
		for _, name := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
			info, err := os.Lstat(filepath.Join(self.topDirectory, filepath.FromSlash(name)))
			// a file git still lists after its deletion is in no tree this checkout will tag
			if name == "" || err != nil || !info.Mode().IsRegular() {
				continue
			}
			candidates = append(candidates, name)
		}
		return candidates, nil
	}
	err := filepath.WalkDir(self.topDirectory, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		relativePath, err := filepath.Rel(self.topDirectory, walkPath)
		if err != nil {
			return err
		}
		candidates = append(candidates, filepath.ToSlash(relativePath))
		return nil
	})
	return candidates, err
}

// True when the top directory is the top of a git work tree. A directory inside some other work
// tree, as a fixture under a checkout's temporary directory might be, is read from disk instead,
// because that tree's ignore rules would hide the fixture's files.
func (self *repository) isGitTop() bool {
	command := exec.Command("git", "rev-parse", "--show-toplevel")
	command.Dir = self.topDirectory
	output, err := command.Output()
	if err != nil {
		return false
	}
	top, err := filepath.EvalSymlinks(string(bytes.TrimSpace(output)))
	return err == nil && top == self.topDirectory
}

// The hygiene rule: each module's paths, read from that module's root.
func (self *repository) moduleZipFindings(t testing.TB) []string {
	t.Helper()
	candidates, err := self.zipCandidatePaths()
	if err != nil {
		return []string{findingf("listing the paths a module zip would hold: %v", err)}
	}
	// a directory holding a go.mod in any case starts a module, as the go command reads one
	moduleRoots := []string{"."}
	for _, candidate := range candidates {
		if strings.EqualFold(path.Base(candidate), "go.mod") {
			moduleRoots = append(moduleRoots, path.Dir(candidate))
		}
	}
	// deepest first, so a nested module's paths are not read as its parent's
	slices.SortFunc(moduleRoots, func(a string, b string) int {
		return len(b) - len(a)
	})
	moduleRootPaths := map[string][]string{}
	for _, candidate := range candidates {
		for _, root := range moduleRoots {
			if root == "." || underPath(candidate, root) {
				moduleRootPaths[root] = append(moduleRootPaths[root], strings.TrimPrefix(candidate, root+"/"))
				break
			}
		}
	}
	findings := []string{}
	for _, root := range slices.Sorted(maps.Keys(moduleRootPaths)) {
		display := func(relativePath string) string {
			return path.Join(root, relativePath)
		}
		findings = append(findings, moduleZipPathFindings(moduleRootPaths[root], display)...)
	}
	return findings
}
