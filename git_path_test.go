//go:build !ios_extension && !sidecar_http

// GIT-M13-01's path safety test: gitCheckPath against testdata/git/path/corpus.txt, git's 2014-2025 advisory paths
// among them, and, where the host has git, each path a tree can hold checked against stock git's fsck --strict.

package sidecar

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// One corpus line.
type gitPathCase struct {
	verdict string
	path    string
	mode    uint32
	line    int
}

// The corpus's lines.
func gitPathCorpus(t *testing.T) []gitPathCase {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "git", "path", "corpus.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cases := []gitPathCase{}
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line += 1 {
		text := scanner.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		verdict, rest, _ := strings.Cut(text, " ")
		quoted, err := strconv.QuotedPrefix(rest)
		if err != nil {
			t.Fatalf("corpus line %d: %v", line, err)
		}
		path, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("corpus line %d: %v", line, err)
		}
		mode := EvsGitModeFile
		if fields := strings.Fields(rest[len(quoted):]); 0 < len(fields) {
			if parsed, err := strconv.ParseUint(fields[0], 8, 32); err == nil {
				mode = uint32(parsed)
			}
		}
		switch verdict {
		case "refuse", "stricter", "allow":
		default:
			t.Fatalf("corpus line %d: verdict %q", line, verdict)
		}
		cases = append(cases, gitPathCase{verdict: verdict, path: path, mode: mode, line: line})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return cases
}

// Whether a tree can hold path: names that are not empty and hold no NUL.
func gitPathRepresentable(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
		return false
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			return false
		}
	}
	return true
}

// Every corpus path's verdict holds, its refusal naming the rule and never the path; and where the host has git, a
// tree holding it is refused by fsck --strict exactly where the corpus says refuse.
func TestPathSafetyCorpus(t *testing.T) {
	cases := gitPathCorpus(t)
	if len(cases) < 50 {
		t.Fatalf("the corpus holds %d paths", len(cases))
	}
	for _, c := range cases {
		err := gitCheckPath(c.path, c.mode)
		refused := err != nil
		if refused != (c.verdict != "allow") {
			t.Fatalf("line %d: %q with mode %o: %v, the corpus says %s", c.line, c.path, c.mode, err, c.verdict)
		}
		if refused {
			pathError := &GitPathError{}
			// the text is the rule alone, one of gitCheckPath's fixed words, which name no path a caller gave
			if !errors.As(err, &pathError) || pathError.Path != c.path || err.Error() != ErrGitPathUnsafe.Error()+": "+pathError.Rule ||
				(strings.Contains(c.path, "/") && strings.Contains(pathError.Rule, c.path)) {
				t.Fatalf("line %d: a refusal that names its path or no rule: %v", c.line, err)
			}
		}
	}
	gitPath := gitTestStockGit(t)
	for _, c := range cases {
		if !gitPathRepresentable(c.path) {
			continue
		}
		dir := t.TempDir()
		if out, err := gitTestRunGit(t, gitPath, dir, nil, "init", "-q"); err != nil {
			t.Fatalf("git init: %v: %s", err, out)
		}
		fileSystem, closeFileSystem, err := NewGitOsFileSystem(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		objects := newGitObjectStore(fileSystem, DefaultGitSettings())
		names := strings.Split(c.path, "/")
		oid, err := objects.WriteGitObject(evsGitBlobKind, []byte("target"))
		if err != nil {
			t.Fatal(err)
		}
		mode := c.mode
		for index := len(names) - 1; index >= 0; index -= 1 {
			tree, err := objects.WriteTree(&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: mode, Name: []byte(names[index]), Oid: oid}}})
			if err != nil {
				t.Fatalf("line %d: %v", c.line, err)
			}
			oid, mode = tree, EvsGitModeDirectory
		}
		commit := gitTestCommit(t, objects, oid, nil, "corpus")
		refs := newGitRefs(fileSystem, DefaultGitSettings())
		if err := refs.Set(GitBranchPrefix+"main", commit); err != nil {
			t.Fatal(err)
		}
		if err := refs.SetHead(&GitHead{Symbolic: GitBranchPrefix + "main"}); err != nil {
			t.Fatal(err)
		}
		closeFileSystem()
		out, err := gitTestRunGit(t, gitPath, dir, nil, "fsck", "--strict", "--no-dangling")
		fsckRefused := err != nil
		if fsckRefused != (c.verdict == "refuse") {
			t.Fatalf("line %d: %q: stock git's fsck refused %v, the corpus says %s: %s", c.line, c.path, fsckRefused, c.verdict, out)
		}
	}
}
