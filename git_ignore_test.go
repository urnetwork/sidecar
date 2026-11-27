//go:build !ios_extension && !sidecar_http

// GIT-M13-01's ignore tests: the rules of testdata/git/ignore/corpus.txt matched here and by stock git's check-ignore
// --no-index -v -n, case-sensitive and not, against the answers stock git gave (expected.txt, expected-icase.txt), and
// git's wildmatch vectors.

package sidecar

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The corpus: its rule files' bytes by name, and its paths with whether each is a directory.
type gitIgnoreCorpus struct {
	files       map[string][]byte
	paths       []string
	directories map[string]bool
}

// Reads the corpus (see its header).
func gitReadIgnoreCorpus(t *testing.T) *gitIgnoreCorpus {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "git", "ignore", "corpus.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	corpus := &gitIgnoreCorpus{files: map[string][]byte{}, directories: map[string]bool{}}
	unquote := func(line int, text string) string {
		value, err := strconv.Unquote(text)
		if err != nil {
			t.Fatalf("corpus line %d: %v", line, err)
		}
		return value
	}
	scanner := bufio.NewScanner(file)
	collecting := ""
	lines := []string{}
	for line := 1; scanner.Scan(); line += 1 {
		text := scanner.Text()
		switch {
		case collecting != "" && text == "end":
			corpus.files[collecting] = []byte(strings.Join(lines, "\n") + "\n")
			collecting, lines = "", nil
		case collecting != "":
			lines = append(lines, unquote(line, text))
		case text == "" || strings.HasPrefix(text, "#"):
		case strings.HasPrefix(text, "file "):
			collecting = strings.TrimPrefix(text, "file ")
		case strings.HasPrefix(text, "rawfile "):
			name, content, _ := strings.Cut(strings.TrimPrefix(text, "rawfile "), " ")
			corpus.files[name] = []byte(unquote(line, content))
		case strings.HasPrefix(text, "path "):
			kind, quoted, _ := strings.Cut(strings.TrimPrefix(text, "path "), " ")
			name := unquote(line, quoted)
			corpus.paths = append(corpus.paths, name)
			corpus.directories[name] = kind == "d"
		default:
			t.Fatalf("corpus line %d: %q", line, text)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return corpus
}

// Makes the corpus's worktree in a fresh directory: stock git's .git where the host has git, the rule files, and
// every path.
func (self *gitIgnoreCorpus) materialize(t *testing.T, gitPath string) string {
	t.Helper()
	dir := t.TempDir()
	if gitPath != "" {
		if out, err := gitTestRunGit(t, gitPath, dir, nil, "init", "-q"); err != nil {
			t.Fatalf("git init: %v: %s", err, out)
		}
	}
	write := func(name string, content []byte) {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range self.paths {
		if self.directories[name] {
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(name)), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		write(name, []byte("x\n"))
	}
	for name, content := range self.files {
		write(name, content)
	}
	return dir
}

// One answer as check-ignore -v gives it: source:line:pattern, or "" for no match.
func gitIgnoreAnswer(match *GitIgnoreMatch) string {
	if match == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d:%s", match.Source, match.Line, match.Pattern)
}

// Stock git's answers for the corpus's paths, core.ignorecase as given.
func (self *gitIgnoreCorpus) stockAnswers(t *testing.T, gitPath string, dir string, ignoreCase bool) map[string]string {
	t.Helper()
	stdin := strings.Join(self.paths, "\x00") + "\x00"
	out, err := gitTestRunGit(t, gitPath, dir, []byte(stdin), "-c", "core.ignorecase="+strconv.FormatBool(ignoreCase),
		"check-ignore", "--no-index", "-v", "-n", "-z", "--stdin")
	// check-ignore answers 1 where nothing is ignored, which this corpus never is
	if err != nil {
		t.Fatalf("git check-ignore: %v: %s", err, out)
	}
	fields := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(fields)%4 != 0 {
		t.Fatalf("git check-ignore gave %d fields", len(fields))
	}
	answers := map[string]string{}
	for at := 0; at < len(fields); at += 4 {
		answer := ""
		if fields[at] != "" {
			answer = fmt.Sprintf("%s:%s:%s", fields[at], fields[at+1], fields[at+2])
		}
		answers[fields[at+3]] = answer
	}
	return answers
}

// The answers a committed expected file holds, each line a quoted path and a quoted answer.
func gitReadIgnoreExpected(t *testing.T, name string) map[string]string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "git", "ignore", name))
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		quotedPath, err := strconv.QuotedPrefix(line)
		if err != nil {
			t.Fatalf("%s: %q: %v", name, line, err)
		}
		filePath, _ := strconv.Unquote(quotedPath)
		answer, err := strconv.Unquote(strings.TrimSpace(line[len(quotedPath):]))
		if err != nil {
			t.Fatalf("%s: %q: %v", name, line, err)
		}
		answers[filePath] = answer
	}
	return answers
}

// Writes answers as an expected file, in the corpus's order.
func (self *gitIgnoreCorpus) writeExpected(t *testing.T, name string, answers map[string]string) {
	t.Helper()
	builder := &strings.Builder{}
	for _, filePath := range self.paths {
		fmt.Fprintf(builder, "%s %s\n", strconv.Quote(filePath), strconv.Quote(answers[filePath]))
	}
	if err := os.WriteFile(filepath.Join("testdata", "git", "ignore", name), []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The corpus's every path matches here as stock git's check-ignore matched it, case-sensitive and not.
func TestIgnoreCorpus(t *testing.T) {
	corpus := gitReadIgnoreCorpus(t)
	gitPath := ""
	if found, err := lookGit(); err == nil {
		gitPath = found
	}
	regenerate := os.Getenv("SIDECAR_REGENERATE_GIT_VECTORS") == "1"
	if regenerate && gitPath == "" {
		t.Fatal("regenerating the corpus's answers needs stock git")
	}
	dir := corpus.materialize(t, gitPath)
	fileSystem, closeFileSystem, err := NewGitOsFileSystem(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileSystem()
	for _, ignoreCase := range []bool{false, true} {
		expectedName := "expected.txt"
		if ignoreCase {
			expectedName = "expected-icase.txt"
		}
		if gitPath != "" {
			stock := corpus.stockAnswers(t, gitPath, dir, ignoreCase)
			if regenerate {
				corpus.writeExpected(t, expectedName, stock)
			}
			expected := gitReadIgnoreExpected(t, expectedName)
			for _, filePath := range corpus.paths {
				if stock[filePath] != expected[filePath] {
					t.Fatalf("%s: stock git now answers %q for %q, the corpus %q", expectedName, stock[filePath], filePath, expected[filePath])
				}
			}
		}
		expected := gitReadIgnoreExpected(t, expectedName)
		ignore, err := NewGitIgnore(fileSystem, DefaultGitSettings(), ignoreCase)
		if err != nil {
			t.Fatal(err)
		}
		for _, filePath := range corpus.paths {
			match, err := ignore.Match(filePath, corpus.directories[filePath])
			if err != nil {
				t.Fatal(err)
			}
			if answer := gitIgnoreAnswer(match); answer != expected[filePath] {
				t.Fatalf("ignorecase %v: %q matches %q here, %q in stock git", ignoreCase, filePath, answer, expected[filePath])
			}
		}
	}
	// a walk passes over what is ignored and never enters .git
	ignore, err := NewGitIgnore(fileSystem, DefaultGitSettings(), false)
	if err != nil {
		t.Fatal(err)
	}
	worktree := newGitWorktree(fileSystem, DefaultGitSettings(), newGitObjectStore(fileSystem, DefaultGitSettings()), &GitWorktreeHabits{})
	walked := map[string]bool{}
	if err := worktree.Walk("", ignore, func(file *GitWorktreeFile) error {
		if strings.HasPrefix(file.Path, ".git/") || path.Base(file.Path) == ".git" {
			t.Fatalf("the walk entered %q", file.Path)
		}
		walked[file.Path] = file.Ignored
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !walked["build"] || !walked["debug.log"] || walked["important.log"] || walked["README"] {
		t.Fatalf("the walk's verdicts: build %v, debug.log %v, important.log %v, README %v", walked["build"], walked["debug.log"], walked["important.log"], walked["README"])
	}
	if _, entered := walked["build/out.o"]; entered {
		t.Fatal("the walk entered an ignored directory")
	}
}

// git's wildmatch on vectors from its t3070, with and without WM_PATHNAME.
func TestWildmatchVectors(t *testing.T) {
	cases := []struct {
		pattern  string
		text     string
		pathname bool
		match    bool
	}{
		{"foo", "foo", true, true}, {"bar", "foo", true, false}, {"", "", true, true}, {"???", "foo", true, true},
		{"??", "foo", true, false}, {"*", "foo", true, true}, {"f*", "foo", true, true}, {"*f", "foo", true, false},
		{"*foo*", "foo", true, true}, {"*ob*a*r*", "foobar", true, true}, {"*ab", "aaaaaaabababab", true, true},
		{"foo\\*", "foo*", true, true}, {"foo\\*bar", "foobar", true, false}, {"f\\\\oo", "f\\oo", true, true},
		{"*[al]?", "ball", true, true}, {"[ten]", "ten", true, false}, {"**[!te]", "ten", true, true},
		{"**[!ten]", "ten", true, false}, {"t[a-g]n", "ten", true, true}, {"t[!a-g]n", "ten", true, false},
		{"t[!a-g]n", "ton", true, true}, {"t[^a-g]n", "ton", true, true}, {"a[]]b", "a]b", true, true},
		{"a[]-]b", "a-b", true, true}, {"a[]-]b", "a]b", true, true}, {"a[]-]b", "aab", true, false},
		{"a[]a-]b", "aab", true, true}, {"]", "]", true, true},
		{"foo*bar", "foo/baz/bar", true, false}, {"foo*bar", "foo/baz/bar", false, true},
		{"foo**bar", "foo/baz/bar", true, false}, {"foo**bar", "foobazbar", true, true},
		{"foo/**/bar", "foo/baz/bar", true, true}, {"foo/**/**/bar", "foo/baz/bar", true, true},
		{"foo/**/bar", "foo/b/a/z/bar", true, true}, {"foo/**/bar", "foo/bar", true, true},
		{"foo/**/**/bar", "foo/bar", true, true}, {"foo?bar", "foo/bar", true, false}, {"foo[/]bar", "foo/bar", true, false},
		{"foo[^a-z]bar", "foo/bar", true, false}, {"f[^eiu][^eiu][^eiu][^eiu][^eiu]r", "foo-bar", true, true},
		{"**/foo", "foo", true, true}, {"**/foo", "XXX/foo", true, true}, {"**/foo", "bar/baz/foo", true, true},
		{"*/foo", "bar/baz/foo", true, false}, {"**/bar*", "foo/bar/baz", true, false},
		{"**/bar/*", "deep/foo/bar/baz", true, true}, {"**/bar/*", "deep/foo/bar/baz/", true, false},
		{"**/bar/**", "deep/foo/bar/baz/", true, true}, {"**/bar/*", "deep/foo/bar", true, false},
		{"**/bar/**", "deep/foo/bar/", true, true}, {"*/bar/**", "deep/foo/bar/baz/x", true, false},
		{"*/bar/**", "foo/bar/baz/x", true, true}, {"[[:alpha:]][[:digit:]][[:upper:]]", "a1B", true, true},
		{"[[:digit:][:upper:][:space:]]", "a", true, false}, {"[[:digit:][:upper:][:space:]]", "A", true, true},
		{"[[:digit:][:upper:][:space:]]", "1", true, true}, {"[[:digit:][:upper:][:space:]]", " ", true, true},
		{"[[:digit:][:upper:][:spaci:]]", "1", true, false}, {"[[:xdigit:]]", "f", true, true},
		{"*.c", "mozilla-sha1/sha1.c", true, false}, {"*.c", "mozilla-sha1/sha1.c", false, true},
	}
	for _, c := range cases {
		if got := gitWildmatch(c.pattern, c.text, c.pathname, false); got != c.match {
			t.Fatalf("wildmatch(%q, %q, pathname %v) = %v, git's %v", c.pattern, c.text, c.pathname, got, c.match)
		}
	}
}
