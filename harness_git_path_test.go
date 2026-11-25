//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"errors"
	"testing"
)

// Every .git spelling git refuses, and the folded ones, is refused as a component anywhere in a path, for every file
// tool's path; names that only look alike pass.
func TestHarnessGitPathEverySpellingRefused(t *testing.T) {
	refused := []string{
		".git", ".GIT", ".Git", ".gIT",
		".git.", ".git ", ".git. .", ".git...", ".GIT .",
		".git::$INDEX_ALLOCATION", ".git:stream",
		"git~1", "GIT~1", "git~1.", "Git~1 ",
		// HFS+'s ignorable code points: a zero-width non-joiner, a left-to-right mark, a byte order mark
		".g\u200cit", ".gi\u200et", ".git\ufeff", "\u200d.git",
		// Unicode folding: fullwidth letters, a capital I with a dot above, a combining mark
		"\uff0e\uff47\uff49\uff54", ".G\u0130T", ".gi\u0307t",
	}
	for _, name := range refused {
		if !harnessGitPathComponent(name) {
			t.Errorf("%q passes as a component", name)
		}
		for _, path := range []string{name, "repo/" + name + "/config", "a/b/" + name} {
			if _, err := harnessWorkspacePath(path); !errors.Is(err, ErrHarnessWorkspacePath) {
				t.Errorf("%q passes as a path: %v", path, err)
			}
		}
	}
	for _, name := range []string{".gitignore", ".github", ".gitattributes", "git", ".git2", "x.git", "gitk", "git~2x", ".gi", "agit"} {
		if harnessGitPathComponent(name) {
			t.Errorf("%q is refused", name)
		}
		if _, err := harnessWorkspacePath("repo/" + name); err != nil {
			t.Errorf("repo/%q refused: %v", name, err)
		}
	}
}
