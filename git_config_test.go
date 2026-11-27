//go:build !ios_extension && !sidecar_http

// GIT-M13-01's config tests (DESIGN-COMPUTE §13.7, IC-7): after every sequence of writes .git/config holds the
// repository format, the remote and the branches alone, with user.* kept, by this git's parser and stock git's; a
// config another hand planted commands in is clean before a command runs; a sha256 repository is refused before
// anything is written.

package sidecar

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every key a config holds, by this git's parser and, where the host has git, by stock git's config --list.
func gitConfigKeysOf(t *testing.T, gitPath string, dir string) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	read, err := gitParseConfig(content)
	if err != nil {
		t.Fatalf("the config does not parse here: %v\n%s", err, content)
	}
	keys := slices.Clone(read.keys)
	if gitPath != "" {
		out, err := gitTestRunGit(t, gitPath, dir, nil, "config", "--file", ".git/config", "--list", "--null")
		if err != nil {
			t.Fatalf("git config --list: %v: %s", err, out)
		}
		for _, item := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
			key, _, _ := strings.Cut(item, "\n")
			keys = append(keys, key)
		}
	}
	return keys
}

// Holds every key of the config to the ones gitWriteConfig writes.
func gitCheckConfigClean(t *testing.T, gitPath string, dir string, step string) {
	t.Helper()
	for _, key := range gitConfigKeysOf(t, gitPath, dir) {
		if !gitConfigKeyAllowed(key) {
			content, _ := os.ReadFile(filepath.Join(dir, ".git", "config"))
			t.Fatalf("%s: the config holds %q:\n%s", step, key, content)
		}
	}
}

// After every sequence of writes, and after an open of a config a hand planted commands in, the config holds nothing a
// git could run; user.* is kept exactly, read back by stock git as written.
func TestConfigHoldsNoCommand(t *testing.T) {
	gitPath := ""
	if found, err := lookGit(); err == nil {
		gitPath = found
	}
	ctx := context.Background()
	dir := t.TempDir()
	fileSystem, closeFileSystem, err := NewGitOsFileSystem(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileSystem()
	repository, err := InitGitRepository(ctx, &GitInitArgs{FileSystem: fileSystem, Remote: "ur://example/id:" + NewId().String()})
	if err != nil {
		t.Fatal(err)
	}
	gitCheckConfigClean(t, gitPath, dir, "init")
	for _, branch := range []string{"main", "feature/x", `quote"in-name`, "semi;colon#hash", "tab-free_+=,%"} {
		if err := repository.SetUpstream(branch, GitBranchPrefix+branch); err != nil {
			t.Fatalf("%q: %v", branch, err)
		}
		gitCheckConfigClean(t, gitPath, dir, "upstream "+branch)
	}
	if gitPath != "" {
		out, err := gitTestRunGit(t, gitPath, dir, nil, "config", "--file", ".git/config", "branch.semi;colon#hash.merge")
		if err != nil || strings.TrimSpace(out) != "refs/heads/semi;colon#hash" {
			t.Fatalf("stock git reads the branch's merge as %q: %v", out, err)
		}
	}
	for _, refused := range []string{"has space", "new\nline", "..", "x.lock"} {
		if err := repository.SetUpstream(refused, GitBranchPrefix+"main"); err == nil {
			t.Fatalf("an upstream for %q was kept", refused)
		}
	}
	if err := repository.SetRemote("ur://example/id:" + NewId().String() + "\n[core]\n\tfsmonitor = planted"); err == nil {
		t.Fatal("a remote holding a line break was kept")
	}
	// a planted config: commands, an alias, an include, a filter, hooks; user.* with every character a value quotes
	planted := strings.Join([]string{
		"[core]", "\trepositoryformatversion = 0", "\tfsmonitor = /bin/planted", "\thooksPath = /tmp/planted",
		"\tsshCommand = planted", "\tpager = planted", "\teditor = planted",
		"[alias]", "\tplanted = !sh -c planted",
		"[include]", "\tpath = /tmp/planted.config",
		"[filter \"planted\"]", "\tclean = planted", "\tsmudge = planted",
		"[user]", "\tname = \"Mal \\\"lory\\\" # ; \\\\ name \"", "\temail = mal@ur.invalid",
		"[remote \"origin\"]", "\turl = ur://planted/id:00000000000000000000000000",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(planted), 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGitRepository(ctx, &GitOpenArgs{FileSystem: fileSystem})
	if err != nil {
		t.Fatal(err)
	}
	gitCheckConfigClean(t, gitPath, dir, "open of a planted config")
	name, email := reopened.User()
	if name != `Mal "lory" # ; \ name ` || email != "mal@ur.invalid" {
		t.Fatalf("user.* read as %q %q", name, email)
	}
	if reopened.Remote() != repository.Remote() {
		t.Fatalf("the planted remote %q took the state's place", reopened.Remote())
	}
	if gitPath != "" {
		out, err := gitTestRunGit(t, gitPath, dir, nil, "config", "--file", ".git/config", "user.name")
		if err != nil || strings.TrimSuffix(out, "\n") != name {
			t.Fatalf("stock git reads user.name as %q: %v", out, err)
		}
	}
	if err := reopened.SetUpstream("feature/x", ""); err != nil {
		t.Fatal(err)
	}
	gitCheckConfigClean(t, gitPath, dir, "an upstream dropped")
	for _, key := range gitConfigKeysOf(t, "", dir) {
		if strings.HasPrefix(key, "branch.feature/x.") {
			t.Fatalf("a dropped upstream left %q", key)
		}
	}
}

// A repository whose format this git does not read, sha256's among them, is refused before anything is written.
func TestSha256RepositoryRefused(t *testing.T) {
	ctx := context.Background()
	for _, config := range []string{
		"[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n",
		"[core]\n\trepositoryformatversion = 1\n[extensions]\n\tpartialclone = origin\n",
		"[core]\n\trepositoryformatversion = 2\n",
	} {
		dir := t.TempDir()
		for _, directory := range []string{".git/objects", ".git/refs/heads"} {
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(directory)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
		fileSystem, closeFileSystem, err := NewGitOsFileSystem(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenGitRepository(ctx, &GitOpenArgs{FileSystem: fileSystem})
		closeFileSystem()
		if !errors.Is(err, ErrGitRepositoryFormat) {
			t.Fatalf("%q: %v", config, err)
		}
		if _, err := os.Stat(filepath.Join(dir, ".git", "ur")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%q: a refused open wrote .git/ur", config)
		}
		content, _ := os.ReadFile(filepath.Join(dir, ".git", "config"))
		if string(content) != config {
			t.Fatalf("%q: a refused open rewrote the config", config)
		}
	}
}
