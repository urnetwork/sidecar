//go:build !ios_extension && !sidecar_http

// GIT-M13-01's worktree tests (DESIGN-COMPUTE §13.4's modes, collisions and workspace rows, §13.7): a folding
// collision on a faked case-insensitive file system, a mode kept from the index on one faked without an executable bit,
// links whose targets leave the worktree checked out as text, nothing written through a link or for an unsafe tree, and
// a full worktree that stock git opens and fscks clean where the host has git.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// One file a test tree holds.
type gitTestFile struct {
	path    string
	mode    uint32
	content string
}

// Writes files as blobs and nested trees through objects, answering the root tree's oid.
func gitTestTree(t *testing.T, objects *GitObjectStore, files []gitTestFile) EvsGitOid {
	t.Helper()
	var build func(prefix string) EvsGitOid
	build = func(prefix string) EvsGitOid {
		tree := &EvsGitTree{}
		directories := []string{}
		for _, file := range files {
			rest, found := strings.CutPrefix(file.path, prefix)
			if !found {
				continue
			}
			name, _, nested := strings.Cut(rest, "/")
			if nested {
				if !slices.Contains(directories, name) {
					directories = append(directories, name)
				}
				continue
			}
			oid, err := objects.WriteGitObject(evsGitBlobKind, []byte(file.content))
			if err != nil {
				t.Fatal(err)
			}
			if file.mode == EvsGitModeGitlink {
				oid = gitBlobOid([]byte("a commit elsewhere " + file.content))
			}
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: file.mode, Name: []byte(name), Oid: oid})
		}
		for _, name := range directories {
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(name), Oid: build(prefix + name + "/")})
		}
		oid, err := objects.WriteTree(tree)
		if err != nil {
			t.Fatal(err)
		}
		return oid
	}
	return build("")
}

// A commit of tree with parents, by a fixed ident.
func gitTestCommit(t *testing.T, objects *GitObjectStore, tree EvsGitOid, parents []EvsGitOid, message string) EvsGitOid {
	t.Helper()
	ident, err := (&EvsGitIdent{Name: []byte("test"), Email: []byte("test@ur.invalid"), TimeSeconds: 1700000000, TimeZone: "+0000"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	oid, err := objects.WriteCommit(&EvsGitCommit{TreeOid: tree, ParentOids: parents, Author: ident, Committer: ident, Message: []byte(message + "\n")})
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// A new repository on fileSystem.
func gitTestInit(t *testing.T, fileSystem GitFileSystem) *GitRepository {
	t.Helper()
	repository, err := InitGitRepository(context.Background(), &GitInitArgs{FileSystem: fileSystem, Settings: DefaultGitSettings()})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

// A new repository in a fresh directory of this host.
func gitTestInitDirectory(t *testing.T) (*GitRepository, string) {
	t.Helper()
	dir := t.TempDir()
	fileSystem, closeFileSystem, err := NewGitOsFileSystem(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeFileSystem() })
	return gitTestInit(t, fileSystem), dir
}

// Checks tree out under the index lock and commits the index it gives.
func gitTestCheckout(t *testing.T, repository *GitRepository, args *GitCheckoutArgs) *GitCheckoutResult {
	t.Helper()
	worktree := repository.Worktree()
	lock, err := worktree.LockIndex()
	if err != nil {
		t.Fatal(err)
	}
	held, err := worktree.ReadIndex()
	if err != nil {
		lock.Abandon()
		t.Fatal(err)
	}
	result, err := worktree.Checkout(context.Background(), args, held)
	if err != nil {
		lock.Abandon()
		t.Fatal(err)
	}
	if err := lock.Commit(result.Index); err != nil {
		t.Fatal(err)
	}
	return result
}

// The stock git on this host, or a skip.
func gitTestStockGit(t *testing.T) string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this host")
	}
	return gitPath
}

// Runs stock git in dir with no system or global config, answering its combined output.
func gitTestRunGit(t *testing.T, gitPath string, dir string, stdin []byte, args ...string) (string, error) {
	t.Helper()
	command := exec.Command(gitPath, args...)
	command.Dir = dir
	home := t.TempDir()
	command.Env = []string{
		"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "LC_ALL=C", "PATH=" + os.Getenv("PATH"),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@ur.invalid", "GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@ur.invalid", "GIT_AUTHOR_DATE=@1700000000 +0000", "GIT_COMMITTER_DATE=@1700000000 +0000",
	}
	if stdin != nil {
		command.Stdin = strings.NewReader(string(stdin))
	}
	out, err := command.CombinedOutput()
	return string(out), err
}

// Where two paths fold to one name, the first is written, the other left unwritten and marked, both named, and the
// unwritten one is never read as deleted (§13.4's collisions row); a path whose directory folds to a link's name is
// never written through it.
func TestCaseFoldCollision(t *testing.T) {
	fileSystem := newGitFakeFileSystem(gitFakeHabits{caseFold: true, normalizationFold: true, execBit: true, symlinks: true})
	repository := gitTestInit(t, fileSystem)
	habits := repository.Worktree().Habits()
	if !habits.CaseFold || !habits.NormalizationFold {
		t.Fatalf("the probe read %+v on a folding file system", habits)
	}
	objects := repository.Objects()
	tree := gitTestTree(t, objects, []gitTestFile{
		{path: "README", mode: EvsGitModeFile, content: "upper\n"},
		{path: "readme", mode: EvsGitModeFile, content: "lower\n"},
		{path: "caf\u00e9.txt", mode: EvsGitModeFile, content: "composed\n"},
		{path: "cafe\u0301.txt", mode: EvsGitModeFile, content: "decomposed\n"},
		{path: "Link", mode: EvsGitModeSymlink, content: "docs"},
		{path: "docs/a.txt", mode: EvsGitModeFile, content: "a\n"},
		{path: "link/planted", mode: EvsGitModeFile, content: "through the link\n"},
	})
	result := gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: tree})
	want := []GitCollision{
		{Written: "Link", Unwritten: "link/planted"},
		{Written: "README", Unwritten: "readme"},
		{Written: "cafe\u0301.txt", Unwritten: "caf\u00e9.txt"},
	}
	got := slices.Clone(result.Collisions)
	slices.SortFunc(got, func(a GitCollision, b GitCollision) int { return strings.Compare(a.Written, b.Written) })
	if !slices.Equal(got, want) {
		t.Fatalf("collisions %v, want %v", got, want)
	}
	if spelling := fileSystem.spelling("README"); spelling != "README" || string(fileSystem.content("readme")) != "upper\n" {
		t.Fatalf("the worktree holds %q with %q", spelling, fileSystem.content("readme"))
	}
	if _, err := fileSystem.Lstat("docs/planted"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file was written through the link: %v", err)
	}
	index, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"readme", "caf\u00e9.txt", "link/planted"} {
		entry := index.Entry(path, 0)
		if entry == nil || !entry.Unwritten {
			t.Fatalf("%q's entry %+v is not marked unwritten", path, entry)
		}
	}
	for _, entry := range index.Entries {
		state, err := repository.Worktree().EntryState(context.Background(), entry, nil)
		if err != nil {
			t.Fatal(err)
		}
		if state != GitEntryUnchanged {
			t.Fatalf("%q reads %d after a clean checkout", entry.Path, state)
		}
	}
	// the unwritten side stays unwritten and unchanged across a second checkout of the same tree
	again := gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: tree})
	if len(again.Collisions) != 3 || string(fileSystem.content("README")) != "upper\n" {
		t.Fatalf("a second checkout gave %v and %q", again.Collisions, fileSystem.content("README"))
	}
}

// On a file system that keeps no executable bit, a checkout keeps 100755 from the index and reads it back unchanged; on
// one that keeps the bit, the file system's bit is read (§13.4's modes row).
func TestModeKeptWithoutExecBit(t *testing.T) {
	files := []gitTestFile{
		{path: "run.sh", mode: EvsGitModeExecutable, content: "#!/bin/sh\necho run\n"},
		{path: "notes.txt", mode: EvsGitModeFile, content: "notes\n"},
		{path: "old.txt", mode: EvsGitModeFileGroupWritable, content: "early git\n"},
	}
	without := newGitFakeFileSystem(gitFakeHabits{execBit: false, symlinks: true})
	repository := gitTestInit(t, without)
	if repository.Worktree().Habits().ExecBit {
		t.Fatal("the probe found an executable bit a file system does not keep")
	}
	tree := gitTestTree(t, repository.Objects(), files)
	gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: tree})
	index, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	wantModes := map[string]uint32{"run.sh": EvsGitModeExecutable, "notes.txt": EvsGitModeFile, "old.txt": EvsGitModeFile}
	for _, entry := range index.Entries {
		if entry.Mode != wantModes[entry.Path] {
			t.Fatalf("%q holds mode %o in the index", entry.Path, entry.Mode)
		}
		info, err := without.Lstat(entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 != 0 {
			t.Fatalf("the fake kept an executable bit on %q", entry.Path)
		}
		if mode := repository.Worktree().FileMode(info, entry); mode != entry.Mode {
			t.Fatalf("%q reads mode %o, the index %o", entry.Path, mode, entry.Mode)
		}
		if state, err := repository.Worktree().EntryState(context.Background(), entry, nil); err != nil || state != GitEntryUnchanged {
			t.Fatalf("%q reads %d, %v", entry.Path, state, err)
		}
	}

	with := newGitFakeFileSystem(gitFakeHabits{execBit: true, symlinks: true})
	keeping := gitTestInit(t, with)
	if !keeping.Worktree().Habits().ExecBit {
		t.Fatal("the probe missed an executable bit the file system keeps")
	}
	gitTestCheckout(t, keeping, &GitCheckoutArgs{Tree: gitTestTree(t, keeping.Objects(), files)})
	if info, err := with.Lstat("run.sh"); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("run.sh was checked out without its bit: %v", err)
	}
	// the bit dropped where the file system keeps it reads as a mode change
	if err := with.Chmod("run.sh", 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := keeping.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if state, err := keeping.Worktree().EntryState(context.Background(), held.Entry("run.sh", 0), nil); err != nil || state != GitEntryModified {
		t.Fatalf("a dropped bit reads %d, %v", state, err)
	}
}

// A link is checked out as a link only when its target, resolved through the links the checkout writes, stays inside
// the worktree and passes through no .git; else, and on a file system that makes none, as a text file naming its
// target (§13.4, §13.7).
func TestSymlinkOutsideWorktreeAsText(t *testing.T) {
	files := []gitTestFile{
		{path: "docs/a.txt", mode: EvsGitModeFile, content: "a\n"},
		{path: "inside", mode: EvsGitModeSymlink, content: "docs/a.txt"},
		{path: "sub/up-inside", mode: EvsGitModeSymlink, content: "../docs/a.txt"},
		{path: "here", mode: EvsGitModeSymlink, content: "."},
		{path: "up", mode: EvsGitModeSymlink, content: "../outside.txt"},
		{path: "absolute", mode: EvsGitModeSymlink, content: "/etc/hosts"},
		{path: "dotgit", mode: EvsGitModeSymlink, content: ".git/config"},
		{path: "dotgit-folded", mode: EvsGitModeSymlink, content: "docs/../.GIT/config"},
		{path: "through-here", mode: EvsGitModeSymlink, content: "here/.."},
		{path: "loop-a", mode: EvsGitModeSymlink, content: "loop-b"},
		{path: "loop-b", mode: EvsGitModeSymlink, content: "loop-a"},
	}
	wantText := []string{"absolute", "dotgit", "dotgit-folded", "loop-a", "loop-b", "through-here", "up"}
	wantLinks := []string{"here", "inside", "sub/up-inside"}

	repository, dir := gitTestInitDirectory(t)
	if !repository.Worktree().Habits().Symlinks {
		t.Skip("this host's file system makes no links")
	}
	result := gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: gitTestTree(t, repository.Objects(), files)})
	if !slices.Equal(result.LinksAsText, wantText) {
		t.Fatalf("links as text %v, want %v", result.LinksAsText, wantText)
	}
	for _, name := range wantLinks {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("%q is no link: %v", name, err)
		}
	}
	for _, name := range wantText {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%q is no text file: %v", name, err)
		}
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if file.path == name && string(content) != file.content {
				t.Fatalf("%q holds %q, its target is %q", name, content, file.content)
			}
		}
	}
	// every link reads back unchanged, a text one as its target
	index, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range index.Entries {
		if state, err := repository.Worktree().EntryState(context.Background(), entry, nil); err != nil || state != GitEntryUnchanged {
			t.Fatalf("%q reads %d, %v", entry.Path, state, err)
		}
	}

	// a file system that makes no links writes every one as text
	noLinks := newGitFakeFileSystem(gitFakeHabits{execBit: true, symlinks: false})
	phone := gitTestInit(t, noLinks)
	if phone.Worktree().Habits().Symlinks {
		t.Fatal("the probe found links on a file system that makes none")
	}
	phoneResult := gitTestCheckout(t, phone, &GitCheckoutArgs{Tree: gitTestTree(t, phone.Objects(), files)})
	all := append(slices.Clone(wantText), wantLinks...)
	slices.Sort(all)
	if !slices.Equal(phoneResult.LinksAsText, all) {
		t.Fatalf("links as text %v, want every link", phoneResult.LinksAsText)
	}
	if string(noLinks.content("inside")) != "docs/a.txt" {
		t.Fatalf("a link as text holds %q", noLinks.content("inside"))
	}
}

// A tree holding a path git refuses is refused before anything is written.
func TestCheckoutRefusesUnsafeTreeBeforeWriting(t *testing.T) {
	for _, bad := range []string{".GIT/config", "sub/git~1/hooks", ".g\u200cit/config"} {
		fileSystem := newGitFakeFileSystem(gitFakeHabits{execBit: true, symlinks: true})
		repository := gitTestInit(t, fileSystem)
		tree := gitTestTree(t, repository.Objects(), []gitTestFile{
			{path: "a.txt", mode: EvsGitModeFile, content: "a\n"},
			{path: bad, mode: EvsGitModeFile, content: "planted\n"},
		})
		held, err := repository.Worktree().ReadIndex()
		if err != nil {
			t.Fatal(err)
		}
		_, err = repository.Worktree().Checkout(context.Background(), &GitCheckoutArgs{Tree: tree}, held)
		pathError := &GitPathError{}
		if !errors.As(err, &pathError) || pathError.Path != bad || strings.Contains(err.Error(), bad) {
			t.Fatalf("%q: %v", bad, err)
		}
		if _, err := fileSystem.Lstat("a.txt"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%q: a refused checkout wrote a.txt", bad)
		}
	}
}

// A second checkout removes what the first wrote and the tree dropped, rewrites what changed, and turns a file into a
// directory and back.
func TestCheckoutFollowsTheTree(t *testing.T) {
	fileSystem := newGitFakeFileSystem(gitFakeHabits{execBit: true, symlinks: true})
	repository := gitTestInit(t, fileSystem)
	objects := repository.Objects()
	first := gitTestTree(t, objects, []gitTestFile{
		{path: "keep.txt", mode: EvsGitModeFile, content: "keep\n"},
		{path: "drop/x.txt", mode: EvsGitModeFile, content: "x\n"},
		{path: "change.txt", mode: EvsGitModeFile, content: "one\n"},
		{path: "kind", mode: EvsGitModeFile, content: "a file\n"},
	})
	second := gitTestTree(t, objects, []gitTestFile{
		{path: "keep.txt", mode: EvsGitModeFile, content: "keep\n"},
		{path: "change.txt", mode: EvsGitModeFile, content: "two\n"},
		{path: "kind/inner.txt", mode: EvsGitModeFile, content: "now a directory\n"},
	})
	gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: first})
	result := gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: second})
	if result.WrittenCount != 2 {
		t.Fatalf("the second checkout wrote %d files, want the two that changed", result.WrittenCount)
	}
	for _, gone := range []string{"drop/x.txt", "drop"} {
		if _, err := fileSystem.Lstat(gone); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%q stands after its tree dropped it", gone)
		}
	}
	if string(fileSystem.content("change.txt")) != "two\n" || string(fileSystem.content("kind/inner.txt")) != "now a directory\n" {
		t.Fatal("the second checkout did not write the tree's content")
	}
	gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: first})
	if string(fileSystem.content("kind")) != "a file\n" {
		t.Fatal("the directory did not turn back into a file")
	}
}

// A full worktree this git makes opens in stock git: fsck --strict is clean, status is clean, and the index lists the
// same entries (D-GIT-1).
func TestWorktreeOpensInStockGit(t *testing.T) {
	gitPath := gitTestStockGit(t)
	repository, dir := gitTestInitDirectory(t)
	objects := repository.Objects()
	files := []gitTestFile{
		{path: "README.md", mode: EvsGitModeFile, content: "# readme\n"},
		{path: "bin/run.sh", mode: EvsGitModeExecutable, content: "#!/bin/sh\necho run\n"},
		{path: "docs/deep/a.txt", mode: EvsGitModeFile, content: "a\n"},
		{path: "docs/deep/b.txt", mode: EvsGitModeFile, content: ""},
		{path: "a.txt", mode: EvsGitModeFile, content: "a sorts before a/ and after a-\n"},
		{path: "a-b.txt", mode: EvsGitModeFile, content: "dash\n"},
	}
	if repository.Worktree().Habits().Symlinks {
		files = append(files, gitTestFile{path: "link", mode: EvsGitModeSymlink, content: "docs/deep/a.txt"})
	}
	tree := gitTestTree(t, objects, files)
	commit := gitTestCommit(t, objects, tree, nil, "first")
	if err := repository.Refs().Set(GitBranchPrefix+"main", commit); err != nil {
		t.Fatal(err)
	}
	gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: tree})
	if out, err := gitTestRunGit(t, gitPath, dir, nil, "fsck", "--strict", "--no-dangling"); err != nil {
		t.Fatalf("git fsck: %v: %s", err, out)
	}
	if out, err := gitTestRunGit(t, gitPath, dir, nil, "status", "--porcelain"); err != nil || out != "" {
		t.Fatalf("git status: %v: %q", err, out)
	}
	out, err := gitTestRunGit(t, gitPath, dir, nil, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(out) != commit.String() {
		t.Fatalf("git rev-parse HEAD: %v: %q, want %s", err, out, commit)
	}
	out, err = gitTestRunGit(t, gitPath, dir, nil, "ls-files", "-s")
	if err != nil {
		t.Fatal(err)
	}
	index, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	listed := []string{}
	for _, entry := range index.Entries {
		listed = append(listed, fmt.Sprintf("%06o %s 0\t%s", entry.Mode, entry.Oid, entry.Path))
	}
	if strings.TrimSpace(out) != strings.Join(listed, "\n") {
		t.Fatalf("git ls-files -s:\n%s\nthe index:\n%s", out, strings.Join(listed, "\n"))
	}
}
