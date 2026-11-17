//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FI-9's oracle against go-git (QD-861; FI-9, D-TEST-10, §22.6's git row). sidecartest/fault reads an export with
// its own parse of git's object format, which shares no code with the root's evs_git_* or export, as FI-9's trap asks
// (oids come from an independent parse). This file holds that parse, fault.GitRepository, equal to go-git's reading
// of the same repositories: ur's export of stock git pushes, made as FI-9's harness makes one and passing FI-9's
// check, and repositories stock git makes, one of them packed. What is held equal, item by item:
//
//	refs     every ref go-git lists, loose or packed, symbolic or direct, resolves through Ref to the oid go-git
//	         resolves it to; a symbolic ref to nothing resolves to nothing; a loose ref resolves past its stale packed
//	         line; a ref deleted or never made is absent from both
//	objects  every loose object go-git lists has the same kind and bytes through Object
//	commits  tree, parents in order, author and committer lines and message, through Commit
//	trees    entries in order, each its mode, name and oid, through Tree
//	blobs    content, through go-git's blob reader
//	walks    Ancestry from every commit is go-git's walk of its history, and CheckTree passes on every commit's tree
//	         go-git reads whole
//
// Equal has git_oracle_test.go's meaning: on what both read, the same bytes and fields; where one refuses, the other
// refuses too, or the difference is one this file names. Two are named. FI-9's parse reads loose objects only, which
// is all ur's export writes, and refuses an object only a pack holds, saying so, where go-git reads the pack; so does
// every walk and tree check that reaches one. And go-git reads mode 100664, the group-writable file early git wrote,
// as 100644, as git's canon_mode does in memory, where the parse keeps the mode the tree holds, as ur's codec does
// (checkTreeFields reads the root's codec the same way).
//
// Left to the review phase: the parse against go-git on bytes no stock git writes (a fuzz target over hand-made
// objects), and sha256 repositories, which ur refuses before any evs write.

package mlsinterop

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/filesystem"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
	"github.com/urnetwork/sidecar/sidecartest/fault"
)

// What the parse says of an object only a pack holds (fi9.go's object).
const fi9PackedRefusal = "is not loose and the repository holds packs"

// What one reading held equal, so a test knows its repository held what it meant to.
type fi9GoGitReading struct {
	// each place the parse read otherwise than go-git, beyond the two the file header names
	differences []string
	refs        int
	commits     int
	trees       int
	blobs       int
	tags        int
	// objects only a pack holds, each refused as the file header names
	packed int
	// tree entries by the mode the parse read
	modeEntries map[string]int
	// commits whose whole history both walked alike
	walks int
	// commits whose whole tree both read alike
	wholeTrees int
}

// fault.GitRepository's reading of the git directory dir against go-git's, as the file header lists it. absentRefs
// names refs neither may find.
func fi9ReadAsGoGit(t testing.TB, dir string, absentRefs []string) *fi9GoGitReading {
	t.Helper()
	repository, err := fault.OpenGitRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	storage := filesystem.NewStorage(osfs.New(dir), cache.NewObjectLRUDefault())
	reading := &fi9GoGitReading{modeEntries: map[string]int{}}
	differ := func(format string, args ...any) {
		reading.differences = append(reading.differences, fmt.Sprintf(format, args...))
	}
	refusesPacked := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), fi9PackedRefusal)
	}
	// an author or committer line as go-git's fields give it back, "" for none
	signatureLine := func(signature object.Signature) string {
		if signature.Name == "" && signature.Email == "" && signature.When.IsZero() {
			return ""
		}
		line := &bytes.Buffer{}
		if err := signature.Encode(line); err != nil {
			t.Fatal(err)
		}
		return line.String()
	}

	// refs
	references, err := storage.IterReferences()
	if err != nil {
		t.Fatal(err)
	}
	listedRefNames := []string{}
	if err := references.ForEach(func(reference *plumbing.Reference) error {
		listedRefNames = append(listedRefNames, reference.Name().String())
		return nil
	}); err != nil {
		t.Fatalf("go-git cannot list the refs: %v", err)
	}
	for _, refName := range absentRefs {
		if slices.Contains(listedRefNames, refName) {
			differ("%s: go-git lists a ref the test deleted or never made", refName)
		}
	}
	for _, refName := range append(slices.Clone(listedRefNames), absentRefs...) {
		oid, found, err := repository.Ref(refName)
		if err != nil {
			differ("%s: the parse refuses it: %v", refName, err)
			continue
		}
		resolved, theirErr := storer.ResolveReference(storage, plumbing.ReferenceName(refName))
		switch {
		case errors.Is(theirErr, plumbing.ErrReferenceNotFound):
			if found {
				differ("%s: the parse resolves it to %s, and go-git to nothing", refName, oid)
			}
		case theirErr != nil:
			differ("%s: go-git refuses it (%v), and the parse resolves it to %q, %v", refName, theirErr, oid, found)
		case !found || oid != resolved.Hash().String():
			differ("%s: the parse resolves it to %q, %v, and go-git to %s", refName, oid, found, resolved.Hash())
		default:
			reading.refs += 1
		}
	}

	// loose objects, each by the name go-git lists it under, so bytes hashing to another name are read as stored
	looseOids := map[string]bool{}
	if err := storage.ForEachObjectHash(func(hash plumbing.Hash) error {
		looseOids[hash.String()] = true
		return nil
	}); err != nil {
		t.Fatalf("go-git cannot list the loose objects: %v", err)
	}
	commitOids := []string{}
	for _, oid := range slices.Sorted(maps.Keys(looseOids)) {
		encoded, theirErr := storage.EncodedObject(plumbing.AnyObject, plumbing.NewHash(oid))
		if theirErr != nil {
			differ("%s: go-git lists it loose and cannot read it: %v", oid, theirErr)
			continue
		}
		content := objectBytes(t, encoded)
		theirKind := encoded.Type().String()
		kind, parsedContent, err := repository.Object(oid)
		if err != nil {
			differ("%s: go-git reads a %s of %d B, and the parse refuses it: %v", oid, theirKind, len(content), err)
			continue
		}
		if kind != theirKind || !bytes.Equal(parsedContent, content) {
			differ("%s: the parse reads a %s of %d B, and go-git a %s of %d B", oid, kind, len(parsedContent), theirKind, len(content))
			continue
		}
		switch encoded.Type() {
		case plumbing.CommitObject:
			commitOids = append(commitOids, oid)
			theirs, theirErr := object.DecodeCommit(storage, encoded)
			commit, err := repository.Commit(oid)
			if theirErr != nil || err != nil {
				differ("commit %s: the parse says %v, and go-git %v", oid, err, theirErr)
				continue
			}
			reading.commits += 1
			parents := []string{}
			for _, parent := range theirs.ParentHashes {
				parents = append(parents, parent.String())
			}
			if commit.Tree != theirs.TreeHash.String() || !slices.Equal(commit.Parents, parents) {
				differ("commit %s: the parse reads tree %s and parents %v, and go-git tree %s and parents %v", oid, commit.Tree, commit.Parents, theirs.TreeHash, parents)
			}
			if author := signatureLine(theirs.Author); commit.Author != author {
				differ("commit %s: the parse reads the author line %q, and go-git %q", oid, commit.Author, author)
			}
			if committer := signatureLine(theirs.Committer); commit.Committer != committer {
				differ("commit %s: the parse reads the committer line %q, and go-git %q", oid, commit.Committer, committer)
			}
			if commit.Message != theirs.Message {
				differ("commit %s: the parse reads the message %q, and go-git %q", oid, commit.Message, theirs.Message)
			}
		case plumbing.TreeObject:
			theirs, theirErr := object.DecodeTree(storage, encoded)
			entries, err := repository.Tree(oid)
			if theirErr != nil || err != nil {
				differ("tree %s: the parse says %v, and go-git %v", oid, err, theirErr)
				continue
			}
			reading.trees += 1
			if len(entries) != len(theirs.Entries) {
				differ("tree %s: the parse reads %d entries, and go-git %d", oid, len(entries), len(theirs.Entries))
				continue
			}
			for index, entry := range entries {
				their := theirs.Entries[index]
				reading.modeEntries[entry.Mode] += 1
				// the second named difference: go-git reads 100664 as git's canon_mode does
				mode := entry.Mode
				if mode == "100664" {
					mode = "100644"
				}
				if mode != strconv.FormatUint(uint64(their.Mode), 8) || entry.Name != their.Name || entry.Oid != their.Hash.String() {
					differ("tree %s, entry %d: the parse reads %s %q %s, and go-git %o %q %s", oid, index, entry.Mode, entry.Name, entry.Oid, their.Mode, their.Name, their.Hash)
				}
			}
		case plumbing.BlobObject:
			blob, theirErr := object.DecodeBlob(encoded)
			if theirErr != nil {
				differ("blob %s: go-git refuses it: %v", oid, theirErr)
				continue
			}
			reader, theirErr := blob.Reader()
			if theirErr != nil {
				t.Fatal(theirErr)
			}
			theirContent, theirErr := io.ReadAll(reader)
			reader.Close()
			if theirErr != nil {
				t.Fatal(theirErr)
			}
			if !bytes.Equal(parsedContent, theirContent) {
				differ("blob %s: the parse reads %d B, and go-git's blob reader %d B", oid, len(parsedContent), len(theirContent))
			}
			reading.blobs += 1
		case plumbing.TagObject:
			// FI-9 reads no tag's fields, so a tag is held equal by its bytes alone
			reading.tags += 1
		}
	}

	// the objects only a pack holds: the first named difference
	objects, err := storage.IterEncodedObjects(plumbing.AnyObject)
	if err != nil {
		t.Fatal(err)
	}
	err = objects.ForEach(func(encoded plumbing.EncodedObject) error {
		oid := encoded.Hash().String()
		if looseOids[oid] {
			return nil
		}
		if _, theirErr := storage.EncodedObject(plumbing.AnyObject, encoded.Hash()); theirErr != nil {
			// a loose object whose bytes hash to no name it is stored under, which the loose reading above names
			return nil
		}
		if encoded.Type() == plumbing.CommitObject {
			commitOids = append(commitOids, oid)
		}
		kind, _, err := repository.Object(oid)
		if !refusesPacked(err) {
			differ("%s, a %s only a pack holds: the parse reads it as a %q (%v), where it refuses one only a pack holds", oid, encoded.Type(), kind, err)
		}
		reading.packed += 1
		return nil
	})
	if err != nil {
		t.Fatalf("go-git cannot list the objects: %v", err)
	}

	// walks: each commit's history and its whole tree, which reach a pack's objects or not
	packedOnly := func(oid string) bool {
		return !looseOids[oid]
	}
	var treeClosure func(hash plumbing.Hash, oids map[string]bool) error
	// go-git's reading of a tree whole, every tree and blob below it, a gitlink's commit not followed
	treeClosure = func(hash plumbing.Hash, oids map[string]bool) error {
		oids[hash.String()] = true
		tree, err := object.GetTree(storage, hash)
		if err != nil {
			return err
		}
		for _, entry := range tree.Entries {
			switch entry.Mode {
			case filemode.Dir:
				if err := treeClosure(entry.Hash, oids); err != nil {
					return fmt.Errorf("%s/: %w", entry.Name, err)
				}
			case filemode.Submodule:
			default:
				if _, err := storage.EncodedObject(plumbing.BlobObject, entry.Hash); err != nil {
					return fmt.Errorf("%s: %w", entry.Name, err)
				}
				oids[entry.Hash.String()] = true
			}
		}
		return nil
	}
	for _, oid := range commitOids {
		theirs, err := object.GetCommit(storage, plumbing.NewHash(oid))
		if err != nil {
			differ("commit %s: go-git cannot read it again: %v", oid, err)
			continue
		}
		theirAncestry := map[string]bool{}
		walkErr := object.NewCommitPreorderIter(theirs, nil, nil).ForEach(func(commit *object.Commit) error {
			theirAncestry[commit.Hash.String()] = true
			return nil
		})
		ancestry, err := repository.Ancestry(oid)
		switch {
		case walkErr != nil:
			if err == nil {
				differ("commit %s: go-git cannot walk its history (%v), and the parse walks it", oid, walkErr)
			}
		case slices.ContainsFunc(slices.Collect(maps.Keys(theirAncestry)), packedOnly):
			if !refusesPacked(err) {
				differ("commit %s: its history reaches a commit only a pack holds, and the parse's walk says %v", oid, err)
			}
		case err != nil:
			differ("commit %s: go-git walks its history, and the parse refuses it: %v", oid, err)
		case !maps.Equal(ancestry, theirAncestry):
			differ("commit %s: the parse walks %d commits, and go-git %d", oid, len(ancestry), len(theirAncestry))
		default:
			reading.walks += 1
		}
		treeOids := map[string]bool{}
		closureErr := treeClosure(theirs.TreeHash, treeOids)
		checkErr := repository.CheckTree(theirs.TreeHash.String())
		switch {
		case closureErr != nil:
			if checkErr == nil {
				differ("tree %s: go-git cannot read it whole (%v), and the parse checks it clean", theirs.TreeHash, closureErr)
			}
		case slices.ContainsFunc(slices.Collect(maps.Keys(treeOids)), packedOnly):
			if !refusesPacked(checkErr) {
				differ("tree %s: a pack holds some of it, and the parse's check says %v", theirs.TreeHash, checkErr)
			}
		case checkErr != nil:
			differ("tree %s: go-git reads it whole, and the parse's check refuses it: %v", theirs.TreeHash, checkErr)
		default:
			reading.wholeTrees += 1
		}
	}
	return reading
}

// Fails t with every difference the reading holds, and with each count under least's.
func (self *fi9GoGitReading) require(t testing.TB, least *fi9GoGitReading) {
	t.Helper()
	for _, difference := range self.differences {
		t.Error(difference)
	}
	for _, c := range []struct {
		name  string
		count int
		least int
	}{
		{name: "refs", count: self.refs, least: least.refs},
		{name: "commits", count: self.commits, least: least.commits},
		{name: "trees", count: self.trees, least: least.trees},
		{name: "blobs", count: self.blobs, least: least.blobs},
		{name: "tags", count: self.tags, least: least.tags},
		{name: "objects only a pack holds", count: self.packed, least: least.packed},
		{name: "walks", count: self.walks, least: least.walks},
		{name: "whole trees", count: self.wholeTrees, least: least.wholeTrees},
	} {
		if c.count < c.least {
			t.Errorf("%d %s held equal, and the repository was made to hold at least %d", c.count, c.name, c.least)
		}
	}
	for _, mode := range slices.Sorted(maps.Keys(least.modeEntries)) {
		if self.modeEntries[mode] < least.modeEntries[mode] {
			t.Errorf("%d entries of mode %s read, and the repository was made to hold at least %d", self.modeEntries[mode], mode, least.modeEntries[mode])
		}
	}
}

// Runs stock git in dir with nothing of this host's configuration, as stockGit does, env beside it and input on its
// stdin: its output, or the test's end.
func fi9Git(t testing.TB, dir string, env []string, input []byte, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"LC_ALL=C",
		// the files ref store the parse reads, whatever a later git defaults to
		"GIT_DEFAULT_REF_FORMAT=files",
	}, env...)
	command.Stdin = bytes.NewReader(input)
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr)
	}
	return string(output)
}

// Not a test: the hook the world's mounts exec relays to its device's daemon (evsgit.HookHelper).
func TestFi9GoGitHookHelperProcess(t *testing.T) {
	evsgit.HookHelper()
}

// ur's export of stock git pushes, made as fault's TestFi9ReadsUrsExportOfSiblingPushesClean makes one and recorded
// into FI-9's ledger: sibling pushes, the second heard as non-fast-forward and merged, over a base with nested
// directories, an empty file, an executable and a symlink, a commit authored by someone else in another zone, and a
// branch whose tree holds a group-writable file. FI-9's check passes on the export, and the parse reads it as go-git
// does, loose throughout, its HEAD naming a main no one pushed.
func TestFi9ReadsUrsExportAsGoGitDoes(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings := evsgit.DefaultWorldSettings()
	settings.HookCommand = []string{binary, "-test.run=^TestFi9GoGitHookHelperProcess$", "--"}
	settings.ClientSettings = evsgit.Fs5ClientSettings()
	world := evsgit.NewWorld(t, settings)
	a, b := world.Device("fi9-go-git-a", nil), world.Device("fi9-go-git-b", nil)
	const branch = "fi9-go-git"
	const oldModeBranch = "fi9-go-git-old-mode"
	ledger := fault.NewGitLedger()
	// each update's commit, tree and parents as the client's stock git names them; cause marks a refusal's cause
	record := func(device *evsgit.Device, dir string, output string, cause string) {
		t.Helper()
		push, err := fault.GitPushOf(device.Label, false, output, func(source string) (string, string, []string, error) {
			fields := strings.Fields(device.MustGit(dir, "log", "-1", "--format=%H %T %P", source))
			return fields[0], fields[1], fields[2:], nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, update := range push.Updates {
			if update.Status == fault.GitPushRejected {
				update.Cause = cause
			}
		}
		ledger.RecordPush(push)
	}

	dirA := a.Clone()
	if err := os.WriteFile(filepath.Join(dirA, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dirA, "link")); err != nil {
		t.Fatal(err)
	}
	a.Commit(dirA, "base\n\nwith a body", map[string]*string{
		"a.txt": evsgit.Text("alpha\n"), "a.b": evsgit.Text("dot\n"), "a-b": evsgit.Text("dash\n"),
		"a/inner.txt": evsgit.Text("inner\n"), "d/nested.txt": evsgit.Text("nested\n"),
		"d/e/deep.txt": evsgit.Text("deep\n"), "empty": evsgit.Text(""),
	})
	out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch)
	if !ok {
		t.Fatalf("the base: %s", out)
	}
	record(a, dirA, out, "")
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	a.Commit(dirA, "a's sibling", map[string]*string{"siblings.txt": evsgit.Text("from a\n"), "d/e/deep.txt": nil})
	authoredElsewhere := []string{"GIT_AUTHOR_NAME=A U Thor", "GIT_AUTHOR_EMAIL=author@example.com", "GIT_AUTHOR_DATE=@1112911993 -0700"}
	if out, ok := a.GitIn(dirA, authoredElsewhere, "commit", "-q", "--allow-empty", "-m", "authored elsewhere"); !ok {
		t.Fatalf("git commit: %s", out)
	}
	if out, ok = a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("a's sibling: %s", out)
	}
	record(a, dirA, out, "")
	b.Commit(dirB, "b's sibling", map[string]*string{"b.txt": evsgit.Text("from b\n")})
	if out, ok = b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); ok || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("b's sibling: %v %s", ok, out)
	}
	record(b, dirB, out, fault.GitCauseTipMoved)
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	b.MustGit(dirB, "fetch", "-q", "origin")
	b.MustGit(dirB, "merge", "-q", "--no-edit", "origin/"+branch)
	if out, ok = b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("b's merge: %s", out)
	}
	record(b, dirB, out, "")

	// a tree holding the group-writable file early git wrote, which only git's plumbing still makes
	blob := strings.TrimSpace(fi9Git(t, dirA, nil, []byte("group writable\n"), "hash-object", "-w", "--stdin"))
	alpha := strings.TrimSpace(a.MustGit(dirA, "rev-parse", "HEAD:a.txt"))
	tree := strings.TrimSpace(fi9Git(t, dirA, nil, []byte("100644 blob "+alpha+"\ta.txt\n100664 blob "+blob+"\tgw.txt\n"), "mktree"))
	oldMode := strings.TrimSpace(fi9Git(t, dirA, nil, []byte("old mode\n"), "commit-tree", tree, "-p", "HEAD"))
	a.MustGit(dirA, "update-ref", "refs/heads/old-mode", oldMode)
	if out, ok = a.Push(dirA, "origin", "refs/heads/old-mode:refs/heads/"+oldModeBranch); !ok {
		t.Fatalf("the group-writable file: %s", out)
	}
	record(a, dirA, out, "")

	exportDir, tips := a.Export(branch, oldModeBranch)
	if tips["refs/heads/"+oldModeBranch] != oldMode {
		t.Fatalf("the export's %s is at %q, and a pushed %s", oldModeBranch, tips["refs/heads/"+oldModeBranch], oldMode)
	}
	ledger.RecordExport(exportDir)
	if err := fault.CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
	reading := fi9ReadAsGoGit(t, exportDir, []string{"refs/heads/main", "refs/heads/never"})
	// the six commits pushed, their nine trees and twelve blobs, the two branches; and ur's provenance notes beside
	reading.require(t, &fi9GoGitReading{
		refs: 2, commits: 6, trees: 9, blobs: 12, walks: 6, wholeTrees: 6,
		modeEntries: map[string]int{"40000": 1, "100644": 1, "100755": 1, "120000": 1, "100664": 1},
	})
}

// A repository stock git makes, its work tree at dir and its git directory dir/.git, every author's and committer's
// date fixed so its oids are the same on every run.
type fi9StockRepository struct {
	t   *testing.T
	dir string
	// the last date git stamped
	unixSeconds int64
}

// Stock git in the work tree, as a commit's author and committer, apart in name and zone, a second past the last.
func (self *fi9StockRepository) git(input []byte, args ...string) string {
	self.t.Helper()
	self.unixSeconds += 1
	return fi9Git(self.t, self.dir, []string{
		"GIT_AUTHOR_NAME=A U Thor", "GIT_AUTHOR_EMAIL=author@example.com",
		fmt.Sprintf("GIT_AUTHOR_DATE=@%d -0700", self.unixSeconds),
		"GIT_COMMITTER_NAME=C O Mitter", "GIT_COMMITTER_EMAIL=committer@example.com",
		fmt.Sprintf("GIT_COMMITTER_DATE=@%d +0530", self.unixSeconds+60),
	}, input, args...)
}

// The oid rev names.
func (self *fi9StockRepository) revParse(rev string) string {
	self.t.Helper()
	return strings.TrimSpace(self.git(nil, "rev-parse", rev))
}

// Writes files, a nil content removing its path, adds them and the paths written otherwise, and commits with gitArgs
// before git's command, answering the commit's oid. Only the paths named are added, so an index entry with no file
// behind it, a gitlink's, stays.
func (self *fi9StockRepository) commit(gitArgs []string, message string, files map[string]*string, paths ...string) string {
	self.t.Helper()
	for path, content := range files {
		full := filepath.Join(self.dir, filepath.FromSlash(path))
		paths = append(paths, path)
		if content == nil {
			if err := os.Remove(full); err != nil {
				self.t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			self.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(*content), 0o644); err != nil {
			self.t.Fatal(err)
		}
	}
	if 0 < len(paths) {
		self.git(nil, append([]string{"add", "-A", "--"}, paths...)...)
	}
	self.git(nil, append(slices.Clone(gitArgs), "commit", "-q", "--allow-empty", "--allow-empty-message", "-m", message)...)
	return self.revParse("HEAD")
}

// A content pointer, for commit's files.
func fi9Text(content string) *string {
	return &content
}

// A repository holding, loose: commits with no parent, one, two and three, a message with no end, an empty one and
// one in ISO-8859-1 under its encoding header, a commit carrying a signature header's continuation lines; trees whose
// entries git's order turns on (a-b, a.b, a.txt, a/), nested directories, an empty file, a 300 KiB binary file, an
// executable, a symlink, a gitlink and a group-writable file; an annotated tag and a lightweight one; a notes ref; a
// symbolic branch; and a branch made and deleted. It answers the refs it deleted or never made.
func newFi9StockRepository(t *testing.T) (*fi9StockRepository, []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
	repository := &fi9StockRepository{t: t, dir: filepath.Join(t.TempDir(), "stock"), unixSeconds: 1112911993}
	if err := os.MkdirAll(repository.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	repository.git(nil, "init", "-q", "--object-format=sha1", "-b", "main", ".")
	// nothing packs on its own
	repository.git(nil, "config", "gc.auto", "0")
	repository.git(nil, "config", "maintenance.auto", "false")
	random := rand.New(rand.NewPCG(13, 14))
	binary := make([]byte, 300*1024)
	for index := range binary {
		binary[index] = byte(random.Uint32())
	}
	if err := os.WriteFile(filepath.Join(repository.dir, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(repository.dir, "link")); err != nil {
		t.Fatal(err)
	}
	base := repository.commit(nil, "base\n\nwith a body", map[string]*string{
		"a.txt": fi9Text("alpha\n"), "a-b": fi9Text("dash\n"), "a.b": fi9Text("dot\n"), "a/inner.txt": fi9Text("inner\n"),
		"d/nested.txt": fi9Text("nested\n"), "d/e/deep.txt": fi9Text("deep\n"), "empty": fi9Text(""),
		"naïve name.txt": fi9Text("utf-8\n"), "big.bin": fi9Text(string(binary)),
	}, "run.sh", "link")
	repository.commit(nil, "second", map[string]*string{"a.txt": fi9Text("alpha, again\n"), "d/e/deep.txt": nil})
	repository.git(nil, "checkout", "-q", "-b", "topic", base)
	repository.commit([]string{"-c", "i18n.commitEncoding=ISO-8859-1"}, "caf\xe9 au lait", map[string]*string{"topic.txt": fi9Text("topic\n")})
	repository.commit(nil, "", nil)
	repository.git(nil, "checkout", "-q", "main")
	repository.git(nil, "merge", "-q", "--no-ff", "-m", "merge topic", "topic")
	for _, name := range []string{"x", "y"} {
		repository.git(nil, "checkout", "-q", "-b", name, "main")
		repository.commit(nil, "on "+name, map[string]*string{name + ".txt": fi9Text(name + "\n")})
	}
	repository.git(nil, "checkout", "-q", "main")
	repository.git(nil, "merge", "-q", "-m", "octopus", "x", "y")
	repository.git(nil, "update-index", "--add", "--cacheinfo", "160000,"+base+",sub")
	repository.commit(nil, "a gitlink", nil)

	// what only git's plumbing still makes: a group-writable file, a message with no end, a signature header
	blob := strings.TrimSpace(repository.git([]byte("group writable\n"), "hash-object", "-w", "--stdin"))
	alpha := repository.revParse(base + ":a.txt")
	tree := strings.TrimSpace(repository.git([]byte("100644 blob "+alpha+"\ta.txt\n100664 blob "+blob+"\tgw.txt\n"), "mktree"))
	repository.git(nil, "update-ref", "refs/heads/old-mode", strings.TrimSpace(repository.git([]byte("old mode\n"), "commit-tree", tree, "-p", base)))
	baseTree := repository.revParse(base + "^{tree}")
	repository.git(nil, "update-ref", "refs/heads/no-end", strings.TrimSpace(repository.git([]byte("no end"), "commit-tree", baseTree, "-p", base)))
	signed := "tree " + baseTree + "\nparent " + base + "\n" +
		"author A U Thor <author@example.com> 1112911993 -0700\n" +
		"committer C O Mitter <committer@example.com> 1112912053 +0530\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n c3ludGhldGljLCBzaWduZWQgYnkgbm8ga2V5\n -----END PGP SIGNATURE-----\n" +
		"\nsigned by no key\n"
	repository.git(nil, "update-ref", "refs/heads/signed", strings.TrimSpace(repository.git([]byte(signed), "hash-object", "-t", "commit", "-w", "--stdin")))

	repository.git(nil, "tag", "-a", "v1", "-m", "release v1", "main")
	repository.git(nil, "tag", "v0", base)
	repository.git(nil, "notes", "add", "-m", "a note", base)
	repository.git(nil, "symbolic-ref", "refs/heads/alias", "refs/heads/main")
	repository.git(nil, "update-ref", "refs/heads/doomed", base)
	repository.git(nil, "update-ref", "-d", "refs/heads/doomed")
	return repository, []string{"refs/heads/doomed", "refs/heads/never"}
}

func TestFi9ReadsStockGitAsGoGitDoes(t *testing.T) {
	repository, absentRefs := newFi9StockRepository(t)
	reading := fi9ReadAsGoGit(t, filepath.Join(repository.dir, ".git"), absentRefs)
	reading.require(t, &fi9GoGitReading{
		// HEAD, main, alias, topic, x, y, old-mode, no-end, signed, v1, v0 and the notes ref; twelve commits and the
		// note's, fourteen trees with the note's, seventeen blobs with the note's, and v1's tag
		refs: 12, commits: 13, trees: 14, blobs: 17, tags: 1, walks: 13, wholeTrees: 13,
		modeEntries: map[string]int{"40000": 1, "100644": 1, "100755": 1, "120000": 1, "160000": 1, "100664": 1},
	})
}

// The same repository packed, objects and refs, then changed: a commit on main past the pack, loose, its ref loose
// over main's stale packed line, and a packed branch deleted. Every ref resolves alike; the loose objects read alike;
// every object only the pack holds, and every history and tree reaching one, the parse refuses as the file header
// names.
func TestFi9ReadsPackedStockGitAsGoGitDoes(t *testing.T) {
	repository, absentRefs := newFi9StockRepository(t)
	gitDir := filepath.Join(repository.dir, ".git")
	packedMain := repository.revParse("main")
	repository.git(nil, "repack", "-a", "-d", "-q")
	repository.git(nil, "pack-refs", "--all")
	packedRefs, err := os.ReadFile(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(packedRefs), packedMain+" refs/heads/main\n") {
		t.Fatalf("packed-refs holds no main at %s: %s", packedMain, packedRefs)
	}
	repository.git(nil, "update-ref", "-d", "refs/heads/x")
	after := repository.commit(nil, "after the pack", map[string]*string{"after.txt": fi9Text("after\n")})
	reading := fi9ReadAsGoGit(t, gitDir, append(absentRefs, "refs/heads/x"))
	// the stock repository's 45 objects packed, and the commit past the pack, its tree and its blob loose; that
	// commit's history and tree reach the pack, so the parse walks and reads whole none
	reading.require(t, &fi9GoGitReading{refs: 11, commits: 1, trees: 1, blobs: 1, packed: 45})
	parsed, err := fault.OpenGitRepository(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if main, _, err := parsed.Ref("refs/heads/main"); err != nil || main != after {
		t.Errorf("main resolves to %s (%v), past its packed line at %s, and the commit past the pack is %s", main, err, packedMain, after)
	}
}

// The comparison is no formality: one loose blob's bytes changed under its name, which the parse refuses as hashing
// otherwise and go-git's loose reader takes as stored, and the reading names that blob.
func TestFi9GoGitReadingCatchesAnObjectReadOtherwise(t *testing.T) {
	repository, absentRefs := newFi9StockRepository(t)
	gitDir := filepath.Join(repository.dir, ".git")
	nested := repository.revParse("main:d/nested.txt")
	compressed := &bytes.Buffer{}
	writer := zlib.NewWriter(compressed)
	if _, err := writer.Write([]byte("blob 8\x00altered\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(gitDir, "objects", nested[:2], nested[2:])
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	reading := fi9ReadAsGoGit(t, gitDir, absentRefs)
	named := false
	for _, difference := range reading.differences {
		named = named || (strings.Contains(difference, nested) && strings.Contains(difference, "hashes to"))
	}
	if !named {
		t.Fatalf("no difference names %s hashing otherwise: %q", nested, reading.differences)
	}
}
