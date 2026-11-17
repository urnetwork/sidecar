package fault

// GitRepository's readings beyond FI-9's checks, which mlsinterop's fi9_go_git_test.go holds equal to go-git's (QD-861):
// a commit's author and committer lines and message, a tree's entries, an object's kind and bytes. And the group-
// writable file early git wrote (mode 100664), which ur's codec keeps so old history keeps its oids: an export holding
// one reads clean, where the parse once refused its mode.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A tree's bytes, its entries as given, in the order given.
func fi9RawTree(entries ...*GitTreeEntry) []byte {
	content := []byte{}
	for _, entry := range entries {
		oid, _ := hex.DecodeString(entry.Oid)
		content = append(content, entry.Mode+" "+entry.Name+"\x00"...)
		content = append(content, oid...)
	}
	return content
}

func newFi9ReadRepository(t *testing.T, repo *fi9Repo) *GitRepository {
	t.Helper()
	repository, err := OpenGitRepository(repo.dir)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

// The author and committer lines where git reads them, past a signature header's continuation lines and an encoding
// header, and the message as stored, its last line with no end; with no author line, the committer's in its place;
// an author line out of place read as none; and a commit ending with its headers, no message.
func TestFi9ReadsACommitsAuthorCommitterAndMessage(t *testing.T) {
	repo := newFi9Repo(t)
	tree := repo.tree(fi9Entry{name: "a.txt", oid: repo.blob("a\n")})
	base := repo.commit(tree, nil, "base")
	author := "A U Thor <author@example.com> 1112911993 -0700"
	committer := "C O Mitter <committer@example.com> 1112912053 +0530"
	message := "subject\n\nbody, its last line with no end"
	signed := repo.write("commit", []byte("tree "+tree+"\nparent "+base+"\nauthor "+author+"\ncommitter "+committer+
		"\nencoding ISO-8859-1\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n c3ludGhldGlj\n -----END PGP SIGNATURE-----\n\n"+message))
	noAuthor := repo.write("commit", []byte("tree "+tree+"\ncommitter "+committer+"\n\nno author\n"))
	misplaced := repo.write("commit", []byte("tree "+tree+"\ncommitter "+committer+"\nauthor "+author+"\n\nmisplaced\n"))
	headersOnly := repo.write("commit", []byte("tree "+tree+"\nparent "+base+"\nauthor "+author+"\ncommitter "+committer+"\n"))
	repository := newFi9ReadRepository(t, repo)
	for _, want := range []*GitCommit{
		{Oid: signed, Tree: tree, Parents: []string{base}, Author: author, Committer: committer, Message: message},
		{Oid: noAuthor, Tree: tree, Committer: committer, Message: "no author\n"},
		{Oid: misplaced, Tree: tree, Committer: committer, Message: "misplaced\n"},
		{Oid: headersOnly, Tree: tree, Parents: []string{base}, Author: author, Committer: committer},
	} {
		commit, err := repository.Commit(want.Oid)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(commit, want) {
			t.Errorf("%s reads %+v, want %+v", want.Oid, commit, want)
		}
	}
}

// Each mode git writes, in the order the tree holds them, and the tree checks clean, a gitlink's commit not followed;
// a mode git does not write, which ur's codec refuses to store, is refused by both readings. Object gives the bytes as
// the caller's own.
func TestFi9ReadsATreesEntries(t *testing.T) {
	repo := newFi9Repo(t)
	blob := repo.blob("a\n")
	subtree := repo.tree(fi9Entry{name: "n.txt", oid: blob})
	entries := []*GitTreeEntry{
		{Mode: "40000", Name: "d", Oid: subtree},
		{Mode: "100755", Name: "exec.sh", Oid: blob},
		{Mode: "100664", Name: "gw.txt", Oid: blob},
		{Mode: "120000", Name: "link", Oid: blob},
		{Mode: "100644", Name: "plain.txt", Oid: blob},
		// a commit of another repository, which this one does not store
		{Mode: "160000", Name: "sub", Oid: strings.Repeat("1", 40)},
	}
	tree := repo.write("tree", fi9RawTree(entries...))
	padded := repo.write("tree", fi9RawTree(&GitTreeEntry{Mode: "040000", Name: "d", Oid: subtree}))
	repository := newFi9ReadRepository(t, repo)
	read, err := repository.Tree(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, entries) {
		t.Errorf("the tree reads %+v, want %+v", read, entries)
	}
	if err := repository.CheckTree(tree); err != nil {
		t.Errorf("the tree checks %v", err)
	}
	if _, err := repository.Tree(padded); err == nil || !strings.Contains(err.Error(), `has an entry of mode "040000"`) {
		t.Errorf("a zero-padded mode reads %v", err)
	}
	if err := repository.CheckTree(padded); err == nil || !strings.Contains(err.Error(), `has an entry of mode "040000"`) {
		t.Errorf("a zero-padded mode checks %v", err)
	}
	kind, content, err := repository.Object(tree)
	if err != nil || kind != "tree" || string(content) != string(fi9RawTree(entries...)) {
		t.Fatalf("the tree's object reads %q, %q, %v", kind, content, err)
	}
	content[0] ^= 0xff
	if _, again, _ := repository.Object(tree); string(again) != string(fi9RawTree(entries...)) {
		t.Errorf("a change to Object's bytes reached the parse's own")
	}
}

// An acknowledged push whose tree holds a group-writable file reads clean, the file's blob checked as any file's is,
// and fails when that blob is gone. Before the parse took the mode, the clean export failed on it.
func TestFi9ReadsAGroupWritableFileAsAFile(t *testing.T) {
	repo := newFi9Repo(t)
	blob := repo.blob("group writable\n")
	tree := repo.write("tree", fi9RawTree(&GitTreeEntry{Mode: "100664", Name: "gw.txt", Oid: blob}))
	commit := repo.commit(tree, nil, "old history")
	repo.setRef("refs/heads/main", commit)
	push := &GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", commit, tree)}}
	ledger := NewGitLedger()
	ledger.RecordPush(push)
	ledger.RecordExport(repo.dir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo.dir, "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	missing := NewGitLedger()
	missing.RecordPush(push)
	missing.RecordExport(repo.dir)
	fi9RequireViolation(t, CheckGitPushes(missing, true), "gw.txt: object "+blob+" is not stored")
}
