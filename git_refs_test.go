//go:build !ios_extension && !sidecar_http

// GIT-M13-01's ref tests: the compare-and-swap every update goes through, a lock another git holds, symbolic and packed
// refs as stock git writes them, and check-ref-format's names.

package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An update takes only where the ref still holds what the caller read; a held lock refuses it; a delete drops a
// packed ref too; a symbolic ref is followed; stock git reads what this writes.
func TestRefsCompareAndSwap(t *testing.T) {
	repository, dir := gitTestInitDirectory(t)
	refs := repository.Refs()
	objects := repository.Objects()
	first := gitTestCommit(t, objects, EvsGitEmptyTreeOid, nil, "first")
	second := gitTestCommit(t, objects, EvsGitEmptyTreeOid, []EvsGitOid{first}, "second")
	main := GitBranchPrefix + "main"
	if head, err := refs.ResolveHead(); err != nil || head != nil {
		t.Fatalf("an unborn branch resolves to %v, %v", head, err)
	}
	if err := refs.Update(main, first, &second); !errors.Is(err, ErrGitRefMoved) {
		t.Fatalf("an update expecting a ref that does not stand: %v", err)
	}
	if err := refs.Update(main, first, nil); err != nil {
		t.Fatal(err)
	}
	if err := refs.Update(main, second, nil); !errors.Is(err, ErrGitRefMoved) {
		t.Fatalf("a create over a ref that stands: %v", err)
	}
	if err := refs.Update(main, second, &first); err != nil {
		t.Fatal(err)
	}
	if head, err := refs.ResolveHead(); err != nil || *head != second {
		t.Fatalf("HEAD resolves to %v, %v", head, err)
	}
	// a lock another git holds refuses the update and is left standing
	lock := filepath.Join(dir, ".git", "refs", "heads", "main.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := refs.Update(main, first, &second); !errors.Is(err, ErrGitRefLocked) {
		t.Fatalf("an update under another git's lock: %v", err)
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("the other git's lock was removed")
	}
	os.Remove(lock)
	// packed refs and a symbolic ref as stock git writes them
	packed := "# pack-refs with: peeled fully-peeled sorted \n" + first.String() + " refs/tags/v1\n^" + second.String() + "\n" +
		second.String() + " refs/remotes/origin/main\n"
	if err := os.WriteFile(filepath.Join(dir, ".git", "packed-refs"), []byte(packed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git", "refs", "remotes", "origin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "refs", "remotes", "origin", "HEAD"), []byte("ref: refs/remotes/origin/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if oid, err := refs.Read(GitRemotePrefix + "HEAD"); err != nil || *oid != second {
		t.Fatalf("a symbolic ref reads %v, %v", oid, err)
	}
	listed, err := refs.List(GitTagPrefix)
	if err != nil || len(listed) != 1 || listed[0].Name != "refs/tags/v1" || listed[0].Oid != first {
		t.Fatalf("the tags list %v, %v", listed, err)
	}
	if err := refs.Delete("refs/tags/v1", &first); err != nil {
		t.Fatal(err)
	}
	if oid, err := refs.Read("refs/tags/v1"); err != nil || oid != nil {
		t.Fatalf("a deleted packed ref reads %v, %v", oid, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, ".git", "packed-refs"))
	if err != nil || strings.Contains(string(content), "v1") || strings.Contains(string(content), "^") {
		t.Fatalf("packed-refs still holds the tag or its peeled line:\n%s", content)
	}
	if err := refs.Update(GitRemotePrefix+"main", first, &second); err != nil {
		t.Fatalf("a loose update over a packed ref: %v", err)
	}
	if gitPath, err := lookGit(); err == nil {
		out, err := gitTestRunGit(t, gitPath, dir, nil, "rev-parse", "main", "origin/main")
		if err != nil || out != second.String()+"\n"+first.String()+"\n" {
			t.Fatalf("stock git reads %q: %v", out, err)
		}
	}
	if err := refs.SetHead(&GitHead{Oid: &first}); err != nil {
		t.Fatal(err)
	}
	if head, err := refs.Head(); err != nil || head.Oid == nil || *head.Oid != first || head.Symbolic != "" {
		t.Fatalf("a detached HEAD reads %+v, %v", head, err)
	}
}

// check-ref-format's rules, and a ref that would be an unsafe path under .git.
func TestRefNames(t *testing.T) {
	for _, good := range []string{"refs/heads/main", "refs/heads/feature/x", "refs/tags/v1.0", "refs/remotes/origin/a-b_c", `refs/heads/q"uote`} {
		if err := GitCheckRefName(good); err != nil {
			t.Fatalf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{
		"main", "refs/heads/", "refs/heads/a..b", "refs/heads/.hidden", "refs/heads/x.lock", "refs/heads/a b",
		"refs/heads/a~1", "refs/heads/a^", "refs/heads/a:b", "refs/heads/a?", "refs/heads/a*", "refs/heads/a[",
		"refs/heads/a\\b", "refs/heads/a@{1}", "refs/heads//a", "refs/heads/a.", "refs/heads/\x01", "refs/heads/git~1",
		"refs/heads/../../config",
	} {
		if err := GitCheckRefName(bad); !errors.Is(err, ErrGitRefInvalid) {
			t.Fatalf("%q was taken: %v", bad, err)
		}
	}
}
