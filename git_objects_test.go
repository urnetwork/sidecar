//go:build !ios_extension && !sidecar_http

// GIT-M13-01's object store tests: loose objects round-trip with stock git's cat-file and hash-object where the host
// has git, and a loose object that is not its oid, holds trailing bytes or passes a limit is refused.

package sidecar

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each kind written here reads back here and in stock git's cat-file, and each object stock git's hash-object,
// mktree and commit-tree write reads back here with the same bytes.
func TestLooseObjectRoundTrip(t *testing.T) {
	repository, dir := gitTestInitDirectory(t)
	objects := repository.Objects()
	ctx := context.Background()
	blob, err := objects.WriteBlob(strings.NewReader("hello, loose objects\n"), int64(len("hello, loose objects\n")))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := objects.WriteGitObject(evsGitBlobKind, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := objects.WriteTree(&EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("hello.txt"), Oid: blob},
		{Mode: EvsGitModeExecutable, Name: []byte("empty"), Oid: empty},
	}})
	if err != nil {
		t.Fatal(err)
	}
	commit := gitTestCommit(t, objects, tree, nil, "a commit")
	tag := []byte(fmt.Sprintf("object %s\ntype commit\ntag v1\ntagger test <test@ur.invalid> 1700000000 +0000\n\nv1\n", commit))
	tagOid, err := objects.WriteGitObject(evsGitTagKind, tag)
	if err != nil {
		t.Fatal(err)
	}
	written := map[EvsGitOid]string{blob: evsGitBlobKind, empty: evsGitBlobKind, tree: evsGitTreeKind, commit: evsGitCommitKind, tagOid: evsGitTagKind}
	for oid, kind := range written {
		readKind, content, err := objects.ReadGitObject(ctx, oid)
		if err != nil || readKind != kind || evsGitObjectOid(kind, content) != oid {
			t.Fatalf("%s %s read back as %s: %v", kind, oid, readKind, err)
		}
	}
	// writing again changes nothing
	if again, err := objects.WriteBlob(strings.NewReader("hello, loose objects\n"), int64(len("hello, loose objects\n"))); err != nil || again != blob {
		t.Fatalf("a second write gave %s, %v", again, err)
	}

	gitPath := gitTestStockGit(t)
	for oid, kind := range written {
		out, err := gitTestRunGit(t, gitPath, dir, nil, "cat-file", "-t", oid.String())
		if err != nil || strings.TrimSpace(out) != kind {
			t.Fatalf("git cat-file -t %s: %v: %q", oid, err, out)
		}
		_, content, _ := objects.ReadGitObject(ctx, oid)
		out, err = gitTestRunGit(t, gitPath, dir, nil, "cat-file", kind, oid.String())
		if err != nil || out != string(content) {
			t.Fatalf("git cat-file %s %s: %v: %q", kind, oid, err, out)
		}
	}
	// stock git's objects read here
	out, err := gitTestRunGit(t, gitPath, dir, []byte("from stock git\n"), "hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	stockBlob := strings.TrimSpace(out)
	out, err = gitTestRunGit(t, gitPath, dir, []byte("100644 blob "+stockBlob+"\tfrom-git.txt\n"), "mktree")
	if err != nil {
		t.Fatal(err)
	}
	stockTree := strings.TrimSpace(out)
	out, err = gitTestRunGit(t, gitPath, dir, nil, "commit-tree", stockTree, "-p", commit.String(), "-m", "stock git's commit")
	if err != nil {
		t.Fatal(err)
	}
	stockCommit := strings.TrimSpace(out)
	for _, stock := range []struct{ hex, kind string }{{stockBlob, evsGitBlobKind}, {stockTree, evsGitTreeKind}, {stockCommit, evsGitCommitKind}} {
		oid := mustHexOid(t, stock.hex)
		kind, content, err := objects.ReadGitObject(ctx, oid)
		if err != nil || kind != stock.kind {
			t.Fatalf("stock git's %s %s: %s, %v", stock.kind, oid, kind, err)
		}
		out, err := gitTestRunGit(t, gitPath, dir, nil, "cat-file", stock.kind, stock.hex)
		if err != nil || out != string(content) {
			t.Fatalf("stock git's %s reads differently here", stock.kind)
		}
	}
	view, err := objects.ReadCommit(ctx, mustHexOid(t, stockCommit))
	if err != nil || view.Commit == nil || view.ParentOids[0] != commit {
		t.Fatalf("stock git's commit reads %+v, %v", view, err)
	}
}

// An oid from 40 hex digits.
func mustHexOid(t *testing.T, hexOid string) EvsGitOid {
	t.Helper()
	oid := EvsGitOid{}
	if decoded, err := hex.DecodeString(hexOid); err != nil || len(decoded) != len(oid) {
		t.Fatalf("%q is no oid", hexOid)
	} else {
		copy(oid[:], decoded)
	}
	return oid
}

// A loose object is refused where it is not its oid, holds bytes after its content, has no header git writes, or
// passes its kind's limit, on write and on read.
func TestLooseObjectRefusals(t *testing.T) {
	repository, dir := gitTestInitDirectory(t)
	objects := repository.Objects()
	ctx := context.Background()
	plant := func(oid EvsGitOid, raw []byte) {
		t.Helper()
		var deflated bytes.Buffer
		compressor := zlib.NewWriter(&deflated)
		compressor.Write(raw)
		compressor.Close()
		name := filepath.Join(dir, filepath.FromSlash(gitObjectName(oid)))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, deflated.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	named := gitBlobOid([]byte("what the name says"))
	plant(named, []byte("blob 9\x00not this!"))
	if _, _, err := objects.ReadGitObject(ctx, named); !errors.Is(err, ErrGitObjectCorrupt) {
		t.Fatalf("a blob that is not its oid: %v", err)
	}
	trailing := gitBlobOid([]byte("short"))
	plant(trailing, []byte("blob 5\x00shortTRAILING"))
	if _, _, err := objects.ReadGitObject(ctx, trailing); !errors.Is(err, ErrGitObjectCorrupt) {
		t.Fatalf("trailing bytes: %v", err)
	}
	headerless := gitBlobOid([]byte("headerless"))
	plant(headerless, []byte(strings.Repeat("x", 64)))
	if _, _, err := objects.ReadGitObject(ctx, headerless); !errors.Is(err, ErrGitObjectCorrupt) {
		t.Fatalf("no header: %v", err)
	}
	padded := gitBlobOid([]byte("ab"))
	plant(padded, []byte("blob 02\x00ab"))
	if _, _, err := objects.ReadGitObject(ctx, padded); !errors.Is(err, ErrGitObjectCorrupt) {
		t.Fatalf("a zero-padded size: %v", err)
	}
	if _, _, err := objects.ReadGitObject(ctx, gitBlobOid([]byte("never written"))); !errors.Is(err, ErrEvsGitObjectMissing) {
		t.Fatalf("a missing object: %v", err)
	}
	settings := DefaultGitSettings()
	settings.FileByteCount = 4
	small := newGitObjectStore(repository.FileSystem(), settings)
	if _, err := small.WriteBlob(strings.NewReader("12345"), 5); !errors.Is(err, ErrGitFileTooLarge) {
		t.Fatalf("a blob past the limit was written: %v", err)
	}
	large, err := objects.WriteBlob(strings.NewReader("12345"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := small.ReadGitObject(ctx, large); !errors.Is(err, ErrGitFileTooLarge) {
		t.Fatalf("a blob past the limit was read: %v", err)
	}
	if _, err := objects.WriteBlob(strings.NewReader("1234"), 5); err == nil {
		t.Fatal("a blob shorter than its size was written")
	}
	if _, err := objects.WriteGitObject("bundle", []byte("x")); err == nil {
		t.Fatal("an object of no kind was written")
	}
	// imported history the strict codec refuses reads for its tree and parents
	lenient := []byte("tree " + EvsGitEmptyTreeOid.String() + "\nauthor a <a> 1 +0000\ncommitter c <c> 1 +0000\ntree " + EvsGitEmptyTreeOid.String() + "\n\nm\n")
	oid, err := objects.WriteGitObject(evsGitCommitKind, lenient)
	if err != nil {
		t.Fatal(err)
	}
	view, err := objects.ReadCommit(ctx, oid)
	if err != nil || view.Commit != nil || view.TreeOid != EvsGitEmptyTreeOid {
		t.Fatalf("a lenient commit reads %+v, %v", view, err)
	}
}
