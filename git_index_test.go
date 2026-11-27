//go:build !ios_extension && !sidecar_http

// GIT-M13-01's index tests: the version 2 encoder byte-equal with stock git's update-index on the vectors in
// testdata/git/index/ (each <name>.index written by stock git, regenerated with SIDECAR_REGENERATE_GIT_VECTORS=1 where
// the host has git, and checked against it on every run that has one), and a read refusing what this index cannot
// keep.

package sidecar

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// One entry of an index vector: its blob's content stands for its oid, a gitlink's for a commit's.
type gitIndexVectorEntry struct {
	mode            uint32
	stage           int
	path            string
	content         string
	assumeUnchanged bool
}

// The vectors, each a set of entries stock git's update-index --index-info adds to an empty index.
func gitIndexVectors() map[string][]gitIndexVectorEntry {
	long := strings.Repeat("deep/", 819) + "end.txt"
	padding := []gitIndexVectorEntry{}
	for length := 1; length <= 9; length += 1 {
		padding = append(padding, gitIndexVectorEntry{mode: EvsGitModeFile, path: strings.Repeat("p", length), content: fmt.Sprint(length)})
	}
	return map[string][]gitIndexVectorEntry{
		"empty": {},
		"simple": {
			{mode: EvsGitModeFile, path: "README.md", content: "# readme\n"},
			{mode: EvsGitModeExecutable, path: "bin/run.sh", content: "#!/bin/sh\n"},
			{mode: EvsGitModeFile, path: "docs/a.txt", content: "a\n"},
			{mode: EvsGitModeSymlink, path: "link", content: "docs/a.txt"},
			{mode: EvsGitModeGitlink, path: "vendor/module", content: "a commit elsewhere"},
		},
		"order": {
			{mode: EvsGitModeFile, path: "B", content: "upper\n"},
			{mode: EvsGitModeFile, path: "a-b", content: "dash\n"},
			{mode: EvsGitModeFile, path: "a.b", content: "dot\n"},
			{mode: EvsGitModeFile, path: "a/b", content: "slash\n"},
			{mode: EvsGitModeFile, path: "a0", content: "zero\n"},
			{mode: EvsGitModeFile, path: "ab", content: "ab\n"},
			{mode: EvsGitModeFile, path: "café", content: "unicode\n"},
		},
		"stages": {
			{mode: EvsGitModeFile, path: "clean.txt", content: "clean\n"},
			{mode: EvsGitModeFile, stage: 1, path: "conflict.txt", content: "base\n"},
			{mode: EvsGitModeFile, stage: 2, path: "conflict.txt", content: "ours\n"},
			{mode: EvsGitModeExecutable, stage: 3, path: "conflict.txt", content: "theirs\n"},
			{mode: EvsGitModeFile, stage: 2, path: "only-ours.txt", content: "ours alone\n"},
		},
		"assume-unchanged": {
			{mode: EvsGitModeFile, path: "README", content: "upper\n"},
			{mode: EvsGitModeFile, path: "readme", content: "lower\n", assumeUnchanged: true},
		},
		"long-path": {
			{mode: EvsGitModeFile, path: long, content: "far down\n"},
			{mode: EvsGitModeFile, path: "short", content: "near\n"},
		},
		"padding": padding,
	}
}

// The oid a vector entry names.
func (self gitIndexVectorEntry) oid() EvsGitOid {
	if self.mode == EvsGitModeGitlink {
		return evsGitObjectOid(evsGitCommitKind, []byte(self.content))
	}
	return gitBlobOid([]byte(self.content))
}

// Stock git's index for a vector: the blobs written, the entries added with update-index --index-info, the
// assume-unchanged bits set, and .git/index's bytes.
func gitIndexStock(t *testing.T, gitPath string, entries []gitIndexVectorEntry) []byte {
	t.Helper()
	dir := t.TempDir()
	if out, err := gitTestRunGit(t, gitPath, dir, nil, "init", "-q"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	info := &strings.Builder{}
	assume := []string{}
	for _, entry := range entries {
		if entry.mode != EvsGitModeGitlink {
			if out, err := gitTestRunGit(t, gitPath, dir, []byte(entry.content), "hash-object", "-w", "--stdin"); err != nil {
				t.Fatalf("git hash-object: %v: %s", err, out)
			}
		}
		fmt.Fprintf(info, "%o %s %d\t%s\n", entry.mode, entry.oid(), entry.stage, entry.path)
		if entry.assumeUnchanged {
			assume = append(assume, entry.path)
		}
	}
	args := []string{"-c", "index.version=2", "-c", "index.skipHash=false", "-c", "feature.manyFiles=false", "-c",
		"core.untrackedCache=false", "-c", "index.threads=1", "update-index", "--index-info"}
	if out, err := gitTestRunGit(t, gitPath, dir, []byte(info.String()), args...); err != nil {
		t.Fatalf("git update-index --index-info: %v: %s", err, out)
	}
	if len(entries) == 0 {
		// an empty index stock git writes: one entry added, then removed
		dummy := gitBlobOid([]byte("dummy"))
		if out, err := gitTestRunGit(t, gitPath, dir, []byte(fmt.Sprintf("100644 %s 0\tdummy\n", dummy)), args...); err != nil {
			t.Fatalf("git update-index --index-info: %v: %s", err, out)
		}
		if out, err := gitTestRunGit(t, gitPath, dir, nil, "-c", "index.version=2", "-c", "index.threads=1", "update-index", "--force-remove", "dummy"); err != nil {
			t.Fatalf("git update-index --force-remove: %v: %s", err, out)
		}
	}
	if 0 < len(assume) {
		args := append([]string{"-c", "index.version=2", "-c", "index.threads=1", "update-index", "--assume-unchanged", "--"}, assume...)
		if out, err := gitTestRunGit(t, gitPath, dir, nil, args...); err != nil {
			t.Fatalf("git update-index --assume-unchanged: %v: %s", err, out)
		}
	}
	content, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// The encoder's bytes equal stock git's update-index output for each vector, the committed golden is stock git's, and a
// read of it gives the vector's entries back.
func TestIndexV2Vectors(t *testing.T) {
	gitPath := ""
	if path, err := lookGit(); err == nil {
		gitPath = path
	}
	regenerate := os.Getenv("SIDECAR_REGENERATE_GIT_VECTORS") == "1"
	if regenerate && gitPath == "" {
		t.Fatal("regenerating the vectors needs stock git")
	}
	for name, entries := range gitIndexVectors() {
		index := &GitIndex{}
		for _, entry := range entries {
			index.Entries = append(index.Entries, &GitIndexEntry{
				Path: entry.path, Mode: entry.mode, Oid: entry.oid(), Stage: entry.stage, Unwritten: entry.assumeUnchanged,
			})
		}
		ours, err := index.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		goldenName := filepath.Join("testdata", "git", "index", name+".index")
		if gitPath != "" {
			stock := gitIndexStock(t, gitPath, entries)
			if regenerate {
				if err := os.MkdirAll(filepath.Dir(goldenName), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenName, stock, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(ours, stock) {
				t.Fatalf("%s: the encoder's %d bytes differ from stock git's %d", name, len(ours), len(stock))
			}
		}
		golden, err := os.ReadFile(goldenName)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(ours, golden) {
			t.Fatalf("%s: the encoder's bytes differ from the golden stock git wrote", name)
		}
		decoded, err := GitIndexDecode(golden, DefaultGitSettings())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(decoded.Entries) != len(index.Entries) {
			t.Fatalf("%s: %d entries read back, %d written", name, len(decoded.Entries), len(index.Entries))
		}
		for at, entry := range decoded.Entries {
			want := index.Entries[at]
			if entry.Path != want.Path || entry.Mode != want.Mode || entry.Oid != want.Oid || entry.Stage != want.Stage ||
				entry.Unwritten != want.Unwritten || entry.Stat != (GitStatData{}) {
				t.Fatalf("%s: entry %d reads %+v, want %+v", name, at, entry, want)
			}
		}
	}
}

// The git on this host's PATH.
func lookGit() (string, error) {
	return exec.LookPath("git")
}

// An index this git cannot keep is refused, never repaired: another version, a required extension, a bad trailer,
// entries out of order or twice, a path both a file and a directory, an unsafe path, a bad mode, too many entries; an
// optional extension is passed over and a zero trailer, stock git's index.skipHash, reads.
func TestIndexRefusals(t *testing.T) {
	settings := DefaultGitSettings()
	encode := func(entries ...*GitIndexEntry) []byte {
		t.Helper()
		encoded, err := (&GitIndex{Entries: entries}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	rehash := func(body []byte) []byte {
		sum := sha1.Sum(body)
		return append(bytes.Clone(body), sum[:]...)
	}
	file := func(path string) *GitIndexEntry {
		return &GitIndexEntry{Path: path, Mode: EvsGitModeFile, Oid: gitBlobOid([]byte(path))}
	}
	good := encode(file("a.txt"), file("b.txt"))
	body := good[:len(good)-sha1.Size]
	if _, err := GitIndexDecode(good, settings); err != nil {
		t.Fatal(err)
	}
	zeroTrailer := append(bytes.Clone(body), make([]byte, sha1.Size)...)
	if _, err := GitIndexDecode(zeroTrailer, settings); err != nil {
		t.Fatalf("a zero trailer: %v", err)
	}
	optional := rehash(append(append(bytes.Clone(body), "TREE"...), 0, 0, 0, 2, 'x', 'y'))
	if index, err := GitIndexDecode(optional, settings); err != nil || len(index.Entries) != 2 {
		t.Fatalf("an optional extension: %v", err)
	}
	version3 := bytes.Clone(body)
	binary.BigEndian.PutUint32(version3[4:8], 3)
	required := rehash(append(append(bytes.Clone(body), "link"...), 0, 0, 0, 0))
	badTrailer := bytes.Clone(good)
	badTrailer[len(badTrailer)-1] ^= 1
	refused := map[string][]byte{
		"version 3":           rehash(version3),
		"a required one":      required,
		"a bad trailer":       badTrailer,
		"out of order":        rehash(encodeUnchecked(t, file("b.txt"), file("a.txt"))),
		"twice":               rehash(encodeUnchecked(t, file("a.txt"), file("a.txt"))),
		"a file and a dir":    rehash(encodeUnchecked(t, file("a"), file("a.txt"), file("a/b"))),
		"an unsafe path":      rehash(encodeUnchecked(t, file(".GIT/config"))),
		"a bad mode":          rehash(encodeUnchecked(t, &GitIndexEntry{Path: "x", Mode: 0o100600})),
		"merged and conflict": rehash(encodeUnchecked(t, file("c"), &GitIndexEntry{Path: "c", Mode: EvsGitModeFile, Stage: 2})),
	}
	for what, encoded := range refused {
		if _, err := GitIndexDecode(encoded, settings); err == nil {
			t.Fatalf("%s was read", what)
		} else if !errors.Is(err, ErrGitIndexInvalid) && !errors.Is(err, ErrGitPathUnsafe) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	few := DefaultGitSettings()
	few.FileCount = 1
	if _, err := GitIndexDecode(good, few); err == nil {
		t.Fatal("an index past FileCount was read")
	}
	// the setter refuses what the reader would
	index := &GitIndex{}
	if err := index.Set(file("a")); err != nil {
		t.Fatal(err)
	}
	if err := index.Set(file("a/b")); err == nil {
		t.Fatal("a path under a file was set")
	}
	if err := index.Set(file("dir/x")); err != nil {
		t.Fatal(err)
	}
	if err := index.Set(file("dir")); err == nil {
		t.Fatal("a file of a directory's name was set")
	}
	if err := index.Set(&GitIndexEntry{Path: "dir/x", Mode: EvsGitModeFile, Stage: 2}); err != nil || index.Entry("dir/x", 0) != nil {
		t.Fatalf("a conflict stage did not replace the merged entry: %v", err)
	}
}

// Entries in the format's bytes with no order or mode checked, so a read's refusals can be tried; the trailer left off.
func encodeUnchecked(t *testing.T, entries ...*GitIndexEntry) []byte {
	t.Helper()
	encoded := []byte(gitIndexSignature)
	encoded = binary.BigEndian.AppendUint32(encoded, gitIndexVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(entries)))
	for _, entry := range entries {
		encoded = append(encoded, make([]byte, 24)...)
		encoded = binary.BigEndian.AppendUint32(encoded, entry.Mode)
		encoded = append(encoded, make([]byte, 12)...)
		encoded = append(encoded, entry.Oid[:]...)
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(min(len(entry.Path), gitIndexNameMask))|uint16(entry.Stage)<<gitIndexStageShift)
		encoded = append(encoded, entry.Path...)
		size := gitIndexEntryFixed + len(entry.Path)
		encoded = append(encoded, make([]byte, (size+8)&^7-size)...)
	}
	return encoded
}
