//go:build !js

// EVS1-M2-49's codec tests (DESIGN-DETAILS 8.6's codec row): the lenient readers over stock git's own objects, made
// by git 2.56 with hash-object --literally and read back by git ls-tree, git log and git rev-parse
// (testdata/evs/git/lenient_vectors.json): a tree with a zero-padded mode, with mode 100600 and out of order; a commit
// with a late committer, with a NUL in a header and with no blank line; a tag and a tag of a tag. Each is read as git
// reads it and keeps its oid. The tree reader's two refusals beyond git's, and git's own; canon_mode; the graph and
// tag readers' refusals; and fuzz targets for the tree reader and the graph decoder.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// One object of the vectors file, with git's reading of it.
type evsTestLenientVector struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Hex        string `json:"hex"`
	Oid        string `json:"oid"`
	Note       string `json:"note"`
	GitEntries []struct {
		Mode string `json:"mode"`
		Kind string `json:"kind"`
		Oid  string `json:"oid"`
		Name string `json:"name"`
	} `json:"git_entries"`
	GitTree          *string  `json:"git_tree"`
	GitParents       []string `json:"git_parents"`
	GitCommitterName *string  `json:"git_committer_name"`
	GitPeeled        *string  `json:"git_peeled"`
}

// The vectors file: the objects, the blobs and tree they name, and what git fsck says of them all.
type evsTestLenientVectors struct {
	MadeBy  string                  `json:"made_by"`
	Support []*evsTestLenientVector `json:"support"`
	Vectors []*evsTestLenientVector `json:"vectors"`
	Fsck    struct {
		Code int    `json:"code"`
		Out  string `json:"out"`
	} `json:"fsck"`
}

func readEvsTestLenientVectors(t testing.TB) *evsTestLenientVectors {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "evs", "git", "lenient_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &evsTestLenientVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func evsTestHex(t testing.TB, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func evsTestOid(t testing.TB, text string) EvsGitOid {
	t.Helper()
	return EvsGitOid(evsTestHex(t, text))
}

// Each of stock git's objects hashes to the oid git gave it, and the lenient readers read it as git does: a tree's
// entries in its own order, each mode as written with git's canon_mode, which ls-tree prints; a commit's tree and
// parents as git log walks them, a late committer and a NUL in a header and no blank line notwithstanding; a tag's
// object and type down to the commit rev-parse peels it to. The strict codecs, which do not change, refuse what is
// not canonical.
func TestEvsGitLenientReadersReadStockGitsObjects(t *testing.T) {
	vectors := readEvsTestLenientVectors(t)
	objects := map[EvsGitOid]*evsTestLenientVector{}
	for _, vector := range append(append([]*evsTestLenientVector{}, vectors.Support...), vectors.Vectors...) {
		objects[evsTestOid(t, vector.Oid)] = vector
	}
	seen := map[string]bool{}
	for _, vector := range vectors.Vectors {
		seen[vector.Name] = true
		encoded := evsTestHex(t, vector.Hex)
		if oid := evsGitObjectOid(vector.Kind, encoded); oid != evsTestOid(t, vector.Oid) {
			t.Errorf("%s: oid %x, git's %s", vector.Name, oid, vector.Oid)
		}
		switch vector.Kind {
		case evsGitTreeKind:
			entries, err := EvsGitTreeRead(encoded)
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			if len(entries) != len(vector.GitEntries) {
				t.Fatalf("%s: %d entries, git's %d", vector.Name, len(entries), len(vector.GitEntries))
			}
			raw := []byte{}
			for i, entry := range entries {
				gitEntry := vector.GitEntries[i]
				gitMode, err := strconv.ParseUint(gitEntry.Mode, 8, 32)
				if err != nil {
					t.Fatal(err)
				}
				if string(entry.Name) != gitEntry.Name || entry.Oid != evsTestOid(t, gitEntry.Oid) || entry.CanonMode != uint32(gitMode) {
					t.Errorf("%s: entry %d %q %o %x, git's %q %s %s", vector.Name, i, entry.Name, entry.CanonMode, entry.Oid, gitEntry.Name, gitEntry.Mode, gitEntry.Oid)
				}
				raw = append(append(append(append(raw, entry.ModeText...), ' '), entry.Name...), 0)
				raw = append(raw, entry.Oid[:]...)
			}
			// the reading keeps every byte, so the raw tree is its own bytes again
			if !bytes.Equal(raw, encoded) {
				t.Errorf("%s: the reading does not give the tree's bytes back", vector.Name)
			}
			_, strictErr := EvsGitTreeDecode(encoded)
			if (strictErr == nil) != (vector.Name == "tree-canonical") {
				t.Errorf("%s: the strict codec answered %v", vector.Name, strictErr)
			}
		case evsGitCommitKind:
			treeOid, parentOids, err := EvsGitCommitGraph(encoded)
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			if vector.GitTree == nil || treeOid != evsTestOid(t, *vector.GitTree) || len(parentOids) != len(vector.GitParents) {
				t.Fatalf("%s: tree %x parents %x, git's %v %v", vector.Name, treeOid, parentOids, vector.GitTree, vector.GitParents)
			}
			for i, parentOid := range parentOids {
				if parentOid != evsTestOid(t, vector.GitParents[i]) {
					t.Errorf("%s: parent %d %x, git's %s", vector.Name, i, parentOid, vector.GitParents[i])
				}
			}
			_, strictErr := EvsGitCommitDecode(encoded)
			// a commit with no blank line is one the strict codec keeps whole (TestEvsGitCommitDecodeKeepsAMissingBody)
			canonical := vector.Name == "commit-canonical" || vector.Name == "commit-raw-trees" || vector.Name == "commit-no-blank-line"
			if (strictErr == nil) != canonical {
				t.Errorf("%s: the strict codec answered %v", vector.Name, strictErr)
			}
		case evsGitTagKind:
			peeled := evsTestOid(t, vector.Oid)
			for hops := 0; ; hops += 1 {
				object := objects[peeled]
				if object == nil || object.Kind != evsGitTagKind {
					break
				}
				tag, err := EvsGitTagDecode(evsTestHex(t, object.Hex))
				if err != nil {
					t.Fatalf("%s: %v", vector.Name, err)
				}
				if next := objects[tag.ObjectOid]; next == nil || next.Kind != tag.ObjectKind {
					t.Fatalf("%s: a tag naming a %s it does not hold", vector.Name, tag.ObjectKind)
				}
				peeled = tag.ObjectOid
			}
			if vector.GitPeeled == nil || peeled != evsTestOid(t, *vector.GitPeeled) {
				t.Errorf("%s: peels to %x, git's %v", vector.Name, peeled, vector.GitPeeled)
			}
		}
	}
	for _, name := range []string{"tree-zero-padded-mode", "tree-mode-100600", "tree-unsorted", "commit-late-committer", "commit-nul-in-header", "commit-no-blank-line", "tag", "tag-of-a-tag"} {
		if !seen[name] {
			t.Errorf("no vector %s", name)
		}
	}
	// git log prints the last of two committers, the reading the strict codec's refusal exists to prevent
	for _, vector := range vectors.Vectors {
		if vector.Name == "commit-late-committer" && (vector.GitCommitterName == nil || *vector.GitCommitterName != "other") {
			t.Errorf("git's committer %v", vector.GitCommitterName)
		}
	}
}

// Where git is installed, its readings are taken again from the vectors' bytes, so the file holds what git says.
func TestEvsGitLenientVectorsAreStockGitsReadings(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	vectors := readEvsTestLenientVectors(t)
	dir := filepath.Join(t.TempDir(), "vectors.git")
	run := func(input []byte, args ...string) string {
		command := exec.Command(gitPath, append([]string{"-C", dir}, args...)...)
		command.Env = []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
		command.Stdin = bytes.NewReader(input)
		out, err := command.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	if out, err := exec.Command(gitPath, "init", "-q", "--bare", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	for _, vector := range append(append([]*evsTestLenientVector{}, vectors.Support...), vectors.Vectors...) {
		if oid := run(evsTestHex(t, vector.Hex), "hash-object", "-w", "--literally", "-t", vector.Kind, "--stdin"); oid != vector.Oid {
			t.Fatalf("%s: git hashes it to %s, the file says %s", vector.Name, oid, vector.Oid)
		}
	}
	for _, vector := range vectors.Vectors {
		if vector.Kind != evsGitTreeKind {
			continue
		}
		entries, err := EvsGitTreeRead(evsTestHex(t, vector.Hex))
		if err != nil {
			t.Fatal(err)
		}
		lines := []string{}
		for _, entry := range entries {
			kind := evsGitBlobKind
			if entry.CanonMode == EvsGitModeDirectory {
				kind = evsGitTreeKind
			}
			// ls-tree's own form: the canon mode as %06o, the kind, the oid, a tab and the name
			lines = append(lines, fmt.Sprintf("%06o %s %x\t%s", entry.CanonMode, kind, entry.Oid[:], entry.Name))
		}
		got := strings.Join(lines, "\n")
		if want := run(nil, "ls-tree", vector.Oid); got != want {
			t.Errorf("%s: read as\n%s\ngit ls-tree says\n%s", vector.Name, got, want)
		}
	}
}

// Beyond git's own refusals, the tree reader refuses a name no path can name: one holding a slash, and two entries of
// one name. Each refusal is ErrEvsGitObjectInvalid and names no bytes.
func TestEvsGitTreeReadRefusesASlashAndARepeatedName(t *testing.T) {
	oid := evsTestBytes("an oid", 20)
	entry := func(mode string, name string) []byte {
		return append([]byte(mode+" "+name+"\x00"), oid...)
	}
	for label, encoded := range map[string][]byte{
		"a slash":       entry("100644", "a/b"),
		"a repeat":      append(entry("100644", "a"), entry("40000", "a")...),
		"a late repeat": append(append(entry("100644", "a"), entry("100644", "b")...), entry("100755", "a")...),
	} {
		if _, err := EvsGitTreeRead(encoded); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		} else if strings.Contains(err.Error(), "a/b") {
			t.Errorf("%s: the refusal names the bytes: %v", label, err)
		}
	}
}

// What git refuses, the reader refuses: no mode, a mode that is no octal number, a name that does not end, an oid
// cut short and an empty name. An empty tree reads as no entries.
func TestEvsGitTreeReadRefusesWhatGitRefuses(t *testing.T) {
	oid := evsTestBytes("an oid", 20)
	for label, encoded := range map[string][]byte{
		"no mode":          append([]byte(" a\x00"), oid...),
		"no space":         []byte("100644"),
		"a decimal digit":  append([]byte("100684 a\x00"), oid...),
		"a name unended":   []byte("100644 a"),
		"an oid cut short": append([]byte("100644 a\x00"), oid[:19]...),
		"an empty name":    append([]byte("100644 \x00"), oid...),
	} {
		if _, err := EvsGitTreeRead(encoded); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	entries, err := EvsGitTreeRead(nil)
	if err != nil || len(entries) != 0 {
		t.Errorf("the empty tree: %v %v", entries, err)
	}
}

// git's canon_mode: a regular file by its owner's execute bit, 100664 kept, a symlink, a directory, and anything else
// a gitlink.
func TestEvsGitCanonMode(t *testing.T) {
	for mode, canon := range map[uint32]uint32{
		0o100644: 0o100644, 0o100755: 0o100755, 0o100664: 0o100664, 0o100600: 0o100644, 0o100700: 0o100755,
		0o100000: 0o100644, 0o120000: 0o120000, 0o120777: 0o120000, 0o040000: 0o040000, 0o040755: 0o040000,
		0o160000: 0o160000, 0: 0o160000, 0o777: 0o160000,
	} {
		if got := EvsGitCanonMode(mode); got != canon {
			t.Errorf("canon_mode(%o) = %o, want %o", mode, got, canon)
		}
	}
}

// The graph reader refuses what commit.c refuses: no tree line, nothing after it, a parent line cut short and a
// parent line that ends the commit; it stops at the first line that is not a parent, as git does.
func TestEvsGitCommitGraphRefuses(t *testing.T) {
	tree := strings.Repeat("ab", 20)
	parent := strings.Repeat("cd", 20)
	for label, encoded := range map[string]string{
		"no tree line":      "author a <a> 1 +0000\n",
		"a tree line alone": "tree " + tree,
		"a short tree":      "tree " + tree[:39] + "\nauthor x\n",
		"a bad tree hex":    "tree " + strings.Repeat("zz", 20) + "\nauthor x\n",
		// commit.c reads a parent line while more than its 47 bytes remain, and refuses one that is not a line or
		// ends the commit
		"a parent cut short": "tree " + tree + "\nparent " + parent[:39] + "\nauthor x\n",
		"a parent line last": "tree " + tree + "\nparent " + parent + "\n",
	} {
		if _, _, err := EvsGitCommitGraph([]byte(encoded)); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	treeOid, parentOids, err := EvsGitCommitGraph([]byte("tree " + tree + "\nauthor x\nparent " + parent + "\n\nmessage\n"))
	if err != nil || hex.EncodeToString(treeOid[:]) != tree || len(parentOids) != 0 {
		t.Errorf("a parent after another header is not one: %x %x %v", treeOid[:], parentOids, err)
	}
	// hex in capitals names the same objects, as git's get_oid_hex reads it
	treeOid, parentOids, err = EvsGitCommitGraph([]byte("tree " + strings.ToUpper(tree) + "\nparent " + strings.ToUpper(parent) + "\nauthor x\n"))
	if err != nil || hex.EncodeToString(treeOid[:]) != tree || len(parentOids) != 1 || hex.EncodeToString(parentOids[0][:]) != parent {
		t.Errorf("capitals: %x %x %v", treeOid[:], parentOids, err)
	}
}

// The tag reader refuses a tag with no object line, no type line, or a type git does not know.
func TestEvsGitTagDecodeRefuses(t *testing.T) {
	object := strings.Repeat("ab", 20)
	for label, encoded := range map[string]string{
		"no object line":  "type commit\ntag v1\n",
		"a short object":  "object " + object[:39] + "\ntype commit\n",
		"no type line":    "object " + object + "\ntag v1\n",
		"a type unended":  "object " + object + "\ntype commit",
		"an unknown type": "object " + object + "\ntype branch\ntag v1\n",
	} {
		if _, err := EvsGitTagDecode([]byte(encoded)); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// The tree reader's seeds: the vectors' trees and the strict codec's.
func evsGitTreeReadSeeds(f *testing.F) [][]byte {
	seeds := evsGitTreeSeeds()
	for _, vector := range readEvsTestLenientVectors(f).Vectors {
		if vector.Kind == evsGitTreeKind {
			seeds = append(seeds, evsTestHex(f, vector.Hex))
		}
	}
	return seeds
}

// The graph decoder's seeds: the vectors' commits, the strict codec's, and a tree line in capitals.
func evsGitCommitGraphSeeds(f *testing.F) [][]byte {
	seeds := append(evsGitCommitSeeds(), []byte("tree "+strings.Repeat("AB", 20)+"\nauthor x\n"))
	for _, vector := range readEvsTestLenientVectors(f).Vectors {
		if vector.Kind == evsGitCommitKind {
			seeds = append(seeds, evsTestHex(f, vector.Hex))
		}
	}
	return seeds
}

// The tree reader never panics; what it takes it reads losslessly, entries in the tree's order whose raw form is the
// input again, names non-empty, slash-free and distinct, each canon mode git's of its mode; and every tree the strict
// codec takes it takes with the same entries.
func FuzzEvsGitTreeRead(f *testing.F) {
	for _, seed := range evsGitTreeReadSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		entries, err := EvsGitTreeRead(encoded)
		strict, strictErr := EvsGitTreeDecode(encoded)
		if err != nil {
			if !errors.Is(err, ErrEvsGitObjectInvalid) {
				t.Fatalf("a refusal of another kind: %v", err)
			}
			if strictErr == nil {
				t.Fatalf("the strict codec takes what the reader refuses: %v", err)
			}
			return
		}
		raw := []byte{}
		names := map[string]bool{}
		for _, entry := range entries {
			if len(entry.Name) == 0 || bytes.IndexByte(entry.Name, '/') != -1 || names[string(entry.Name)] {
				t.Fatalf("a name no path can hold: %q", entry.Name)
			}
			names[string(entry.Name)] = true
			if entry.CanonMode != EvsGitCanonMode(entry.Mode) {
				t.Fatalf("canon %o of %o", entry.CanonMode, entry.Mode)
			}
			raw = append(append(append(append(raw, entry.ModeText...), ' '), entry.Name...), 0)
			raw = append(raw, entry.Oid[:]...)
		}
		if !bytes.Equal(raw, encoded) {
			t.Fatalf("a reading that loses bytes")
		}
		if strictErr == nil {
			if len(strict.Entries) != len(entries) {
				t.Fatalf("the strict codec read %d entries, the reader %d", len(strict.Entries), len(entries))
			}
			for i, entry := range strict.Entries {
				if !bytes.Equal(entry.Name, entries[i].Name) || entry.Mode != entries[i].CanonMode || entry.Oid != entries[i].Oid {
					t.Fatalf("entry %d read two ways", i)
				}
			}
		}
	})
}

// The graph decoder never panics; what the strict codec takes it reads to the same tree and parents, and what it
// takes begins with its tree line.
func FuzzEvsGitCommitGraph(f *testing.F) {
	for _, seed := range evsGitCommitGraphSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		treeOid, parentOids, err := EvsGitCommitGraph(encoded)
		strict, strictErr := EvsGitCommitDecode(encoded)
		if err != nil {
			if !errors.Is(err, ErrEvsGitObjectInvalid) {
				t.Fatalf("a refusal of another kind: %v", err)
			}
			if strictErr == nil {
				t.Fatalf("the strict codec takes what the graph decoder refuses: %v", err)
			}
			return
		}
		// git's get_oid_hex takes either case
		if len(encoded) < 46 || !bytes.EqualFold(encoded[:46], []byte("tree "+hex.EncodeToString(treeOid[:])+"\n")) {
			t.Fatalf("a tree that is not the first line's")
		}
		if strictErr == nil {
			if strict.TreeOid != treeOid || len(strict.ParentOids) != len(parentOids) {
				t.Fatalf("the strict codec read another graph")
			}
			for i, parentOid := range strict.ParentOids {
				if parentOid != parentOids[i] {
					t.Fatalf("parent %d read two ways", i)
				}
			}
		}
	})
}
