// The git codec on its own: vectors, every refusal, the delta round trip and its working set, and
// §22.6's targets, which mlsinterop's git_oracle_test.go runs again against go-git. Seeds are embedded
// so they run on the sidecar_http leg, whose Worker has no file system. Stock git is T1's oracle on
// hosts that have it, and elsewhere its test skips.

package sidecar

import (
	"bytes"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

// Delta seeds are a base, framed as evsGitFuzzSplit reads, then a delta. Pkt-line seeds are raw streams.
//
//go:embed testdata/fuzz/evs_git_delta testdata/fuzz/evs_git_pktline
var evsGitFuzzSeeds embed.FS

func evsGitFuzzSeedFiles(t testing.TB, directory string) [][]byte {
	t.Helper()
	seeds := [][]byte{}
	entries, err := evsGitFuzzSeeds.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		seed, err := evsGitFuzzSeeds.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	if len(seeds) == 0 {
		t.Fatalf("no seeds in %s", directory)
	}
	return seeds
}

// Splits a fuzz input into a base and what follows it: a three-byte base length, high byte first, then
// that many bytes, or as many as there are. mlsinterop's oracle reads its seeds the same way.
func evsGitFuzzSplit(input []byte) ([]byte, []byte) {
	if len(input) < 3 {
		return nil, input
	}
	baseSize := int(input[0])*65536 + int(input[1])*256 + int(input[2])
	baseSize = min(baseSize, len(input)-3)
	return input[3 : 3+baseSize], input[3+baseSize:]
}

// Frames a base for evsGitFuzzSplit.
func evsGitFuzzJoin(base []byte, rest []byte) []byte {
	input := []byte{byte(len(base) / 65536), byte(len(base) / 256), byte(len(base))}
	return append(append(input, base...), rest...)
}

func evsGitTestOid(t testing.TB, text string) EvsGitOid {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return EvsGitOid(decoded)
}

// Applies a whole delta with no bound of its own and the default settings.
func evsGitTestApply(base []byte, delta []byte) ([]byte, error) {
	result := &bytes.Buffer{}
	size, err := EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(delta), 1024*1024*1024, result, DefaultEvsGitDeltaSettings())
	if err != nil {
		return nil, err
	}
	if size != int64(result.Len()) {
		return nil, fmt.Errorf("apply answered %d and wrote %d", size, result.Len())
	}
	return result.Bytes(), nil
}

func evsGitTestEncode(t testing.TB, base []byte, target []byte, settings *EvsGitDeltaSettings) []byte {
	t.Helper()
	delta := &bytes.Buffer{}
	if err := EvsGitDeltaEncode(bytes.NewReader(base), bytes.NewReader(target), delta, settings); err != nil {
		t.Fatal(err)
	}
	return delta.Bytes()
}

// Settings small enough that short inputs reach every path: a window that slides, an index that
// samples, chunks that run out mid-match.
func evsGitTestSmallSettings() *EvsGitDeltaSettings {
	return &EvsGitDeltaSettings{
		IndexBlockCount:    8,
		CandidateCount:     2,
		GoodMatchByteCount: 64,
		WindowByteCount:    256,
		ChunkByteCount:     256,
	}
}

func TestEvsGitBlobOidVectors(t *testing.T) {
	for _, c := range []struct {
		content string
		oid     string
	}{
		{content: "", oid: "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		{content: "hello\n", oid: "ce013625030ba8dba906f756967f9e9ca394464a"},
		{content: "what is up, doc?", oid: "bd9dbf5aae1a3862dd1526723246b20206e5fc37"},
	} {
		oid, err := EvsGitBlobOid(strings.NewReader(c.content), int64(len(c.content)))
		if err != nil {
			t.Fatal(err)
		}
		if oid.String() != c.oid {
			t.Errorf("%q: %s", c.content, oid)
		}
	}
}

func TestEvsGitBlobHashTakesPieces(t *testing.T) {
	blobHash, err := newEvsGitBlobHash(6)
	if err != nil {
		t.Fatal(err)
	}
	for _, piece := range []string{"he", "", "llo", "\n"} {
		if _, err := blobHash.Write([]byte(piece)); err != nil {
			t.Fatal(err)
		}
	}
	oid, err := blobHash.Oid()
	if err != nil {
		t.Fatal(err)
	}
	if oid.String() != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Error(oid)
	}
}

func TestEvsGitBlobOidRefusesTheWrongSize(t *testing.T) {
	for _, c := range []struct {
		content string
		size    int64
	}{
		{content: "hello", size: 4},
		{content: "hello", size: 6},
		{content: "", size: 1},
		{content: "", size: -1},
	} {
		if _, err := EvsGitBlobOid(strings.NewReader(c.content), c.size); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%q at %d: %v", c.content, c.size, err)
		}
	}
}

func TestEvsGitBlobHashHoldsItsSizeAfterARefusal(t *testing.T) {
	blobHash, err := newEvsGitBlobHash(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobHash.Write([]byte("abc")); !errors.Is(err, ErrEvsGitObjectInvalid) {
		t.Fatal(err)
	}
	if _, err := blobHash.Oid(); !errors.Is(err, ErrEvsGitObjectInvalid) {
		t.Error(err)
	}
}

func TestEvsGitEmptyTreeOid(t *testing.T) {
	oid, err := (&EvsGitTree{}).Oid()
	if err != nil {
		t.Fatal(err)
	}
	if oid.String() != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Error(oid)
	}
}

// The tree stock git's mktree made from these entries, in another order.
func TestEvsGitTreeVector(t *testing.T) {
	blobOid := evsGitTestOid(t, "ce013625030ba8dba906f756967f9e9ca394464a")
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("hello.txt"), Oid: blobOid},
		{Mode: EvsGitModeDirectory, Name: []byte("dir"), Oid: evsGitTestOid(t, "4b825dc642cb6eb9a060e54bf8d69288fbee4904")},
		{Mode: EvsGitModeExecutable, Name: []byte("run.sh"), Oid: blobOid},
		{Mode: EvsGitModeSymlink, Name: []byte("link"), Oid: blobOid},
	}}
	oid, err := tree.Oid()
	if err != nil {
		t.Fatal(err)
	}
	if oid.String() != "cf656b586d56636fa958e3f794e7c1d98ea15588" {
		t.Error(oid)
	}
}

func evsGitTestTreeNames(t *testing.T, encoded []byte) []string {
	t.Helper()
	tree, err := EvsGitTreeDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range tree.Entries {
		names = append(names, string(entry.Name))
	}
	return names
}

func TestEvsGitTreeSortsADirectoryAsIfItEndsInASlash(t *testing.T) {
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("foo0")},
		{Mode: EvsGitModeDirectory, Name: []byte("foo")},
		{Mode: EvsGitModeFile, Name: []byte("foo.txt")},
		{Mode: EvsGitModeFile, Name: []byte("foo-bar")},
		{Mode: EvsGitModeDirectory, Name: []byte("fo")},
	}}
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fo", "foo-bar", "foo.txt", "foo", "foo0"}
	if names := evsGitTestTreeNames(t, encoded); !slices.Equal(names, want) {
		t.Errorf("%q", names)
	}
}

func TestEvsGitTreeSortsAFileBeforeItsExtensions(t *testing.T) {
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("a.b")},
		{Mode: EvsGitModeFile, Name: []byte("a")},
	}}
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if names := evsGitTestTreeNames(t, encoded); !slices.Equal(names, []string{"a", "a.b"}) {
		t.Errorf("%q", names)
	}
}

func TestEvsGitTreeSortsAGitlinkAsAFile(t *testing.T) {
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("a.b")},
		{Mode: EvsGitModeGitlink, Name: []byte("a")},
	}}
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if names := evsGitTestTreeNames(t, encoded); !slices.Equal(names, []string{"a", "a.b"}) {
		t.Errorf("%q", names)
	}
}

// Bytes sort as themselves: a name is never read as text.
func TestEvsGitTreeKeepsNamesAsRawBytes(t *testing.T) {
	composed := []byte("caf\xc3\xa9")
	decomposed := []byte("cafe\xcc\x81")
	invalid := []byte("caf\xff")
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: composed},
		{Mode: EvsGitModeFile, Name: decomposed},
		{Mode: EvsGitModeFile, Name: invalid},
	}}
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{string(decomposed), string(composed), string(invalid)}
	if names := evsGitTestTreeNames(t, encoded); !slices.Equal(names, want) {
		t.Errorf("%q", names)
	}
}

func TestEvsGitTreeEncodeLeavesItsEntriesAlone(t *testing.T) {
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeFile, Name: []byte("b")},
		{Mode: EvsGitModeFile, Name: []byte("a")},
	}}
	if _, err := tree.Encode(); err != nil {
		t.Fatal(err)
	}
	if string(tree.Entries[0].Name) != "b" {
		t.Error("the entries moved")
	}
}

func TestEvsGitTreeEncodeRefuses(t *testing.T) {
	for _, c := range []struct {
		name    string
		entries []EvsGitTreeEntry
	}{
		{name: "an empty name", entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: nil}}},
		{name: "a slash", entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("a/b")}}},
		{name: "a NUL", entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("a\x00b")}}},
		{name: "mode zero", entries: []EvsGitTreeEntry{{Mode: 0, Name: []byte("a")}}},
		{name: "a mode git never wrote", entries: []EvsGitTreeEntry{{Mode: 0o100600, Name: []byte("a")}}},
		{
			name: "a repeat",
			entries: []EvsGitTreeEntry{
				{Mode: EvsGitModeFile, Name: []byte("a")},
				{Mode: EvsGitModeFile, Name: []byte("a")},
			},
		},
		{
			// these sort apart, so the repeat is not adjacent
			name: "a file and directory of one name",
			entries: []EvsGitTreeEntry{
				{Mode: EvsGitModeFile, Name: []byte("a")},
				{Mode: EvsGitModeFile, Name: []byte("a.txt")},
				{Mode: EvsGitModeDirectory, Name: []byte("a")},
			},
		},
	} {
		if _, err := (&EvsGitTree{Entries: c.entries}).Encode(); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := (&EvsGitTree{Entries: c.entries}).Oid(); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsGitTreeRoundTrips(t *testing.T) {
	oid := evsGitTestOid(t, "ce013625030ba8dba906f756967f9e9ca394464a")
	tree := &EvsGitTree{Entries: []EvsGitTreeEntry{
		{Mode: EvsGitModeDirectory, Name: []byte("d"), Oid: oid},
		{Mode: EvsGitModeFile, Name: []byte("f"), Oid: oid},
		{Mode: EvsGitModeFileGroupWritable, Name: []byte("g"), Oid: oid},
		{Mode: EvsGitModeExecutable, Name: []byte("x"), Oid: oid},
		{Mode: EvsGitModeSymlink, Name: []byte("y"), Oid: oid},
		{Mode: EvsGitModeGitlink, Name: []byte("z"), Oid: oid},
	}}
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := EvsGitTreeDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(decoded.Entries, tree.Entries, func(a EvsGitTreeEntry, b EvsGitTreeEntry) bool {
		return a.Mode == b.Mode && bytes.Equal(a.Name, b.Name) && a.Oid == b.Oid
	}) {
		t.Errorf("%v", decoded.Entries)
	}
}

func TestEvsGitTreeDecodeOwnsItsNames(t *testing.T) {
	encoded, err := (&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("name")}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := EvsGitTreeDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	if string(tree.Entries[0].Name) != "name" {
		t.Errorf("%q", tree.Entries[0].Name)
	}
}

func TestEvsGitTreeDecodeRefuses(t *testing.T) {
	oid := strings.Repeat("\x11", 20)
	for _, c := range []struct {
		name    string
		encoded string
	}{
		{name: "no mode", encoded: "abc"},
		{name: "an empty mode", encoded: " a\x00" + oid},
		{name: "a mode that is not octal", encoded: "100648 a\x00" + oid},
		{name: "a zero-padded mode", encoded: "040000 a\x00" + oid},
		{name: "a mode git never wrote", encoded: "100600 a\x00" + oid},
		{name: "a name that does not end", encoded: "100644 a"},
		{name: "an empty name", encoded: "100644 \x00" + oid},
		{name: "a slash", encoded: "100644 a/b\x00" + oid},
		{name: "a cut oid", encoded: "100644 a\x00" + oid[:19]},
		{name: "bytes after an entry", encoded: "100644 a\x00" + oid + "1"},
		{name: "entries out of order", encoded: "100644 b\x00" + oid + "100644 a\x00" + oid},
		{name: "a directory sorted as a file", encoded: "40000 a\x00" + oid + "100644 a.b\x00" + oid},
		{name: "a repeat", encoded: "100644 a\x00" + oid + "100644 a\x00" + oid},
		{name: "a repeat apart", encoded: "100644 a\x00" + oid + "100644 a.b\x00" + oid + "40000 a\x00" + oid},
	} {
		if _, err := EvsGitTreeDecode([]byte(c.encoded)); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsGitIdentRoundTrips(t *testing.T) {
	for _, value := range []string{
		"A U Thor <author@example.com> 1112911993 -0700",
		"agent <01J00000000000000000000000@ur.invalid> 1112912053 +0000",
		" <no-name@example.com> 0 +0000",
		"no email <> 1 -0000",
		"two  spaces  <a b@example.com> 9223372036854775807 +1400",
		"trailing space  <a@example.com> 2 +0000",
		" leading space <a@example.com> 2 +0000",
		"\xff\xfe <\xfd@example.com> 3 +0000",
	} {
		ident, err := EvsGitIdentDecode([]byte(value))
		if err != nil {
			t.Errorf("%q: %v", value, err)
			continue
		}
		encoded, err := ident.Encode()
		if err != nil {
			t.Errorf("%q: %v", value, err)
			continue
		}
		if string(encoded) != value {
			t.Errorf("%q came back %q", value, encoded)
		}
	}
}

func TestEvsGitIdentDecodeReadsItsFields(t *testing.T) {
	ident, err := EvsGitIdentDecode([]byte("A U Thor <author@example.com> 1112911993 -0700"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ident.Name) != "A U Thor" || string(ident.Email) != "author@example.com" ||
		ident.TimeSeconds != 1112911993 || ident.TimeZone != "-0700" {
		t.Errorf("%+v", ident)
	}
}

func TestEvsGitIdentDecodeRefuses(t *testing.T) {
	for _, value := range []string{
		"",
		"name",
		"<a@example.com> 1 +0000",
		"name<a@example.com> 1 +0000",
		"name <a@example.com>",
		"name <a@example.com> 1",
		"name <a@example.com> 1 0000",
		"name <a@example.com> 1 +000",
		"name <a@example.com> 1 +00000",
		"name <a@example.com> 1 +00a0",
		"name <a@example.com>  1 +0000",
		"name <a@example.com> 1  +0000",
		"name <a@example.com> 01 +0000",
		"name <a@example.com> +1 +0000",
		"name <a@example.com> -1 +0000",
		"name <a@example.com> 9223372036854775808 +0000",
		"name <a@example.com>1 +0000",
		"name <a@example.com",
		"na>me <a@example.com> 1 +0000",
		"na<me <a@example.com> 1 +0000",
		"name <a<b@example.com> 1 +0000",
		"name <a@example.com> <b@example.com> 1 +0000",
		"name <a@example.com> 1 +0000 <b@example.com>",
		"name <a\x00@example.com> 1 +0000",
		"na\nme <a@example.com> 1 +0000",
	} {
		if _, err := EvsGitIdentDecode([]byte(value)); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%q: %v", value, err)
		}
	}
}

func TestEvsGitIdentEncodeRefuses(t *testing.T) {
	for _, ident := range []*EvsGitIdent{
		{Name: []byte("a<b"), Email: []byte("c"), TimeZone: "+0000"},
		{Name: []byte("a"), Email: []byte("b>c"), TimeZone: "+0000"},
		{Name: []byte("a\n"), Email: []byte("c"), TimeZone: "+0000"},
		{Name: []byte("a"), Email: []byte("\x00"), TimeZone: "+0000"},
		{Name: []byte("a"), Email: []byte("b"), TimeSeconds: -1, TimeZone: "+0000"},
		{Name: []byte("a"), Email: []byte("b"), TimeZone: ""},
		{Name: []byte("a"), Email: []byte("b"), TimeZone: "0000"},
		{Name: []byte("a"), Email: []byte("b"), TimeZone: "+000a"},
		{Name: []byte("a"), Email: []byte("b"), TimeZone: "+00:00"},
	} {
		if _, err := ident.Encode(); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%+v: %v", ident, err)
		}
	}
}

const evsGitTestCommitOne = "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n" +
	"author A U Thor <author@example.com> 1112911993 -0700\n" +
	"committer agent <01J00000000000000000000000@ur.invalid> 1112912053 +0000\n" +
	"\n" +
	"first\n"

const evsGitTestCommitTwo = "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n" +
	"parent fe15d1340f7f283a87474f1114513d1b8d96b342\n" +
	"author A U Thor <author@example.com> 1112911993 -0700\n" +
	"committer agent <01J00000000000000000000000@ur.invalid> 1112912053 +0000\n" +
	"\n" +
	"second\n\nwith a body\n"

// Oids stock git's commit-tree gave these.
func TestEvsGitCommitVectors(t *testing.T) {
	treeOid := evsGitTestOid(t, "cf656b586d56636fa958e3f794e7c1d98ea15588")
	parentOid := evsGitTestOid(t, "fe15d1340f7f283a87474f1114513d1b8d96b342")
	author, err := (&EvsGitIdent{
		Name:        []byte("A U Thor"),
		Email:       []byte("author@example.com"),
		TimeSeconds: 1112911993,
		TimeZone:    "-0700",
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	committer, err := (&EvsGitIdent{
		Name:        []byte("agent"),
		Email:       []byte("01J00000000000000000000000@ur.invalid"),
		TimeSeconds: 1112912053,
		TimeZone:    "+0000",
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		commit  *EvsGitCommit
		encoded string
		oid     string
	}{
		{
			commit:  &EvsGitCommit{TreeOid: treeOid, Author: author, Committer: committer, Message: []byte("first\n")},
			encoded: evsGitTestCommitOne,
			oid:     "fe15d1340f7f283a87474f1114513d1b8d96b342",
		},
		{
			commit: &EvsGitCommit{
				TreeOid:    treeOid,
				ParentOids: []EvsGitOid{parentOid},
				Author:     author,
				Committer:  committer,
				Message:    []byte("second\n\nwith a body\n"),
			},
			encoded: evsGitTestCommitTwo,
			oid:     "a0915de08cfe98186df28ce4e974dceb2e5cdf7f",
		},
	} {
		encoded, err := c.commit.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != c.encoded {
			t.Errorf("%q", encoded)
		}
		oid, err := c.commit.Oid()
		if err != nil {
			t.Fatal(err)
		}
		if oid.String() != c.oid {
			t.Errorf("%s, want %s", oid, c.oid)
		}
	}
}

func TestEvsGitCommitDecodeReadsItsFields(t *testing.T) {
	commit, err := EvsGitCommitDecode([]byte(evsGitTestCommitTwo))
	if err != nil {
		t.Fatal(err)
	}
	if commit.TreeOid.String() != "cf656b586d56636fa958e3f794e7c1d98ea15588" {
		t.Error(commit.TreeOid)
	}
	if len(commit.ParentOids) != 1 || commit.ParentOids[0].String() != "fe15d1340f7f283a87474f1114513d1b8d96b342" {
		t.Errorf("%v", commit.ParentOids)
	}
	committer, err := EvsGitIdentDecode(commit.Committer)
	if err != nil {
		t.Fatal(err)
	}
	if string(committer.Email) != "01J00000000000000000000000@ur.invalid" {
		t.Errorf("%q", committer.Email)
	}
	if string(commit.Message) != "second\n\nwith a body\n" {
		t.Errorf("%q", commit.Message)
	}
}

func TestEvsGitCommitDecodeKeepsEveryByte(t *testing.T) {
	head := "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n" +
		"parent fe15d1340f7f283a87474f1114513d1b8d96b342\n" +
		"parent a0915de08cfe98186df28ce4e974dceb2e5cdf7f\n" +
		"author A <a@example.com> 1 +0000\n" +
		"committer B <b@example.com> 2 +0000\n"
	for _, c := range []struct {
		name string
		tail string
	}{
		{name: "an empty message", tail: "\n"},
		{name: "no final line break", tail: "\nsubject"},
		{name: "blank lines", tail: "\n\n\nsubject\n\n"},
		{name: "a NUL in the message", tail: "\nsub\x00ject\n"},
		{name: "bytes that are not text", tail: "\n\xff\xfe\n"},
		{name: "a header-like message", tail: "\ncommitter C <c@example.com> 3 +0000\n"},
		{name: "an encoding", tail: "encoding ISO-8859-1\n\nsubject\n"},
		{name: "a signature", tail: "gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nsubject\n"},
		{name: "a merged tag", tail: "mergetag object fe15d1340f7f283a87474f1114513d1b8d96b342\n type commit\n tag v1\n\nmerge\n"},
		{name: "a header unknown to git", tail: "x-something value\nx-bare\n\nsubject\n"},
		{name: "a signed committer line", tail: "gpgsig x\n committer C <c@example.com> 3 +0000\n\nsubject\n"},
	} {
		encoded := []byte(head + c.tail)
		commit, err := EvsGitCommitDecode(encoded)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		reencoded, err := commit.Encode()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("%s came back %q", c.name, reencoded)
		}
		oid, err := commit.Oid()
		if err != nil {
			t.Fatal(err)
		}
		if oid != evsGitObjectOid(evsGitCommitKind, encoded) {
			t.Errorf("%s: %s", c.name, oid)
		}
	}
}

// fsck refuses these idents, and a commit carrying one still replays: only the committer check
// decodes an ident, and an import's listed oids skip that.
func TestEvsGitCommitDecodeLeavesAnIdentAsRead(t *testing.T) {
	encoded := "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n" +
		"author nobody 1112911993\n" +
		"committer <a@example.com> 01 +00000\n" +
		"\n"
	commit, err := EvsGitCommitDecode([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if string(commit.Author) != "nobody 1112911993" {
		t.Errorf("%q", commit.Author)
	}
	if _, err := EvsGitIdentDecode(commit.Committer); !errors.Is(err, ErrEvsGitObjectInvalid) {
		t.Error(err)
	}
}

func TestEvsGitCommitDecodeOwnsItsFields(t *testing.T) {
	encoded := []byte(evsGitTestCommitOne)
	commit, err := EvsGitCommitDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	oid, err := commit.Oid()
	if err != nil {
		t.Fatal(err)
	}
	if oid.String() != "fe15d1340f7f283a87474f1114513d1b8d96b342" {
		t.Error(oid)
	}
}

func TestEvsGitCommitDecodeRefuses(t *testing.T) {
	tree := "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n"
	parent := "parent fe15d1340f7f283a87474f1114513d1b8d96b342\n"
	author := "author A <a@example.com> 1 +0000\n"
	committer := "committer B <b@example.com> 2 +0000\n"
	for _, c := range []struct {
		name    string
		encoded string
	}{
		{name: "nothing", encoded: ""},
		{name: "no tree", encoded: author + committer + "\n"},
		{name: "a short tree", encoded: "tree cf656b\n" + author + committer + "\n"},
		{name: "an uppercase tree", encoded: "tree CF656B586D56636FA958E3F794E7C1D98EA15588\n" + author + committer + "\n"},
		{name: "an uppercase parent", encoded: tree + "parent FE15D1340F7F283A87474F1114513D1B8D96B342\n" + author + committer + "\n"},
		{name: "a tree of a sha256 repository", encoded: "tree " + strings.Repeat("ab", 32) + "\n" + author + committer + "\n"},
		{name: "a bad parent", encoded: tree + "parent 123\n" + author + committer + "\n"},
		{name: "no author", encoded: tree + committer + "\n"},
		{name: "no committer", encoded: tree + author + "\n"},
		{name: "a committer first", encoded: tree + committer + author + "\n"},
		{name: "a parent after the author", encoded: tree + author + parent + committer + "\n"},
		{name: "no blank line", encoded: tree + author + committer},
		{name: "a line with no end", encoded: tree + author + "committer B <b@example.com> 2 +0000"},
		{name: "a second tree", encoded: tree + author + committer + tree + "\n"},
		{name: "a second parent late", encoded: tree + author + committer + parent + "\n"},
		{name: "a second author", encoded: tree + author + committer + author + "\n"},
		{name: "a second committer", encoded: tree + author + committer + committer + "\n"},
		{name: "a second committer after a header", encoded: tree + author + committer + "encoding x\n" + committer + "\n"},
		{name: "a bare committer", encoded: tree + author + committer + "committer\n\n"},
		{name: "a NUL in an ident", encoded: tree + "author A\x00 <a@example.com> 1 +0000\n" + committer + "\n"},
		{name: "a NUL in a header", encoded: tree + author + committer + "x-a b\x00c\n\n"},
		{name: "a continuation of nothing", encoded: tree + author + committer + " continued\n\n"},
		{name: "a header with no end", encoded: tree + author + committer + "x-a b"},
	} {
		if _, err := EvsGitCommitDecode([]byte(c.encoded)); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsGitCommitEncodeRefuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		commit *EvsGitCommit
	}{
		{name: "a line break in an ident", commit: &EvsGitCommit{Author: []byte("a\nb")}},
		{name: "a NUL in an ident", commit: &EvsGitCommit{Committer: []byte("a\x00b")}},
		{name: "extra headers with no end", commit: &EvsGitCommit{ExtraHeaders: []byte("a b")}},
		{name: "a blank line in extra headers", commit: &EvsGitCommit{ExtraHeaders: []byte("a b\n\nc d\n")}},
		{name: "a committer in extra headers", commit: &EvsGitCommit{ExtraHeaders: []byte("committer x\n")}},
		{name: "extra headers opening on a continuation", commit: &EvsGitCommit{ExtraHeaders: []byte(" a\n")}},
		{name: "a NUL in extra headers", commit: &EvsGitCommit{ExtraHeaders: []byte("a\x00\n")}},
	} {
		if _, err := c.commit.Encode(); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := c.commit.Oid(); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Assembles a delta by hand: its two sizes, then its instructions.
func evsGitTestDelta(baseSize int64, resultSize int64, instructions ...byte) []byte {
	return append(evsGitDeltaAppendSize(evsGitDeltaAppendSize(nil, baseSize), resultSize), instructions...)
}

func TestEvsGitDeltaApplyRunsInstructions(t *testing.T) {
	base := []byte("hello world")
	for _, c := range []struct {
		name   string
		delta  []byte
		result string
	}{
		{
			name:   "a copy from the start",
			delta:  evsGitTestDelta(11, 5, 0x90, 5),
			result: "hello",
		},
		{
			name:   "a copy with an offset",
			delta:  evsGitTestDelta(11, 5, 0x91, 6, 5),
			result: "world",
		},
		{
			name:   "an insert",
			delta:  evsGitTestDelta(11, 3, 3, 'a', 'b', 'c'),
			result: "abc",
		},
		{
			name:   "copies and inserts",
			delta:  evsGitTestDelta(11, 11, 0x91, 6, 5, 1, ' ', 0x90, 5),
			result: "world hello",
		},
		{
			name:   "a copy to the end of the base",
			delta:  evsGitTestDelta(11, 1, 0x91, 10, 1),
			result: "d",
		},
		{
			name:   "an empty result",
			delta:  evsGitTestDelta(11, 0),
			result: "",
		},
		{
			name:   "a size in more bytes than it needs",
			delta:  []byte{0x8b, 0x00, 0x01, 0x01, 'a'},
			result: "a",
		},
		{
			name:   "operands written as zero",
			delta:  evsGitTestDelta(11, 2, 0xb3, 0, 0, 2, 0),
			result: "he",
		},
	} {
		result, err := evsGitTestApply(base, c.delta)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(result) != c.result {
			t.Errorf("%s: %q", c.name, result)
		}
	}
}

// A copy's size of zero is 64 KiB, and its third size byte reaches past that.
func TestEvsGitDeltaApplyReadsEveryCopySize(t *testing.T) {
	base := make([]byte, 128*1024)
	for index := range base {
		base[index] = byte(index / 251)
	}
	for _, c := range []struct {
		name        string
		delta       []byte
		copiedStart int
		copiedSize  int
	}{
		{
			name:       "no size field",
			delta:      evsGitTestDelta(int64(len(base)), 64*1024, 0x80),
			copiedSize: 64 * 1024,
		},
		{
			name:        "an offset and no size field",
			delta:       evsGitTestDelta(int64(len(base)), 64*1024, 0x81, 7),
			copiedStart: 7,
			copiedSize:  64 * 1024,
		},
		{
			name:       "the third size byte",
			delta:      evsGitTestDelta(int64(len(base)), 65537, 0xd0, 1, 1),
			copiedSize: 65537,
		},
		{
			name:       "only the third size byte",
			delta:      evsGitTestDelta(int64(len(base)), 65536, 0xc0, 1),
			copiedSize: 65536,
		},
	} {
		result, err := evsGitTestApply(base, c.delta)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !bytes.Equal(result, base[c.copiedStart:c.copiedStart+c.copiedSize]) {
			t.Errorf("%s: wrong bytes", c.name)
		}
	}
}

func TestEvsGitDeltaApplyRefuses(t *testing.T) {
	base := []byte("hello world")
	for _, c := range []struct {
		name  string
		base  []byte
		delta []byte
	}{
		{name: "nothing", base: base, delta: nil},
		{name: "one size", base: base, delta: []byte{11}},
		{name: "a base size cut short", base: base, delta: []byte{0x80 | 11}},
		{name: "a result size cut short", base: base, delta: []byte{11, 0x80}},
		{name: "a base size past 63 bits", base: base, delta: bytes.Repeat([]byte{0x80}, 10)},
		{name: "a result size past 63 bits", base: base, delta: append([]byte{11}, bytes.Repeat([]byte{0xff}, 10)...)},
		{name: "a size in ten bytes that would fit in one", base: base, delta: []byte{0x8b, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 1, 1, 'a'}},
		{name: "a result size that would turn negative", base: base, delta: []byte{11, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}},
		{name: "a base size not the base's", base: base, delta: evsGitTestDelta(10, 1, 1, 'a')},
		{name: "a base size past the base", base: base, delta: evsGitTestDelta(12, 1, 1, 'a')},
		{name: "a base size on an empty base", base: nil, delta: evsGitTestDelta(1, 1, 1, 'a')},
		{name: "an empty base's copy", base: nil, delta: evsGitTestDelta(0, 1, 0x90, 1)},
		{name: "no instructions", base: base, delta: evsGitTestDelta(11, 1)},
		{name: "the reserved instruction", base: base, delta: evsGitTestDelta(11, 1, 0)},
		{name: "the reserved instruction after the result", base: base, delta: evsGitTestDelta(11, 1, 1, 'a', 0)},
		{name: "a copy past the base", base: base, delta: evsGitTestDelta(11, 5, 0x91, 7, 5)},
		{name: "a copy starting past the base", base: base, delta: evsGitTestDelta(11, 1, 0x91, 12, 1)},
		{name: "a copy at the base's end", base: base, delta: evsGitTestDelta(11, 1, 0x91, 11, 1)},
		{name: "a copy of the default size past the base", base: base, delta: evsGitTestDelta(11, 11, 0x80)},
		{name: "a copy at the top of the offset field", base: base, delta: evsGitTestDelta(11, 1, 0x9f, 0xff, 0xff, 0xff, 0xff, 1)},
		{name: "a copy of the largest size", base: base, delta: evsGitTestDelta(11, 1, 0xf0, 0xff, 0xff, 0xff)},
		{name: "a copy past the result", base: base, delta: evsGitTestDelta(11, 2, 0x90, 3)},
		{name: "an insert past the result", base: base, delta: evsGitTestDelta(11, 1, 2, 'a', 'b')},
		{name: "a copy cut short at its offset", base: base, delta: evsGitTestDelta(11, 1, 0x91)},
		{name: "a copy cut short at its size", base: base, delta: evsGitTestDelta(11, 1, 0x91, 1)},
		{name: "an insert cut short", base: base, delta: evsGitTestDelta(11, 3, 3, 'a')},
		{name: "an insert with no bytes", base: base, delta: evsGitTestDelta(11, 3, 3)},
		{name: "a result left short", base: base, delta: evsGitTestDelta(11, 2, 1, 'a')},
		{name: "bytes after the result", base: base, delta: evsGitTestDelta(11, 1, 1, 'a', 'b')},
		{name: "a copy after the result", base: base, delta: evsGitTestDelta(11, 1, 1, 'a', 0x90, 1)},
		{name: "bytes after an empty result", base: base, delta: evsGitTestDelta(11, 0, 1, 'a')},
	} {
		if _, err := evsGitTestApply(c.base, c.delta); !errors.Is(err, ErrEvsGitDeltaInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsGitDeltaApplyEmptyEnds(t *testing.T) {
	for _, c := range []struct {
		name   string
		base   string
		target string
	}{
		{name: "both empty", base: "", target: ""},
		{name: "an empty base", base: "", target: "hello"},
		{name: "an empty target", base: "hello", target: ""},
	} {
		delta := evsGitTestEncode(t, []byte(c.base), []byte(c.target), DefaultEvsGitDeltaSettings())
		result, err := evsGitTestApply([]byte(c.base), delta)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(result) != c.target {
			t.Errorf("%s: %q", c.name, result)
		}
	}
}

// A 7 B copy claims 16 MiB of result, so the claim itself is what the bound stops, before a byte.
func TestEvsGitDeltaApplyBoundsTheResultBeforeWriting(t *testing.T) {
	base := make([]byte, 32*1024*1024)
	delta := evsGitTestDelta(int64(len(base)), 16*1024*1024-1, 0xf0, 0xff, 0xff, 0xff)
	result := &bytes.Buffer{}
	_, err := EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(delta), 1024, result, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, ErrEvsGitDeltaTooLarge) {
		t.Fatal(err)
	}
	if result.Len() != 0 {
		t.Errorf("wrote %d B", result.Len())
	}
	// at the bound exactly, it runs
	size, err := EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(delta), 16*1024*1024-1, result, DefaultEvsGitDeltaSettings())
	if err != nil {
		t.Fatal(err)
	}
	if size != 16*1024*1024-1 || int64(result.Len()) != size {
		t.Errorf("%d and %d", size, result.Len())
	}
}

// A caller's bound is checked against the delta's claim, so the claim has to hold: a delta claiming
// little must not go on to write more, whatever its last instruction would have said.
func TestEvsGitDeltaApplyWritesNoMoreThanItClaimed(t *testing.T) {
	base := make([]byte, 1024*1024)
	baseSize := int64(len(base))
	for _, c := range []struct {
		name  string
		delta []byte
	}{
		{name: "a copy", delta: evsGitTestDelta(baseSize, 2, 0xf0, 0xff, 0xff, 0x0f)},
		{name: "a copy of the default size", delta: evsGitTestDelta(baseSize, 2, 0x80)},
		{name: "a copy after an insert", delta: evsGitTestDelta(baseSize, 2, 1, 'a', 0x80)},
		{name: "an insert", delta: evsGitTestDelta(baseSize, 2, 3, 'a', 'b', 'c')},
		{name: "an insert after a copy", delta: evsGitTestDelta(baseSize, 2, 0x90, 1, 2, 'a', 'b')},
	} {
		result := &bytes.Buffer{}
		_, err := EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(c.delta), 2, result, DefaultEvsGitDeltaSettings())
		if !errors.Is(err, ErrEvsGitDeltaInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
		if 2 < result.Len() {
			t.Errorf("%s: wrote %d B", c.name, result.Len())
		}
	}
}

func TestEvsGitDeltaApplyBoundsTheLargestClaim(t *testing.T) {
	delta := evsGitTestDelta(5, math.MaxInt64, 0x90, 5)
	result := &bytes.Buffer{}
	_, err := EvsGitDeltaApply(strings.NewReader("hello"), bytes.NewReader(delta), 1024*1024, result, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, ErrEvsGitDeltaTooLarge) {
		t.Fatal(err)
	}
}

// Gives its bytes, then fails with err.
type evsGitFailingReader struct {
	remaining []byte
	err       error
}

func (self *evsGitFailingReader) Read(buffer []byte) (int, error) {
	if len(self.remaining) == 0 {
		return 0, self.err
	}
	readSize := copy(buffer, self.remaining)
	self.remaining = self.remaining[readSize:]
	return readSize, nil
}

// A sealed stream's failure must not read as a bad delta, which would alarm as tampering by the writer.
func TestEvsGitDeltaApplyPassesOnAReadersError(t *testing.T) {
	sealedError := errors.New("a frame failed its tag")
	base := []byte("hello world")
	for _, delta := range [][]byte{
		nil,
		{11},
		{11, 0x80},
		evsGitTestDelta(11, 3),
		evsGitTestDelta(11, 3, 0x91),
		evsGitTestDelta(11, 3, 3, 'a'),
	} {
		reader := &evsGitFailingReader{remaining: delta, err: sealedError}
		_, err := EvsGitDeltaApply(bytes.NewReader(base), reader, 1024, &bytes.Buffer{}, DefaultEvsGitDeltaSettings())
		if !errors.Is(err, sealedError) {
			t.Errorf("%x: %v", delta, err)
		}
	}
}

// Refuses every write past its allowance.
type evsGitLimitWriter struct {
	remainingSize int
	err           error
}

func (self *evsGitLimitWriter) Write(content []byte) (int, error) {
	if self.remainingSize < len(content) {
		return 0, self.err
	}
	self.remainingSize -= len(content)
	return len(content), nil
}

func TestEvsGitDeltaApplyPassesOnAWritersError(t *testing.T) {
	writerError := errors.New("the spill is full")
	delta := evsGitTestDelta(11, 5, 0x90, 5)
	result := &evsGitLimitWriter{remainingSize: 2, err: writerError}
	_, err := EvsGitDeltaApply(strings.NewReader("hello world"), bytes.NewReader(delta), 1024, result, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, writerError) {
		t.Fatal(err)
	}
}

// A planner stops a delta outgrowing its file through the writer, as §11.7's checkpoint rule (3) wants.
func TestEvsGitDeltaEncodeStopsAtAWritersError(t *testing.T) {
	writerError := errors.New("the delta outgrew the file")
	random := rand.New(rand.NewPCG(1, 2))
	target := make([]byte, 1024*1024)
	for index := range target {
		target[index] = byte(random.Uint32())
	}
	delta := &evsGitLimitWriter{remainingSize: 64 * 1024, err: writerError}
	err := EvsGitDeltaEncode(strings.NewReader(""), bytes.NewReader(target), delta, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, writerError) {
		t.Fatal(err)
	}
}

// A source that says it holds more than it does.
type evsGitShortSource struct {
	*bytes.Reader
	claimedSize int64
}

func (self *evsGitShortSource) Size() int64 {
	return self.claimedSize
}

func TestEvsGitDeltaSourceStoppingShortIsNotABadDelta(t *testing.T) {
	short := &evsGitShortSource{Reader: bytes.NewReader([]byte("hello")), claimedSize: 11}
	_, err := EvsGitDeltaApply(short, bytes.NewReader(evsGitTestDelta(11, 11, 0x90, 11)), 1024, &bytes.Buffer{}, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrEvsGitDeltaInvalid) {
		t.Errorf("apply: %v", err)
	}
	long := bytes.Repeat([]byte("0123456789abcdef"), 64)
	shortBase := &evsGitShortSource{Reader: bytes.NewReader(long[:100]), claimedSize: int64(len(long))}
	if err := EvsGitDeltaEncode(shortBase, bytes.NewReader(long), &bytes.Buffer{}, DefaultEvsGitDeltaSettings()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a short base: %v", err)
	}
	shortTarget := &evsGitShortSource{Reader: bytes.NewReader(long[:100]), claimedSize: int64(len(long))}
	if err := EvsGitDeltaEncode(bytes.NewReader(long), shortTarget, &bytes.Buffer{}, DefaultEvsGitDeltaSettings()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a short target: %v", err)
	}
}

func TestEvsGitDeltaEncodeRefusesANegativeSize(t *testing.T) {
	negative := &evsGitShortSource{Reader: bytes.NewReader(nil), claimedSize: -1}
	if err := EvsGitDeltaEncode(negative, strings.NewReader(""), &bytes.Buffer{}, DefaultEvsGitDeltaSettings()); err == nil {
		t.Error("a negative base passed")
	}
	if err := EvsGitDeltaEncode(strings.NewReader(""), negative, &bytes.Buffer{}, DefaultEvsGitDeltaSettings()); err == nil {
		t.Error("a negative target passed")
	}
	_, err := EvsGitDeltaApply(negative, bytes.NewReader([]byte{0, 0}), 1024, &bytes.Buffer{}, DefaultEvsGitDeltaSettings())
	if !errors.Is(err, ErrEvsGitDeltaInvalid) {
		t.Errorf("apply: %v", err)
	}
}

func TestEvsGitDeltaSettingsRefused(t *testing.T) {
	changed := func(change func(settings *EvsGitDeltaSettings)) *EvsGitDeltaSettings {
		settings := DefaultEvsGitDeltaSettings()
		change(settings)
		return settings
	}
	for _, settings := range []*EvsGitDeltaSettings{
		nil,
		changed(func(settings *EvsGitDeltaSettings) { settings.IndexBlockCount = 0 }),
		changed(func(settings *EvsGitDeltaSettings) { settings.CandidateCount = -1 }),
		changed(func(settings *EvsGitDeltaSettings) { settings.GoodMatchByteCount = 0 }),
		changed(func(settings *EvsGitDeltaSettings) { settings.WindowByteCount = evsGitDeltaMinBufferSize - 1 }),
		changed(func(settings *EvsGitDeltaSettings) { settings.ChunkByteCount = evsGitDeltaMinBufferSize - 16 }),
		changed(func(settings *EvsGitDeltaSettings) { settings.ChunkByteCount = evsGitDeltaMinBufferSize + 1 }),
	} {
		err := EvsGitDeltaEncode(strings.NewReader(""), strings.NewReader(""), &bytes.Buffer{}, settings)
		if !errors.Is(err, errInvalidSettings) {
			t.Errorf("encode: %v", err)
		}
		_, err = EvsGitDeltaApply(strings.NewReader(""), bytes.NewReader([]byte{0, 0}), 1024, &bytes.Buffer{}, settings)
		if !errors.Is(err, errInvalidSettings) {
			t.Errorf("apply: %v", err)
		}
	}
}

// Target shapes a real edit makes, built from a base: a mutation may keep, drop, move or repeat runs.
func evsGitTestMutate(random *rand.Rand, base []byte) []byte {
	target := []byte{}
	for count := random.IntN(8); 0 <= count; count -= 1 {
		switch random.IntN(5) {
		case 0:
			// a run of the base from anywhere
			if 0 < len(base) {
				start := random.IntN(len(base))
				target = append(target, base[start:start+random.IntN(len(base)-start+1)]...)
			}
		case 1:
			// new bytes
			for size := random.IntN(600); 0 < size; size -= 1 {
				target = append(target, byte(random.Uint32()))
			}
		case 2:
			// a repeated byte
			target = append(target, bytes.Repeat([]byte{byte(random.IntN(3))}, random.IntN(2000))...)
		case 3:
			// the whole base with one byte changed
			target = append(target, base...)
			if 0 < len(base) {
				target[len(target)-1-random.IntN(len(base))] ^= 0x40
			}
		case 4:
			// a repeating pattern
			pattern := []byte("abcdefg")[:1+random.IntN(7)]
			target = append(target, bytes.Repeat(pattern, random.IntN(300))...)
		}
	}
	return target
}

// apply(a, encode(a, b)) == b, over shapes a real edit makes, on settings that reach every path.
func TestEvsGitDeltaRoundTripProperty(t *testing.T) {
	random := rand.New(rand.NewPCG(5, 6))
	defaultSettings := DefaultEvsGitDeltaSettings()
	sampling := evsGitTestSmallSettings()
	smallCopies := &EvsGitDeltaSettings{
		IndexBlockCount:    64,
		CandidateCount:     1,
		GoodMatchByteCount: 1,
		WindowByteCount:    300,
		ChunkByteCount:     272,
	}
	for round := 0; round < 1000; round += 1 {
		base := evsGitTestMutate(random, evsGitTestMutate(random, nil))
		target := evsGitTestMutate(random, base)
		for _, settings := range []*EvsGitDeltaSettings{defaultSettings, sampling, smallCopies} {
			delta := evsGitTestEncode(t, base, target, settings)
			result, err := evsGitTestApply(base, delta)
			if err != nil {
				t.Fatalf("round %d, %d into %d: %v", round, len(base), len(target), err)
			}
			if !bytes.Equal(result, target) {
				t.Fatalf("round %d, %d into %d: result differs", round, len(base), len(target))
			}
		}
	}
}

func TestEvsGitDeltaIsDeterministic(t *testing.T) {
	random := rand.New(rand.NewPCG(7, 8))
	base := evsGitTestMutate(random, evsGitTestMutate(random, nil))
	target := evsGitTestMutate(random, base)
	first := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	second := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	if !bytes.Equal(first, second) {
		t.Error("two encodes differ")
	}
}

func TestEvsGitDeltaOfOneChangedByteIsSmall(t *testing.T) {
	random := rand.New(rand.NewPCG(9, 10))
	base := make([]byte, 1024*1024)
	for index := range base {
		base[index] = byte(random.Uint32())
	}
	target := bytes.Clone(base)
	target[len(target)/2] ^= 1
	delta := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	// 16 copies of 64 KiB and a few bytes around the change
	if 256 < len(delta) {
		t.Errorf("%d B", len(delta))
	}
	result, err := evsGitTestApply(base, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, target) {
		t.Error("result differs")
	}
}

// A base past what the index covers block by block is sampled, and its copies still reach back to the
// start of each common run.
func TestEvsGitDeltaOfASampledBaseIsSmall(t *testing.T) {
	random := rand.New(rand.NewPCG(11, 12))
	base := make([]byte, 8*1024*1024)
	for index := range base {
		base[index] = byte(random.Uint32())
	}
	// a stretch cut out, one inserted and two halves swapped
	half := len(base) / 2
	target := slices.Concat(base[half:half+1024*1024], []byte("inserted"), base[:half-4096], base[half+1024*1024+4096:])
	delta := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	if 4096 < len(delta) {
		t.Errorf("%d B", len(delta))
	}
	result, err := evsGitTestApply(base, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, target) {
		t.Error("result differs")
	}
}

// A run of one byte keeps its first block alone, so a match can run the length of the file instead of
// hitting a late candidate's end.
func TestEvsGitDeltaOfARepeatedByteUsesLongCopies(t *testing.T) {
	base := make([]byte, 1024*1024)
	target := make([]byte, 1024*1024-1)
	delta := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	if 256 < len(delta) {
		t.Errorf("%d B", len(delta))
	}
}

// A run enters the index once, so a long one late in the base stays among the candidates that a short
// one earlier would otherwise use up.
func TestEvsGitDeltaOfARepeatedByteFindsItsLongestRun(t *testing.T) {
	random := rand.New(rand.NewPCG(15, 16))
	apart := make([]byte, 4096)
	for index := range apart {
		apart[index] = byte(random.Uint32())
	}
	base := slices.Concat(make([]byte, 1024), apart, make([]byte, 1024*1024))
	target := make([]byte, 1024*1024)
	delta := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	if 512 < len(delta) {
		t.Errorf("%d B", len(delta))
	}
}

// Git's own shortest forms: a field of zero stays out, and a copy of 64 KiB holds no size at all.
func TestEvsGitDeltaEncodeWritesTheShortestCopies(t *testing.T) {
	random := rand.New(rand.NewPCG(17, 18))
	base := make([]byte, 1024*1024)
	for index := range base {
		base[index] = byte(random.Uint32())
	}
	for _, c := range []struct {
		name        string
		target      []byte
		instruction []byte
	}{
		{name: "the longest copy from the start", target: base[:64*1024], instruction: []byte{0x80}},
		{name: "a copy with one size byte", target: base[:200], instruction: []byte{0x90, 200}},
		{name: "a copy with a low size byte of zero", target: base[:256], instruction: []byte{0xa0, 1}},
		{name: "an offset with one byte set", target: base[0x10000 : 0x10000+256], instruction: []byte{0xa4, 1, 1}},
		{name: "an offset with every byte it needs", target: base[0x012340 : 0x012340+200], instruction: []byte{0x97, 0x40, 0x23, 0x01, 200}},
	} {
		want := evsGitTestDelta(int64(len(base)), int64(len(c.target)), c.instruction...)
		if delta := evsGitTestEncode(t, base, c.target, DefaultEvsGitDeltaSettings()); !bytes.Equal(delta, want) {
			t.Errorf("%s: %x, want %x", c.name, delta, want)
		}
	}
}

func TestEvsGitDeltaOfEqualFilesIsCopies(t *testing.T) {
	base := bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstu"), 10000)
	delta := evsGitTestEncode(t, base, base, DefaultEvsGitDeltaSettings())
	if 128 < len(delta) {
		t.Errorf("%d B", len(delta))
	}
}

// Under the block size there is nothing to index, and nothing the target can match.
func TestEvsGitDeltaOfATinyBaseIsInserts(t *testing.T) {
	base := []byte("0123456789abcde")
	target := bytes.Repeat([]byte("0123456789abcde"), 20)
	delta := evsGitTestEncode(t, base, target, DefaultEvsGitDeltaSettings())
	if len(delta) < len(target) {
		t.Errorf("%d B", len(delta))
	}
	result, err := evsGitTestApply(base, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, target) {
		t.Error("result differs")
	}
}

// Generated bytes, a function of offset, so a source of any size costs nothing to hold. Bytes before
// otherUntil come from another seed, so two sources can share all but an opening stretch.
type evsGitGeneratedSource struct {
	seed       uint64
	size       int64
	otherUntil int64
	// the most asked for in one read
	maxReadSize int
}

func (self *evsGitGeneratedSource) Size() int64 {
	return self.size
}

func (self *evsGitGeneratedSource) ReadAt(buffer []byte, offset int64) (int, error) {
	self.maxReadSize = max(self.maxReadSize, len(buffer))
	for index := range buffer {
		position := offset + int64(index)
		if self.size <= position {
			return index, io.EOF
		}
		mixed := uint64(position/8) + self.seed
		if position < self.otherUntil {
			mixed += 0x1234567
		}
		mixed *= 0x9e3779b97f4a7c15
		mixed ^= mixed >> 29
		mixed *= 0xbf58476d1ce4e5b9
		mixed ^= mixed >> 32
		buffer[index] = byte(mixed >> (8 * uint(position%8)))
	}
	return len(buffer), nil
}

// A copy's offset field stops at 4 GiB, so a run that crosses that line copies up to it and inserts
// the rest. A small chunk keeps the sampled reads of this base short.
func TestEvsGitDeltaStopsAtWhatAnOffsetReaches(t *testing.T) {
	settings := DefaultEvsGitDeltaSettings()
	settings.ChunkByteCount = evsGitDeltaMinBufferSize
	reach := int64(evsGitDeltaMaxBaseReach)
	base := &evsGitGeneratedSource{seed: 1, size: reach + 4*1024*1024}
	target := make([]byte, 128*1024)
	if _, err := base.ReadAt(target, reach-int64(len(target))/2); err != nil {
		t.Fatal(err)
	}
	delta := &bytes.Buffer{}
	if err := EvsGitDeltaEncode(base, bytes.NewReader(target), delta, settings); err != nil {
		t.Fatal(err)
	}
	if delta.Len() < len(target)/2 || len(target)/2+len(target)/8 < delta.Len() {
		t.Errorf("%d B: the half before the line copies and the half after it inserts", delta.Len())
	}
	result := &bytes.Buffer{}
	if _, err := EvsGitDeltaApply(base, bytes.NewReader(delta.Bytes()), int64(len(target)), result, settings); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Bytes(), target) {
		t.Error("result differs")
	}
}

// Bytes allocated while run runs: every byte, freed or not, so the bound holds on any collector.
func evsGitTestAllocated(run func()) uint64 {
	before := runtime.MemStats{}
	runtime.ReadMemStats(&before)
	run()
	after := runtime.MemStats{}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// R-EVS-14 and §11.15: 8 MiB files, the largest a diff covers, pass through both directions and
// neither holds one. The result is hashed as it passes, so nothing holds it here either. The delta
// sits in memory as a test's own, grown beforehand so its growth is not counted.
func TestEvsGitDeltaWorkingSetStaysInItsSettings(t *testing.T) {
	settings := DefaultEvsGitDeltaSettings()
	fileSize := int64(8 * 1024 * 1024)
	base := &evsGitGeneratedSource{seed: 2, size: fileSize}
	target := &evsGitGeneratedSource{seed: 2, size: fileSize, otherUntil: 2 * 1024 * 1024}

	delta := &bytes.Buffer{}
	delta.Grow(3 * 1024 * 1024)
	allocated := evsGitTestAllocated(func() {
		if err := EvsGitDeltaEncode(base, target, delta, settings); err != nil {
			t.Fatal(err)
		}
	})
	// its settings come to 800 KiB, and the margin is for anything else this process allocates
	if 2*1024*1024 < allocated {
		t.Errorf("encoding allocated %d B", allocated)
	}
	if settings.ChunkByteCount < base.maxReadSize || settings.WindowByteCount < target.maxReadSize {
		t.Errorf("read %d B of the base and %d B of the target at once", base.maxReadSize, target.maxReadSize)
	}
	// the opening stretch inserts and the rest copies
	if delta.Len() < 2*1024*1024 || 2*1024*1024+64*1024 < delta.Len() {
		t.Errorf("a delta of %d B", delta.Len())
	}

	blobHash, err := newEvsGitBlobHash(fileSize)
	if err != nil {
		t.Fatal(err)
	}
	base.maxReadSize = 0
	allocated = evsGitTestAllocated(func() {
		if _, err := EvsGitDeltaApply(base, bytes.NewReader(delta.Bytes()), fileSize, blobHash, settings); err != nil {
			t.Fatal(err)
		}
	})
	if 1024*1024 < allocated {
		t.Errorf("applying allocated %d B", allocated)
	}
	if settings.ChunkByteCount < base.maxReadSize {
		t.Errorf("read %d B of the base at once", base.maxReadSize)
	}
	gotOid, err := blobHash.Oid()
	if err != nil {
		t.Fatal(err)
	}
	wantOid, err := EvsGitBlobOid(io.NewSectionReader(target, 0, fileSize), fileSize)
	if err != nil {
		t.Fatal(err)
	}
	if gotOid != wantOid {
		t.Errorf("%s, want %s", gotOid, wantOid)
	}
}

func TestEvsPktLineFormatsExamples(t *testing.T) {
	for _, c := range []struct {
		encoded string
		payload string
	}{
		{encoded: "0006a\n", payload: "a\n"},
		{encoded: "0005a", payload: "a"},
		{encoded: "000bfoobar\n", payload: "foobar\n"},
	} {
		encoded, err := EvsPktLine{Kind: EvsPktLineData, Payload: []byte(c.payload)}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != c.encoded {
			t.Errorf("%q", encoded)
		}
		line, err := NewEvsPktLineReader(strings.NewReader(c.encoded)).Next()
		if err != nil {
			t.Fatal(err)
		}
		if line.Kind != EvsPktLineData || string(line.Payload) != c.payload {
			t.Errorf("%+v", line)
		}
	}
}

func TestEvsPktLineSpecialPackets(t *testing.T) {
	for _, c := range []struct {
		encoded string
		kind    EvsPktLineKind
	}{
		{encoded: "0000", kind: EvsPktLineFlush},
		{encoded: "0001", kind: EvsPktLineDelim},
		{encoded: "0002", kind: EvsPktLineResponseEnd},
	} {
		encoded, err := EvsPktLine{Kind: c.kind}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != c.encoded {
			t.Errorf("%q", encoded)
		}
		line, err := NewEvsPktLineReader(strings.NewReader(c.encoded)).Next()
		if err != nil {
			t.Fatal(err)
		}
		if line.Kind != c.kind || len(line.Payload) != 0 {
			t.Errorf("%+v", line)
		}
	}
}

// 0004 is an empty line and 0000 is a flush, which the format says must not be confused.
func TestEvsPktLineReadsAnEmptyLineAsData(t *testing.T) {
	line, err := NewEvsPktLineReader(strings.NewReader("0004")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if line.Kind != EvsPktLineData || len(line.Payload) != 0 {
		t.Errorf("%+v", line)
	}
}

func TestEvsPktLineReadsUppercaseLengths(t *testing.T) {
	line, err := NewEvsPktLineReader(strings.NewReader("000Bfoobar\n")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(line.Payload) != "foobar\n" {
		t.Errorf("%q", line.Payload)
	}
}

func TestEvsPktLineLongestLineRoundTrips(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, EvsPktLineMaxPayloadSize)
	encoded, err := EvsPktLine{Kind: EvsPktLineData, Payload: payload}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte("fff0x")) || len(encoded) != 65520 {
		t.Errorf("%d B", len(encoded))
	}
	line, err := NewEvsPktLineReader(bytes.NewReader(encoded)).Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(line.Payload, payload) {
		t.Error("payload differs")
	}
}

func TestEvsPktLineEncodeRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		line EvsPktLine
	}{
		{name: "an empty payload", line: EvsPktLine{Kind: EvsPktLineData}},
		{name: "a payload past the limit", line: EvsPktLine{Kind: EvsPktLineData, Payload: make([]byte, EvsPktLineMaxPayloadSize+1)}},
		{name: "a flush with a payload", line: EvsPktLine{Kind: EvsPktLineFlush, Payload: []byte("a")}},
		{name: "a delim with a payload", line: EvsPktLine{Kind: EvsPktLineDelim, Payload: []byte("a")}},
		{name: "a response end with a payload", line: EvsPktLine{Kind: EvsPktLineResponseEnd, Payload: []byte("a")}},
		{name: "no known kind", line: EvsPktLine{Kind: EvsPktLineKind(7)}},
	} {
		if _, err := c.line.Encode(); !errors.Is(err, ErrEvsPktLineInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsPktLineReaderRefuses(t *testing.T) {
	for _, c := range []struct {
		name    string
		encoded string
	}{
		{name: "length 0003", encoded: "0003"},
		{name: "one past the limit", encoded: "fff1" + strings.Repeat("x", 65517)},
		{name: "the largest length", encoded: "ffff"},
		{name: "a length that is not hex", encoded: "00g6a\n"},
		{name: "a signed length", encoded: "+006a\n"},
		{name: "a spaced length", encoded: " 006a\n"},
		{name: "a cut length", encoded: "00"},
		{name: "a cut payload", encoded: "000bfoo"},
		{name: "a payload with nothing", encoded: "0005"},
	} {
		if _, err := NewEvsPktLineReader(strings.NewReader(c.encoded)).Next(); !errors.Is(err, ErrEvsPktLineInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEvsPktLineReaderEndsBetweenLines(t *testing.T) {
	reader := NewEvsPktLineReader(strings.NewReader("0005a"))
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Error(err)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Error(err)
	}
}

func TestEvsPktLineReaderPassesOnAReadersError(t *testing.T) {
	sealedError := errors.New("the socket broke")
	for _, stream := range []string{"", "00", "0009", "0009ab"} {
		reader := NewEvsPktLineReader(&evsGitFailingReader{remaining: []byte(stream), err: sealedError})
		if _, err := reader.Next(); !errors.Is(err, sealedError) {
			t.Errorf("%q: %v", stream, err)
		}
	}
}

// A caller hands the stream on after a flush, so nothing past it may be read ahead.
func TestEvsPktLineReaderReadsOnlyItsLines(t *testing.T) {
	stream := strings.NewReader("0006a\n0000PACK...")
	reader := NewEvsPktLineReader(stream)
	for range 2 {
		if _, err := reader.Next(); err != nil {
			t.Fatal(err)
		}
	}
	rest, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "PACK..." {
		t.Errorf("%q", rest)
	}
}

func TestEvsPktLineTextDropsOneLineFeed(t *testing.T) {
	for _, c := range []struct {
		payload string
		text    string
	}{
		{payload: "ok refs/heads/main\n", text: "ok refs/heads/main"},
		{payload: "ok refs/heads/main", text: "ok refs/heads/main"},
		{payload: "two\n\n", text: "two\n"},
		{payload: "\n", text: ""},
	} {
		line := EvsPktLine{Kind: EvsPktLineData, Payload: []byte(c.payload)}
		if string(line.Text()) != c.text {
			t.Errorf("%q: %q", c.payload, line.Text())
		}
	}
}

// The conversation githooks(5) gives proc-receive, read and answered through these framings.
func TestEvsPktLineCarriesAProcReceiveExchange(t *testing.T) {
	zeroOid := strings.Repeat("0", 40)
	newOid := strings.Repeat("1", 40)
	received := &bytes.Buffer{}
	for _, line := range []EvsPktLine{
		{Kind: EvsPktLineData, Payload: []byte("version=1\x00push-options atomic\n")},
		{Kind: EvsPktLineFlush},
		{Kind: EvsPktLineData, Payload: []byte(zeroOid + " " + newOid + " refs/heads/main\n")},
		{Kind: EvsPktLineFlush},
	} {
		encoded, err := line.Encode()
		if err != nil {
			t.Fatal(err)
		}
		received.Write(encoded)
	}
	reader := NewEvsPktLineReader(received)
	version, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(version.Text()) != "version=1\x00push-options atomic" {
		t.Errorf("%q", version.Payload)
	}
	if flush, err := reader.Next(); err != nil || flush.Kind != EvsPktLineFlush {
		t.Fatalf("%+v, %v", flush, err)
	}
	command, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if fields := strings.Fields(string(command.Text())); len(fields) != 3 || fields[2] != "refs/heads/main" {
		t.Errorf("%q", fields)
	}
	if flush, err := reader.Next(); err != nil || flush.Kind != EvsPktLineFlush {
		t.Fatalf("%+v, %v", flush, err)
	}
}

// Seeds of the pkt-line target: the seed files, and lines too long to keep as one.
func evsGitPktLineSeeds(t testing.TB) [][]byte {
	t.Helper()
	return append(evsGitFuzzSeedFiles(t, "testdata/fuzz/evs_git_pktline"),
		append([]byte("fff0"), make([]byte, EvsPktLineMaxPayloadSize)...))
}

// A reader's lines read out of a stream and encoded again give the stream back, except where the
// format offers a second spelling: an uppercase length, or the empty line no writer sends.
func checkEvsPktLineStream(t testing.TB, stream []byte) {
	t.Helper()
	reader := NewEvsPktLineReader(bytes.NewReader(stream))
	consumed := 0
	for {
		line, err := reader.Next()
		if err == io.EOF {
			if consumed != len(stream) {
				t.Fatalf("ended at %d of %d", consumed, len(stream))
			}
			return
		}
		if err != nil {
			if !errors.Is(err, ErrEvsPktLineInvalid) {
				t.Fatal(err)
			}
			return
		}
		read := stream[consumed : consumed+evsPktLineHeaderSize+len(line.Payload)]
		consumed += len(read)
		if line.Kind == EvsPktLineData && len(line.Payload) == 0 {
			continue
		}
		encoded, err := line.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.EqualFold(encoded[:evsPktLineHeaderSize], read[:evsPktLineHeaderSize]) ||
			!bytes.Equal(encoded[evsPktLineHeaderSize:], read[evsPktLineHeaderSize:]) {
			t.Fatalf("%q from %q", encoded, read)
		}
	}
}

// Seeds of the delta apply target: the seed files, and copies that need a base of over 64 KiB.
func evsGitDeltaApplySeeds(t testing.TB) [][]byte {
	t.Helper()
	return append(evsGitFuzzSeedFiles(t, "testdata/fuzz/evs_git_delta"),
		evsGitFuzzJoin(make([]byte, 64*1024), evsGitTestDelta(64*1024, 64*1024, 0x80)),
		evsGitFuzzJoin(make([]byte, 64*1024+1), evsGitTestDelta(64*1024+1, 64*1024+1, 0xd0, 1, 1)))
}

// Whatever apply is given it refuses or answers the size it wrote, under any shape of its reads, and
// never goes past its bound.
func checkEvsGitDeltaApply(t testing.TB, input []byte) {
	t.Helper()
	base, delta := evsGitFuzzSplit(input)
	maxResultSize := int64(1024 * 1024)
	result := &bytes.Buffer{}
	size, err := EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(delta), maxResultSize, result, DefaultEvsGitDeltaSettings())
	if err != nil {
		if !errors.Is(err, ErrEvsGitDeltaInvalid) && !errors.Is(err, ErrEvsGitDeltaTooLarge) {
			t.Fatal(err)
		}
	} else if size != int64(result.Len()) || maxResultSize < size {
		t.Fatalf("answered %d, wrote %d", size, result.Len())
	}
	// a reader that gives one byte at a time and the smallest chunks change nothing
	small := &bytes.Buffer{}
	smallSize, smallErr := EvsGitDeltaApply(bytes.NewReader(base), iotest.OneByteReader(bytes.NewReader(delta)), maxResultSize, small, evsGitTestSmallSettings())
	if (err == nil) != (smallErr == nil) || size != smallSize {
		t.Fatalf("%v and %v", err, smallErr)
	}
	if err == nil && !bytes.Equal(result.Bytes(), small.Bytes()) {
		t.Fatal("results differ")
	}
}

// Seeds of the delta round trip target: the seed files, read as a base and a target, and targets that
// share runs with their base.
func evsGitDeltaRoundTripSeeds(t testing.TB) [][]byte {
	t.Helper()
	repeated := bytes.Repeat([]byte("0123456789abcdef0123456789abcdeg"), 40)
	return append(evsGitFuzzSeedFiles(t, "testdata/fuzz/evs_git_delta"),
		evsGitFuzzJoin(repeated, repeated),
		evsGitFuzzJoin(repeated, repeated[7:len(repeated)-9]),
		evsGitFuzzJoin(repeated, append(bytes.Clone(repeated[100:]), repeated[:100]...)))
}

// apply(a, encode(a, b)) == b for any two inputs, under the default settings and ones that slide and
// sample.
func checkEvsGitDeltaRoundTrip(t testing.TB, input []byte) {
	t.Helper()
	base, target := evsGitFuzzSplit(input)
	for _, settings := range []*EvsGitDeltaSettings{DefaultEvsGitDeltaSettings(), evsGitTestSmallSettings()} {
		delta := evsGitTestEncode(t, base, target, settings)
		result, err := evsGitTestApply(base, delta)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result, target) {
			t.Fatal("result differs")
		}
	}
}

// Seeds of the tree target.
func evsGitTreeSeeds() [][]byte {
	oid := strings.Repeat("\x11", 20)
	return [][]byte{
		[]byte(""),
		[]byte("100644 a\x00" + oid + "40000 b\x00" + oid),
		[]byte("100644 a\x00" + oid + "100644 a.b\x00" + oid + "40000 a\x00" + oid),
		[]byte("040000 a\x00" + oid),
	}
}

// A tree that decodes encodes back to its bytes, and what it hashes to is theirs.
func checkEvsGitTreeDecode(t testing.TB, encoded []byte) {
	t.Helper()
	tree, err := EvsGitTreeDecode(encoded)
	if err != nil {
		if !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Fatal(err)
		}
		return
	}
	reencoded, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("%q from %q", reencoded, encoded)
	}
	oid, err := tree.Oid()
	if err != nil {
		t.Fatal(err)
	}
	if oid != evsGitObjectOid(evsGitTreeKind, encoded) {
		t.Fatal(oid)
	}
}

// Seeds of the commit target.
func evsGitCommitSeeds() [][]byte {
	return [][]byte{
		[]byte(evsGitTestCommitOne),
		[]byte(evsGitTestCommitTwo),
		[]byte(strings.Replace(evsGitTestCommitOne, "\n\n", "\ncommitter x\n\n", 1)),
		[]byte(strings.Replace(evsGitTestCommitOne, "\n\n", "\ngpgsig x\n y\nencoding z\n\n", 1)),
	}
}

// A commit that decodes encodes back to its bytes, and one that holds a reserved header anywhere but
// its place never decodes.
func checkEvsGitCommitDecode(t testing.TB, encoded []byte) {
	t.Helper()
	commit, err := EvsGitCommitDecode(encoded)
	if err != nil {
		if !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Fatal(err)
		}
		return
	}
	reencoded, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("%q from %q", reencoded, encoded)
	}
	headers, _, _ := bytes.Cut(encoded, []byte("\n\n"))
	lines := append([]byte{'\n'}, headers...)
	if !bytes.HasPrefix(headers, []byte("tree ")) || bytes.Count(lines, []byte("\ntree ")) != 1 ||
		bytes.Count(lines, []byte("\nauthor ")) != 1 || bytes.Count(lines, []byte("\ncommitter ")) != 1 {
		t.Fatalf("%q", headers)
	}
}

// Seeds of the ident target.
func evsGitIdentSeeds() [][]byte {
	return [][]byte{
		[]byte("A U Thor <author@example.com> 1112911993 -0700"),
		[]byte(" <> 0 +0000"),
		[]byte("a <b> <c> 1 +0000"),
	}
}

// An ident that decodes encodes back to its bytes, with exactly the two marks it was read by.
func checkEvsGitIdentDecode(t testing.TB, encoded []byte) {
	t.Helper()
	ident, err := EvsGitIdentDecode(encoded)
	if err != nil {
		if !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Fatal(err)
		}
		return
	}
	reencoded, err := ident.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("%q from %q", reencoded, encoded)
	}
	if bytes.Count(encoded, []byte{'<'}) != 1 || bytes.Count(encoded, []byte{'>'}) != 1 {
		t.Fatalf("%q", encoded)
	}
}

// §22.6's seeds on every leg. evs_git_fuzz_test.go runs them too, and fuzzes from them, but go test's
// fuzz targets read a corpus directory, which the sidecar_http leg's Worker does not have.
func TestEvsGitFuzzSeedsHold(t *testing.T) {
	for _, seed := range evsGitPktLineSeeds(t) {
		checkEvsPktLineStream(t, seed)
	}
	for _, seed := range evsGitDeltaApplySeeds(t) {
		checkEvsGitDeltaApply(t, seed)
	}
	for _, seed := range evsGitDeltaRoundTripSeeds(t) {
		checkEvsGitDeltaRoundTrip(t, seed)
	}
	for _, seed := range evsGitTreeSeeds() {
		checkEvsGitTreeDecode(t, seed)
	}
	for _, seed := range evsGitCommitSeeds() {
		checkEvsGitCommitDecode(t, seed)
	}
	for _, seed := range evsGitIdentSeeds() {
		checkEvsGitIdentDecode(t, seed)
	}
}

// Runs stock git in a bare sha1 repository of its own, with nothing of this host's configuration,
// feeding it input.
func evsGitTestStockGit(t *testing.T, directory string, input []byte, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + directory,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

// T1's oracle: the objects hashed by stock git, on hosts that have it. A byte-for-byte equal object is
// what lets export and a bare repository agree on every oid.
func TestEvsGitObjectsEqualStockGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
	directory := filepath.Join(t.TempDir(), "oracle.git")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	evsGitTestStockGit(t, directory, nil, "init", "--quiet", "--bare", "--object-format=sha1")
	random := rand.New(rand.NewPCG(13, 14))

	blobOids := []EvsGitOid{}
	for size := 0; size < 300; size += 37 {
		content := make([]byte, size*size)
		for index := range content {
			content[index] = byte(random.Uint32())
		}
		oid, err := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if stock := evsGitTestStockGit(t, directory, content, "hash-object", "-w", "--stdin"); stock != oid.String() {
			t.Errorf("a blob of %d B: stock git says %s, this says %s", size*size, stock, oid)
		}
		blobOids = append(blobOids, oid)
	}

	tree := &EvsGitTree{}
	mktree := &bytes.Buffer{}
	for index, c := range []struct {
		name string
		mode uint32
		kind string
	}{
		{name: "a", mode: EvsGitModeFile, kind: "blob"},
		{name: "a.txt", mode: EvsGitModeExecutable, kind: "blob"},
		{name: "a0", mode: EvsGitModeSymlink, kind: "blob"},
		{name: "b", mode: EvsGitModeDirectory, kind: "tree"},
		{name: "b.txt", mode: EvsGitModeFile, kind: "blob"},
		{name: "b0", mode: EvsGitModeFile, kind: "blob"},
		{name: "c", mode: EvsGitModeGitlink, kind: "commit"},
		{name: "c.txt", mode: EvsGitModeFile, kind: "blob"},
		{name: "caf\xc3\xa9", mode: EvsGitModeFile, kind: "blob"},
		{name: "cafe\xcc\x81", mode: EvsGitModeFile, kind: "blob"},
		{name: "with space", mode: EvsGitModeFile, kind: "blob"},
	} {
		oid := blobOids[index%len(blobOids)]
		switch c.kind {
		case "tree":
			oid = evsGitTestOid(t, "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
		case "commit":
			// absent from this repository, which mktree --missing takes on trust
			oid = evsGitTestOid(t, "fe15d1340f7f283a87474f1114513d1b8d96b342")
		}
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: c.mode, Name: []byte(c.name), Oid: oid})
		fmt.Fprintf(mktree, "%06o %s %s\t%s\x00", c.mode, c.kind, oid, c.name)
	}
	treeOid, err := tree.Oid()
	if err != nil {
		t.Fatal(err)
	}
	stockTree := evsGitTestStockGit(t, directory, mktree.Bytes(), "mktree", "-z", "--missing")
	if stockTree != treeOid.String() {
		t.Errorf("stock git's tree is %s, this says %s", stockTree, treeOid)
	}
	// hash-object also runs fsck's format checks over the bytes
	encodedTree, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if stock := evsGitTestStockGit(t, directory, encodedTree, "hash-object", "-t", "tree", "--stdin"); stock != treeOid.String() {
		t.Errorf("stock git hashes the tree to %s, this says %s", stock, treeOid)
	}

	message := []byte("subject\n\nbody with \xc3\xa9\n")
	for _, parentOids := range [][]EvsGitOid{
		nil,
		{evsGitTestOid(t, "fe15d1340f7f283a87474f1114513d1b8d96b342")},
		{
			evsGitTestOid(t, "fe15d1340f7f283a87474f1114513d1b8d96b342"),
			evsGitTestOid(t, "a0915de08cfe98186df28ce4e974dceb2e5cdf7f"),
		},
	} {
		author, err := (&EvsGitIdent{
			Name:        []byte("A U Thor"),
			Email:       []byte("author@example.com"),
			TimeSeconds: 1112911993,
			TimeZone:    "-0700",
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		committer, err := (&EvsGitIdent{
			Name:        []byte("agent"),
			Email:       []byte("01J00000000000000000000000@ur.invalid"),
			TimeSeconds: 1112912053,
			TimeZone:    "+0000",
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		commit := &EvsGitCommit{TreeOid: treeOid, ParentOids: parentOids, Author: author, Committer: committer, Message: message}
		encoded, err := commit.Encode()
		if err != nil {
			t.Fatal(err)
		}
		commitOid, err := commit.Oid()
		if err != nil {
			t.Fatal(err)
		}
		stockCommit := evsGitTestStockGit(t, directory, encoded, "hash-object", "-t", "commit", "--stdin")
		if stockCommit != commitOid.String() {
			t.Errorf("stock git's commit is %s, this says %s", stockCommit, commitOid)
		}
	}
}
