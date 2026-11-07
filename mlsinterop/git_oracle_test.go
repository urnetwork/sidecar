// §22.6's git row: pkt-line, pack and delta, and head mode's object codec, each held equal to go-git,
// with stock git's own packs and index-pack beside it on hosts that have git (D-EVS-3, §11.11).
//
// Equal has one meaning here: on an input both take, the two give the same bytes and fields, and on
// any input one refuses, either the other refuses too or the difference is one this file names. The
// root is stricter than go-git in a few places, each of them named below and held to that exact class,
// so a new difference fails. go-git's ident reader refuses nothing, so an ident compares on what both
// read. No evs code parses a pack stream: stock git does, behind the daemon. So §22.6's pack target is
// the pack delta, carried in real packs built here and by stock git.

package mlsinterop

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/urnetwork/sidecar"
)

// The root's seed directory for one of §22.6's targets.
func seedFiles(t testing.TB, directory string) [][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "fuzz", directory, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no seeds in %s", directory)
	}
	seeds := [][]byte{}
	for _, path := range paths {
		seed, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	return seeds
}

// A delta seed's two halves: a three-byte base length, high byte first, then that many bytes, or as
// many as there are, then the rest. The root's evs_git_test.go reads its seeds the same way.
func splitSeed(input []byte) ([]byte, []byte) {
	if len(input) < 3 {
		return nil, input
	}
	baseSize := int(input[0])*65536 + int(input[1])*256 + int(input[2])
	baseSize = min(baseSize, len(input)-3)
	return input[3 : 3+baseSize], input[3+baseSize:]
}

func toHash(oid sidecar.EvsGitOid) plumbing.Hash {
	return plumbing.Hash(oid)
}

func memoryObject(objectType plumbing.ObjectType, content []byte) *plumbing.MemoryObject {
	memory := &plumbing.MemoryObject{}
	memory.SetType(objectType)
	memory.Write(content)
	return memory
}

func objectBytes(t testing.TB, encoded plumbing.EncodedObject) []byte {
	t.Helper()
	reader, err := encoded.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestBlobOidsEqualGoGit(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 200; round += 1 {
		content := make([]byte, random.IntN(100000))
		for index := range content {
			content[index] = byte(random.Uint32())
		}
		oid, err := sidecar.EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if want := plumbing.ComputeHash(plumbing.BlobObject, content); toHash(oid) != want {
			t.Errorf("%d B: %s, go-git says %s", len(content), oid, want)
		}
	}
}

// Names drawn so that the bytes around a slash, the ones git's order turns on, come up constantly.
func randomName(random *rand.Rand) []byte {
	alphabet := []byte(".-0/a\xc3\xa9\xff ")
	name := make([]byte, 1+random.IntN(6))
	for index := range name {
		name[index] = alphabet[random.IntN(len(alphabet))]
		if name[index] == '/' {
			name[index] = '1'
		}
	}
	return name
}

func randomOid(random *rand.Rand) sidecar.EvsGitOid {
	oid := sidecar.EvsGitOid{}
	for index := range oid {
		oid[index] = byte(random.Uint32())
	}
	return oid
}

func TestTreesEqualGoGit(t *testing.T) {
	random := rand.New(rand.NewPCG(3, 4))
	modes := []uint32{
		sidecar.EvsGitModeDirectory,
		sidecar.EvsGitModeFile,
		sidecar.EvsGitModeExecutable,
		sidecar.EvsGitModeSymlink,
		sidecar.EvsGitModeGitlink,
	}
	for round := 0; round < 2000; round += 1 {
		tree := &sidecar.EvsGitTree{}
		theirs := &object.Tree{}
		names := map[string]bool{}
		for count := random.IntN(40); 0 < count; count -= 1 {
			name := randomName(random)
			if names[string(name)] {
				continue
			}
			names[string(name)] = true
			mode := modes[random.IntN(len(modes))]
			oid := randomOid(random)
			tree.Entries = append(tree.Entries, sidecar.EvsGitTreeEntry{Mode: mode, Name: name, Oid: oid})
			theirs.Entries = append(theirs.Entries, object.TreeEntry{Name: string(name), Mode: filemode.FileMode(mode), Hash: toHash(oid)})
		}
		sort.Sort(object.TreeEntrySorter(theirs.Entries))
		wanted := &plumbing.MemoryObject{}
		if err := theirs.Encode(wanted); err != nil {
			t.Fatal(err)
		}
		encoded, err := tree.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, objectBytes(t, wanted)) {
			t.Fatalf("round %d: %q, go-git says %q", round, encoded, objectBytes(t, wanted))
		}
		oid, err := tree.Oid()
		if err != nil {
			t.Fatal(err)
		}
		if toHash(oid) != wanted.Hash() {
			t.Fatalf("round %d: %s, go-git says %s", round, oid, wanted.Hash())
		}
		decoded, err := sidecar.EvsGitTreeDecode(encoded)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		checkTreeFields(t, decoded, memoryObject(plumbing.TreeObject, encoded))
	}
}

// go-git's reading of the same bytes, entry for entry. It maps the group-writable mode to the plain
// one, as git's own canon_mode does in memory, and this keeps it so a tree's oid survives.
func checkTreeFields(t testing.TB, tree *sidecar.EvsGitTree, encoded plumbing.EncodedObject) {
	t.Helper()
	theirs := &object.Tree{}
	if err := theirs.Decode(encoded); err != nil {
		t.Fatalf("go-git refuses a tree this decoded: %v", err)
	}
	if len(tree.Entries) != len(theirs.Entries) {
		t.Fatalf("%d entries, go-git reads %d", len(tree.Entries), len(theirs.Entries))
	}
	for index, entry := range tree.Entries {
		their := theirs.Entries[index]
		mode := entry.Mode
		if mode == sidecar.EvsGitModeFileGroupWritable {
			mode = sidecar.EvsGitModeFile
		}
		if string(entry.Name) != their.Name || mode != uint32(their.Mode) || toHash(entry.Oid) != their.Hash {
			t.Fatalf("entry %d: %q %o %s, go-git reads %q %o %s", index, entry.Name, entry.Mode, entry.Oid, their.Name, their.Mode, their.Hash)
		}
	}
}

func FuzzEvsGitTreeEqualsGoGit(f *testing.F) {
	oid := strings.Repeat("\x11", 20)
	f.Add([]byte(""))
	f.Add([]byte("100644 a\x00" + oid + "40000 b\x00" + oid))
	f.Add([]byte("100664 a\x00" + oid + "160000 b\x00" + oid))
	f.Add([]byte("100644 a\x00" + oid + "100644 a.b\x00" + oid + "40000 a\x00" + oid))
	f.Add([]byte("040000 a\x00" + oid))
	f.Add([]byte("100644 b\x00" + oid + "100644 a\x00" + oid))
	f.Add([]byte("100644 a/b\x00" + oid))
	f.Add([]byte("100644 a\x00" + oid + "100644 a\x00" + oid))
	f.Add([]byte("100600 a\x00" + oid))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		tree, err := sidecar.EvsGitTreeDecode(encoded)
		if err == nil {
			checkTreeFields(t, tree, memoryObject(plumbing.TreeObject, encoded))
			return
		}
		theirs := &object.Tree{}
		if theirs.Decode(memoryObject(plumbing.TreeObject, encoded)) != nil {
			return
		}
		// a tree go-git takes and this refuses, which must be one this file names: bytes re-encoding
		// would not give back, a name with a slash, or a name twice, whatever their modes
		names := map[string]bool{}
		for _, entry := range theirs.Entries {
			if strings.Contains(entry.Name, "/") || names[entry.Name] {
				return
			}
			names[entry.Name] = true
		}
		reencoded := &plumbing.MemoryObject{}
		if theirs.Encode(reencoded) != nil || !bytes.Equal(objectBytes(t, reencoded), encoded) {
			return
		}
		t.Fatalf("this refuses a tree go-git takes and could give back: %q: %v", encoded, err)
	})
}

func randomIdent(random *rand.Rand, seconds int64) (*sidecar.EvsGitIdent, object.Signature) {
	zones := []string{"+0000", "-0700", "+0530", "-1130", "+1400"}
	zone := zones[random.IntN(len(zones))]
	name := fmt.Sprintf("agent %d", random.IntN(1000))
	email := fmt.Sprintf("%d@ur.invalid", random.IntN(1000))
	when, err := time.Parse("-0700", zone)
	if err != nil {
		panic(err)
	}
	return &sidecar.EvsGitIdent{Name: []byte(name), Email: []byte(email), TimeSeconds: seconds, TimeZone: zone},
		object.Signature{Name: name, Email: email, When: time.Unix(seconds, 0).In(when.Location())}
}

func TestCommitsEqualGoGit(t *testing.T) {
	random := rand.New(rand.NewPCG(5, 6))
	for round := 0; round < 2000; round += 1 {
		author, theirAuthor := randomIdent(random, random.Int64N(4000000000))
		committer, theirCommitter := randomIdent(random, random.Int64N(4000000000))
		authorValue, err := author.Encode()
		if err != nil {
			t.Fatal(err)
		}
		committerValue, err := committer.Encode()
		if err != nil {
			t.Fatal(err)
		}
		treeOid := randomOid(random)
		commit := &sidecar.EvsGitCommit{
			TreeOid:   treeOid,
			Author:    authorValue,
			Committer: committerValue,
			Message:   fmt.Appendf(nil, "message %d\n\nbody\n", random.IntN(1000)),
		}
		theirs := &object.Commit{
			TreeHash:  toHash(treeOid),
			Author:    theirAuthor,
			Committer: theirCommitter,
			Message:   string(commit.Message),
		}
		for count := random.IntN(4); 0 < count; count -= 1 {
			parentOid := randomOid(random)
			commit.ParentOids = append(commit.ParentOids, parentOid)
			theirs.ParentHashes = append(theirs.ParentHashes, toHash(parentOid))
		}
		if round%3 == 0 {
			commit.ExtraHeaders = []byte("encoding ISO-8859-1\n")
			theirs.Encoding = "ISO-8859-1"
		}
		if round%5 == 0 {
			commit.ExtraHeaders = append(commit.ExtraHeaders, "gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n"...)
			theirs.PGPSignature = "-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n"
		}
		wanted := &plumbing.MemoryObject{}
		if err := theirs.Encode(wanted); err != nil {
			t.Fatal(err)
		}
		encoded, err := commit.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, objectBytes(t, wanted)) {
			t.Fatalf("round %d: %q, go-git says %q", round, encoded, objectBytes(t, wanted))
		}
		oid, err := commit.Oid()
		if err != nil {
			t.Fatal(err)
		}
		if toHash(oid) != wanted.Hash() {
			t.Fatalf("round %d: %s, go-git says %s", round, oid, wanted.Hash())
		}
		decoded, err := sidecar.EvsGitCommitDecode(encoded)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		checkCommitFields(t, decoded, memoryObject(plumbing.CommitObject, encoded))
	}
}

// go-git's reading of the same bytes, field for field. It trims a name, so that is what is compared.
func checkCommitFields(t testing.TB, commit *sidecar.EvsGitCommit, encoded plumbing.EncodedObject) {
	t.Helper()
	theirs := &object.Commit{}
	if err := theirs.Decode(encoded); err != nil {
		t.Fatalf("go-git refuses a commit this decoded: %v", err)
	}
	if toHash(commit.TreeOid) != theirs.TreeHash {
		t.Fatalf("tree %s, go-git reads %s", commit.TreeOid, theirs.TreeHash)
	}
	if len(commit.ParentOids) != len(theirs.ParentHashes) {
		t.Fatalf("%d parents, go-git reads %d", len(commit.ParentOids), len(theirs.ParentHashes))
	}
	for index, parentOid := range commit.ParentOids {
		if toHash(parentOid) != theirs.ParentHashes[index] {
			t.Fatalf("parent %d: %s, go-git reads %s", index, parentOid, theirs.ParentHashes[index])
		}
	}
	if string(commit.Message) != theirs.Message {
		t.Fatalf("message %q, go-git reads %q", commit.Message, theirs.Message)
	}
	for _, c := range []struct {
		value []byte
		their object.Signature
	}{
		{value: commit.Author, their: theirs.Author},
		{value: commit.Committer, their: theirs.Committer},
	} {
		ident, err := sidecar.EvsGitIdentDecode(c.value)
		if err != nil {
			continue
		}
		name := strings.Trim(string(ident.Name), " ")
		if name != c.their.Name || string(ident.Email) != c.their.Email || ident.TimeSeconds != c.their.When.Unix() {
			t.Fatalf("%q, go-git reads %+v", c.value, c.their)
		}
	}
}

func FuzzEvsGitCommitEqualsGoGit(f *testing.F) {
	head := "tree cf656b586d56636fa958e3f794e7c1d98ea15588\n" +
		"parent fe15d1340f7f283a87474f1114513d1b8d96b342\n"
	author := "author A U Thor <author@example.com> 1112911993 -0700\n"
	committer := "committer agent <0000@ur.invalid> 1112912053 +0000\n"
	f.Add([]byte(head + author + committer + "\nsubject\n\nbody\n"))
	f.Add([]byte(head + author + committer + "\n"))
	f.Add([]byte(head + author + committer + "encoding ISO-8859-1\n\nsubject\n"))
	f.Add([]byte(head + author + committer + "gpgsig a\n b\n c\n\nsubject\n"))
	f.Add([]byte(head + author + committer + "mergetag object 1\n type commit\n\nsubject\n"))
	f.Add([]byte(head + author + committer + "x-a b\nx-c\n\nsubject\n"))
	f.Add([]byte(head + author + committer + committer + "\nsubject\n"))
	f.Add([]byte(head + author + author + committer + "\nsubject\n"))
	f.Add([]byte(head + committer + author + "\nsubject\n"))
	f.Add([]byte(head + author + committer))
	f.Add([]byte(head + author + committer + "\x00\n\nsubject\n"))
	f.Add([]byte(head + author + committer + " continues nothing\n\nsubject\n"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		commit, err := sidecar.EvsGitCommitDecode(encoded)
		if err == nil {
			checkCommitFields(t, commit, memoryObject(plumbing.CommitObject, encoded))
			if oid, err := commit.Oid(); err != nil || toHash(oid) != plumbing.ComputeHash(plumbing.CommitObject, encoded) {
				t.Fatalf("%s, %v", oid, err)
			}
			return
		}
		theirs := &object.Commit{}
		if theirs.Decode(memoryObject(plumbing.CommitObject, encoded)) != nil {
			return
		}
		// a commit go-git takes and this refuses, which must be one this file names: bytes go-git's own
		// fields would not give back, which is every repeated, misplaced or missing header and a missing
		// blank line, or else a NUL in the headers, or a continuation right after the committer
		reencoded := &plumbing.MemoryObject{}
		if theirs.Encode(reencoded) != nil || !bytes.Equal(objectBytes(t, reencoded), encoded) {
			return
		}
		headers, _, _ := bytes.Cut(encoded, []byte("\n\n"))
		if bytes.IndexByte(headers, 0) != -1 {
			return
		}
		_, afterCommitter, _ := bytes.Cut(headers, []byte("\ncommitter "))
		if _, extraHeaders, _ := bytes.Cut(afterCommitter, []byte{'\n'}); bytes.HasPrefix(extraHeaders, []byte{' '}) {
			return
		}
		t.Fatalf("this refuses a commit go-git takes and could give back: %q: %v", encoded, err)
	})
}

// go-git's apply of a delta. ApplyDelta and not PatchDelta, whose empty-base guard its own apply does
// not share and stock git does not have.
func applyGoGit(t testing.TB, base []byte, delta []byte) ([]byte, error) {
	t.Helper()
	target := &plumbing.MemoryObject{}
	if err := packfile.ApplyDelta(target, memoryObject(plumbing.BlobObject, base), delta); err != nil {
		return nil, err
	}
	return objectBytes(t, target), nil
}

func apply(base []byte, delta []byte, maxResultSize int64) ([]byte, error) {
	result := &bytes.Buffer{}
	_, err := sidecar.EvsGitDeltaApply(bytes.NewReader(base), bytes.NewReader(delta), maxResultSize, result, sidecar.DefaultEvsGitDeltaSettings())
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func encode(t testing.TB, base []byte, target []byte) []byte {
	t.Helper()
	delta := &bytes.Buffer{}
	if err := sidecar.EvsGitDeltaEncode(bytes.NewReader(base), bytes.NewReader(target), delta, sidecar.DefaultEvsGitDeltaSettings()); err != nil {
		t.Fatal(err)
	}
	return delta.Bytes()
}

// Whether a delta's two sizes run off its end, the one input go-git takes and apply refuses: go-git
// reads the bytes it got as a whole size, and only an empty result can follow.
func sizesCutShort(delta []byte) bool {
	for count := 0; count < 2; count += 1 {
		for {
			if len(delta) == 0 {
				return true
			}
			sizeByte := delta[0]
			delta = delta[1:]
			if sizeByte&0x80 == 0 {
				break
			}
		}
	}
	return false
}

// The delta target: on any bytes, apply and go-git's agree on acceptance and result, but for sizes cut
// short, which stock git also reads as whole and apply refuses as a delta that was cut.
func checkApplyEqualsGoGit(t testing.TB, base []byte, delta []byte) {
	t.Helper()
	// a 7 B copy can claim 16 MiB, and the point here is what each does, not how fast
	maxResultSize := int64(64 * 1024 * 1024)
	result, err := apply(base, delta, maxResultSize)
	if errors.Is(err, sidecar.ErrEvsGitDeltaTooLarge) {
		return
	}
	if err != nil && !errors.Is(err, sidecar.ErrEvsGitDeltaInvalid) {
		t.Fatal(err)
	}
	theirs, theirErr := applyGoGit(t, base, delta)
	switch {
	case err != nil && theirErr != nil:
	case err == nil && theirErr == nil:
		if !bytes.Equal(result, theirs) {
			t.Fatalf("%x on %d B: results differ", delta, len(base))
		}
	case theirErr != nil:
		t.Fatalf("%x on %d B: go-git refuses what this applied: %v", delta, len(base), theirErr)
	case !sizesCutShort(delta):
		t.Fatalf("%x on %d B: this refuses what go-git applied: %v", delta, len(base), err)
	}
}

func FuzzEvsGitDeltaApplyEqualsGoGit(f *testing.F) {
	for _, seed := range seedFiles(f, "evs_git_delta") {
		f.Add(seed)
	}
	// a 64 KiB base, and a delta of two 64 KiB sizes and a copy cut at its one offset byte, which a zero
	// read for that byte would make a copy of the whole base
	f.Add(slices.Concat([]byte{1, 0, 0}, make([]byte, 64*1024), []byte{0x80, 0x80, 0x04, 0x80, 0x80, 0x04, 0x81}))
	f.Fuzz(func(t *testing.T, input []byte) {
		base, delta := splitSeed(input)
		checkApplyEqualsGoGit(t, base, delta)
	})
}

// A pack of two objects: base as a whole blob, and an OFS_DELTA holding delta against it. This is the
// form a delta has everywhere git keeps one (gitformat-pack).
func packOf(t testing.TB, base []byte, delta []byte) []byte {
	t.Helper()
	appendEntry := func(pack []byte, objectType int, size int) []byte {
		first := byte(objectType<<4) | byte(size&0x0f)
		size >>= 4
		for 0 < size {
			pack = append(pack, first|0x80)
			first = byte(size & 0x7f)
			size >>= 7
		}
		return append(pack, first)
	}
	appendDeflated := func(pack []byte, content []byte) []byte {
		deflated := &bytes.Buffer{}
		writer := zlib.NewWriter(deflated)
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return append(pack, deflated.Bytes()...)
	}
	pack := []byte("PACK")
	pack = binary.BigEndian.AppendUint32(pack, 2)
	pack = binary.BigEndian.AppendUint32(pack, 2)
	baseOffset := len(pack)
	pack = appendEntry(pack, 3, len(base))
	pack = appendDeflated(pack, base)
	deltaOffset := len(pack)
	pack = appendEntry(pack, 6, len(delta))
	// big-endian, each continuation byte adding one to what the bytes after it can reach
	distance := deltaOffset - baseOffset
	encodedDistance := []byte{byte(distance & 0x7f)}
	for distance >>= 7; distance != 0; distance >>= 7 {
		distance -= 1
		encodedDistance = append([]byte{0x80 | byte(distance&0x7f)}, encodedDistance...)
	}
	pack = append(pack, encodedDistance...)
	pack = appendDeflated(pack, delta)
	checksum := sha1.Sum(pack)
	return append(pack, checksum[:]...)
}

// Collects what go-git's parser resolved: each object's hash, by the offset it sits at.
type packObserver struct {
	hashes map[int64]plumbing.Hash
}

func (self *packObserver) OnHeader(count uint32) error {
	return nil
}

func (self *packObserver) OnInflatedObjectHeader(objectType plumbing.ObjectType, size int64, position int64) error {
	return nil
}

func (self *packObserver) OnInflatedObjectContent(hash plumbing.Hash, position int64, crc uint32, content []byte) error {
	self.hashes[position] = hash
	return nil
}

func (self *packObserver) OnFooter(hash plumbing.Hash) error {
	return nil
}

func parsePack(t testing.TB, pack []byte) *packObserver {
	t.Helper()
	observer := &packObserver{hashes: map[int64]plumbing.Hash{}}
	parser, err := packfile.NewParser(packfile.NewScanner(bytes.NewReader(pack)), observer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse(); err != nil {
		t.Fatalf("go-git refuses a pack: %v", err)
	}
	return observer
}

// The encoder's half of the delta target: what it writes means the same to go-git, by apply and inside
// a pack, and what go-git's encoder writes means the same to apply.
func checkEncodeEqualsGoGit(t testing.TB, base []byte, target []byte) {
	t.Helper()
	delta := encode(t, base, target)
	theirs, err := applyGoGit(t, base, delta)
	if err != nil {
		t.Fatalf("go-git refuses a delta of %d B into %d B: %v", len(base), len(target), err)
	}
	if !bytes.Equal(theirs, target) {
		t.Fatalf("go-git's result of a delta of %d B into %d B differs", len(base), len(target))
	}
	wantOid := plumbing.ComputeHash(plumbing.BlobObject, target)
	observer := parsePack(t, packOf(t, base, delta))
	if !slices.Contains(slices.Collect(maps.Values(observer.hashes)), wantOid) {
		t.Fatalf("go-git's pack holds no %s", wantOid)
	}
	theirDelta := packfile.DiffDelta(base, target)
	result, err := apply(base, theirDelta, int64(len(target)))
	if err != nil {
		t.Fatalf("a go-git delta of %d B into %d B refused: %v", len(base), len(target), err)
	}
	if !bytes.Equal(result, target) {
		t.Fatalf("a go-git delta of %d B into %d B differs", len(base), len(target))
	}
}

func FuzzEvsGitDeltaEncodeEqualsGoGit(f *testing.F) {
	for _, seed := range seedFiles(f, "evs_git_delta") {
		f.Add(seed)
	}
	repeated := bytes.Repeat([]byte("0123456789abcdef0123456789abcdeg"), 40)
	f.Add(append([]byte{0, byte(len(repeated) / 256), byte(len(repeated))}, append(repeated, repeated[7:]...)...))
	f.Fuzz(func(t *testing.T, input []byte) {
		base, target := splitSeed(input)
		checkEncodeEqualsGoGit(t, base, target)
	})
}

// Target shapes a real edit makes, built from a base.
func mutate(random *rand.Rand, base []byte) []byte {
	target := []byte{}
	for count := random.IntN(8); 0 <= count; count -= 1 {
		switch random.IntN(4) {
		case 0:
			if 0 < len(base) {
				start := random.IntN(len(base))
				target = append(target, base[start:start+random.IntN(len(base)-start+1)]...)
			}
		case 1:
			for size := random.IntN(2000); 0 < size; size -= 1 {
				target = append(target, byte(random.Uint32()))
			}
		case 2:
			target = append(target, bytes.Repeat([]byte{byte(random.IntN(3))}, random.IntN(70000))...)
		case 3:
			target = append(target, base...)
			if 0 < len(base) {
				target[len(target)-1-random.IntN(len(base))] ^= 0x40
			}
		}
	}
	return target
}

// Beyond what the seeds reach: files long enough for 64 KiB copies, offsets of three and four bytes, and
// a window that slides.
func TestEvsGitDeltasEqualGoGit(t *testing.T) {
	random := rand.New(rand.NewPCG(7, 8))
	for round := 0; round < 200; round += 1 {
		base := mutate(random, mutate(random, nil))
		target := mutate(random, base)
		checkEncodeEqualsGoGit(t, base, target)
		checkApplyEqualsGoGit(t, base, encode(t, base, target))
		checkApplyEqualsGoGit(t, base, packfile.DiffDelta(base, target))
	}
}

// One go-git reading of a stream against this one, line by line, up to the first place they part, which
// must be one this names. go-git's scanner refuses 0001, 0002 and 0004, reads an `ERR ` payload as an
// error, and takes a line up to 65,524 B where the format stops at 65,520.
func checkPktLinesEqualGoGit(t testing.TB, stream []byte) {
	t.Helper()
	reader := sidecar.NewEvsPktLineReader(bytes.NewReader(stream))
	theirs := pktline.NewScanner(bytes.NewReader(stream))
	offset := 0
	for {
		line, err := reader.Next()
		theyRead := theirs.Scan()
		theirErr := theirs.Err()
		switch {
		case err == io.EOF:
			if theyRead || theirErr != nil {
				t.Fatalf("at %d: the stream ended here, and go-git reads %v, %v", offset, theyRead, theirErr)
			}
			return
		case err != nil:
			if !errors.Is(err, sidecar.ErrEvsPktLineInvalid) {
				t.Fatal(err)
			}
			if !theyRead && theirErr != nil {
				return
			}
			// the one line go-git takes and this refuses, which is past the format's limit
			if theyRead && len(theirs.Bytes()) <= sidecar.EvsPktLineMaxPayloadSize {
				t.Fatalf("at %d: this refuses a line go-git reads: %v", offset, err)
			}
			if theyRead {
				return
			}
			t.Fatalf("at %d: this refuses a stream go-git ends cleanly: %v", offset, err)
		case line.Kind == sidecar.EvsPktLineFlush:
			if !theyRead || len(theirs.Bytes()) != 0 {
				t.Fatalf("at %d: a flush, and go-git reads %v, %q", offset, theyRead, theirs.Bytes())
			}
		case line.Kind == sidecar.EvsPktLineDelim, line.Kind == sidecar.EvsPktLineResponseEnd,
			line.Kind == sidecar.EvsPktLineData && len(line.Payload) == 0:
			if theyRead || !errors.Is(theirErr, pktline.ErrInvalidPktLen) {
				t.Fatalf("at %d: go-git v5 takes a line it should not: %v", offset, theirErr)
			}
			return
		case bytes.HasPrefix(line.Payload, []byte("ERR ")):
			errorLine := &pktline.ErrorLine{}
			if theyRead || !errors.As(theirErr, &errorLine) {
				t.Fatalf("at %d: an error line, and go-git reads %v, %v", offset, theyRead, theirErr)
			}
			return
		default:
			if !theyRead || !bytes.Equal(line.Payload, theirs.Bytes()) {
				t.Fatalf("at %d: %q, and go-git reads %v, %q", offset, line.Payload, theyRead, theirs.Bytes())
			}
		}
		offset += 4 + len(line.Payload)
	}
}

func FuzzEvsPktLineEqualsGoGit(f *testing.F) {
	for _, seed := range seedFiles(f, "evs_git_pktline") {
		f.Add(seed)
	}
	f.Add(append([]byte("fff0"), make([]byte, sidecar.EvsPktLineMaxPayloadSize)...))
	f.Add(append([]byte("fff1"), make([]byte, sidecar.EvsPktLineMaxPayloadSize+1)...))
	f.Add(append([]byte("fff4"), make([]byte, sidecar.EvsPktLineMaxPayloadSize+4)...))
	f.Add(append([]byte("fff5"), make([]byte, sidecar.EvsPktLineMaxPayloadSize+5)...))
	f.Fuzz(func(t *testing.T, stream []byte) {
		checkPktLinesEqualGoGit(t, stream)
	})
}

// A payload encodes to go-git's bytes, and past the format's limit both refuse. go-git's encoder writes
// a flush for an empty payload, which this refuses rather than turn a line into a message end.
func FuzzEvsPktLineEncodeEqualsGoGit(f *testing.F) {
	f.Add([]byte("a\n"))
	f.Add([]byte("version=1\x00push-options atomic\n"))
	f.Add(make([]byte, sidecar.EvsPktLineMaxPayloadSize))
	f.Add(make([]byte, sidecar.EvsPktLineMaxPayloadSize+1))
	f.Fuzz(func(t *testing.T, payload []byte) {
		encoded, err := sidecar.EvsPktLine{Kind: sidecar.EvsPktLineData, Payload: payload}.Encode()
		theirs := &bytes.Buffer{}
		theirErr := pktline.NewEncoder(theirs).Encode(payload)
		if len(payload) == 0 {
			if err == nil {
				t.Fatal("an empty payload encoded")
			}
			return
		}
		if (err == nil) != (theirErr == nil) {
			t.Fatalf("%v and %v", err, theirErr)
		}
		if err == nil && !bytes.Equal(encoded, theirs.Bytes()) {
			t.Fatalf("%q, go-git says %q", encoded, theirs.Bytes())
		}
	})
}

func TestPktLineFlushEqualsGoGit(t *testing.T) {
	encoded, err := sidecar.EvsPktLine{Kind: sidecar.EvsPktLineFlush}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	theirs := &bytes.Buffer{}
	if err := pktline.NewEncoder(theirs).Flush(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, theirs.Bytes()) {
		t.Errorf("%q, go-git says %q", encoded, theirs.Bytes())
	}
}

// Runs stock git in repository, with nothing of this host's configuration, feeding it input. The second
// answer is its exit, for a test that expects refusals.
func stockGit(t testing.TB, repository string, input []byte, args ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = repository
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + repository,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}
	command.Stdin = bytes.NewReader(input)
	stdout := &bytes.Buffer{}
	command.Stdout = stdout
	err := command.Run()
	if err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			t.Fatal(err)
		}
	}
	return stdout.Bytes(), err
}

// A fresh bare sha1 repository, or a skip on a host with no git.
func stockGitRepository(t testing.TB) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
	repository := t.TempDir()
	if _, err := stockGit(t, repository, nil, "init", "--quiet", "--bare", "--object-format=sha1"); err != nil {
		t.Fatal(err)
	}
	return repository
}

// Stock git's index-pack, with fsck on, takes the encoder's deltas and resolves them to the target's oid.
func TestEvsGitDeltasPassStockIndexPack(t *testing.T) {
	repository := stockGitRepository(t)
	random := rand.New(rand.NewPCG(9, 10))
	for round := 0; round < 40; round += 1 {
		base := mutate(random, mutate(random, nil))
		target := mutate(random, base)
		if len(base) == 0 || len(target) == 0 {
			continue
		}
		pack := packOf(t, base, encode(t, base, target))
		if _, err := stockGit(t, repository, pack, "index-pack", "--stdin", "--strict"); err != nil {
			t.Fatalf("round %d: index-pack refused: %v", round, err)
		}
		oid, err := sidecar.EvsGitBlobOid(bytes.NewReader(target), int64(len(target)))
		if err != nil {
			t.Fatal(err)
		}
		content, err := stockGit(t, repository, nil, "cat-file", "blob", oid.String())
		if err != nil {
			t.Fatalf("round %d: %s: %v", round, oid, err)
		}
		if !bytes.Equal(content, target) {
			t.Fatalf("round %d: stock git's blob differs", round)
		}
	}
}

// The seeds' verdicts against stock git's apply, reached through a pack. Stock git differs in the two
// ways the file header's rule allows: it refuses any delta under 4 B (DELTA_SIZE_MIN), which encoding
// an empty file writes, and from 4 B on it reads sizes cut short as whole, as go-git does.
func TestEvsGitDeltaSeedsEqualStockGit(t *testing.T) {
	repository := stockGitRepository(t)
	for index, seed := range seedFiles(t, "evs_git_delta") {
		base, delta := splitSeed(seed)
		result, err := apply(base, delta, 1024*1024)
		_, stockErr := stockGit(t, repository, packOf(t, base, delta), "index-pack", "--stdin")
		switch {
		case len(delta) < 4:
			if stockErr == nil {
				t.Errorf("seed %d, delta %x: stock git takes a delta under its minimum", index, delta)
			}
		case sizesCutShort(delta):
			if err == nil || stockErr != nil {
				t.Errorf("seed %d, delta %x: %v, stock git says %v", index, delta, err, stockErr)
			}
		case (err == nil) != (stockErr == nil):
			t.Errorf("seed %d, delta %x: %v, stock git says %v", index, delta, err, stockErr)
		case err == nil:
			oid, oidErr := sidecar.EvsGitBlobOid(bytes.NewReader(result), int64(len(result)))
			if oidErr != nil {
				t.Fatal(oidErr)
			}
			content, catErr := stockGit(t, repository, nil, "cat-file", "blob", oid.String())
			if catErr != nil || !bytes.Equal(content, result) {
				t.Errorf("seed %d: stock git's result differs: %v", index, catErr)
			}
		}
	}
}

// What stock git's pack-objects writes, read object by object with go-git's scanner, its deltas applied
// here: real deltas from the encoder this one stands in for, in both of the pack's delta forms, and
// each result equal to the hash go-git's parser gives that object and to one stock git filed.
func TestStockGitPackDeltasApply(t *testing.T) {
	repository := stockGitRepository(t)
	random := rand.New(rand.NewPCG(11, 12))
	version := make([]byte, 60000)
	for index := range version {
		version[index] = byte(random.Uint32() % 32)
	}
	oids := []string{}
	for count := 0; count < 30; count += 1 {
		// an edit: a run replaced, a run moved
		start := random.IntN(len(version) - 2000)
		for index := start; index < start+1000; index += 1 {
			version[index] = byte(random.Uint32() % 32)
		}
		version = slices.Concat(version[3000:], version[:3000])
		output, err := stockGit(t, repository, version, "hash-object", "-w", "--stdin")
		if err != nil {
			t.Fatal(err)
		}
		oids = append(oids, strings.TrimSpace(string(output)))
	}
	objects := []byte(strings.Join(oids, "\n") + "\n")
	for _, c := range []struct {
		args      []string
		deltaType plumbing.ObjectType
	}{
		{args: []string{"pack-objects", "--stdout", "--window=30", "--depth=20", "--delta-base-offset"}, deltaType: plumbing.OFSDeltaObject},
		{args: []string{"pack-objects", "--stdout", "--window=30", "--depth=20"}, deltaType: plumbing.REFDeltaObject},
	} {
		pack, err := stockGit(t, repository, objects, c.args...)
		if err != nil {
			t.Fatal(err)
		}
		contents, deltaCount := resolvePack(t, pack, c.deltaType)
		if deltaCount == 0 {
			t.Errorf("%v: no deltas to apply", c.args)
		}
		observer := parsePack(t, pack)
		for offset, content := range contents {
			oid, err := sidecar.EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
			if err != nil {
				t.Fatal(err)
			}
			if toHash(oid) != observer.hashes[offset] {
				t.Errorf("at %d: %s, go-git says %s", offset, oid, observer.hashes[offset])
			}
			if !slices.Contains(oids, oid.String()) {
				t.Errorf("at %d: %s is no object of this repository", offset, oid)
			}
		}
	}
}

// Every object of a pack by its offset, and how many of them were deltas of deltaType. A delta applies
// once its base is known, which for a ref delta can be an object later in the pack, so this sweeps
// until nothing is left.
func resolvePack(t testing.TB, pack []byte, deltaType plumbing.ObjectType) (map[int64][]byte, int) {
	t.Helper()
	type packObject struct {
		header  *packfile.ObjectHeader
		content []byte
	}
	scanner := packfile.NewScanner(bytes.NewReader(pack))
	_, objectCount, err := scanner.Header()
	if err != nil {
		t.Fatal(err)
	}
	objects := []*packObject{}
	for range objectCount {
		header, err := scanner.NextObjectHeader()
		if err != nil {
			t.Fatal(err)
		}
		content := &bytes.Buffer{}
		if _, _, err := scanner.NextObject(content); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, &packObject{header: header, content: content.Bytes()})
	}
	resolved := map[int64][]byte{}
	offsetsByHash := map[plumbing.Hash]int64{}
	deltaCount := 0
	for len(resolved) < len(objects) {
		progressed := false
		for _, packed := range objects {
			offset := packed.header.Offset
			if _, done := resolved[offset]; done {
				continue
			}
			content := packed.content
			if packed.header.Type.IsDelta() {
				baseOffset, known := packed.header.OffsetReference, true
				if packed.header.Type == plumbing.REFDeltaObject {
					baseOffset, known = offsetsByHash[packed.header.Reference]
				}
				base, baseDone := resolved[baseOffset]
				if !known || !baseDone {
					continue
				}
				if content, err = apply(base, packed.content, 1024*1024); err != nil {
					t.Fatalf("a stock git delta at %d refused: %v", offset, err)
				}
				if packed.header.Type == deltaType {
					deltaCount += 1
				}
			}
			resolved[offset] = content
			offsetsByHash[plumbing.ComputeHash(plumbing.BlobObject, content)] = offset
			progressed = true
		}
		if !progressed {
			t.Fatal("a delta's base is not in the pack")
		}
	}
	return resolved, deltaCount
}
