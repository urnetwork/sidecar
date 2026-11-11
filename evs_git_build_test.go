//go:build !js

// EVS1-M2-49's builder tests (DESIGN-DETAILS 8.6's builder row): 1,000 commits stock git made, by fast-import with
// merges, kind changes, symlinks and gitlinks, each rebuilt from its first parent's tree and its changes alone, with
// equal tree oids; a raw tree inherited across a commit that changes a sibling directory; a raw tree whose reading
// differs from the changes, refused; and the tree cache held to its bound over 100,000 commits.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// An object store in memory, both a source and a sink: what it is written it reads back at once.
type evsTestGitStore struct {
	objects map[EvsGitOid]*evsTestGitObject
}

type evsTestGitObject struct {
	kind    string
	content []byte
}

func newEvsTestGitStore() *evsTestGitStore {
	return &evsTestGitStore{objects: map[EvsGitOid]*evsTestGitObject{}}
}

func (self *evsTestGitStore) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	object := self.objects[oid]
	if object == nil {
		return "", nil, ErrEvsGitObjectMissing
	}
	return object.kind, object.content, nil
}

func (self *evsTestGitStore) WriteGitObject(kind string, content []byte) (EvsGitOid, error) {
	oid := evsGitObjectOid(kind, content)
	if self.objects[oid] == nil {
		self.objects[oid] = &evsTestGitObject{kind: kind, content: bytes.Clone(content)}
	}
	return oid, nil
}

func (self *evsTestGitStore) WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	encoded, err := io.ReadAll(content)
	if err != nil {
		return EvsGitOid{}, err
	}
	if int64(len(encoded)) != size {
		return EvsGitOid{}, fmt.Errorf("%w: a short object", ErrEvsGitObjectInvalid)
	}
	return self.WriteGitObject(kind, encoded)
}

func (self *evsTestGitStore) HasGitObject(oid EvsGitOid) bool {
	return self.objects[oid] != nil
}

func (self *evsTestGitStore) PendingGitObject(oid EvsGitOid) (string, []byte, bool) {
	return "", nil, false
}

func (self *evsTestGitStore) Flush(ctx context.Context) error {
	return nil
}

// Every object of a repository, read through git cat-file --batch-all-objects --batch.
func evsTestGitObjects(t *testing.T, dir string) *evsTestGitStore {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	command := exec.Command(gitPath, "-C", dir, "cat-file", "--batch-all-objects", "--batch")
	command.Env = []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
	out, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	store := newEvsTestGitStore()
	reader := bufio.NewReader(bytes.NewReader(out))
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(line)
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		content := make([]byte, size+1)
		if _, err := io.ReadFull(reader, content); err != nil {
			t.Fatal(err)
		}
		oid, _ := store.WriteGitObject(fields[1], content[:size])
		if fmt.Sprintf("%x", oid[:]) != fields[0] {
			t.Fatalf("object %s hashed to %x", fields[0], oid[:])
		}
	}
	return store
}

// A fast-import stream of commits commits on main, a side branch merged in every so often: each commit writes,
// removes, re-modes and replaces paths at random, so files turn into directories and back, with symlinks and
// gitlinks among them.
func evsTestFastImportStream(commits int, seed uint64) []byte {
	random := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	stream := &bytes.Buffer{}
	names := []string{"a", "b", "c.txt", "d", "e.md", "f"}
	pathOf := func() string {
		depth := 1 + random.IntN(3)
		parts := make([]string, depth)
		for i := range parts {
			parts[i] = names[random.IntN(len(names))]
		}
		return strings.Join(parts, "/")
	}
	mark := 0
	mainTip, sideTip := 0, 0
	for i := 0; i < commits; i += 1 {
		mark += 1
		branch, from := "refs/heads/main", mainTip
		merge := 0
		switch {
		case 0 < mainTip && random.IntN(9) == 0:
			// start or extend a side branch
			branch, from = "refs/heads/side", sideTip
			if from == 0 {
				from = mainTip
			}
		case 0 < sideTip && random.IntN(7) == 0:
			merge = sideTip
		}
		fmt.Fprintf(stream, "commit %s\nmark :%d\ncommitter c <c@example.invalid> %d +0000\ndata 3\nc%d\n", branch, mark, 1767225600+i, i%10)
		if 0 < from {
			fmt.Fprintf(stream, "from :%d\n", from)
		}
		if 0 < merge {
			fmt.Fprintf(stream, "merge :%d\n", merge)
		}
		for op := 0; op < 1+random.IntN(5); op += 1 {
			path := pathOf()
			switch kind := random.IntN(10); {
			case kind < 5:
				content := fmt.Sprintf("%d %d\n", i, random.IntN(1<<20))
				fmt.Fprintf(stream, "M 100644 inline %s\ndata %d\n%s\n", path, len(content), content)
			case kind == 5:
				content := fmt.Sprintf("#!/bin/sh\n# %d\n", random.IntN(4))
				fmt.Fprintf(stream, "M 100755 inline %s\ndata %d\n%s\n", path, len(content), content)
			case kind == 6:
				target := "../" + names[random.IntN(len(names))]
				fmt.Fprintf(stream, "M 120000 inline %s\ndata %d\n%s\n", path, len(target), target)
			case kind == 7:
				fmt.Fprintf(stream, "M 160000 %x %s\n", evsTestBytes(fmt.Sprint("link ", random.IntN(8)), 20), path)
			default:
				// a file or a whole directory gone
				fmt.Fprintf(stream, "D %s\n", strings.Join(strings.Split(path, "/")[:1+random.IntN(len(strings.Split(path, "/")))], "/"))
			}
		}
		stream.WriteString("\n")
		if branch == "refs/heads/side" {
			sideTip = mark
		} else {
			mainTip = mark
			if 0 < merge {
				sideTip = 0
			}
		}
	}
	return stream.Bytes()
}

// Stock git's commits, each rebuilt by the builder from its first parent's tree and its changes alone: the reader's
// store starts with the blobs and no tree, so every tree is the builder's, and each must be the tree its commit names.
// fast-import writes canonical trees, so no commit carries a raw tree.
func TestEvsGitTreeBuilderRebuildsStockGitsCommits(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	dir := filepath.Join(t.TempDir(), "oracle.git")
	environment := []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
	if out, err := exec.Command(gitPath, "init", "-q", "--bare", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	fastImport := exec.Command(gitPath, "-C", dir, "fast-import", "--quiet")
	fastImport.Env = environment
	fastImport.Stdin = bytes.NewReader(evsTestFastImportStream(1000, 49))
	if out, err := fastImport.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v: %s", err, out)
	}
	listing := exec.Command(gitPath, "-C", dir, "rev-list", "--topo-order", "--reverse", "--all")
	listing.Env = environment
	out, err := listing.Output()
	if err != nil {
		t.Fatal(err)
	}
	commitOids := strings.Fields(string(out))
	if len(commitOids) != 1000 {
		t.Fatalf("%d commits", len(commitOids))
	}
	gitObjects := evsTestGitObjects(t, dir)
	reader := newEvsTestGitStore()
	for oid, object := range gitObjects.objects {
		if object.kind == evsGitBlobKind {
			reader.objects[oid] = object
		}
	}
	builder := NewEvsGitTreeBuilder(reader, reader, 1<<20)
	ctx := context.Background()
	merges, kindChanges, gitlinks, symlinks := 0, 0, 0, 0
	for _, text := range commitOids {
		oid := evsTestOid(t, text)
		_, object, err := gitObjects.ReadGitObject(ctx, oid)
		if err != nil {
			t.Fatal(err)
		}
		treeOid, parentOids, err := EvsGitCommitGraph(object)
		if err != nil {
			t.Fatal(err)
		}
		var parentTree *EvsGitOid
		if 0 < len(parentOids) {
			_, parentObject, err := gitObjects.ReadGitObject(ctx, parentOids[0])
			if err != nil {
				t.Fatal(err)
			}
			parentTreeOid, _, err := EvsGitCommitGraph(parentObject)
			if err != nil {
				t.Fatal(err)
			}
			parentTree = &parentTreeOid
		}
		if 1 < len(parentOids) {
			merges += 1
		}
		changes, raw, err := EvsGitCommitChanges(ctx, gitObjects, parentTree, treeOid)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 0 {
			t.Fatalf("commit %s carries %d raw trees", text, len(raw))
		}
		paths := map[string]bool{}
		for _, change := range changes {
			paths[string(bytes.Join(change.GetPath(), []byte{'/'}))] = true
			switch change.GetMode() {
			case EvsGitModeGitlink:
				gitlinks += 1
			case EvsGitModeSymlink:
				symlinks += 1
			}
		}
		// a kind change: a change at a path and another below it
		for path := range paths {
			for other := range paths {
				if strings.HasPrefix(other, path+"/") {
					kindChanges += 1
					break
				}
			}
		}
		built, err := builder.Build(ctx, parentTree, changes, raw)
		if err != nil {
			t.Fatalf("commit %s: %v", text, err)
		}
		if built != treeOid {
			t.Fatalf("commit %s: built %x, git's %x", text, built[:], treeOid[:])
		}
	}
	if merges == 0 || kindChanges == 0 || gitlinks == 0 || symlinks == 0 {
		t.Errorf("the history lacks a case: %d merges, %d kind changes, %d gitlinks, %d symlinks", merges, kindChanges, gitlinks, symlinks)
	}
}

// A history with a raw tree: the first commit brings a directory whose tree has a zero-padded mode and a file of mode
// 100600, which no encoding rebuilds, so the commit carries it; the second changes a sibling directory, and the raw
// tree is inherited unchanged, its oid kept. A raw tree whose reading is not what the changes build is refused, and
// so is one at a path that ends empty.
func TestEvsGitTreeBuilderTakesARawTreeOnlyWhereItsReadingIsBuilt(t *testing.T) {
	ctx := context.Background()
	writer := newEvsTestGitStore()
	blob := func(content string) EvsGitOid {
		oid, _ := writer.WriteGitObject(evsGitBlobKind, []byte(content))
		return oid
	}
	rawEntry := func(mode string, name string, oid EvsGitOid) []byte {
		return append([]byte(mode+" "+name+"\x00"), oid[:]...)
	}
	canonicalTree := func(entries ...EvsGitTreeEntry) EvsGitOid {
		encoded, err := (&EvsGitTree{Entries: entries}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		oid, _ := writer.WriteGitObject(evsGitTreeKind, encoded)
		return oid
	}
	deep := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte("z"), Oid: blob("z\n")})
	subBytes := append(append(rawEntry("100600", "a", blob("a\n")), rawEntry("100644", "b", blob("b\n"))...), rawEntry("040000", "deep", deep)...)
	sub, _ := writer.WriteGitObject(evsGitTreeKind, subBytes)
	other1 := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte("x"), Oid: blob("x1\n")})
	other2 := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte("x"), Oid: blob("x2\n")})
	root1 := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("sub"), Oid: sub}, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("other"), Oid: other1})
	root2 := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("sub"), Oid: sub}, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("other"), Oid: other2})

	reader := newEvsTestGitStore()
	for oid, object := range writer.objects {
		if object.kind == evsGitBlobKind {
			reader.objects[oid] = object
		}
	}
	builder := NewEvsGitTreeBuilder(reader, reader, 1<<20)
	changes1, raw1, err := EvsGitCommitChanges(ctx, writer, nil, root1)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw1) != 1 || string(bytes.Join(raw1[0].GetPath(), []byte{'/'})) != "sub" || !bytes.Equal(raw1[0].GetObject(), subBytes) {
		t.Fatalf("raw trees %v", raw1)
	}
	built1, err := builder.Build(ctx, nil, changes1, raw1)
	if err != nil || built1 != root1 {
		t.Fatalf("the first commit: %x %v", built1[:], err)
	}
	// the sibling changes; the raw tree is inherited, carried by no change and no raw tree of the second commit
	changes2, raw2, err := EvsGitCommitChanges(ctx, writer, &root1, root2)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes2) != 1 || len(raw2) != 0 {
		t.Fatalf("the second commit: %v %v", changes2, raw2)
	}
	built2, err := builder.Build(ctx, &root1, changes2, raw2)
	if err != nil || built2 != root2 {
		t.Fatalf("the second commit: %x %v", built2[:], err)
	}
	// a third commit changes a file inside the raw directory: written by git from its index, the directory is
	// canonical again and rebuilds from changes alone; written by a tool that keeps its modes, it is raw and carried
	canonicalSub := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte("a"), Oid: blob("a\n")},
		EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte("b"), Oid: blob("b2\n")}, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("deep"), Oid: deep})
	keptBytes := append(append(rawEntry("100600", "a", blob("a\n")), rawEntry("100644", "b", blob("b2\n"))...), rawEntry("040000", "deep", deep)...)
	keptSub, _ := writer.WriteGitObject(evsGitTreeKind, keptBytes)
	for label, nextSub := range map[string]EvsGitOid{"canonical again": canonicalSub, "kept raw": keptSub} {
		root3 := canonicalTree(EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("sub"), Oid: nextSub}, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte("other"), Oid: other2})
		changes3, raw3, err := EvsGitCommitChanges(ctx, writer, &root2, root3)
		if err != nil {
			t.Fatal(err)
		}
		if (len(raw3) == 1) != (nextSub == keptSub) {
			t.Fatalf("%s: raw trees %v", label, raw3)
		}
		built3, err := builder.Build(ctx, &root2, changes3, raw3)
		if err != nil || built3 != root3 {
			t.Fatalf("%s: %x %v", label, built3[:], err)
		}
	}

	// the raw tree's reading must be what the changes build: a change dropped, or the raw bytes naming another blob
	for label, mutate := range map[string]func(changes []*protocol.EvsSealedChange, raw []*protocol.EvsSealedTree) ([]*protocol.EvsSealedChange, []*protocol.EvsSealedTree){
		"a change dropped": func(changes []*protocol.EvsSealedChange, raw []*protocol.EvsSealedTree) ([]*protocol.EvsSealedChange, []*protocol.EvsSealedTree) {
			kept := []*protocol.EvsSealedChange{}
			for _, change := range changes {
				if string(bytes.Join(change.GetPath(), []byte{'/'})) != "sub/b" {
					kept = append(kept, change)
				}
			}
			return kept, raw
		},
		"another blob": func(changes []*protocol.EvsSealedChange, raw []*protocol.EvsSealedTree) ([]*protocol.EvsSealedChange, []*protocol.EvsSealedTree) {
			other := bytes.Clone(subBytes)
			other[len(other)-1] ^= 1
			return changes, []*protocol.EvsSealedTree{{Path: raw[0].GetPath(), Object: other}}
		},
		"a path that ends empty": func(changes []*protocol.EvsSealedChange, raw []*protocol.EvsSealedTree) ([]*protocol.EvsSealedChange, []*protocol.EvsSealedTree) {
			return changes, append(raw, &protocol.EvsSealedTree{Path: [][]byte{[]byte("gone")}, Object: subBytes})
		},
	} {
		changes, raw := mutate(changes1, raw1)
		store := newEvsTestGitStore()
		for oid, object := range writer.objects {
			if object.kind == evsGitBlobKind {
				store.objects[oid] = object
			}
		}
		if _, err := NewEvsGitTreeBuilder(store, store, 1<<20).Build(ctx, nil, changes, raw); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// The builder refuses changes a tree cannot take: a removal of a file the tree does not hold, a removal of a
// directory, a change of a mode git does not write, one path changed twice, and a file over a directory whose files
// stay.
func TestEvsGitTreeBuilderRefusesChangesATreeCannotTake(t *testing.T) {
	ctx := context.Background()
	store := newEvsTestGitStore()
	blob, _ := store.WriteGitObject(evsGitBlobKind, []byte("a\n"))
	sub, _ := (&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("f"), Oid: blob}}}).Encode()
	subOid, _ := store.WriteGitObject(evsGitTreeKind, sub)
	root, _ := (&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: EvsGitModeDirectory, Name: []byte("d"), Oid: subOid}}}).Encode()
	rootOid, _ := store.WriteGitObject(evsGitTreeKind, root)
	write := func(path string, mode uint32) *protocol.EvsSealedChange {
		return &protocol.EvsSealedChange{Path: bytes.Split([]byte(path), []byte{'/'}), Mode: mode, GitOid: blob[:]}
	}
	remove := func(path string) *protocol.EvsSealedChange {
		return &protocol.EvsSealedChange{Path: bytes.Split([]byte(path), []byte{'/'})}
	}
	for label, changes := range map[string][]*protocol.EvsSealedChange{
		"a removal of an absent file": {remove("x")},
		"a removal of a directory":    {remove("d")},
		"a mode git does not write":   {write("x", 0o100600)},
		"a directory as a change":     {write("x", EvsGitModeDirectory)},
		"one path twice":              {write("x", EvsGitModeFile), write("x", EvsGitModeExecutable)},
		"a file over a directory":     {write("d", EvsGitModeFile)},
		"a file and a directory":      {write("d", EvsGitModeFile), write("d/g", EvsGitModeFile)},
	} {
		if _, err := NewEvsGitTreeBuilder(store, store, 1<<20).Build(ctx, &rootOid, changes, nil); !errors.Is(err, ErrEvsGitObjectInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	// the file over the directory whose files go is a kind change, taken
	built, err := NewEvsGitTreeBuilder(store, store, 1<<20).Build(ctx, &rootOid, []*protocol.EvsSealedChange{write("d", EvsGitModeFile), remove("d/f")}, nil)
	want, _ := (&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("d"), Oid: blob}}}).Oid()
	if err != nil || built != want {
		t.Errorf("a kind change: %x %v", built[:], err)
	}
}

// Over 100,000 commits of a 16 by 16 tree, each changing one file, the builder's cache never holds more than its
// bound, which is too small for every tree, and the reader's store only the tip's trees, so memory is flat; the last
// tree is the tree the files make.
func TestEvsGitTreeBuilderMemoryIsFlatOver100000Commits(t *testing.T) {
	if testing.Short() {
		t.Skip("100,000 commits")
	}
	ctx := context.Background()
	const width = 16
	const cacheByteCount = 8 * 1024
	random := rand.New(rand.NewPCG(49, 100000))
	files := make([][]EvsGitOid, width)
	store := newEvsTestGitStore()
	directoryOids := make([]EvsGitOid, width)
	rootEntries := []EvsGitTreeEntry{}
	for d := range files {
		files[d] = make([]EvsGitOid, width)
		entries := []EvsGitTreeEntry{}
		for f := range files[d] {
			files[d][f] = EvsGitOid(evsTestBytes(fmt.Sprint("blob ", d, " ", f, " 0"), 20))
			entries = append(entries, EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte(fmt.Sprintf("f%02d", f)), Oid: files[d][f]})
		}
		encoded, _ := (&EvsGitTree{Entries: entries}).Encode()
		directoryOids[d], _ = store.WriteGitObject(evsGitTreeKind, encoded)
		rootEntries = append(rootEntries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(fmt.Sprintf("d%02d", d)), Oid: directoryOids[d]})
	}
	rootBytes, _ := (&EvsGitTree{Entries: rootEntries}).Encode()
	tip, _ := store.WriteGitObject(evsGitTreeKind, rootBytes)
	builder := NewEvsGitTreeBuilder(store, store, cacheByteCount)
	for commit := 1; commit <= 100000; commit += 1 {
		d, f := random.IntN(width), random.IntN(width)
		files[d][f] = EvsGitOid(evsTestBytes(fmt.Sprint("blob ", d, " ", f, " ", commit), 20))
		change := &protocol.EvsSealedChange{
			Path: [][]byte{[]byte(fmt.Sprintf("d%02d", d)), []byte(fmt.Sprintf("f%02d", f))}, Mode: EvsGitModeFile, GitOid: bytes.Clone(files[d][f][:]),
		}
		built, err := builder.Build(ctx, &tip, []*protocol.EvsSealedChange{change}, nil)
		if err != nil {
			t.Fatal(err)
		}
		tip = built
		if cacheByteCount < builder.cache.held {
			t.Fatalf("commit %d: the cache holds %d bytes", commit, builder.cache.held)
		}
		// the reader keeps the tip's trees and drops the rest, as a pack's index would leave them to git
		if commit%1000 == 0 || commit == 100000 {
			live := map[EvsGitOid]bool{tip: true}
			_, encoded, _ := store.ReadGitObject(ctx, tip)
			entries, _ := EvsGitTreeRead(encoded)
			for _, entry := range entries {
				live[entry.Oid] = true
			}
			for oid := range store.objects {
				if !live[oid] {
					delete(store.objects, oid)
				}
			}
			if width+1 < len(store.objects) {
				t.Fatalf("commit %d: the store holds %d trees", commit, len(store.objects))
			}
		}
	}
	// the tip is the tree the files make
	rootEntries = rootEntries[:0]
	for d := range files {
		entries := []EvsGitTreeEntry{}
		for f := range files[d] {
			entries = append(entries, EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte(fmt.Sprintf("f%02d", f)), Oid: files[d][f]})
		}
		oid, _ := (&EvsGitTree{Entries: entries}).Oid()
		rootEntries = append(rootEntries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(fmt.Sprintf("d%02d", d)), Oid: oid})
	}
	if want, _ := (&EvsGitTree{Entries: rootEntries}).Oid(); tip != want {
		t.Fatalf("the tip %x, the files' %x", tip[:], want[:])
	}
}

// The pack sink writes a pack git takes: objects added whole, a blob streamed that the sink holds already taken back
// out, pending objects read back before the flush, and the flush's pack indexed by git index-pack with every object
// where it should be.
func TestEvsGitPackSinkWritesAPackGitIndexes(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	dir := filepath.Join(t.TempDir(), "sink.git")
	environment := []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
	if out, err := exec.Command(gitPath, "init", "-q", "--bare", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	spool, err := os.Create(filepath.Join(t.TempDir(), "spool"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	flushes := 0
	flush := func(ctx context.Context, pack io.Reader) error {
		flushes += 1
		command := exec.CommandContext(ctx, gitPath, "-C", dir, "index-pack", "--stdin", "--strict")
		command.Env = environment
		command.Stdin = pack
		if out, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("index-pack: %v: %s", err, out)
		}
		return nil
	}
	sink := NewEvsGitPackSink(spool, flush, nil, 1<<20)
	blobOid, err := sink.WriteGitObject(evsGitBlobKind, []byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("big "), 64*1024)
	bigOid, err := sink.WriteGitObjectFrom(evsGitBlobKind, bytes.NewReader(big), int64(len(big)))
	if err != nil {
		t.Fatal(err)
	}
	before := sink.writer.Count()
	if again, err := sink.WriteGitObjectFrom(evsGitBlobKind, bytes.NewReader(big), int64(len(big))); err != nil || again != bigOid || sink.writer.Count() != before {
		t.Fatalf("a streamed blob held already: %v, %d entries", err, sink.writer.Count())
	}
	treeBytes, _ := (&EvsGitTree{Entries: []EvsGitTreeEntry{{Mode: EvsGitModeFile, Name: []byte("hello"), Oid: blobOid}, {Mode: EvsGitModeFile, Name: []byte("big"), Oid: bigOid}}}).Encode()
	treeOid, err := sink.WriteGitObject(evsGitTreeKind, treeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if kind, content, ok := sink.PendingGitObject(treeOid); !ok || kind != evsGitTreeKind || !bytes.Equal(content, treeBytes) {
		t.Fatal("a pending tree not read back")
	}
	if _, err := sink.WriteGitObjectFrom(evsGitBlobKind, bytes.NewReader([]byte("short")), 9); !errors.Is(err, ErrEvsGitObjectInvalid) || sink.writer.Count() != before+1 {
		t.Fatalf("a short object: %v, %d entries", err, sink.writer.Count())
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := sink.PendingGitObject(treeOid); ok || flushes != 1 || sink.writer.Count() != 0 {
		t.Fatalf("after the flush: %d flushes, %d entries", flushes, sink.writer.Count())
	}
	for _, oid := range []EvsGitOid{blobOid, bigOid, treeOid} {
		command := exec.Command(gitPath, "-C", dir, "cat-file", "-t", fmt.Sprintf("%x", oid[:]))
		command.Env = environment
		if out, err := command.CombinedOutput(); err != nil {
			t.Errorf("%x not indexed: %v: %s", oid[:], err, out)
		}
	}
	// a flush that fails leaves the pending objects pending, and ends its writer
	failingSpool, err := os.Create(filepath.Join(t.TempDir(), "failing spool"))
	if err != nil {
		t.Fatal(err)
	}
	defer failingSpool.Close()
	failing := NewEvsGitPackSink(failingSpool, func(ctx context.Context, pack io.Reader) error { return errors.New("refused") }, nil, 1<<20)
	failing.WriteGitObject(evsGitBlobKind, []byte("kept\n"))
	if err := failing.Flush(context.Background()); err == nil || failing.writer.Count() != 1 {
		t.Fatalf("a failed flush: %v, %d entries", err, failing.writer.Count())
	}
}
