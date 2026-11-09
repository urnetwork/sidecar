//go:build !js

// EVS1-M2-32's tests: a git-mode ref exported with its original commit oids, git fsck clean, provenance in
// refs/notes/ur, and equal oids from two exporters; a file-mode version's commit deterministic; an erased entry's stub;
// a file-mode ref refused while its root's names have no home; a tampered tree refused.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One git commit a test pushes: files it writes (content) or removes (nil).
type evsTestGitCommit struct {
	files map[string][]byte
}

// Commits one git-mode push carrying commits, each on the one before it (the ref's tip first), with their sealed
// changes, and the net change of every path as entries; answers the last commit's oid.
func (self *evsTestWorld) pushGit(parent *EvsGitOid, commits ...*evsTestGitCommit) EvsGitOid {
	self.t.Helper()
	self.mode = protocol.EvsRefMode_EVS_REF_GIT
	keys := evsTestKeys(self.t, self.repoId, self.generation)
	metadata := &protocol.EvsSealedMetadata{}
	net := map[string][]byte{}
	tip := parent
	for i, commit := range commits {
		sealed := &protocol.EvsSealedCommit{}
		paths := []string{}
		for path := range commit.files {
			paths = append(paths, path)
		}
		slicesSortStrings(paths)
		for _, path := range paths {
			content := commit.files[path]
			names := [][]byte{}
			for _, name := range strings.Split(path, "/") {
				names = append(names, []byte(name))
			}
			change := &protocol.EvsSealedChange{Path: names, Mode: 0o100644}
			if content != nil {
				oid, _ := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
				change.GitOid = oid[:]
				self.gitState[path] = oid
			} else {
				delete(self.gitState, path)
			}
			net[path] = content
			sealed.Changes = append(sealed.Changes, change)
		}
		treeOid := self.gitTreeOid()
		ident, _ := (&EvsGitIdent{Name: []byte("agent"), Email: []byte(evsTestId("world client").String() + evsCommitterDomain), TimeSeconds: 1767225600 + int64(i), TimeZone: "+0000"}).Encode()
		gitCommit := &EvsGitCommit{TreeOid: treeOid, Author: ident, Committer: ident, Message: []byte(fmt.Sprint("commit ", i, "\n"))}
		if tip != nil {
			gitCommit.ParentOids = []EvsGitOid{*tip}
		}
		object, err := gitCommit.Encode()
		if err != nil {
			self.t.Fatal(err)
		}
		sealed.Object = object
		metadata.Commits = append(metadata.Commits, sealed)
		oid := evsGitObjectOid("commit", object)
		tip = &oid
	}
	sealedMetadata, err := EvsSealMetadata(keys.manifest, metadata)
	if err != nil {
		self.t.Fatal(err)
	}
	self.nextMetadata = sealedMetadata
	changes := []*evsTestChange{}
	paths := []string{}
	for path := range net {
		paths = append(paths, path)
	}
	slicesSortStrings(paths)
	for _, path := range paths {
		changes = append(changes, &evsTestChange{path: path, content: net[path]})
	}
	self.push(changes...)
	return *tip
}

// The tree oid of the world's git state, as git would hash it.
func (self *evsTestWorld) gitTreeOid() EvsGitOid {
	type node struct {
		entries  []EvsGitTreeEntry
		children map[string]*node
	}
	root := &node{children: map[string]*node{}}
	for path, oid := range self.gitState {
		names := strings.Split(path, "/")
		at := root
		for _, name := range names[:len(names)-1] {
			if at.children[name] == nil {
				at.children[name] = &node{children: map[string]*node{}}
			}
			at = at.children[name]
		}
		at.entries = append(at.entries, EvsGitTreeEntry{Mode: 0o100644, Name: []byte(names[len(names)-1]), Oid: oid})
	}
	var hash func(at *node) EvsGitOid
	hash = func(at *node) EvsGitOid {
		tree := &EvsGitTree{Entries: append([]EvsGitTreeEntry{}, at.entries...)}
		for name, child := range at.children {
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: evsGitModeTree, Name: []byte(name), Oid: hash(child)})
		}
		oid, err := tree.Oid()
		if err != nil {
			self.t.Fatal(err)
		}
		return oid
	}
	return hash(root)
}

// Sorts strings in place.
func slicesSortStrings(values []string) {
	for i := 1; i < len(values); i += 1 {
		for j := i; 0 < j && values[j] < values[j-1]; j -= 1 {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// Runs git in dir, its output, skipping the test where no git is installed.
func evsTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	command := exec.Command(gitPath, append([]string{"-C", dir}, args...)...)
	command.Env = []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

// A git-mode ref exports with its original oids, fsck clean, its provenance in refs/notes/ur, and a second exporter
// gives the same refs.
func TestEvsExportGitModeKeepsOriginalOids(t *testing.T) {
	world := newEvsTestWorld(t)
	first := world.pushGit(nil, &evsTestGitCommit{files: map[string][]byte{"README": []byte("hello\n"), "src/main.go": []byte("package main\n")}})
	tip := world.pushGit(&first,
		&evsTestGitCommit{files: map[string][]byte{"src/main.go": []byte("package main\n\nfunc main() {}\n")}},
		&evsTestGitCommit{files: map[string][]byte{"README": nil, "docs/a.md": []byte("# a\n")}},
	)
	exports := []string{}
	for _, label := range []string{"one", "two"} {
		reader := world.reader(t, evsTestId("exporter "+label))
		dir := filepath.Join(t.TempDir(), "export.git")
		result, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Refs) != 1 || result.Refs[0].GitRef != "refs/heads/main" || result.Refs[0].Tip != tip {
			t.Fatalf("exported %+v, want tip %s", result.Refs, tip)
		}
		evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
		if log := evsTestGit(t, dir, "log", "--format=%H", "main"); !strings.HasPrefix(log, hex.EncodeToString(tip[:])) {
			t.Errorf("log %s", log)
		}
		note := evsTestGit(t, dir, "notes", "--ref=ur", "show", hex.EncodeToString(tip[:]))
		if !strings.Contains(note, "ur push ") || !strings.Contains(note, "statement ") {
			t.Errorf("note %q", note)
		}
		exports = append(exports, evsTestGit(t, dir, "show-ref"))
	}
	if exports[0] != exports[1] {
		t.Errorf("two exporters differ:\n%s\n%s", exports[0], exports[1])
	}
}

// A sealed commit whose tree does not rebuild from its changes is refused, and alarmed.
func TestEvsExportRefusesATreeItsChangesDoNotBuild(t *testing.T) {
	world := newEvsTestWorld(t)
	world.pushGit(nil, &evsTestGitCommit{files: map[string][]byte{"a": []byte("a\n")}})
	// a second push whose commit claims a file its changes never write
	world.gitState["ghost"] = EvsGitOid(evsTestBytes("ghost blob", 20))
	world.pushGit(nil, &evsTestGitCommit{files: map[string][]byte{"b": []byte("b\n")}})
	reader := world.reader(t, evsTestId("exporter"))
	_, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: filepath.Join(t.TempDir(), "x.git")})
	if !errors.Is(err, ErrEvsExport) {
		t.Fatalf("a tree its changes do not build: %v", err)
	}
}

// A file-mode ref refuses, naming the question its root's names wait on.
func TestEvsExportFileModeWaitsOnTheRootQuestion(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	reader := world.reader(t, evsTestId("exporter"))
	_, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: filepath.Join(t.TempDir(), "x.git")})
	if !errors.Is(err, ErrEvsExport) || !strings.Contains(err.Error(), "evs1-m2-24-root-directory-names") {
		t.Fatalf("a file-mode export: %v", err)
	}
}

// A file-mode version's commit depends only on its tree, its parent and its signed statement: two exporters give one
// oid, git fsck takes it, and the stub of an erased entry names its path and hash.
func TestEvsFileModeCommitsAreDeterministic(t *testing.T) {
	oids := []EvsGitOid{}
	var dir string
	for range 2 {
		dir = filepath.Join(t.TempDir(), "file.git")
		writer, err := newEvsGitObjectWriter(dir)
		if err != nil {
			t.Fatal(err)
		}
		state := evsExportState{}
		for _, path := range []string{"b/z.txt", "a.txt", "b/y.txt"} {
			oid, err := writer.write("blob", []byte(path))
			if err != nil {
				t.Fatal(err)
			}
			names := [][]byte{}
			for _, name := range strings.Split(path, "/") {
				names = append(names, []byte(name))
			}
			state[evsExportKey(names)] = &evsExportPath{names: names, mode: 0o100644, oid: oid}
		}
		stub := evsExportErasedStub(EvsTokenPath{evsTestToken("gone")}, evsTestBytes("entry", 32))
		stubOid, err := writer.write("blob", stub)
		if err != nil {
			t.Fatal(err)
		}
		state[evsExportKey([][]byte{[]byte("gone.txt")})] = &evsExportPath{names: [][]byte{[]byte("gone.txt")}, mode: 0o100644, oid: stubOid}
		tree, err := writer.writeTree(state)
		if err != nil {
			t.Fatal(err)
		}
		first, err := evsFileModeCommit(tree, nil, evsTestId("client"), 1767225600123, evsTestId("push 1"))
		if err != nil {
			t.Fatal(err)
		}
		firstOid, err := writer.write("commit", first)
		if err != nil {
			t.Fatal(err)
		}
		second, err := evsFileModeCommit(tree, &firstOid, evsTestId("client"), 1767225601000, evsTestId("push 2"))
		if err != nil {
			t.Fatal(err)
		}
		secondOid, err := writer.write("commit", second)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.setRef("refs/heads/main", secondOid); err != nil {
			t.Fatal(err)
		}
		oids = append(oids, secondOid)
		if !bytes.HasPrefix(stub, []byte("ur-erased ")) || !bytes.Contains(stub, []byte(hex.EncodeToString(evsTestBytes("entry", 32)))) {
			t.Errorf("stub %q", stub)
		}
	}
	if oids[0] != oids[1] {
		t.Errorf("two exporters: %s, %s", oids[0], oids[1])
	}
	evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
	if show := evsTestGit(t, dir, "log", "-1", "--format=%cn <%ce> %ct %s", "main"); !strings.Contains(show, evsTestId("client").String()+"@ur.invalid") || !strings.Contains(show, "1767225601 ur push ") {
		t.Errorf("commit %q", show)
	}
}
