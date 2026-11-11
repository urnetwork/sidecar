//go:build !js

// EVS1-M2-32's tests: a git-mode ref exported with its original commit oids, git fsck clean, provenance in
// refs/notes/ur, and equal oids from two exporters; a file-mode version's commit deterministic; an erased entry's stub;
// a file-mode ref refused while its root's names have no home; a tampered tree refused. EVS1-M2-49's (DESIGN-DETAILS
// 8.6): a history with history blobs, a source, a tag of a tag and a raw tree, exported with the original's oids by
// two exporters and git fsck saying of the export what it says of the original; a refused version reported, the ref
// stopped before it until a DELETE.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
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
	// the update the push makes (DESIGN-DETAILS 8.2.3): the ref's tip before and after, and a creating push's name
	metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, NewTip: bytes.Clone(tip[:])}
	if parent != nil {
		metadata.Git.OldTip = bytes.Clone(parent[:])
	} else {
		metadata.RefName = bytes.Clone(EvsMainRefName)
		sealedRefName, err := EvsSealRefName(keys.manifest, self.refId, EvsMainRefName)
		if err != nil {
			self.t.Fatal(err)
		}
		self.nextRefName = sealedRefName
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

// A sealed commit whose tree does not rebuild from its changes is refused and alarmed: its version stops the ref at
// the one before, and export reports it rather than skipping it (DESIGN-DETAILS 8.5).
func TestEvsExportRefusesATreeItsChangesDoNotBuild(t *testing.T) {
	world := newEvsTestWorld(t)
	first := world.pushGit(nil, &evsTestGitCommit{files: map[string][]byte{"a": []byte("a\n")}})
	// a second push whose commit claims a file its changes never write
	world.gitState["ghost"] = EvsGitOid(evsTestBytes("ghost blob", 20))
	world.pushGit(&first, &evsTestGitCommit{files: map[string][]byte{"b": []byte("b\n")}})
	reader := world.reader(t, evsTestId("exporter"))
	result, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: filepath.Join(t.TempDir(), "x.git")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Refs) != 1 || result.Refs[0].Tip != first || len(result.Refs[0].Refused) != 1 || result.Refs[0].Refused[0].Version != 2 {
		t.Fatalf("a tree its changes do not build: %+v", result.Refs)
	}
	alarms := reader.eventsOf(SidecarEventEvsAlarm)
	if len(alarms) != 2 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper || alarms[1].EvsAlarm != SidecarEvsAlarmVersionRule {
		t.Errorf("alarms %v", alarms)
	}
}

// A file-mode ref exports one commit a version, each path named by the rows its directories' deltas added, the root's
// for the top level (question evs1-m2-24-root-directory-names, option 1): the tree holds what stands at each version,
// a removal taking its path out, git fsck takes it, and two exporters give one tip.
func TestEvsExportFileModeRebuildsASmallTree(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "", children: []string{"a.txt", "d"}}, &evsTestChange{path: "a.txt", content: []byte("a\n")},
		&evsTestChange{path: "d", children: []string{"b.txt", "c.txt"}}, &evsTestChange{path: "d/b.txt", content: []byte("b\n")},
		&evsTestChange{path: "d/c.txt", content: []byte("c\n"), segment: true})
	world.push(&evsTestChange{path: "d/c.txt"}, &evsTestChange{path: "a.txt", content: []byte("a again\n")})
	tips := []EvsGitOid{}
	for _, label := range []string{"one", "two"} {
		dir := filepath.Join(t.TempDir(), "file.git")
		result, err := world.reader(t, evsTestId("exporter "+label)).client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Refs) != 1 || result.Refs[0].Versions != 2 {
			t.Fatalf("exported %+v", result.Refs)
		}
		tips = append(tips, result.Refs[0].Tip)
		evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
		if tree := evsTestGit(t, dir, "ls-tree", "-r", "--name-only", "main"); tree != "a.txt\nd/b.txt\n" {
			t.Fatalf("the tip's tree %q", tree)
		}
		if first := evsTestGit(t, dir, "ls-tree", "-r", "--name-only", "main~1"); first != "a.txt\nd/b.txt\nd/c.txt\n" {
			t.Fatalf("the first version's tree %q", first)
		}
		if content := evsTestGit(t, dir, "show", "main:a.txt"); content != "a again\n" {
			t.Fatalf("a.txt at the tip %q", content)
		}
	}
	if tips[0] != tips[1] {
		t.Fatalf("two exporters: %s, %s", tips[0], tips[1])
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

// One git-mode update a test pushes, built as DESIGN-DETAILS 8.2.3 has a writer build it.
type evsTestGitUpdate struct {
	// a creating push's name, and an overlay's base
	refName []byte
	base    *protocol.EvsOverlay
	flags   uint32
	shape   protocol.EvsGitShape
	oldTip  *EvsGitOid
	newTip  *EvsGitOid
	commits []*protocol.EvsSealedCommit
	tags    [][]byte
	sources []*protocol.EvsOverlay
	// the history blobs, each a checkpoint or a diff against a blob its readers hold
	history []*evsTestHistoryBlob
	// the net change's entries
	changes      []*evsTestChange
	signedImport []byte
}

// One history blob: its content, and the content of the blob it is a diff of, nil for a checkpoint.
type evsTestHistoryBlob struct {
	content []byte
	base    []byte
}

// Commits one git-mode push of update on the world's ref and answers its version: its history blobs sealed as
// records of one history segment the push introduces, its sealed metadata the update's, a creating push's name and
// base in sections 15 and 16 beside it.
func (self *evsTestWorld) pushGitUpdate(update *evsTestGitUpdate) uint64 {
	self.t.Helper()
	self.mode = protocol.EvsRefMode_EVS_REF_GIT
	keys := evsTestKeys(self.t, self.repoId, self.generation)
	shape := update.shape
	if shape == protocol.EvsGitShape_EVS_GIT_SHAPE_UNSPECIFIED {
		shape = protocol.EvsGitShape_EVS_GIT_UPDATE
	}
	git := &protocol.EvsGitUpdate{Shape: shape, Tags: update.tags, Sources: update.sources}
	if update.oldTip != nil {
		git.OldTip = bytes.Clone(update.oldTip[:])
	}
	if update.newTip != nil {
		git.NewTip = bytes.Clone(update.newTip[:])
	}
	if 0 < len(update.history) {
		out := &bytes.Buffer{}
		builder, err := NewEvsSegmentBuilder(out, keys.manifest, keys.fek)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, history := range update.history {
			oid, err := EvsGitBlobOid(bytes.NewReader(history.content), int64(len(history.content)))
			if err != nil {
				self.t.Fatal(err)
			}
			header := &EvsRecordHeader{
				RecordId: NewEvsSlotId(), Generation: self.generation, Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT,
				KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
			}
			copy(header.Oid[:], oid[:])
			body := history.content
			blob := &protocol.EvsSealedBlob{GitOid: bytes.Clone(oid[:]), Size: uint64(len(history.content)), FileId: NewEvsSlotId().Bytes()}
			if history.base != nil {
				delta := &bytes.Buffer{}
				if err := EvsGitDeltaEncode(bytes.NewReader(history.base), bytes.NewReader(history.content), delta, DefaultEvsGitDeltaSettings()); err != nil {
					self.t.Fatal(err)
				}
				baseOid, _ := EvsGitBlobOid(bytes.NewReader(history.base), int64(len(history.base)))
				header.Kind, body, blob.BaseOid = protocol.EvsRecordKind_EVS_RECORD_DIFF, delta.Bytes(), bytes.Clone(baseOid[:])
			}
			header.BodyLength = uint64(len(body))
			fileId, _ := IdFromBytes(blob.FileId)
			writer, err := builder.BeginRecord(fileId, header)
			if err != nil {
				self.t.Fatal(err)
			}
			writer.Write(body)
			if err := writer.Close(); err != nil {
				self.t.Fatal(err)
			}
			git.Blobs = append(git.Blobs, blob)
		}
		summary, err := builder.Finish()
		if err != nil {
			self.t.Fatal(err)
		}
		for i, place := range summary.Places {
			git.Blobs[i].Records = []*protocol.EvsHistoryLocator{{Segment: 0, Offset: place.Offset, Length: place.Length}}
		}
		self.stateLock.Lock()
		self.segments[string(summary.Id[:])] = out.Bytes()
		self.stateLock.Unlock()
		git.SegmentIds = [][]byte{bytes.Clone(summary.Id[:])}
		self.nextNewObjects = []*EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: bytes.Clone(summary.Id[:]), PaddedSize: summary.PaddedSize, UploadDay: 20454}}
	}
	metadata := &protocol.EvsSealedMetadata{Commits: update.commits, Git: git, SignedImport: update.signedImport}
	if update.refName != nil {
		sealedRefName, err := EvsSealRefName(keys.manifest, self.refId, update.refName)
		if err != nil {
			self.t.Fatal(err)
		}
		metadata.RefName, metadata.Base = update.refName, update.base
		self.nextRefName, self.nextBase = sealedRefName, update.base
	}
	sealedMetadata, err := EvsSealMetadata(keys.manifest, metadata)
	if err != nil {
		self.t.Fatal(err)
	}
	self.nextMetadata = sealedMetadata
	self.nextFlags = update.flags
	return self.push(update.changes...)
}

// An object store of a history built in memory and written to a stock git repository, so git fsck reads the
// original as export's reader rebuilds it.
type evsTestGitHistory struct {
	t       *testing.T
	store   *evsTestGitStore
	email   string
	seconds int64
	// added to every commit's message
	messagePad string
}

func (self *evsTestGitHistory) blob(content string) EvsGitOid {
	oid, _ := self.store.WriteGitObject(evsGitBlobKind, []byte(content))
	return oid
}

// A canonical tree of files and subtrees, by name.
func (self *evsTestGitHistory) tree(entries map[string]EvsGitOid, directories map[string]EvsGitOid) EvsGitOid {
	tree := &EvsGitTree{}
	for name, oid := range entries {
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte(name), Oid: oid})
	}
	for name, oid := range directories {
		tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(name), Oid: oid})
	}
	encoded, err := tree.Encode()
	if err != nil {
		self.t.Fatal(err)
	}
	oid, _ := self.store.WriteGitObject(evsGitTreeKind, encoded)
	return oid
}

// A commit of tree on parents by email's committer, sealed with its changes and raw trees against its first parent.
func (self *evsTestGitHistory) commit(tree EvsGitOid, email string, parents ...EvsGitOid) (EvsGitOid, *protocol.EvsSealedCommit) {
	self.seconds += 1
	ident, err := (&EvsGitIdent{Name: []byte("agent"), Email: []byte(email), TimeSeconds: 1767225600 + self.seconds, TimeZone: "+0000"}).Encode()
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := (&EvsGitCommit{TreeOid: tree, ParentOids: parents, Author: ident, Committer: ident, Message: []byte(fmt.Sprint("commit ", self.seconds, "\n", self.messagePad))}).Encode()
	if err != nil {
		self.t.Fatal(err)
	}
	oid, _ := self.store.WriteGitObject(evsGitCommitKind, object)
	var parentTree *EvsGitOid
	if 0 < len(parents) {
		_, parentObject, _ := self.store.ReadGitObject(context.Background(), parents[0])
		parentTreeOid, _, err := EvsGitCommitGraph(parentObject)
		if err != nil {
			self.t.Fatal(err)
		}
		parentTree = &parentTreeOid
	}
	changes, raw, err := EvsGitCommitChanges(context.Background(), self.store, parentTree, tree)
	if err != nil {
		self.t.Fatal(err)
	}
	return oid, &protocol.EvsSealedCommit{Object: object, Changes: changes, Trees: raw}
}

// The repository at dir holding every object, by git hash-object --literally, with refs.
func (self *evsTestGitHistory) writeRepository(dir string, refs map[string]EvsGitOid) {
	self.t.Helper()
	evsTestGit(self.t, filepath.Dir(dir), "init", "-q", "--bare", dir)
	for oid, object := range self.store.objects {
		gitPath, _ := exec.LookPath("git")
		command := exec.Command(gitPath, "-C", dir, "hash-object", "-w", "--literally", "-t", object.kind, "--stdin")
		command.Env = []string{"HOME=" + self.t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
		command.Stdin = bytes.NewReader(object.content)
		out, err := command.Output()
		if err != nil || strings.TrimSpace(string(out)) != hex.EncodeToString(oid[:]) {
			self.t.Fatalf("git hash-object: %v %s", err, out)
		}
	}
	for gitRef, oid := range refs {
		evsTestGit(self.t, dir, "update-ref", gitRef, hex.EncodeToString(oid[:]))
	}
}

// What git fsck says of a repository, line by line, sorted.
func evsTestFsck(t *testing.T, dir string) []string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	command := exec.Command(gitPath, "-C", dir, "fsck", "--no-dangling", "--no-progress")
	command.Env = []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}
	out, _ := command.CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	slicesSortStrings(lines)
	return lines
}

// A history 8.1's A, C and J describe, pushed as 8.2.3 builds it: two commits in one push whose middle blob only a
// history blob carries; two more whose middle blob is a history diff on a held blob; a feature branch that names main
// as its source and carries its one commit; an import whose commit's directory is a raw tree with a zero-padded mode
// and a foreign committer; a merge of the feature that names it as a source; and a tag of a tag naming main as its
// source and carrying nothing. Two exporters give the original's oids, the second reading the log a statement a page,
// and git fsck says of each export what it says of the original: the raw tree's warning and nothing more.
func TestEvsExportGitHistoryWithHistoryBlobsSourcesTagsAndRawTrees(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no system git")
	}
	world := newEvsTestWorld(t)
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	email := evsTestId("world client").String() + evsCommitterDomain
	history := &evsTestGitHistory{t: t, store: newEvsTestGitStore(), email: email}

	// main, push 1: c1 then c2 on plan.md; plan one rides only as a history checkpoint
	readme := history.blob("hello\n")
	c1, sealed1 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan one\n")}, nil), email)
	c2, sealed2 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan two\n")}, nil), email, c1)
	world.pushGitUpdate(&evsTestGitUpdate{
		refName: EvsMainRefName, newTip: &c2, commits: []*protocol.EvsSealedCommit{sealed1, sealed2},
		history: []*evsTestHistoryBlob{{content: []byte("plan one\n")}},
		changes: []*evsTestChange{{path: "README", content: []byte("hello\n")}, {path: "plan.md", content: []byte("plan two\n")}},
	})
	// main, push 2: c3a then c3; c3a's plan.md a history diff on plan two, which the readers hold
	c3a, sealed3a := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan two, and a half\n")}, nil), email, c2)
	c3, sealed3 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan three\n")}, nil), email, c3a)
	mainAtC3 := world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c2, newTip: &c3, commits: []*protocol.EvsSealedCommit{sealed3a, sealed3},
		history: []*evsTestHistoryBlob{{content: []byte("plan two, and a half\n"), base: []byte("plan two\n")}},
		changes: []*evsTestChange{{path: "plan.md", content: []byte("plan three\n")}},
	})
	// feature: f1 on c3, which main holds; the push names main and carries f1 alone
	feature := world.otherRef([]byte("feature"))
	featureBlob := history.blob("a feature\n")
	featureTree := history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan three\n"), "feature.txt": featureBlob}, nil)
	f1, sealedF1 := history.commit(featureTree, email, c3)
	featureVersion := feature.pushGitUpdate(&evsTestGitUpdate{
		refName: []byte("feature"), newTip: &f1, commits: []*protocol.EvsSealedCommit{sealedF1},
		sources: []*protocol.EvsOverlay{{RefId: world.refId.Bytes(), Version: mainAtC3}},
		changes: []*evsTestChange{{path: "README", content: []byte("hello\n")}, {path: "plan.md", content: []byte("plan three\n")}, {path: "feature.txt", content: []byte("a feature\n")}},
	})
	// main, push 3: an import of a foreign commit whose vendor directory is a raw tree, a zero-padded mode in it
	lib := history.blob("int lib;\n")
	inner := history.tree(map[string]EvsGitOid{"x": history.blob("x\n")}, nil)
	vendorBytes := append(append([]byte("100644 lib.c\x00"), lib[:]...), append([]byte("040000 sub\x00"), inner[:]...)...)
	vendor, _ := history.store.WriteGitObject(evsGitTreeKind, vendorBytes)
	c4, sealed4 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan three\n")}, map[string]EvsGitOid{"vendor": vendor}), "other@example.invalid", c3)
	if len(sealed4.GetTrees()) != 1 {
		t.Fatalf("the import's raw trees %v", sealed4.GetTrees())
	}
	list := sha256.Sum256(c4[:])
	importBody, _ := proto.Marshal(&protocol.EvsImport{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), TipOid: c4[:], OidListSha256: list[:], Count: 1})
	signedImport, _ := world.signer.sign(evsImportPurpose, bridge.SignedType_SIGNED_EVS_IMPORT, importBody, nil)
	signedImportBytes, _ := proto.Marshal(signedImport)
	world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c3, newTip: &c4, commits: []*protocol.EvsSealedCommit{sealed4}, signedImport: signedImportBytes,
		changes: []*evsTestChange{{path: "vendor/lib.c", content: []byte("int lib;\n")}, {path: "vendor/sub/x", content: []byte("x\n")}},
	})
	// main, push 4: the merge of feature, naming it as a source and carrying the merge alone
	mergeTree := history.tree(map[string]EvsGitOid{"README": readme, "plan.md": history.blob("plan three\n"), "feature.txt": featureBlob}, map[string]EvsGitOid{"vendor": vendor})
	m, sealedM := history.commit(mergeTree, email, c4, f1)
	mainAtM := world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c4, newTip: &m, commits: []*protocol.EvsSealedCommit{sealedM},
		sources: []*protocol.EvsOverlay{{RefId: feature.refId.Bytes(), Version: featureVersion}},
		changes: []*evsTestChange{{path: "feature.txt", content: []byte("a feature\n")}},
	})
	// refs/tags/v1: a tag of a tag of m, IMMUTABLE, naming main and carrying nothing
	tagRef := world.otherRef([]byte("refs/tags/v1"))
	tagInner := evsTestTag(m, evsGitCommitKind, "v1-inner")
	tagInnerOid, _ := history.store.WriteGitObject(evsGitTagKind, tagInner)
	tagOuter := evsTestTag(tagInnerOid, evsGitTagKind, "v1")
	tagOuterOid, _ := history.store.WriteGitObject(evsGitTagKind, tagOuter)
	tagRef.pushGitUpdate(&evsTestGitUpdate{
		refName: []byte("refs/tags/v1"), flags: uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE), newTip: &tagOuterOid,
		tags: [][]byte{tagOuter, tagInner}, sources: []*protocol.EvsOverlay{{RefId: world.refId.Bytes(), Version: mainAtM}},
	})

	original := filepath.Join(t.TempDir(), "original.git")
	history.writeRepository(original, map[string]EvsGitOid{"refs/heads/main": m, "refs/heads/feature": f1, "refs/tags/v1": tagOuterOid})
	originalFsck := evsTestFsck(t, original)
	if !strings.Contains(strings.Join(originalFsck, "\n"), "zeroPaddedFilemode") {
		t.Fatalf("the original's fsck: %v", originalFsck)
	}
	refsOut := []string{}
	for _, label := range []string{"one", "two"} {
		dir := filepath.Join(t.TempDir(), "export.git")
		reader := world.reader(t, evsTestId("exporter "+label))
		if label == "two" {
			// the second reads the log a statement a page, so what export holds is one page of each ref
			reader.client.settings.HistoryVersionCount = 1
		}
		result, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir, RefNames: [][]byte{EvsMainRefName, []byte("refs/tags/v1")}})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Refs) != 2 || result.Refs[0].Tip != m || result.Refs[1].Tip != tagOuterOid || result.Refs[1].GitRef != "refs/tags/v1" {
			for _, exported := range result.Refs {
				t.Logf("%s %x %d refused %d", exported.GitRef, exported.Tip[:], exported.Versions, len(exported.Refused))
				for _, refusal := range exported.Refused {
					t.Logf("  version %d: %s", refusal.Version, refusal.Reason)
				}
			}
			t.Fatalf("exported %d refs", len(result.Refs))
		}
		for _, exported := range result.Refs {
			if len(exported.Refused) != 0 {
				t.Fatalf("%s refused %v", exported.GitRef, exported.Refused[0])
			}
		}
		if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
			t.Fatalf("alarms %v", alarms)
		}
		if fsck := evsTestFsck(t, dir); strings.Join(fsck, "\n") != strings.Join(originalFsck, "\n") {
			t.Errorf("the export's fsck:\n%s\nthe original's:\n%s", strings.Join(fsck, "\n"), strings.Join(originalFsck, "\n"))
		}
		// every object the refs reach, in both
		objects := evsTestGit(t, dir, "rev-list", "--objects", "refs/heads/main", "refs/tags/v1")
		if want := evsTestGit(t, original, "rev-list", "--objects", "refs/heads/main", "refs/tags/v1"); objects != want {
			t.Errorf("the export's objects differ from the original's")
		}
		if content := evsTestGit(t, dir, "cat-file", "-p", hex.EncodeToString(c3a[:])+":plan.md"); content != "plan two, and a half\n" {
			t.Errorf("the history diff's blob %q", content)
		}
		refsOut = append(refsOut, evsTestGit(t, dir, "show-ref"))
	}
	if refsOut[0] != refsOut[1] {
		t.Errorf("two exporters differ:\n%s\n%s", refsOut[0], refsOut[1])
	}
}

// A version that fails its check is refused, alarmed and reported, and its ref stops at the version before: a later
// version is not applied, until a DELETE, after which the ref is created again and exports.
func TestEvsExportStopsARefAtARefusedVersionUntilADelete(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no system git")
	}
	world := newEvsTestWorld(t)
	// a DELETE on a shared ref is an admin's (§11.8's refs table)
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	email := evsTestId("world client").String() + evsCommitterDomain
	history := &evsTestGitHistory{t: t, store: newEvsTestGitStore(), email: email}
	c1, sealed1 := history.commit(history.tree(map[string]EvsGitOid{"a": history.blob("a\n")}, nil), email)
	world.pushGitUpdate(&evsTestGitUpdate{refName: EvsMainRefName, newTip: &c1, commits: []*protocol.EvsSealedCommit{sealed1}, changes: []*evsTestChange{{path: "a", content: []byte("a\n")}}})
	// version 2: another client's commit, which no committer rule takes
	c2, sealed2 := history.commit(history.tree(map[string]EvsGitOid{"a": history.blob("a2\n")}, nil), "someone@example.invalid", c1)
	world.pushGitUpdate(&evsTestGitUpdate{oldTip: &c1, newTip: &c2, commits: []*protocol.EvsSealedCommit{sealed2}, changes: []*evsTestChange{{path: "a", content: []byte("a2\n")}}})
	// version 3, on the refused one, is not applied
	c3, sealed3 := history.commit(history.tree(map[string]EvsGitOid{"a": history.blob("a3\n")}, nil), email, c2)
	world.pushGitUpdate(&evsTestGitUpdate{oldTip: &c2, newTip: &c3, commits: []*protocol.EvsSealedCommit{sealed3}, changes: []*evsTestChange{{path: "a", content: []byte("a3\n")}}})
	exportOnce := func() *EvsExportedRef {
		dir := filepath.Join(t.TempDir(), "export.git")
		result, err := world.reader(t, evsTestId("exporter")).client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Refs) != 1 {
			t.Fatalf("exported %+v", result.Refs)
		}
		return result.Refs[0]
	}
	if exported := exportOnce(); exported.Tip != c1 || len(exported.Refused) != 1 || exported.Refused[0].Version != 2 || !strings.Contains(exported.Refused[0].Reason, "committer") {
		t.Fatalf("a refused version: %+v %v", exported, exported.Refused)
	}
	// a DELETE, then the ref created again from nothing
	world.pushGitUpdate(&evsTestGitUpdate{flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE), shape: protocol.EvsGitShape_EVS_GIT_DELETE, oldTip: &c3})
	c5, sealed5 := history.commit(history.tree(map[string]EvsGitOid{"b": history.blob("b\n")}, nil), email)
	world.pushGitUpdate(&evsTestGitUpdate{refName: EvsMainRefName, newTip: &c5, commits: []*protocol.EvsSealedCommit{sealed5}, changes: []*evsTestChange{{path: "a"}, {path: "b", content: []byte("b\n")}}})
	if exported := exportOnce(); exported.Tip != c5 || len(exported.Refused) != 1 {
		t.Fatalf("after the DELETE: %+v %v", exported, exported.Refused)
	}
}

// A push of 2,000 commits whose sealed metadata passes 1 MiB is sent in parts, the metadata's slices in changeless
// parts after the one with the change (DESIGN-DETAILS 8.1's D, 8.2.2's parts row); export reads it part by part and
// gives the original's oids, every middle blob a history blob, and git fsck takes it.
func TestEvsExportReadsAPushInParts(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no system git")
	}
	world := newEvsTestWorld(t)
	email := evsTestId("world client").String() + evsCommitterDomain
	history := &evsTestGitHistory{t: t, store: newEvsTestGitStore(), email: email, messagePad: strings.Repeat("a long message line\n", 30)}
	commits := []*protocol.EvsSealedCommit{}
	blobs := []*evsTestHistoryBlob{}
	var tip *EvsGitOid
	var previous []byte
	for i := range 2000 {
		content := []byte(fmt.Sprintf("entry %d %s\n", i, strings.Repeat("x", 480)))
		var parents []EvsGitOid
		if tip != nil {
			parents = []EvsGitOid{*tip}
		}
		oid, sealed := history.commit(history.tree(map[string]EvsGitOid{"log.txt": history.blob(string(content))}, nil), email, parents...)
		commits = append(commits, sealed)
		if i < 1999 {
			blobs = append(blobs, &evsTestHistoryBlob{content: content, base: previous})
		}
		previous, tip = content, &oid
	}
	version := world.pushGitUpdate(&evsTestGitUpdate{
		refName: EvsMainRefName, newTip: tip, commits: commits, history: blobs,
		changes: []*evsTestChange{{path: "log.txt", content: previous}},
	})
	world.stateLock.Lock()
	parts := len(world.commits[version-1].built.Parts)
	world.stateLock.Unlock()
	if parts < 2 {
		t.Fatalf("the push went in %d parts", parts)
	}
	dir := filepath.Join(t.TempDir(), "export.git")
	result, err := world.reader(t, evsTestId("exporter")).client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Refs) != 1 || result.Refs[0].Tip != *tip || len(result.Refs[0].Refused) != 0 {
		t.Fatalf("exported %+v", result.Refs)
	}
	evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
	if count := strings.TrimSpace(evsTestGit(t, dir, "rev-list", "--count", "main")); count != "2000" {
		t.Fatalf("%s commits", count)
	}
}
