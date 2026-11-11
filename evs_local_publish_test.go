//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-34's tests of what an update carries (DESIGN-DETAILS 8.2.3, 8.2.5): the tree reader over git cat-file
// --batch; 8.1's C, a pull of other sidecars' commits that names their ref as its one source and carries only the
// merge; past 16 sources the seventeenth side carried and held to the new-commit rule; each carried commit sealed with
// its changes against its first parent; and the new-commit rule's refusals.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A mount's bare repository the tests build history in: objects written by git hash-object, refs by git update-ref.
type evsTestMount struct {
	t       *testing.T
	repo    *EvsLocalRepo
	history *evsTestGitHistory
}

func newEvsTestMount(t *testing.T) *evsTestMount {
	t.Helper()
	git := evsTestGitRunner(t)
	dir := filepath.Join(t.TempDir(), "mount.git")
	if _, err := git.Run(context.Background(), "", "init", "--bare", "--quiet", "--object-format=sha1", dir); err != nil {
		t.Fatal(err)
	}
	repo := &EvsLocalRepo{BareDir: dir, git: git, locks: NewEvsRefLocks(DefaultEvsSettings(), nil)}
	return &evsTestMount{t: t, repo: repo, history: &evsTestGitHistory{t: t, store: newEvsTestGitStore()}}
}

// Writes every object the history made that the repository lacks.
func (self *evsTestMount) sync() {
	self.t.Helper()
	for oid, object := range self.history.store.objects {
		command := exec.Command(self.repo.git.gitPath, "-C", self.repo.BareDir, "hash-object", "-w", "--literally", "-t", object.kind, "--stdin")
		command.Env = self.repo.git.environment()
		command.Stdin = bytes.NewReader(object.content)
		out, err := command.Output()
		if err != nil || strings.TrimSpace(string(out)) != hex.EncodeToString(oid[:]) {
			self.t.Fatalf("hash-object: %v %s", err, out)
		}
	}
}

// Points refs/ur/evs/<refId> at oid, as replay leaves a ref's tip as evs holds it.
func (self *evsTestMount) evsTip(refId Id, oid EvsGitOid) {
	self.t.Helper()
	self.sync()
	if _, err := self.repo.Git(context.Background(), "update-ref", evsLocalEvsRefPrefix+evsUrlId(refId), hex.EncodeToString(oid[:])); err != nil {
		self.t.Fatal(err)
	}
}

// A commit by email on parents whose tree holds files.
func (self *evsTestMount) commit(email string, files map[string]string, parents ...EvsGitOid) EvsGitOid {
	entries := map[string]EvsGitOid{}
	for name, content := range files {
		entries[name] = self.history.blob(content)
	}
	oid, _ := self.history.commit(self.history.tree(entries, nil), email, parents...)
	return oid
}

// Replay's state in a test: the refs it holds, by id.
type evsTestSourceState struct {
	refs map[Id]*EvsGitSourceRef
}

func (self *evsTestSourceState) SourceRef(ctx context.Context, refId Id) (*EvsGitSourceRef, bool, error) {
	source, ok := self.refs[refId]
	return source, ok, nil
}

// The tree reader reads each kind of object, its oid checked, streams a blob, and answers a missing object as such.
func TestEvsLocalObjectsReadThroughCatFile(t *testing.T) {
	mount := newEvsTestMount(t)
	tip := mount.commit("me@example.invalid", map[string]string{"a.txt": "a\n", "b.txt": strings.Repeat("b", 100000)})
	mount.sync()
	objects, err := mount.repo.Objects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	for oid, object := range mount.history.store.objects {
		kind, content, err := objects.ReadGitObject(context.Background(), oid)
		if err != nil || kind != object.kind || !bytes.Equal(content, object.content) {
			t.Fatalf("%x: %s %v", oid[:], kind, err)
		}
	}
	blob := mount.history.blob(strings.Repeat("b", 100000))
	out := &bytes.Buffer{}
	if size, err := objects.CopyBlob(context.Background(), blob, out); err != nil || size != 100000 || out.Len() != 100000 {
		t.Fatalf("a streamed blob: %d %v", size, err)
	}
	if _, err := objects.CopyBlob(context.Background(), tip, io.Discard); !errors.Is(err, ErrEvsGitObjectInvalid) {
		t.Fatalf("a commit streamed as a blob: %v", err)
	}
	if _, _, err := objects.ReadGitObject(context.Background(), EvsGitOid(evsTestBytes("no such object", 20))); !errors.Is(err, ErrEvsGitObjectMissing) {
		t.Fatalf("a missing object: %v", err)
	}
	// the reader goes on after a miss
	if kind, _, err := objects.ReadGitObject(context.Background(), tip); err != nil || kind != evsGitCommitKind {
		t.Fatalf("after a miss: %s %v", kind, err)
	}
}

// 8.1's C: main holds two other sidecars' commits, which this device's owned ref pulls into a merge of its own. The
// update carries the merge alone, names main at the version replay holds as its one source, and carries only the
// blob the merge brought.
func TestEvsLocalCarriedNamesAPulledRefAsItsSource(t *testing.T) {
	mount := newEvsTestMount(t)
	mainRefId, workRefId := evsTestId("main ref"), evsTestId("work ref")
	m1 := mount.commit("a@example.invalid", map[string]string{"shared.txt": "one\n"})
	m2 := mount.commit("b@example.invalid", map[string]string{"shared.txt": "two\n"}, m1)
	w1 := mount.commit("me@example.invalid", map[string]string{"shared.txt": "one\n", "mine.txt": "mine\n"}, m1)
	merge := mount.commit("me@example.invalid", map[string]string{"shared.txt": "two\n", "mine.txt": "mine\n", "merged.txt": "merged\n"}, w1, m2)
	mount.evsTip(mainRefId, m2)
	mount.evsTip(workRefId, w1)
	mount.sync()
	state := &evsTestSourceState{refs: map[Id]*EvsGitSourceRef{
		mainRefId: {RefId: mainRefId, Kind: protocol.EvsRefKind_EVS_REF_SHARED, Version: 7, Tip: m2, AppliedOrder: 3},
		workRefId: {RefId: workRefId, Kind: protocol.EvsRefKind_EVS_REF_OWNED, Version: 2, Tip: w1, AppliedOrder: 4},
	}}
	carried, err := mount.repo.carried(context.Background(), workRefId, merge, []EvsGitOid{w1}, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(carried.commits) != 1 || carried.commits[0] != merge {
		t.Fatalf("carried %x", carried.commits)
	}
	if len(carried.sources) != 1 || carried.sources[0].RefId != mainRefId || carried.sources[0].Version != 7 {
		t.Fatalf("sources %+v", carried.sources)
	}
	if len(carried.blobs) != 1 || !carried.blobs[mount.history.blob("merged\n")] {
		t.Fatalf("blobs %v", carried.blobs)
	}
}

// A merge of 17 refs' tips at once names 16 of them, the shared refs and the most recently applied first, and carries
// the seventeenth's commits, which must then be this sidecar's own.
func TestEvsLocalCarriedPastSixteenSources(t *testing.T) {
	mount := newEvsTestMount(t)
	base := mount.commit("me@example.invalid", map[string]string{"base.txt": "base\n"})
	state := &evsTestSourceState{refs: map[Id]*EvsGitSourceRef{}}
	parents := []EvsGitOid{base}
	for i := 0; i < 17; i += 1 {
		refId := evsTestId(fmt.Sprint("side ", i))
		tip := mount.commit("other@example.invalid", map[string]string{"base.txt": "base\n", fmt.Sprintf("side-%02d.txt", i): fmt.Sprint(i)}, base)
		parents = append(parents, tip)
		mount.evsTip(refId, tip)
		state.refs[refId] = &EvsGitSourceRef{RefId: refId, Kind: protocol.EvsRefKind_EVS_REF_SHARED, Version: uint64(i + 1), Tip: tip, AppliedOrder: uint64(100 - i)}
	}
	files := map[string]string{"base.txt": "base\n"}
	for i := 0; i < 17; i += 1 {
		files[fmt.Sprintf("side-%02d.txt", i)] = fmt.Sprint(i)
	}
	octopus := mount.commit("me@example.invalid", files, parents...)
	mount.sync()
	carried, err := mount.repo.carried(context.Background(), evsTestId("octopus ref"), octopus, []EvsGitOid{base}, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(carried.sources) != EvsGitMaxSourceCount {
		t.Fatalf("%d sources", len(carried.sources))
	}
	// the side no source names is carried before the octopus, and its foreign commit fails the new-commit rule
	named := map[Id]bool{}
	for _, source := range carried.sources {
		named[source.RefId] = true
	}
	var unnamed *EvsGitSourceRef
	for refId, source := range state.refs {
		if !named[refId] {
			unnamed = source
		}
	}
	if unnamed == nil || len(carried.commits) != 2 || carried.commits[0] != unnamed.Tip || carried.commits[1] != octopus {
		t.Fatalf("carried %x", carried.commits)
	}
	objects, err := mount.repo.Objects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	sealed, _, err := evsGitSealCommit(context.Background(), objects, unnamed.Tip)
	if err != nil {
		t.Fatal(err)
	}
	if err := evsGitCheckNewCommit(unnamed.Tip, sealed, func(clientId Id) bool { return true }); !errors.Is(err, ErrEvsGitUpdateInvalid) {
		t.Fatalf("the unnamed side's foreign commit: %v", err)
	}
}

// Each carried commit is sealed with its changes against its first parent's tree, as the builder rebuilds it, and a
// tree no path can name refuses the commit naming the tree.
func TestEvsLocalSealsACommitWithItsChanges(t *testing.T) {
	mount := newEvsTestMount(t)
	first := mount.commit("me@example.invalid", map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
	second := mount.commit("me@example.invalid", map[string]string{"a.txt": "a2\n", "c.txt": "c\n"}, first)
	mount.sync()
	objects, err := mount.repo.Objects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	sealed, parents, err := evsGitSealCommit(context.Background(), objects, second)
	if err != nil || len(parents) != 1 || parents[0] != first {
		t.Fatalf("sealed: %v %x", err, parents)
	}
	paths := []string{}
	for _, change := range sealed.GetChanges() {
		paths = append(paths, string(bytes.Join(change.GetPath(), []byte{'/'}))+fmt.Sprint(" ", len(change.GetGitOid()) == 0))
	}
	if strings.Join(paths, ",") != "a.txt false,b.txt true,c.txt false" {
		t.Fatalf("changes %v", paths)
	}
	// a tree holding a slashed name, which git stores and no path names
	slashed := append([]byte("100644 a/b\x00"), evsTestBytes("blob", 20)...)
	slashedOid, _ := mount.history.store.WriteGitObject(evsGitTreeKind, slashed)
	ident, _ := (&EvsGitIdent{Name: []byte("me"), Email: []byte("me@example.invalid"), TimeSeconds: 1767225600, TimeZone: "+0000"}).Encode()
	object, err := (&EvsGitCommit{TreeOid: slashedOid, ParentOids: []EvsGitOid{first}, Author: ident, Committer: ident, Message: []byte("slashed\n")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := mount.history.store.WriteGitObject(evsGitCommitKind, object)
	mount.sync()
	if _, _, err := evsGitSealCommit(context.Background(), objects, bad); !errors.Is(err, ErrEvsGitObjectInvalid) ||
		!strings.Contains(err.Error(), hex.EncodeToString(slashedOid[:])) {
		t.Fatalf("a slashed tree: %v", err)
	}
}

// 8.2.3's rule for a new commit: canonical, a strict committer who is a client of this sidecar, no raw tree.
func TestEvsLocalNewCommitRule(t *testing.T) {
	history := &evsTestGitHistory{t: t, store: newEvsTestGitStore()}
	own := evsTestId("own client")
	ownEmail := own.String() + evsCommitterDomain
	isOwn := func(clientId Id) bool { return clientId == own }
	tree := history.tree(map[string]EvsGitOid{"a": history.blob("a\n")}, nil)
	oid, sealed := history.commit(tree, ownEmail)
	if err := evsGitCheckNewCommit(oid, sealed, isOwn); err != nil {
		t.Fatalf("an own commit: %v", err)
	}
	foreignOid, foreign := history.commit(tree, evsTestId("other client").String()+evsCommitterDomain)
	if err := evsGitCheckNewCommit(foreignOid, foreign, isOwn); !errors.Is(err, ErrEvsGitUpdateInvalid) {
		t.Fatalf("a foreign committer: %v", err)
	}
	nul := &protocol.EvsSealedCommit{Object: bytes.Replace(sealed.GetObject(), []byte("\ncommitter "), []byte("\x00x\ncommitter "), 1)}
	if err := evsGitCheckNewCommit(oid, nul, isOwn); !errors.Is(err, ErrEvsGitUpdateInvalid) {
		t.Fatalf("a NUL in a header: %v", err)
	}
	raw := &protocol.EvsSealedCommit{Object: sealed.GetObject(), Trees: []*protocol.EvsSealedTree{{Object: []byte("040000 x\x00")}}}
	if err := evsGitCheckNewCommit(oid, raw, isOwn); !errors.Is(err, ErrEvsGitUpdateInvalid) {
		t.Fatalf("a raw tree: %v", err)
	}
}
