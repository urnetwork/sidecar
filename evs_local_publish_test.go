//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-34's tests of what an update carries (DESIGN-DETAILS 8.2.3, 8.2.5): the tree reader over git cat-file
// --batch; 8.1's C, a pull of other sidecars' commits that names their ref as its one source and carries only the
// merge; past 16 sources the seventeenth side carried and held to the new-commit rule; each carried commit sealed with
// its changes against its first parent; and the new-commit rule's refusals.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A mount's bare repository the tests build history in: objects written by git hash-object, refs by git update-ref.
type evsTestMount struct {
	t       *testing.T
	repo    *EvsLocalRepo
	history *evsTestGitHistory
	// the objects written already
	synced map[EvsGitOid]bool
}

func newEvsTestMount(t *testing.T) *evsTestMount {
	t.Helper()
	git := evsTestGitRunner(t)
	dir := filepath.Join(t.TempDir(), "mount.git")
	if _, err := git.Run(context.Background(), "", "init", "--bare", "--quiet", "--object-format=sha1", dir); err != nil {
		t.Fatal(err)
	}
	repo := &EvsLocalRepo{BareDir: dir, git: git, locks: NewEvsRefLocks(DefaultEvsSettings(), nil)}
	return &evsTestMount{t: t, repo: repo, history: &evsTestGitHistory{t: t, store: newEvsTestGitStore()}, synced: map[EvsGitOid]bool{}}
}

// Writes every object the history made that the repository lacks.
func (self *evsTestMount) sync() {
	self.t.Helper()
	for oid, object := range self.history.store.objects {
		if self.synced[oid] {
			continue
		}
		self.synced[oid] = true
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

// Replay's state in a test: the refs it holds, by id, and every version's tip it applied, by ref.
type evsTestSourceState struct {
	refs map[Id]*EvsGitSourceRef
	tips map[Id]map[uint64]EvsGitOid
}

func (self *evsTestSourceState) SourceRef(ctx context.Context, refId Id) (*EvsGitSourceRef, bool, error) {
	source, ok := self.refs[refId]
	return source, ok, nil
}

func (self *evsTestSourceState) Refs(ctx context.Context) ([]*EvsGitSourceRef, error) {
	refs := []*EvsGitSourceRef{}
	for _, ref := range self.refs {
		refs = append(refs, ref)
	}
	return refs, nil
}

func (self *evsTestSourceState) TipsOf(ctx context.Context, oid EvsGitOid) ([]*EvsGitSourceRef, error) {
	found := []*EvsGitSourceRef{}
	for refId, versions := range self.tips {
		for version, tip := range versions {
			if tip == oid {
				ref := *self.refs[refId]
				ref.Version, ref.Tip = version, tip
				found = append(found, &ref)
			}
		}
	}
	return found, nil
}

func (self *evsTestSourceState) TipAt(ctx context.Context, refId Id, version uint64) (EvsGitOid, bool, error) {
	tip, ok := self.tips[refId][version]
	return tip, ok, nil
}

// Notes a ref's version and its tip as applied.
func (self *evsTestSourceState) applied(source *EvsGitSourceRef) {
	self.refs[source.RefId] = source
	if self.tips == nil {
		self.tips = map[Id]map[uint64]EvsGitOid{}
	}
	if self.tips[source.RefId] == nil {
		self.tips[source.RefId] = map[uint64]EvsGitOid{}
	}
	self.tips[source.RefId][source.Version] = source.Tip
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

// A device that publishes a mount's refs to the stand-in evs: the world's writer, the mount, and replay's state as the
// tests apply each committed push, which EVS1-M2-35's sync engine does for real: each ref's tip, version and chain,
// its refs/ur/evs/ tip, and its row in the source state.
type evsTestPublisher struct {
	t      *testing.T
	writer *evsTestWriter
	mount  *evsTestMount
	state  *evsTestSourceState
	refs   map[string]*evsTestPublishedRef
	email  string
	order  uint64
}

// One ref as the tests' replay applied it.
type evsTestPublishedRef struct {
	refId   Id
	tip     *EvsGitOid
	lastTip *EvsGitOid
	version uint64
	chain   [32]byte
	deleted bool
	// an overlay's base, as replay keeps it from the head
	base *protocol.EvsOverlay
}

func newEvsTestPublisher(t *testing.T) *evsTestPublisher {
	t.Helper()
	writer := newEvsTestWriter(t)
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	// a repo admin, who may FORCE and DELETE a shared ref (§11.8's refs table) and sign an import
	writer.world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: writer.world.signer.sidecarId.Bytes()}}
	mount := newEvsTestMount(t)
	mount.repo.RepoId = writer.world.repoId
	return &evsTestPublisher{
		t: t, writer: writer, mount: mount, state: &evsTestSourceState{refs: map[Id]*EvsGitSourceRef{}},
		refs: map[string]*evsTestPublishedRef{}, email: evsTestId("world client").String() + evsCommitterDomain,
	}
}

// The ref of name, its world made on first use so the stand-in serves it.
func (self *evsTestPublisher) ref(name string) *evsTestPublishedRef {
	ref := self.refs[name]
	if ref == nil {
		world := self.writer.world
		if name != string(EvsMainRefName) {
			world = world.otherRef([]byte(name))
		}
		ref = &evsTestPublishedRef{refId: world.refId, chain: EvsChainStart(world.repoId, world.refId)}
		self.refs[name] = ref
	}
	return ref
}

// A tree of files by path, its directories nested as git builds them; a gitlink's content is the hex of its oid
// after "gitlink:".
func (self *evsTestPublisher) tree(files map[string]string) EvsGitOid {
	self.t.Helper()
	type node struct {
		files    map[string]string
		children map[string]*node
	}
	root := &node{files: map[string]string{}, children: map[string]*node{}}
	for path, content := range files {
		names := strings.Split(path, "/")
		at := root
		for _, name := range names[:len(names)-1] {
			if at.children[name] == nil {
				at.children[name] = &node{files: map[string]string{}, children: map[string]*node{}}
			}
			at = at.children[name]
		}
		at.files[names[len(names)-1]] = content
	}
	var build func(at *node) EvsGitOid
	build = func(at *node) EvsGitOid {
		tree := &EvsGitTree{}
		for name, content := range at.files {
			if oidText, ok := strings.CutPrefix(content, "gitlink:"); ok {
				oid, err := evsGitOidDecodeHex([]byte(oidText))
				if err != nil {
					self.t.Fatal(err)
				}
				tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeGitlink, Name: []byte(name), Oid: oid})
				continue
			}
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte(name), Oid: self.mount.history.blob(content)})
		}
		for name, child := range at.children {
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(name), Oid: build(child)})
		}
		encoded, err := tree.Encode()
		if err != nil {
			self.t.Fatal(err)
		}
		oid, _ := self.mount.history.store.WriteGitObject(evsGitTreeKind, encoded)
		return oid
	}
	// the stand-in maps each change's token path back to its plaintext path
	paths := []string{}
	for path := range files {
		paths = append(paths, path)
	}
	self.writer.server.know(paths...)
	return build(root)
}

// A commit of files by this device's client on parents.
func (self *evsTestPublisher) commit(files map[string]string, parents ...EvsGitOid) EvsGitOid {
	oid, _ := self.mount.history.commit(self.tree(files), self.email, parents...)
	return oid
}

// Publishes the ref of name to new, nil deleting it, from the tip the tests' replay applied, and applies what
// commits.
func (self *evsTestPublisher) publish(name string, new *EvsGitOid, configure ...func(args *EvsLocalPublishArgs)) (*EvsLocalPublishResult, error) {
	self.t.Helper()
	self.mount.sync()
	ref := self.ref(name)
	args := &EvsLocalPublishArgs{
		Mount: self.mount.repo, Repo: self.writer.repo, RefName: []byte(name), Old: ref.tip, New: new,
		BaseVersion: ref.version, BaseChain: ref.chain, Deleted: ref.deleted, LastTip: ref.lastTip, State: self.state,
		Base: ref.base,
	}
	for _, f := range configure {
		f(args)
	}
	result, err := EvsLocalPublish(context.Background(), args)
	if err != nil {
		return nil, err
	}
	ref.base = result.Base
	self.apply(name, result.Version, new)
	return result, nil
}

// Applies version of the ref of name, its tip now tip (nil: deleted), as replay does after a commit: its record, its
// refs/ur/evs/ tip and its source row.
func (self *evsTestPublisher) apply(name string, version uint64, tip *EvsGitOid) {
	self.t.Helper()
	ref := self.ref(name)
	world := self.writer.server.worldOf(ref.refId)
	world.stateLock.Lock()
	ref.version, ref.chain = version, world.commits[version-1].chain
	world.stateLock.Unlock()
	if tip == nil {
		ref.lastTip, ref.tip, ref.deleted = ref.tip, nil, true
		return
	}
	ref.tip, ref.deleted, ref.lastTip = tip, false, nil
	self.mount.evsTip(ref.refId, *tip)
	self.order += 1
	kind := protocol.EvsRefKind_EVS_REF_SHARED
	if _, ok := EvsOwnedRefOwner([]byte(name)); ok {
		kind = protocol.EvsRefKind_EVS_REF_OWNED
	}
	self.state.applied(&EvsGitSourceRef{
		RefId: ref.refId, Kind: kind, Version: version, Tip: *tip, AppliedOrder: self.order,
		Tag: strings.HasPrefix(name, evsGitTagRefPrefix),
	})
}

// Exports the repo through a fresh reader's verifying replay, its refs of names, into a new repository, failing on
// any refused version or alarm: what a second device's replay would hold.
func (self *evsTestPublisher) export(names ...string) (string, *EvsExportResult) {
	self.t.Helper()
	dir := filepath.Join(self.t.TempDir(), "export.git")
	reader := self.writer.world.reader(self.t, evsTestId("export reader"))
	refNames := [][]byte{}
	for _, name := range names {
		refNames = append(refNames, []byte(name))
	}
	result, err := reader.client.Repo(self.writer.world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir, RefNames: refNames})
	if err != nil {
		self.t.Fatal(err)
	}
	for _, exported := range result.Refs {
		for _, refusal := range exported.Refused {
			self.t.Fatalf("%s refused at version %d: %s", exported.GitRef, refusal.Version, refusal.Reason)
		}
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		self.t.Fatalf("alarms %v", alarms)
	}
	return dir, result
}

// The posted statements' count, each a push or a seal.
func (self *evsTestPublisher) posted() int {
	self.writer.server.stateLock.Lock()
	defer self.writer.server.stateLock.Unlock()
	return len(self.writer.server.postedStatements)
}

// The sealed metadata of the ref's committed version.
func (self *evsTestPublisher) metadata(name string, version uint64) *protocol.EvsSealedMetadata {
	self.t.Helper()
	world := self.writer.server.worldOf(self.ref(name).refId)
	world.stateLock.Lock()
	commit := world.commits[version-1]
	world.stateLock.Unlock()
	var checked *EvsCheckedPayload
	var err error
	if 0 < len(commit.built.Parts) {
		checked, _, err = EvsCheckSeal(commit.parsed, commit.built.Parts)
	} else {
		checked, err = EvsCheckPayload(commit.parsed, commit.built.Payload)
	}
	if err != nil {
		self.t.Fatal(err)
	}
	keys := evsTestKeys(self.t, world.repoId, commit.parsed.Push.GetGeneration())
	metadata, err := EvsOpenMetadata(keys.manifest, checked.SealedMetadata)
	if err != nil {
		self.t.Fatal(err)
	}
	return metadata
}

// 8.1's A: two commits pushed at once, the middle blob carried by a history blob alone; the push creates main with its
// name sealed; a second push adds a directory and removes a file. A second device's export holds every oid and git
// fsck is clean, and reads the middle blob back.
func TestEvsLocalPublishCarriesTheMiddleBlobAsAHistoryBlob(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan one\n"})
	c2 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan two\n"}, c1)
	result, err := publisher.publish("main", &c2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || len(result.Commits) != 2 || result.HistoryBlobCount != 1 || result.Flags != 0 || len(result.Sources) != 0 {
		t.Fatalf("result %+v", result)
	}
	metadata := publisher.metadata("main", 1)
	git := metadata.GetGit()
	planOne := publisher.mount.history.blob("plan one\n")
	if !bytes.Equal(metadata.GetRefName(), EvsMainRefName) || len(git.GetOldTip()) != 0 || !bytes.Equal(git.GetNewTip(), c2[:]) ||
		len(git.GetBlobs()) != 1 || !bytes.Equal(git.GetBlobs()[0].GetGitOid(), planOne[:]) {
		t.Fatalf("the sealed update %v", git)
	}
	c3 := publisher.commit(map[string]string{"plan.md": "plan two\n", "docs/a.md": "a\n", "docs/deep/b.md": "b\n"}, c2)
	result, err = publisher.publish("main", &c3)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 2 || len(result.Commits) != 1 || result.HistoryBlobCount != 0 {
		t.Fatalf("result %+v", result)
	}
	if len(publisher.metadata("main", 2).GetRefName()) != 0 {
		t.Fatal("a ref name on a push that does not create its ref")
	}
	dir, exported := publisher.export("main")
	if len(exported.Refs) != 1 || exported.Refs[0].Tip != c3 {
		t.Fatalf("exported %+v", exported.Refs)
	}
	if fsck := evsTestFsck(t, dir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	if content := evsTestGit(t, dir, "cat-file", "-p", hex.EncodeToString(c1[:])+":plan.md"); content != "plan one\n" {
		t.Fatalf("the history blob %q", content)
	}
	if content := evsTestGit(t, dir, "cat-file", "-p", hex.EncodeToString(c3[:])+":docs/deep/b.md"); content != "b\n" {
		t.Fatalf("a nested file %q", content)
	}
}

// A DELETE carries nothing and states no tip; the push that re-creates the ref states its net change against the tree
// the deleted ref's entries stand at, carries its name again, and exports.
func TestEvsLocalPublishDeleteAndRecreate(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	deleted, err := publisher.publish("main", nil)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Shape != protocol.EvsGitShape_EVS_GIT_DELETE || deleted.Flags != uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) || len(deleted.Commits) != 0 {
		t.Fatalf("the DELETE %+v", deleted)
	}
	if git := publisher.metadata("main", 2).GetGit(); !bytes.Equal(git.GetOldTip(), c1[:]) || len(git.GetNewTip()) != 0 {
		t.Fatalf("the DELETE's update %v", git)
	}
	c2 := publisher.commit(map[string]string{"a.txt": "a again\n", "c.txt": "c\n"}, c1)
	recreated, err := publisher.publish("main", &c2)
	if err != nil {
		t.Fatal(err)
	}
	metadata := publisher.metadata("main", 3)
	if recreated.Version != 3 || !bytes.Equal(metadata.GetRefName(), EvsMainRefName) || len(metadata.GetGit().GetOldTip()) != 0 {
		t.Fatalf("the re-creation %+v %v", recreated, metadata.GetGit())
	}
	// against the deleted tree: a.txt written over its standing version, b.txt removed, c.txt created
	world := publisher.writer.world
	world.stateLock.Lock()
	removal := world.paths["b.txt"].removal
	aVersion := world.paths["a.txt"].newest
	world.stateLock.Unlock()
	if removal == nil || aVersion != 2 {
		t.Fatalf("b.txt's removal %v, a.txt's version %d", removal, aVersion)
	}
	dir, exported := publisher.export("main")
	if exported.Refs[0].Tip != c2 {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
	if fsck := evsTestFsck(t, dir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
}

// A forced rewind to an ancestor carries no commit, sets FORCE and states the net change back to the old tree.
func TestEvsLocalPublishForcedRewind(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n", "b.txt": "b\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	rewound, err := publisher.publish("main", &c1)
	if err != nil {
		t.Fatal(err)
	}
	if rewound.Flags != uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) || len(rewound.Commits) != 0 || rewound.HistoryBlobCount != 0 {
		t.Fatalf("the rewind %+v", rewound)
	}
	dir, exported := publisher.export("main")
	if exported.Refs[0].Tip != c1 {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
	if content := evsTestGit(t, dir, "cat-file", "-p", hex.EncodeToString(c2[:])+":b.txt"); content != "b\n" {
		t.Fatalf("the rewound commit's blob %q", content)
	}
}

// 8.1's N: a file replaced by a directory, then the directory by a file again, each one push on a git-mode ref; a
// gitlink, a file entry with an empty chain; every oid rebuilt by the export.
func TestEvsLocalPublishFileAndDirectoryKindsAndAGitlink(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	link := hex.EncodeToString(evsTestBytes("a submodule commit", 20))
	c1 := publisher.commit(map[string]string{"docs": "a file\n", "keep.txt": "k\n", "sub": "gitlink:" + link})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	c2 := publisher.commit(map[string]string{"docs/one.md": "one\n", "docs/two/three.md": "three\n", "keep.txt": "k\n", "sub": "gitlink:" + link}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	c3 := publisher.commit(map[string]string{"docs": "a file again\n", "keep.txt": "k\n"}, c2)
	if _, err := publisher.publish("main", &c3); err != nil {
		t.Fatal(err)
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	removed := world.paths["docs/two/three.md"].removal != nil && world.paths["docs/two"].removal != nil
	world.stateLock.Unlock()
	if !removed {
		t.Fatal("the paths below the replaced directory stand")
	}
	_, exported := publisher.export("main")
	if exported.Refs[0].Tip != c3 {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A rename keeps the removed file's file_id and chain and uploads nothing: the created path's entry cites the removed
// path's segment.
func TestEvsLocalPublishRenameUploadsNothing(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	big := strings.Repeat("a large file that rides in a segment\n", 1024)
	c1 := publisher.commit(map[string]string{"old/name.txt": big, "other.txt": "o\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	removed := publisher.writer.entry(t, "old/name.txt")
	uploads := len(publisher.writer.server.uploads)
	c2 := publisher.commit(map[string]string{"new/name.txt": big, "other.txt": "o\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	if len(publisher.writer.server.uploads) != uploads {
		t.Fatalf("a rename uploaded %d segments", len(publisher.writer.server.uploads)-uploads)
	}
	created := publisher.writer.entry(t, "new/name.txt")
	if len(created.GetChain()) != len(removed.GetChain()) || !proto.Equal(created.GetChain()[0], removed.GetChain()[0]) {
		t.Fatal("the renamed path does not cite the removed path's chain")
	}
	_, exported := publisher.export("main")
	if exported.Refs[0].Tip != c2 {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A branch at a commit main holds and a lightweight and an annotated tag of it: one push each, no commit, no change,
// no upload, naming main as their source; the tags IMMUTABLE, the annotated one's tag object sealed; a second push to
// a tag refused before anything is sent.
func TestEvsLocalPublishBranchesAndTagsAtHeldCommits(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	main, err := publisher.publish("main", &c2)
	if err != nil {
		t.Fatal(err)
	}
	uploads := len(publisher.writer.server.uploads)
	mainSource := &protocol.EvsOverlay{RefId: publisher.ref("main").refId.Bytes(), Version: main.Version}
	feature, err := publisher.publish("feature", &c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(feature.Commits) != 0 || feature.Flags != 0 || len(feature.Sources) != 1 || !proto.Equal(feature.Sources[0], mainSource) {
		t.Fatalf("the branch %+v", feature)
	}
	light, err := publisher.publish("refs/tags/v1", &c2)
	if err != nil {
		t.Fatal(err)
	}
	if light.Flags != uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) || len(light.Commits) != 0 || len(light.Sources) != 1 {
		t.Fatalf("the lightweight tag %+v", light)
	}
	tagObject := evsTestTag(c2, evsGitCommitKind, "v2")
	tagOid, _ := publisher.mount.history.store.WriteGitObject(evsGitTagKind, tagObject)
	annotated, err := publisher.publish("refs/tags/v2", &tagOid)
	if err != nil {
		t.Fatal(err)
	}
	if tags := publisher.metadata("refs/tags/v2", annotated.Version).GetGit().GetTags(); len(tags) != 1 || !bytes.Equal(tags[0], tagObject) {
		t.Fatalf("the tag objects %d", len(tags))
	}
	if len(publisher.writer.server.uploads) != uploads {
		t.Fatal("a branch or tag at a held commit uploaded")
	}
	posted := publisher.posted()
	if _, err := publisher.publish("refs/tags/v2", &c1); !errors.Is(err, ErrEvsGitUpdateInvalid) || publisher.posted() != posted {
		t.Fatalf("a second push to a tag: %v", err)
	}
	_, exported := publisher.export("main", "feature", "refs/tags/v1", "refs/tags/v2")
	if len(exported.Refs) != 4 || exported.Refs[1].Tip != c1 || exported.Refs[3].Tip != tagOid {
		t.Fatalf("exported %+v", exported.Refs)
	}
}

// §11.19's bounds on the new tree, and a foreign commit with no import, each refused before any evs write.
func TestEvsLocalPublishRefusesBeforeAnyWrite(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	files := map[string]string{}
	for i := 0; i <= EvsDirectoryMaxChildCount; i += 1 {
		files[fmt.Sprintf("wide/%05d", i)] = "x"
	}
	wide := publisher.commit(files)
	if _, err := publisher.publish("main", &wide); !errors.Is(err, ErrEvsDirectoryFull) || publisher.posted() != 0 {
		t.Fatalf("a directory past 4,096 children: %v", err)
	}
	foreign, _ := publisher.mount.history.commit(publisher.tree(map[string]string{"a.txt": "a\n"}), evsTestId("another client").String()+evsCommitterDomain)
	if _, err := publisher.publish("main", &foreign); !errors.Is(err, ErrEvsGitUpdateInvalid) || publisher.posted() != 0 ||
		len(publisher.writer.server.uploads) != 0 {
		t.Fatalf("a foreign commit: %v", err)
	}
}

// A history blob is a diff against the same path's blob in its commit's first parent, which the readers hold, when the
// delta is smaller: the export applies it.
func TestEvsLocalPublishHistoryBlobDiffsOnItsFirstParent(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	text := strings.Repeat("a line of the plan that does not change\n", 64)
	c1 := publisher.commit(map[string]string{"plan.md": text})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	c2 := publisher.commit(map[string]string{"plan.md": text + "one more line\n"}, c1)
	c3 := publisher.commit(map[string]string{"plan.md": text + "the last line\n"}, c2)
	result, err := publisher.publish("main", &c3)
	if err != nil || result.HistoryBlobCount != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	blob := publisher.metadata("main", 2).GetGit().GetBlobs()[0]
	base := publisher.mount.history.blob(text)
	if !bytes.Equal(blob.GetBaseOid(), base[:]) || len(blob.GetRecords()) != 1 {
		t.Fatalf("the history blob %v", blob)
	}
	dir, _ := publisher.export("main")
	if content := evsTestGit(t, dir, "cat-file", "-p", hex.EncodeToString(c2[:])+":plan.md"); content != text+"one more line\n" {
		t.Fatalf("the history diff's blob %q", content)
	}
}

// 8.1's D: sealed commits past what one part holds go in parts, the slices past the changes in changeless parts after
// them, committed and read back by the export.
func TestEvsLocalPublishSealedCommitsPastOnePartGoInParts(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	publisher.mount.history.messagePad = strings.Repeat("a long commit message\n", 1500)
	tip := publisher.commit(map[string]string{"a.txt": "0\n"})
	for i := 1; i < 40; i += 1 {
		tip = publisher.commit(map[string]string{"a.txt": fmt.Sprint(i, "\n")}, tip)
	}
	result, err := publisher.publish("main", &tip)
	if err != nil || len(result.Commits) != 40 {
		t.Fatalf("%+v %v", result, err)
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	parts := len(world.commits[0].built.Parts)
	world.stateLock.Unlock()
	if parts < 2 {
		t.Fatalf("%d parts", parts)
	}
	if publisher.writer.server.leases == 0 {
		t.Fatal("a git-mode push in parts took no seal lease")
	}
	_, exported := publisher.export("main")
	if exported.Refs[0].Tip != tip {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// An import's push carries a foreign committer's commits under an EvsImport this admin signs over the push's own
// commits (QD-603), which the export's check verifies; the same commits without the import are refused before any
// write.
func TestEvsLocalPublishImportSignsItsOwnCommits(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	publisher.email = "someone@example.invalid"
	c1 := publisher.commit(map[string]string{"lib.c": "int lib;\n"})
	c2 := publisher.commit(map[string]string{"lib.c": "int lib2;\n"}, c1)
	if _, err := publisher.publish("main", &c2); !errors.Is(err, ErrEvsGitUpdateInvalid) {
		t.Fatalf("foreign commits with no import: %v", err)
	}
	result, err := publisher.publish("main", &c2, func(args *EvsLocalPublishArgs) { args.Import = true })
	if err != nil || len(result.Commits) != 2 {
		t.Fatalf("%+v %v", result, err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(publisher.metadata("main", 1).GetSignedImport(), signed); err != nil {
		t.Fatal(err)
	}
	evsImport := &protocol.EvsImport{}
	if err := proto.Unmarshal(signed.GetBody(), evsImport); err != nil {
		t.Fatal(err)
	}
	list := sha256.Sum256(append(bytes.Clone(c1[:]), c2[:]...))
	if evsImport.GetCount() != 2 || !bytes.Equal(evsImport.GetTipOid(), c2[:]) || !bytes.Equal(evsImport.GetOidListSha256(), list[:]) ||
		!bytes.Equal(evsImport.GetRefId(), publisher.ref("main").refId.Bytes()) {
		t.Fatalf("the import %v", evsImport)
	}
	_, exported := publisher.export("main")
	if exported.Refs[0].Tip != c2 {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A head past the update's base: a REKEY alone between leaves the tip, so the update is built again on the new head
// and commits; an UPDATE between moved the tip, ErrEvsGitTipMoved, with nothing more sent (8.2.5's 409 row).
func TestEvsLocalPublishJudgesAHeadPastItsBase(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	// a rekey of a.txt from a head-mode device: version 2, the tip still c1
	if _, err := publisher.writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path: "a.txt", Content: bytes.NewReader([]byte("a\n")), ForceCheckpoint: true, IfVersion: 1,
	}}}); err != nil {
		t.Fatal(err)
	}
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	result, err := publisher.publish("main", &c2)
	if err != nil || result.Version != 3 {
		t.Fatalf("after a rekey: %+v %v", result, err)
	}
	stale := *publisher.ref("main")
	c3 := publisher.commit(map[string]string{"a.txt": "a three\n"}, c2)
	if _, err := publisher.publish("main", &c3); err != nil {
		t.Fatal(err)
	}
	// a sibling built on version 3, which another update moved past
	*publisher.ref("main") = stale
	sibling := publisher.commit(map[string]string{"a.txt": "a sibling\n"}, c2)
	posted := publisher.posted()
	if _, err := publisher.publish("main", &sibling); !errors.Is(err, ErrEvsGitTipMoved) || publisher.posted() != posted {
		t.Fatalf("a sibling of a committed update: %v", err)
	}
}

// The checked payload of the ref's committed version.
func (self *evsTestPublisher) payload(name string, version uint64) *EvsCheckedPayload {
	self.t.Helper()
	world := self.writer.server.worldOf(self.ref(name).refId)
	world.stateLock.Lock()
	commit := world.commits[version-1]
	world.stateLock.Unlock()
	if 0 < len(commit.built.Parts) {
		checked, _, err := EvsCheckSeal(commit.parsed, commit.built.Parts)
		if err != nil {
			self.t.Fatal(err)
		}
		return checked
	}
	checked, err := EvsCheckPayload(commit.parsed, commit.built.Payload)
	if err != nil {
		self.t.Fatal(err)
	}
	return checked
}

// FS-5's overlay and 8.1's H: a branch created at a commit main holds is an overlay of main at that version, which the
// base search finds; its first push writes the one file it changed, a diff on main's entry that a reuse item cites,
// and no directory; removing an inherited file writes its directory whole without it and nothing for the file. The
// export, which replays the base first, holds every oid.
func TestEvsLocalPublishOverlayHoldsOnlyWhatItWrites(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	text := strings.Repeat("an inherited line\n", 64)
	m1 := publisher.commit(map[string]string{"src/a.go": text, "src/b.go": "b\n", "docs/readme": "r\n"})
	if _, err := publisher.publish("main", &m1); err != nil {
		t.Fatal(err)
	}
	mainRefId := publisher.ref("main").refId
	f1 := publisher.commit(map[string]string{"src/a.go": text + "a change\n", "src/b.go": "b\n", "docs/readme": "r\n"}, m1)
	created, err := publisher.publish("feature", &f1)
	if err != nil {
		t.Fatal(err)
	}
	base := &protocol.EvsOverlay{RefId: mainRefId.Bytes(), Version: 1}
	if !proto.Equal(created.Base, base) || !proto.Equal(publisher.metadata("feature", 1).GetBase(), base) {
		t.Fatalf("the overlay's base %v", created.Base)
	}
	payload := publisher.payload("feature", 1)
	if len(payload.Changes) != 1 || len(payload.ReuseList) != 1 || payload.ReuseList[0].RefId != mainRefId || !proto.Equal(payload.Base, base) {
		t.Fatalf("the overlay's first push: %d changes, %d reuse items", len(payload.Changes), len(payload.ReuseList))
	}
	feature := publisher.writer.server.worldOf(publisher.ref("feature").refId)
	feature.stateLock.Lock()
	if !proto.Equal(feature.base, base) || feature.paths["src"] != nil || feature.paths["src/a.go"] == nil {
		feature.stateLock.Unlock()
		t.Fatal("the overlay holds what it did not write")
	}
	feature.stateLock.Unlock()
	f2 := publisher.commit(map[string]string{"src/a.go": text + "a change\n", "docs/readme": "r\n"}, f1)
	if _, err := publisher.publish("feature", &f2); err != nil {
		t.Fatal(err)
	}
	feature.stateLock.Lock()
	src := feature.paths["src"]
	removedFile := feature.paths["src/b.go"]
	feature.stateLock.Unlock()
	if src == nil || len(src.rows) != 1 || removedFile != nil {
		t.Fatalf("the inherited file's directory, held whole: %v; the file's own state %v", src, removedFile)
	}
	dir, exported := publisher.export("main", "feature")
	if len(exported.Refs) != 2 || exported.Refs[1].Tip != f2 {
		t.Fatalf("exported %+v", exported.Refs)
	}
	if fsck := evsTestFsck(t, dir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
}

// The base search: the nearest tip on the new tip's first-parent line that the tip index holds, and any other branch
// whose tip the new tip descends from, the one leaving the fewest commits chosen; a tag is never a base, and no
// candidate leaves the branch with none.
func TestEvsLocalOverlayBaseSearch(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	m1 := publisher.commit(map[string]string{"a": "1\n"})
	m2 := publisher.commit(map[string]string{"a": "2\n"}, m1)
	if _, err := publisher.publish("main", &m2); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.publish("refs/tags/v2", &m2); err != nil {
		t.Fatal(err)
	}
	f1 := publisher.commit(map[string]string{"a": "2\n", "f": "f\n"}, m2)
	f2 := publisher.commit(map[string]string{"a": "2\n", "f": "f2\n"}, f1)
	publisher.mount.sync()
	found, err := publisher.mount.repo.overlayBase(context.Background(), evsTestId("new branch"), f2, publisher.state, 10000)
	if err != nil || found == nil || found.RefId != publisher.ref("main").refId || found.Version != 1 {
		t.Fatalf("found %+v: %v", found, err)
	}
	lone := publisher.commit(map[string]string{"z": "z\n"})
	publisher.mount.sync()
	if found, err := publisher.mount.repo.overlayBase(context.Background(), evsTestId("new branch"), lone, publisher.state, 10000); err != nil || found != nil {
		t.Fatalf("a branch sharing no commit: %+v %v", found, err)
	}
}

// §22.8's pushes row at the unit leg's size: a commit of 1,100 files on a new ref goes as one push in parts, past one
// part's 1,024 entry writes, and exports.
func TestEvsLocalPublishAWideCommitGoesInParts(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	files := map[string]string{}
	for i := 0; i < 1100; i += 1 {
		files[fmt.Sprintf("d%02d/f%04d.txt", i%20, i)] = fmt.Sprint("file ", i, "\n")
	}
	tip := publisher.commit(files)
	if _, err := publisher.publish("main", &tip); err != nil {
		t.Fatal(err)
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	parts := len(world.commits[0].built.Parts)
	world.stateLock.Unlock()
	if parts < 2 {
		t.Fatalf("%d parts", parts)
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != tip {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// §11.19's bounds on a new tree, checked on the changes before any read: a directory's names past 448 KiB, and a path
// of 33 components.
func TestEvsGitCheckLimitsRefusesNamesAndDepth(t *testing.T) {
	children := []*EvsGitChild{}
	for i := 0; i < 1000; i += 1 {
		children = append(children, &EvsGitChild{Name: []byte(fmt.Sprintf("%0500d", i)), Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE})
	}
	wide := &EvsGitPathChange{Path: "wide", Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, Children: children}
	if err := evsGitCheckLimits([]*EvsGitPathChange{wide}); !errors.Is(err, ErrEvsDirectoryFull) {
		t.Fatalf("names past 448 KiB: %v", err)
	}
	wide.Children = children[:100]
	if err := evsGitCheckLimits([]*EvsGitPathChange{wide}); err != nil {
		t.Fatalf("names within the bound: %v", err)
	}
	deep := &EvsGitPathChange{Path: strings.Repeat("d/", 32) + "f", Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE}
	if err := evsGitCheckLimits([]*EvsGitPathChange{deep}); !errors.Is(err, ErrEvsDirectoryFull) {
		t.Fatalf("a path of 33 components: %v", err)
	}
}
