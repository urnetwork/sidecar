//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-34's import tests (DESIGN-DETAILS 8.6's git-to-evs row): a foreign history imported in three pushes by a
// lowered ImportPushPartCount, each EvsImport over its own push's commits, which the export checks; a kill between
// pushes and a rerun that resumes from the target's tip; a merge of two disjoint histories through one helper ref,
// its step's push naming the helper as its one source and carrying the merge alone, the helper deleted at the end and
// replayed from its deleted history by a later export; a helper inside a helper; a kill at each of the five kill
// points with a rerun finishing alike and no second helper for a pair; --abandon; the hard bounds refused before any
// write for the step; the refusals before any fetch; and ur status's facts.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The tests' sync engine over a publisher's stand-in (EVS1-M2-35 builds the real one): Replay applies each version
// the world committed past what it applied, its sealed update's tip, a DELETE and a creating push's base, as replay
// does, keeping each ref's record, its refs/ur/evs/ tip, its local ref and the publisher's source state.
type evsTestSync struct {
	publisher *evsTestPublisher

	stateLock sync.Mutex
	refStates map[Id]*EvsGitRefState
	locks     map[Id]*sync.Mutex
}

func newEvsTestSync(publisher *evsTestPublisher) *evsTestSync {
	return &evsTestSync{publisher: publisher, refStates: map[Id]*EvsGitRefState{}, locks: map[Id]*sync.Mutex{}}
}

func (self *evsTestSync) SourceRef(ctx context.Context, refId Id) (*EvsGitSourceRef, bool, error) {
	return self.publisher.state.SourceRef(ctx, refId)
}

func (self *evsTestSync) Refs(ctx context.Context) ([]*EvsGitSourceRef, error) {
	return self.publisher.state.Refs(ctx)
}

func (self *evsTestSync) TipsOf(ctx context.Context, oid EvsGitOid) ([]*EvsGitSourceRef, error) {
	return self.publisher.state.TipsOf(ctx, oid)
}

func (self *evsTestSync) TipAt(ctx context.Context, refId Id, version uint64) (EvsGitOid, bool, error) {
	return self.publisher.state.TipAt(ctx, refId, version)
}

func (self *evsTestSync) Ref(ctx context.Context, refId Id) (*EvsGitRefState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.refStates[refId]
	if state == nil {
		return &EvsGitRefState{Chain: EvsChainStart(self.publisher.writer.world.repoId, refId)}, nil
	}
	copied := *state
	return &copied, nil
}

func (self *evsTestSync) LockPublish(ctx context.Context, refId Id) (func(), error) {
	self.stateLock.Lock()
	lock := self.locks[refId]
	if lock == nil {
		lock = &sync.Mutex{}
		self.locks[refId] = lock
	}
	self.stateLock.Unlock()
	lock.Lock()
	return lock.Unlock, nil
}

func (self *evsTestSync) Replay(ctx context.Context, refId Id) error {
	publisher := self.publisher
	world := publisher.writer.server.worldOf(refId)
	state, _ := self.Ref(ctx, refId)
	world.stateLock.Lock()
	head := uint64(len(world.commits))
	world.stateLock.Unlock()
	for version := state.Version + 1; version <= head; version += 1 {
		world.stateLock.Lock()
		commit := world.commits[version-1]
		world.stateLock.Unlock()
		state.Version, state.Chain = version, commit.chain
		if commit.parsed.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			continue
		}
		var checked *EvsCheckedPayload
		var err error
		if 0 < len(commit.built.Parts) {
			checked, _, err = EvsCheckSeal(commit.parsed, commit.built.Parts)
		} else {
			checked, err = EvsCheckPayload(commit.parsed, commit.built.Payload)
		}
		if err != nil {
			return err
		}
		keys := evsTestKeys(publisher.t, world.repoId, commit.parsed.Push.GetGeneration())
		metadata, err := EvsOpenMetadata(keys.manifest, checked.SealedMetadata)
		if err != nil {
			return err
		}
		git := metadata.GetGit()
		name := self.nameOf(refId, metadata)
		switch git.GetShape() {
		case protocol.EvsGitShape_EVS_GIT_DELETE:
			state.LastTip, state.Tip, state.Deleted = state.Tip, nil, true
			if name != "" {
				publisher.mount.repo.Git(ctx, "update-ref", "-d", EvsGitRefOfName([]byte(name)))
			}
		case protocol.EvsGitShape_EVS_GIT_UPDATE:
			tip := EvsGitOid(git.GetNewTip())
			state.Tip, state.Deleted, state.LastTip = &tip, false, nil
			if metadata.GetBase() != nil {
				state.Base = metadata.GetBase()
			}
			// refs/ur/evs/<ref> at the tip evs holds, written straight, so the bare repository holds only what came in
			publisher.mount.repo.Git(ctx, "update-ref", evsLocalEvsRefPrefix+evsUrlId(refId), hex.EncodeToString(tip[:]))
			if name != "" {
				publisher.mount.repo.Git(ctx, "update-ref", EvsGitRefOfName([]byte(name)), hex.EncodeToString(tip[:]))
			}
			publisher.order += 1
			kind := protocol.EvsRefKind_EVS_REF_SHARED
			if _, ok := EvsOwnedRefOwner([]byte(name)); ok {
				kind = protocol.EvsRefKind_EVS_REF_OWNED
			}
			publisher.state.applied(&EvsGitSourceRef{
				RefId: refId, Kind: kind, Version: version, Tip: tip, AppliedOrder: publisher.order,
				Tag: strings.HasPrefix(name, evsGitTagRefPrefix),
			})
		}
	}
	self.stateLock.Lock()
	self.refStates[refId] = state
	self.stateLock.Unlock()
	return nil
}

// The ref's name, from its creating push's sealed copy, remembered on the publisher.
func (self *evsTestSync) nameOf(refId Id, metadata *protocol.EvsSealedMetadata) string {
	for name, ref := range self.publisher.refs {
		if ref.refId == refId {
			return name
		}
	}
	if name := metadata.GetRefName(); len(name) != 0 {
		self.publisher.refs[string(name)] = &evsTestPublishedRef{refId: refId}
		return string(name)
	}
	return ""
}

// A publisher's mount registered as its client's local tier, with the tests' sync engine, and the world making each
// ref a push names on first use.
func newEvsTestImporter(t *testing.T) (*evsTestPublisher, *evsTestSync) {
	t.Helper()
	publisher := newEvsTestPublisher(t)
	publisher.writer.world.autoRefs = true
	client := publisher.writer.test.client
	mounts := &EvsMounts{client: client, git: publisher.mount.repo.git, repoIdMounts: map[Id]*EvsLocalRepo{publisher.writer.world.repoId: publisher.mount.repo}}
	client.stateLock.Lock()
	client.localTier = mounts
	client.stateLock.Unlock()
	fake := newEvsTestSync(publisher)
	mounts.SetSync(fake)
	settings := client.settings
	// 16 commits a part, a push cut at one part, and a step past one part oversized
	settings.ImportCommitEstimate = 64 * 1024
	settings.ImportPushPartCount = 1
	settings.ImportStepPartCount = 1
	return publisher, fake
}

// A foreign history written to a repository of its own, the tests' source, its ref at tip.
func (self *evsTestPublisher) sourceRepository(tip EvsGitOid) string {
	self.t.Helper()
	dir := filepath.Join(self.t.TempDir(), "source.git")
	self.mount.history.writeRepository(dir, map[string]EvsGitOid{"refs/heads/main": tip})
	evsTestGit(self.t, dir, "symbolic-ref", "HEAD", "refs/heads/main")
	return dir
}

// A line of count commits by a foreign committer on parent, nil for a root, each changing file.
func (self *evsTestPublisher) foreignLine(count int, file string, parent *EvsGitOid) EvsGitOid {
	self.t.Helper()
	email := self.email
	self.email = "someone@example.invalid"
	defer func() { self.email = email }()
	var tip EvsGitOid
	for i := 0; i < count; i += 1 {
		files := map[string]string{file: fmt.Sprint(file, " ", i, "\n")}
		if parent != nil {
			tip = self.commit(files, *parent)
		} else {
			tip = self.commit(files)
		}
		at := tip
		parent = &at
	}
	return tip
}

// A foreign merge of parents whose tree holds files.
func (self *evsTestPublisher) foreignMerge(files map[string]string, parents ...EvsGitOid) EvsGitOid {
	email := self.email
	self.email = "someone@example.invalid"
	defer func() { self.email = email }()
	return self.commit(files, parents...)
}

// A foreign history of 40 commits comes in as three pushes cut at 16 commits, each signing its own commits, and
// exports with the original's oids; nothing of it needs a helper.
func TestEvsLocalImportCutsAHistoryIntoPushes(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	tip := publisher.foreignLine(40, "lib.c", nil)
	dir := publisher.sourceRepository(tip)
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PushIds) != 3 || result.Tip != tip || len(result.Helpers) != 0 {
		t.Fatalf("result %+v", result)
	}
	for version := uint64(1); version <= 3; version += 1 {
		if len(publisher.metadata("main", version).GetSignedImport()) == 0 {
			t.Fatalf("push %d carries no import", version)
		}
	}
	dir, exported := publisher.export("main")
	if exported.Refs[0].Tip != tip {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
	if fsck := evsTestFsck(t, dir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	status, err := publisher.writer.test.client.localTier.(*EvsMounts).ImportStatus(context.Background(), publisher.writer.world.repoId)
	if err != nil || len(status.Unfinished) != 0 || len(status.Leftover) != 0 {
		t.Fatalf("status %+v %v", status, err)
	}
}

// An import killed after its first push leaves an unfinished import ur status lists at the cut it reached; a rerun
// resumes from the target's tip and sends only the rest.
func TestEvsLocalImportResumesAfterAKill(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	tip := publisher.foreignLine(40, "lib.c", nil)
	dir := publisher.sourceRepository(tip)
	killed := errors.New("killed")
	evsImportKillHook = func(point string) error {
		if point == "step_sent" {
			return killed
		}
		return nil
	}
	t.Cleanup(func() { evsImportKillHook = nil })
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, killed) {
		t.Fatalf("the killed run: %v", err)
	}
	status, err := publisher.writer.test.client.localTier.(*EvsMounts).ImportStatus(context.Background(), publisher.writer.world.repoId)
	if err != nil || len(status.Unfinished) != 1 || status.Unfinished[0].Reached == nil {
		t.Fatalf("status %+v %v", status, err)
	}
	evsImportKillHook = nil
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil || len(result.PushIds) != 2 || result.Tip != tip {
		t.Fatalf("the rerun %+v %v", result, err)
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != tip {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A merge of two disjoint histories whose step passes one push comes in through one helper ref: the side brought to
// the helper by its own cut pushes, the step's push carrying the merge alone and naming the helper as its one source,
// the helper deleted at the end and replayed from its deleted history by an export.
func TestEvsLocalImportBringsAnOversizedSideThroughAHelper(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Helpers) != 1 || result.Tip != merge {
		t.Fatalf("result %+v", result)
	}
	sidecarId, importId, n, ok := ParseEvsImportHelperRefName(result.Helpers[0])
	if !ok || sidecarId != publisher.writer.world.signer.sidecarId || importId != result.ImportId || n != 1 {
		t.Fatalf("the helper %q", result.Helpers[0])
	}
	helperRef := publisher.ref(string(result.Helpers[0]))
	helper := publisher.writer.server.worldOf(helperRef.refId)
	helper.stateLock.Lock()
	helperVersions, deleted := len(helper.commits), helper.deleted
	helper.stateLock.Unlock()
	if helperVersions != 3 || !deleted {
		t.Fatalf("the helper: %d versions, deleted %t", helperVersions, deleted)
	}
	// main: the line's cut, then the merge alone naming the helper
	world := publisher.writer.world
	world.stateLock.Lock()
	mainVersions := len(world.commits)
	world.stateLock.Unlock()
	last := publisher.metadata("main", uint64(mainVersions))
	if len(last.GetCommits()) != 1 || len(last.GetGit().GetSources()) != 1 ||
		Id(last.GetGit().GetSources()[0].GetRefId()) != helperRef.refId {
		t.Fatalf("the merge's push: %d commits, sources %v", len(last.GetCommits()), last.GetGit().GetSources())
	}
	dir, exported := publisher.export("main")
	if exported.Refs[0].Tip != merge {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
	if fsck := evsTestFsck(t, dir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	status, err := publisher.writer.test.client.localTier.(*EvsMounts).ImportStatus(context.Background(), publisher.writer.world.repoId)
	if err != nil || len(status.Unfinished) != 0 || len(status.Leftover) != 0 {
		t.Fatalf("status %+v %v", status, err)
	}
}

// A side that itself merges an oversized side makes a helper inside a helper, numbered in the order first needed,
// and the most deeply nested is deleted first.
func TestEvsLocalImportNestsAHelperInsideAHelper(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	line := publisher.foreignLine(2, "main.c", nil)
	inner := publisher.foreignLine(20, "inner.c", nil)
	sideLine := publisher.foreignLine(2, "side.c", nil)
	side := publisher.foreignMerge(map[string]string{"side.c": "side.c 1\n", "inner.c": "inner.c 19\n"}, sideLine, inner)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 1\n", "side.c": "side.c 1\n", "inner.c": "inner.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Helpers) != 2 || result.Tip != merge {
		t.Fatalf("result %+v", result)
	}
	for i, helperName := range result.Helpers {
		if _, _, n, ok := ParseEvsImportHelperRefName(helperName); !ok || n != uint32(i+1) {
			t.Fatalf("helper %d is %q", i, helperName)
		}
		world := publisher.writer.server.worldOf(publisher.ref(string(helperName)).refId)
		world.stateLock.Lock()
		deleted := world.deleted
		world.stateLock.Unlock()
		if !deleted {
			t.Fatalf("helper %q stands", helperName)
		}
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != merge {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A kill at each of the five kill points, then a rerun, finishes with the same tip, makes no second helper for a pair
// and leaves no helper standing.
func TestEvsLocalImportKilledAtEachPointFinishesOnARerun(t *testing.T) {
	for _, point := range []string{"helper_recorded", "helper_pushed", "helper_done", "step_sent", "clean_deleted"} {
		publisher, _ := newEvsTestImporter(t)
		line := publisher.foreignLine(3, "main.c", nil)
		side := publisher.foreignLine(20, "side.c", nil)
		merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
		dir := publisher.sourceRepository(merge)
		killed := errors.New("killed at " + point)
		kills := 0
		evsImportKillHook = func(at string) error {
			if at == point && kills == 0 {
				kills += 1
				return killed
			}
			return nil
		}
		if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, killed) {
			evsImportKillHook = nil
			t.Fatalf("%s: the killed run: %v", point, err)
		}
		result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
		evsImportKillHook = nil
		if err != nil || result.Tip != merge {
			t.Fatalf("%s: the rerun %+v %v", point, result, err)
		}
		records, err := evsImportRecords(publisher.writer.test.client.args.Store, publisher.writer.world.repoId)
		if err != nil || len(records) != 0 {
			t.Fatalf("%s: records %d %v", point, len(records), err)
		}
		helperName := EvsImportHelperRefName(publisher.writer.world.signer.sidecarId, result.ImportId, 1)
		world := publisher.writer.server.worldOf(publisher.ref(string(helperName)).refId)
		world.stateLock.Lock()
		deleted := world.deleted
		world.stateLock.Unlock()
		second := publisher.writer.world.otherOfId(publisher.ref(string(EvsImportHelperRefName(publisher.writer.world.signer.sidecarId, result.ImportId, 2))).refId)
		second.stateLock.Lock()
		secondVersions := len(second.commits)
		second.stateLock.Unlock()
		if !deleted || secondVersions != 0 {
			t.Fatalf("%s: helper 1 deleted %t, helper 2 has %d versions", point, deleted, secondVersions)
		}
		if _, exported := publisher.export("main"); exported.Refs[0].Tip != merge {
			t.Fatalf("%s: exported %+v", point, exported.Refs[0])
		}
	}
}

// --abandon ends an unfinished import: its helpers deleted, its record and source ref dropped, the target left at the
// cut it reached.
func TestEvsLocalImportAbandon(t *testing.T) {
	publisher, engine := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	killed := errors.New("killed")
	evsImportKillHook = func(point string) error {
		if point == "helper_done" {
			return killed
		}
		return nil
	}
	t.Cleanup(func() { evsImportKillHook = nil })
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, killed) {
		t.Fatalf("the killed run: %v", err)
	}
	evsImportKillHook = nil
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir, Abandon: true})
	if err != nil {
		t.Fatal(err)
	}
	records, _ := evsImportRecords(publisher.writer.test.client.args.Store, publisher.writer.world.repoId)
	if len(records) != 0 {
		t.Fatal("the record outlived --abandon")
	}
	helperName := EvsImportHelperRefName(publisher.writer.world.signer.sidecarId, result.ImportId, 1)
	helperState, _ := engine.Ref(context.Background(), publisher.ref(string(helperName)).refId)
	mainState, _ := engine.Ref(context.Background(), publisher.ref("main").refId)
	if !helperState.Deleted || mainState.Tip == nil || *mainState.Tip != line {
		t.Fatalf("after --abandon: helper deleted %t, main at %v", helperState.Deleted, mainState.Tip)
	}
	if out := evsTestGit(t, publisher.mount.repo.BareDir, "for-each-ref", evsLocalImportRefPrefix); out != "" {
		t.Fatalf("the source ref outlived --abandon: %s", out)
	}
}

// The hard bounds of a step, each refused before any evs write for the step, naming the commit: a step of one commit
// too large for a push, and helpers past ImportHelperDepth.
func TestEvsLocalImportRefusesAStepPastItsBounds(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	publisher.writer.test.client.settings.ImportStepPartCount = 0
	tip := publisher.foreignLine(1, "lib.c", nil)
	dir := publisher.sourceRepository(tip)
	posted := publisher.posted()
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, ErrEvsImportStepBound) ||
		!strings.Contains(err.Error(), hex.EncodeToString(tip[:])) || publisher.posted() != posted {
		t.Fatalf("a one-commit step past the bound: %v", err)
	}
	nested, _ := newEvsTestImporter(t)
	nested.writer.test.client.settings.ImportHelperDepth = 0
	line := nested.foreignLine(3, "main.c", nil)
	side := nested.foreignLine(20, "side.c", nil)
	merge := nested.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	nestedDir := nested.sourceRepository(merge)
	if _, err := nested.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: nestedDir}); !errors.Is(err, ErrEvsImportStepBound) ||
		!strings.Contains(err.Error(), hex.EncodeToString(merge[:])) {
		t.Fatalf("a helper past ImportHelperDepth: %v", err)
	}
}

// The refusals before anything is fetched: another sidecar's owned ref, a target under ur/<this sidecar>/import/, a
// tag, a shared target with a tip, a sha256 repository, and a caller that is no repo admin.
func TestEvsLocalImportRefusesBeforeAnyFetch(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	tip := publisher.foreignLine(1, "lib.c", nil)
	dir := publisher.sourceRepository(tip)
	sidecarId := publisher.writer.world.signer.sidecarId
	for _, target := range [][]byte{
		EvsOwnedRefName(evsTestId("another sidecar"), "work"),
		EvsImportHelperRefName(sidecarId, NewEvsImportId(), 1),
		[]byte("refs/tags/v1"),
	} {
		if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir, Target: target}); !errors.Is(err, ErrEvsImportRefused) {
			t.Errorf("target %q: %v", target, err)
		}
	}
	own := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &own); err != nil {
		t.Fatal(err)
	}
	engine := publisher.writer.test.client.localTier.(*EvsMounts).gitSync().(*evsTestSync)
	if err := engine.Replay(context.Background(), publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, ErrEvsImportRefused) {
		t.Errorf("a shared target with a tip: %v", err)
	}
	sha256Dir := filepath.Join(t.TempDir(), "sha256.git")
	evsTestGit(t, filepath.Dir(sha256Dir), "init", "-q", "--bare", "--object-format=sha256", sha256Dir)
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: sha256Dir, Target: []byte("other")}); !errors.Is(err, ErrEvsImportRefused) {
		t.Errorf("a sha256 repository: %v", err)
	}
	publisher.writer.world.config.repo.Admins = nil
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir, Target: []byte("other")}); !errors.Is(err, ErrEvsImportRefused) {
		t.Errorf("no repo admin: %v", err)
	}
	if out := evsTestGit(t, publisher.mount.repo.BareDir, "for-each-ref", evsLocalImportRefPrefix); out != "" {
		t.Fatalf("a refused import fetched: %s", out)
	}
}

// An octopus merge of three sides, two of them oversized, makes a helper for each of the two, the larger first, and
// its step's push carries the third side's commits with the merge, naming both helpers.
func TestEvsLocalImportOctopusWithTwoOversizedSides(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	line := publisher.foreignLine(2, "main.c", nil)
	big := publisher.foreignLine(24, "big.c", nil)
	other := publisher.foreignLine(20, "other.c", nil)
	small := publisher.foreignLine(2, "small.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 1\n", "big.c": "big.c 23\n", "other.c": "other.c 19\n", "small.c": "small.c 1\n"},
		line, big, other, small)
	dir := publisher.sourceRepository(merge)
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Helpers) != 2 || result.Tip != merge {
		t.Fatalf("result %+v", result)
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	mainVersions := len(world.commits)
	world.stateLock.Unlock()
	last := publisher.metadata("main", uint64(mainVersions))
	if len(last.GetCommits()) != 3 || len(last.GetGit().GetSources()) != 2 {
		t.Fatalf("the merge's push: %d commits, %d sources", len(last.GetCommits()), len(last.GetGit().GetSources()))
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != merge {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A side forked from the target's line gets a helper that is an overlay of the target at the cut it forked from.
func TestEvsLocalImportHelperOfAForkedSideIsAnOverlay(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", &line)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil || len(result.Helpers) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	helper := publisher.writer.server.worldOf(publisher.ref(string(result.Helpers[0])).refId)
	helper.stateLock.Lock()
	base := helper.base
	helper.stateLock.Unlock()
	if base == nil || Id(base.GetRefId()) != publisher.ref("main").refId {
		t.Fatalf("the helper's base %v", base)
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != merge {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A helper its owner deletes while it is open is abandoned on the rerun, the step being oversized still, and its pair
// numbered again; the deleted helper's history, its refs/ur/evs/ tip kept at its last tip, still serves.
func TestEvsLocalImportReplacesAHelperDeletedMidImport(t *testing.T) {
	publisher, engine := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(40, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 39\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	killed := errors.New("killed")
	evsImportKillHook = func(point string) error {
		if point == "helper_pushed" {
			return killed
		}
		return nil
	}
	t.Cleanup(func() { evsImportKillHook = nil })
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, killed) {
		t.Fatalf("the killed run: %v", err)
	}
	evsImportKillHook = nil
	records, err := evsImportRecords(publisher.writer.test.client.args.Store, publisher.writer.world.repoId)
	if err != nil || len(records) != 1 {
		t.Fatalf("records %d %v", len(records), err)
	}
	importId, _ := ParseEvsImportId(records[0].ImportId)
	first := EvsImportHelperRefName(publisher.writer.world.signer.sidecarId, importId, 1)
	firstId := publisher.ref(string(first)).refId
	// its owner deletes it with git push --delete: a DELETE push, replayed
	state, _ := engine.Ref(context.Background(), firstId)
	if _, err := EvsLocalPublish(context.Background(), &EvsLocalPublishArgs{
		Mount: publisher.mount.repo, Repo: publisher.writer.repo, RefName: first, Old: state.Tip, BaseVersion: state.Version,
		BaseChain: state.Chain, State: engine,
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Replay(context.Background(), firstId); err != nil {
		t.Fatal(err)
	}
	result, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir})
	if err != nil || result.Tip != merge || len(result.Helpers) != 1 {
		t.Fatalf("the rerun %+v %v", result, err)
	}
	if _, _, n, _ := ParseEvsImportHelperRefName(result.Helpers[0]); n != 2 {
		t.Fatalf("the replacement %q", result.Helpers[0])
	}
	if _, exported := publisher.export("main"); exported.Refs[0].Tip != merge {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
}

// A helper's push refused for good stops the import with the target at the cut before the step, its record kept;
// --abandon then drops the record, and the helper, which never took a version, needs no DELETE.
func TestEvsLocalImportRefusedHelperPushThenAbandon(t *testing.T) {
	publisher, engine := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	evsImportKillHook = func(point string) error {
		if point == "helper_recorded" {
			publisher.writer.server.stateLock.Lock()
			publisher.writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusForbidden, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE}}}
			publisher.writer.server.stateLock.Unlock()
		}
		return nil
	}
	t.Cleanup(func() { evsImportKillHook = nil })
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE) {
		t.Fatalf("a refused helper push: %v", err)
	}
	evsImportKillHook = nil
	mainState, _ := engine.Ref(context.Background(), publisher.ref("main").refId)
	if mainState.Tip == nil || *mainState.Tip != line {
		t.Fatalf("the target at %v, not the cut before the step", mainState.Tip)
	}
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir, Abandon: true}); err != nil {
		t.Fatal(err)
	}
	if records, _ := evsImportRecords(publisher.writer.test.client.args.Store, publisher.writer.world.repoId); len(records) != 0 {
		t.Fatal("the record outlived --abandon")
	}
}

// A step needing a helper past ImportHelperCount is refused before any write for it, naming the merge.
func TestEvsLocalImportRefusesHelpersPastTheirCount(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	publisher.writer.test.client.settings.ImportHelperCount = 0
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, ErrEvsImportStepBound) ||
		!strings.Contains(err.Error(), hex.EncodeToString(merge[:])) {
		t.Fatalf("a helper past ImportHelperCount: %v", err)
	}
}

// Imported history git holds and the codec refuses, a raw tree with a zero-padded mode, comes in as bytes and exports
// with the original's oids, git fsck saying of the export what it says of the original.
func TestEvsLocalImportCarriesRawTrees(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	history := publisher.mount.history
	lib := history.blob("int lib;\n")
	inner := history.tree(map[string]EvsGitOid{"x": history.blob("x\n")}, nil)
	vendorBytes := append(append([]byte("100644 lib.c\x00"), lib[:]...), append([]byte("040000 sub\x00"), inner[:]...)...)
	vendor, _ := history.store.WriteGitObject(evsGitTreeKind, vendorBytes)
	publisher.writer.server.know("vendor/lib.c", "vendor/sub/x", "README")
	tip, _ := history.commit(history.tree(map[string]EvsGitOid{"README": history.blob("r\n")}, map[string]EvsGitOid{"vendor": vendor}), "someone@example.invalid")
	dir := publisher.sourceRepository(tip)
	originalFsck := evsTestFsck(t, dir)
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	exportDir, exported := publisher.export("main")
	if exported.Refs[0].Tip != tip {
		t.Fatalf("exported %+v", exported.Refs[0])
	}
	if fsck := evsTestFsck(t, exportDir); strings.Join(fsck, "\n") != strings.Join(originalFsck, "\n") {
		t.Fatalf("the export's fsck %v, the original's %v", fsck, originalFsck)
	}
}

// ur status's facts: an import whose record is lost leaves its helper refs named by no record, which status lists as
// leftover for their owner to remove.
func TestEvsLocalImportStatusListsLeftoverHelpers(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	line := publisher.foreignLine(3, "main.c", nil)
	side := publisher.foreignLine(20, "side.c", nil)
	merge := publisher.foreignMerge(map[string]string{"main.c": "main.c 2\n", "side.c": "side.c 19\n"}, line, side)
	dir := publisher.sourceRepository(merge)
	killed := errors.New("killed")
	evsImportKillHook = func(point string) error {
		if point == "helper_done" {
			return killed
		}
		return nil
	}
	t.Cleanup(func() { evsImportKillHook = nil })
	if _, err := publisher.writer.repo.Import(context.Background(), &EvsImportArgs{Dir: dir}); !errors.Is(err, killed) {
		t.Fatalf("the killed run: %v", err)
	}
	evsImportKillHook = nil
	mounts := publisher.writer.test.client.localTier.(*EvsMounts)
	status, err := mounts.ImportStatus(context.Background(), publisher.writer.world.repoId)
	if err != nil || len(status.Unfinished) != 1 || len(status.Unfinished[0].Helpers) != 1 || len(status.Leftover) != 0 {
		t.Fatalf("status %+v %v", status, err)
	}
	// local/<repo>/ lost: the record goes with it
	records, _ := evsImportRecords(publisher.writer.test.client.args.Store, publisher.writer.world.repoId)
	importId, _ := ParseEvsImportId(records[0].ImportId)
	name, _ := EvsLocalKey{Family: EvsLocalImports, ImportId: importId}.Name()
	if err := publisher.writer.test.client.args.Store.Remove(evsLocalStatePrefix(publisher.writer.world.repoId) + name); err != nil {
		t.Fatal(err)
	}
	status, err = mounts.ImportStatus(context.Background(), publisher.writer.world.repoId)
	helperName := EvsImportHelperRefName(publisher.writer.world.signer.sidecarId, importId, 1)
	if err != nil || len(status.Unfinished) != 0 || len(status.Leftover) != 1 || string(status.Leftover[0]) != string(helperName) {
		t.Fatalf("status %+v %v", status, err)
	}
}
