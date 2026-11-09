package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One change a world push makes: a file's write or removal, or a directory's delta or removal.
type worldChange struct {
	path sidecar.EvsTokenPath
	base uint64
	// the version it writes; 0 removes the path
	version   uint64
	directory bool
	// a directory delta's names added and tokens removed
	names         []sidecar.EvsToken
	removedTokens []sidecar.EvsToken
}

// One committed push of the world, as the brute force reads history.
type worldPush struct {
	version uint64
	changes []*worldChange
}

// A ref's committed history on fake clusters: real statements and records through the batch writer, a head moved
// by HeadStore, and folds into idx/ by the real Folder (fold.go), so the newest rule runs over what evs would read.
// The brute force replays history alone.
type evsWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	cluster  sidecar.BlobCluster
	settings *EvsSettings
	heads    *HeadStore
	batches  *BatchWriter
	builder  *sidecar.EvsStatementBuilder
	paidCtx  context.Context
	repoId   sidecar.Id
	refId    sidecar.Id
	signerId sidecar.Id
	head     *EvsStoredHead
	history  []*worldPush
	pushSeq  int
	// the folds' process, and the metadata cluster as the engine sees it, writes held to the budget
	folder       *Folder
	budgetedBlob sidecar.BlobStore
	foldCluster  sidecar.BlobCluster
}

func newEvsWorld(t *testing.T) *evsWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", connectNetworkId(), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	signerId := testId("signer")
	world := &evsWorld{
		t: t, ctx: ctx, clock: clock, host: host, cluster: cluster, settings: settings,
		heads:   NewHeadStore(clock, host.ClockCheck, host.Redis, settings, sidecar.NewNoopLogger()),
		batches: NewBatchWriter(ctx, clock, host.Blobs, nil, settings, sidecar.NewNoopLogger()),
		builder: sidecar.NewEvsStatementBuilder(func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: bytes.Clone(body), SignerId: signerId.Bytes(), Signature: make([]byte, 64), Type: uint32(signedType)}, nil
		}),
		paidCtx:  grant.Context(),
		repoId:   testId("repo"),
		refId:    testId("ref"),
		signerId: signerId,
		head:     &EvsStoredHead{},
	}
	world.budgetedBlob = NewBudgetedBlobs(host.Blobs)
	world.foldCluster, err = world.budgetedBlob.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		t.Fatal(err)
	}
	world.folder = NewFolder(ctx, clock, host.ClockCheck, world.budgetedBlob, host.Budget, world.heads, NewRecordCache(settings),
		NewRepoCache(clock, settings), priceTable, settings, sidecar.NewNoopLogger())
	world.putRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	return world
}

// Writes the repo's repo/ in state, which every fold write rereads (§11.13's skip row).
func (self *evsWorld) putRepo(state protocol.EvsRepoState) {
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: state, Format: 1,
		NetworkId: testId("network-a").Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := self.cluster.Head(self.ctx, RepoKey(self.repoId))
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		_, err = self.cluster.PutIfNoneMatch(self.paidCtx, RepoKey(self.repoId), repoBytes, nil)
	case err == nil:
		_, err = self.cluster.PutIfMatch(self.paidCtx, RepoKey(self.repoId), object.Etag, repoBytes, nil)
	}
	if err != nil {
		self.t.Fatal(err)
	}
}

// A token from a label.
func worldToken(label string) sidecar.EvsToken {
	return sidecar.EvsToken(testId("token-" + label))
}

// A token path from labels.
func worldPath(labels ...string) sidecar.EvsTokenPath {
	tokenPath := sidecar.EvsTokenPath{}
	for _, label := range labels {
		tokenPath = append(tokenPath, worldToken(label))
	}
	return tokenPath
}

// The entry version bytes a change writes.
func (self *evsWorld) entryVersion(pushId sidecar.Id, baseVersion uint64, change *worldChange) []byte {
	entry := &protocol.EvsEntryVersion{
		Version: change.version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: self.clock.Now().UnixMilli(),
		PaddedSize: 4096,
	}
	if change.directory {
		entry.Kind = uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		names := &protocol.EvsNameTable{}
		for _, token := range change.names {
			names.Names = append(names.Names, &protocol.EvsName{Token: bytes.Clone(token[:]), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed")})
		}
		for _, token := range change.removedTokens {
			names.RemovedTokens = append(names.RemovedTokens, bytes.Clone(token[:]))
		}
		entry.Names = names
	} else {
		entry.Kind = uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)
		entry.SealedFields = []byte(fmt.Sprintf("sealed fields %d", change.version))
		entry.Chain = []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}}
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// Commits a push of changes at the head's next version, its record through the batch writer and its window entry
// appended, and returns that version.
func (self *evsWorld) push(changes ...*worldChange) uint64 {
	self.pushSeq += 1
	pushId := testId(fmt.Sprintf("push-%d", self.pushSeq))
	baseVersion := self.head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, self.refId)
	if !self.head.Absent() && 0 < baseVersion {
		baseChain = [32]byte(self.head.Head.GetChain())
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: 1, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: testId("client"), TimeMs: self.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"),
	}
	for _, change := range changes {
		planned := &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: change.base}
		if change.version != 0 {
			planned.EntryVersion = self.entryVersion(pushId, baseVersion, change)
		}
		plan.Changes = append(plan.Changes, planned)
	}
	built, err := self.builder.Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: self.refId, PushId: pushId,
		SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	place, err := self.batches.Append(self.paidCtx, "meta-1", record)
	if err != nil {
		self.t.Fatal(err)
	}
	changedPaths := make([]sidecar.EvsTokenPath, len(changes))
	createsPath := false
	for i, change := range changes {
		changedPaths[i] = change.path
		createsPath = createsPath || (change.base == 0 && change.version != 0)
	}
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(built.Statement.Push.GetChangesRoot()) != 0 {
		coveringPrefixes = built.Statement.ChangedPrefixes
	}
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, coveringPrefixes, createsPath, place)
	next := CloneEvsHead(self.head.Head)
	if self.head.Absent() {
		next = &protocol.EvsHead{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
			PathEpoch: &protocol.EvsPathEpoch{Current: 1}, WindowBaseChain: baseChain[:],
		}
	}
	chain := sidecar.EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	next.Version = baseVersion + 1
	next.Chain = chain[:]
	next.PushId = pushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
	self.history = append(self.history, &worldPush{version: next.Version, changes: changes})
	return next.Version
}

// Drops the window's versions at or below through, as a page-out leaves them in log pages: the window then starts
// at through+1.
func (self *evsWorld) pageOut(through uint64) {
	next := CloneEvsHead(self.head.Head)
	first := EvsHeadWindowFirstVersion(next)
	if through+1 <= first {
		return
	}
	cut := int(through+1-first) * sidecar.EvsWindowEntryByteCount
	next.Window = bytes.Clone(next.GetWindow()[cut:])
	chain := sidecar.EvsChainStart(self.repoId, self.refId)
	for _, version := range self.history {
		if version.version > through {
			break
		}
		// the chain at the cut is what the base chain names; the test only needs it present
		chain = sha256Of(chain[:])
	}
	next.WindowBaseChain = chain[:]
	next.Fence += 1
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
}

// A stand-in hash for pageOut's base chain.
func sha256Of(value []byte) [32]byte {
	var digest [32]byte
	copy(digest[:], value)
	digest[0] ^= 1
	return digest
}

// A path's state before a version, by the brute force: whether it stands, its last version, and its removal's.
type bruteState struct {
	exists         bool
	version        uint64
	removalVersion uint64
	commitVersion  uint64
	directory      bool
}

// Every path's state after replaying history through version, as §11.7 defines each event.
func (self *evsWorld) bruteForce(through uint64) map[string]*bruteState {
	states := map[string]*bruteState{}
	stateOf := func(tokenPath sidecar.EvsTokenPath) *bruteState {
		key := string(tokenPath.Bytes())
		if states[key] == nil {
			states[key] = &bruteState{}
		}
		return states[key]
	}
	for _, push := range self.history {
		if through < push.version {
			break
		}
		for _, change := range push.changes {
			state := stateOf(change.path)
			if change.version == 0 {
				// this path's removal, and every standing path below it
				for key, below := range states {
					if below.exists && (key == string(change.path.Bytes()) || bytes.HasPrefix([]byte(key), change.path.Bytes())) {
						below.removalVersion = below.version + 1
						below.exists = false
						below.version = 0
						below.commitVersion = push.version
					}
				}
				state.removalVersion = change.base + 1
				state.exists = false
				state.version = 0
				state.commitVersion = push.version
				continue
			}
			state.exists = true
			state.version = change.version
			state.removalVersion = 0
			state.commitVersion = push.version
			state.directory = change.directory
		}
	}
	return states
}

// Folds the window's versions through through by the real fold, then raises folded_through to the folder's horizon
// by a fence write, standing in for the folding process's next commit (§11.7's horizon row).
func (self *evsWorld) fold(through uint64) {
	self.t.Helper()
	result, err := self.folder.Fold(self.ctx, &EvsFoldRequest{
		Cluster: self.foldCluster, RepoId: self.repoId, RefId: self.refId, Through: through, Rank: sidecar.WriteP2RankFold,
	})
	if err != nil {
		self.t.Fatalf("fold through %d: %v", through, err)
	}
	if result.Superseded {
		self.t.Fatalf("fold through %d superseded", through)
	}
	self.raiseHorizon()
}

// Raises the head's folded_through to the folder's horizon by a fence write, as the folding process's next commit
// would.
func (self *evsWorld) raiseHorizon() {
	self.t.Helper()
	horizon := self.folder.Horizon(self.repoId, self.refId, self.head.Head)
	if horizon <= self.head.Head.GetFoldedThrough() {
		return
	}
	next := CloneEvsHead(self.head.Head)
	next.FoldedThrough = horizon
	next.Fence += 1
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
}

// The newest of path at the world's head, its entry read after the head.
func (self *evsWorld) newest(path sidecar.EvsTokenPath) (*EvsNewest, error) {
	head, err := self.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, 1, path, head.Head.GetFoldedThrough())
	if err != nil {
		self.t.Fatal(err)
	}
	return Newest(self.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(self.settings), self.cluster, self.repoId, self.refId))
}

// Asserts Newest against the brute force for path at the head.
func (self *evsWorld) requireNewest(path sidecar.EvsTokenPath) *EvsNewest {
	self.t.Helper()
	newest, err := self.newest(path)
	if err != nil {
		self.t.Fatalf("newest: %v", err)
	}
	want := self.bruteForce(self.head.Version())[string(path.Bytes())]
	if want == nil {
		want = &bruteState{}
	}
	if newest.Exists != want.exists || newest.CommitVersion != want.commitVersion {
		self.t.Fatalf("path %x at %d: exists %v at %d, want %v at %d", path.Bytes()[:2], self.head.Version(),
			newest.Exists, newest.CommitVersion, want.exists, want.commitVersion)
	}
	if !want.directory && (newest.Version != want.version || newest.RemovalVersion != want.removalVersion) {
		self.t.Fatalf("path %x at %d: version %d removal %d, want %d and %d", path.Bytes()[:2], self.head.Version(),
			newest.Version, newest.RemovalVersion, want.version, want.removalVersion)
	}
	return newest
}

func TestNewestReadsTheEntryThenTheWindowAfterItsHorizon(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("f")
	world.push(&worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1, version: 2})
	world.fold(2)
	world.push(&worldChange{path: file, base: 2, version: 3})
	world.push(&worldChange{path: worldPath("g"), version: 4})
	newest := world.requireNewest(file)
	if !newest.FromWindow || newest.CommitVersion != 3 || newest.Version != 3 {
		t.Errorf("newest %+v", newest)
	}
	world.fold(4)
	newest = world.requireNewest(file)
	if newest.FromWindow || newest.IndexVersion == nil {
		t.Errorf("after the fold: %+v", newest)
	}
	// a path never written
	if newest := world.requireNewest(worldPath("never")); newest.Exists || newest.CommitVersion != 0 {
		t.Errorf("a path never written: %+v", newest)
	}
}

// §11.7's newest row: a folded version committed after the served head's v sends evs to a newer head.
func TestNewestEntryAboveTheServedHeadSendsToANewerHead(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("f")
	world.push(&worldChange{path: file, version: 1})
	stale := world.head
	world.push(&worldChange{path: file, base: 1, version: 2})
	world.fold(2)
	// the entry is read after the newer head, and combined with the stale one
	read, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, file, stale.Head.GetFoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Newest(world.ctx, read, stale.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if !errors.Is(err, ErrEvsEntryAheadOfHead) {
		t.Errorf("an entry above the head: %v", err)
	}
}

// FS-58: A reads head H1 and X's entry, then waits while B commits X, a fold takes it in and a commit raises
// folded_through past it; A's rerun keeps H1's horizon with its entry and reads the new head's window, so it sees
// B's change and never commits over it.
func TestNewestRerunKeepsTheHorizonItsEntryWasReadAfter(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("x")
	world.push(&worldChange{path: file, version: 1})
	world.fold(1)
	h1 := world.head
	aRead, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, file, h1.Head.GetFoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	world.push(&worldChange{path: file, base: 1, version: 2})
	world.fold(2)
	world.push(&worldChange{path: worldPath("other"), version: 3})
	h2, err := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	newest, err := Newest(world.ctx, aRead, h2.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if err != nil {
		t.Fatal(err)
	}
	if newest.Version != 2 || !newest.FromWindow {
		t.Errorf("the rerun saw %+v", newest)
	}
	// A based its write on version 1: the CAS refuses it
	if err := CheckPathVersion(newest, 1, 2, false, h1.Version()); !errors.Is(err, ErrEvsPathConflict) {
		t.Errorf("a write over B's change: %v", err)
	}
	// with the window paged past A's horizon, A must read the entry again after the new head
	world.pageOut(2)
	h3, _ := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	if _, err := Newest(world.ctx, aRead, h3.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId)); !errors.Is(err, ErrEvsEntryBehindWindow) {
		t.Errorf("a window past the horizon: %v", err)
	}
	reread, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, file, h3.Head.GetFoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	newest, err = Newest(world.ctx, reread, h3.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if err != nil || newest.Version != 2 {
		t.Errorf("after the reread: %+v %v", newest, err)
	}
}

// A directory's removal ends every path below it, one past each one's last version.
func TestNewestPrefixRemovalEndsAPathBelowIt(t *testing.T) {
	world := newEvsWorld(t)
	directory := worldPath("d")
	file := worldPath("d", "x")
	world.push(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1, version: 2})
	world.push(&worldChange{path: directory, base: 1})
	newest := world.requireNewest(file)
	if newest.Exists || !newest.RemovedByPrefix || newest.RemovalVersion != 3 || newest.CommitVersion != 3 {
		t.Errorf("under a removed directory: %+v", newest)
	}
	// the same once folded: the fold's marker says it
	world.fold(3)
	newest = world.requireNewest(file)
	if newest.Exists || newest.Marker == nil || newest.RemovalVersion != 3 {
		t.Errorf("folded: %+v", newest)
	}
	// re-created: a creation's version passes every one the path held (max(b, m) + 1)
	want := ExpectedEntryVersion(0, world.head.Version(), newest.RemovalVersion)
	if want != 4 {
		t.Errorf("the creation's version %d", want)
	}
	if err := CheckPathVersion(newest, 0, want, false, world.head.Version()); err != nil {
		t.Errorf("the creation: %v", err)
	}
	world.push(&worldChange{path: directory, directory: true, version: 1 + 3, names: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: file, version: want})
	if newest := world.requireNewest(file); !newest.Exists || newest.Version != want {
		t.Errorf("re-created: %+v", newest)
	}
}

// The digest is a filter: a window version whose digest misses the path and every prefix costs no record read.
func TestNewestReadsNoStatementTheDigestRulesOut(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("f")
	world.push(&worldChange{path: file, version: 1})
	world.fold(1)
	for i := 0; i < 20; i += 1 {
		world.push(&worldChange{path: worldPath(fmt.Sprintf("other-%d", i)), version: 1})
	}
	head, _ := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	read, _ := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, file, head.Head.GetFoldedThrough())
	cache := NewRecordCache(world.settings)
	newest, err := Newest(world.ctx, read, head.Head, NewRecordPushSource(cache, world.cluster, world.repoId, world.refId))
	if err != nil || newest.Version != 1 {
		t.Fatalf("%+v %v", newest, err)
	}
	// a 64-bit filter of one path a push: a false match now and then, never one a version
	if _, readCount, _ := cache.Counts(); 5 < readCount {
		t.Errorf("%d records read for 20 pushes of other paths", readCount)
	}
}

// §11.8's trust row: a record at a window entry's place that is not the statement it names breaks the rule.
func TestNewestRefusesARecordThatIsNotItsStatement(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("f")
	world.push(&worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1, version: 2})
	head := CloneEvsHead(world.head.Head)
	window, _ := EvsHeadWindow(head)
	// version 2's entry names version 1's place
	window[1].Place = window[0].Place
	head.Window = append(window[0].Encode(), window[1].Encode()...)
	read, _ := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, file, 0)
	_, err := Newest(world.ctx, read, head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if !errors.Is(err, ErrEvsStatementMismatch) {
		t.Errorf("a mismatched record: %v", err)
	}
}

// A listing is the folded table plus, in version order, the window's deltas after the horizon.
func TestListingMergesTheFoldedTableAndTheWindowsDeltas(t *testing.T) {
	world := newEvsWorld(t)
	directory := worldPath("d")
	world.push(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("a")}}, &worldChange{path: worldPath("d", "a"), version: 1})
	world.push(&worldChange{path: directory, directory: true, base: 1, version: 2, names: []sidecar.EvsToken{worldToken("b")}}, &worldChange{path: worldPath("d", "b"), version: 1})
	world.fold(2)
	world.push(&worldChange{path: directory, directory: true, base: 2, version: 3, names: []sidecar.EvsToken{worldToken("c")}, removedTokens: []sidecar.EvsToken{worldToken("a")}},
		&worldChange{path: worldPath("d", "a"), base: 1}, &worldChange{path: worldPath("d", "c"), version: 1})
	head, _ := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	read, _ := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, directory, head.Head.GetFoldedThrough())
	listing, err := Listing(world.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if err != nil {
		t.Fatal(err)
	}
	tokens := []sidecar.EvsToken{}
	for _, name := range listing.Names {
		tokens = append(tokens, sidecar.EvsToken(name.GetToken()))
	}
	if !listing.Exists || len(tokens) != 2 || listing.TableThrough != 2 || len(listing.DeltaVersions) != 1 {
		t.Fatalf("listing %+v", listing)
	}
	for _, want := range []sidecar.EvsToken{worldToken("b"), worldToken("c")} {
		found := false
		for _, token := range tokens {
			found = found || token == want
		}
		if !found {
			t.Errorf("missing %x", want[:2])
		}
	}
	// the directory removed: no listing
	world.push(&worldChange{path: directory, base: 3})
	head, _ = world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	listing, err = Listing(world.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId))
	if err != nil || listing.Exists {
		t.Errorf("a removed directory listed: %+v %v", listing, err)
	}
}

func TestCheckPathVersionHoldsBothRules(t *testing.T) {
	present := &EvsNewest{Exists: true, Version: 7, CommitVersion: 12}
	removed := &EvsNewest{RemovalVersion: 8, CommitVersion: 20}
	never := &EvsNewest{}
	cases := []struct {
		name      string
		newest    *EvsNewest
		base      uint64
		version   uint64
		removal   bool
		effective uint64
		want      error
	}{
		{"a write on the newest", present, 7, 8, false, 15, nil},
		{"a write on an older version", present, 6, 7, false, 15, ErrEvsPathConflict},
		{"a write skipping a version", present, 7, 9, false, 15, ErrEvsVersionRule},
		{"a creation over a standing path", present, 0, 16, false, 15, ErrEvsPathConflict},
		{"a removal of the newest", present, 7, 0, true, 15, nil},
		{"a creation after a removal below b", removed, 0, 26, false, 25, nil},
		{"a creation after a removal past b", removed, 0, 9, false, 5, nil},
		{"a creation restarting below the removal", removed, 0, 6, false, 5, ErrEvsVersionRule},
		{"a creation of a path never written", never, 0, 31, false, 30, nil},
		{"a creation at b", never, 0, 30, false, 30, ErrEvsVersionRule},
		{"a removal of an absent path", never, 0, 0, true, 30, ErrEvsPathConflict},
	}
	for _, c := range cases {
		err := CheckPathVersion(c.newest, c.base, c.version, c.removal, c.effective)
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if EffectiveBaseVersion(10, []uint64{5, 2}) != 17 {
		t.Error("an overlay chain's effective base")
	}
}

// I-EVS-8 as a property: over random histories of writes, removals and directory removals, with folds and
// page-outs between, the newest rule answers what replaying history answers, and every version a writer takes by
// the versions rule passes every one its path held.
func TestNewestAndTheVersionsRuleAgainstABruteForceHistory(t *testing.T) {
	// what the histories covered, so a generator that stops reaching a case fails here
	pushCount, creationAfterRemovalCount, prefixRemovalCount, foldCount, pageOutCount, windowAnswerCount := 0, 0, 0, 0, 0, 0
	for seed := uint64(1); seed <= 12; seed += 1 {
		random := rand.New(rand.NewPCG(seed, 7))
		world := newEvsWorld(t)
		directory := worldPath("d")
		paths := []sidecar.EvsTokenPath{worldPath("f"), worldPath("d", "x"), worldPath("d", "y")}
		everVersions := map[string][]uint64{}
		for step := 0; step < 40; step += 1 {
			states := world.bruteForce(world.head.Version())
			stateOf := func(tokenPath sidecar.EvsTokenPath) *bruteState {
				if state := states[string(tokenPath.Bytes())]; state != nil {
					return state
				}
				return &bruteState{}
			}
			path := paths[random.IntN(len(paths))]
			state := stateOf(path)
			// the writer's own reading of the path, through the newest rule
			newest, err := world.newest(path)
			if err != nil {
				t.Fatalf("seed %d step %d: %v", seed, step, err)
			}
			changes := []*worldChange{}
			switch {
			case state.exists && random.IntN(3) == 0:
				changes = append(changes, &worldChange{path: path, base: newest.Version})
			case state.exists:
				changes = append(changes, &worldChange{path: path, base: newest.Version, version: ExpectedEntryVersion(newest.Version, world.head.Version(), newest.RemovalVersion)})
			case random.IntN(5) == 0 && stateOf(directory).exists:
				changes = append(changes, &worldChange{path: directory, base: stateOf(directory).version})
			default:
				version := ExpectedEntryVersion(0, world.head.Version(), newest.RemovalVersion)
				if err := CheckPathVersion(newest, 0, version, false, world.head.Version()); err != nil {
					t.Fatalf("seed %d step %d: a creation by the rule refused: %v", seed, step, err)
				}
				changes = append(changes, &worldChange{path: path, version: version})
				if len(path) == 2 && !stateOf(directory).exists {
					dirNewest, err := world.newest(directory)
					if err != nil {
						t.Fatal(err)
					}
					changes = append(changes, &worldChange{path: directory, directory: true, version: ExpectedEntryVersion(0, world.head.Version(), dirNewest.RemovalVersion), names: []sidecar.EvsToken{path.Last()}})
				}
			}
			// sorted by token path, as a statement lists them
			if 1 < len(changes) && 0 < changes[0].path.Compare(changes[1].path) {
				changes[0], changes[1] = changes[1], changes[0]
			}
			world.push(changes...)
			pushCount += 1
			for _, change := range changes {
				if change.version == 0 {
					if change.path.Equal(directory) {
						prefixRemovalCount += 1
					}
					continue
				}
				if change.base == 0 && 0 < stateOf(change.path).removalVersion {
					creationAfterRemovalCount += 1
				}
				key := string(change.path.Bytes())
				for _, earlier := range everVersions[key] {
					if !change.directory && change.version <= earlier {
						t.Fatalf("seed %d step %d: version %d restarts below %d", seed, step, change.version, earlier)
					}
				}
				everVersions[key] = append(everVersions[key], change.version)
				if removal := stateOf(change.path).removalVersion; !change.directory && change.version <= removal {
					t.Fatalf("seed %d step %d: a creation at %d not past its removal's %d", seed, step, change.version, removal)
				}
			}
			if random.IntN(4) == 0 {
				world.fold(max(world.head.Head.GetFoldedThrough(), world.head.Version()-uint64(random.IntN(2))))
				foldCount += 1
			}
			if random.IntN(6) == 0 && EvsHeadWindowFirstVersion(world.head.Head) <= world.head.Head.GetFoldedThrough() {
				world.pageOut(world.head.Head.GetFoldedThrough())
				pageOutCount += 1
			}
			for _, checked := range append(paths, directory) {
				if newest := world.requireNewest(checked); newest.FromWindow {
					windowAnswerCount += 1
				}
			}
		}
	}
	t.Logf("%d pushes, %d creations after a removal, %d directory removals, %d folds, %d page-outs, %d window answers",
		pushCount, creationAfterRemovalCount, prefixRemovalCount, foldCount, pageOutCount, windowAnswerCount)
	if creationAfterRemovalCount == 0 || prefixRemovalCount == 0 || foldCount == 0 || pageOutCount == 0 || windowAnswerCount == 0 {
		t.Error("the histories missed a case the property needs")
	}
}

func TestParseEvsIndexEntryRefusesTamperedEntries(t *testing.T) {
	entryVersion := func(version uint64, pushLabel string) []byte {
		entryBytes, _ := proto.Marshal(&protocol.EvsEntryVersion{Version: version, PushId: testId(pushLabel).Bytes(), Kind: 1})
		return entryBytes
	}
	good := &protocol.EvsIndexEntry{Versions: []*protocol.EvsIndexVersion{
		{PushId: testId("p2").Bytes(), CommitVersion: 9, EntryVersion: entryVersion(5, "p2")},
		{PushId: testId("p1").Bytes(), CommitVersion: 4, EntryVersion: entryVersion(4, "p1"), Elided: true},
	}}
	goodBytes, _ := proto.Marshal(good)
	if _, err := ParseEvsIndexEntry(goodBytes); err != nil {
		t.Fatal(err)
	}
	tampered := map[string]func(entry *protocol.EvsIndexEntry){
		"versions out of order":  func(entry *protocol.EvsIndexEntry) { entry.Versions[0].CommitVersion = 3 },
		"path versions repeat":   func(entry *protocol.EvsIndexEntry) { entry.Versions[1].EntryVersion = entryVersion(5, "p1") },
		"the newest elided":      func(entry *protocol.EvsIndexEntry) { entry.Versions[0].Elided = true },
		"another push's version": func(entry *protocol.EvsIndexEntry) { entry.Versions[0].EntryVersion = entryVersion(5, "p9") },
		"five versions": func(entry *protocol.EvsIndexEntry) {
			for len(entry.Versions) < 5 {
				entry.Versions = append(entry.Versions, entry.Versions[1])
			}
		},
		"a version beside a table": func(entry *protocol.EvsIndexEntry) { entry.Names = &protocol.EvsNameTable{} },
		"a marker below a version": func(entry *protocol.EvsIndexEntry) {
			entry.Marker = &protocol.EvsRemovalMarker{PushId: testId("p3").Bytes(), RemovalVersion: 8, PathVersion: 6}
		},
		"a marker not past the last version": func(entry *protocol.EvsIndexEntry) {
			entry.Marker = &protocol.EvsRemovalMarker{PushId: testId("p3").Bytes(), RemovalVersion: 10, PathVersion: 5}
		},
		"an entry version that does not parse": func(entry *protocol.EvsIndexEntry) { entry.Versions[0].EntryVersion = []byte{0xff} },
		"a short push id":                      func(entry *protocol.EvsIndexEntry) { entry.Versions[0].PushId = []byte{1} },
	}
	for name, tamper := range tampered {
		entry := proto.Clone(good).(*protocol.EvsIndexEntry)
		tamper(entry)
		entryBytes, _ := proto.Marshal(entry)
		if _, err := ParseEvsIndexEntry(entryBytes); !errors.Is(err, ErrEvsIndexEntryInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	table := &protocol.EvsIndexEntry{Names: &protocol.EvsNameTable{Names: []*protocol.EvsName{{Token: make([]byte, 16), Kind: 1, SealedName: []byte("s")}}, RemovedTokens: [][]byte{make([]byte, 16)}}}
	tableBytes, _ := proto.Marshal(table)
	if _, err := ParseEvsIndexEntry(tableBytes); !errors.Is(err, ErrEvsIndexEntryInvalid) {
		t.Errorf("a folded table removing names: %v", err)
	}
	if _, err := ParseEvsIndexEntry(make([]byte, EvsIndexEntryMaxByteCount+1)); !errors.Is(err, ErrEvsIndexEntryInvalid) {
		t.Errorf("past 512 KiB: %v", err)
	}
}

func TestEntryStateRidesInMetadata(t *testing.T) {
	for _, state := range []EvsEntryStateValue{{}, {State: EvsEntryStateFresh}, {State: EvsEntryStateRemoved}, {State: EvsEntryStateCarried, Epoch: 3}} {
		parsed, err := ParseEvsEntryState(state.Metadata())
		if err != nil || parsed != state {
			t.Errorf("%+v: %+v %v", state, parsed, err)
		}
	}
	for _, value := range []string{"carried:", "carried:0", "carried:03", "carried:x", "moved", ""} {
		if _, err := ParseEvsEntryState(map[string]string{EvsEntryStateMetadataKey: value}); !errors.Is(err, ErrEvsIndexEntryInvalid) {
			t.Errorf("%q: %v", value, err)
		}
	}
}

// §11.6's read row while the head lists sources: prefixes' states, the current entry, the newest source's.
func TestReadPathEntryWhileSourcesStand(t *testing.T) {
	world := newEvsWorld(t)
	world.push(&worldChange{path: worldPath("f"), version: 1})
	head := CloneEvsHead(world.head.Head)
	head.PathEpoch = &protocol.EvsPathEpoch{Current: 3, Sources: []*protocol.EvsEpochSource{{Epoch: 2, MapSha256: make([]byte, 32)}, {Epoch: 1, MapSha256: make([]byte, 32)}}}
	current := worldPath("d3", "x3")
	tokens := &EvsPathTokens{Current: current, Sources: []*EvsSourceTokenPath{
		{Epoch: 1, TokenPath: worldPath("d1", "x1")}, {Epoch: 2, TokenPath: worldPath("d2", "x2")},
	}}
	put := func(epoch uint64, tokenPath sidecar.EvsTokenPath, commitVersion uint64, state EvsEntryStateValue) {
		entry := &protocol.EvsIndexEntry{Versions: []*protocol.EvsIndexVersion{{
			PushId: testId("push-1").Bytes(), CommitVersion: commitVersion,
			EntryVersion: world.entryVersion(testId("push-1"), 0, &worldChange{path: tokenPath, version: commitVersion}),
		}}}
		prior, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, epoch, tokenPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PutEntry(world.ctx, world.cluster, world.repoId, world.refId, epoch, tokenPath, prior, entry, state); err != nil {
			t.Fatal(err)
		}
	}
	read := func() *EvsPathRead {
		pathRead, err := ReadPathEntry(world.ctx, world.cluster, world.repoId, world.refId, head, tokens)
		if err != nil {
			t.Fatal(err)
		}
		return pathRead
	}
	// every GET 404s: the current entry is read a second time, since a copy PUTs it before deleting a source's
	getsBefore := world.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	if pathRead := read(); !pathRead.Absent() {
		t.Error("found an entry nowhere written")
	}
	// one GET each of the current and two sources, a HEAD of the one prefix, and the current again
	if got := world.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; got != 5 {
		t.Errorf("%d reads", got)
	}
	// the older source alone holds it, then the newer one too: the newest source's
	put(1, tokens.Sources[0].TokenPath, 1, EvsEntryStateValue{})
	if pathRead := read(); pathRead.SourceEpoch != 1 || !pathRead.TokenPath.Equal(current) {
		t.Errorf("from %d, path %v", pathRead.SourceEpoch, pathRead.TokenPath)
	}
	put(2, tokens.Sources[1].TokenPath, 2, EvsEntryStateValue{})
	if pathRead := read(); pathRead.SourceEpoch != 2 {
		t.Errorf("from %d, want the newest source", pathRead.SourceEpoch)
	}
	// the copy has put the current entry: it stands over every source
	put(3, current, 3, EvsEntryStateValue{State: EvsEntryStateCarried, Epoch: 2})
	if pathRead := read(); pathRead.SourceEpoch != 0 || pathRead.Absent() {
		t.Errorf("from %d", pathRead.SourceEpoch)
	}
	// a fresh prefix: absent, unless the path's own current entry is fresh
	put(3, worldPath("d3"), 3, EvsEntryStateValue{State: EvsEntryStateFresh})
	if pathRead := read(); !pathRead.Absent() || pathRead.Prefix != EvsPrefixVerdictFresh {
		t.Errorf("under a fresh prefix: %+v", pathRead)
	}
	put(3, current, 3, EvsEntryStateValue{State: EvsEntryStateFresh})
	if pathRead := read(); pathRead.Absent() {
		t.Error("a fresh path under a fresh prefix read absent")
	}
	// a removed prefix: absent, whatever the path's own entry says
	put(3, worldPath("d3"), 3, EvsEntryStateValue{State: EvsEntryStateRemoved})
	if pathRead := read(); !pathRead.Absent() || pathRead.Prefix != EvsPrefixVerdictRemoved {
		t.Errorf("under a removed prefix: %+v", pathRead)
	}
	// with no source listed, one GET of the current entry
	head.PathEpoch.Sources = nil
	getsBefore = world.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	if pathRead := read(); pathRead.Absent() {
		t.Error("no sources: absent")
	}
	if got := world.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; got != 1 {
		t.Errorf("%d reads with no source", got)
	}
}

// §22.6's index-entry target: decoding is total and bounded, and an entry that decodes encodes back to one that does.
func FuzzEvsIndexEntry(f *testing.F) {
	entryVersion, _ := proto.Marshal(&protocol.EvsEntryVersion{Version: 3, PushId: make([]byte, 16), Kind: 1})
	seeds := []*protocol.EvsIndexEntry{
		{Versions: []*protocol.EvsIndexVersion{{PushId: make([]byte, 16), CommitVersion: 4, EntryVersion: entryVersion}}},
		{Names: &protocol.EvsNameTable{Names: []*protocol.EvsName{{Token: make([]byte, 16), Kind: 2, SealedName: []byte("n")}}}, NamesThrough: 7},
		{Marker: &protocol.EvsRemovalMarker{PushId: make([]byte, 16), RemovalVersion: 9, PathVersion: 4}},
	}
	for _, seed := range seeds {
		seedBytes, _ := proto.Marshal(seed)
		f.Add(seedBytes)
	}
	f.Fuzz(func(t *testing.T, entryBytes []byte) {
		entry, err := ParseEvsIndexEntry(entryBytes)
		if err != nil {
			if !errors.Is(err, ErrEvsIndexEntryInvalid) {
				t.Fatalf("an error of another kind: %v", err)
			}
			return
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseEvsIndexEntry(again); err != nil {
			t.Fatalf("an entry that decoded does not decode again: %v", err)
		}
	})
}

// Commits a push of changes in parts, as the seal of §11.8's parts row leaves it: each part's record, then the seal's
// record naming their places, changes_roots and first token paths, which the window entry places.
func (self *evsWorld) pushInParts(changes ...*worldChange) uint64 {
	self.pushSeq += 1
	pushId := testId(fmt.Sprintf("push-%d", self.pushSeq))
	baseVersion := self.head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, self.refId)
	if 0 < baseVersion {
		baseChain = [32]byte(self.head.Head.GetChain())
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: 1, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: testId("client"), TimeMs: self.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"),
	}
	for _, change := range changes {
		planned := &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: change.base}
		if change.version != 0 {
			planned.EntryVersion = self.entryVersion(pushId, baseVersion, change)
		}
		plan.Changes = append(plan.Changes, planned)
	}
	built, err := self.builder.Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	if len(built.Parts) < 2 {
		self.t.Fatalf("%d parts", len(built.Parts))
	}
	sealParts := []*sidecar.EvsSealPart{}
	for _, partBytes := range built.Parts {
		checked, err := sidecar.EvsCheckPart(built.Statement, partBytes)
		if err != nil {
			self.t.Fatal(err)
		}
		place, err := self.batches.Append(self.paidCtx, "meta-1", &sidecar.EvsBatchRecord{
			Type: protocol.EvsBatchRecordType_EVS_BATCH_PART, RepoId: self.repoId, RefId: self.refId, PushId: pushId,
			SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPartRecordBody(built.Statement.Bytes, partBytes, nil, baseVersion),
		})
		if err != nil {
			self.t.Fatal(err)
		}
		sealParts = append(sealParts, &sidecar.EvsSealPart{Place: place, ChangesRoot: checked.Root, FirstTokenPath: checked.Changes[0].TokenPath})
	}
	place, err := self.batches.Append(self.paidCtx, "meta-1", &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, RepoId: self.repoId, RefId: self.refId, PushId: pushId,
		SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsSealRecordBody(built.Statement.Bytes, sealParts),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	changedPaths := make([]sidecar.EvsTokenPath, len(changes))
	for i, change := range changes {
		changedPaths[i] = change.path
	}
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, built.Statement.ChangedPrefixes, true, place)
	next := CloneEvsHead(self.head.Head)
	chain := sidecar.EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	next.Version = baseVersion + 1
	next.Chain = chain[:]
	next.PushId = pushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
	self.history = append(self.history, &worldPush{version: next.Version, changes: changes})
	return next.Version
}

// A push in parts: the rule reads the seal's record and only the part whose run holds the path, matched to the
// seal's changes_root for it.
func TestNewestReadsASealedPushsPartHoldingThePath(t *testing.T) {
	world := newEvsWorld(t)
	world.push(&worldChange{path: worldPath("seed"), version: 1})
	changes := []*worldChange{}
	for i := 0; i < 1100; i += 1 {
		changes = append(changes, &worldChange{path: worldPath(fmt.Sprintf("p%d", i)), version: 2})
	}
	world.pushInParts(changes...)
	cache := NewRecordCache(world.settings)
	source := NewRecordPushSource(cache, world.cluster, world.repoId, world.refId)
	head, _ := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	for _, label := range []string{"p0", "p1099", "p550"} {
		path := worldPath(label)
		read, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, path, head.Head.GetFoldedThrough())
		if err != nil {
			t.Fatal(err)
		}
		newest, err := Newest(world.ctx, read, head.Head, source)
		if err != nil || !newest.Exists || newest.Version != 2 || newest.CommitVersion != 2 {
			t.Fatalf("%s: %+v %v", label, newest, err)
		}
	}
	// the seal's record once, and each part once, for three paths
	if _, readCount, _ := cache.Counts(); 3 < readCount {
		t.Errorf("%d records read", readCount)
	}
	// a seal whose part's changes_root it does not name is no statement of it
	tampered := CloneEvsHead(head.Head)
	window, _ := EvsHeadWindow(tampered)
	sealRecord, err := ReadRecord(world.ctx, cache, world.cluster, window[1].Place)
	if err != nil {
		t.Fatal(err)
	}
	statementBytes, parts, err := sidecar.ParseEvsSealRecordBody(sealRecord.Body)
	if err != nil {
		t.Fatal(err)
	}
	parts[0].ChangesRoot[0] ^= 1
	place, err := world.batches.Append(world.paidCtx, "meta-1", &sidecar.EvsBatchRecord{
		Type: sealRecord.Type, RepoId: sealRecord.RepoId, RefId: sealRecord.RefId, PushId: sealRecord.PushId,
		SignerSidecarId: sealRecord.SignerSidecarId, TimeMs: sealRecord.TimeMs, Body: sidecar.EvsSealRecordBody(statementBytes, parts),
	})
	if err != nil {
		t.Fatal(err)
	}
	window[1].Place = place
	tampered.Window = append(window[0].Encode(), window[1].Encode()...)
	read, _ := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, worldPath("p0"), 0)
	if _, err := Newest(world.ctx, read, tampered, NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId)); !errors.Is(err, ErrEvsStatementMismatch) {
		t.Errorf("a seal naming another changes_root: %v", err)
	}
}
