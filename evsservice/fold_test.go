package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A second process's folder over the world's clusters, its own caches and fold state, paying through budget.
func (self *evsWorld) otherFolder(budget sidecar.WriteBudget) *Folder {
	priceTable, err := DefaultPriceTable(self.settings.PriceBlockByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	return NewFolder(self.ctx, self.clock, self.host.ClockCheck, self.budgetedBlob, budget, self.heads, NewRecordCache(self.settings),
		NewRepoCache(self.clock, self.settings), priceTable, self.settings, sidecar.NewNoopLogger())
}

// The entry of path in the head's current path epoch.
func (self *evsWorld) entryOf(path sidecar.EvsTokenPath) *EvsEntryRead {
	self.t.Helper()
	read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, EvsHeadCurrentEpoch(self.head.Head), path, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return read
}

// The change writing path's next version by §11.7's versions rule, its creation while it is absent.
func (self *evsWorld) nextWrite(path sidecar.EvsTokenPath) *worldChange {
	self.t.Helper()
	newest, err := self.newest(path)
	if err != nil {
		self.t.Fatal(err)
	}
	if newest.Exists {
		return &worldChange{path: path, base: newest.Version, version: newest.Version + 1}
	}
	return &worldChange{path: path, version: ExpectedEntryVersion(0, self.head.Version(), newest.RemovalVersion)}
}

// A directory's listing at the cluster's head, its entry read after it.
func (self *evsWorld) listing(path sidecar.EvsTokenPath) *EvsListing {
	self.t.Helper()
	head, err := self.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, EvsHeadCurrentEpoch(head.Head), path, head.Head.GetFoldedThrough())
	if err != nil {
		self.t.Fatal(err)
	}
	listing, err := Listing(self.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(self.settings), self.cluster, self.repoId, self.refId))
	if err != nil {
		self.t.Fatal(err)
	}
	return listing
}

// Step 6's page-out on the prior head, applied to the next one, as a commit runs it (§11.8).
func (self *evsWorld) pageOutStep() func(prior *EvsStoredHead, next *protocol.EvsHead) error {
	return func(prior *EvsStoredHead, next *protocol.EvsHead) error {
		if prior.Absent() {
			return nil
		}
		now := self.clock.Now()
		pageOut, err := self.folder.PageOut(self.ctx, &EvsPageOutRequest{
			Cluster: self.foldCluster, RepoId: self.repoId, RefId: self.refId, Head: prior, HeadReadAt: now,
			Deadline: now.Add(5 * time.Second),
		})
		if err != nil {
			return err
		}
		return pageOut.Apply(next)
	}
}

// One head write that raises only the fence, as a collection window or a path epoch's commit sets these fields.
func (self *evsWorld) fenceWrite(change func(next *protocol.EvsHead)) {
	self.t.Helper()
	next := CloneEvsHead(self.head.Head)
	change(next)
	next.Fence += 1
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
}

// Sorts changes by token path, as a statement lists them.
func sortedChanges(changes ...*worldChange) []*worldChange {
	sort.Slice(changes, func(i int, j int) bool { return changes[i].path.Compare(changes[j].path) < 0 })
	return changes
}

// A budget whose P2 a test holds closed: TryAcquireP2 answers no and AcquireP2 waits until open. Safe for
// concurrent use.
type gatedBudget struct {
	sidecar.WriteBudget

	stateLock   sync.Mutex
	closed      bool
	opened      chan struct{}
	waiting     chan struct{}
	waitingOnce sync.Once
}

func newGatedBudget(budget sidecar.WriteBudget) *gatedBudget {
	return &gatedBudget{WriteBudget: budget, closed: true, opened: make(chan struct{}), waiting: make(chan struct{})}
}

func (self *gatedBudget) open() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		self.closed = false
		close(self.opened)
	}
}

func (self *gatedBudget) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

func (self *gatedBudget) TryAcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, bool, error) {
	if self.isClosed() {
		return nil, false, nil
	}
	return self.WriteBudget.TryAcquireP2(ctx, clusterId, work)
}

func (self *gatedBudget) AcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	if self.isClosed() {
		self.waitingOnce.Do(func() { close(self.waiting) })
		select {
		case <-self.opened:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return self.WriteBudget.AcquireP2(ctx, clusterId, work)
}

// Waits for a channel a test's goroutine closes, failing past a real 10 s, which only a hung test reaches.
func awaitClosed(t *testing.T, channel <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s never happened", what)
	}
}

// §11.7's fold row: a file takes its newest version, four kept and the older ones elided; a removal marks the path
// and, by a LIST, every entry below it, each one past its last version; a fold of a range already folded writes
// nothing.
func TestFoldTakesEachPathsNewestAndMarksBelowARemoval(t *testing.T) {
	world := newEvsWorld(t)
	directory, x, y, file := worldPath("d"), worldPath("d", "x"), worldPath("d", "y"), worldPath("f")
	world.push(sortedChanges(
		&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x"), worldToken("y")}},
		&worldChange{path: x, version: 1}, &worldChange{path: y, version: 1}, &worldChange{path: file, version: 1},
	)...)
	world.fold(1)
	for version := uint64(2); version <= 6; version += 1 {
		world.push(&worldChange{path: file, base: version - 1, version: version})
	}
	world.push(&worldChange{path: x, base: 1, version: 2})
	world.push(&worldChange{path: directory, base: 1})
	before := world.head
	world.fold(8)

	versions := world.entryOf(file).Entry.GetVersions()
	if len(versions) != 4 {
		t.Fatalf("%d folded versions", len(versions))
	}
	for i, version := range versions {
		want := uint64(6 - i)
		entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
		if err != nil {
			t.Fatal(err)
		}
		inline := entryVersion.GetChain()[0].GetInline()
		if version.GetCommitVersion() != want || entryVersion.GetVersion() != want || (i == 0) != (0 < len(inline)) || (0 < i) != version.GetElided() {
			t.Errorf("folded version %d: at %d, version %d, %d inline bytes, elided %v", i, version.GetCommitVersion(), entryVersion.GetVersion(), len(inline), version.GetElided())
		}
	}
	// the directory's own marker, x's from its own events, y's from the LIST below the removal
	for _, c := range []struct {
		path        sidecar.EvsTokenPath
		pathVersion uint64
	}{{directory, 2}, {x, 3}, {y, 2}} {
		marker := world.entryOf(c.path).Entry.GetMarker()
		if marker == nil || marker.GetRemovalVersion() != 8 || marker.GetPathVersion() != c.pathVersion {
			t.Errorf("path %x's marker %v, want removal 8 and version %d", c.path.Bytes()[:2], marker, c.pathVersion)
		}
	}
	for _, path := range []sidecar.EvsTokenPath{directory, x, y, file} {
		world.requireNewest(path)
	}
	// another process folding the range again on the head before finds every entry holding it
	result, err := world.otherFolder(world.host.Budget).Fold(world.ctx, &EvsFoldRequest{
		Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Head: before, HeadReadAt: world.clock.Now(),
		Rank: sidecar.WriteP2RankFold,
	})
	if err != nil || result.EntryWriteCount != 0 || result.From != 1 || result.Through != 8 {
		t.Errorf("a refold: %+v %v", result, err)
	}
	if violations := world.host.Blobs.Violations(); len(violations) != 0 {
		t.Errorf("store rules broken: %v", violations)
	}
}

// §11.7's fold row skips a file a later window version changes again, but a removal's own marker stands before the
// removal leaves the window (I-EVS-6) and before the LIST below it: a path removed in the range and re-created after
// it gets its marker, and the re-creation's fold replaces it.
func TestFoldWritesARemovalsMarkerThoughALaterVersionChangesThePath(t *testing.T) {
	world := newEvsWorld(t)
	file, other, skipped := worldPath("x"), worldPath("y"), worldPath("z")
	world.push(&worldChange{path: file, version: 1}, &worldChange{path: other, version: 1}, &worldChange{path: skipped, version: 1})
	world.push(&worldChange{path: file, base: 1}, &worldChange{path: other, base: 1, version: 2})
	world.push(&worldChange{path: other, base: 2, version: 3})
	creation := ExpectedEntryVersion(0, world.head.Version(), 2)
	world.push(&worldChange{path: file, version: creation}, &worldChange{path: skipped, base: 1, version: 2})
	world.fold(3)
	// z, written again after the range, is left to that version's fold
	if !world.entryOf(skipped).Absent() {
		t.Error("a file changed after the range was folded")
	}
	world.requireNewest(skipped)
	if marker := world.entryOf(file).Entry.GetMarker(); marker == nil || marker.GetRemovalVersion() != 2 || marker.GetPathVersion() != 2 {
		t.Errorf("the removal's marker %v", marker)
	}
	// y, written at 1, 2 and 3, is folded through 3 whole: nothing after the range changes it
	if versions := world.entryOf(other).Entry.GetVersions(); len(versions) != 3 || versions[0].GetCommitVersion() != 3 {
		t.Errorf("y's entry holds %d versions", len(versions))
	}
	world.requireNewest(file)
	world.fold(4)
	if entry := world.entryOf(file).Entry; entry.GetMarker() != nil || entry.GetVersions()[0].GetCommitVersion() != 4 {
		t.Errorf("the re-creation folded over the marker: %v", entry)
	}
	world.requireNewest(file)
}

// FS-58: a fold killed after half its entries, then rerun by another process, which writes only what the first did
// not, and the horizon the dead fold never finished stays where it was.
func TestFoldKilledAfterHalfItsEntriesThenRerun(t *testing.T) {
	world := newEvsWorld(t)
	paths := []sidecar.EvsTokenPath{}
	creations := []*worldChange{}
	for _, label := range []string{"a", "b", "c", "d", "e", "f"} {
		paths = append(paths, worldPath(label))
		creations = append(creations, &worldChange{path: worldPath(label), version: 1})
	}
	world.push(sortedChanges(creations...)...)
	world.push(sortedChanges(&worldChange{path: paths[0], base: 1, version: 2}, &worldChange{path: paths[1], base: 1})...)
	fired, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: indexKeyPrefix, Nth: 4, Result: sidecartest.CrashBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	died := make(chan struct{})
	go func() {
		defer close(died)
		world.folder.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold})
		t.Error("the killed fold returned")
	}()
	awaitClosed(t, died, "the fold's death")
	awaitClosed(t, fired, "the crash")
	objects, _, err := world.cluster.List(world.ctx, IndexEpochPrefix(world.repoId, world.refId, 1), "", 100)
	if err != nil || len(objects) != 3 {
		t.Fatalf("%d entries after the kill: %v", len(objects), err)
	}
	if horizon := world.folder.Horizon(world.repoId, world.refId, world.head.Head); horizon != 0 {
		t.Errorf("a killed fold left a horizon of %d", horizon)
	}
	rerun := world.otherFolder(world.host.Budget)
	result, err := rerun.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold})
	if err != nil || result.EntryWriteCount != 3 || result.Through != 2 {
		t.Fatalf("the rerun: %+v %v", result, err)
	}
	world.folder = rerun
	world.raiseHorizon()
	for _, path := range paths {
		world.requireNewest(path)
	}
}

// FS-58: two folds of one entry race. The second process folds a longer range between the first's read and its
// If-Match, which meets a 412: the first reads the entry again, finds newer versions than its own there, and writes
// nothing.
func TestTwoFoldsOfOneEntryRace(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("x")
	for version := uint64(1); version <= 3; version += 1 {
		world.push(&worldChange{path: file, base: version - 1, version: version})
	}
	world.push(&worldChange{path: worldPath("y"), version: 4})
	other := world.otherFolder(world.host.Budget)
	raced := false
	world.folder.beforeEntryWrite = func(key string) {
		if raced {
			return
		}
		raced = true
		result, err := other.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold})
		if err != nil || result.EntryWriteCount != 2 {
			t.Errorf("the other fold: %+v %v", result, err)
		}
	}
	result, err := world.folder.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Through: 3, Rank: sidecar.WriteP2RankFold})
	if err != nil || !raced || result.EntryWriteCount != 0 {
		t.Fatalf("the raced fold: %+v %v", result, err)
	}
	versions := world.entryOf(file).Entry.GetVersions()
	if len(versions) != 3 || versions[0].GetCommitVersion() != 3 || versions[2].GetCommitVersion() != 1 {
		t.Fatalf("the entry after the race holds %d versions", len(versions))
	}
	// each process raises the horizon by its own commit
	world.raiseHorizon()
	if folded := world.head.Head.GetFoldedThrough(); folded != 3 {
		t.Errorf("the first's commit raised folded_through to %d", folded)
	}
	world.folder = other
	world.raiseHorizon()
	if folded := world.head.Head.GetFoldedThrough(); folded != 4 {
		t.Errorf("the second's commit raised folded_through to %d", folded)
	}
	world.requireNewest(file)
	world.requireNewest(worldPath("y"))
}

// FS-58: two folds of a range holding directory D's removal, the first held. The second marks D and D/x removed and
// its commit raises folded_through, D and D/x are re-created, and a third fold takes them in. The first then runs
// and writes nothing over the newer entries: held in P2's queue its If-Match fails and its reread finds them newer;
// held past its 15 s deadline the store refuses its write and its head reread shows another fold past it; with its
// marker PUT delayed in the network and applying late, the If-Match fails. Reads and listings show D/x throughout,
// and a push creating it again gets 409.
func TestALateRemovalFoldWritesNothingOverNewerEntries(t *testing.T) {
	for _, variant := range []string{"queued", "stale", "delayed"} {
		world := newEvsWorld(t)
		directory, x := worldPath("d"), worldPath("d", "x")
		world.push(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: x, version: 1})
		world.fold(1)
		world.push(&worldChange{path: directory, base: 1})
		removalHead, readAt := world.head, world.clock.Now()

		budget := newGatedBudget(world.host.Budget)
		var delayed <-chan struct{}
		if variant == "delayed" {
			budget.open()
			var err error
			delayed, err = world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
				Op: sidecartest.FaultOpPut, KeyPrefix: IndexEntryKey(world.repoId, world.refId, 1, directory), Nth: 1,
				Result: sidecartest.Delay, Delay: sidecartest.DelayInNetwork,
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		first := world.otherFolder(budget)
		done := make(chan struct{})
		var firstResult *EvsFoldResult
		var firstErr error
		go func() {
			defer close(done)
			firstResult, firstErr = first.Fold(world.ctx, &EvsFoldRequest{
				Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Head: removalHead, HeadReadAt: readAt,
				Rank: sidecar.WriteP2RankFold,
			})
		}()
		if variant == "delayed" {
			awaitClosed(t, delayed, "the delayed marker PUT")
		} else {
			awaitClosed(t, budget.waiting, "the first fold's wait in P2's queue")
		}

		world.fold(2)
		if marker := world.entryOf(x).Entry.GetMarker(); marker == nil || marker.GetRemovalVersion() != 2 {
			t.Fatalf("%s: the second fold's marker on D/x: %v", variant, marker)
		}
		creation := ExpectedEntryVersion(0, world.head.Version(), 2)
		world.push(&worldChange{path: directory, directory: true, version: creation, names: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: x, version: creation})
		world.fold(3)

		switch variant {
		case "queued":
			budget.open()
		case "stale":
			world.clock.Advance(20 * time.Second)
			budget.open()
		case "delayed":
			if delivered := world.host.Blobs.DeliverDelayed("meta-1", indexKeyPrefix); delivered != 1 {
				t.Fatalf("%d delayed requests delivered", delivered)
			}
		}
		awaitClosed(t, done, "the first fold")
		if firstErr != nil {
			t.Fatalf("%s: the first fold: %v", variant, firstErr)
		}
		if firstResult.EntryWriteCount != 0 || (variant == "stale") != firstResult.Superseded {
			t.Errorf("%s: the first fold %+v", variant, firstResult)
		}
		newest := world.requireNewest(x)
		if !newest.Exists || newest.Version != creation {
			t.Errorf("%s: D/x after the late fold: %+v", variant, newest)
		}
		listing := world.listing(directory)
		if !listing.Exists || len(listing.Names) != 1 || !bytes.Equal(listing.Names[0].GetToken(), worldToken("x").Bytes()) {
			t.Errorf("%s: D's listing %+v", variant, listing)
		}
		if err := CheckPathVersion(newest, 0, ExpectedEntryVersion(0, world.head.Version(), newest.RemovalVersion), false, world.head.Version()); !errors.Is(err, ErrEvsPathConflict) {
			t.Errorf("%s: another creation of D/x: %v", variant, err)
		}
	}
}

// §11.8 step 6: a commit past 127 versions folds its oldest page and writes log/<n>, and its head drops the page from
// the window, moving window_base_chain to the page's last chain; the pages chain on from C_0 to the head's base.
func TestPageOutFoldsThePageWritesItsLogPageAndMovesTheWindow(t *testing.T) {
	world := newEvsWorld(t)
	files := []sidecar.EvsTokenPath{worldPath("a"), worldPath("b"), worldPath("c"), worldPath("d"), worldPath("e")}
	step := world.pageOutStep()
	for version := uint64(1); version <= 191; version += 1 {
		if _, err := world.commit(step, world.nextWrite(files[version%5])); err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		first := EvsHeadWindowFirstVersion(world.head.Head)
		want := uint64(1)
		switch {
		case version == 191:
			want = 128
		case 128 <= version:
			want = 64
		}
		if first != want {
			t.Fatalf("version %d: the window starts at %d, want %d", version, first, want)
		}
		if want != 1 && world.head.Head.GetFoldedThrough() < want-1 {
			t.Fatalf("version %d: paged past folded_through %d", version, world.head.Head.GetFoldedThrough())
		}
	}
	pages := NewLogPageCache(world.settings)
	page0, err := ReadLogPage(world.ctx, pages, world.cluster, world.repoId, world.refId, 0)
	if err != nil {
		t.Fatal(err)
	}
	page1, err := ReadLogPage(world.ctx, pages, world.cluster, world.repoId, world.refId, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page0.FirstChain != sidecar.EvsChainStart(world.repoId, world.refId) || page0.LastChain != page1.FirstChain ||
		!bytes.Equal(page1.LastChain[:], world.head.Head.GetWindowBaseChain()) {
		t.Error("the pages do not chain from C_0 to the window's base")
	}
	if len(page0.Entries) != 63 || len(page1.Entries) != 64 {
		t.Errorf("pages of %d and %d versions", len(page0.Entries), len(page1.Entries))
	}
	if version, ok := page1.VersionOf(testId("push-100")); !ok || version != 100 {
		t.Errorf("push 100 in page 1 at %d %v", version, ok)
	}
	for _, path := range files {
		world.requireNewest(path)
	}
}

// FS-58: a page-out whose fold meets 412s reads each entry again and still pages. The page's versions each create a
// path no later version changes, so its fold writes every one of them.
func TestPageOutWhoseFoldMeets412s(t *testing.T) {
	world := newEvsWorld(t)
	paths := []sidecar.EvsTokenPath{}
	for version := uint64(1); version <= 63; version += 1 {
		path := worldPath(fmt.Sprintf("p%d", version))
		paths = append(paths, path)
		world.push(world.nextWrite(path))
	}
	busy := worldPath("busy")
	for version := uint64(64); version <= 127; version += 1 {
		world.push(world.nextWrite(busy))
	}
	fired, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: indexKeyPrefix, Result: sidecartest.Precondition, Repeat: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.commit(world.pageOutStep(), world.nextWrite(busy)); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, fired, "the 412s")
	if first := EvsHeadWindowFirstVersion(world.head.Head); first != 64 || world.head.Head.GetFoldedThrough() < 63 {
		t.Fatalf("the window starts at %d, folded through %d", first, world.head.Head.GetFoldedThrough())
	}
	for _, path := range append(paths, busy) {
		world.requireNewest(path)
		if path.Equal(busy) {
			continue
		}
		if entry := world.entryOf(path); entry.Absent() || len(entry.Entry.GetVersions()) != 1 {
			t.Fatalf("path %x's entry after the page-out", path.Bytes()[:2])
		}
	}
}

// FS-58: folds blocked until the window reaches 255, when the next push gets 429 FOLD_BEHIND with retry_after_ms and
// commits nothing; released, each push pages one page out until the window is back under 127.
func TestFoldsBlockedUntilTheWindowReaches255ThenReleased(t *testing.T) {
	world := newEvsWorld(t)
	budget := newGatedBudget(world.host.Budget)
	world.folder = world.otherFolder(budget)
	files := []sidecar.EvsTokenPath{worldPath("a"), worldPath("b"), worldPath("c"), worldPath("d")}
	step := world.pageOutStep()
	for version := uint64(1); version <= 255; version += 1 {
		if _, err := world.commit(step, world.nextWrite(files[version%4])); err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
	}
	if entryCount := len(world.head.Head.GetWindow()) / sidecar.EvsWindowEntryByteCount; entryCount != 255 {
		t.Fatalf("a window of %d entries", entryCount)
	}
	_, err := world.commit(step, world.nextWrite(files[0]))
	var behind *EvsFoldBehindError
	if !errors.As(err, &behind) || behind.RetryAfterMs() != 1000 || world.head.Version() != 255 {
		t.Fatalf("past 255: %v at version %d", err, world.head.Version())
	}
	budget.open()
	for _, want := range []struct {
		first      uint64
		entryCount int
	}{{64, 193}, {128, 130}, {192, 67}, {192, 68}} {
		if _, err := world.commit(step, world.nextWrite(files[world.head.Version()%4])); err != nil {
			t.Fatal(err)
		}
		first := EvsHeadWindowFirstVersion(world.head.Head)
		entryCount := len(world.head.Head.GetWindow()) / sidecar.EvsWindowEntryByteCount
		if first != want.first || entryCount != want.entryCount || world.head.Head.GetFoldedThrough() < first-1 {
			t.Fatalf("version %d: window from %d of %d entries, folded through %d", world.head.Version(), first, entryCount, world.head.Head.GetFoldedThrough())
		}
	}
	for _, path := range files {
		world.requireNewest(path)
	}
}

// §11.7's when row (4): on an idle ref whose folded_through trails v, a PATH_EPOCH's process folds every unfolded
// version, and its commit carries folded_through = v.
func TestPathEpochFoldsEveryUnfoldedVersionOfAnIdleRef(t *testing.T) {
	world := newEvsWorld(t)
	files := []sidecar.EvsTokenPath{worldPath("a"), worldPath("b"), worldPath("c")}
	for version := uint64(1); version <= 10; version += 1 {
		world.push(world.nextWrite(files[version%3]))
	}
	world.fold(4)
	head, readAt := world.head, world.clock.Now()
	result, err := world.folder.FoldAll(world.ctx, world.foldCluster, world.repoId, world.refId, head, readAt, readAt.Add(5*time.Second))
	if err != nil || result.From != 4 || result.Through != 10 {
		t.Fatalf("%+v %v", result, err)
	}
	if horizon := world.folder.Horizon(world.repoId, world.refId, head.Head); horizon != 10 {
		t.Fatalf("the epoch's commit would carry %d", horizon)
	}
	world.raiseHorizon()
	if world.head.Head.GetFoldedThrough() != 10 {
		t.Errorf("folded through %d", world.head.Head.GetFoldedThrough())
	}
	for _, path := range files {
		world.requireNewest(path)
	}
}

// FS-58: a directory changed in every version across a page-out keeps its whole listing, its folded table and the
// window's deltas together.
func TestADirectoryChangedInEveryVersionAcrossAPageOutKeepsItsWholeListing(t *testing.T) {
	world := newEvsWorld(t)
	directory := worldPath("d")
	step := world.pageOutStep()
	children := map[sidecar.EvsToken]bool{}
	for version := uint64(1); version <= 130; version += 1 {
		child := worldToken(fmt.Sprintf("c%d", version))
		changes := sortedChanges(
			&worldChange{path: directory, directory: true, base: version - 1, version: version, names: []sidecar.EvsToken{child}},
			&worldChange{path: sidecar.EvsTokenPath{directory[0], child}, version: ExpectedEntryVersion(0, world.head.Version(), 0)},
		)
		if _, err := world.commit(step, changes...); err != nil {
			t.Fatal(err)
		}
		children[child] = true
		listing := world.listing(directory)
		if !listing.Exists || len(listing.Names) != len(children) {
			t.Fatalf("version %d: %d names listed, want %d", version, len(listing.Names), len(children))
		}
		for _, name := range listing.Names {
			if !children[sidecar.EvsToken(name.GetToken())] {
				t.Fatalf("version %d: a name never added", version)
			}
		}
	}
	if first := EvsHeadWindowFirstVersion(world.head.Head); first != 64 {
		t.Errorf("the window starts at %d", first)
	}
	if names := world.entryOf(directory).Entry.GetNames().GetNames(); len(names) < 63 {
		t.Errorf("the folded table holds %d names", len(names))
	}
}

// FS-9's listing cases on the fold's side: a directory at its bound, 3,584 children with real sealed names under
// 64 B, lists whole folded and unfolded, with a concurrent child add and removal; its folded entry stays within idx/'s
// 512 KiB, and a copy carrying it counts each tagged row at its untagged size, so the bound still holds.
func TestADirectoryAtItsBoundFromRealSealedNamesFoldsWhole(t *testing.T) {
	world := newEvsWorld(t)
	repoKey, _, err := sidecar.NewGkmFirstGeneration(world.repoId, testId("group"), &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Time: world.clock.Now(),
		HoldersSha256: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestKey, err := sidecar.NewEvsManifestKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	pathKey, err := sidecar.NewEvsPathKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	directoryToken, err := sidecar.EvsPathToken(pathKey, sidecar.EvsRootToken, []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	directory := sidecar.EvsTokenPath{directoryToken}
	sealedRow := func(name string) *protocol.EvsName {
		token, err := sidecar.EvsPathToken(pathKey, directoryToken, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sidecar.EvsNameSeal(manifestKey, directoryToken, token, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsName{Token: token.Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: sealed}
	}
	// two pushes of 1,792 names each: the bound's 3,584 under 64 B
	halves := [2][]*protocol.EvsName{}
	for i := 0; i < 3584; i += 1 {
		halves[i/1792] = append(halves[i/1792], sealedRow(fmt.Sprintf("child-%04d.txt", i)))
	}
	pushDelta := func(base uint64, version uint64, added []*protocol.EvsName, removed [][]byte) {
		pushId := testId(fmt.Sprintf("push-%d", world.pushSeq+1))
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
			Version: version, PushId: pushId.Bytes(), BaseVersion: world.head.Version(), TimeMs: world.clock.Now().UnixMilli(),
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY), Names: &protocol.EvsNameTable{Names: added, RemovedTokens: removed},
		})
		if err != nil {
			t.Fatal(err)
		}
		world.push(&worldChange{path: directory, directory: true, base: base, version: version, entryVersionBytes: entryBytes})
	}
	pushDelta(0, 1, halves[0], nil)
	pushDelta(1, 2, halves[1], nil)
	if listing := world.listing(directory); len(listing.Names) != 3584 {
		t.Fatalf("unfolded: %d names", len(listing.Names))
	}
	world.fold(2)
	entry := world.entryOf(directory)
	if bound := sidecar.EvsNameTableBoundByteCount(entry.Entry.GetNames()); bound != sidecar.EvsNameTableMaxBoundByteCount {
		t.Errorf("the folded table counts %d bytes against the bound", bound)
	}
	if listing := world.listing(directory); len(listing.Names) != 3584 || listing.TableThrough != 2 {
		t.Fatalf("folded: %d names through %d", len(listing.Names), listing.TableThrough)
	}
	// a child removed and another added in one delta: still whole, folded and not
	replacement := sealedRow("child-new.txt")
	pushDelta(2, 3, []*protocol.EvsName{replacement}, [][]byte{halves[0][0].GetToken()})
	if listing := world.listing(directory); len(listing.Names) != 3584 {
		t.Fatalf("with the window's delta: %d names", len(listing.Names))
	}
	world.fold(3)
	listing := world.listing(directory)
	if len(listing.Names) != 3584 || listing.TableThrough != 3 {
		t.Fatalf("folded again: %d names through %d", len(listing.Names), listing.TableThrough)
	}
	for _, name := range listing.Names {
		if bytes.Equal(name.GetToken(), halves[0][0].GetToken()) {
			t.Error("a removed child still listed")
		}
	}
	// carried into a new epoch, each row tagged: its bound and idx/'s bound hold
	carried := carryEvsIndexEntry(world.entryOf(directory).Entry, 1)
	carriedBytes, err := proto.Marshal(carried)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.EvsNameTableBoundByteCount(carried.GetNames()) != sidecar.EvsNameTableMaxBoundByteCount || EvsIndexEntryMaxByteCount < len(carriedBytes) {
		t.Errorf("a carried table of %d bytes, counting %d", len(carriedBytes), sidecar.EvsNameTableBoundByteCount(carried.GetNames()))
	}
	for _, row := range carried.GetNames().GetNames() {
		if row.GetEpoch() != 1 {
			t.Fatal("an untagged row carried")
		}
	}
}

// §11.7's collect row: a fold that read a head whose collection window covers a marker writes over it only 150 ms
// past until_ms by its clock, never on an unsure clock, and a page-out's fold, which never waits, defers instead.
func TestFoldWritesOverACoveredMarkerOnlyPastTheCollectionWindow(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("x")
	world.push(&worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1})
	world.fold(2)
	creation := ExpectedEntryVersion(0, world.head.Version(), 2)
	world.push(&worldChange{path: file, version: creation})
	untilMs := world.clock.Now().Add(30 * time.Second).UnixMilli()
	world.fenceWrite(func(next *protocol.EvsHead) {
		next.Collect = &protocol.EvsCollect{Through: 2, UntilMs: untilMs}
	})
	request := func(noWait bool) *EvsFoldRequest {
		rank := sidecar.WriteP2RankFold
		if noWait {
			rank = sidecar.WriteP2RankPageOutFold
		}
		return &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: rank, NoWait: noWait}
	}
	if _, err := world.folder.Fold(world.ctx, request(true)); !errors.Is(err, ErrEvsFoldDeferred) {
		t.Errorf("a page-out's fold over a covered marker: %v", err)
	}
	world.host.ClockCheck.SetUnknown()
	if _, err := world.folder.Fold(world.ctx, request(false)); !errors.Is(err, ErrEvsFoldDeferred) {
		t.Errorf("a fold on an unsure clock: %v", err)
	}
	world.host.ClockCheck.SetOffset(0)
	if marker := world.entryOf(file).Entry.GetMarker(); marker == nil {
		t.Fatal("the marker was written over")
	}
	done := make(chan struct{})
	var result *EvsFoldResult
	var err error
	go func() {
		defer close(done)
		result, err = world.folder.Fold(world.ctx, request(false))
	}()
	// the fold waits on a timer at 150 ms past until_ms, and the test moves the clock only once it is set
	writableAt := time.UnixMilli(untilMs).Add(150 * time.Millisecond)
	for {
		pending, added := world.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(at time.Time) bool { return at.Equal(writableAt) }) {
			break
		}
		awaitClosed(t, added, "the fold's wait for the window")
	}
	world.clock.AdvanceTo(writableAt.Add(-time.Millisecond))
	select {
	case <-done:
		t.Fatal("the fold wrote inside the margin")
	default:
	}
	if marker := world.entryOf(file).Entry.GetMarker(); marker == nil {
		t.Fatal("the marker was written over inside the margin")
	}
	world.clock.Advance(time.Millisecond)
	awaitClosed(t, done, "the fold past the margin")
	if err != nil || result.EntryWriteCount != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	entry := world.entryOf(file).Entry
	if entry.GetMarker() != nil || len(entry.GetVersions()) != 1 || entry.GetVersions()[0].GetCommitVersion() != 3 {
		t.Errorf("after the window: %v", entry)
	}
}

// §11.7's epochs row: while the head lists sources, a fold carries a path only a source holds with its folded
// versions, writes a new path fresh and a removal as removed, each state in the entry's metadata.
func TestFoldWhileSourcesStandCarriesFreshAndRemovedEntries(t *testing.T) {
	world := newEvsWorld(t)
	oldX, oldY := worldPath("x"), worldPath("y")
	world.push(&worldChange{path: oldX, version: 1}, &worldChange{path: oldY, version: 1})
	world.fold(1)
	// the path epoch's commit: epoch 2 current, epoch 1 its source, everything folded
	world.fenceWrite(func(next *protocol.EvsHead) {
		next.PathEpoch = &protocol.EvsPathEpoch{Current: 2, Sources: []*protocol.EvsEpochSource{{Epoch: 1, MapSha256: make([]byte, 32)}}}
	})
	sourceOf := func(path sidecar.EvsTokenPath) [][]byte {
		encoded, err := proto.Marshal(&protocol.EvsSourcePath{Epoch: 1, TokenPath: path.Components()})
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{encoded}
	}
	newX, newY, newW := worldPath("x2"), worldPath("y2"), worldPath("w2")
	world.push(&worldChange{path: newX, base: 1, version: 2, sourcePaths: sourceOf(oldX)})
	world.push(&worldChange{path: newW, version: 3})
	world.push(&worldChange{path: newY, base: 1, sourcePaths: sourceOf(oldY)})
	world.fold(4)
	for _, c := range []struct {
		path  sidecar.EvsTokenPath
		state EvsEntryStateValue
	}{
		{newX, EvsEntryStateValue{State: EvsEntryStateCarried, Epoch: 1}},
		{newW, EvsEntryStateValue{State: EvsEntryStateFresh}},
		{newY, EvsEntryStateValue{State: EvsEntryStateRemoved}},
	} {
		state, exists, err := HeadEntryState(world.ctx, world.cluster, world.repoId, world.refId, 2, c.path)
		if err != nil || !exists || state != c.state {
			t.Errorf("path %x: %+v %v %v, want %+v", c.path.Bytes()[:2], state, exists, err, c.state)
		}
	}
	versions := world.entryOf(newX).Entry.GetVersions()
	if len(versions) != 2 || versions[0].GetCommitVersion() != 2 || versions[1].GetCommitVersion() != 1 {
		t.Errorf("the carried entry holds %d versions", len(versions))
	}
	if marker := world.entryOf(newY).Entry.GetMarker(); marker == nil || marker.GetPathVersion() != 2 {
		t.Errorf("the removed entry's marker %v", marker)
	}
}

// The cut-over to epoch 2 with epoch 1 its source, as a PATH_EPOCH's commit leaves the head, everything folded.
func (self *evsWorld) cutOverToEpochTwo() {
	self.t.Helper()
	self.fenceWrite(func(next *protocol.EvsHead) {
		next.PathEpoch = &protocol.EvsPathEpoch{Current: 2, Sources: []*protocol.EvsEpochSource{{Epoch: 1, MapSha256: make([]byte, 32)}}}
	})
}

// A path's encoded source path in epoch, as a change names it while sources stand.
func (self *evsWorld) sourceOf(epoch uint64, path sidecar.EvsTokenPath) [][]byte {
	encoded, err := proto.Marshal(&protocol.EvsSourcePath{Epoch: epoch, TokenPath: path.Components()})
	if err != nil {
		self.t.Fatal(err)
	}
	return [][]byte{encoded}
}

// Whether epoch holds an entry for path.
func (self *evsWorld) holds(epoch uint64, path sidecar.EvsTokenPath) bool {
	self.t.Helper()
	read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, epoch, path, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return !read.Absent()
}

// One fold of the world's whole range by folder.
func (self *evsWorld) foldBy(folder *Folder) *EvsFoldResult {
	self.t.Helper()
	result, err := folder.Fold(self.ctx, &EvsFoldRequest{Cluster: self.foldCluster, RepoId: self.repoId, RefId: self.refId, Rank: sidecar.WriteP2RankFold})
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// DESIGN-DETAILS 9.2.6: while sources stand, once a path's current entry holds its changes the fold deletes the
// source copies they name, a modification's after carrying from it and a removal's after its marker; a path whose
// changes name no source leaves the source as it is; and a rerun of the range deletes nothing more.
func TestFoldDeletesTheSourceCopiesItsChangesName(t *testing.T) {
	world := newEvsWorld(t)
	oldX, oldY, oldZ := worldPath("x"), worldPath("y"), worldPath("z")
	world.push(&worldChange{path: oldX, version: 1}, &worldChange{path: oldY, version: 1}, &worldChange{path: oldZ, version: 1})
	world.fold(1)
	world.cutOverToEpochTwo()
	newX, newY, newZ := worldPath("x2"), worldPath("y2"), worldPath("z2")
	world.push(&worldChange{path: newX, base: 1, version: 2, sourcePaths: world.sourceOf(1, oldX)})
	world.push(&worldChange{path: newY, base: 1, sourcePaths: world.sourceOf(1, oldY)})
	world.push(&worldChange{path: newZ, base: 1, version: 2})
	result := world.foldBy(world.folder)
	if result.SourceDeleteCount != 2 || result.EntryWriteCount != 3 {
		t.Fatalf("the fold: %+v", result)
	}
	if world.holds(1, oldX) || world.holds(1, oldY) || !world.holds(1, oldZ) {
		t.Fatalf("epoch 1 holds x %t, y %t, z %t", world.holds(1, oldX), world.holds(1, oldY), world.holds(1, oldZ))
	}
	if versions := world.entryOf(newX).Entry.GetVersions(); len(versions) != 2 {
		t.Fatalf("x's current entry holds %d versions, not its carried one and its own", len(versions))
	}
	if marker := world.entryOf(newY).Entry.GetMarker(); marker == nil {
		t.Fatal("y's removal left no marker")
	}
	world.raiseHorizon()
	if again := world.foldBy(world.otherFolder(world.host.Budget)); again.SourceDeleteCount != 0 || again.EntryWriteCount != 0 {
		t.Fatalf("a fold of nothing new: %+v", again)
	}
}

// DESIGN-DETAILS 9.6: a fold killed between its PUT of the current entry and its DELETE of the source copy leaves the
// range unfolded, the copy standing beside the current entry; the rerun by another process finds the entry holding
// the change, writes nothing, and still deletes, and only then does its commit raise folded_through.
func TestFoldKilledBetweenItsPutAndItsSourceDelete(t *testing.T) {
	world := newEvsWorld(t)
	oldX := worldPath("x")
	world.push(&worldChange{path: oldX, version: 1})
	world.fold(1)
	world.cutOverToEpochTwo()
	newX := worldPath("x2")
	world.push(&worldChange{path: newX, base: 1, version: 2, sourcePaths: world.sourceOf(1, oldX)})
	fired, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpDelete, KeyPrefix: IndexEntryKey(world.repoId, world.refId, 1, oldX), Result: sidecartest.CrashBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	died := make(chan struct{})
	go func() {
		defer close(died)
		world.folder.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold})
		t.Error("the killed fold returned")
	}()
	awaitClosed(t, died, "the fold's death")
	awaitClosed(t, fired, "the crash")
	if !world.holds(2, newX) || !world.holds(1, oldX) {
		t.Fatalf("after the kill: current %t, source %t", world.holds(2, newX), world.holds(1, oldX))
	}
	if horizon := world.folder.Horizon(world.repoId, world.refId, world.head.Head); horizon != world.head.Head.GetFoldedThrough() {
		t.Fatalf("a fold killed before its deletes left a horizon of %d", horizon)
	}
	rerun := world.otherFolder(world.host.Budget)
	result := world.foldBy(rerun)
	if result.EntryWriteCount != 0 || result.SourceDeleteCount != 1 || result.Through != 2 {
		t.Fatalf("the rerun: %+v", result)
	}
	if world.holds(1, oldX) {
		t.Fatal("the rerun left the source copy")
	}
	world.folder = rerun
	world.raiseHorizon()
	if folded := world.head.Head.GetFoldedThrough(); folded != 2 {
		t.Fatalf("folded through %d after the rerun", folded)
	}
}

// DESIGN-DETAILS 9.2.6's directory rule: a fold of a directory's removal, its marker standing, LISTs every key below
// the directory in the source its removal names and deletes each, nested ones included, leaving the source's other
// entries.
func TestFoldRemovingADirectoryEmptiesItsNamedSourceBelowIt(t *testing.T) {
	world := newEvsWorld(t)
	directory, x, y, z, other := worldPath("d"), worldPath("d", "x"), worldPath("d", "y"), worldPath("d", "y", "z"), worldPath("o")
	world.push(sortedChanges(
		&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x"), worldToken("y")}},
		&worldChange{path: x, version: 1},
		&worldChange{path: y, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("z")}},
		&worldChange{path: z, version: 1},
		&worldChange{path: other, version: 1},
	)...)
	world.fold(1)
	world.cutOverToEpochTwo()
	newDirectory := worldPath("d2")
	world.push(&worldChange{path: newDirectory, base: 1, directory: true, sourcePaths: world.sourceOf(1, directory)})
	result := world.foldBy(world.folder)
	if result.SourceDeleteCount != 4 || result.MarkerWriteCount != 1 {
		t.Fatalf("the fold: %+v", result)
	}
	if marker := world.entryOf(newDirectory).Entry.GetMarker(); marker == nil {
		t.Fatal("the directory's removal left no marker")
	}
	objects, _, err := world.cluster.List(world.ctx, IndexEpochPrefix(world.repoId, world.refId, 1), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Key != IndexEntryKey(world.repoId, world.refId, 1, other) {
		keys := []string{}
		for _, object := range objects {
			keys = append(keys, object.Key)
		}
		t.Fatalf("epoch 1 keeps %q", keys)
	}
}

// §11.7's when row: a commit leaving FoldUnfoldedTriggerCount unfolded has its process fold the oldest
// FoldVersionCount, at most once per FoldTriggerInterval, and FoldIdleDelay after a ref's last commit the rest; the
// horizon rises with that process's next commit, and the folds the ref owes are declared to the budget.
func TestCommitsTriggerFoldsOfTheOldestAndAfterIdlingTheRest(t *testing.T) {
	world := newEvsWorld(t)
	world.settings.FoldUnfoldedTriggerCount = 3
	world.settings.FoldVersionCount = 2
	files := []sidecar.EvsTokenPath{worldPath("a"), worldPath("b")}
	commit := func() {
		_, err := world.commit(func(prior *EvsStoredHead, next *protocol.EvsHead) error {
			next.FoldedThrough = max(next.GetFoldedThrough(), world.folder.Horizon(world.repoId, world.refId, prior.Head))
			return nil
		}, world.nextWrite(files[world.head.Version()%2]))
		if err != nil {
			t.Fatal(err)
		}
		world.folder.NoteCommit("meta-1", world.repoId, world.refId, world.head.Head)
	}
	awaitFolds := func(count int) {
		for {
			finished, next := world.folder.BackgroundFolds()
			if count <= finished {
				return
			}
			awaitClosed(t, next, fmt.Sprintf("background fold %d", count))
		}
	}
	commit()
	commit()
	if folds, _ := world.folder.BackgroundFolds(); folds != 0 {
		t.Fatalf("%d folds under the trigger", folds)
	}
	if backlog := world.host.Budget.P2Backlog("meta-1", "folds", sidecar.WriteP2RankFold, true); backlog <= 0 {
		t.Errorf("a backlog of %d declared", backlog)
	}
	commit()
	awaitFolds(1)
	commit()
	if folded := world.head.Head.GetFoldedThrough(); folded != 2 {
		t.Fatalf("the next commit carries folded_through %d", folded)
	}
	// three unfolded again within the interval: no fold
	commit()
	if folds, _ := world.folder.BackgroundFolds(); folds != 1 {
		t.Fatalf("%d folds within the interval", folds)
	}
	world.clock.Advance(10 * time.Second)
	commit()
	awaitFolds(2)
	if horizon := world.folder.Horizon(world.repoId, world.refId, world.head.Head); horizon != 4 {
		t.Errorf("after the second trigger the horizon is %d", horizon)
	}
	world.clock.Advance(10 * time.Minute)
	awaitFolds(3)
	if horizon := world.folder.Horizon(world.repoId, world.refId, world.head.Head); horizon != world.head.Version() {
		t.Errorf("after idling the horizon is %d of %d", horizon, world.head.Version())
	}
	if backlog := world.host.Budget.P2Backlog("meta-1", "folds", sidecar.WriteP2RankFold, true); backlog != 0 {
		t.Errorf("a backlog of %d left", backlog)
	}
	if spent := world.host.Budget.P2ByteCount("meta-1", true); spent <= 0 {
		t.Error("folds spent no funded P2")
	}
	for _, path := range files {
		world.requireNewest(path)
	}
}

// §11.13's skip row: a fold of a repo neither active nor deleted issues no write.
func TestFoldWritesNothingForARepoNeitherActiveNorDeleted(t *testing.T) {
	world := newEvsWorld(t)
	world.push(&worldChange{path: worldPath("x"), version: 1})
	world.putRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING)
	_, err := world.folder.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold})
	if !errors.Is(err, ErrEvsFoldRepoState) {
		t.Fatalf("a shredding repo's fold: %v", err)
	}
	if !world.entryOf(worldPath("x")).Absent() {
		t.Error("a shredding repo's entry written")
	}
}

// A log page read back is held to its number, entries, statements and chain before use.
func TestParseLogPageRefusesTamperedPages(t *testing.T) {
	world := newEvsWorld(t)
	for version := uint64(1); version <= 128; version += 1 {
		if _, err := world.commit(world.pageOutStep(), world.nextWrite(worldPath(fmt.Sprintf("f%d", version%3)))); err != nil {
			t.Fatal(err)
		}
	}
	object, err := world.cluster.Get(world.ctx, LogPageKey(world.repoId, world.refId, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	pageBytes, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLogPage(world.repoId, world.refId, 0, pageBytes); err != nil {
		t.Fatalf("the page as written: %v", err)
	}
	tampered := map[string]func(page *protocol.EvsLogPage){
		"another page's number": func(page *protocol.EvsLogPage) { page.Page = 1 },
		"two statements swapped": func(page *protocol.EvsLogPage) {
			page.Statements[0], page.Statements[1] = page.Statements[1], page.Statements[0]
		},
		"a statement missing": func(page *protocol.EvsLogPage) { page.Statements = page.Statements[1:] },
		"another last chain":  func(page *protocol.EvsLogPage) { page.LastChain = make([]byte, 32) },
		"another first chain": func(page *protocol.EvsLogPage) { page.FirstChain = make([]byte, 32) },
		"an entry swapped": func(page *protocol.EvsLogPage) {
			window := bytes.Clone(page.Window)
			copy(window[0:64], page.Window[64:128])
			copy(window[64:128], page.Window[0:64])
			page.Window = window
		},
	}
	for name, tamper := range tampered {
		page := &protocol.EvsLogPage{}
		if err := proto.Unmarshal(pageBytes, page); err != nil {
			t.Fatal(err)
		}
		tamper(page)
		tamperedBytes, err := proto.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseLogPage(world.repoId, world.refId, 0, tamperedBytes); !errors.Is(err, ErrEvsLogPageInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for page, want := range map[uint64][2]uint64{0: {1, 63}, 1: {64, 127}, 2: {128, 191}} {
		first, last := EvsLogPageVersions(page)
		if first != want[0] || last != want[1] || EvsLogPageOf(first) != page || EvsLogPageOf(last) != page {
			t.Errorf("page %d holds %d to %d", page, first, last)
		}
	}
}
