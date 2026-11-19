//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-111 on T2 (§11.14's cut, epoch, erase and writers rows; §11.12's cut, rekey and reconcile rows; D-EVS-66,
// I-EVS-17, FI-2, FI-18, FI-19; SEARCH-M10-37): an erasure's CUT fencing every kind of index push prepared before it,
// with no indexer and no hint, on the search world, whose erasure model stands in for evs's eraser routes
// (search_erase_testhooks.go) under a slot-keyed repo's keys, the index's own eraser (SEARCH-M10-16, SEARCH-M10-17)
// cutting, rewriting and resuming, and a desktop's search held to SearchOracle's set after the steps.
//
//	kinds     prepared before eraser B's CUT and paused just before their head CAS: a companion push to a fresh writer
//	          head and one to a large entry (planned at the old epoch), a merge's new shard (held at its built
//	          barrier), a backfill's head, a build, and a push opening its writer's head in a slot a merge absorbed;
//	          each is refused 409 INDEX_EPOCH, a refused one stays refused, and each rebuilds from the erasure set and
//	          commits without the documents it lists
//	death     B dies right after its first CLOSURE, the clock passes 20 min, and its device's restart finishes the
//	          erasure from evs's state, first erasing the keys its orphaned CLOSURE names; with B's device gone, another
//	          device of B's member finishes it 25 h after the CUT and not before
//	closure   a CLOSURE built before another eraser's CUT still commits, a CLOSURE naming no epoch
//	after     no index file version committed after the CUT holds a listed document; every stored version that held
//	          one, a held one included, has its key destroyed, so none opens; a fresh device masks the documents from
//	          the CUT and fetches none of their copies after the ERASE
//	twins     a builder that ignores the set, and an erasure whose ERASEs never commit, each fail the check above that
//	          catches them
//
// The main clauses also run as a schedule under TEST-M10-02's search invariants, FI-18 to FI-23 read after every step
// (TestFs111UnderTheSearchInvariants); and the fence of a paused in-ref push, the CLOSURE, the eraser's death and its
// resume run on real engines as the row's registered case (fs111.go), on T2 here (TestFs111) and on T3 through server's
// evshost (server/fs111_t3_test.go).
//
// No hint reaches anyone here: every device reads the index at its next round, which is FS-111's "every hint is
// dropped". The world's store checks no push life or signed time, so a planned push sent 20 min on reaches the epoch
// check as a push in parts does within its 30-minute seal; a builder's own push is let go within its 5-minute life.
// Not here, each named for what it waits on: the evs clauses (a stale index_epoch refused at once and a
// future one once recorded, a CUT changing a file but the set or past 16,208 B, a CUT below admin), which evsservice's
// check_cut_test.go runs on the engine (EVS2-M10-11); a multi-part push's 30-minute seal and an i2 rebuild in parts
// (no builder writes in parts or into i2 yet, SEARCH-M10-15's draft: the build case is one push); a writer's journal
// begun below listed_since (the world has no companion journal; TestIndexJournalBegunBelowListedSinceRebuilds runs it
// on the root's fake); and the mailbox and team-record cases, at the later of M10-out and M7-out and M6-out.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// --- what FS-78, FS-111 and FS-112 share ---

// The barrier hooks of one erasure schedule: a hold of a barrier's first arrival until released, and a kill of a
// barrier's first arrival, which ends that goroutine there as a process the OS killed. One a test: they are the
// process's test hooks.
type fsEraseHooks struct {
	stateLock sync.Mutex
	holds     map[string]*fsEraseHold
	kills     map[string]chan struct{}
	// barrier names reached, in order
	reached []string
	// at each arrival, before a hold or a kill
	onBarrier func(name string)
}

// One barrier's held arrival.
type fsEraseHold struct {
	reached chan struct{}
	release chan struct{}
	used    bool
}

// Installs the hooks for the test.
func newFsEraseHooks(t *testing.T) *fsEraseHooks {
	hooks := &fsEraseHooks{holds: map[string]*fsEraseHold{}, kills: map[string]chan struct{}{}}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		hooks.arrive(name)
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	return hooks
}

// An arrival at name.
func (self *fsEraseHooks) arrive(name string) {
	var hold *fsEraseHold
	var killed chan struct{}
	var onBarrier func(name string)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.reached = append(self.reached, name)
		onBarrier = self.onBarrier
		if candidate := self.holds[name]; candidate != nil && !candidate.used {
			candidate.used = true
			hold = candidate
		}
		if candidate, ok := self.kills[name]; ok {
			delete(self.kills, name)
			killed = candidate
		}
	}()
	if onBarrier != nil {
		onBarrier(name)
	}
	if hold != nil {
		close(hold.reached)
		<-hold.release
	}
	if killed != nil {
		close(killed)
		runtime.Goexit()
	}
}

// Holds name's next arrival until the hold is released.
func (self *fsEraseHooks) hold(name string) *fsEraseHold {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold := &fsEraseHold{reached: make(chan struct{}), release: make(chan struct{})}
	self.holds[name] = hold
	return hold
}

// Kills the goroutine making name's next arrival; the channel closes as it dies.
func (self *fsEraseHooks) kill(name string) chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	killed := make(chan struct{})
	self.kills[name] = killed
	return killed
}

// Whether name was reached.
func (self *fsEraseHooks) wasReached(name string) bool {
	return 0 < self.count(name)
}

// How many times name was reached.
func (self *fsEraseHooks) count(name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, reached := range self.reached {
		if reached == name {
			count += 1
		}
	}
	return count
}

// Whether path is a writer's large entry, b/<S>/w/<xx>/<writer>/L<n>.
func fsIsLargeEntry(path string) bool {
	name := path[strings.LastIndex(path, "/")+1:]
	return strings.Contains(path, "/w/") && strings.HasPrefix(name, "L")
}

// A listed document: its path, doc_key, and the version through which the CUT lists it.
type fsErased struct {
	path    string
	key     [16]byte
	version uint64
}

// The CUT's documents of erased.
func fsCutDocuments(erased []*fsErased) []*sidecar.IndexCutDocument {
	documents := []*sidecar.IndexCutDocument{}
	for _, document := range erased {
		documents = append(documents, &sidecar.IndexCutDocument{Key: document.key, Version: document.version})
	}
	return documents
}

// path's chunk 0 at version, erased.
func fsErasedOf(t *testing.T, world *searchWorld, path string, version uint64) *fsErased {
	t.Helper()
	key, err := world.index.DocKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return &fsErased{path: path, key: key, version: version}
}

// The ledger forgets each erased document from the CUT on, as readers mask it (§11.14's cut row).
func (self *searchWorld) eraseInLedger(t *testing.T, erased []*fsErased) {
	t.Helper()
	for _, document := range erased {
		if err := self.ledger.Erase(self.index.RepoId(), self.index.RefId(), document.path, document.version); err != nil {
			t.Fatal(err)
		}
	}
}

// FI-19's fence: no index file version committed after the CUT at cutVersion holds a listed document. A CLOSURE
// re-keys a file that held one and writes it clean, so a CLOSURE holding one breaks it too.
func fsEraseFence(erasure *sidecar.SearchTestErasure, cutVersion uint64, erased []*fsErased) error {
	holding, err := erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		return err
	}
	for _, held := range holding {
		if cutVersion < held.CommitVersion {
			return fmt.Errorf("%s@%d, committed at %d after the CUT at %d, holds a listed document (closure %t)", held.Path, held.Version, held.CommitVersion, cutVersion, held.Closure)
		}
	}
	return nil
}

// FI-19's sweep once an erasure completes: no stored version a current reader's keys open holds a listed document,
// and each stored version that held one has its key destroyed; wantHeld asks that a held one be among them.
func fsEraseSweep(erasure *sidecar.SearchTestErasure, erased []*fsErased, wantHeld bool) error {
	holding, err := erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		return err
	}
	held := false
	for _, version := range holding {
		if version.Openable() {
			return fmt.Errorf("%s@%d (live %t, held %t, staged %t) holds a listed document and still opens", version.Path, version.Version, version.Live, version.Held, version.Staged)
		}
		held = held || version.Held && version.Destroyed
	}
	if wantHeld && !held {
		return errors.New("no held version holding a listed document was among the destroyed ones")
	}
	return nil
}

// What a fresh device fetches of the copies holding the erased documents after the erasure: none, and it finds none.
func (self *searchWorld) fsEraseFreshDevice(t *testing.T, erasure *sidecar.SearchTestErasure, erased []*fsErased, queries []string) {
	t.Helper()
	ctx := t.Context()
	device, err := self.device(ctx, searchHostNamed("desktop"), nil, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer self.done(device)
	for _, query := range queries {
		if hits := self.searchOn(t, device, query); 0 < len(hits) {
			t.Fatalf("a fresh device's %q found %v after the erasure", query, hits)
		}
	}
	holding, err := erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		t.Fatal(err)
	}
	copies := map[string]bool{}
	for _, held := range holding {
		copies[fmt.Sprintf("%s@%d", held.Path, held.Version)] = true
	}
	for _, fetch := range device.Fetches() {
		if copies[fmt.Sprintf("%s@%d", fetch.Path, fetch.Version)] {
			t.Fatalf("a fresh device fetched %s@%d, a copy of an erased document", fetch.Path, fetch.Version)
		}
	}
}

// An erasure world: the search world, its erasure model and its clock.
type fsEraseWorld struct {
	*searchWorld
	clock   *sidecartest.FakeClock
	erasure *sidecar.SearchTestErasure
}

// A search world of label with an erasure model under settings, nil taking a slot-keyed repo's.
func newFsEraseWorld(t *testing.T, label string, settings *sidecar.SearchTestErasureSettings) *fsEraseWorld {
	t.Helper()
	world, clock := newFsIndexWorld(t, label)
	return &fsEraseWorld{searchWorld: world, clock: clock, erasure: world.index.NewErasure(settings)}
}

// An eraser of the world's ref signing as signer (zero: the world's admin), its events kept.
func (self *fsEraseWorld) eraser(t *testing.T, signer sidecar.Id, events *[]sidecar.SidecarErasure) *sidecar.IndexEraser {
	t.Helper()
	args := &sidecar.SearchTestEraserArgs{Signer: signer}
	if events != nil {
		args.Events = func(erasure *sidecar.SidecarErasure) { *events = append(*events, *erasure) }
	}
	eraser, err := self.erasure.NewEraser(args)
	if err != nil {
		t.Fatal(err)
	}
	return eraser
}

// The CUT of erased by eraser: the ref version it committed at, the ledger forgetting them from then.
func (self *fsEraseWorld) cut(t *testing.T, eraser *sidecar.IndexEraser, erasureId sidecar.Id, erased []*fsErased) uint64 {
	t.Helper()
	result, err := eraser.Cut(t.Context(), &sidecar.IndexCutArgs{ErasureId: erasureId, Documents: fsCutDocuments(erased)})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pushed || result.Version == 0 {
		t.Fatalf("the CUT pushed nothing: %+v", result)
	}
	if epoch, err := self.index.IndexEpoch(t.Context()); err != nil || epoch != result.Version {
		t.Fatalf("after the CUT at %d the head's index_epoch is %d, %v", result.Version, epoch, err)
	}
	self.eraseInLedger(t, erased)
	return result.Version
}

// writer's push of documents at now, recorded in the ledger.
func (self *fsEraseWorld) push(t *testing.T, writer sidecar.Id, documents ...*sidecar.SearchTestDocument) {
	t.Helper()
	now := self.clock.Now()
	if err := self.index.PushDocuments(t.Context(), writer, now, documents); err != nil {
		t.Fatal(err)
	}
	if err := self.record(now, documents...); err != nil {
		t.Fatal(err)
	}
}

// The live doc_keys of the world's index files.
func (self *fsEraseWorld) live(t *testing.T) map[[16]byte]uint64 {
	t.Helper()
	live, err := self.index.LiveDocKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return live
}

// Rewrites erasureId to its end with eraser, below the limit: it never waits.
func fsRewriteAll(t *testing.T, eraser *sidecar.IndexEraser, erasureId sidecar.Id, complete bool) *sidecar.IndexRewriteResult {
	t.Helper()
	result, err := eraser.Rewrite(t.Context(), &sidecar.IndexRewriteArgs{ErasureId: erasureId, Complete: complete, Note: []byte("note")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Erasure == nil || result.Erasure.State == sidecar.SidecarErasureWaiting {
		t.Fatalf("a rewrite below the limit waited: %+v", result.Erasure)
	}
	return result
}

// Runs eraser's rewrite of erasureId in the background, killed at its first CLOSURE: answers once it died there.
func fsRewriteKilledAtFirstClosure(t *testing.T, hooks *fsEraseHooks, eraser *sidecar.IndexEraser, erasureId sidecar.Id) {
	t.Helper()
	killed := hooks.kill("evs.index.erase.closed")
	ended := make(chan error, 1)
	go func() {
		_, err := eraser.Rewrite(context.Background(), &sidecar.IndexRewriteArgs{ErasureId: erasureId, Complete: true, Note: []byte("note")})
		ended <- err
	}()
	select {
	case <-killed:
	case err := <-ended:
		t.Fatalf("the rewrite ended before its first CLOSURE: %v", err)
	}
}

// --- FS-111 ---

// The world's three companion-style documents and the bucket's filler, laid out for the kinds that ride a writer's or
// a merger's push: writer W's head holds D, writer L's large entry holds Dl, and writer S's 160 sealed slots hold Dm
// among their documents.
func fs111Kinds(t *testing.T, world *fsEraseWorld) (*sidecar.SearchTestDocument, *sidecar.SearchTestDocument, string, []*fsErased) {
	t.Helper()
	now := world.clock.Now()
	d := fsIndexDocument("notes/cormorant.md", 1, "cormorant", now)
	large, phrase := fs74IdeographDocument("notes/atlas.md", 1, 4000, 23, now)
	world.push(t, searchId("writer w"), d)
	world.push(t, searchId("writer l"), large)
	world.fillSeals(t, searchId("writer s"), "seal", 160, now)
	erased := []*fsErased{
		fsErasedOf(t, world.searchWorld, d.Path, 1),
		fsErasedOf(t, world.searchWorld, large.Path, 1),
		fsErasedOf(t, world.searchWorld, "notes/seal-7.md", 1),
	}
	return d, large, phrase, erased
}

// FS-111's main schedule: a companion push to a fresh writer head, one to a large entry and a merge's new shard, each
// prepared before eraser B's CUT and paused before its head CAS; B dies right after its first CLOSURE and the clock
// passes 20 min; each push is refused 409 INDEX_EPOCH, stays refused, and rebuilds without the listed documents; B's
// device restarting finishes the erasure from evs's state, its orphaned CLOSURE's keys erased first; afterwards no
// version committed after the CUT holds a listed document, every stored copy, a held one included, has its key
// destroyed, and a fresh device masks them from the CUT and fetches none of their copies after the ERASE.
func TestFs111PreparedPushesRebuildWithoutTheDocuments(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 kinds", nil)
	ctx := t.Context()
	hooks := newFsEraseHooks(t)
	d, large, phrase, erased := fs111Kinds(t, world)
	queries := []string{"cormorant", phrase, "marker0007"}
	for _, query := range queries {
		if hits := world.checkSearch(t, query); len(hits) != 1 {
			t.Fatalf("before the erasure %q found %v", query, hits)
		}
	}
	// a hold keeps what stands now: W's head among it
	world.erasure.SetHold(true)

	// the kinds, each paused before its head CAS
	now := world.clock.Now()
	e := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", now)
	companion, err := world.index.PlanPush(ctx, searchId("writer a"), now, []*sidecar.SearchTestDocument{d, e})
	if err != nil {
		t.Fatal(err)
	}
	largeCompanion, err := world.index.PlanPush(ctx, searchId("writer a2"), now, []*sidecar.SearchTestDocument{large})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(largeCompanion.Paths(), fsIsLargeEntry) {
		t.Fatalf("the large document's companion push writes no large entry: %v", largeCompanion.Paths())
	}
	mergeHeld := hooks.hold("evs.index.merge.built")
	merged := make(chan *sidecar.SearchTestMerge, 1)
	mergeErr := make(chan error, 1)
	go func() {
		result, err := world.index.MergeResult(context.Background(), searchId("merger"), 0)
		merged <- result
		mergeErr <- err
	}()
	<-mergeHeld.reached

	// B's CUT; no hint reaches anyone
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs111 erasure")
	cutVersion := world.cut(t, b, erasureId, erased)
	for _, query := range queries {
		if hits := world.checkSearch(t, query); 0 < len(hits) {
			t.Fatalf("from the CUT %q found %v", query, hits)
		}
	}

	// the merge, built before the CUT, is refused and rebuilt without Dm
	close(mergeHeld.release)
	if err := <-mergeErr; err != nil {
		t.Fatal(err)
	}
	if result := <-merged; result.Version == 0 || result.Attempts < 2 {
		t.Fatalf("the merge built before the CUT: %+v", result)
	}

	// B dies right after its first CLOSURE, and 20 min pass
	fsRewriteKilledAtFirstClosure(t, hooks, b, erasureId)
	if closures, erases := world.erasure.Closures(), world.erasure.Erases(); len(closures) != 1 || len(erases) != 0 {
		t.Fatalf("B died after %d CLOSUREs and %d ERASEs", len(closures), len(erases))
	}
	world.clock.Advance(20 * time.Minute)

	// each companion push is refused, stays refused, and rebuilds without the listed documents
	for _, planned := range []*sidecar.SearchTestPlannedPush{companion, largeCompanion} {
		for attempt := range 2 {
			if _, err := planned.Commit(ctx); !errors.Is(err, sidecar.ErrSearchTestIndexEpoch) {
				t.Fatalf("attempt %d of a push built before the CUT: %v", attempt, err)
			}
		}
	}
	// rebuilt from the erasure set: D's entry leaves the push, E's stays
	if err := world.index.PushDocuments(ctx, searchId("writer a"), world.clock.Now(), []*sidecar.SearchTestDocument{d, e}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(world.clock.Now(), e); err != nil {
		t.Fatal(err)
	}
	if err := world.index.PushDocuments(ctx, searchId("writer a2"), world.clock.Now(), []*sidecar.SearchTestDocument{large}); err != nil {
		t.Fatal(err)
	}
	live := world.live(t)
	for _, document := range erased {
		if _, ok := live[document.key]; ok && document.path != d.Path {
			// D stands in W's head until a CLOSURE rewrites it; the rebuilt pushes add none
			t.Fatalf("%s is live after the rebuilt pushes", document.path)
		}
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	world.checkSearch(t, "lighthouse")

	// B's device starts again and finishes from evs's state, its orphan's keys first
	orphan := world.erasure.Closures()[0]
	restarted := world.eraser(t, sidecar.Id{}, nil)
	resumed, err := restarted.Resume(ctx, &sidecar.IndexResumeArgs{ErasureId: erasureId, Role: sidecar.IndexResumeEraser, Complete: true, Note: []byte("note")})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Rewrite == nil || !resumed.Rewrite.Completed || !world.erasure.Complete(erasureId) {
		t.Fatalf("the restarted eraser did not finish: %+v", resumed.Rewrite)
	}
	if erases := world.erasure.Erases(); len(erases) == 0 || erases[0].KeyCount != orphan.KeyCount {
		t.Fatalf("the restart's first ERASE named %v keys, the orphaned CLOSURE %d", erases, orphan.KeyCount)
	}
	for _, document := range erased {
		if _, ok := world.live(t)[document.key]; ok {
			t.Fatalf("%s is live after the erasure", document.path)
		}
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	if err := fsEraseSweep(world.erasure, erased, true); err != nil {
		t.Fatal(err)
	}
	world.fsEraseFreshDevice(t, world.erasure, erased, queries)
	world.checkSearch(t, "lighthouse")
	world.checkSearch(t, "marker0008")
}

// FS-111's reused old slot: a push opening its writer's head in a slot a merge absorbed, holding D, planned before the
// CUT, is refused 409 INDEX_EPOCH and rebuilt into that slot without D.
func TestFs111AReusedSlotRebuildsWithoutTheDocument(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 reuse", nil)
	ctx := t.Context()
	s := searchId("writer s")
	world.fillSeals(t, s, "seal", 160, world.clock.Now())
	if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	absorbed, err := world.index.WriterFiles(ctx, s, 0)
	if err != nil {
		t.Fatal(err)
	}
	absorbedSlots := map[string]bool{}
	for _, slot := range absorbed.Slots {
		if slot.Path != absorbed.Head {
			absorbedSlots[slot.Path] = true
		}
	}
	d := fsIndexDocument("notes/cormorant.md", 1, "cormorant", world.clock.Now())
	var planned *sidecar.SearchTestPlannedPush
	for index := 0; planned == nil && index < 400; index += 1 {
		candidate, err := world.index.PlanPush(ctx, s, world.clock.Now(), []*sidecar.SearchTestDocument{d})
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(candidate.Paths(), func(path string) bool { return absorbedSlots[path] }) {
			planned = candidate
			break
		}
		world.fillSeals(t, s, fmt.Sprintf("after%d", index), 1, world.clock.Now())
	}
	if planned == nil {
		t.Fatal("no push opened the writer's head in an absorbed slot")
	}
	// D stands in another writer's head, so the erasure has a copy to rewrite
	world.push(t, searchId("writer w"), d)
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, d.Path, 1)}
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs111 reuse erasure")
	cutVersion := world.cut(t, b, erasureId, erased)
	if _, err := planned.Commit(ctx); !errors.Is(err, sidecar.ErrSearchTestIndexEpoch) {
		t.Fatalf("the reused slot's push built before the CUT: %v", err)
	}
	rebuilt, err := world.index.PlanPush(ctx, s, world.clock.Now(), []*sidecar.SearchTestDocument{d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rebuilt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	fsRewriteAll(t, b, erasureId, true)
	if err := fsEraseSweep(world.erasure, erased, false); err != nil {
		t.Fatal(err)
	}
	world.fsEraseFreshDevice(t, world.erasure, erased, []string{"cormorant"})
	world.checkSearch(t, "marker0151")
}

// FS-111's backfill kind: a backfill of an unindexed push holding D, built before the CUT and held at its built
// barrier, is refused 409 INDEX_EPOCH and rebuilt without D, which then reads not yet searchable nowhere: masked.
func TestFs111ABackfillBuiltBeforeTheCutRebuilds(t *testing.T) {
	world := newFs79World(t, "fs111 backfill", protocol.RepoKind_REPO_KIND_GENERAL)
	erasure := world.index.NewErasure(nil)
	hooks := newFsEraseHooks(t)
	phone, desktop := searchId("phone"), searchId("desktop")
	commit := world.commitContent(t, phone, fs79Change("notes/cormorant.md", "the cormorant at noon"), fs79Change("notes/heron.md", "a heron at dusk"))
	world.clock.Advance(sidecar.DefaultIndexBackfillSettings().BackfillAge + time.Minute)
	held := hooks.hold("evs.index.backfill.built")
	type backfilled struct {
		result *sidecar.SearchTestBackfill
		err    error
	}
	ended := make(chan backfilled, 1)
	go func() {
		result, err := world.index.Backfill(context.Background(), desktop)
		ended <- backfilled{result: result, err: err}
	}()
	<-held.reached
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, "notes/cormorant.md", commit.Versions["notes/cormorant.md"])}
	eraserWorld := &fsEraseWorld{searchWorld: world.searchWorld, clock: world.clock, erasure: erasure}
	b := eraserWorld.eraser(t, sidecar.Id{}, nil)
	cutVersion := eraserWorld.cut(t, b, searchId("fs111 backfill erasure"), erased)
	close(held.release)
	outcome := <-ended
	if outcome.err != nil || outcome.result.Version == 0 {
		t.Fatalf("the backfill built before the CUT: %+v, %v", outcome.result, outcome.err)
	}
	// built once before the CUT, refused 409 INDEX_EPOCH, built again
	if built := hooks.count("evs.index.backfill.built"); built < 2 || !hooks.wasReached("evs.index.backfill.pushed") {
		t.Fatalf("the backfill was built %d times", built)
	}
	if err := fsEraseFence(erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	live := eraserWorld.live(t)
	if _, ok := live[erased[0].key]; ok {
		t.Fatal("the backfill built before the CUT committed the listed document")
	}
	heron, err := world.index.DocKey("notes/heron.md")
	if err != nil {
		t.Fatal(err)
	}
	if live[heron] == 0 {
		t.Fatal("the rebuilt backfill lost a document the CUT does not list")
	}
}

// FS-111's build kind: a build of the index, built before the CUT and held at its built barrier, is refused 409
// INDEX_EPOCH and rebuilt without D. (A rebuild into i2 in parts is not built: the build is one push.)
func TestFs111ABuildBuiltBeforeTheCutRebuilds(t *testing.T) {
	world := newFs79World(t, "fs111 build", protocol.RepoKind_REPO_KIND_GENERAL)
	erasure := world.index.NewErasure(nil)
	hooks := newFsEraseHooks(t)
	world.setIndex(t, "off")
	commit := world.commitContent(t, searchId("phone"), fs79Change("notes/cormorant.md", "the cormorant at noon"), fs79Change("notes/heron.md", "a heron at dusk"))
	world.setIndex(t, "on")
	held := hooks.hold("evs.index.build.built")
	type built struct {
		result *sidecar.SearchTestBuild
		err    error
	}
	ended := make(chan built, 1)
	go func() {
		result, err := world.index.Build(context.Background(), searchId("builder"))
		ended <- built{result: result, err: err}
	}()
	<-held.reached
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, "notes/cormorant.md", commit.Versions["notes/cormorant.md"])}
	eraserWorld := &fsEraseWorld{searchWorld: world.searchWorld, clock: world.clock, erasure: erasure}
	cutVersion := eraserWorld.cut(t, eraserWorld.eraser(t, sidecar.Id{}, nil), searchId("fs111 build erasure"), erased)
	close(held.release)
	outcome := <-ended
	if outcome.err != nil || outcome.result.Version == 0 {
		t.Fatalf("the build built before the CUT: %+v, %v", outcome.result, outcome.err)
	}
	if built := hooks.count("evs.index.build.built"); built < 2 {
		t.Fatalf("the build was built %d times, never again after its refusal", built)
	}
	if err := fsEraseFence(erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	live := eraserWorld.live(t)
	if _, ok := live[erased[0].key]; ok {
		t.Fatal("the build built before the CUT committed the listed document")
	}
	heron, err := world.index.DocKey("notes/heron.md")
	if err != nil {
		t.Fatal(err)
	}
	if live[heron] == 0 {
		t.Fatal("the rebuilt build lost a document the CUT does not list")
	}
}

// FS-111's reconcile clause with B's device gone: another device of B's member resumes the erasure only 25 h after
// its CUT and last ERASE, first committing the ERASE its orphaned CLOSURE names, then finishes it.
func TestFs111AnotherDeviceOfTheMemberFinishesAfter25Hours(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 member", nil)
	ctx := t.Context()
	hooks := newFsEraseHooks(t)
	_, _, phrase, erased := fs111Kinds(t, world)
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs111 member erasure")
	world.cut(t, b, erasureId, erased)
	fsRewriteKilledAtFirstClosure(t, hooks, b, erasureId)
	orphan := world.erasure.Closures()[0]

	member := searchId("another device of the admin")
	world.index.AddAdmin(member)
	other := world.eraser(t, member, nil)
	resume := func() *sidecar.IndexResumeResult {
		result, err := other.Resume(ctx, &sidecar.IndexResumeArgs{ErasureId: erasureId, Role: sidecar.IndexResumeMember, Complete: true, Note: []byte("note")})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	world.clock.Advance(20 * time.Minute)
	if early := resume(); early.NotBefore.IsZero() || early.Rewrite != nil || 1 < len(world.erasure.Closures()) || 0 < len(world.erasure.Erases()) {
		t.Fatalf("another device resumed 20 min after the CUT: %+v", early)
	}
	world.clock.Advance(25 * time.Hour)
	late := resume()
	if late.Rewrite == nil || !late.Rewrite.Completed {
		t.Fatalf("another device did not finish 25 h on: %+v", late)
	}
	erases := world.erasure.Erases()
	if len(erases) == 0 || erases[0].KeyCount != orphan.KeyCount || erases[0].Signer != member {
		t.Fatalf("the member's first ERASE: %+v, the orphaned CLOSURE named %d keys", erases, orphan.KeyCount)
	}
	if err := fsEraseSweep(world.erasure, erased, false); err != nil {
		t.Fatal(err)
	}
	world.fsEraseFreshDevice(t, world.erasure, erased, []string{"cormorant", phrase, "marker0007"})
}

// FS-111's closure clause: eraser B's CLOSURE, built before another eraser's CUT, commits, since a CLOSURE names no
// epoch; and the other erasure then runs to its end beside it.
func TestFs111AClosureBuiltBeforeAnotherCutCommits(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 closure", nil)
	hooks := newFsEraseHooks(t)
	now := world.clock.Now()
	d := fsIndexDocument("notes/cormorant.md", 1, "cormorant", now)
	f := fsIndexDocument("notes/heron.md", 1, "heron", now)
	world.push(t, searchId("writer w"), d)
	world.push(t, searchId("writer x"), f)
	first := []*fsErased{fsErasedOf(t, world.searchWorld, d.Path, 1)}
	second := []*fsErased{fsErasedOf(t, world.searchWorld, f.Path, 1)}
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureB := searchId("fs111 erasure b")
	world.cut(t, b, erasureB, first)

	listed := hooks.hold("evs.index.erase.listed")
	ended := make(chan *sidecar.IndexRewriteResult, 1)
	failed := make(chan error, 1)
	go func() {
		result, err := b.Rewrite(context.Background(), &sidecar.IndexRewriteArgs{ErasureId: erasureB, Complete: true, Note: []byte("note")})
		ended <- result
		failed <- err
	}()
	<-listed.reached
	c := searchId("another admin")
	world.index.AddAdmin(c)
	other := world.eraser(t, c, nil)
	erasureC := searchId("fs111 erasure c")
	world.cut(t, other, erasureC, second)
	close(listed.release)
	if err := <-failed; err != nil {
		t.Fatal(err)
	}
	result := <-ended
	if !result.Completed || result.Attempts != 1 || result.PairCount == 0 {
		t.Fatalf("B's CLOSURE built before C's CUT: %+v", result)
	}
	fsRewriteAll(t, other, erasureC, true)
	all := slices.Concat(first, second)
	if err := fsEraseSweep(world.erasure, all, false); err != nil {
		t.Fatal(err)
	}
	world.fsEraseFreshDevice(t, world.erasure, all, []string{"cormorant", "heron"})
}

// A twin: a builder that ignores the erasure set, its push built at the new epoch holding D, commits on the world's
// store, which takes the epoch it names; FI-19's fence catches it.
func TestFs111FenceCatchesABuilderIgnoringTheSet(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 twin fence", nil)
	ctx := t.Context()
	now := world.clock.Now()
	d := fsIndexDocument("notes/cormorant.md", 1, "cormorant", now)
	world.push(t, searchId("writer w"), d)
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, d.Path, 1)}
	cutVersion := world.cut(t, world.eraser(t, sidecar.Id{}, nil), searchId("fs111 twin erasure"), erased)
	// the planner leaves listed documents out, so the forger plans before the CUT's set reaches its view: another
	// world's plan of the same push at this epoch, as a builder that never read the set writes it
	forged, err := world.index.ForgePushIgnoringTheSet(ctx, searchId("writer a"), now, []*sidecar.SearchTestDocument{d})
	if err != nil {
		t.Fatal(err)
	}
	if forged == 0 {
		t.Fatal("the forged push did not commit")
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err == nil {
		t.Fatal("the fence did not catch a push holding a listed document after the CUT")
	}
}

// A twin: an erasure whose CLOSUREs commit and whose ERASEs never do leaves the old slots' keys standing, so the
// replaced versions' staged bytes still open; FI-19's sweep catches it.
func TestFs111SweepCatchesAnErasureWithoutItsErases(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 twin sweep", nil)
	hooks := newFsEraseHooks(t)
	now := world.clock.Now()
	d := fsIndexDocument("notes/cormorant.md", 1, "cormorant", now)
	world.push(t, searchId("writer w"), d)
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, d.Path, 1)}
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs111 twin sweep erasure")
	world.cut(t, b, erasureId, erased)
	fsRewriteKilledAtFirstClosure(t, hooks, b, erasureId)
	if live := world.live(t); 0 < live[erased[0].key] {
		t.Fatal("the CLOSURE left D live")
	}
	if err := fsEraseSweep(world.erasure, erased, false); err == nil {
		t.Fatal("the sweep did not catch an erasure whose ERASE never committed")
	}
}

// FS-111's registered case on real engines (fs111.go), under every rule §22.8 gives the row: the conventional T2 test.
func TestFs111(t *testing.T) {
	RunRow(t, "FS-111", "", nil)
}

// FS-111's main clauses as a schedule on a Net, so TEST-M10-02's search invariants read the world's index history and
// every recorded search after every step (FI-18 to FI-23): writer W's head holds D, writer L's large entry holds Dl and
// writer S's sealed slots hold Dm; a hold; a companion push to a fresh head and one to a large entry are planned at the
// old epoch and a merge is held at its built barrier; eraser B's CUT lists the three; a desktop searches; the merge is
// released and rebuilds; B dies right after its first CLOSURE; 20 min pass; the planned pushes are refused 409
// INDEX_EPOCH and rebuilt; B's device starts again and finishes; the erasure is recorded complete, and the desktop
// searches again.
func TestFs111UnderTheSearchInvariants(t *testing.T) {
	world := newFsEraseWorld(t, "fs111 invariants", nil)
	source := newSearchWorldIndex("the search world's ref", world.index)
	erasureId := searchId("fs111 invariants erasure")
	var d, large *sidecar.SearchTestDocument
	var phrase string
	var erased []*fsErased
	var companion, largeCompanion *sidecar.SearchTestPlannedPush
	e := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", world.clock.Now())
	search := func(label string, query string) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			return world.recordedSearch(source, label, query, nil)(ctx, net)
		}
	}
	eraser := func() (*sidecar.IndexEraser, error) {
		return world.erasure.NewEraser(&sidecar.SearchTestEraserArgs{})
	}
	steps := []*Step{
		{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(source)
			return nil
		}},
		{Actor: "writers", Action: func(ctx context.Context, net *Net) error {
			d, large, phrase, erased = fs111Kinds(t, world)
			world.erasure.SetHold(true)
			return nil
		}},
		{Actor: "desktop", Action: search("cormorant before the CUT", "cormorant")},
		{Actor: "writers", Action: func(ctx context.Context, net *Net) error {
			var err error
			if companion, err = world.index.PlanPush(ctx, searchId("writer a"), world.clock.Now(), []*sidecar.SearchTestDocument{d, e}); err != nil {
				return err
			}
			largeCompanion, err = world.index.PlanPush(ctx, searchId("writer a2"), world.clock.Now(), []*sidecar.SearchTestDocument{large})
			return err
		}},
		{Actor: "merger", Action: func(ctx context.Context, net *Net) error {
			result, err := world.index.MergeResult(ctx, searchId("merger"), 0)
			if err == nil && (result.Version == 0 || result.Attempts < 2) {
				err = fmt.Errorf("the merge built before the CUT: %+v", result)
			}
			return err
		}, Background: true},
		{Actor: "merger", Await: "evs.index.merge.built"},
		{Actor: "eraserB", Action: func(ctx context.Context, net *Net) error {
			b, err := eraser()
			if err != nil {
				return err
			}
			if _, err := b.Cut(ctx, &sidecar.IndexCutArgs{ErasureId: erasureId, Documents: fsCutDocuments(erased)}); err != nil {
				return err
			}
			for _, document := range erased {
				if err := world.ledger.Erase(world.index.RepoId(), world.index.RefId(), document.path, document.version); err != nil {
					return err
				}
			}
			return nil
		}},
		{Actor: "desktop", Action: search("cormorant after the CUT", "cormorant")},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			return search("the large document after the CUT", phrase)(ctx, net)
		}},
		{Release: []string{"evs.index.merge.built"}},
		{Actor: "merger", Join: true},
		{Actor: "desktop", Action: search("marker0007 after the merge", "marker0007")},
		{Actor: "eraserB", Action: func(ctx context.Context, net *Net) error {
			b, err := eraser()
			if err != nil {
				return err
			}
			_, err = b.Rewrite(ctx, &sidecar.IndexRewriteArgs{ErasureId: erasureId, Complete: true, Note: []byte("note")})
			return err
		}, Background: true},
		{Actor: "eraserB", Await: "evs.index.erase.closed"},
		{Actor: "eraserB", Kill: true},
		{Actor: "writers", Action: func(ctx context.Context, net *Net) error {
			world.clock.Advance(20 * time.Minute)
			for _, planned := range []*sidecar.SearchTestPlannedPush{companion, largeCompanion} {
				if _, err := planned.Commit(ctx); !errors.Is(err, sidecar.ErrSearchTestIndexEpoch) {
					return fmt.Errorf("a push built before the CUT: %v", err)
				}
			}
			if err := world.index.PushDocuments(ctx, searchId("writer a"), world.clock.Now(), []*sidecar.SearchTestDocument{d, e}); err != nil {
				return err
			}
			if err := world.record(world.clock.Now(), e); err != nil {
				return err
			}
			return world.index.PushDocuments(ctx, searchId("writer a2"), world.clock.Now(), []*sidecar.SearchTestDocument{large})
		}},
		{Actor: "desktop", Action: search("lighthouse after the rebuilt push", "lighthouse")},
		{Actor: "eraserB", Action: func(ctx context.Context, net *Net) error {
			restarted, err := eraser()
			if err != nil {
				return err
			}
			resumed, err := restarted.Resume(ctx, &sidecar.IndexResumeArgs{ErasureId: erasureId, Role: sidecar.IndexResumeEraser, Complete: true, Note: []byte("note")})
			if err != nil {
				return err
			}
			if resumed.Rewrite == nil || !resumed.Rewrite.Completed {
				return fmt.Errorf("the restarted eraser did not finish: %+v", resumed.Rewrite)
			}
			SearchRecordOf(net).CompleteErasure(source.Name(), erasureId)
			return fsEraseSweep(world.erasure, erased, true)
		}},
		{Actor: "desktop", Action: search("cormorant after the erasure", "cormorant")},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			return search("the large document after the erasure", phrase)(ctx, net)
		}},
	}
	schedule := &Schedule{Id: "fs111-search-invariants", Steps: steps}
	for _, n := range []int{18, 19, 20, 21, 22, 23} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	wantPass(t, runFresh(t, schedule))
}
