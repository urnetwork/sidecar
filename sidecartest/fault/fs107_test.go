//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-107 on T2 (§11.14's dependency, merges and reads rows; owner decision 584's full entries, which reworded the row;
// FI-18, FI-22; D-TEST-14; SEARCH-M10-36): every index entry a full key set, searched from a fresh cache on the search
// world, whose store keeps a replaced index version unreadable at once, as the purge and evacuation leave it, so a
// replaced version still on disk cannot make a broken index look whole. Every search runs on a fresh phone and a fresh
// desktop holding the world's text, each synced to the head with nothing of an earlier device's cache, and is held to
// SearchOracle's set: the desktop's hits checked against its own text equal the oracle's covered matches, the phone's
// candidates include every one and rest on no masked version, and no hit shows twice.
//
//	head      D created and edited twice in one unsealed head, each full entry replacing the last: the head holds one
//	          entry of D, and a fresh phone finds D's unchanged term and each added one at the newest version, and no
//	          removed one
//	sealed    the head sealed and D edited again, small (the new head beside the sealed slot's older version) and
//	          large (a large entry, then another replacing it): each search finds the newest version alone
//	reuse     a merge absorbs the slot holding D's older version; the writer's next push removes its absorbed large
//	          entries and its later seals reuse the slot: the same answers
//	other     an edit by another writer, a full entry in that writer's own head, and the first writer's next: newest wins
//	race      a merge landing between an entry's build and its commit: the entry commits and one version is found; a
//	          backfilled copy of D's version beside a late copy of it: both read, one version found
//	seal      the writer's two pushes on one base, one appending and one sealing its head, in both orders: one gets 409,
//	          is planned again and lands, every entry once
//	drop      a DROP listing D's older versions replaces the writer's head and leaves the kept version's entry where it
//	          is, no file holding a listed version after
//	kind 2    a slot holding an entry of the reserved kind 2 is refused: a fresh device lists it bad and raises
//	          index_malformed naming its signer, and every search is as before
//	fetch     no body is fetched: every file a search's device asked for is an index file
//
// The main clauses also run as a schedule under the search invariants, FI-18 and FI-22 read after every step
// (TestFs107UnderTheSearchInvariants), and the head and other-writer clauses run on real engines as the row's registered
// case (fs107.go), on T2 here (TestFs107) and on T3 through server's evshost (server/fs107_t3_test.go).
//
// Not here, each named for what it waits on: the clauses on real engines past the head and other-writer ones (merges,
// slot reuse, large entries, backfills, DROPs and a device's search over EvsRepo, SEARCH-M10-19's EvsRepo-backed sync
// source); the real purge between steps (EVSB-M10-01's PurgeSink.Certain is unwired; the world's store collects a
// replaced version at once, and the registered case runs evacuation's sweep with format2.purge on); a DROP's content
// write of through_version (evs's DROP push, EVS2-M10-21's; the world models the index side alone); and DESIGN-DETAILS
// 1.6's explorer, mutation sweeps and long schedules (review phase).

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// --- what FS-76, FS-107 and FS-108 share ---

// A results world: FS-79's world over a ref of kind, its content pushes recorded in the oracle's ledger at the world's
// own versions (fs79_test.go), and fresh devices of §18.4's hosts held to SearchOracle's set.
type fsResultsWorld struct {
	*fs79World
	// Its documents are written by index-only pushes (PushDocuments), with no content a desktop holds the text of, so
	// a desktop's hits are confirmed from their fields or possible rather than verified.
	indexOnly bool
	// The ref versions of the DROPs and CLOSUREs it committed, which a schedule's source names as rewrites in place
	// (FI-19, FI-20, FI-22).
	stateLock           sync.Mutex
	rewriteVersionKinds map[uint64]SearchIndexPushKind
}

func newFsResultsWorld(t *testing.T, label string, kind protocol.RepoKind) *fsResultsWorld {
	t.Helper()
	return newFsResultsWorldOn(t, label, kind, sidecartest.NewFakeClock(sidecartest.DefaultClockStart()))
}

// A results world on clock, which other worlds may share: FS-76's mailbox and notes on one timeline. Its ledger and
// oracle are its own, holding its one repo.
func newFsResultsWorldOn(t *testing.T, label string, kind protocol.RepoKind, clock *sidecartest.FakeClock) *fsResultsWorld {
	t.Helper()
	repoId, refId := searchId("fs results repo "+label), searchId("fs results ref "+label)
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: repoId, RefId: refId, Clock: clock, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	world := &searchWorld{
		index: index, ledger: sidecartest.NewSearchLedger(), readByteCount: 32 * 1024 * 1024,
		readerId: searchId("fs results reader " + label), networkId: searchId("fs results network " + label),
		writerId: searchId("fs results writer " + label),
	}
	err = world.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
		RepoId: repoId, NetworkId: world.networkId, Kind: kind, DefaultRefId: refId,
		Key: index.RepoKey(), ReaderIds: []sidecar.Id{world.readerId},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.oracle = sidecartest.NewSearchOracle(world.ledger)
	t.Cleanup(world.close)
	return &fsResultsWorld{
		fs79World:           &fs79World{searchWorld: world, clock: clock, refVersions: map[string]uint64{}},
		rewriteVersionKinds: map[uint64]SearchIndexPushKind{},
	}
}

// A fresh device of host following the world, synced to its head: nothing of any earlier device's cache. A desktop
// holds the world's text and verifies against it; a phone holds none. Both read coverage. events nil drops them.
func (self *fsResultsWorld) fresh(ctx context.Context, host *searchHost, events func(event sidecar.SidecarEvent)) (*sidecar.SearchTestDevice, error) {
	conditions := host.conditions
	device, err := self.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: host.settings(), Conditions: func() sidecar.SearchConditions { return conditions },
		ReadByteCount: self.readByteCount, Coverage: true, Text: host.name == "desktop", Events: events,
	})
	if err != nil {
		return nil, err
	}
	if err := device.Sync(ctx); err != nil && !errors.Is(err, sidecar.ErrSearchSyncUnfollowed) {
		device.Close()
		return nil, err
	}
	return device, nil
}

// The oracle's scope of partitions over the world's network, as its reader reads it.
func (self *fsResultsWorld) scope(partitions sidecartest.SearchScopePartitions) *sidecartest.SearchScope {
	return &sidecartest.SearchScope{
		Partitions: partitions, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
	}
}

// The oracle's partitions for a device's scope.
func fsResultsPartitions(scope sidecar.SearchScope) sidecartest.SearchScopePartitions {
	if scope == sidecar.SearchLatest {
		return sidecartest.SearchScopeLatest
	}
	return sidecartest.SearchScopeAll
}

// What one search found.
type fsResultsSearch struct {
	host  string
	query string
	scope sidecar.SearchScope
	// Every hit but a near one, as the oracle keys a document (fs79Key), in the order found.
	hits []string
	all  []sidecar.SearchHit
	// What the search reported not yet searchable: its local layer's count, and for its ref the pin and the
	// indexed_through above which a change is not yet searchable (§16.10's coverage row), the gap counted in
	// uncovered as FI-18 reads it.
	uncovered      int
	coverageKnown  bool
	indexedThrough uint64
	fetches        []string
	// The paths a commit the index does not cover yet changed, while it waits for its backfill: a device may still show
	// such a path's older indexed version, since a desktop's local overlay, which would mask it, is not wired to a
	// device yet and a phone shows it until the backfill lands. hold leaves a hit on one of them out.
	waitingPaths map[string]bool
}

// Runs query on device in scope, its whole answer.
func fsResultsRun(ctx context.Context, device *sidecar.SearchTestDevice, host string, query string, scope sidecar.SearchScope) (*fsResultsSearch, error) {
	before := len(device.Fetches())
	search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: scope, Remote: "off"}, 4096, nil)
	if err != nil {
		return nil, err
	}
	progress := search.Last()
	found := &fsResultsSearch{host: host, query: query, scope: scope, all: search.Hits(), uncovered: progress.Uncovered}
	for _, coverage := range progress.Coverage {
		found.coverageKnown, found.indexedThrough = true, coverage.IndexedThrough
		if coverage.IndexedThrough < coverage.PinVersion {
			found.uncovered += int(coverage.PinVersion - coverage.IndexedThrough)
		}
	}
	for _, hit := range found.all {
		if hit.State != sidecar.SearchNear {
			found.hits = append(found.hits, fs79Key(hit.Path, hit.DocKey, hit.Version))
		}
	}
	found.fetches = searchTraceOf(device.Fetches()[before:])
	return found, nil
}

// Holds a search to the oracle at the world's ledger as it stands (FI-18; FS-76's and FS-107's equality): no hit shows
// twice, no body is fetched, and every covered match is a hit; on a desktop, its hits checked against its own text are
// the oracle's matches, so with every match covered they equal the oracle's set; on a phone each names a document's
// newest live version, none resting on a version hidden by newest-version masking, a tombstone or the ERASE mask; a
// match not covered yet is found from the device's own text, or reported not yet searchable.
func (self *fsResultsWorld) hold(found *fsResultsSearch) error {
	at := fmt.Sprintf("%s's search for %q in scope %d", found.host, found.query, found.scope)
	scope := self.scope(fsResultsPartitions(found.scope))
	matches, covered, err := self.oracle.Judge(found.query, scope)
	if err != nil && !errors.Is(err, sidecartest.ErrSearchOracleQueryRefused) {
		return fmt.Errorf("%s: the oracle cannot judge it: %w", at, err)
	}
	documents, err := self.oracle.Documents(scope)
	if err != nil {
		return fmt.Errorf("%s: the oracle cannot judge it: %w", at, err)
	}
	isCovered, live := map[string]bool{}, map[string]bool{}
	for _, key := range covered {
		isCovered[fs79Key(key.Name, key.DocKey, key.Version)] = true
	}
	for _, key := range documents {
		live[fs79Key(key.Name, key.DocKey, key.Version)] = true
	}
	want, matching := []string{}, map[string]bool{}
	for _, match := range matches {
		key := fs79Key(match.Name, match.DocKey, match.Version)
		matching[key] = true
		if isCovered[key] {
			want = append(want, key)
		}
	}
	slices.Sort(want)
	hits := slices.Clone(found.hits)
	if 0 < len(found.waitingPaths) {
		hits = slices.DeleteFunc(hits, func(hit string) bool { return found.waitingPaths[hit[:strings.LastIndex(hit, "#")]] })
	}
	slices.Sort(hits)
	if compacted := slices.Compact(slices.Clone(hits)); len(compacted) != len(hits) {
		return fmt.Errorf("%s shows a document twice: %v", at, hits)
	}
	for _, fetch := range found.fetches {
		if !strings.HasPrefix(fetch, ".ur-index/") {
			return fmt.Errorf("%s fetched %s, which is no index file", at, fetch)
		}
	}
	for _, key := range want {
		if !slices.Contains(hits, key) {
			return fmt.Errorf("%s left out %s, covered and matching: found %v", at, key, hits)
		}
	}
	// a match the index does not cover yet is found from the device's own text, or reported not yet searchable: its
	// commit above the indexed_through the search gave
	for _, match := range matches {
		key := fs79Key(match.Name, match.DocKey, match.Version)
		if isCovered[key] || slices.Contains(hits, key) {
			continue
		}
		refVersion, ok := self.refVersions[fmt.Sprintf("%s@%d", match.Name, match.Version)]
		if !ok || !found.coverageKnown || refVersion <= found.indexedThrough {
			return fmt.Errorf("%s leaves %s silently absent: its push at %d, indexed through %d (coverage %t)", at, key, refVersion, found.indexedThrough, found.coverageKnown)
		}
	}
	if found.host == "desktop" {
		// checked against its own text, every hit is a match of the oracle's
		for _, key := range hits {
			if !matching[key] {
				return fmt.Errorf("%s found %s, which the oracle does not match: found %v, the oracle's covered matches %v", at, key, hits, want)
			}
		}
		for _, hit := range found.all {
			if !self.indexOnly && hit.State != sidecar.SearchNear && hit.State != sidecar.SearchVerified {
				return fmt.Errorf("%s left %s@%d unverified, state %d, though it holds the text", at, hit.Path, hit.Version, hit.State)
			}
		}
		return nil
	}
	for _, key := range hits {
		if !live[key] {
			return fmt.Errorf("%s found %s, which is no document's newest live version: found %v, the oracle %v", at, key, hits, want)
		}
	}
	return nil
}

// Each query on a fresh phone and a fresh desktop, each made for its search, so every cache is discarded before each
// search, held to the oracle (hold), and, where record names a source, recorded for FI-18.
func (self *fsResultsWorld) checkFresh(ctx context.Context, net *Net, source SearchIndexSource, label string, scope sidecar.SearchScope, queries ...string) error {
	for _, query := range queries {
		for _, hostName := range []string{"ios32", "desktop"} {
			host := searchHostNamed(hostName)
			device, err := self.fresh(ctx, host, nil)
			if err != nil {
				return err
			}
			found, err := fsResultsRun(ctx, device, hostName, query, scope)
			if err == nil {
				// a fresh device: every file it fetched, its sync's and its search's
				found.fetches = searchTraceOf(device.Fetches())
			}
			device.Close()
			if err != nil {
				return err
			}
			if err := self.hold(found); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			if source != nil && net != nil {
				self.record(net, source, found, label)
			}
		}
	}
	return nil
}

// Records a search for FI-18, judged at the next check against the ledger as it stood when it ran.
func (self *fsResultsWorld) record(net *Net, source SearchIndexSource, found *fsResultsSearch, label string) {
	version, _ := self.index.HeadVersion(context.Background())
	SearchRecordOf(net).RecordSearch(&SearchRun{
		Label: fmt.Sprintf("%s: %s %q", label, found.host, found.query), Query: found.query,
		Scope: self.scope(fsResultsPartitions(found.scope)), Oracle: self.oracle, Hits: found.all, Uncovered: found.uncovered,
		SyncState: fmt.Sprintf("a fresh %s at ref version %d", found.host, version), Fetches: found.fetches,
		SyncedVersions: map[string]uint64{source.Name(): version},
	})
}

// A step that holds each query to the oracle on fresh devices, as checkFresh does, recording them for FI-18.
func (self *fsResultsWorld) checkStep(source SearchIndexSource, label string, queries ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.checkFresh(ctx, net, source, label, sidecar.SearchAll, queries...)
	}
}

// Commits writer's in-ref push of changes at the world's clock now, recording it in the ledger: the step's error rather
// than a test's fatal, for a schedule.
func (self *fsResultsWorld) commit(ctx context.Context, writer sidecar.Id, changes ...*sidecar.SearchTestChange) (*sidecar.SearchTestCommit, error) {
	commit, err := self.index.CommitIndexed(ctx, writer, self.clock.Now(), changes)
	if err != nil {
		return nil, err
	}
	return commit, self.recordContent(writer, commit, changes)
}

// Records a committed push in the ledger, indexed where it carried entries.
func (self *fsResultsWorld) recordContent(writer sidecar.Id, commit *sidecar.SearchTestCommit, changes []*sidecar.SearchTestChange) error {
	ledgerCommit := &sidecartest.SearchCommit{
		RepoId: self.index.RepoId(), RefId: self.index.RefId(), RefVersion: commit.RefVersion, Time: commit.Time,
		WriterId: writer, Indexed: 0 < commit.IndexWriteCount,
	}
	for _, change := range changes {
		version := commit.Versions[change.Path]
		ledgerCommit.Changes = append(ledgerCommit.Changes, &sidecartest.SearchChange{Path: change.Path, Version: version, Content: change.Content})
		self.refVersions[fmt.Sprintf("%s@%d", change.Path, version)] = commit.RefVersion
	}
	return self.ledger.Commit(ledgerCommit)
}

// Fills writer's head with notes of its own until it seals: the head moves to another slot. Answers the head it left.
func (self *fsResultsWorld) fillUntilSealed(ctx context.Context, writer sidecar.Id, label string) (string, error) {
	files, err := self.index.WriterFiles(ctx, writer, 0)
	if err != nil {
		return "", err
	}
	sealed := files.Head
	for index := 0; index < 400; index += 1 {
		filler := fs79Change(fmt.Sprintf("notes/%s-%03d.md", label, index),
			fmt.Sprintf("Filler\n%s filler marker%04d with enough words to take room in a slot", label, index))
		if _, err := self.commit(ctx, writer, filler); err != nil {
			return "", err
		}
		files, err := self.index.WriterFiles(ctx, writer, 0)
		if err != nil {
			return "", err
		}
		if sealed != "" && files.Head != sealed {
			return sealed, nil
		}
		if sealed == "" {
			sealed = files.Head
		}
	}
	return "", fmt.Errorf("%s's head did not seal", label)
}

// A source of the world's index whose DROP and CLOSURE pushes read as rewrites in place (FI-19, FI-20, FI-22).
type fsResultsIndex struct {
	*searchWorldIndex
	world *fsResultsWorld
}

// The world's index as a source named name, for a schedule's search invariants.
func (self *fsResultsWorld) source(name string) *fsResultsIndex {
	return &fsResultsIndex{searchWorldIndex: newSearchWorldIndex(name, self.index), world: self}
}

// See SearchIndexSource: the world's history, its rewrites in place marked as such.
func (self *fsResultsIndex) IndexPushes(ctx context.Context) ([]*SearchIndexPush, error) {
	pushes, err := self.searchWorldIndex.IndexPushes(ctx)
	if err != nil {
		return nil, err
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	marked := []*SearchIndexPush{}
	for _, push := range pushes {
		if kind, ok := self.world.rewriteVersionKinds[push.RefVersion]; ok {
			copied := *push
			copied.Kind = kind
			push = &copied
		}
		marked = append(marked, push)
	}
	return marked, nil
}

// Remembers erasure's committed CLOSUREs as rewrites in place.
func (self *fsResultsWorld) markClosures(erasure *sidecar.SearchTestErasure) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, closure := range erasure.Closures() {
		self.rewriteVersionKinds[closure.RefVersion] = SearchIndexPushClosure
	}
}

// signer's DROP of paths at the world's clock, remembered as a rewrite.
func (self *fsResultsWorld) drop(ctx context.Context, signer sidecar.Id, paths ...*sidecar.SearchTestDropPath) (*sidecar.SearchTestDrop, error) {
	drop, err := self.index.Drop(ctx, signer, self.clock.Now(), paths)
	if err != nil {
		return nil, err
	}
	if drop.Version != 0 {
		self.stateLock.Lock()
		self.rewriteVersionKinds[drop.Version] = SearchIndexPushDrop
		self.stateLock.Unlock()
	}
	return drop, nil
}

// --- FS-107 ---

// D's path, and the version texts the row writes, each holding the unchanged term and one of its own, so a search
// finds a version's own term at its newest version alone and no term an edit removed.
const fs107Path = "notes/field-log.md"

// D's text at a version: its unchanged term, its own term, and for a large version count CJK ideographs from seed,
// which make its entry a large one, their first four a phrase that finds it.
func fs107Text(term string, count int, seed int64) ([]byte, string) {
	text := "Field log\nkestrel " + term + "\n"
	phrase := ""
	if 0 < count {
		random := rand.New(rand.NewSource(seed))
		ideographs := []rune{}
		for range count {
			ideographs = append(ideographs, rune(0x4E00+random.Intn(0x9FA5-0x4E00)))
		}
		text += string(ideographs) + "\n"
		phrase = string(ideographs[:4])
	}
	return []byte(text), phrase
}

// FS-107's state as its steps write it: D's versions and their queries, and the writers.
type fs107State struct {
	world  *fsResultsWorld
	source *fsResultsIndex
	a, b   sidecar.Id
	// every query the steps have made, which each check runs
	queries []string
	// D's entry versions in order, and the newest
	versions []uint64
}

// FS-107's state on a world of its own.
func newFs107State(t *testing.T, label string) *fs107State {
	world := newFsResultsWorld(t, label, protocol.RepoKind_REPO_KIND_GENERAL)
	return &fs107State{world: world, source: world.source("the fs107 world's ref"), a: searchId("writer a"), b: searchId("writer b")}
}

// A step: writer writes D's next version holding term, a large one when count is above 0.
func (self *fs107State) edit(writer sidecar.Id, term string, count int, seed int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		content, phrase := fs107Text(term, count, seed)
		commit, err := self.world.commit(ctx, writer, &sidecar.SearchTestChange{Path: fs107Path, Content: content})
		if err != nil {
			return err
		}
		self.note(commit.Versions[fs107Path], term, phrase)
		self.world.clock.Advance(time.Minute)
		return nil
	}
}

// Remembers D's version and the queries it adds.
func (self *fs107State) note(version uint64, term string, phrase string) {
	self.versions = append(self.versions, version)
	if !slices.Contains(self.queries, "kestrel") {
		self.queries = append(self.queries, "kestrel")
	}
	self.queries = append(self.queries, term)
	if phrase != "" {
		self.queries = append(self.queries, phrase)
	}
}

// A step: every query so far on fresh devices, held to the oracle.
func (self *fs107State) check(label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.world.checkFresh(ctx, net, self.source, label, sidecar.SearchAll, self.queries...)
	}
}

// A step: the files holding D hold it once, at its newest version, and where held names them; extra files may hold
// older versions only where allowOlder.
func (self *fs107State) heldOnce(label string, allowOlder bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		held, err := self.world.index.FilesHolding(fs107Path, 0)
		if err != nil {
			return err
		}
		newest := self.versions[len(self.versions)-1]
		atNewest := 0
		for _, file := range held {
			switch {
			case file.Version == newest:
				atNewest += 1
			case !allowOlder:
				return fmt.Errorf("%s: %s holds D at %d beside the newest, %d: %v", label, file.Path, file.Version, newest, held)
			case newest < file.Version:
				return fmt.Errorf("%s: %s holds D at %d, above the newest, %d", label, file.Path, file.Version, newest)
			}
		}
		if atNewest == 0 {
			return fmt.Errorf("%s: no file holds D at its newest version %d: %v", label, newest, held)
		}
		return nil
	}
}

// FS-107's schedule: see the file header's head, sealed, reuse, other, race, seal and drop clauses, each step's state
// held to the oracle on fresh devices, and with checks FI-18 and FI-22 read after every step.
func fs107Schedule(t *testing.T, label string) (*Schedule, *fs107State) {
	state := newFs107State(t, label)
	world := state.world
	a, b := state.a, state.b
	var sealedSlot string
	var raced *sidecar.SearchTestPlannedContentPush
	steps := []*Step{
		{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(state.source)
			return nil
		}},
		// head: created and edited twice in one unsealed head
		{Actor: "writerA", Action: state.edit(a, "osprey", 0, 0)},
		{Actor: "writerA", Action: state.edit(a, "plover", 0, 0)},
		{Actor: "writerA", Action: state.edit(a, "quail", 0, 0)},
		{Actor: "check", Action: state.heldOnce("one unsealed head", false)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			files, err := world.index.WriterFiles(ctx, a, 0)
			if err != nil {
				return err
			}
			if len(files.Slots) != 1 || 0 < len(files.Large) {
				return fmt.Errorf("three edits in one head took slots %v and large entries %v", files.Slots, files.Large)
			}
			return nil
		}},
		{Actor: "phone", Action: state.check("one head")},
		// sealed: the head seals, D's version standing in the sealed slot, then a small edit and two large ones
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			sealedSlot, err = world.fillUntilSealed(ctx, a, "seal")
			return err
		}},
		{Actor: "writerA", Action: state.edit(a, "redstart", 0, 0)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			held, err := world.index.FilesHolding(fs107Path, 0)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return file.Path == sealedSlot }) {
				return fmt.Errorf("the sealed slot %s holds no older version of D: %v", sealedSlot, held)
			}
			return nil
		}},
		{Actor: "check", Action: state.heldOnce("after the seal", true)},
		{Actor: "phone", Action: state.check("small after the seal")},
		{Actor: "writerA", Action: state.edit(a, "siskin", 4000, 31)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			files, err := world.index.WriterFiles(ctx, a, 0)
			if err != nil {
				return err
			}
			if len(files.Large) == 0 {
				return errors.New("a large version of D wrote no large entry")
			}
			return nil
		}},
		{Actor: "phone", Action: state.check("a large entry")},
		{Actor: "writerA", Action: state.edit(a, "tanager", 4000, 37)},
		{Actor: "check", Action: state.heldOnce("a large entry replacing a large entry", true)},
		{Actor: "phone", Action: state.check("a large entry replacing a large entry")},
		// reuse: a merge absorbs the sealed slot and the large entries, the writer's next push removes them, and its
		// later seals reuse the slot
		{Actor: "merger", Action: func(ctx context.Context, net *Net) error {
			merged, err := world.index.Merge(ctx, searchId("merger"), 0)
			if err == nil && merged == 0 {
				err = errors.New("the merge committed nothing")
			}
			return err
		}},
		{Actor: "phone", Action: state.check("after the merge")},
		{Actor: "writerA", Action: state.edit(a, "thrush", 0, 0)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			files, err := world.index.WriterFiles(ctx, a, 0)
			if err != nil {
				return err
			}
			if 0 < len(files.Large) {
				return fmt.Errorf("the writer's next push kept its absorbed large entries: %v", files.Large)
			}
			return nil
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			for index := 0; index < 8; index += 1 {
				files, err := world.index.WriterFiles(ctx, a, 0)
				if err != nil {
					return err
				}
				if files.Head == sealedSlot {
					return nil
				}
				if _, err := world.fillUntilSealed(ctx, a, fmt.Sprintf("reuse%d", index)); err != nil {
					return err
				}
			}
			return fmt.Errorf("no seal reused the absorbed slot %s", sealedSlot)
		}},
		{Actor: "phone", Action: state.check("after the slot's reuse")},
		// other: another writer's edit, a full entry in its own head, then the first writer's
		{Actor: "writerB", Action: state.edit(b, "vireo", 0, 0)},
		{Actor: "phone", Action: state.check("another writer's edit")},
		{Actor: "writerA", Action: state.edit(a, "warbler", 0, 0)},
		{Actor: "phone", Action: state.check("the first writer's edit after it")},
		// race: a merge between an entry's build and its commit
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			content, _ := fs107Text("waxwing", 0, 0)
			var err error
			raced, err = world.index.PlanIndexed(ctx, a, world.clock.Now(), []*sidecar.SearchTestChange{{Path: fs107Path, Content: content}})
			return err
		}},
		{Actor: "merger", Action: func(ctx context.Context, net *Net) error {
			merged, err := world.index.Merge(ctx, searchId("merger"), 0)
			if err == nil && merged == 0 {
				err = errors.New("the merge committed nothing")
			}
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			commit, err := raced.Commit(ctx)
			if err != nil {
				return fmt.Errorf("an entry built before a merge and committed after it: %w", err)
			}
			content, _ := fs107Text("waxwing", 0, 0)
			if err := world.recordContent(a, commit, []*sidecar.SearchTestChange{{Path: fs107Path, Content: content}}); err != nil {
				return err
			}
			state.note(commit.Versions[fs107Path], "waxwing", "")
			world.clock.Advance(time.Minute)
			return nil
		}},
		{Actor: "phone", Action: state.check("a merge between an entry's build and its commit")},
		// race: a backfilled copy of D's version beside a late copy of the same version
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			content, _ := fs107Text("wren", 0, 0)
			changes := []*sidecar.SearchTestChange{{Path: fs107Path, Content: content}}
			commit, err := world.index.CommitContent(ctx, a, world.clock.Now(), changes)
			if err != nil {
				return err
			}
			if err := world.recordContent(a, commit, changes); err != nil {
				return err
			}
			version := commit.Versions[fs107Path]
			state.note(version, "wren", "")
			world.clock.Advance(sidecar.DefaultIndexBackfillSettings().BackfillAge + time.Second)
			backfill, err := world.index.Backfill(ctx, searchId("indexer x"))
			if err != nil {
				return err
			}
			if backfill.Version == 0 {
				return fmt.Errorf("no backfill of the unindexed edit: %+v", backfill)
			}
			if err := world.ledger.Cover(world.index.RepoId(), world.index.RefId(), commit.RefVersion, world.clock.Now()); err != nil {
				return err
			}
			if _, err := world.index.PushChunks(ctx, a, world.clock.Now(), fs107Path, version, content, []uint32{0}); err != nil {
				return err
			}
			held, err := world.index.FilesHolding(fs107Path, 0)
			if err != nil {
				return err
			}
			copies := 0
			for _, file := range held {
				if file.Version == version {
					copies += 1
				}
			}
			if copies < 2 {
				return fmt.Errorf("the backfill and the late copy left %d copies of D's version: %v", copies, held)
			}
			return nil
		}},
		{Actor: "phone", Action: state.check("a backfilled copy beside a late one")},
		// seal: the writer's two pushes on one base, one appending and one sealing
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return fs107TwoPushes(ctx, state, false)
		}},
		{Actor: "phone", Action: state.check("an append and a seal on one base")},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return fs107TwoPushes(ctx, state, true)
		}},
		{Actor: "phone", Action: state.check("a seal and an append on one base")},
		// drop: every older version of D listed, the newest kept
		{Actor: "admin", Action: func(ctx context.Context, net *Net) error {
			before, err := world.index.FilesHolding(fs107Path, 0)
			if err != nil {
				return err
			}
			kept := state.versions[len(state.versions)-1]
			drop, err := world.drop(ctx, world.index.AdminId(), &sidecar.SearchTestDropPath{Path: fs107Path, Listed: state.versions, Kept: kept})
			if err != nil {
				return err
			}
			if drop.Version == 0 || drop.RewrittenCount == 0 || drop.HeadCount == 0 {
				return fmt.Errorf("a DROP of D's older versions: %+v", drop)
			}
			after, err := world.index.FilesHolding(fs107Path, 0)
			if err != nil {
				return err
			}
			keptBefore, keptAfter := []string{}, []string{}
			for _, file := range before {
				if file.Version == kept {
					keptBefore = append(keptBefore, file.Path)
				}
			}
			for _, file := range after {
				if file.Version != kept {
					return fmt.Errorf("after the DROP %s still holds D's listed version %d", file.Path, file.Version)
				}
				keptAfter = append(keptAfter, file.Path)
			}
			if !slices.Equal(keptBefore, keptAfter) {
				return fmt.Errorf("the DROP moved the kept version's entry from %v to %v", keptBefore, keptAfter)
			}
			return nil
		}},
		{Actor: "phone", Action: state.check("after the DROP")},
	}
	schedule := &Schedule{Id: "fs107-" + label, Steps: steps}
	for _, n := range []int{18, 22} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return schedule, state
}

// FS-107's seal clause on D: the writer's head filled until a small edit of D fits it and a note past its room does
// not; the edit, appending, and the note, sealing, planned on one base and committed in an order: the second gets 409,
// is planned again on the winner's head and lands, every entry once.
func fs107TwoPushes(ctx context.Context, state *fs107State, sealFirst bool) error {
	world, a := state.world, state.a
	slotMax := sidecar.DefaultIndexFormatSettings().SlotMaxByteCount
	for index := 0; ; index += 1 {
		files, err := world.index.WriterFiles(ctx, a, 0)
		if err != nil {
			return err
		}
		if files.Head != "" && slotMax-files.HeadByteCount < 1200 {
			break
		}
		if 600 < index {
			return errors.New("the head did not come within an entry of its room")
		}
		filler := fs79Change(fmt.Sprintf("notes/room%v-%03d.md", sealFirst, index),
			fmt.Sprintf("Room\nroom%v marker%04d with enough words", sealFirst, index))
		if _, err := world.commit(ctx, a, filler); err != nil {
			return err
		}
	}
	term := "yellowthroat"
	if sealFirst {
		term = "zebrafinch"
	}
	content, _ := fs107Text(term, 0, 0)
	appendChange := &sidecar.SearchTestChange{Path: fs107Path, Content: content}
	wide := strings.Builder{}
	for index := range 120 {
		fmt.Fprintf(&wide, "sealing%v word%03d ", sealFirst, index)
	}
	sealChange := fs79Change(fmt.Sprintf("notes/sealing-%v.md", sealFirst), "Sealing\n"+wide.String())
	now := world.clock.Now()
	appending, err := world.index.PlanIndexed(ctx, a, now, []*sidecar.SearchTestChange{appendChange})
	if err != nil {
		return err
	}
	sealing, err := world.index.PlanIndexed(ctx, a, now, []*sidecar.SearchTestChange{sealChange})
	if err != nil {
		return err
	}
	first, second := appending, sealing
	firstChange, secondChange := appendChange, sealChange
	if sealFirst {
		first, second = sealing, appending
		firstChange, secondChange = sealChange, appendChange
	}
	committed, err := first.Commit(ctx)
	if err != nil {
		return fmt.Errorf("the first of two pushes on one base: %w", err)
	}
	if err := world.recordContent(a, committed, []*sidecar.SearchTestChange{firstChange}); err != nil {
		return err
	}
	if _, err := second.Commit(ctx); !errors.Is(err, sidecar.ErrSearchTestConflict) {
		return fmt.Errorf("the second of two pushes on one base was not refused 409: %v", err)
	}
	again, err := world.commit(ctx, a, secondChange)
	if err != nil {
		return fmt.Errorf("the refused push planned again: %w", err)
	}
	version := committed.Versions[fs107Path]
	if version == 0 {
		version = again.Versions[fs107Path]
	}
	state.note(version, term, "")
	state.queries = append(state.queries, fmt.Sprintf("sealing%v", sealFirst))
	world.clock.Advance(time.Minute)
	return nil
}

// FS-107's main clauses: see the file header.
func TestFs107UnderTheSearchInvariants(t *testing.T) {
	schedule, _ := fs107Schedule(t, "invariants")
	wantPass(t, runFresh(t, schedule))
}

// FS-107's kind-2 clause: a slot well formed but for one entry of the reserved kind 2 for D is refused. A fresh
// phone and desktop list the file bad and raise index_malformed naming its signer, keep nothing of it, and every
// search is as before, the forged version's term found nowhere; an honest index raises nothing.
func TestFs107AReservedKindEntryIsRefused(t *testing.T) {
	state := newFs107State(t, "kind 2")
	world := state.world
	ctx := t.Context()
	for _, step := range []func(ctx context.Context, net *Net) error{
		state.edit(state.a, "osprey", 0, 0), state.edit(state.b, "plover", 0, 0),
	} {
		if err := step(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	malformed := func(host *searchHost) map[string]sidecar.Id {
		named := map[string]sidecar.Id{}
		lock := sync.Mutex{}
		device, err := world.fresh(ctx, host, func(event sidecar.SidecarEvent) {
			if event.Kind == sidecar.SidecarEventIndexMalformed && event.SidecarId != nil {
				lock.Lock()
				named[event.Path] = *event.SidecarId
				lock.Unlock()
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		device.Close()
		lock.Lock()
		defer lock.Unlock()
		return named
	}
	for _, host := range []string{"ios32", "desktop"} {
		if named := malformed(searchHostNamed(host)); 0 < len(named) {
			t.Fatalf("an honest index raised index_malformed on a fresh %s: %v", host, named)
		}
	}
	if err := world.checkFresh(ctx, nil, nil, "before the forgery", sidecar.SearchAll, state.queries...); err != nil {
		t.Fatal(err)
	}
	forger := searchId("forger")
	newest := state.versions[len(state.versions)-1]
	forged := &sidecar.SearchTestDocument{Path: fs107Path, Version: newest + 1, Title: "Field log", Text: "kestrel forgedterm", Time: world.clock.Now()}
	path, _, err := world.index.ForgeReservedKindSlot(ctx, forger, world.clock.Now(), forged)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"ios32", "desktop"} {
		named := malformed(searchHostNamed(host))
		if signer, ok := named[path]; !ok || signer != forger || len(named) != 1 {
			t.Fatalf("a fresh %s raised index_malformed %v for the forged slot %s by %s", host, named, path, forger)
		}
	}
	if err := world.checkFresh(ctx, nil, nil, "after the forgery", sidecar.SearchAll, append(slices.Clone(state.queries), "forgedterm")...); err != nil {
		t.Fatal(err)
	}
}

// FS-107's registered case on real engines (fs107.go), under every rule §22.8 gives the row: the conventional T2 test.
func TestFs107(t *testing.T) {
	RunRow(t, "FS-107", "", nil)
}
