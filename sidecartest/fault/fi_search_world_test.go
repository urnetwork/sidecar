//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// The search invariants on a healthy run of FS-74's shape (TEST-M10-02): two writers' pushes to one file-mode ref, each
// changing only its own head, a merge, a desktop's searches between, the bucket's roll-up once it expires, and an
// erasure's CUT, all on the root's search world (search_schedule_testhooks.go) through the index's own writers, merger,
// roller and engine, the oracle replaying the world's history from its bytes (SearchTestWorld.IndexHistory) and judging
// each recorded search by SearchOracle. FI-18 to FI-23 read it clean; FI-18's search mutants (a hit on a masked
// version, a covered match left out), FI-21's (a hit from an unread repo, untrusted text before the taint's fsync) and
// FI-19's (an erased document a device past the CUT returns) each fail.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A search world's ref as an index source: its history from the world's own store, and its repo key, so FI-22 holds
// each fresh shard to its keyed pad. Every schedule on a search world hands one to its Net's SearchRecord.
type searchWorldIndex struct {
	name  string
	world *sidecar.SearchTestWorld

	stateLock sync.Mutex
	pushes    []*SearchIndexPush
}

func newSearchWorldIndex(name string, world *sidecar.SearchTestWorld) *searchWorldIndex {
	return &searchWorldIndex{name: name, world: world}
}

func (self *searchWorldIndex) Name() string {
	return self.name
}

// See SearchIndexSource: the world's committed ref versions, those since the last look converted and kept.
func (self *searchWorldIndex) IndexPushes(ctx context.Context) ([]*SearchIndexPush, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	after := uint64(0)
	if count := len(self.pushes); 0 < count {
		after = self.pushes[count-1].RefVersion
	}
	for _, push := range self.world.IndexHistory(after) {
		kind := SearchIndexPushIndex
		if push.Cut {
			kind = SearchIndexPushCut
		}
		converted := &SearchIndexPush{RefVersion: push.RefVersion, SignerId: push.SignerId, SignedTime: push.SignedTime, Kind: kind, Removed: push.Removed}
		for _, file := range push.Written {
			converted.Written = append(converted.Written, &SearchIndexFile{Path: file.Path, Version: file.Version, Plaintext: file.Plaintext, ContentSha256: file.ContentSha256})
		}
		self.pushes = append(self.pushes, converted)
	}
	return slices.Clone(self.pushes), nil
}

// See SearchIndexKeys: the world's one generation.
func (self *searchWorldIndex) IndexRepoKey(generation uint64) (*sidecar.EvsRepoKey, error) {
	if generation != 1 {
		return nil, fmt.Errorf("the search world holds generation 1 alone, not %d", generation)
	}
	return self.world.RepoKey(), nil
}

// The oracle's scope of a desktop holding the buckets and all of the world's network.
func (self *searchWorld) desktopScope() *sidecartest.SearchScope {
	return &sidecartest.SearchScope{
		Partitions: sidecartest.SearchScopeAll, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
	}
}

// A step: a fresh desktop syncs the world and searches query, the search recorded as it ran, with mutate's change
// to what it recorded where given.
func (self *searchWorld) recordedSearch(source *searchWorldIndex, label string, query string, mutate func(run *SearchRun)) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device, err := self.device(ctx, searchHostNamed("desktop"), nil, nil, 0, nil)
		if err != nil {
			return err
		}
		defer self.done(device)
		if err := device.Sync(ctx); err != nil {
			return err
		}
		version, err := self.index.HeadVersion(ctx)
		if err != nil {
			return err
		}
		before := len(device.Fetches())
		search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll, Remote: "off"}, 4096, nil)
		if err != nil {
			return err
		}
		run := &SearchRun{
			Label: label, Query: query, Scope: self.desktopScope(), Oracle: self.oracle,
			Hits: search.Hits(), Uncovered: search.Last().Uncovered,
			SyncState: fmt.Sprintf("desktop at ref version %d", version), Fetches: searchTraceOf(device.Fetches()[before:]),
			SyncedVersions: map[string]uint64{source.Name(): version},
		}
		if mutate != nil {
			mutate(run)
		}
		SearchRecordOf(net).RecordSearch(run)
		return nil
	}
}

// FS-74's shape: writers a and b each push a document to their own heads, a desktop searches, a merge, searches again,
// a third document in the next window, the expired bucket's roll-up, searches, and an erasure's CUT of one document,
// after which the desktop finds it no more.
func fiSearchWorldSchedule(t *testing.T, mutate map[string]func(run *SearchRun)) (*Schedule, *searchWorld) {
	world, clock := newFsIndexWorld(t, "fi search world")
	source := newSearchWorldIndex("the search world's ref", world.index)
	a, b := searchId("writer a"), searchId("writer b")
	push := func(writer sidecar.Id, path string, word string) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			document := fsIndexDocument(path, 1, word, clock.Now())
			if err := world.index.PushDocuments(ctx, writer, clock.Now(), []*sidecar.SearchTestDocument{document}); err != nil {
				return err
			}
			return world.record(clock.Now(), document)
		}
	}
	search := func(label string, query string) func(ctx context.Context, net *Net) error {
		// read at the run, so a test may name its mutant once the world it needs exists
		return world.recordedSearch(source, label, query, func(run *SearchRun) {
			if change := mutate[label]; change != nil {
				change(run)
			}
		})
	}
	steps := []*Step{
		{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(source)
			return nil
		}},
		{Actor: "writerA", Action: push(a, "notes/harbor.md", "harbor")},
		{Actor: "writerB", Action: push(b, "notes/lighthouse.md", "lighthouse")},
		{Actor: "desktop", Action: search("harbor before the merge", "harbor")},
		{Actor: "desktop", Action: search("lighthouse before the merge", "lighthouse")},
		{Actor: "merger", Action: func(ctx context.Context, net *Net) error {
			_, err := world.index.Merge(ctx, searchId("merger"), 0)
			return err
		}},
		{Actor: "desktop", Action: search("harbor after the merge", "harbor")},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			clock.Advance(100 * 24 * time.Hour)
			return push(a, "notes/keeper.md", "keeper")(ctx, net)
		}},
		{Actor: "indexer", Action: func(ctx context.Context, net *Net) error {
			version, err := world.index.RollUp(ctx, searchId("indexer"))
			if err == nil && version == 0 {
				err = fmt.Errorf("no bucket rolled")
			}
			return err
		}},
		{Actor: "desktop", Action: search("lighthouse after the roll-up", "lighthouse")},
		{Actor: "desktop", Action: search("keeper after the roll-up", "keeper")},
		{Actor: "eraser", Action: func(ctx context.Context, net *Net) error {
			erased := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", clock.Now())
			if _, err := world.index.Cut(ctx, searchId("erasure"), []*sidecar.SearchTestDocument{erased}); err != nil {
				return err
			}
			return world.ledger.Erase(world.index.RepoId(), world.index.RefId(), erased.Path, erased.Version)
		}},
		{Actor: "desktop", Action: search("lighthouse after the cut", "lighthouse")},
	}
	schedule := &Schedule{Id: "fi-search-world", Steps: steps}
	for _, n := range []int{18, 19, 20, 21, 22, 23} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return schedule, world
}

func TestFiSearchReadsAHealthyRunOfFs74sShapeClean(t *testing.T) {
	schedule, _ := fiSearchWorldSchedule(t, nil)
	result := runFresh(t, schedule)
	wantPass(t, result)
}

// FI-18's search mutants: a hit on a version older than its document's newest, and a covered match left out.
func TestFi18CatchesAHitOnAMaskedVersionAndACoveredMatchLeftOut(t *testing.T) {
	masked := map[string]func(run *SearchRun){"harbor after the merge": func(run *SearchRun) {
		for index := range run.Hits {
			run.Hits[index].Version += 1
		}
	}}
	schedule, _ := fiSearchWorldSchedule(t, masked)
	wantFailure(t, runFresh(t, schedule), "rests on a masked version")
	left := map[string]func(run *SearchRun){"keeper after the roll-up": func(run *SearchRun) {
		run.Hits = nil
	}}
	schedule, _ = fiSearchWorldSchedule(t, left)
	wantFailure(t, runFresh(t, schedule), "is among no hit")
}

// FI-21's mutants: a hit from a repo the reader does not read, and an untrusted hit's text, not asked for, before the
// run's taint was fsynced.
func TestFi21CatchesAHitFromAnUnreadRepoAndUntrustedText(t *testing.T) {
	other := map[string]func(run *SearchRun){"harbor before the merge": func(run *SearchRun) {
		hit := run.Hits[0]
		hit.Repo = sidecar.Id{0xee}
		run.Hits = append(run.Hits, hit)
	}}
	schedule, _ := fiSearchWorldSchedule(t, other)
	wantFailure(t, runFresh(t, schedule), "which the scope's reader does not read")
	text := map[string]func(run *SearchRun){"harbor before the merge": func(run *SearchRun) {
		// as a search tool returned them to a run, not as the engine found them
		run.Returned = true
		for index := range run.Hits {
			run.Hits[index].Trust = sidecar.SearchTrustUntrusted
			run.Hits[index].Snippet = "the harbor at noon"
		}
	}}
	schedule, _ = fiSearchWorldSchedule(t, text)
	result := runFresh(t, schedule)
	wantFailure(t, result, "carries its text, which was not asked for")
	wantFailure(t, result, "before the run's taint was fsynced")
}

// FI-19's search mutant: a device synced past the CUT returns the erased document.
func TestFi19CatchesAnErasedDocumentReturnedPastTheCut(t *testing.T) {
	returned := map[string]func(run *SearchRun){}
	schedule, world := fiSearchWorldSchedule(t, returned)
	key, err := world.index.DocKey("notes/lighthouse.md")
	if err != nil {
		t.Fatal(err)
	}
	returned["lighthouse after the cut"] = func(run *SearchRun) {
		run.Hits = append(run.Hits, sidecar.SearchHit{Repo: world.index.RepoId(), Ref: world.index.RefId(), Path: "notes/lighthouse.md", Version: 1, DocKey: key, State: sidecar.SearchPossible})
	}
	wantFailure(t, runFresh(t, schedule), "which erasure")
}

// A source whose roll-up wrote all's shard with a byte more pad than its keyed pad: the shard decodes and encodes again
// to its bytes, since a decoder takes any zero pad, and only the keyed pad's check sees it (§22.7's shards row).
type searchWorldMispadded struct {
	*searchWorldIndex
}

func (self *searchWorldMispadded) IndexPushes(ctx context.Context) ([]*SearchIndexPush, error) {
	pushes, err := self.searchWorldIndex.IndexPushes(ctx)
	if err != nil {
		return nil, err
	}
	mispadded := []*SearchIndexPush{}
	for _, push := range pushes {
		copied := *push
		copied.Written = nil
		for _, file := range push.Written {
			if strings.HasSuffix(file.Path, "/a/0") {
				changed := *file
				changed.Plaintext = append(slices.Clone(file.Plaintext), 0)
				changed.ContentSha256 = nil
				file = &changed
			}
			copied.Written = append(copied.Written, file)
		}
		mispadded = append(mispadded, &copied)
	}
	return mispadded, nil
}

func TestFi22CatchesAShardWithoutItsKeyedPad(t *testing.T) {
	schedule, world := fiSearchWorldSchedule(t, nil)
	source := &searchWorldMispadded{searchWorldIndex: newSearchWorldIndex("the mispadded ref", world.index)}
	schedule.Steps = append([]*Step{{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
		SearchRecordOf(net).AddIndex(source)
		return nil
	}}}, schedule.Steps...)
	schedule.Check = []Invariant{FI(22)}
	wantFailure(t, runFresh(t, schedule), "not its keyed pad of")
}
