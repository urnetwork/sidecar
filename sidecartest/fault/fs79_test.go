//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-79 on T2 (§11.14's settings, on, off and never rows, D4 and D6; D-EVS-43, D-EVS-61, R-EVS-21, R-EVS-24, FI-18,
// FI-21; SEARCH-M10-35): a repo's index turned on and off, through the index's own builder, settings writes and
// in-ref writer on the search world, whose ref holds its text beside its index (search_content_testhooks.go). After
// every step a fresh desktop device, reading coverage, finds what SearchOracle matches and the index covers, and
// reports every other match not yet searchable, never silently absent.
//
//	on         while an admin's settings say off, honest writers' pushes take no entry; turned on, searches find none
//	           of that text and report every push not yet searchable until one full build by a device holding the
//	           text lands, the older note in all and the newer in the latest bucket, after which nothing is uncovered
//	racing     two devices building one pin: one holds the lock and the other finds it held and writes nothing; and
//	           one whose lock lapsed while it built loses it to the other, which builds equal plaintext and commits,
//	           the first refused at the lock
//	off        one push removes every index file but the settings, searches answer index_off, an honest writer's
//	           push takes no delta, and builds and backfills write nothing
//	migration  a format-1 client's text, no index on the ref, every push not yet searchable, ends with the first
//	           build, after which every push is indexed
//	never      config, mailcfg and secret repos: an honest writer writes no entry, a build is refused, a backfill
//	           writes nothing, and a well-formed index forged into the repo is never followed, fetched or searched
//	documents  a binary, a chunk D6's shard test skips, and text past 1 MiB indexed by 1 MiB chunk, a word across a
//	           chunk's end found through the 256 B overlap
//
// Not here, each named for what it waits on: the purge of an off's removed files after the allowance (evs's purge, on
// T3); a versionless file above the network's rule, which the search world's ref has no versioning rules to place
// (the evs world on T2, through EvsRepo); a build in parts and a rebuild into .ur-index/i2 beside i1 (SEARCH-M10-15's
// draft builds in one push and rebuilds in place); SearchOracle's half of D6's shard test (SEARCH-M10-43's), so a
// chunk only that test skips is held to the index's files and not to the oracle; and T3 (server/fs74_t3_test.go).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An FS-79 world: the search world over a ref of its kind, the oracle's ledger beside it, and each content commit's
// ref version by path and version, which a search's coverage is read against.
type fs79World struct {
	*searchWorld
	clock       *sidecartest.FakeClock
	refVersions map[string]uint64
}

// A world over a ref of kind, the ledger holding its repo, on a fake clock of its own. Two worlds of one label and
// kind are alike: their ids, keys and clocks.
func newFs79World(t *testing.T, label string, kind protocol.RepoKind) *fs79World {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	repoId, refId := searchId("fs79 repo "+label), searchId("fs79 ref "+label)
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: repoId, RefId: refId, Clock: clock, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	world := &searchWorld{
		index: index, ledger: sidecartest.NewSearchLedger(), readByteCount: 32 * 1024 * 1024,
		readerId: searchId("fs79 reader " + label), networkId: searchId("fs79 network " + label),
		writerId: searchId("fs79 writer " + label),
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
	return &fs79World{searchWorld: world, clock: clock, refVersions: map[string]uint64{}}
}

// A change writing text at path.
func fs79Change(path string, text string) *sidecar.SearchTestChange {
	return &sidecar.SearchTestChange{Path: path, Content: []byte(text)}
}

// Records commit in the ledger, indexed where its push carried its entries, else not until a build or a backfill
// covers it.
func (self *fs79World) recordCommit(t *testing.T, signer sidecar.Id, commit *sidecar.SearchTestCommit, changes []*sidecar.SearchTestChange) {
	t.Helper()
	ledgerCommit := &sidecartest.SearchCommit{
		RepoId: self.index.RepoId(), RefId: self.index.RefId(), RefVersion: commit.RefVersion, Time: commit.Time,
		WriterId: signer, Indexed: 0 < commit.IndexWriteCount,
	}
	for _, change := range changes {
		version := commit.Versions[change.Path]
		ledgerCommit.Changes = append(ledgerCommit.Changes, &sidecartest.SearchChange{Path: change.Path, Version: version, Content: change.Content})
		self.refVersions[fmt.Sprintf("%s@%d", change.Path, version)] = commit.RefVersion
	}
	if err := self.ledger.Commit(ledgerCommit); err != nil {
		t.Fatal(err)
	}
}

// writer's push of changes that writes no index entry, as an old client, a phone or a format-1 client pushes.
func (self *fs79World) commitContent(t *testing.T, writer sidecar.Id, changes ...*sidecar.SearchTestChange) *sidecar.SearchTestCommit {
	t.Helper()
	commit, err := self.index.CommitContent(t.Context(), writer, self.clock.Now(), changes)
	if err != nil {
		t.Fatal(err)
	}
	if commit.IndexWriteCount != 0 {
		t.Fatalf("a push that skips the index wrote %d index files", commit.IndexWriteCount)
	}
	self.recordCommit(t, writer, commit, changes)
	return commit
}

// writer's in-ref push of changes, its head beside its content.
func (self *fs79World) commitIndexed(t *testing.T, writer sidecar.Id, changes ...*sidecar.SearchTestChange) *sidecar.SearchTestCommit {
	t.Helper()
	commit, err := self.index.CommitIndexed(t.Context(), writer, self.clock.Now(), changes)
	if err != nil {
		t.Fatal(err)
	}
	self.recordCommit(t, writer, commit, changes)
	return commit
}

// builder's build, which must commit: every commit at or below its pin is covered from then on.
func (self *fs79World) build(t *testing.T, builder sidecar.Id, first bool) *sidecar.SearchTestBuild {
	t.Helper()
	run := self.index.Build
	if first {
		run = self.index.FirstBuild
	}
	build, err := run(t.Context(), builder)
	if err != nil || build.Version == 0 {
		t.Fatalf("the build committed %+v: %v", build, err)
	}
	self.cover(t, build.Pin)
	return build
}

// The ledger learns that an index push covered every commit at or below throughRefVersion.
func (self *fs79World) cover(t *testing.T, throughRefVersion uint64) {
	t.Helper()
	if err := self.ledger.Cover(self.index.RepoId(), self.index.RefId(), throughRefVersion, self.clock.Now()); err != nil {
		t.Fatal(err)
	}
}

// The admin's settings version, as `ur evs index on|off` writes it, and the ledger's from now on.
func (self *fs79World) setIndex(t *testing.T, action string) *sidecar.SearchTestSettings {
	t.Helper()
	settings, err := self.index.SetIndex(t.Context(), self.index.AdminId(), action, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = self.ledger.SetIndexSettings(self.index.RepoId(), self.index.RefId(), &sidecartest.SearchIndexSettings{Off: action == sidecar.EvsIndexOff}, self.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return settings
}

// A document's key as a search and the oracle both name it: its path, doc_key and version.
func fs79Key(path string, docKey [16]byte, version uint64) string {
	return fmt.Sprintf("%s#%x@%d", path, docKey[:4], version)
}

// A fresh desktop device, reading coverage.
func (self *fs79World) desktop(t *testing.T) *sidecar.SearchTestDevice {
	t.Helper()
	device, err := self.index.NewDevice(t.Context(), &sidecar.SearchTestDeviceArgs{
		Settings:      sidecar.DefaultSidecarSettings().Search,
		Conditions:    func() sidecar.SearchConditions { return sidecar.SearchConditions{DaemonHost: true} },
		ReadByteCount: self.readByteCount,
		Coverage:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Close)
	return device
}

// What a search found and reported.
type fs79Searched struct {
	progress sidecar.SearchProgress
	hits     []string
	// The oracle's matches the index does not cover yet, each reported not yet searchable.
	uncovered int
	device    *sidecar.SearchTestDevice
}

// A fresh desktop device syncs the world and searches query in scope all (FI-18): its exact hits are the oracle's
// matches the index covers, and every match it does not cover is reported not yet searchable, its commit above the
// indexed_through the search gives.
func (self *fs79World) checkSearch(t *testing.T, query string) *fs79Searched {
	t.Helper()
	ctx := t.Context()
	device := self.desktop(t)
	if err := device.Sync(ctx); err != nil && !errors.Is(err, sidecar.ErrSearchSyncUnfollowed) {
		t.Fatal(err)
	}
	search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll, Remote: "off"}, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	searched := &fs79Searched{progress: search.Last(), device: device}
	for _, hit := range search.Hits() {
		// near hits are the vocabulary's corrections (SEARCH-M10-25), which the oracle's exact set leaves out
		if hit.State != sidecar.SearchNear {
			searched.hits = append(searched.hits, fs79Key(hit.Path, hit.DocKey, hit.Version))
		}
	}
	slices.Sort(searched.hits)
	scope := &sidecartest.SearchScope{
		Partitions: sidecartest.SearchScopeAll, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
	}
	matches, covered, err := self.oracle.Judge(query, scope)
	if err != nil {
		t.Fatal(err)
	}
	coveredKeys := map[string]bool{}
	for _, key := range covered {
		coveredKeys[fs79Key(key.Name, key.DocKey, key.Version)] = true
	}
	indexedThrough := uint64(0)
	for _, coverage := range searched.progress.Coverage {
		if coverage.RefId == self.index.RefId() {
			indexedThrough = coverage.IndexedThrough
		}
	}
	want := []string{}
	for _, match := range matches {
		key := fs79Key(match.Name, match.DocKey, match.Version)
		if coveredKeys[key] {
			want = append(want, key)
			continue
		}
		searched.uncovered += 1
		refVersion, ok := self.refVersions[fmt.Sprintf("%s@%d", match.Name, match.Version)]
		if !ok || refVersion <= indexedThrough {
			t.Fatalf("a search for %q leaves %s silently absent: its push at %d, indexed through %d", query, key, refVersion, indexedThrough)
		}
	}
	slices.Sort(want)
	if !slices.Equal(searched.hits, want) {
		t.Fatalf("a search for %q found %v, the oracle's covered matches %v", query, searched.hits, want)
	}
	return searched
}

// Whether progress names the world's ref or repo left out for reason.
func fs79Excluded(progress sidecar.SearchProgress, reason string) bool {
	return slices.ContainsFunc(progress.Excluded, func(exclusion sidecar.SearchExclusion) bool { return exclusion.Reason == reason })
}

// Three notes by two writers: an old one, then 100 days on two new ones, each pushed by commit.
func fs79Notes(t *testing.T, world *fs79World, commit func(t *testing.T, writer sidecar.Id, changes ...*sidecar.SearchTestChange) *sidecar.SearchTestCommit) {
	t.Helper()
	a, b := searchId("writer a"), searchId("writer b")
	commit(t, a, fs79Change("notes/old.md", "an old ledger of turnips"))
	world.clock.Advance(100 * 24 * time.Hour)
	commit(t, a, fs79Change("notes/harbor.md", "the harbor at noon"))
	world.clock.Advance(time.Minute)
	commit(t, b, fs79Change("notes/lighthouse.md", "a lighthouse keeper's log"))
	world.clock.Advance(time.Minute)
}

// FS-79's on clause: honest writers' pushes while the index is off take no entry; once an admin turns it on, every
// search reports their text not yet searchable until one full build by a device holding the text lands, and then
// finds it, the old note in all and the new ones in the latest bucket, with nothing left uncovered.
func TestFs79OnBuildsTheIndexOnceAndSearchesWaitForIt(t *testing.T) {
	world := newFs79World(t, "on", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	if off := world.setIndex(t, sidecar.EvsIndexOff); off.Version == 0 {
		t.Fatal("the off version did not land")
	}
	fs79Notes(t, world, func(t *testing.T, writer sidecar.Id, changes ...*sidecar.SearchTestChange) *sidecar.SearchTestCommit {
		commit := world.commitIndexed(t, writer, changes...)
		if commit.IndexWriteCount != 0 {
			t.Fatalf("an honest writer's push with the index off wrote %d index files", commit.IndexWriteCount)
		}
		return commit
	})
	if searched := world.checkSearch(t, "harbor"); !fs79Excluded(searched.progress, sidecar.SearchExcludedIndexOff) {
		t.Fatalf("a search with the index off: excluded %v", searched.progress.Excluded)
	}

	// on, before any build: nothing found, every push reported not yet searchable
	if on := world.setIndex(t, sidecar.EvsIndexOn); on.Version == 0 {
		t.Fatal("the on version did not land")
	}
	for _, query := range []string{"harbor", "lighthouse", "turnips"} {
		if searched := world.checkSearch(t, query); searched.uncovered != 1 || len(searched.hits) != 0 {
			t.Fatalf("before the build %q found %v, %d uncovered", query, searched.hits, searched.uncovered)
		}
	}
	if _, unindexed, err := world.index.Coverage(ctx); err != nil || unindexed != 3 {
		t.Fatalf("before the build %d pushes read unindexed: %v", unindexed, err)
	}

	build := world.build(t, searchId("builder"), false)
	if build.EntryCount != 3 {
		t.Fatalf("the build wrote %d documents", build.EntryCount)
	}
	for _, query := range []string{"harbor", "lighthouse", "turnips"} {
		if searched := world.checkSearch(t, query); searched.uncovered != 0 || len(searched.hits) != 1 {
			t.Fatalf("after the build %q found %v, %d uncovered", query, searched.hits, searched.uncovered)
		}
	}
	through, unindexed, err := world.index.Coverage(ctx)
	head, headErr := world.index.HeadVersion(ctx)
	if err != nil || headErr != nil || unindexed != 0 || through != head {
		t.Fatalf("after the build: indexed through %d of %d, %d unindexed: %v %v", through, head, unindexed, err, headErr)
	}
	// the old note in all, the new ones in the latest bucket
	old, err := world.index.ShardHolding("notes/old.md")
	if err != nil || !strings.Contains(old, "/a/") {
		t.Fatalf("the old note is in %q: %v", old, err)
	}
	harbor, err := world.index.ShardHolding("notes/harbor.md")
	if err != nil || !strings.Contains(harbor, "/b/") {
		t.Fatalf("the new note is in %q: %v", harbor, err)
	}
}

// The notes of fs79Notes, pushed by a client that skips the index.
func fs79SkippedNotes(t *testing.T, world *fs79World) {
	t.Helper()
	fs79Notes(t, world, world.commitContent)
}

// Builds holding the world's barrier: the first to reach evs.index.build.built waits there until release closes.
func fs79HoldBuilt(t *testing.T) (chan struct{}, chan struct{}) {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != "evs.index.build.built" {
			return
		}
		first := false
		once.Do(func() { first = true })
		if first {
			close(held)
			<-release
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	return held, release
}

// A build run on its own goroutine, and its result.
type fs79Built struct {
	build *sidecar.SearchTestBuild
	err   error
}

// FS-79's racing clause: two devices building one pin build equal plaintext, and one commits. A builder holding the
// lock keeps the other out, which writes nothing; and a builder whose lock lapsed while it built loses it to the
// other, which builds the same shards and manifests and commits, the first then refused at the lock.
func TestFs79TwoBuildersRacingBuildEqualPlaintext(t *testing.T) {
	a, b := searchId("builder a"), searchId("builder b")
	twin := newFs79World(t, "racing", protocol.RepoKind_REPO_KIND_GENERAL)
	fs79SkippedNotes(t, twin)
	alone := twin.build(t, b, false)
	if len(alone.Content) < 2 {
		t.Fatalf("a lone build wrote %d files beside its head", len(alone.Content))
	}
	equal := func(label string, built *sidecar.SearchTestBuild) {
		if len(built.Content) != len(alone.Content) {
			t.Fatalf("%s wrote %d files beside its head, a lone builder %d", label, len(built.Content), len(alone.Content))
		}
		for path, digest := range alone.Content {
			if built.Content[path] != digest {
				t.Fatalf("%s's %s differs from a lone builder's", label, path)
			}
		}
	}

	// a holds the lock while it builds: b finds it held and writes nothing
	world := newFs79World(t, "racing", protocol.RepoKind_REPO_KIND_GENERAL)
	fs79SkippedNotes(t, world)
	held, release := fs79HoldBuilt(t)
	result := make(chan fs79Built, 1)
	go func() {
		build, err := world.index.Build(context.Background(), a)
		result <- fs79Built{build: build, err: err}
	}()
	<-held
	beside, err := world.index.Build(t.Context(), b)
	if err != nil || beside.Skipped != "locked" || beside.Version != 0 {
		t.Fatalf("a build beside a held lock: %+v, %v", beside, err)
	}
	close(release)
	first := <-result
	if first.err != nil || first.build.Version == 0 {
		t.Fatalf("the lock's holder: %+v, %v", first.build, first.err)
	}
	equal("the holder", first.build)
	world.cover(t, first.build.Pin)
	world.checkSearch(t, "harbor")
	world.checkSearch(t, "turnips")
	sidecar.SetTestHooks(nil)

	// a's lock lapses while it builds: b takes it, builds equal plaintext and commits, and a is refused at the lock
	lapsed := newFs79World(t, "racing", protocol.RepoKind_REPO_KIND_GENERAL)
	fs79SkippedNotes(t, lapsed)
	held, release = fs79HoldBuilt(t)
	go func() {
		build, err := lapsed.index.Build(context.Background(), a)
		result <- fs79Built{build: build, err: err}
	}()
	<-held
	// past the lock's term and grace
	lapsed.clock.Advance(45 * time.Minute)
	taker, err := lapsed.index.Build(t.Context(), b)
	if err != nil || taker.Version == 0 {
		t.Fatalf("a build past a lapsed lock: %+v, %v", taker, err)
	}
	close(release)
	late := <-result
	if !errors.Is(late.err, sidecar.ErrSearchTestLockLost) || late.build.Version != 0 {
		t.Fatalf("the lapsed holder's build: %+v, %v", late.build, late.err)
	}
	equal("the lapsed holder", late.build)
	equal("the taker", taker)
	lapsed.cover(t, taker.Pin)
	lapsed.checkSearch(t, "lighthouse")
}

// FS-79's off clause: one push removes every index file but the settings, searches answer index_off, an honest
// writer's push takes no delta, and a build and a backfill write nothing.
func TestFs79OffRemovesEveryIndexFileAndSearchesAnswerIndexOff(t *testing.T) {
	world := newFs79World(t, "off", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	fs79SkippedNotes(t, world)
	world.build(t, searchId("builder"), false)
	world.checkSearch(t, "harbor")
	built := world.index.IndexPaths()
	before, err := world.index.HeadVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}

	off := world.setIndex(t, sidecar.EvsIndexOff)
	after, err := world.index.HeadVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if off.Waiting || off.Version == 0 || off.RemovedCount != len(built) || after != before+1 {
		t.Fatalf("off removed %d of %d files from %d to %d: %+v", off.RemovedCount, len(built), before, after, off)
	}
	if paths := world.index.IndexPaths(); len(paths) != 1 || !strings.HasSuffix(paths[0], "/settings") {
		t.Fatalf("after off the root holds %v", paths)
	}
	for _, query := range []string{"harbor", "turnips"} {
		if searched := world.checkSearch(t, query); !fs79Excluded(searched.progress, sidecar.SearchExcludedIndexOff) || len(searched.hits) != 0 {
			t.Fatalf("a search for %q with the index off found %v, excluded %v", query, searched.hits, searched.progress.Excluded)
		}
	}

	// an honest writer's push takes no delta, and neither a build nor a backfill writes
	if commit := world.commitIndexed(t, searchId("writer a"), fs79Change("notes/harbor.md", "the harbor at dusk")); commit.IndexWriteCount != 0 {
		t.Fatalf("an honest writer's push with the index off wrote %d index files", commit.IndexWriteCount)
	}
	if build, err := world.index.Build(ctx, searchId("builder")); err != nil || build.Skipped != "off" || build.Version != 0 {
		t.Fatalf("a build with the index off: %+v, %v", build, err)
	}
	world.clock.Advance(time.Hour)
	if backfill, err := world.index.Backfill(ctx, searchId("indexer")); err != nil || backfill.Skipped != "off" || backfill.Version != 0 {
		t.Fatalf("a backfill with the index off: %+v, %v", backfill, err)
	}
	if paths := world.index.IndexPaths(); len(paths) != 1 {
		t.Fatalf("the off root holds %v", paths)
	}
}

// FS-79's migration clause: a ref a format-1 client wrote holds no index, every push reads not yet searchable, and
// the migration's first build ends it: every push is then indexed and found.
func TestFs79MigrationEndsWithItsFirstBuild(t *testing.T) {
	world := newFs79World(t, "migration", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	fs79SkippedNotes(t, world)
	if paths := world.index.IndexPaths(); len(paths) != 0 {
		t.Fatalf("a format-1 client's ref holds %v", paths)
	}
	if _, unindexed, err := world.index.Coverage(ctx); err != nil || unindexed != 3 {
		t.Fatalf("the migrated ref: %d unindexed, %v", unindexed, err)
	}
	if searched := world.checkSearch(t, "lighthouse"); searched.uncovered != 1 {
		t.Fatalf("before the first build %d uncovered", searched.uncovered)
	}
	first := world.build(t, searchId("migrating device"), true)
	if first.EntryCount != 3 {
		t.Fatalf("the first build wrote %d documents", first.EntryCount)
	}
	through, unindexed, err := world.index.Coverage(ctx)
	head, headErr := world.index.HeadVersion(ctx)
	if err != nil || headErr != nil || unindexed != 0 || through != head {
		t.Fatalf("after the first build: through %d of %d, %d unindexed", through, head, unindexed)
	}
	for _, query := range []string{"harbor", "lighthouse", "turnips"} {
		if searched := world.checkSearch(t, query); searched.uncovered != 0 || len(searched.hits) != 1 {
			t.Fatalf("after the first build %q found %v, %d uncovered", query, searched.hits, searched.uncovered)
		}
	}

	// a format-1 client still pushing after the build writes no entry: its push reads not yet searchable above the
	// build's horizon, the rest still found
	world.clock.Advance(time.Minute)
	late := world.commitContent(t, searchId("format-1 writer"), fs79Change("notes/cormorant.md", "a cormorant on the pier"))
	through, unindexed, err = world.index.Coverage(ctx)
	if err != nil || unindexed != 1 || late.RefVersion <= through {
		t.Fatalf("a push after the first build: through %d, %d unindexed, the push at %d", through, unindexed, late.RefVersion)
	}
	if searched := world.checkSearch(t, "cormorant"); searched.uncovered != 1 || len(searched.hits) != 0 {
		t.Fatalf("a push after the first build found %v, %d uncovered", searched.hits, searched.uncovered)
	}
	world.checkSearch(t, "harbor")
}

// FS-79's never clause: config, mailcfg and secret repos hold no index. An honest writer's push writes no entry, a
// build is refused and a backfill writes nothing; a well-formed index forged into the repo past every builder is never
// followed, so a device fetches nothing of it and a search finds nothing there, config and mailcfg named no_index and
// secret repos never listed (§16.6).
func TestFs79ConfigMailcfgAndSecretReposHoldNoIndex(t *testing.T) {
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET} {
		world := newFs79World(t, kind.String(), kind)
		ctx := t.Context()
		note := fs79Change("notes/harbor.md", "the harbor at noon")
		if commit := world.commitIndexed(t, searchId("writer a"), note); commit.IndexWriteCount != 0 {
			t.Fatalf("%s: an honest writer wrote %d index files", kind, commit.IndexWriteCount)
		}
		if build, err := world.index.Build(ctx, searchId("builder")); !errors.Is(err, sidecar.ErrSearchTestExcluded) || build.Version != 0 {
			t.Fatalf("%s: a build: %+v, %v", kind, build, err)
		}
		world.clock.Advance(time.Hour)
		if backfill, err := world.index.Backfill(ctx, searchId("indexer")); err != nil || backfill.Version != 0 {
			t.Fatalf("%s: a backfill: %+v, %v", kind, backfill, err)
		}
		if paths := world.index.IndexPaths(); len(paths) != 0 {
			t.Fatalf("%s holds index files %v", kind, paths)
		}

		// a forged index, well formed, the note's text in a bucket of its own
		now := world.clock.Now()
		forged := &sidecar.SearchTestDocument{Path: note.Path, Version: 1, Title: "Notes", Text: string(note.Content), Time: now}
		partition := &sidecar.SearchTestPartition{StartDay: sidecar.SearchTestBucketStartDay(now), ShardDocumentCount: 16}
		if err := world.index.WriteShards(ctx, searchId("forger"), now, partition, []*sidecar.SearchTestDocument{forged}, nil); err != nil {
			t.Fatal(err)
		}
		if paths := world.index.IndexPaths(); len(paths) < 2 {
			t.Fatalf("%s: the forged index wrote %v", kind, paths)
		}
		device := world.desktop(t)
		if err := device.Sync(ctx); !errors.Is(err, sidecar.ErrSearchSyncUnfollowed) {
			t.Fatalf("%s: a device's round over a forged index: %v", kind, err)
		}
		searched := world.checkSearch(t, "harbor")
		if len(searched.hits) != 0 || 0 < len(device.Fetches()) || 0 < len(searched.device.Fetches()) {
			t.Fatalf("%s: a forged index was read: hits %v", kind, searched.hits)
		}
		noIndex := fs79Excluded(searched.progress, sidecar.SearchExcludedNoIndex)
		if (kind == protocol.RepoKind_REPO_KIND_SECRET) == noIndex || (kind == protocol.RepoKind_REPO_KIND_SECRET && 0 < len(searched.progress.Excluded)) {
			t.Fatalf("%s: excluded %v", kind, searched.progress.Excluded)
		}
	}
}

// At most byteCount bytes of BMP letters, two- and three-byte ones with equal odds, then any of the kind, from a
// fixed generator: a text of many scripts with little repeated, whose lone shard passes the shard's cap though its key
// set stays within 512 KiB, so D6's shard test skips it (DESIGN-DETAILS 11.6's chunk).
func fs79MixedScriptLetters(seed int64, byteCount int) []byte {
	two, three := []rune{}, []rune{}
	for letter := rune(0x80); letter <= 0xFFFF; letter += 1 {
		switch {
		case !unicode.IsLetter(letter):
		case utf8.RuneLen(letter) == 2:
			two = append(two, letter)
		default:
			three = append(three, letter)
		}
	}
	random := rand.New(rand.NewSource(seed))
	text := make([]byte, 0, byteCount)
	for {
		letters := three
		if random.Intn(2) == 0 {
			letters = two
		}
		letter := letters[random.Intn(len(letters))]
		if byteCount < len(text)+utf8.RuneLen(letter) {
			return text
		}
		text = utf8.AppendRune(text, letter)
	}
}

// FS-79's documents clause through a build: a binary is skipped by its sniff, a chunk D6's shard test skips is left
// out, and text past 1 MiB is indexed by 1 MiB chunk, a word past chunk 0's end found through its 256 B overlap and a
// word in chunk 2 found as chunk 2's document.
func TestFs79SkipsBinariesAndD6ChunksAndChunksLongText(t *testing.T) {
	world := newFs79World(t, "documents", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	const mebibyte = 1024 * 1024
	binary := append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0, 1, 2, ' ', 'h', 'a', 'r', 'b', 'o', 'r', ' '}, 1000)...)
	noise := fs79MixedScriptLetters(5, mebibyte)
	sentence := "the quiet river bends past the old mill "
	long := []byte(strings.Repeat(sentence, (5*mebibyte/2)/len(sentence)+1))[:5*mebibyte/2]
	copy(long[mebibyte-4:], "cormorant")
	copy(long[2*mebibyte+1000:], "albatross")
	world.commitContent(t, searchId("writer a"),
		&sidecar.SearchTestChange{Path: "notes/scan.pdf", Content: binary},
		&sidecar.SearchTestChange{Path: "notes/noise.txt", Content: noise},
		&sidecar.SearchTestChange{Path: "notes/long.txt", Content: long},
		fs79Change("notes/harbor.md", "the harbor at noon"),
	)
	build := world.build(t, searchId("builder"), false)
	// harbor.md's one document and long.txt's three
	if build.EntryCount != 4 {
		t.Fatalf("the build wrote %d documents", build.EntryCount)
	}
	for path, want := range map[string]int{"notes/scan.pdf": 0, "notes/noise.txt": 0, "notes/long.txt": 3, "notes/harbor.md": 1} {
		chunks, err := world.index.LiveChunks(ctx, path, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunks) != want {
			t.Fatalf("%s holds %d live chunks, not %d: %v", path, len(chunks), want, chunks)
		}
	}
	if searched := world.checkSearch(t, "harbor"); len(searched.hits) != 1 || !strings.HasPrefix(searched.hits[0], "notes/harbor.md#") {
		t.Fatalf("harbor found %v", searched.hits)
	}
	if searched := world.checkSearch(t, "cormorant"); len(searched.hits) != 1 {
		t.Fatalf("a word across chunk 0's end found %v", searched.hits)
	}
	albatross := world.checkSearch(t, "albatross")
	chunk2, err := world.index.LiveChunks(ctx, "notes/long.txt", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(albatross.hits) != 1 || chunk2[2] == 0 {
		t.Fatalf("a word in chunk 2 found %v", albatross.hits)
	}
}
