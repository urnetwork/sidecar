//go:build !ios_extension

package sidecar

// QD-1026 (owner decision 583; §18.4's windows row, §18.7's window row; FS-77's mid-round case on the sync engine's
// fake, which sidecartest/fault/fs77_test.go holds on the search world): a round that is not "search more"'s asks the
// ref's keepAll again before each read of all. A phone's window on Wi-Fi while charging whose link turns metered, whose
// charger is unplugged or that enters Low Power Mode while its first shard of all is read reads no further shard, ends
// its round with no error and no swap of all, keeps that shard staged through a round the rule does not allow, and
// neither spends nor holds back the day's budget for what it did not read; the next window the rule allows reads the
// rest, youngest first, never that shard again, and swaps all. A "search more", by its call or by a round asked for all,
// reads every shard under the same change; the latest set is read whole whatever the rule answers.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A phone following the sync world's ref through a phone's policy, reading one file a read, so each of all's shards is
// a read of its own: keepAll is the policy's KeepsAll, and the policy is the engine's background budget.
type testFetchWorld struct {
	sync   *testSyncWorld
	engine *SearchSync
	policy *SearchPolicy
	// all's shards at the head in the order a fetch reads them, youngest first, and every file's bytes by path
	order []string
	sizes map[string]int64

	stateLock  sync.Mutex
	conditions SearchConditions
}

// A world whose ref holds a latest set of four documents and an all of shardCount shards, nothing synced yet, the phone
// in the background on Wi-Fi while charging.
func newTestFetchWorld(t *testing.T, shardCount int) *testFetchWorld {
	t.Helper()
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "doc", 4)
	testWriteAll(t, world, shardCount)
	fetchWorld := &testFetchWorld{
		sync:       world,
		sizes:      map[string]int64{},
		conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true},
	}
	policy, err := NewSearchPolicy(&SearchPolicyArgs{
		Settings: testPhoneSearchSettings(), Conditions: fetchWorld.currentConditions, Clock: world.cache.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	fetchWorld.policy = policy
	engine, err := newSearchSync(&searchSyncArgs{
		cache: world.cache.cache, settings: world.cache.settings, format: DefaultIndexFormatSettings(), clock: world.cache.clock,
		log: NewNoopLogger(), readPathCount: 1, readByteCount: 32 * 1024 * 1024, budget: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	err = engine.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: world.source,
		keepAll:  func() bool { return policy.KeepsAll(world.repoId, 0) },
		mayErase: func(Id, int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	fetchWorld.engine = engine
	listing, err := world.head.ref.store(evsTestId("reader")).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := indexNewPaths(false, indexRootNumber)
	for n := shardCount - 1; 0 <= n; n -= 1 {
		fetchWorld.order = append(fetchWorld.order, paths.allShard(uint32(n)))
	}
	for _, file := range listing.files {
		fetchWorld.sizes[file.path] = int64(file.byteCount)
	}
	return fetchWorld
}

// The conditions the host last reported.
func (self *testFetchWorld) currentConditions() SearchConditions {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.conditions
}

// Reports conditions, as Sidecar.SetSearchConditions does: the policy reads them at its next decision.
func (self *testFetchWorld) setConditions(conditions SearchConditions) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.conditions = conditions
}

// Reports conditions while the next read is in flight: the source's next fetch call takes them before it answers, and
// the read it serves lands.
func (self *testFetchWorld) setConditionsInNextRead(conditions SearchConditions) {
	source := self.sync.source
	source.stateLock.Lock()
	defer source.stateLock.Unlock()
	source.beforeFetch[source.fetchCalls] = func() { self.setConditions(conditions) }
}

// Opens an OS window an hour long on the world's clock, which only a test moves: the answer ends it.
func (self *testFetchWorld) beginWindow() func() {
	return self.policy.BeginWindow(self.sync.cache.clock.Now().Add(time.Hour))
}

// One round now that is not "search more"'s.
func (self *testFetchWorld) round(t *testing.T) {
	t.Helper()
	if err := self.engine.RunRound(context.Background(), self.sync.repoId, self.sync.refId, false); err != nil {
		t.Fatal(err)
	}
}

// How many files the source has fetched so far.
func (self *testFetchWorld) fetchCount() int {
	return len(self.sync.source.fetched())
}

// The files fetched after the first count, as path@version, and all's shards among them by path, in order.
func (self *testFetchWorld) fetchedSince(count int) (files []string, shards []string) {
	files = self.sync.source.fetched()[count:]
	for _, line := range files {
		path, _, _ := strings.Cut(line, "@")
		if strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m") {
			shards = append(shards, path)
		}
	}
	return files, shards
}

// The paths the engine's plan stages, sorted.
func (self *testFetchWorld) staged() []string {
	self.engine.stateLock.Lock()
	ref := self.engine.refs[[2]Id{self.sync.repoId, self.sync.refId}]
	self.engine.stateLock.Unlock()
	_, plan := self.engine.state(ref)
	paths := []string{}
	if plan != nil {
		for _, staged := range plan.Staged {
			paths = append(paths, staged.Path)
		}
	}
	slices.Sort(paths)
	return paths
}

// Whether a snapshot of the ref now would search its all.
func (self *testFetchWorld) allUsable() bool {
	return self.engine.allUsable(self.sync.repoId, self.sync.refId)
}

// What ends a phone's window work partway: its link turning metered, its charger unplugged, Low Power Mode turned on.
func testFetchChanges(foreground bool) []struct {
	name       string
	conditions SearchConditions
} {
	return []struct {
		name       string
		conditions SearchConditions
	}{
		{name: "the link turned metered", conditions: SearchConditions{Reported: true, Charging: true, Foreground: foreground}},
		{name: "the charger was unplugged", conditions: SearchConditions{Reported: true, Unmetered: true, Foreground: foreground}},
		{name: "Low Power Mode turned on", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true, LowPower: true, Foreground: foreground}},
	}
}

// A window on Wi-Fi while charging whose conditions change while its first shard of all is read. The round reads no
// further shard, answers no error and swaps no all, the shard staying staged and the budget counting only that read and
// holding nothing back; a round while the change holds reads nothing and keeps the shard staged; once Wi-Fi and the
// charger are back, the next window reads the rest, youngest first, never that shard again, and swaps all.
func TestAWindowStopsReadingAllOnceTheWindowsRuleNoLongerKeepsIt(t *testing.T) {
	allowed := SearchConditions{Reported: true, Unmetered: true, Charging: true}
	for _, change := range testFetchChanges(false) {
		world := newTestFetchWorld(t, 4)
		// outside a window a phone in the background keeps no all: the latest set alone
		world.round(t)
		if _, shards := world.fetchedSince(0); len(shards) != 0 {
			t.Fatalf("%s: a round outside a window read all's %v", change.name, shards)
		}

		endWindow := world.beginWindow()
		before := world.fetchCount()
		usedBefore, _ := world.policy.BackgroundBytes(world.sync.repoId)
		world.setConditionsInNextRead(change.conditions)
		world.round(t)
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order[:1]) {
			t.Fatalf("%s while the first shard of all was read: the window read all as %v, not %v alone", change.name, shards, world.order[:1])
		}
		if staged := world.staged(); !slices.Equal(staged, world.order[:1]) {
			t.Fatalf("%s: the plan stages %v, not the shard that landed, %v", change.name, staged, world.order[:1])
		}
		if world.allUsable() {
			t.Fatalf("%s: all was swapped holding one shard of %d", change.name, len(world.order))
		}
		used, heldBack := world.policy.BackgroundBytes(world.sync.repoId)
		if want := world.sizes[world.order[0]]; used-usedBefore != want || heldBack != 0 {
			t.Fatalf("%s: the budget counted %d bytes of a %d byte read and holds back %d", change.name, used-usedBefore, want, heldBack)
		}

		// a round while the change holds, still in the window: nothing read, the shard still staged
		before = world.fetchCount()
		world.round(t)
		if files, _ := world.fetchedSince(before); len(files) != 0 {
			t.Fatalf("%s: a round while the change held fetched %v", change.name, files)
		}
		if staged := world.staged(); !slices.Equal(staged, world.order[:1]) {
			t.Fatalf("%s: after a round while the change held the plan stages %v, not %v", change.name, staged, world.order[:1])
		}
		endWindow()

		// the next window the rule allows resumes from the plan
		world.setConditions(allowed)
		endWindow = world.beginWindow()
		before = world.fetchCount()
		world.round(t)
		endWindow()
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order[1:]) {
			t.Fatalf("%s: the next allowed window read all as %v, not on from the staged shard, %v", change.name, shards, world.order[1:])
		}
		if !world.allUsable() || len(world.staged()) != 0 {
			t.Fatalf("%s: after the next allowed window all is usable %t, %v still staged", change.name, world.allUsable(), world.staged())
		}
	}
}

// The same holds for a round in the foreground on Wi-Fi while charging: it reads no further shard of all once the
// change lands in its first read of all, and the next foreground round the rule allows reads the rest.
func TestAForegroundRoundStopsReadingAllOnceTheWindowsRuleNoLongerKeepsIt(t *testing.T) {
	allowed := SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true}
	for _, change := range testFetchChanges(true) {
		world := newTestFetchWorld(t, 3)
		world.setConditions(SearchConditions{Reported: true, Foreground: true})
		// on cellular in the foreground: the latest set alone
		world.round(t)
		world.setConditions(allowed)
		before := world.fetchCount()
		world.setConditionsInNextRead(change.conditions)
		world.round(t)
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order[:1]) {
			t.Fatalf("%s in the foreground: the round read all as %v, not %v alone", change.name, shards, world.order[:1])
		}
		world.setConditions(allowed)
		before = world.fetchCount()
		world.round(t)
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order[1:]) || !world.allUsable() {
			t.Fatalf("%s: the next allowed foreground round read all as %v, not %v, all usable %t", change.name, shards, world.order[1:], world.allUsable())
		}
	}
}

// A "search more" reads on under the same change, which lands in its first read of all: its call, whose metered wait
// is judged once at the call, reads every shard youngest first and completes, and a round asked for all (more) reads
// every shard and swaps all; neither asks the windows rule again.
func TestASearchMoreReadsOnPastTheWindowsRule(t *testing.T) {
	allowed := SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true}
	for _, change := range testFetchChanges(true) {
		world := newTestFetchWorld(t, 4)
		// in the background outside a window: the latest set alone
		world.round(t)
		world.setConditions(allowed)
		settings := testPhoneSearchSettings()
		more, err := NewSearchMore(&SearchMoreArgs{
			Sync: world.engine, Policy: world.policy, Settings: settings, RepoId: world.sync.repoId, RefId: world.sync.refId,
			Clock: world.sync.cache.clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		before := world.fetchCount()
		world.setConditionsInNextRead(change.conditions)
		progress, err := more.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order) {
			t.Fatalf("%s in a search more's first read of all: the call read all as %v, not every shard, %v", change.name, shards, world.order)
		}
		if !progress.Complete || progress.Waiting != "" || !world.allUsable() {
			t.Fatalf("%s: the search more ended %+v, all usable %t", change.name, progress, world.allUsable())
		}

		// a round asked for all, a "search more"'s trigger, under the same change
		world = newTestFetchWorld(t, 4)
		world.round(t)
		world.setConditions(allowed)
		before = world.fetchCount()
		world.setConditionsInNextRead(change.conditions)
		if err := world.engine.RunRound(context.Background(), world.sync.repoId, world.sync.refId, true); err != nil {
			t.Fatal(err)
		}
		if _, shards := world.fetchedSince(before); !slices.Equal(shards, world.order) || !world.allUsable() {
			t.Fatalf("%s in a round asked for all: it read all as %v, not every shard, %v, all usable %t", change.name, shards, world.order, world.allUsable())
		}
	}
}

// The latest set is read whole whatever the rule answers: a first window whose link turns metered while it reads its
// first file reads every latest-set file the head lists and swaps them, and reads nothing of all.
func TestTheLatestSetIsReadWholePastTheWindowsRule(t *testing.T) {
	world := newTestFetchWorld(t, 4)
	endWindow := world.beginWindow()
	defer endWindow()
	world.setConditionsInNextRead(SearchConditions{Reported: true, Charging: true})
	world.round(t)
	files, shards := world.fetchedSince(0)
	if len(shards) != 0 {
		t.Fatalf("a window whose link turned metered in its first read read all's %v", shards)
	}
	want := []string{}
	for path, version := range world.sync.listingAt(t, 0) {
		if !strings.Contains(path, "/a/") || strings.HasSuffix(path, "/a/m") {
			want = append(want, fmt.Sprintf("%s@%d", path, version))
		}
	}
	slices.Sort(want)
	if got := slices.Sorted(slices.Values(files)); !slices.Equal(got, want) {
		t.Fatalf("a window whose link turned metered in its first read read %v of the latest set %v", got, want)
	}
	snapshot, err := world.engine.Snapshot(world.sync.repoId, world.sync.refId)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Release()
	world.sync.assertOneVersion(t, snapshot)
	if snapshot.AllUsable() {
		t.Fatal("all is usable with none of it read")
	}
}
