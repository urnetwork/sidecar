package evsservice

// EVSB-M10-01's Purger on T2: the allowance, the newest version's reread, the gates (observe, settle, clock), holds
// by placement, staged candidates left to evacuation, the queue's bounds, the give-up age, a kill between DELETEs,
// usage, and the engine's reader of a path's newest version.

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A format2 gate whose purge mode a test sets.
type testFormat2Gate struct {
	stateLock sync.Mutex
	purge     sidecar.Format2Mode
}

func (self *testFormat2Gate) Admits(networkId sidecar.Id) bool {
	return true
}

func (self *testFormat2Gate) PurgeMode() sidecar.Format2Mode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.purge
}

func (self *testFormat2Gate) DropMode() sidecar.Format2Mode {
	return sidecar.Format2Observe
}

func (self *testFormat2Gate) set(mode sidecar.Format2Mode) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.purge = mode
}

// X's newest version's names as a test sets them, by path.
type fakePurgeNewest struct {
	stateLock            sync.Mutex
	pathNames            map[string]map[string]bool
	pathCommitMinuteEnds map[string]time.Time
	err                  error
	readCount            int
}

func (self *fakePurgeNewest) NewestNames(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, pathEpoch uint64, tokenPath sidecar.EvsTokenPath) (*PurgeNewest, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readCount += 1
	if self.err != nil {
		return nil, self.err
	}
	newest := &PurgeNewest{Names: map[string]bool{}, CommitMinuteEnd: self.pathCommitMinuteEnds[tokenPath.KeyString()]}
	for id := range self.pathNames[tokenPath.KeyString()] {
		newest.Names[id] = true
	}
	return newest, nil
}

// The minute X's newest version committed in, for evacuation's 60 s rule.
func (self *fakePurgeNewest) committed(tokenPath sidecar.EvsTokenPath, minuteEnd time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pathCommitMinuteEnds == nil {
		self.pathCommitMinuteEnds = map[string]time.Time{}
	}
	self.pathCommitMinuteEnds[tokenPath.KeyString()] = minuteEnd
}

func (self *fakePurgeNewest) name(tokenPath sidecar.EvsTokenPath, ids ...[]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pathNames == nil {
		self.pathNames = map[string]map[string]bool{}
	}
	names := map[string]bool{}
	for _, id := range ids {
		names[string(id)] = true
	}
	self.pathNames[tokenPath.KeyString()] = names
}

type purgeFixture struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	gate      *testFormat2Gate
	newest    *fakePurgeNewest
	usage     *UsageBatcher
	purger    *Purger
	repoId    sidecar.Id
	refId     sidecar.Id
	networkId sidecar.Id
	pushId    sidecar.Id
	// a barrier name a test stops the item at, and the barriers passed
	stateLock sync.Mutex
	stopAt    string
	stopCount int
	passed    []string
}

func newPurgeFixture(t *testing.T, adjust func(settings *PurgerSettings)) *purgeFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	settings := DefaultPurgerSettings()
	if adjust != nil {
		adjust(settings)
	}
	fixture := &purgeFixture{
		t: t, ctx: ctx, clock: clock, host: host,
		gate:      &testFormat2Gate{purge: sidecar.Format2On},
		newest:    &fakePurgeNewest{},
		usage:     usage,
		repoId:    testId("purge repo"),
		refId:     testId("purge ref"),
		networkId: testId("purge network"),
		pushId:    testId("purge push u"),
	}
	purger, err := newPurger(ctx, host.ServiceHost(), &PurgerDeps{
		Format2:  fixture.gate,
		Newest:   fixture.newest,
		Usage:    usage,
		Settings: settings,
		atStep:   fixture.atStep,
		wait:     clock.Advance,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(purger.Close)
	fixture.purger = purger
	return fixture
}

func (self *purgeFixture) atStep(name string, key string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.passed = append(self.passed, name)
	if name == self.stopAt {
		self.stopCount += 1
		return errors.New("stopped")
	}
	return nil
}

// A kind-5 segment of byteCount at seg/, stored now, and its id.
func (self *purgeFixture) segment(label string, byteCount int) []byte {
	self.t.Helper()
	id := bytes.Repeat([]byte{0}, 32)
	copy(id, label)
	cluster, err := self.host.Blobs.Cluster("seg-1")
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, SegmentKey(self.repoId, [32]byte(id)), make([]byte, byteCount), nil); err != nil {
		self.t.Fatal(err)
	}
	return id
}

// A slot at slot/, stored now, and its id.
func (self *purgeFixture) slot(label string) []byte {
	self.t.Helper()
	slotId := testId(label)
	cluster, err := self.host.Blobs.Cluster("meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, SlotKey(self.repoId, slotId), []byte("slot"), nil); err != nil {
		self.t.Fatal(err)
	}
	return slotId.Bytes()
}

func (self *purgeFixture) segmentStored(id []byte) bool {
	cluster, _ := self.host.Blobs.Cluster("seg-1")
	_, err := cluster.Head(self.ctx, SegmentKey(self.repoId, [32]byte(id)))
	return err == nil
}

func (self *purgeFixture) slotStored(id []byte) bool {
	cluster, _ := self.host.Blobs.Cluster("meta-1")
	slotId, _ := sidecar.IdFromBytes(id)
	_, err := cluster.Head(self.ctx, SlotKey(self.repoId, slotId))
	return err == nil
}

// u's commit replacing version 3 of path, written at versionTime, whose list names segments, staged ones and slots.
func (self *purgeFixture) commit(path sidecar.EvsTokenPath, versionTime time.Time, segmentIds [][]byte, stagedIds [][]byte, slotIds [][]byte) *PurgeCommit {
	return &PurgeCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: self.refId, NetworkId: self.networkId,
		PushId: self.pushId, Version: 9, PathEpoch: 1,
		List: &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
			TokenPath: path.Components(), ReplacedVersion: 3,
			SegmentIds: segmentIds, StagedSegmentIds: stagedIds, SlotIds: slotIds,
		}}},
		Replaced: []*PurgeReplaced{{TokenPath: path, Version: &protocol.EvsEntryVersion{Version: 3, TimeMs: versionTime.UnixMilli()}}},
	}
}

// The stored delta the usage batches carried for the network.
func (self *purgeFixture) storedDelta() int64 {
	self.t.Helper()
	if err := self.usage.Drain(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	return self.host.Quota.StoredDelta(connect.Id(self.networkId))
}

// §11.13's who row: nothing goes before the 60 s allowance; then each candidate the path's newest version does not
// name, kind-5 segments at seg/ reported as negative stored deltas and slots on the metadata cluster, which report
// nothing; a candidate the newest names stays; the queue empties.
func TestPurgerDeletesAfterTheAllowance(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	gone := fixture.segment("chunk 2", 4096)
	named := fixture.segment("chunk 4", 4096)
	slot := fixture.slot("x slot")
	// a client re-uploaded chunk 4's bytes for the path's newest version (FS-64's k+2): it stays
	fixture.newest.name(path, named)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{gone, named}, nil, [][]byte{slot}))
	if fixture.purger.QueuedIdCount() != 3 {
		t.Fatalf("queued %d ids", fixture.purger.QueuedIdCount())
	}

	fixture.clock.Advance(59 * time.Second)
	fixture.purger.runDue()
	if !fixture.segmentStored(gone) || !fixture.slotStored(slot) {
		t.Fatal("a candidate went inside the readers' allowance")
	}
	fixture.clock.Advance(time.Second)
	fixture.purger.runDue()
	if fixture.segmentStored(gone) || fixture.slotStored(slot) {
		t.Fatal("a candidate stayed past the allowance")
	}
	if !fixture.segmentStored(named) {
		t.Fatal("a candidate the newest version names was deleted (FI-16)")
	}
	stats := fixture.purger.Stats()
	if stats.DeletedCount != 2 || stats.NamedCount != 1 || stats.FreedByteCount != 4096 || fixture.purger.QueuedIdCount() != 0 {
		t.Fatalf("stats %+v", stats)
	}
	if delta := fixture.storedDelta(); delta != -4096 {
		t.Fatalf("stored delta %d, want the deleted segment's -4096 and nothing for the slot", delta)
	}
	if got := fixture.host.Metrics.Value(versionlessPurgedBytesMetricName, versionlessPurgedByCommit); got != 4096 {
		t.Fatalf("purged bytes %v", got)
	}
}

// D-TEST-12's observe mode deletes nothing and logs each candidate; a build that has not passed the settle cases
// deletes nothing; a marked or empty list queues nothing.
func TestPurgerGatesDeleteNothing(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	id := fixture.segment("observed", 4096)
	fixture.gate.set(sidecar.Format2Observe)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(id) || fixture.purger.Stats().ObservedCount != 1 {
		t.Fatalf("observe mode: stored %v, %+v", fixture.segmentStored(id), fixture.purger.Stats())
	}

	fixture.gate.set(sidecar.Format2On)
	fixture.host.Blobs.SetSettlePassed("seg-1", false)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(id) {
		t.Fatal("a DELETE on a build that has not passed the settle cases")
	}
	fixture.host.Blobs.SetSettlePassed("seg-1", true)

	fixture.purger.Certain(&PurgeCommit{ClusterId: "meta-1", RepoId: fixture.repoId, List: &protocol.EvsPurgeList{Marked: true}})
	fixture.purger.Certain(&PurgeCommit{ClusterId: "meta-1", RepoId: fixture.repoId, List: &protocol.EvsPurgeList{}})
	if fixture.purger.QueuedIdCount() != 0 {
		t.Fatal("a marked or empty list was queued")
	}
	if fixture.newest.readCount != 0 {
		t.Fatal("a gated purge reread the newest version")
	}
}

// FS-65's clock clauses: an offset unknown or 150 ms fast at the certainty queues nothing; a clock that turns unsure
// inside the allowance deletes nothing, whatever it reads at the due time; each is the sweep's.
func TestPurgerUnsureClockDeletesNothing(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	id := fixture.segment("clocked", 4096)
	fixture.host.ClockCheck.SetOffset(150 * time.Millisecond)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	if fixture.purger.QueuedIdCount() != 0 || fixture.purger.Stats().SweepCount != 1 {
		t.Fatal("a 150 ms fast clock queued a candidate")
	}
	fixture.host.ClockCheck.SetOffset(time.Millisecond)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	fixture.host.ClockCheck.SetUnknown()
	fixture.clock.Advance(30 * time.Second)
	fixture.host.ClockCheck.SetOffset(time.Millisecond)
	fixture.clock.Advance(30 * time.Second)
	fixture.purger.runDue()
	if !fixture.segmentStored(id) || fixture.purger.Stats().SweepCount != 2 {
		t.Fatalf("a clock unsure inside the allowance: stored %v %+v", fixture.segmentStored(id), fixture.purger.Stats())
	}
}

// FS-69's purge clauses: a hold covering the repo keeps what existed at its placement, an uploaded segment by its
// LastModified, which leaves the stored count, and purges what came after; a hold placed between the certainty and
// the DELETEs stops every DELETE after its reread.
func TestPurgerHoldKeepsWhatExistedAtItsPlacement(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	before := fixture.segment("before the hold", 1000)
	fixture.clock.Advance(time.Minute)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.networkId, CaseId: testId("purge case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(fixture.repoId), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)
	after := fixture.segment("after the hold", 2000)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{before, after}, nil, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(before) {
		t.Fatal("content that existed at the hold's placement was purged")
	}
	if fixture.segmentStored(after) {
		t.Fatal("content written after the hold's placement was kept")
	}
	if stats := fixture.purger.Stats(); stats.HeldCount != 1 || stats.DeletedCount != 1 {
		t.Fatalf("stats %+v", stats)
	}
	// both leave the stored count: one deleted, one kept only by the hold (§20.7's stored row)
	if delta := fixture.storedDelta(); delta != -3000 {
		t.Fatalf("stored delta %d", delta)
	}
}

// A hold placed after the certainty: the DELETE whose reread sees it, and every one after, keeps its candidate.
func TestPurgerHoldPlacedAfterTheCertaintyStopsLaterDeletes(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	first := fixture.segment("first", 100)
	second := fixture.segment("second", 100)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{first, second}, nil, nil))
	// past the hold cache's 5 s, so the reread before each DELETE sees what hold/ holds
	fixture.clock.Advance(time.Minute)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.networkId, CaseId: testId("late case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(fixture.repoId), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.purger.runDue()
	if !fixture.segmentStored(first) || !fixture.segmentStored(second) {
		t.Fatal("a DELETE issued after the reread found the hold")
	}
}

// A staged candidate whose version is under 23 h old is left to its batch's evacuation; an older one, which
// evacuation wrote to seg/, is deleted there.
func TestPurgerLeavesYoungStagedCandidatesToEvacuation(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	path := checkTestPath("x")
	young := fixture.segment("young staged", 300)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-22*time.Hour), nil, [][]byte{young}, nil))
	old := fixture.segment("old staged", 300)
	fixture.purger.Certain(fixture.commit(checkTestPath("y"), fixture.clock.Now().Add(-24*time.Hour), nil, [][]byte{old}, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(young) || fixture.segmentStored(old) {
		t.Fatalf("young stored %v, old stored %v", fixture.segmentStored(young), fixture.segmentStored(old))
	}
	if stats := fixture.purger.Stats(); stats.EvacuationCount != 1 || stats.DeletedCount != 1 {
		t.Fatalf("stats %+v", stats)
	}
}

// Past the queue's ids a commit is the sweep's; a candidate not reached within 10 min of its certainty is the
// sweep's; a missing reread leaves the path's candidates; a kill between DELETEs leaves the rest to the sweep.
func TestPurgerBoundsLeaveTheRestToTheSweep(t *testing.T) {
	fixture := newPurgeFixture(t, func(settings *PurgerSettings) { settings.QueueIdCount = 2 })
	path := checkTestPath("x")
	a, b, c := fixture.segment("a", 10), fixture.segment("b", 10), fixture.segment("c", 10)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{a, b}, nil, nil))
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{c}, nil, nil))
	if fixture.purger.QueuedIdCount() != 2 || fixture.purger.Stats().SweepCount != 1 {
		t.Fatalf("a full queue: %d queued, %+v", fixture.purger.QueuedIdCount(), fixture.purger.Stats())
	}
	fixture.clock.Advance(11 * time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(a) || !fixture.segmentStored(b) || fixture.purger.Stats().SweepCount != 3 {
		t.Fatal("a candidate went past the give-up age")
	}

	fixture.newest.err = errors.New("head held")
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{a}, nil, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.segmentStored(a) {
		t.Fatal("a candidate went without its newest version read")
	}
	fixture.newest.err = nil

	// killed after its first DELETE: the second is the sweep's
	fixture.stopAt = BarrierPurgeDeleteAfter
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{a, b}, nil, nil))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if fixture.segmentStored(a) || !fixture.segmentStored(b) || fixture.stopCount != 1 {
		t.Fatalf("killed after one DELETE: a %v b %v", fixture.segmentStored(a), fixture.segmentStored(b))
	}
}

// At most DeleteRate DELETEs a second: two candidates at 2 a second take half a second of the clock.
func TestPurgerPacesItsDeletes(t *testing.T) {
	fixture := newPurgeFixture(t, func(settings *PurgerSettings) { settings.DeleteRate = 2 })
	path := checkTestPath("x")
	ids := [][]byte{fixture.segment("p1", 10), fixture.segment("p2", 10), fixture.segment("p3", 10)}
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), ids, nil, nil))
	fixture.clock.Advance(time.Minute)
	start := fixture.clock.Now()
	fixture.purger.runDue()
	if elapsed := fixture.clock.Now().Sub(start); elapsed != time.Second {
		t.Fatalf("three DELETEs at 2 a second took %s", elapsed)
	}
}

// A stopping process drains what has fallen due, whether or not its loop has woken for it, and takes nothing new.
func TestPurgerDrainsDueItems(t *testing.T) {
	fixture := newPurgeFixture(t, nil)
	purger, err := NewPurger(fixture.ctx, fixture.host.ServiceHost(), &PurgerDeps{
		Format2: fixture.gate, Newest: fixture.newest, Usage: fixture.usage, wait: fixture.clock.Advance,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := checkTestPath("x")
	id := fixture.segment("drained", 10)
	purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	// the item falls due; the drain's notice wakes the loop to it if its own timer has not
	fixture.clock.Advance(time.Minute)
	purger.Drain()
	if fixture.segmentStored(id) {
		t.Fatal("a drain left an item that had fallen due")
	}
	purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{id}, nil, nil))
	if purger.QueuedIdCount() != 0 {
		t.Fatal("a drained purge took a commit")
	}
}

// The engine's reader names X's newest version's slots and segments at the cluster's head, follows a replacement,
// names nothing for a removed path, and judges nothing in another path epoch.
func TestPurgeNewestReaderReadsThePathsNewestVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	reader := fixture.engine.PurgeNewest()
	path := checkTestPath("a")
	slotOne, slotOneObject, slotOneBody := checkTestSlot(t, "p1")
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: path, EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotOne)})
	plan.NewObjects = append(plan.NewObjects, slotOneObject)
	plan.SlotBodies = append(plan.SlotBodies, slotOneBody)
	fixture.requireCommitted(fixture.push(plan), 1)
	newest, err := reader.NewestNames(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 1, path)
	if err != nil || !newest.Names[string(slotOne.Bytes())] || newest.CommitVersion != 1 || newest.CommitMinuteEnd.IsZero() {
		t.Fatalf("newest %+v %v", newest, err)
	}

	slotTwo, slotTwoObject, slotTwoBody := checkTestSlot(t, "p2")
	next := fixture.plan()
	next.Changes = append(next.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: 1, EntryVersion: fixture.check.fileEntry(next, 2, nil, slotTwo)})
	next.NewObjects = append(next.NewObjects, slotTwoObject)
	next.SlotBodies = append(next.SlotBodies, slotTwoBody)
	fixture.requireCommitted(fixture.push(next), 2)
	newest, err = reader.NewestNames(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 1, path)
	if err != nil || newest.Names[string(slotOne.Bytes())] || !newest.Names[string(slotTwo.Bytes())] || newest.CommitVersion != 2 {
		t.Fatalf("after the replacement: %+v %v", newest, err)
	}

	removal := fixture.plan()
	removal.Changes = append(removal.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: 2})
	fixture.requireCommitted(fixture.push(removal), 3)
	newest, err = reader.NewestNames(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 1, path)
	if err != nil || len(newest.Names) != 0 || newest.CommitVersion != 3 {
		t.Fatalf("a removed path: %+v %v", newest, err)
	}

	if _, err := reader.NewestNames(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 2, path); !errors.Is(err, errPurgeUnjudged) {
		t.Fatalf("another path epoch: %v", err)
	}
}

// The settings hold §11.13's floors.
func TestPurgerSettingsHoldTheFloors(t *testing.T) {
	settings := DefaultPurgerSettings()
	settings.Allowance = 59 * time.Second
	if settings.Validate() == nil {
		t.Fatal("an allowance under 60 s was taken")
	}
	settings = DefaultPurgerSettings()
	settings.DeleteRate = 0
	if settings.Validate() == nil {
		t.Fatal("a rate of zero was taken")
	}
	if DefaultPurgerSettings().Validate() != nil {
		t.Fatal("the defaults fail")
	}
}
