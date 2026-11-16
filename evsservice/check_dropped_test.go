package evsservice

// EVS2-M10-09's fence, 5h's DROPPED (§11.7's fence row; FS-91's evs clauses; DESIGN-DETAILS 10.2.7 and 10.6's
// check_dropped_test.go and drop_table_test.go rows), each refusal with a passing twin: a reuse source a committed
// DROP lists refused, recorded, while the DROP's kept head may be cited; a cancelled drop's fence standing; a seal
// whose parts were taken before a DROP refused against the head it rereads from the cluster (FS-91 (d)); a base or a
// reuse source below its entry's drop mark refused after the DROP left the window, a removed boundary's included
// (10.1 I), and the version at the mark passing; a refusal resting on a cached head sent back to the cluster; and the
// repair append of a DROP the table lacks, made once a process by a push that met its bit-5 entry on a cluster head.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A plan creating y whose push names a reuse source of x at version on the fixture's ref.
func (self *dropTestFixture) citingPlan(label string, version uint64) *sidecar.EvsPushPlan {
	plan := self.plan()
	self.create(plan, label)
	plan.ReuseList = []*sidecar.EvsReuse{{RefId: self.check.refId, EntryVersion: version, TokenPath: self.x}}
	return plan
}

// A reuse of a listed version is refused DROPPED, recorded, after the DROP commits; one of the kept head commits; and
// the fence stands after the drop's cancel, since a cancel lifts no fence.
func TestPushDroppedRefusesAListedReuseSource(t *testing.T) {
	fixture := newDropTestFixture(t, 3)
	plan, history := fixture.dropPlan(false, fixture.listedBelow(4))
	fixture.commitDrop(plan, 4)

	listed := fixture.citingPlan("y", 2)
	recorder := fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(listed))
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED)
	if head := fixture.head(); head.Version() != 4 || len(head.Head.GetRefused()) == 0 {
		t.Fatal("DROPPED was not recorded, or the push committed")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	kept := fixture.citingPlan("z", 4)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(kept)), 5)
	fixture.awaitStepEights()

	cancel := fixture.cancelPlan(history.GetDropId(), 4)
	fixture.requireCommitted(fixture.postDrop(cancel), 6)
	fixture.awaitStepEights()
	again := fixture.citingPlan("w", 1)
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(again)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED)
}

// FS-91 (d): a push in parts whose parts were taken before a DROP, naming a reuse source the DROP lists, is refused
// DROPPED at its seal, which rereads the head from the cluster.
func TestPushDroppedRefusesASealAfterTheDrop(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	token := fixture.token(fixture.check.signerId)
	parted := fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100)
	parted.ReuseList = []*sidecar.EvsReuse{{RefId: fixture.check.refId, EntryVersion: 1, TokenPath: fixture.x}}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(parted)
	if err != nil {
		t.Fatal(err)
	}
	places := fixture.postParts(token, built)

	drop, _ := fixture.dropPlan(false, fixture.listedBelow(3))
	fixture.commitDrop(drop, 3)
	requireRefusal(t, fixture.seal(token, built, places), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED)
	if head := fixture.head(); head.Version() != 3 {
		t.Fatalf("a sealed push citing a listed version moved the head to %d", head.Version())
	}
}

// The fence over a view: the window's DROP covers a base and a reuse source at its lineage's (epoch, token path) and
// below through_version, never at through_version or another path; a mark covers what lies below it once the DROP left
// the window, a removed boundary's mark on its marker's entry included; and a refusal resting on a cached head is sent
// back to the cluster.
func TestCheckDroppedWindowMarkAndCache(t *testing.T) {
	fixture := newCheckFixture(t)
	view := dropTestView(t, fixture, nil)
	body := &DropBody{Version: 2, Lists: dropTestLists(t, fixture, view)}

	cite := func(version uint64) *PushView {
		citing := dropTestView(t, fixture, nil)
		citing.Statement.Push.Flags = 0
		citing.Payload.Drop = nil
		citing.Payload.Changes = nil
		citing.Reuses = []*ReuseRead{{
			Reuse:        &sidecar.EvsReuse{RefId: fixture.refId, EntryVersion: version, TokenPath: checkTestPath("x")},
			EntryVersion: &protocol.EvsEntryVersion{Version: version},
			Epoch:        1,
		}}
		citing.Fences = map[sidecar.Id]*EvsDropFence{fixture.refId: {Drops: []*DropBody{body}}}
		return citing
	}
	requireCheckRefusal(t, "a listed reuse source", CheckDropped(cite(2)), EvsCheckReasonDropped)
	requireCheckPass(t, "the kept head", CheckDropped(cite(3)))
	other := cite(2)
	other.Reuses[0].Reuse.TokenPath = checkTestPath("other")
	requireCheckPass(t, "another path", CheckDropped(other))
	otherEpoch := cite(2)
	otherEpoch.Reuses[0].Epoch = 2
	requireCheckPass(t, "another epoch's token path", CheckDropped(otherEpoch))

	// the DROP paged out of the window: its mark refuses below through_version, a removed boundary's on its marker's
	// entry as a written one's, and passes at it
	marked := cite(2)
	marked.Fences = map[sidecar.Id]*EvsDropFence{fixture.refId: {}}
	marked.Reuses[0].DropMark = &protocol.EvsDropMark{DropId: testId("view drop").Bytes(), ThroughVersion: 3}
	requireCheckRefusal(t, "below the mark", CheckDropped(marked), EvsCheckReasonDropped)
	atMark := cite(3)
	atMark.Fences = marked.Fences
	atMark.Reuses[0].DropMark = marked.Reuses[0].DropMark
	requireCheckPass(t, "at the mark", CheckDropped(atMark))

	// a base: x's newest read from an entry under the mark
	base := dropTestView(t, fixture, nil)
	base.Statement.Push.Flags = 0
	base.Payload.Drop = nil
	base.Fences = map[sidecar.Id]*EvsDropFence{}
	base.Paths[checkTestPath("x").KeyString()].DropMark = &protocol.EvsDropMark{ThroughVersion: 3}
	requireCheckRefusal(t, "a base below the mark", CheckDropped(base), EvsCheckReasonDropped)
	base.Paths[checkTestPath("x").KeyString()].DropMark = &protocol.EvsDropMark{ThroughVersion: 2}
	requireCheckPass(t, "a base at the mark", CheckDropped(base))

	// no fences: a format-1 instance runs none
	unfenced := cite(2)
	unfenced.Fences = nil
	requireCheckPass(t, "a format-1 instance", CheckDropped(unfenced))

	// a DROPPED resting on a cached head goes back to the cluster
	cached := cite(2)
	cached.Reuses[0].HeadCached = true
	if !evsDroppedOnCachedHead(cached) {
		t.Error("a reuse source's cached head is not one a DROPPED may rest on")
	}
	cached.Reuses[0].HeadCached = false
	cached.Fences[fixture.refId].Cached = true
	if !evsDroppedOnCachedHead(cached) {
		t.Error("a cached fence is not one a DROPPED may rest on")
	}
	if evsDroppedOnCachedHead(cite(2)) {
		t.Error("cluster heads alone were taken as cached")
	}
}

// The body a drop view's DROP carries, checked.
func dropTestLists(t *testing.T, fixture *checkFixture, view *PushView) *sidecar.EvsDropLists {
	t.Helper()
	lists, err := sidecar.NewEvsDropLists(view.Statement.Push, view.Payload.Drop.Body)
	if err != nil {
		t.Fatal(err)
	}
	return lists
}

// A drop sink that records each append and fails while failing is set.
type dropTestSink struct {
	stateLock sync.Mutex
	failing   bool
	appended  []*DropCommit
	seenMs    []int64
	next      DropSink
}

func (self *dropTestSink) Append(ctx context.Context, commit *DropCommit, seenMs int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return errors.New("a lost append")
	}
	self.appended = append(self.appended, commit)
	self.seenMs = append(self.seenMs, seenMs)
	return self.next.Append(ctx, commit, seenMs)
}

func (self *dropTestSink) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.appended)
}

// Step 8's append lost, the next push that reads the head from the cluster and meets the DROP's bit-5 entry appends it
// again, seen_ms read after that read; a later one, its append made, appends nothing again.
func TestPushRepairAppendsADropTheTableLacks(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	sink := &dropTestSink{failing: true, next: fixture.engine.drops}
	fixture.engine.deps.Drops = sink
	plan, history := fixture.dropPlan(false, fixture.listedBelow(2))
	fixture.commitDrop(plan, 2)
	if fixture.table().Drop(sidecar.Id(history.GetDropId())) != nil {
		t.Fatal("a failing sink's append landed")
	}

	sink.stateLock.Lock()
	sink.failing = false
	sink.stateLock.Unlock()
	clearCache := func() {
		if err := fixture.host.Redis.Delete(fixture.ctx, []string{HeadCacheKey(fixture.check.repoId)}); err != nil {
			t.Fatal(err)
		}
	}
	clearCache()
	readAt := fixture.clock.Now()
	next := fixture.plan()
	fixture.create(next, "after")
	fixture.requireCommitted(fixture.push(next), 3)
	fixture.awaitStepEights()
	entry := fixture.table().Drop(sidecar.Id(history.GetDropId()))
	if entry == nil || entry.State != DropStatePending || entry.SeenMs < readAt.UnixMilli() {
		t.Fatalf("the repair append left %+v", entry)
	}
	count := sink.count()
	clearCache()
	again := fixture.plan()
	fixture.create(again, "again")
	fixture.requireCommitted(fixture.push(again), 4)
	fixture.awaitStepEights()
	if sink.count() != count {
		t.Fatalf("a process appended the same DROP again: %d appends after %d", sink.count(), count)
	}
}
