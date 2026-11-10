package gkmservice

// §11.13's write budget at gkm (KEYS-M2-30; §10.6's checks row, FS-117's gkm legs on T2): which writes issue as P0
// whatever the budget holds, which queue as P1 and are shed, and what the reconciler spends. The budget here is
// sidecartest's, which refuses a network's P1 when a test says so; the real governor's storm runs in
// sidecartest/fs_keys_budget_test.go.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// KF7 under a closed budget: a commit while gkm's state shows no holder dropped since epoch n-1 is P1, and the budget
// sheds it, 429 with Retry-After and nothing written; the same commit once the state shows a holder dropped is a
// Remove, P0, which no closed budget refuses. The state is asked at epoch n-1's pin and time, never the commit's.
func TestGkmCommitIsARemoveOnlyWhileTheStateShowsAHolderDropped(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	budget := fixture.host.Budget
	// the group's creation was P1
	p1Before, _ := budget.P1ByteCount("meta-2")
	budget.RefuseP1("meta-2", fixture.networkId, true)
	epochZero := world.storedEpoch(0)
	staged := world.stageSelfUpdate(1, fakeGkmPin(10))
	request := gkmTestEpochRequest(staged.Message(), 1, false)

	recorder := world.postEpoch(world.adminToken, 1, request)
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("a commit no drop makes a Remove, under a closed budget: %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	if world.storedEpoch(1) != nil {
		t.Fatal("a shed commit was written")
	}
	asks := fixture.auth.holdersDroppedAsked()
	if len(asks) != 1 || asks[0].repoId != world.repoId || asks[0].pinVersion != epochZero.GetHeader().GetAuth().GetVersion() ||
		!asks[0].since.Equal(time.UnixMilli(epochZero.GetTimeMs())) {
		t.Fatalf("the state was not asked at epoch 0's pin and time: %+v", asks)
	}
	if shed := fixture.host.Metrics.Value("urnetwork_gkm_budget_shed_total", "POST /gkm/groups/{group_id}/epochs/{n}"); shed != 1 {
		t.Errorf("shed metric %v", shed)
	}

	fixture.auth.setHoldersDropped(world.repoId, GkmAuthAllowed)
	if recorder := world.postEpoch(world.adminToken, 1, request); recorder.Code != http.StatusOK {
		t.Fatalf("a Remove under a closed budget: %d", recorder.Code)
	}
	if world.storedEpoch(1) == nil {
		t.Fatal("the Remove was not written")
	}
	if p0 := budget.P0ByteCount("meta-2", sidecar.WriteP0KindRemove); p0 < fixture.settings.Prices.CreateByteCount {
		t.Errorf("the Remove's P0 bytes: %d", p0)
	}
	if p1, _ := budget.P1ByteCount("meta-2"); p1 != p1Before {
		t.Errorf("P1 admitted %d bytes under a closed budget", p1-p1Before)
	}
	if violations := budget.Violations(); len(violations) != 0 {
		t.Errorf("budget violations: %v", violations)
	}
}

// FS-117's mislabeled rotations: a claim that states cause REMOVE while gkm's state shows no drop since gen/<g-1>'s
// pin and time is P1, so it and its staged deliveries are shed under a closed budget, nothing written; a claim that
// states SCHEDULE while the state shows a drop is a REMOVE rotation's, P0, issued at once. The stated cause never
// decides either way.
func TestGkmRotationClassFollowsTheStateNotTheStatedCause(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	budget := fixture.host.Budget
	p1Before, _ := budget.P1ByteCount("meta-2")
	budget.RefuseP1("meta-2", fixture.networkId, true)
	reader := world.newReader("sc-reader")
	now := fixture.clock.Now()

	mislabeledKey, mislabeled := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) {
		args.Cause = sidecar.GkmCauseRemove
	})
	staged := world.readerWrap(world.admin, mislabeledKey, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	code, results := world.postWraps(world.adminToken, 2, gkmTestC8(mislabeledKey), staged)
	if code != http.StatusOK || results[0].GetStatus() != http.StatusTooManyRequests {
		t.Fatalf("a mislabeled rotation's staged delivery: %d %v", code, results)
	}
	if recorder := world.postClaim(world.adminToken, 2, mislabeled); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("a mislabeled rotation's claim: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 2)) != nil {
		t.Fatal("a shed claim was written")
	}
	for _, ask := range fixture.auth.holdersDroppedAsked() {
		if ask.pinVersion != 10 || !ask.since.Equal(time.UnixMilli(world.key1.Time().UnixMilli())) {
			t.Errorf("the state was asked at %d and %v, not gen/1's pin and time", ask.pinVersion, ask.since)
		}
	}

	fixture.auth.setHoldersDropped(world.repoId, GkmAuthAllowed)
	scheduledKey, scheduled := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) {
		args.Cause = sidecar.GkmCauseSchedule
	})
	staged = world.readerWrap(world.admin, scheduledKey, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(scheduledKey), staged); status != http.StatusCreated {
		t.Fatalf("a REMOVE rotation's staged delivery under a closed budget: %d", status)
	}
	if recorder := world.postClaim(world.adminToken, 2, scheduled); recorder.Code != http.StatusCreated {
		t.Fatalf("a REMOVE rotation's claim under a closed budget: %d", recorder.Code)
	}
	if p0 := budget.P0ByteCount("meta-2", sidecar.WriteP0KindRotation); p0 < 2*fixture.settings.Prices.CreateByteCount {
		t.Errorf("the rotation's P0 bytes: %d", p0)
	}
	if p1, _ := budget.P1ByteCount("meta-2"); p1 != p1Before {
		t.Errorf("P1 admitted %d bytes under a closed budget", p1-p1Before)
	}
}

// LATE deliveries are §11.13's P1 whatever the state shows, so a closed budget sheds them, item by item, while a
// REMOVE rotation's own writes went through; once the budget admits again they land, charged as P1.
func TestGkmLateDeliveriesQueueAsP1(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	budget := fixture.host.Budget
	fixture.auth.setHoldersDropped(world.repoId, GkmAuthAllowed)
	reader := world.newReader("sc-reader")
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	budget.RefuseP1("meta-2", fixture.networkId, true)
	late := world.readerWrap(world.admin, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), fixture.clock.Now())
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), late); status != http.StatusTooManyRequests {
		t.Fatalf("a LATE delivery under a closed budget: %d", status)
	}
	p1Before, _ := budget.P1ByteCount("meta-2")
	budget.RefuseP1("meta-2", fixture.networkId, false)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), late); status != http.StatusCreated {
		t.Fatalf("a LATE delivery once the budget admits: %d", status)
	}
	if p1, _ := budget.P1ByteCount("meta-2"); p1-p1Before != fixture.settings.Prices.CreateByteCount {
		t.Errorf("the LATE delivery's P1 bytes: %d", p1-p1Before)
	}
}

// Key upkeep is P1 on the first cluster: a ReaderKey upload under a closed budget is shed and stores nothing, and
// lands once the budget admits.
func TestGkmReaderKeyUploadQueuesAsP1(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	budget := fixture.host.Budget
	budget.RefuseP1("meta-1", fixture.networkId, true)
	readerKey := world.readerKey(sidecar.GkmReaderKeyLifetime)
	if status := world.upload(world.token, readerKey); status != http.StatusTooManyRequests {
		t.Fatalf("a ReaderKey under a closed budget: %d", status)
	}
	if fixture.object("meta-1", GkmReaderKeyKey(world.device.sidecarId)) != nil {
		t.Fatal("a shed ReaderKey was stored")
	}
	budget.RefuseP1("meta-1", fixture.networkId, false)
	if status := world.upload(world.token, readerKey); status != http.StatusOK {
		t.Fatalf("a ReaderKey once the budget admits: %d", status)
	}
	if p1, _ := budget.P1ByteCount("meta-1"); p1 != fixture.settings.Prices.CreateByteCount {
		t.Errorf("a first ReaderKey's P1 bytes: %d", p1)
	}
}

// A write whose ctx no budget passed is refused before anything is sent, so a handler that forgot its budget fails
// in its first test.
func TestGkmWritesRefuseAContextNoBudgetPassed(t *testing.T) {
	fixture := newGkmFixture(t)
	cluster := fixture.cluster("meta-1")
	key := "gkm/" + sidecar.EvsKeyId(testId("group-g")) + "/gen/00000000000000000002"
	if _, err := createGkmObject(fixture.ctx, cluster, key, []byte("mine"), 1024); !errors.Is(err, errGkmWriteUnbudgeted) {
		t.Errorf("an unbudgeted create: %v", err)
	}
	if err := replaceGkmObject(fixture.ctx, cluster, key, "", []byte("mine")); !errors.Is(err, errGkmWriteUnbudgeted) {
		t.Errorf("an unbudgeted replace: %v", err)
	}
	if fixture.object("meta-1", key) != nil {
		t.Fatal("an unbudgeted write landed")
	}
	fixture.put("meta-1", key, []byte("theirs"))
	if err := deleteGkmObject(fixture.ctx, cluster, key); !errors.Is(err, errGkmWriteUnbudgeted) {
		t.Errorf("an unbudgeted delete: %v", err)
	}
	if fixture.object("meta-1", key) == nil {
		t.Fatal("an unbudgeted delete landed")
	}
}

// No metadata write may go unpriced: the engine, the reconciler and a shred refuse a host with no budget.
func TestGkmRefusesAHostWithNoBudget(t *testing.T) {
	ctx := t.Context()
	host := sidecartest.NewFakeHost(ctx, sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), nil, nil, nil).ServiceHost()
	host.Budget = nil
	if _, err := NewGkmEngine(ctx, host, nil, &GkmEngineDeps{AuthState: newFakeGkmAuthState()}); err == nil {
		t.Error("an engine started with no budget")
	}
	if _, err := NewGkmReconciler(ctx, host, nil, &GkmReconcilerDeps{State: newFakeGkmReconcilerState()}); err == nil {
		t.Error("a reconciler started with no budget")
	}
	cluster, err := host.Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if err := ShredGroup(ctx, host, cluster, testId("repo-r"), true, nil); err == nil {
		t.Error("a shred ran with no budget")
	}
}

// A shred's deletes are P0 of kind shred, issued at once under a closed budget; a sweep's are unfunded P2, declared
// as a backlog while the page runs and cleared after.
func TestGkmShredIsP0AndSweepsAreUnfundedP2(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	budget := fixture.host.Budget
	leaf := testId("sc-leaf")
	world.state.sidecarNetworks[leaf] = world.networkId
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	world.putEpoch(0)
	world.putEpoch(1)
	staleWrapKey := world.wrapKey(1, "00000000000000ff", leaf, 1)
	fixture.put("meta-2", staleWrapKey, []byte("a lost claim's delivery"))
	fixture.clock.Advance(25 * time.Hour)
	world.sweep()
	if fixture.object("meta-2", staleWrapKey) != nil {
		t.Fatal("the sweep kept a lost claim's delivery past 24 h")
	}
	if p2 := budget.P2ByteCount("meta-2", false); p2 < fixture.settings.Prices.DeleteByteCount {
		t.Errorf("the sweep's unfunded P2 bytes: %d", p2)
	}
	if funded := budget.P2ByteCount("meta-2", true); funded != 0 {
		t.Errorf("the sweep spent %d funded bytes", funded)
	}
	if backlog := budget.P2Backlog("meta-2", gkmSweepBacklogOwner, sidecar.WriteP2RankRetention, false); backlog != 0 {
		t.Errorf("the sweep left a declared backlog of %d", backlog)
	}

	budget.RefuseP1("meta-2", fixture.networkId, true)
	if err := ShredGroup(fixture.ctx, fixture.host.ServiceHost(), fixture.cluster("meta-2"), world.repoId, true, fixture.settings); err != nil {
		t.Fatal(err)
	}
	if len(world.standingEpochs(1)) != 0 {
		t.Fatal("the shred left epochs")
	}
	if p0 := budget.P0ByteCount("meta-2", sidecar.WriteP0KindShred); p0 < 3*fixture.settings.Prices.DeleteByteCount {
		t.Errorf("the shred's P0 bytes: %d", p0)
	}
}

// A budget that, as a sweep's P2 work waits, places a hold on the network and lets the hold set's reread pass, as a
// hold placed while the work queued would: the work's recheck then runs on the new hold.
type gkmHoldingBudget struct {
	*sidecartest.FakeWriteBudget
	placeHold func()
}

func (self *gkmHoldingBudget) AcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	self.placeHold()
	return self.FakeWriteBudget.AcquireP2(ctx, clusterId, work)
}

// A hold placed while a sweep's delete waited for the budget pauses it when its turn comes (§21.9): the recheck finds
// the hold, and the delete is dropped, the object kept.
func TestGkmSweepDeleteRechecksTheHoldWhenItsTurnComes(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	leaf := testId("sc-leaf")
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	staleWrapKey := world.wrapKey(1, "00000000000000ff", leaf, 1)
	fixture.put("meta-2", staleWrapKey, []byte("a lost claim's delivery"))
	fixture.clock.Advance(25 * time.Hour)
	caseId := testId("case-1")
	host := fixture.host.ServiceHost()
	placed := false
	host.Budget = &gkmHoldingBudget{
		FakeWriteBudget: fixture.host.Budget,
		placeHold: func() {
			if placed {
				return
			}
			placed = true
			holdBytes, err := sidecar.EncodeHoldRecord(&sidecar.HoldRecord{
				NetworkId:  world.networkId,
				CaseId:     caseId,
				Kind:       sidecar.HoldKindPreserve2703f,
				Scope:      sidecar.HoldScopeNetwork(),
				PlaceTime:  fixture.clock.Now(),
				ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			fixture.put("meta-1", sidecar.HoldObjectKey(world.networkId, caseId), holdBytes)
			fixture.clock.Advance(sidecar.DefaultHoldSetSettings().RereadInterval)
		},
	}
	reconciler, err := NewGkmReconciler(fixture.ctx, host, DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{State: world.state})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	cursor := &GkmSweepCursor{}
	for {
		next, done, err := reconciler.SweepPage(fixture.ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		cursor = next
	}
	if !placed {
		t.Fatal("the sweep reached no delete")
	}
	if fixture.object("meta-2", staleWrapKey) == nil {
		t.Fatal("a delete a hold came to cover while it waited went ahead")
	}
}

// The prices follow §11.13's rows: a small object its row, a larger one its shard past 14 KiB rounded to the block.
func TestGkmWritePricesFollowTheCostRows(t *testing.T) {
	prices := DefaultGkmWritePrices()
	for _, c := range []struct {
		name  string
		price int64
		want  int64
	}{
		{name: "a small create", price: prices.create(1400), want: 9 * 1024},
		{name: "a create at 14 KiB", price: prices.create(14 * 1024), want: 9 * 1024},
		{name: "a 50 KB sealed GroupInfo's epoch", price: prices.create(50 * 1000), want: 9*1024 + 12*1024},
		{name: "an overwrite", price: prices.overwrite(1340), want: 14 * 1024},
		{name: "a replace with no etag", price: prices.replace("", 1340), want: 9 * 1024},
		{name: "a replace with an etag", price: prices.replace("etag", 1340), want: 14 * 1024},
		{name: "a delete", price: prices.delete(), want: 3584},
	} {
		if c.price != c.want {
			t.Errorf("%s: %d, not %d", c.name, c.price, c.want)
		}
	}
	bad := DefaultGkmWritePrices()
	bad.DeleteByteCount = 0
	settings := DefaultGkmServiceSettings()
	settings.Prices = bad
	if err := settings.Validate(); err == nil {
		t.Error("a delete priced at nothing passed")
	}
	settings.Prices = nil
	if err := settings.Validate(); err == nil {
		t.Error("no prices passed")
	}
}
