package evsservice

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A ClusterAtLimitSource a test sets per cluster.
type fakeClusterAtLimit struct {
	stateLock   sync.Mutex
	clusterFull map[string]bool
}

func newFakeClusterAtLimit() *fakeClusterAtLimit {
	return &fakeClusterAtLimit{clusterFull: map[string]bool{}}
}

func (self *fakeClusterAtLimit) set(clusterId string, full bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clusterFull[clusterId] = full
}

func (self *fakeClusterAtLimit) AtLimit(clusterId string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clusterFull[clusterId]
}

// The flag is each cluster's own, a nil limit or one with no source is never full, and its wait is the setting's.
func TestClusterLimitReadsEachClustersFlag(t *testing.T) {
	var nilLimit *ClusterLimit
	if nilLimit.Full("meta-1") {
		t.Fatal("a nil limit reads full")
	}
	empty, err := NewClusterLimit(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Full("meta-1") {
		t.Fatal("a limit with no source reads full")
	}
	source := newFakeClusterAtLimit()
	limit, err := NewClusterLimit(source, &ClusterLimitSettings{RetryAfter: 7 * time.Minute, ListLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	source.set("meta-1", true)
	if !limit.Full("meta-1") || limit.Full("meta-2") {
		t.Fatal("the flag is not the cluster's own")
	}
	reply := limit.UploadRefusal()
	if reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL || reply.GetRetryAfterMs() != uint32((7*time.Minute).Milliseconds()) {
		t.Fatalf("an upload's refusal %v", reply)
	}
	if _, err := NewClusterLimit(source, &ClusterLimitSettings{RetryAfter: 0, ListLimit: 10}); err == nil {
		t.Fatal("a wait that is not positive was taken")
	}
}

// §20.7's classification the cohort limit shares: payload refused, maintenance, authorization, lifecycle, closures,
// drops and CUTs with no upload passing.
func TestQuotaRefusesAtLimitClassifies(t *testing.T) {
	flag := func(flags ...protocol.EvsPushFlag) uint32 {
		value := uint32(0)
		for _, f := range flags {
			value |= uint32(f)
		}
		return value
	}
	cases := []struct {
		name    string
		push    *QuotaPush
		refused bool
	}{
		{name: "a new segment", push: &QuotaPush{NewSegmentCount: 1}, refused: true},
		{name: "an inline record", push: &QuotaPush{InlineRecordCount: 1}, refused: true},
		{name: "a removal", push: &QuotaPush{}, refused: false},
		{name: "a config push", push: &QuotaPush{Authorization: true, NewSegmentCount: 1}, refused: false},
		{name: "a deletion", push: &QuotaPush{Lifecycle: true, NewSegmentCount: 1}, refused: false},
		{name: "a closure", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), InlineRecordCount: 3}, refused: false},
		{name: "a drop with no upload", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_DROP), InlineRecordCount: 2}, refused: false},
		{name: "a drop that uploads", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_DROP), NewSegmentCount: 1}, refused: true},
		{name: "a consume", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME)}, refused: false},
		{name: "a base", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE)}, refused: false},
		{name: "an erase", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_ERASE)}, refused: false},
		{name: "an erase naming a segment", push: &QuotaPush{Flags: flag(protocol.EvsPushFlag_EVS_PUSH_ERASE), NewSegmentCount: 1}, refused: true},
	}
	for _, c := range cases {
		if got := QuotaRefusesAtLimit(c.push); got != c.refused {
			t.Errorf("%s: refused %v, want %v", c.name, got, c.refused)
		}
	}
}

// One engine with the upload route over two metadata clusters, a repo of one network placed on each, and a cohort
// limit a test sets.
type clusterLimitFixture struct {
	*evsFixture
	gate      *QuotaGate
	source    *fakeClusterAtLimit
	firstRepo sidecar.Id
	otherRepo sidecar.Id
	writer    sidecar.Id
	admin     sidecar.Id
}

func newClusterLimitFixture(t *testing.T) *clusterLimitFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	networkId := connect.Id(testId("network-a"))
	host.Gates.OpenService(sidecar.ServiceGateEvs, networkId)
	keys := testReceiptKeys(t, testReceiptKey(1, clock.Now().Add(-time.Hour)))
	gate, err := newQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gate.refresh(ctx)
	usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	source := newFakeClusterAtLimit()
	limit, err := NewClusterLimit(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := newFakeAuthState()
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), nil, &EvsEngineDeps{
		AuthState:  auth,
		ServiceLog: &recordingServiceLog{},
		Uploads:    &EvsUploadDeps{Keys: keys, Quota: gate, Usage: usage, ClusterLimit: limit},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	fixture := &clusterLimitFixture{
		evsFixture: &evsFixture{t: t, ctx: ctx, clock: clock, host: host, auth: auth, engine: engine, networkId: networkId},
		gate:       gate,
		source:     source,
		firstRepo:  testId("cohort repo one"),
		otherRepo:  testId("cohort repo two"),
		writer:     testId("cohort writer"),
		admin:      testId("cohort admin"),
	}
	for _, placed := range []struct {
		repoId    sidecar.Id
		clusterId string
	}{{repoId: fixture.firstRepo, clusterId: "meta-1"}, {repoId: fixture.otherRepo, clusterId: "meta-2"}} {
		// place_new names the cluster as the repo is created, and the repo never moves after
		host.Blobs.SetNewRepoClusterId(placed.clusterId)
		fixture.projectRepo(placed.repoId, fixture.admin)
		if code := fixture.putRepo(placed.repoId, fixture.admin); code != http.StatusOK {
			t.Fatalf("placing a repo on %s: %d", placed.clusterId, code)
		}
		if place := fixture.placement(placed.repoId); place == nil || place.ClusterId != placed.clusterId {
			t.Fatalf("a repo placed on %v, want %s", place, placed.clusterId)
		}
		auth.grant(fixture.writer, placed.repoId, sidecar.AclEvsWrite)
	}
	return fixture
}

// One upload to repoId of byteCount bytes, closure or not, by sidecarId under role.
func (self *clusterLimitFixture) upload(repoId sidecar.Id, sidecarId sidecar.Id, role string, byteCount int, fill byte, closure bool) *httptest.ResponseRecorder {
	segment := testSegment(repoId, byteCount, fill)
	segmentId := sha256.Sum256(segment)
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/segments/" + hex.EncodeToString(segmentId[:]) + "?push=" + sidecar.EvsKeyId(testId("push"))
	if closure {
		path += "&closure=1"
	}
	return self.serve(http.MethodPut, path, self.token(sidecarId, repoScope(repoId, role)), segment)
}

// FS-119's upload clauses on T2: a cluster at its cohort limit refuses an ordinary upload to its repos 507
// CLUSTER_FULL with Retry-After, while the same network's repo on the other cluster takes uploads; a network at its
// own limit gets its QuotaRefusal first; a closure upload within a closure upload's size passes, and one past it is
// refused 507; a re-seed upload passes.
func TestUploadAtTheClusterLimitAnswersClusterFull(t *testing.T) {
	fixture := newClusterLimitFixture(t)
	if recorder := fixture.upload(fixture.firstRepo, fixture.writer, "rw", 4096, 1, false); recorder.Code != http.StatusOK {
		t.Fatalf("below the cohort limit: %d", recorder.Code)
	}

	fixture.source.set("meta-1", true)
	recorder := fixture.upload(fixture.firstRepo, fixture.writer, "rw", 4096, 2, false)
	requireRefusal(t, recorder, http.StatusInsufficientStorage, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)
	if refusalOf(t, recorder).GetRetryAfterMs() != uint32(DefaultClusterLimitSettings().RetryAfter.Milliseconds()) ||
		recorder.Header().Get("Retry-After") != "600" {
		t.Fatalf("a 507 carries retry_after_ms %d and Retry-After %q", refusalOf(t, recorder).GetRetryAfterMs(), recorder.Header().Get("Retry-After"))
	}
	if keys := fixture.keysUnder("seg-1", SegmentKey(fixture.firstRepo, sha256.Sum256(testSegment(fixture.firstRepo, 4096, 2)))); len(keys) != 0 {
		t.Fatal("a refused upload wrote")
	}
	// the network's repo on the other cluster: the estate's free space lifts nothing, and its own cluster refuses nothing
	if recorder := fixture.upload(fixture.otherRepo, fixture.writer, "rw", 4096, 3, false); recorder.Code != http.StatusOK {
		t.Fatalf("the network's repo on the cluster below its limit: %d", recorder.Code)
	}

	// erasure's closure uploads go on within a closure upload's size, and past it are what the limit refuses
	if recorder := fixture.upload(fixture.firstRepo, fixture.admin, "admin", 64*1024, 4, true); recorder.Code != http.StatusOK {
		t.Fatalf("a closure upload at the cohort limit: %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	requireRefusal(t, fixture.upload(fixture.firstRepo, fixture.admin, "admin", sidecar.QuotaClosureUploadMaxByteCount+1, 5, true),
		http.StatusInsufficientStorage, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)

	// a network at its own storage limit hears its QuotaRefusal first, as the route's order says
	fixture.host.Quota.SetStorageRefusal(fixture.networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 10, Used: 10})
	fixture.gate.refresh(fixture.ctx)
	requireRefusal(t, fixture.upload(fixture.firstRepo, fixture.writer, "rw", 4096, 6, false), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	fixture.host.Quota.SetStorageRefusal(fixture.networkId, nil)
	fixture.gate.refresh(fixture.ctx)

	// re-seeding takes uploads at the limit, and so at the cohort limit
	if err := fixture.host.Gates.Set("sidecar:\n  evs:\n    enabled: true\n    networks: [\"" + fixture.networkId.String() + "\"]\n  reseed: true\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.upload(fixture.firstRepo, fixture.writer, "rw", 4096, 7, false); recorder.Code != http.StatusOK {
		t.Fatalf("a re-seed upload at the cohort limit: %d", recorder.Code)
	}

	// the flag falls as the cohort deletes: uploads go on
	fixture.source.set("meta-1", false)
	if err := fixture.host.Gates.Set("sidecar:\n  evs:\n    enabled: true\n    networks: [\"" + fixture.networkId.String() + "\"]\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.upload(fixture.firstRepo, fixture.writer, "rw", 4096, 8, false); recorder.Code != http.StatusOK {
		t.Fatalf("below the cohort limit again: %d", recorder.Code)
	}
}

// FS-119's push clauses at 5c, as pure checks: at the cohort limit a creation answers 507 CLUSTER_FULL with the
// limit's wait, recorded, whatever the network's own state; a removal, a config push, a BASE and a CONSUME pass; a
// network at its own limit hears its QuotaRefusal first.
func TestCheckStorageLimitAtTheClusterLimit(t *testing.T) {
	fixture := newCheckFixture(t)
	creation := func() *PushView {
		plan := fixture.plan()
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
		view := fixture.view(plan)
		view.ClusterFull = true
		view.ClusterFullRetryAfter = 10 * time.Minute
		return view
	}
	removal := func() *PushView {
		plan := fixture.plan()
		plan.BaseVersion = 3
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 1, 0)}
		view := fixture.view(plan)
		view.Head = checkTestHead(view, 3)
		view.ClusterFull = true
		return view
	}
	refusal := CheckRefs(creation())
	requireCheckRefusal(t, "a creation at the cohort limit, under the network's own", refusal, EvsCheckReasonClusterFull)
	if refusal != nil {
		if !refusal.Recorded() || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL {
			t.Fatalf("the cohort limit's refusal: %s recorded %v", refusal.Code, refusal.Recorded())
		}
		if reply := refusal.Reply(fixture.repoId); reply.GetRetryAfterMs() != uint32((10 * time.Minute).Milliseconds()) {
			t.Fatalf("the refusal waits %d ms", reply.GetRetryAfterMs())
		}
	}
	requireCheckPass(t, "a removal at the cohort limit", CheckRefs(removal()))
	configPush := creation()
	configPush.Repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG
	requireCheckPass(t, "a config push at the cohort limit", CheckRefs(configPush))
	mailcfgPush := creation()
	mailcfgPush.Repo.Kind = protocol.RepoKind_REPO_KIND_MAILCFG
	requireCheckPass(t, "a mailcfg push at the cohort limit", CheckRefs(mailcfgPush))

	basePlan := fixture.plan()
	basePlan.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
	basePlan.OwnerSidecarId = &fixture.otherId
	basePlan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_BASE)
	basePlan.BaseVersion = 3
	basePlan.Changes = []*sidecar.EvsPlannedChange{fixture.change(basePlan, checkTestPath("a"), 1, 0)}
	base := fixture.view(basePlan)
	base.Repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	base.Rights = sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	base.Head = checkTestHead(base, 3)
	base.ClusterFull = true
	requireCheckPass(t, "a BASE at the cohort limit", CheckRefs(base))

	below := creation()
	below.ClusterFull = false
	requireCheckPass(t, "a creation below both limits", CheckRefs(below))

	fixture.quota.atLimit(connect.Id(fixture.networkId))
	requireCheckRefusal(t, "a creation at both limits", CheckRefs(creation()), EvsCheckReasonQuota)
}

// The push route at the cohort limit: 507 CLUSTER_FULL with Retry-After, recorded in the head, and recorded: true to
// a retry of the push; a push to a repo on a cluster under its limit commits.
func TestPushAtTheClusterLimitIsRecorded(t *testing.T) {
	fixture := newPushFixture(t, nil)
	source := newFakeClusterAtLimit()
	limit, err := NewClusterLimit(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine.deps.Uploads.ClusterLimit = limit
	source.set("meta-1", true)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusInsufficientStorage, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)
	if recorder.Header().Get("Retry-After") != "600" {
		t.Fatalf("Retry-After %q", recorder.Header().Get("Retry-After"))
	}
	if fixture.head().Version() != 0 || len(fixture.head().Head.GetRefused()) == 0 {
		t.Fatal("the cohort limit's refusal was not recorded in the head")
	}
	// a later attempt of the push meets the recorded refusal, even once the flag falls
	source.set("meta-1", false)
	again := fixture.post(token, body)
	requireRefusal(t, again, http.StatusInsufficientStorage, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("a retry answered without recorded: true")
	}
	// a new push under the limit commits
	next := fixture.plan()
	fixture.create(next, "b")
	fixture.requireCommitted(fixture.push(next), 1)
}

// The first cluster's control plane is counted apart, each family's LIST sizes summed, and its gauge set; repo
// families and the other cluster count nothing.
func TestPublishControlPlaneCountsTheFirstCluster(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	put := func(clusterId string, key string, byteCount int) {
		cluster, err := host.Blobs.Cluster(clusterId)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.PutIfNoneMatch(ctx, key, make([]byte, byteCount), nil); err != nil {
			t.Fatal(err)
		}
	}
	put("meta-1", "place/"+sidecar.EvsKeyId(testId("p1"))+".e", 100)
	put("meta-1", "rev/"+sidecar.EvsKeyId(testId("r1"))+".e", 50)
	put("meta-1", "hold/"+sidecar.EvsKeyId(testId("h1"))+"/_", 25)
	put("meta-1", "gkm/kp/"+sidecar.EvsKeyId(testId("k1"))+"/_", 10)
	put("meta-1", "proj/"+sidecar.EvsKeyId(testId("n1"))+"/1/_", 5)
	// a repo's family and a group's gkm/ objects are its cohort's
	put("meta-1", "head/"+sidecar.EvsKeyId(testId("repo"))+"/_", 1000)
	put("meta-1", "gkm/"+sidecar.EvsKeyId(testId("group"))+"/owner", 1000)
	put("meta-2", "place/"+sidecar.EvsKeyId(testId("p2"))+".e", 1000)

	count, err := PublishControlPlane(ctx, host.ServiceHost(), &ClusterLimitSettings{RetryAfter: time.Minute, ListLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if count.ClusterId != "meta-1" || count.ObjectCount != 5 || count.ByteCount != 190 {
		t.Fatalf("counted %+v, want meta-1's five control-plane objects of 190 bytes", count)
	}
	if got := host.Metrics.Value(fileClusterControlPlaneBytesMetricName, "meta-1"); got != 190 {
		t.Fatalf("the gauge reads %v", got)
	}
}
