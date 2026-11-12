// EVS1-M2-12's tests: the push route on T2's fakes, real signed statements and checked payloads end to end, through
// the engine's guard. Steps 4 to 8 and §11.8's outcome rows: a commit and its retry, PUSH_ID_REUSED, final and
// recorded refusals with the placeholder head, the refusal fence's one-a-second limit and 8 records, ApplyThenDrop
// and a lost answer on the head PUT, 412 reruns and 429 BUSY, the fence row, FS-113's stale below-limit attempt,
// two concurrent retries committing once, new slots, the cost of a push with a cached head, and the Resolve rule.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The gate views a test holds: the check fixture's newest state for its network.
type pushTestGateViews struct {
	check *checkFixture
}

func (self *pushTestGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	if networkId != self.check.networkId {
		return nil, EvsAuthUnknown
	}
	return self.check.auth, EvsAuthAllowed
}

// One engine with a placed, active repo on meta-1, gen/1 of its group stored, and the check fixture's writers.
type pushFixture struct {
	t        *testing.T
	ctx      context.Context
	check    *checkFixture
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	auth     *fakeAuthState
	engine   *EvsEngine
	cluster  sidecar.BlobCluster
	settings *EvsSettings
}

func newPushFixture(t *testing.T, adjust func(settings *EvsSettings)) *pushFixture {
	ctx := t.Context()
	check := newCheckFixture(t)
	clock := sidecartest.NewFakeClock(check.now)
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	host.Gates.OpenService(sidecar.ServiceGateEvs, connect.Id(check.networkId))
	settings := DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	if adjust != nil {
		adjust(settings)
	}
	auth := newFakeAuthState()
	auth.grant(check.signerId, check.repoId, sidecar.AclEvsWrite)
	auth.grant(check.otherId, check.repoId, sidecar.AclEvsWrite)
	usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), settings, &EvsEngineDeps{
		AuthState: auth,
		Uploads:   &EvsUploadDeps{Keys: check.receiptKeys, Quota: check.quota.gate, Usage: usage},
		GateViews: &pushTestGateViews{check: check},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &pushFixture{t: t, ctx: ctx, check: check, clock: clock, host: host, auth: auth, engine: engine, cluster: cluster, settings: settings}
	fixture.place()
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.putGeneration()
	return fixture
}

// place/ on the first cluster, naming meta-1.
func (self *pushFixture) place() {
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.check.signerId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.EvsPlaceKey(self.check.repoId), placeBytes, nil); err != nil {
		self.t.Fatal(err)
	}
}

// repo/ of kind in state, replacing what is there.
func (self *pushFixture) putRepo(kind protocol.RepoKind, state protocol.EvsRepoState) {
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.check.repoId.Bytes(), Kind: kind, State: state, Format: 1, NetworkId: self.check.networkId.Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	info, err := self.cluster.Head(self.ctx, RepoKey(self.check.repoId))
	if err == nil {
		_, err = self.cluster.PutIfMatch(self.ctx, RepoKey(self.check.repoId), info.Etag, repoBytes, nil)
	} else {
		_, err = self.cluster.PutIfNoneMatch(self.ctx, RepoKey(self.check.repoId), repoBytes, nil)
	}
	if err != nil {
		self.t.Fatal(err)
	}
	self.engine.repos.Forget(self.check.repoId)
}

// gen/1 of the fixture's group, signed by its writer, as gkm stores it.
func (self *pushFixture) putGeneration() {
	record := self.check.record()
	record.Cause = uint32(sidecar.GkmCauseRequest)
	record.HoldersSha256 = bytes.Repeat([]byte{3}, 32)
	signed, err := sidecar.SignGenRotate(record, sidecar.GkmSignFunction(checkTestSign(self.check.signingKey, self.check.signerId)))
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.GkmGenerationPath(self.check.groupId, 1), signedBytes, nil); err != nil {
		self.t.Fatal(err)
	}
}

// The writer's evs token: rw on the repo, unless roles name others.
func (self *pushFixture) token(sidecarId sidecar.Id, roles ...string) string {
	if len(roles) == 0 {
		roles = []string{"rw"}
	}
	scopes := []string{}
	for _, role := range roles {
		scopes = append(scopes, repoScope(self.check.repoId, role))
	}
	connectSidecarId := connect.Id(sidecarId)
	clientId := self.check.clientId
	return self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.check.networkId),
		ClientId:  connect.Id(clientId),
		SidecarId: &connectSidecarId,
		Audience:  EvsAudience,
		Scopes:    scopes,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
}

// A plan on the shared file-mode ref, on the head as it stands, under a push id whose first 8 bytes, which a
// refusal record keeps, are its own.
func (self *pushFixture) plan() *sidecar.EvsPushPlan {
	plan := self.check.plan()
	pushIdSum := sha256.Sum256([]byte(fmt.Sprintf("push test push %d", self.check.pushSeq)))
	plan.PushId = sidecar.Id(pushIdSum[:16])
	plan.TimeMs = self.clock.Now().UnixMilli()
	head := self.head()
	if !head.Absent() && 0 < head.Version() {
		plan.BaseVersion = head.Version()
		plan.BaseChain = [32]byte(head.Head.GetChain())
	}
	return plan
}

// plan's request body, built and signed by the fixture's writer.
func (self *pushFixture) body(plan *sidecar.EvsPushPlan) *protocol.EvsPushRequest {
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.check.signingKey, self.check.signerId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
}

// One POST .../push of body under token.
func (self *pushFixture) post(token string, body *protocol.EvsPushRequest) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+"/push", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// plan pushed by the writer.
func (self *pushFixture) push(plan *sidecar.EvsPushPlan) *httptest.ResponseRecorder {
	return self.post(self.token(self.check.signerId), self.body(plan))
}

// The version a 200 answers.
func (self *pushFixture) requireCommitted(recorder *httptest.ResponseRecorder, version uint64) *protocol.EvsPushReply {
	self.t.Helper()
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("status %d (%s), want 200", recorder.Code, refusalOf(self.t, recorder).GetCode())
	}
	reply := &protocol.EvsPushReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		self.t.Fatal(err)
	}
	if reply.GetVersion() != version {
		self.t.Fatalf("committed at %d, want %d", reply.GetVersion(), version)
	}
	return reply
}

// The ref's head from the cluster.
func (self *pushFixture) head() *EvsStoredHead {
	head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.check.repoId, self.check.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	return head
}

// Waits for every started step 8 to finish.
func (self *pushFixture) awaitStepEights() {
	self.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		started, finished, changed := self.engine.StepEights()
		if started == finished {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			self.t.Fatal("step 8 never finished")
		}
	}
}

// A creation of path on base 0, at the versions rule's max(b, m) + 1 for a path never removed.
func (self *pushFixture) create(plan *sidecar.EvsPushPlan, labels ...string) {
	plan.Changes = append(plan.Changes, self.check.change(plan, checkTestPath(labels...), 0, plan.BaseVersion+1))
}

func TestPushCommitsAndAnswersItsVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	head := fixture.head()
	if head.Version() != 1 || sidecar.Id(head.Head.GetPushId()) != plan.PushId {
		t.Fatalf("head at %d with push %x", head.Version(), head.Head.GetPushId())
	}
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != 1 || window[0].PushId != plan.PushId || !window[0].CreatesPath() {
		t.Fatalf("window %v %v", window, err)
	}
	start := sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	if !bytes.Equal(head.Head.GetWindowBaseChain(), start[:]) || head.Head.GetRefKind() != uint32(protocol.EvsRefKind_EVS_REF_SHARED) ||
		head.Head.GetPathEpoch().GetCurrent() != 1 {
		t.Fatal("a first commit without the ref's kind, epoch or base chain")
	}
	// the record is at the place its entry names
	record, err := ReadRecord(fixture.ctx, NewRecordCache(fixture.settings), fixture.cluster, window[0].Place)
	if err != nil || record.PushId != plan.PushId || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH {
		t.Fatalf("record %v %v", record, err)
	}
	fixture.awaitStepEights()
	if cached, ok := fixture.engine.heads.Cache().Read(fixture.ctx, fixture.check.repoId, fixture.check.refId, 1); !ok || cached.Version() != 1 {
		t.Fatal("step 8 cached no head")
	}

	// a second push on version 1
	next := fixture.plan()
	fixture.create(next, "b")
	fixture.requireCommitted(fixture.push(next), 2)
}

// §11.8's 5a: a retry of a committed push answers its original version however many commits followed, a log page
// holding it included; another statement under its push id gets 409 PUSH_ID_REUSED.
func TestPushRetryAnswersTheOriginalVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	fixture.requireCommitted(fixture.post(token, body), 1)
	for i := 0; i < 3; i += 1 {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("more %d", i))
		fixture.requireCommitted(fixture.push(next), uint64(2+i))
	}
	fixture.requireCommitted(fixture.post(token, body), 1)
	if fixture.head().Version() != 4 {
		t.Fatal("a retry committed again")
	}

	reused := fixture.plan()
	reused.PushId = plan.PushId
	reused.BaseVersion = 0
	reused.BaseChain = sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	fixture.create(reused, "another")
	requireRefusal(t, fixture.post(token, fixture.body(reused)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED)
}

// A refusal the head settles for good is answered and never recorded: the head is as it was.
func TestPushFinalRefusalIsNotRecorded(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	before := fixture.head()

	conflict := fixture.plan()
	conflict.Changes = append(conflict.Changes, fixture.check.change(conflict, checkTestPath("a"), 0, 2))
	requireRefusal(t, fixture.push(conflict), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if after := fixture.head(); after.Etag != before.Etag {
		t.Fatal("a final refusal wrote the head")
	}
}

// §11.8's refuse and first rows: a refusal the head does not settle is recorded first, a creating push's in a
// placeholder head at version 0, and every later attempt of its push id answers it with recorded: true; the ref's
// first commit replaces the placeholder by If-Match and keeps its record.
func TestPushRecordedRefusalInAPlaceholderHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if refusalOf(t, recorder).GetRecorded() {
		t.Fatal("the recording attempt answered recorded: true")
	}
	placeholder := fixture.head()
	if placeholder.Absent() || placeholder.Version() != 0 || placeholder.Head.GetRefKind() != 0 || len(placeholder.Head.GetWindow()) != 0 ||
		placeholder.Head.GetFence() != 1 || len(placeholder.Head.GetRefused()) != sidecar.EvsRefusalByteCount {
		t.Fatalf("placeholder %v", placeholder.Head)
	}
	again := fixture.post(token, body)
	requireRefusal(t, again, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("a retry of a recorded refusal answered without recorded: true")
	}

	// the first commit replaces the placeholder, keeping its record, once the refusal fence is a second old
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	creation := fixture.plan()
	fixture.create(creation, "b")
	fixture.requireCommitted(fixture.push(creation), 1)
	head := fixture.head()
	if !bytes.Equal(head.Head.GetRefused(), placeholder.Head.GetRefused()) {
		t.Fatal("the first commit dropped the placeholder's record")
	}
	requireRefusal(t, fixture.post(token, body), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

// §11.8's refuse row's limits: a refusal fence under a second old, or 8 live records, answer 429 WAIT and record
// nothing; past its until, a record lapses at the next head write.
func TestPushRecordsAtMostOneRefusalASecond(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	token := fixture.token(fixture.check.signerId)
	forced := func() *protocol.EvsPushRequest {
		plan := fixture.plan()
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		fixture.create(plan, fmt.Sprintf("forced %d", fixture.check.pushSeq))
		return fixture.body(plan)
	}
	requireRefusal(t, fixture.post(token, forced()), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	waited := fixture.post(token, forced())
	requireRefusal(t, waited, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	if refusalOf(t, waited).GetRetryAfterMs() == 0 || waited.Header().Get("Retry-After") == "" {
		t.Fatal("a 429 without its wait")
	}
	for i := 1; i < sidecar.EvsHeadMaxRefusalCount; i += 1 {
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
		requireRefusal(t, fixture.post(token, forced()), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	requireRefusal(t, fixture.post(token, forced()), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	if count := len(fixture.head().Head.GetRefused()) / sidecar.EvsRefusalByteCount; count != sidecar.EvsHeadMaxRefusalCount {
		t.Fatalf("%d records", count)
	}
	// an honest push still commits beside them, and once the records lapse its write drops them
	fixture.clock.Advance(DefaultEvsSettings().PushTimeBound + 2*time.Second)
	honest := fixture.plan()
	fixture.create(honest, "honest")
	fixture.requireCommitted(fixture.push(honest), 2)
	if 0 < len(fixture.head().Head.GetRefused()) {
		t.Fatal("lapsed records survived a head write")
	}
}

// 5b's time: a statement past its 10 min is refused and recorded (TIME_STALE); one past the bound ahead gets 429
// TIME_AHEAD, refusing nothing.
func TestPushTimeChecks(t *testing.T) {
	fixture := newPushFixture(t, nil)
	stale := fixture.plan()
	stale.TimeMs = fixture.clock.Now().Add(-11 * time.Minute).UnixMilli()
	fixture.create(stale, "stale")
	requireRefusal(t, fixture.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE)
	if fixture.head().Absent() {
		t.Fatal("a stale statement's refusal was not recorded")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	ahead := fixture.plan()
	ahead.TimeMs = fixture.clock.Now().Add(11 * time.Minute).UnixMilli()
	fixture.create(ahead, "ahead")
	requireRefusal(t, fixture.push(ahead), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD)
	if 1 < len(fixture.head().Head.GetRefused())/sidecar.EvsRefusalByteCount {
		t.Fatal("TIME_AHEAD recorded a refusal")
	}
}

// FS-113's core on T2: attempt B, over the limit, records P's refusal; attempt A of the same statement, released
// with a stale below-limit list, answers B's refusal with recorded: true and never commits.
func TestPushStaleBelowLimitAttemptAnswersTheRecordedRefusal(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	fixture.check.quota.atLimit(connect.Id(fixture.check.networkId))
	requireRefusal(t, fixture.post(token, body), http.StatusPaymentRequired, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	// A's list is stale: below the limit
	fixture.check.quota.host.Quota.SetStorageRefusal(connect.Id(fixture.check.networkId), nil)
	fixture.check.quota.gate.refresh(fixture.ctx)
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusPaymentRequired, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	if !refusalOf(t, recorder).GetRecorded() {
		t.Fatal("A answered without recorded: true")
	}
	if fixture.head().Version() != 0 {
		t.Fatal("P committed after its recorded refusal")
	}
}

// §22.8's unknown rule on step 7: the head PUT applies and its answer is lost; the reread finds P committed, which is
// this attempt's own, so it answers 200 and runs step 8. A PUT that never applied leaves the ETag, and the attempt
// issues it again within its 5 s.
func TestPushStepSevenLostAnswer(t *testing.T) {
	for _, result := range []sidecartest.FaultResult{sidecartest.ApplyThenDrop, sidecartest.FailBeforeApply} {
		fixture := newPushFixture(t, nil)
		plan := fixture.plan()
		fixture.create(plan, "a")
		if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: result,
		}); err != nil {
			t.Fatal(err)
		}
		fixture.requireCommitted(fixture.push(plan), 1)
		fixture.awaitStepEights()
		if started, _, _ := fixture.engine.StepEights(); started != 1 {
			t.Errorf("%s: step 8 ran %d times", result, started)
		}
		if fixture.head().Version() != 1 {
			t.Errorf("%s: head at %d", result, fixture.head().Version())
		}
	}
}

// With the store unreachable for every head write and read, the push answers 503 {push_id, outcome: unknown} and
// deletes nothing.
func TestPushStoreUnreachableAnswersUnknown(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	key := HeadKey(fixture.check.repoId, fixture.check.refId)
	for _, op := range []string{sidecartest.FaultOpPut, sidecartest.FaultOpGet} {
		if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
			Op: op, KeyPrefix: key, Result: sidecartest.FailBeforeApply, Repeat: -1, Nth: map[string]int{sidecartest.FaultOpPut: 1, sidecartest.FaultOpGet: 2}[op],
		}); err != nil {
			t.Fatal(err)
		}
	}
	recorder := fixture.push(plan)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	reply := refusalOf(t, recorder)
	if reply.GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN || sidecar.Id(reply.GetPushId()) != plan.PushId {
		t.Fatalf("outcome %s for push %x", reply.GetOutcome(), reply.GetPushId())
	}
}

// §11.8's 412 row: a step 7 that fails its precondition rereads and goes again, and past 8 such answers 429 BUSY,
// refusing nothing, so the client's retry still commits.
func TestPushConflictsRerunAndEndBusy(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	key := HeadKey(fixture.check.repoId, fixture.check.refId)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: key, Result: sidecartest.Precondition, Repeat: 2,
	}); err != nil {
		t.Fatal(err)
	}
	fixture.requireCommitted(fixture.push(plan), 1)

	busy := fixture.plan()
	fixture.create(busy, "b")
	body := fixture.body(busy)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: key, Result: sidecartest.Precondition, Repeat: fixture.settings.PushConflictRetryCount,
	}); err != nil {
		t.Fatal(err)
	}
	token := fixture.token(fixture.check.signerId)
	requireRefusal(t, fixture.post(token, body), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
	fixture.requireCommitted(fixture.post(token, body), 2)
}

// FS-2: two pushes of one path from one base, the first committing; the second, rechecked on the new head after its
// 412, gets 409 naming the path.
func TestPushSecondOfTwoOnOnePathConflicts(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	first := fixture.plan()
	first.Changes = append(first.Changes, fixture.check.change(first, checkTestPath("a"), 1, 2))
	second := fixture.plan()
	second.Changes = append(second.Changes, fixture.check.change(second, checkTestPath("a"), 1, 2))
	fixture.requireCommitted(fixture.push(first), 2)
	recorder := fixture.push(second)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if paths := refusalOf(t, recorder).GetPaths(); len(paths) != 1 {
		t.Fatalf("paths %v", paths)
	}
}

// FS-1's two concurrent retries of one push id commit once, each answering the same version.
func TestPushConcurrentRetriesCommitOnce(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	recorders := make([]*httptest.ResponseRecorder, 4)
	var waitGroup sync.WaitGroup
	for i := range recorders {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			recorders[i] = fixture.post(token, body)
		}()
	}
	waitGroup.Wait()
	for _, recorder := range recorders {
		fixture.requireCommitted(recorder, 1)
	}
	if fixture.head().Version() != 1 {
		t.Fatalf("head at %d", fixture.head().Version())
	}
}

// §11.8's fence row: a fence raised after the attempt's arrival less 100 ms ends it 503 unknown; one arriving a second
// after the fence commits.
func TestPushFenceAfterArrivalEndsTheAttempt(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	paid := fixture.paidContext()
	if _, err := fixture.engine.heads.RaiseFence(paid, fixture.cluster, fixture.check.repoId, fixture.check.refId); err != nil {
		t.Fatal(err)
	}
	fenced := fixture.plan()
	fixture.create(fenced, "b")
	recorder := fixture.push(fenced)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("a fenced attempt's outcome is not unknown")
	}
	fixture.clock.Advance(time.Second)
	later := fixture.plan()
	fixture.create(later, "c")
	fixture.requireCommitted(fixture.push(later), 2)
}

// A ctx carrying a write class, for a test's own writes through the engine's budgeted store.
func (self *pushFixture) paidContext() context.Context {
	grant, err := self.host.Budget.AdmitP1(self.ctx, "meta-1", connect.Id(self.check.networkId), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(grant.Close)
	return grant.Context()
}

// R-EVS-15's cost: with the head cached and repo/ in this process, a push of one change costs three store rounds: its
// entry's GET in step 4's round, its batch's PUT and its head's PUT.
func TestPushCostsThreeStoreRoundsWithACachedHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.awaitStepEights()
	next := fixture.plan()
	fixture.create(next, "b")
	body := fixture.body(next)
	gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	puts := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpPut)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 2)
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets; got != 1 {
		t.Errorf("%d GETs, want the entry's alone", got)
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpPut) - puts; got != 2 {
		t.Errorf("%d PUTs, want the batch's and the head's", got)
	}
}

// A seal of a one-part statement, or one with places unlike its part count, is invalid and writes nothing.
func TestPushRefusesASealOfAOnePartStatement(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	body.PartPlaces = []*protocol.EvsPlace{{Minute: 1}}
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), body), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if !fixture.head().Absent() {
		t.Fatal("a seal wrote the head")
	}
}

// A statement its token's sidecar did not sign refuses nothing and reads nothing.
func TestPushRefusesAForeignSignatureBeforeAnyRead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	warm := fixture.plan()
	fixture.create(warm, "warm")
	fixture.requireCommitted(fixture.push(warm), 1)
	plan := fixture.plan()
	fixture.create(plan, "a")
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.otherKey, fixture.check.signerId)).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}),
		http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets; got != 0 {
		t.Errorf("%d reads for a forged statement", got)
	}
}

// §11.8 step 6's slots: a new slot is written If-None-Match before the head; its retry's equal bytes are success; a
// slot past 23 h with equal bytes is 409 SLOT_STALE, recorded.
func TestPushWritesItsNewSlots(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, slotObject, slotBody := checkTestSlot(t, "slot a")
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	fixture.requireCommitted(fixture.post(token, body), 1)
	object, err := fixture.cluster.Get(fixture.ctx, SlotKey(fixture.check.repoId, slotId))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := readAllLimited(object, DefaultEvsSettings().SlotMaxByteCount)
	object.Body.Close()
	if !bytes.Equal(stored, slotBody) {
		t.Fatal("the slot holds other bytes")
	}

	// a second push introducing that slot id again a day later, with the same bytes: stale
	fixture.clock.Advance(24 * time.Hour)
	again := fixture.plan()
	again.Changes = append(again.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("b"), EntryVersion: fixture.check.fileEntry(again, 2, nil, slotId),
	})
	again.NewObjects = append(again.NewObjects, slotObject)
	again.SlotBodies = append(again.SlotBodies, slotBody)
	requireRefusal(t, fixture.push(again), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
}

// §11.8's Resolve rule: committed at its place, dead once the head passed b+64 or its time checks and a later fence,
// else pending.
func TestResolvePush(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 1)
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: fixture.check.repoId, RefId: fixture.check.refId,
		PushId: plan.PushId, SignerSidecarId: fixture.check.signerId, TimeMs: plan.TimeMs,
		Body: sidecar.EvsPushRecordBody(body.Statement, body.Payload),
	}
	head := fixture.head()
	resolution, err := fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, record, head.Head)
	if err != nil || resolution.State != EvsResolveCommitted || resolution.Version != 1 {
		t.Fatalf("resolution %+v %v", resolution, err)
	}

	pending := fixture.plan()
	fixture.create(pending, "pending")
	pendingBody := fixture.body(pending)
	pendingRecord := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: fixture.check.repoId, RefId: fixture.check.refId,
		PushId: pending.PushId, SignerSidecarId: fixture.check.signerId, TimeMs: pending.TimeMs,
		Body: sidecar.EvsPushRecordBody(pendingBody.Statement, pendingBody.Payload),
	}
	resolution, err = fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, pendingRecord, head.Head)
	if err != nil || resolution.State != EvsResolvePending {
		t.Fatalf("resolution %+v %v", resolution, err)
	}
	fenced := CloneEvsHead(head.Head)
	fenced.FenceMs = time.UnixMilli(pending.TimeMs).Add(evsResolveStatementLife + time.Second).UnixMilli()
	resolution, err = fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, pendingRecord, fenced)
	if err != nil || resolution.State != EvsResolveDead {
		t.Fatalf("resolution %+v %v", resolution, err)
	}
	// 64 commits after the pending push's base: it can no longer land within (b, b+64]
	for i := 0; i < evsFileModeBaseWindow+1; i += 1 {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("after %d", i))
		fixture.requireCommitted(fixture.push(next), uint64(2+i))
	}
	resolution, err = fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, pendingRecord, fixture.head().Head)
	if err != nil || resolution.State != EvsResolveDead {
		t.Fatalf("resolution %+v %v", resolution, err)
	}
}

// DESIGN-DETAILS 2.2.3's record rule: an attempt appends its batch record and awaits its write before it issues
// step 7. A batch that is not written, or whose write's outcome stays unknown, ends the attempt 503 with no head
// write issued: a head PUT here would fire the plan that waits for one.
func TestPushIssuesNoHeadWriteWhenItsBatchIsNotWritten(t *testing.T) {
	for _, result := range []sidecartest.FaultResult{sidecartest.FailBeforeApply, sidecartest.Held} {
		fixture := newPushFixture(t, nil)
		faults := fixture.host.Blobs.Faults()
		// every create of the batch fails, the retry of an unknown outcome included
		if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: batchKeyPrefix, Result: result, Repeat: -1}); err != nil {
			t.Fatal(err)
		}
		if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.FailBeforeApply}); err != nil {
			t.Fatal(err)
		}
		plan := fixture.plan()
		fixture.create(plan, "a")
		recorder := fixture.push(plan)
		requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
		headWrites := 0
		for _, unfired := range faults.Unfired() {
			if unfired.KeyPrefix == "head/" {
				headWrites += 1
			}
		}
		if headWrites != 1 {
			t.Fatalf("%v on the batch: a head write was issued with no record behind it", result)
		}
		if !fixture.head().Absent() {
			t.Fatalf("%v on the batch: a head was written", result)
		}
		faults.Clear()
	}
}

// On an unsure clock a push writes no batch and no head, and commits once the clock is sure again.
func TestPushOnAnUnsureClockWritesNoBatchAndNoHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	fixture.host.ClockCheck.SetUnknown()
	if recorder := fixture.post(token, body); recorder.Code == http.StatusOK {
		t.Fatal("a push committed on an unsure clock")
	}
	if !fixture.head().Absent() {
		t.Fatal("an unsure clock wrote a head")
	}
	if keys, _, err := fixture.cluster.List(fixture.ctx, batchKeyPrefix, "", 10); err != nil || len(keys) != 0 {
		t.Fatalf("batches on an unsure clock: %v, %v", keys, err)
	}
	fixture.host.ClockCheck.SetOffset(0)
	fixture.requireCommitted(fixture.post(token, body), 1)
}
