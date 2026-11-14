// EVS1-M2-15's tests: the push sequence's script and FS-62's exact vectors, the subscription routes and their cap,
// step 8's matching over a token tree with a holder the projection drops, the coalescing of hints to 10 a second a
// repo, the sweep, and §22.4's CROSSSLOT lint over every evs script.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/crossslot"
)

// FS-62's vectors: TIME 1793836800 s and 123456 µs seeds 1793836800123456000, and the next 1,024 raises end at
// 1793836800123457024, every value exact past what a double holds.
func TestPushSequenceVectors(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(time.Unix(1793836800, 123456*1000))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	repoId := testId("sequence repo")
	var last uint64
	for i := 1; i <= 1024; i += 1 {
		sequence, err := RaisePushSequence(ctx, host.Redis, repoId)
		if err != nil {
			t.Fatal(err)
		}
		if want := uint64(1793836800123456000) + uint64(i); sequence != want {
			t.Fatalf("raise %d: %d, want %d", i, sequence, want)
		}
		last = sequence
	}
	if last != 1793836800123457024 {
		t.Fatalf("the 1,024th raise ends at %d", last)
	}
	if read, err := ReadPushSequence(ctx, host.Redis, repoId); err != nil || read != last {
		t.Fatalf("read %d %v", read, err)
	}
	// another repo's sequence is its own
	other, err := RaisePushSequence(ctx, host.Redis, testId("other repo"))
	if err != nil || other != 1793836800123456001 {
		t.Fatalf("another repo's first raise %d %v", other, err)
	}
}

// The twin that answers INCR's number, as a script returning a Lua double would: RaisePushSequence refuses it at the
// first raise, never parsing a number it cannot trust.
func TestPushSequenceRefusesAnIntegerReply(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(time.Unix(1793836800, 123456*1000))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	host.Redis.RegisterScript(PushSequenceRaiseScript.Name, func(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		value, err := call.Increment(call.Keys[0], 0)
		if err != nil {
			return nil, err
		}
		return sidecartest.RedisIntegerReply(value), nil
	})
	if _, err := RaisePushSequence(ctx, host.Redis, testId("sequence repo")); err == nil {
		t.Fatal("an integer reply was taken as the sequence")
	}
}

// One POST|DELETE /evs/v1/subscriptions, or a GET for repoId.
func (self *pushFixture) subscribe(method string, sidecarId sidecar.Id, body *protocol.EvsSubscriptionRequest) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(self.ctx, method, "/evs/v1/subscriptions", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+self.token(sidecarId))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// The caller's leases on the fixture's repo, as GET lists them.
func (self *pushFixture) subscriptions(sidecarId sidecar.Id) []*protocol.EvsSubscription {
	self.t.Helper()
	request := httptest.NewRequestWithContext(self.ctx, http.MethodGet, "/evs/v1/subscriptions?repo_id="+sidecar.EvsKeyId(self.check.repoId), nil)
	request.Header.Set("Authorization", "Bearer "+self.token(sidecarId))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("GET answered %d", recorder.Code)
	}
	reply := &protocol.EvsSubscriptionsReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		self.t.Fatal(err)
	}
	return reply.GetSubscriptions()
}

// The fixture's network allowing limit subscribers a repo, and a client §20.4's 500 repos.
func (self *pushFixture) allowSubscribers(limit int64) {
	self.allowSubscriptions(limit, 500)
}

// The fixture's network allowing subscribers a repo and repos a client.
func (self *pushFixture) allowSubscriptions(subscribersPerRepo int64, reposPerClient int64) {
	self.host.Quota.SetLimits(connect.Id(self.check.networkId), &sidecar.QuotaLimits{
		Tier: "pro", Limits: map[string]int64{evsSubscribersPerRepoLimitKey: subscribersPerRepo, evsReposPerClientLimitKey: reposPerClient},
	})
}

// A lease request on the fixture's ref in epoch 1 for prefixes.
func (self *pushFixture) leaseRequest(prefixes ...sidecar.EvsTokenPath) *protocol.EvsSubscriptionRequest {
	request := &protocol.EvsSubscriptionRequest{RepoId: self.check.repoId.Bytes(), RefId: self.check.refId.Bytes(), PathEpoch: 1}
	for _, prefix := range prefixes {
		request.Prefixes = append(request.Prefixes, prefix.Proto())
	}
	return request
}

// The hints a client got on the fixture's repo's topic, once every step 8 has finished.
func (self *pushFixture) hints(clientId sidecar.Id) []*sidecar.ClientHint {
	self.awaitStepEights()
	topic := sidecar.PushTopicEvs(self.check.repoId)
	hints := []*sidecar.ClientHint{}
	for _, hint := range self.host.Push.Hints(connect.Id(clientId)) {
		if hint.Topic == topic {
			hints = append(hints, hint)
		}
	}
	return hints
}

// §11.10's match on a token tree: a lease on a prefix gets the hint of a commit below it or above it, not one on
// another branch; a whole-ref lease every one; the hint's version is the push sequence and its delta the commit's
// EvsHeadChanged.
func TestSubscriptionsMatchPrefixesOnATokenTree(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a"))); recorder.Code != http.StatusOK {
		t.Fatalf("lease answered %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	below := fixture.plan()
	fixture.create(below, "a", "b")
	fixture.requireCommitted(fixture.push(below), 1)
	hints := fixture.hints(fixture.check.clientId)
	if len(hints) != 1 || hints[0].Kind != uint32(protocol.MessageType_EVS_HEAD_CHANGED) {
		t.Fatalf("hints %v", hints)
	}
	delta := &protocol.EvsHeadChanged{}
	if err := proto.Unmarshal(hints[0].Body, delta); err != nil || delta.GetVersion() != 1 || sidecar.Id(delta.GetPushId()) != below.PushId ||
		sidecar.Id(delta.GetRefId()) != fixture.check.refId {
		t.Fatalf("delta %v %v", delta, err)
	}
	sequence, err := ReadPushSequence(fixture.ctx, fixture.host.Redis, fixture.check.repoId)
	if err != nil || hints[0].Version != sequence {
		t.Fatalf("hint version %d, sequence %d %v", hints[0].Version, sequence, err)
	}

	// another branch: no hint, past the coalescing interval
	fixture.clock.Advance(time.Second)
	elsewhere := fixture.plan()
	fixture.create(elsewhere, "c")
	fixture.requireCommitted(fixture.push(elsewhere), 2)
	if hints := fixture.hints(fixture.check.clientId); len(hints) != 1 {
		t.Fatalf("a commit on another branch hinted: %d hints", len(hints))
	}
	// a whole-ref lease takes it
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest()); recorder.Code != http.StatusOK {
		t.Fatalf("whole-ref lease answered %d", recorder.Code)
	}
	fixture.clock.Advance(time.Second)
	again := fixture.plan()
	fixture.create(again, "d")
	fixture.requireCommitted(fixture.push(again), 3)
	if hints := fixture.hints(fixture.check.clientId); len(hints) != 2 {
		t.Fatalf("a whole-ref lease got %d hints", len(hints))
	}
	if subscriptions := fixture.subscriptions(fixture.check.signerId); len(subscriptions) != 2 {
		t.Fatalf("GET lists %d leases", len(subscriptions))
	}
}

// A holder the newest projection no longer lists as a reader gets no hint (§11.10's match row).
func TestSubscriptionsSkipAHolderTheProjectionDrops(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest()); recorder.Code != http.StatusOK {
		t.Fatalf("lease answered %d", recorder.Code)
	}
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	if hints := fixture.hints(fixture.check.clientId); len(hints) != 1 {
		t.Fatalf("%d hints before the drop", len(hints))
	}
	// the projection's newest state reads the repo with no readers
	view := fixture.check.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: fixture.check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}),
		IdentityKeys: map[sidecar.Id][]byte{fixture.check.signerId: fixture.check.signingKey.Public().(ed25519.PublicKey)},
	})
	notifier := NewEvsHintNotifier(fixture.ctx, fixture.clock, fixture.host.Redis, fixture.host.Push, &fixedGateViews{networkId: fixture.check.networkId, view: view}, sidecar.NewNoopLogger())
	leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, fixture.check.repoId)
	if err != nil {
		t.Fatal(err)
	}
	committed := &EvsCommitted{RepoId: fixture.check.repoId, RefId: fixture.check.refId, RepoNetworkId: fixture.check.networkId, Head: fixture.head()}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	committed.Statement = built.Statement
	if clients := notifier.match(committed, leases); len(clients) != 0 {
		t.Fatalf("a dropped holder matched: %v", clients)
	}
}

// Gate views of one fixed state.
type fixedGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *fixedGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, EvsAuthUnknown
	}
	return self.view, EvsAuthAllowed
}

// The per-repo cap: a new holder past evs_subscribers_per_repo is refused with the key named, while a holder
// already there renews; with no per-repo limit configured every new holder is refused (§20.5's 0). The client's
// repo count, checked first, is within its own cap throughout and changes none of it.
func TestSubscriptionsCapHoldersPerRepo(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.host.Quota.SetLimits(connect.Id(fixture.check.networkId), &sidecar.QuotaLimits{
		Tier: "pro", Limits: map[string]int64{evsReposPerClientLimitKey: 500},
	})
	refused := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest())
	requireRefusal(t, refused, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	if refusalOf(t, refused).GetQuota().GetLimitKey() != evsSubscribersPerRepoLimitKey {
		t.Fatal("the cap's refusal names another key")
	}
	fixture.allowSubscribers(1)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest()); recorder.Code != http.StatusOK {
		t.Fatalf("the first holder answered %d", recorder.Code)
	}
	requireRefusal(t, fixture.subscribe(http.MethodPost, fixture.check.otherId, fixture.leaseRequest()), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("x"))); recorder.Code != http.StatusOK {
		t.Fatalf("a holder's renewal answered %d", recorder.Code)
	}
	// more than 16 prefixes is refused
	tooMany := fixture.leaseRequest()
	for i := 0; i <= fixture.settings.LeaseMaxPrefixCount; i += 1 {
		tooMany.Prefixes = append(tooMany.Prefixes, checkTestPath(fmt.Sprintf("p%d", i)).Proto())
	}
	requireRefusal(t, fixture.subscribe(http.MethodPost, fixture.check.signerId, tooMany), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

// DELETE removes the caller's leases, by prefix or all on a ref; a lease past 7 d is not listed and the sweep drops
// it.
func TestSubscriptionsDeleteAndSweep(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a"), checkTestPath("b")))
	if got := len(fixture.subscriptions(fixture.check.signerId)); got != 2 {
		t.Fatalf("%d leases", got)
	}
	fixture.subscribe(http.MethodDelete, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a")))
	if got := len(fixture.subscriptions(fixture.check.signerId)); got != 1 {
		t.Fatalf("%d leases after deleting one", got)
	}
	fixture.subscribe(http.MethodDelete, fixture.check.signerId, fixture.leaseRequest())
	if got := len(fixture.subscriptions(fixture.check.signerId)); got != 0 {
		t.Fatalf("%d leases after deleting the ref's", got)
	}
	fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("c")))
	fixture.clock.Advance(fixture.settings.LeaseLife + time.Second)
	if got := len(fixture.subscriptions(fixture.check.signerId)); got != 0 {
		t.Fatalf("an expired lease listed: %d", got)
	}
	removed, err := SweepLeases(fixture.ctx, fixture.host.Redis, fixture.check.repoId, fixture.clock.Now())
	if err != nil || removed != 1 {
		t.Fatalf("swept %d %v", removed, err)
	}
}

// §11.12's refused row on the subscription routes (QD-665): with repo/ deleted, POST, GET and DELETE answer 409
// REPO_DELETED, and with it shredding or shredded 409 SHREDDING, changing no lease; keying and active are served;
// a repo never placed answers 404.
func TestSubscriptionsRefuseADeletedOrShreddingRepo(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a"))); recorder.Code != http.StatusOK {
		t.Fatalf("lease answered %d", recorder.Code)
	}
	list := func(repoId sidecar.Id, token string) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(fixture.ctx, http.MethodGet, "/evs/v1/subscriptions?repo_id="+sidecar.EvsKeyId(repoId), nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		fixture.engine.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	states := []struct {
		state protocol.EvsRepoState
		code  protocol.EvsRefusalCode
	}{
		{state: protocol.EvsRepoState_EVS_REPO_DELETED, code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDING, code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDED, code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING},
	}
	for _, c := range states {
		fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, c.state)
		requireRefusal(t, fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("b"))), http.StatusConflict, c.code)
		requireRefusal(t, list(fixture.check.repoId, fixture.token(fixture.check.signerId)), http.StatusConflict, c.code)
		requireRefusal(t, fixture.subscribe(http.MethodDelete, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a"))), http.StatusConflict, c.code)
	}
	if leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, fixture.check.repoId); err != nil || len(leases) != 1 {
		t.Fatalf("the refusals left leases %v %v", leases, err)
	}
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_KEYING)
	if recorder := fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("b"))); recorder.Code != http.StatusOK {
		t.Fatalf("a keying repo's lease answered %d", recorder.Code)
	}
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	if got := len(fixture.subscriptions(fixture.check.signerId)); got != 2 {
		t.Fatalf("%d leases listed once active", got)
	}

	// a repo the token may read that was never placed
	unplaced := testId("subscribe never placed")
	fixture.auth.grant(fixture.check.signerId, unplaced, sidecar.AclEvsRead)
	connectSidecarId := connect.Id(fixture.check.signerId)
	token := fixture.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(fixture.check.networkId), ClientId: connect.Id(fixture.check.clientId), SidecarId: &connectSidecarId,
		Audience: EvsAudience, Scopes: []string{repoScope(unplaced, "r")},
		IssuedAt: fixture.clock.Now(), ExpiresAt: fixture.clock.Now().Add(15 * time.Minute),
	})
	requireRefusal(t, list(unplaced, token), http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

// §11.10's hint row: hints coalesce to 10 a second a repo; a commit inside the interval waits for its end and goes
// with the newest commit's delta.
func TestHintsCoalesceToTenASecondARepo(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest())
	first := fixture.plan()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.push(first), 1)
	second := fixture.plan()
	fixture.create(second, "b")
	fixture.requireCommitted(fixture.push(second), 2)
	third := fixture.plan()
	fixture.create(third, "c")
	fixture.requireCommitted(fixture.push(third), 3)
	if hints := fixture.hints(fixture.check.clientId); len(hints) != 1 {
		t.Fatalf("%d hints inside one interval", len(hints))
	}
	sent, changed := fixture.engine.notifier.(*EvsHintNotifier).Sent()
	fixture.clock.Advance(evsHintPerRepoInterval)
	if sent < 2 {
		<-changed
	}
	hints := fixture.hints(fixture.check.clientId)
	if len(hints) != 2 {
		t.Fatalf("%d hints after the interval", len(hints))
	}
	delta := &protocol.EvsHeadChanged{}
	if err := proto.Unmarshal(hints[1].Body, delta); err != nil || delta.GetVersion() != 3 {
		t.Fatalf("the coalesced hint carries version %d %v", delta.GetVersion(), err)
	}
}

// §22.4's CROSSSLOT lint over evsservice's Redis calls and scripts: each names keys under one hash tag, and the
// families of one repo share it.
func TestEvsRedisCallsPassTheCrossslotLint(t *testing.T) {
	findings, err := crossslot.Check(".", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("CROSSSLOT: %s", finding)
	}
	repoId := testId("lint repo")
	if !sidecar.RedisKeysShareTag([]string{LeaseKey(repoId), LeaseVersionKey(repoId)}) {
		t.Fatal("a repo's leases and their version do not share a tag")
	}
	if !strings.HasPrefix(PushSequenceKey(repoId), "{evsq_") || sidecar.RedisKeysShareTag([]string{LeaseKey(repoId), LeaseKey(testId("other repo"))}) {
		t.Fatal("a family's keys are not one tag a repo")
	}
}

// The daily sweep over every repo the metadata clusters list: each one's lapsed leases go, live ones stay.
func TestSweepAllLeases(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscribers(1000)
	fixture.subscribe(http.MethodPost, fixture.check.signerId, fixture.leaseRequest(checkTestPath("a")))
	fixture.clock.Advance(fixture.settings.LeaseLife - time.Hour)
	fixture.subscribe(http.MethodPost, fixture.check.otherId, fixture.leaseRequest(checkTestPath("b")))
	fixture.clock.Advance(2 * time.Hour)
	removed, err := SweepAllLeases(fixture.ctx, fixture.host.ServiceHost(), fixture.clock.Now())
	if err != nil || removed != 1 {
		t.Fatalf("swept %d %v", removed, err)
	}
	leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, fixture.check.repoId)
	if err != nil || len(leases) != 1 || leases[0].SidecarId != fixture.check.otherId {
		t.Fatalf("leases after the sweep %v %v", leases, err)
	}
}
