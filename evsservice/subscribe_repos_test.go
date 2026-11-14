// The per-client repo cap's tests (plan-EVS1-subscription-caps#2, QD-263, QD-749): {evsc_<client_id>}'s script ahead
// of the lease script on POST /evs/v1/subscriptions, on sidecartest's twin. The real Source runs on the private Redis
// in server's evshost tests.

package evsservice

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Another placed, active repo of the fixture's network on meta-1, which the fixture's two sidecars may read.
func (self *pushFixture) addRepo(name string) sidecar.Id {
	self.t.Helper()
	repoId := testIdFrom(name)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.check.signerId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: 1, NetworkId: self.check.networkId.Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, RepoKey(repoId), repoBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	self.auth.grant(self.check.signerId, repoId, sidecar.AclEvsRead)
	self.auth.grant(self.check.otherId, repoId, sidecar.AclEvsRead)
	return repoId
}

// One POST|DELETE /evs/v1/subscriptions on repoId by clientId's sidecar, for every ref in epoch 1 under prefixes.
func (self *pushFixture) subscribeRepo(method string, clientId sidecar.Id, sidecarId sidecar.Id, repoId sidecar.Id, prefixes ...sidecar.EvsTokenPath) *httptest.ResponseRecorder {
	self.t.Helper()
	body := &protocol.EvsSubscriptionRequest{RepoId: repoId.Bytes(), PathEpoch: 1}
	for _, prefix := range prefixes {
		body.Prefixes = append(body.Prefixes, prefix.Proto())
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	connectSidecarId := connect.Id(sidecarId)
	token := self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.check.networkId), ClientId: connect.Id(clientId), SidecarId: &connectSidecarId,
		Audience: EvsAudience, Scopes: []string{repoScope(repoId, "r")},
		IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
	request := httptest.NewRequestWithContext(self.ctx, method, "/evs/v1/subscriptions", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// Asserts the per-client cap's refusal: 403 QUOTA_LIMIT naming evs_repos_per_client and its limit.
func requireReposPerClientRefusal(t *testing.T, recorder *httptest.ResponseRecorder, limit int64) {
	t.Helper()
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	quota := refusalOf(t, recorder).GetQuota()
	if quota.GetLimitKey() != evsReposPerClientLimitKey || quota.GetLimit() != limit {
		t.Fatalf("the refusal names %q at %d, not %s at %d", quota.GetLimitKey(), quota.GetLimit(), evsReposPerClientLimitKey, limit)
	}
}

// §20.4's evs_repos_per_client at its 500: a client's 500th repo is leased and its 501st refused with the key named
// and no lease written, while every repo it holds still renews; once it unsubscribes from one, another is taken, and
// the one after that refused again.
func TestSubscriptionsCapReposPerClientAtFiveHundred(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscriptions(1000, 500)
	clientId, sidecarId := fixture.check.clientId, fixture.check.signerId
	repoIds := []sidecar.Id{}
	for i := 0; i < 502; i += 1 {
		repoIds = append(repoIds, fixture.addRepo(fmt.Sprintf("client cap repo %d", i)))
	}
	for i := 0; i < 500; i += 1 {
		if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[i]); recorder.Code != http.StatusOK {
			t.Fatalf("repo %d of 500 answered %d", i+1, recorder.Code)
		}
	}
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[500]), 500)
	if leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, repoIds[500]); err != nil || len(leases) != 0 {
		t.Fatalf("the refused repo holds leases %v %v", leases, err)
	}
	// every held repo renews at the cap, and the renewals leave the count at 500
	for i := 0; i < 500; i += 1 {
		if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[i], checkTestPath("renewed")); recorder.Code != http.StatusOK {
			t.Fatalf("the renewal of repo %d answered %d", i+1, recorder.Code)
		}
	}
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[500]), 500)
	// another client of the network is counted on its own
	if recorder := fixture.subscribeRepo(http.MethodPost, testIdFrom("another client"), fixture.check.otherId, repoIds[500]); recorder.Code != http.StatusOK {
		t.Fatalf("another client's first repo answered %d", recorder.Code)
	}
	// one repo given up makes room for one
	if recorder := fixture.subscribeRepo(http.MethodDelete, clientId, sidecarId, repoIds[7]); recorder.Code != http.StatusOK {
		t.Fatalf("the unsubscribe answered %d", recorder.Code)
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[500]); recorder.Code != http.StatusOK {
		t.Fatalf("the repo after an unsubscribe answered %d", recorder.Code)
	}
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, repoIds[501]), 500)
}

// A renewal counts nothing twice: a repo leased again and again, under other prefixes and by another sidecar of the
// same client, is one repo of the client's two.
func TestSubscriptionRenewalCountsARepoOnce(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscriptions(1000, 2)
	clientId := fixture.check.clientId
	first, second, third := fixture.addRepo("renewal first"), fixture.addRepo("renewal second"), fixture.addRepo("renewal third")
	for i := 0; i < 5; i += 1 {
		fixture.clock.Advance(25 * time.Hour)
		if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, first, checkTestPath(fmt.Sprintf("p%d", i))); recorder.Code != http.StatusOK {
			t.Fatalf("renewal %d answered %d", i, recorder.Code)
		}
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.otherId, first); recorder.Code != http.StatusOK {
		t.Fatalf("the client's other sidecar answered %d", recorder.Code)
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, second); recorder.Code != http.StatusOK {
		t.Fatalf("the second repo answered %d", recorder.Code)
	}
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, third), 2)
}

// A repo the client stops renewing leaves its count when its leases lapse, a lease's life after the last subscribe
// or renewal and not a moment sooner; a renewal in between moves that time.
func TestSubscriptionRepoLapsesFromTheClientsCount(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscriptions(1000, 1)
	clientId, sidecarId := fixture.check.clientId, fixture.check.signerId
	first, second := fixture.addRepo("lapse first"), fixture.addRepo("lapse second")
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, first); recorder.Code != http.StatusOK {
		t.Fatalf("the first repo answered %d", recorder.Code)
	}
	// renewed a day on, so its life runs from there
	fixture.clock.Advance(24 * time.Hour)
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, first); recorder.Code != http.StatusOK {
		t.Fatalf("the renewal answered %d", recorder.Code)
	}
	fixture.clock.Advance(fixture.settings.LeaseLife - time.Millisecond)
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, second), 1)
	fixture.clock.Advance(time.Millisecond)
	// the lease has lapsed at this instant, and so has its repo's place in the count
	leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, first)
	if err != nil || len(leases) != 1 || fixture.clock.Now().Before(leases[0].ExpiresAt) {
		t.Fatalf("the first repo's lease has not lapsed: %v %v", leases, err)
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, second); recorder.Code != http.StatusOK {
		t.Fatalf("the second repo answered %d once the first lapsed", recorder.Code)
	}
	// the first is a new repo again, and the count is full
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, sidecarId, first), 1)
}

// DELETE takes a repo out of the client's count with the client's last lease on it, not before: a lease under
// another prefix, or another sidecar's of the same client, keeps it counted.
func TestUnsubscribeUncountsARepoAtItsLastLease(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.allowSubscriptions(1000, 1)
	clientId := fixture.check.clientId
	first, second := fixture.addRepo("unsubscribe first"), fixture.addRepo("unsubscribe second")
	a, b := checkTestPath("a"), checkTestPath("b")
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, first, a, b); recorder.Code != http.StatusOK {
		t.Fatalf("the lease answered %d", recorder.Code)
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.otherId, first, a); recorder.Code != http.StatusOK {
		t.Fatalf("the other sidecar's lease answered %d", recorder.Code)
	}
	steps := []struct {
		sidecarId sidecar.Id
		prefixes  []sidecar.EvsTokenPath
	}{
		{sidecarId: fixture.check.signerId, prefixes: []sidecar.EvsTokenPath{a}},
		{sidecarId: fixture.check.signerId, prefixes: []sidecar.EvsTokenPath{b}},
	}
	for i, step := range steps {
		if recorder := fixture.subscribeRepo(http.MethodDelete, clientId, step.sidecarId, first, step.prefixes...); recorder.Code != http.StatusOK {
			t.Fatalf("delete %d answered %d", i, recorder.Code)
		}
		requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, second), 1)
	}
	// the other sidecar's whole-ref DELETE removes the client's last lease there
	if recorder := fixture.subscribeRepo(http.MethodDelete, clientId, fixture.check.otherId, first); recorder.Code != http.StatusOK {
		t.Fatalf("the last delete answered %d", recorder.Code)
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, second); recorder.Code != http.StatusOK {
		t.Fatalf("the second repo answered %d once the first was given up", recorder.Code)
	}
	// a DELETE of leases the client does not hold changes nothing of another repo's count
	if recorder := fixture.subscribeRepo(http.MethodDelete, clientId, fixture.check.signerId, first); recorder.Code != http.StatusOK {
		t.Fatalf("a repeated delete answered %d", recorder.Code)
	}
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, clientId, fixture.check.signerId, first), 1)
}

// The two caps together: the per-repo cap still refuses a new holder with its own key, and the repo that refusal
// counted against the client a moment before is taken out again, so the client's one repo is still free; with no
// evs_repos_per_client configured every new repo is refused (§20.5's 0), and a negative limit is none.
func TestSubscriptionCapsRefuseApart(t *testing.T) {
	fixture := newPushFixture(t, nil)
	full, free := fixture.addRepo("caps full"), fixture.addRepo("caps free")
	holder, late := fixture.check.clientId, testIdFrom("late client")
	// no evs_repos_per_client: 0
	fixture.host.Quota.SetLimits(connect.Id(fixture.check.networkId), &sidecar.QuotaLimits{
		Tier: "pro", Limits: map[string]int64{evsSubscribersPerRepoLimitKey: 1},
	})
	requireReposPerClientRefusal(t, fixture.subscribeRepo(http.MethodPost, holder, fixture.check.signerId, full), 0)
	if leases, err := ReadLeases(fixture.ctx, fixture.host.Redis, full); err != nil || len(leases) != 0 {
		t.Fatalf("a refused repo holds leases %v %v", leases, err)
	}
	fixture.allowSubscriptions(1, 1)
	if recorder := fixture.subscribeRepo(http.MethodPost, holder, fixture.check.signerId, full); recorder.Code != http.StatusOK {
		t.Fatalf("the repo's one holder answered %d", recorder.Code)
	}
	refused := fixture.subscribeRepo(http.MethodPost, late, fixture.check.otherId, full)
	requireRefusal(t, refused, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT)
	if quota := refusalOf(t, refused).GetQuota(); quota.GetLimitKey() != evsSubscribersPerRepoLimitKey || quota.GetLimit() != 1 {
		t.Fatalf("the per-repo cap's refusal names %q at %d", quota.GetLimitKey(), quota.GetLimit())
	}
	if recorder := fixture.subscribeRepo(http.MethodPost, late, fixture.check.otherId, free); recorder.Code != http.StatusOK {
		t.Fatalf("the late client's one repo answered %d after a refusal counted another", recorder.Code)
	}
	// no limit at all
	fixture.allowSubscriptions(1000, -1)
	for i := 0; i < 3; i += 1 {
		repoId := fixture.addRepo(fmt.Sprintf("caps unlimited %d", i))
		if recorder := fixture.subscribeRepo(http.MethodPost, late, fixture.check.otherId, repoId); recorder.Code != http.StatusOK {
			t.Fatalf("repo %d under no limit answered %d", i, recorder.Code)
		}
	}
}

// The count's script on its own, as the twin runs it: its three replies, the boundary of a lapsed score, and the
// key's ttl set by every write and by no refusal.
func TestClientRepoPutScriptReplies(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	key := ClientRepoKey(testIdFrom("script client"))
	life, ttl := 7*24*time.Hour, 8*24*time.Hour
	put := func(now time.Time, repo string, limit int64) int64 {
		t.Helper()
		reply, err := host.Redis.RunScript(ctx, ClientRepoPutScript, []string{key}, []string{
			strconv.FormatInt(now.UnixMilli(), 10), repo, strconv.FormatInt(limit, 10),
			strconv.FormatInt(now.Add(-life).UnixMilli(), 10), strconv.FormatInt(ttl.Milliseconds(), 10),
		})
		if err != nil {
			t.Fatal(err)
		}
		return reply.Integer
	}
	start := clock.Now()
	if got := put(start, "a", 2); got != evsClientRepoAdded {
		t.Fatalf("a new repo answered %d", got)
	}
	if got := put(start.Add(time.Hour), "a", 2); got != evsClientRepoRenewed {
		t.Fatalf("a renewal answered %d", got)
	}
	if got := put(start.Add(2*time.Hour), "b", 2); got != evsClientRepoAdded {
		t.Fatalf("a second repo answered %d", got)
	}
	if got := put(start.Add(3*time.Hour), "c", 2); got != evsClientRepoRefused {
		t.Fatalf("a third repo of two answered %d", got)
	}
	// a's score is start + 1 h: live a millisecond before its life is up, lapsed at it
	if got := put(start.Add(time.Hour+life-time.Millisecond), "c", 2); got != evsClientRepoRefused {
		t.Fatalf("a repo was taken before the oldest lapsed: %d", got)
	}
	if got := put(start.Add(time.Hour+life), "c", 2); got != evsClientRepoAdded {
		t.Fatalf("a repo was refused once the oldest lapsed: %d", got)
	}
	removed, err := host.Redis.RunScript(ctx, ClientRepoRemoveScript, []string{key}, []string{"b"})
	if err != nil || removed.Integer != 1 {
		t.Fatalf("removing a member answered %v %v", removed, err)
	}
	if removed, err := host.Redis.RunScript(ctx, ClientRepoRemoveScript, []string{key}, []string{"b"}); err != nil || removed.Integer != 0 {
		t.Fatalf("removing it again answered %v %v", removed, err)
	}
	if got := put(start.Add(time.Hour+life), "d", 2); got != evsClientRepoAdded {
		t.Fatalf("the freed place answered %d", got)
	}
}

// {evsc_<client_id>} is evs-8's (§2.8, I-18; QD-749): the list's row names the family the key is of, a client's key
// is its own hash tag, and it shares none with a repo's leases, which is why the count and the lease are two scripts.
func TestClientRepoKeyIsEvsEightsFamily(t *testing.T) {
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	rows := list.RowsNaming(sidecartest.MetadataFamily{Kind: sidecartest.MetadataFamilyRedis, Name: "{evsc_}"})
	if len(rows) != 1 || rows[0].Id != "evs-8" {
		t.Fatalf("{evsc_} is named by %d rows, not evs-8 alone", len(rows))
	}
	clientId, repoId := testIdFrom("family client"), testIdFrom("family repo")
	if got, want := ClientRepoKey(clientId), "{evsc_"+sidecar.EvsKeyId(clientId)+"}"; got != want {
		t.Fatalf("the key is %q, not %q", got, want)
	}
	if sidecar.RedisKeysShareTag([]string{ClientRepoKey(clientId), ClientRepoKey(testIdFrom("another family client"))}) {
		t.Fatal("two clients' counts share a tag")
	}
	if sidecar.RedisKeysShareTag([]string{ClientRepoKey(clientId), LeaseKey(repoId)}) {
		t.Fatal("a client's count and a repo's leases share a tag")
	}
}
