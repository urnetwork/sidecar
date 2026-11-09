package evsservice

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo the projection holds, admin granted to creator.
func (self *evsFixture) projectRepo(repoId sidecar.Id, creatorSidecarIds ...sidecar.Id) {
	self.auth.setRepo(repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: sidecar.Id(self.networkId)})
	for _, creatorSidecarId := range creatorSidecarIds {
		self.auth.grant(creatorSidecarId, repoId, sidecar.AclEvsAdmin)
	}
}

// PUT /evs/v1/repos/<id> by sidecarId.
func (self *evsFixture) putRepo(repoId sidecar.Id, sidecarId sidecar.Id) int {
	return self.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), self.token(sidecarId, repoScope(repoId, "admin")), nil).Code
}

// What a cluster holds at key, nil for nothing.
func (self *evsFixture) object(clusterId string, key string) []byte {
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := cluster.Get(self.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	return body
}

// The placement place/ holds for repoId.
func (self *evsFixture) placement(repoId sidecar.Id) *sidecar.EvsRepoPlace {
	placementBytes := self.object("meta-1", sidecar.EvsPlaceKey(repoId))
	if placementBytes == nil {
		return nil
	}
	place, err := sidecar.ParseEvsRepoPlace(placementBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	return place
}

// Every key a cluster holds under prefix.
func (self *evsFixture) keysUnder(clusterId string, prefix string) []string {
	keys := []string{}
	for key := range self.host.Blobs.Dump() {
		if strings.HasPrefix(key, clusterId+"/"+prefix) {
			keys = append(keys, strings.TrimPrefix(key, clusterId+"/"))
		}
	}
	return keys
}

func TestPlaceCreatesPlaceThenRepoOnTheNewRepoCluster(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatalf("create: %d", status)
	}
	place := fixture.placement(repoId)
	if place == nil || place.ClusterId != "meta-1" || place.CreatorSidecarId != creator {
		t.Fatalf("place/ %+v", place)
	}
	repoBytes := fixture.object("meta-1", RepoKey(repoId))
	object, err := ParseEvsRepoObject(repoId, repoBytes)
	if err != nil {
		t.Fatal(err)
	}
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING || object.GetFormat() != 1 ||
		object.GetKind() != protocol.RepoKind_REPO_KIND_GENERAL || sidecar.Id(object.GetNetworkId()) != sidecar.Id(fixture.networkId) {
		t.Errorf("repo/ %v", object)
	}
	// both writes passed the budget as P1 for the creating network
	if byteCount, _ := fixture.host.Budget.P1ByteCount("meta-1"); byteCount == 0 {
		t.Error("no P1 spent")
	}
}

// FS-63: two creators race at place/'s If-None-Match: one places the repo, the other gets 409.
func TestPlaceTwoCreatorsRaceAndOnePlaces(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creatorA := testId("sidecar-a")
	creatorB := testId("sidecar-b")
	fixture.projectRepo(repoId, creatorA, creatorB)
	// B's PUT is decided after A's: it finds A's placement on its 412
	if status := fixture.putRepo(repoId, creatorA); status != http.StatusOK {
		t.Fatalf("A: %d", status)
	}
	if status := fixture.putRepo(repoId, creatorB); status != http.StatusConflict {
		t.Errorf("B: %d, want 409", status)
	}
	if place := fixture.placement(repoId); place.CreatorSidecarId != creatorA {
		t.Errorf("placed by %v", place.CreatorSidecarId)
	}
	// and the other order on another id: B's create landed first, so A gets 409, whatever place_new says
	otherRepoId := testId("repo-2")
	fixture.projectRepo(otherRepoId, creatorA, creatorB)
	if status := fixture.putRepo(otherRepoId, creatorB); status != http.StatusOK {
		t.Fatalf("B: %d", status)
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-2")
	if status := fixture.putRepo(otherRepoId, creatorA); status != http.StatusConflict {
		t.Errorf("A: %d", status)
	}
	if keys := fixture.keysUnder("meta-2", "repo/"); len(keys) != 0 {
		t.Errorf("a refused creator wrote %v", keys)
	}
}

// FS-63: the winner's retry after a lost response continues on the cluster place/ names, even once place_new names
// another.
func TestPlaceRetryAfterALostResponseContinuesOnItsCluster(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: RepoKey(repoId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	// place/ landed, repo/ did not: the store's outcome is unknown, and the read finds it never landed
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpGet, KeyPrefix: RepoKey(repoId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusServiceUnavailable {
		t.Fatalf("first create: %d", status)
	}
	if fixture.placement(repoId) == nil {
		t.Fatal("place/ was not written")
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-2")
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatalf("retry: %d", status)
	}
	if fixture.placement(repoId).ClusterId != "meta-1" {
		t.Error("the retry moved the repo")
	}
	if fixture.object("meta-1", RepoKey(repoId)) == nil || fixture.object("meta-2", RepoKey(repoId)) != nil {
		t.Error("repo/ is not where place/ names")
	}
}

// A lost response on place/ itself: the create reads place/ and continues.
func TestPlaceLostResponseOnPlaceItselfReadsItBack(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: sidecar.EvsPlaceKey(repoId), Result: sidecartest.ApplyThenDrop,
	}); err != nil {
		t.Fatal(err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatalf("create: %d", status)
	}
	if fixture.object("meta-1", RepoKey(repoId)) == nil {
		t.Error("no repo/")
	}
	// a create that never landed is sent once more
	otherRepoId := testId("repo-2")
	fixture.projectRepo(otherRepoId, creator)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: sidecar.EvsPlaceKey(otherRepoId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	if status := fixture.putRepo(otherRepoId, creator); status != http.StatusOK {
		t.Fatalf("create after a lost send: %d", status)
	}
}

// FS-63: with place_new naming a second metadata cluster, new repos land only there, and placed repos' objects never
// do.
func TestPlaceNewSecondClusterTakesOnlyNewRepos(t *testing.T) {
	fixture := newEvsFixture(t)
	oldRepoId := testId("repo-old")
	newRepoId := testId("repo-new")
	creator := testId("sidecar-a")
	fixture.projectRepo(oldRepoId, creator)
	fixture.projectRepo(newRepoId, creator)
	if status := fixture.putRepo(oldRepoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-2")
	if status := fixture.putRepo(newRepoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	if fixture.placement(newRepoId).ClusterId != "meta-2" || fixture.object("meta-2", RepoKey(newRepoId)) == nil {
		t.Error("the new repo is not on meta-2")
	}
	if fixture.object("meta-1", RepoKey(newRepoId)) != nil || fixture.object("meta-2", RepoKey(oldRepoId)) != nil {
		t.Error("a repo's objects on the other cluster")
	}
	// place/ is the first cluster's alone
	if keys := fixture.keysUnder("meta-2", sidecar.EvsPlaceKeyPrefix); len(keys) != 0 {
		t.Errorf("place/ on meta-2: %v", keys)
	}
	// a restarted resolver resolves each repo to the same cluster
	resolver := sidecar.NewEvsRepoPlaceResolver(fixture.host.Blobs, fixture.clock, nil)
	for repoId, clusterId := range map[sidecar.Id]string{oldRepoId: "meta-1", newRepoId: "meta-2"} {
		cluster, _, err := resolver.Cluster(fixture.ctx, repoId)
		if err != nil || cluster.ClusterId() != clusterId {
			t.Errorf("%v resolves to %v: %v", repoId, cluster, err)
		}
	}
}

// FS-63: place_new naming a cluster this process cannot reach makes creates 503, and no place/ names it.
func TestPlaceNewUnreachableAnswers503AndWritesNothing(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	fixture.host.Blobs.SetNewRepoClusterId("meta-9")
	recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(creator, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if fixture.placement(repoId) != nil {
		t.Error("place/ names an unreachable cluster")
	}
	// a repo placed before continues on its own cluster, and another creator still gets 409
	placedRepoId := testId("repo-placed")
	fixture.projectRepo(placedRepoId, creator, testId("sidecar-b"))
	fixture.host.Blobs.SetNewRepoClusterId("meta-1")
	if status := fixture.putRepo(placedRepoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-9")
	if status := fixture.putRepo(placedRepoId, creator); status != http.StatusOK {
		t.Errorf("its creator's retry with place_new unreachable: %d", status)
	}
	if status := fixture.putRepo(placedRepoId, testId("sidecar-b")); status != http.StatusConflict {
		t.Errorf("another creator with place_new unreachable: %d", status)
	}
}

// FS-63: a cached 404 clears within 5 s.
func TestPlaceCachedNotFoundClearsWithinFiveSeconds(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	// another process's resolver, which learns of the placement only by reading place/
	resolver := sidecar.NewEvsRepoPlaceResolver(fixture.host.Blobs, fixture.clock, nil)
	if _, err := resolver.Resolve(fixture.ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Fatalf("before the create: %v", err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	fixture.clock.Advance(4 * time.Second)
	if _, err := resolver.Resolve(fixture.ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("a 404 cached at 4 s: %v", err)
	}
	readsBefore, _ := resolver.Counts()
	fixture.clock.Advance(time.Second)
	place, err := resolver.Resolve(fixture.ctx, repoId)
	if err != nil || place.ClusterId != "meta-1" {
		t.Fatalf("at 5 s: %v %v", place, err)
	}
	// resolved once, then kept for the process's life
	fixture.clock.Advance(time.Hour)
	if _, err := resolver.Resolve(fixture.ctx, repoId); err != nil {
		t.Fatal(err)
	}
	if readsAfter, _ := resolver.Counts(); readsAfter != readsBefore+1 {
		t.Errorf("%d reads of place/ after it resolved", readsAfter-readsBefore)
	}
}

// A retried create by its creator answers 200 again and changes nothing.
func TestPlaceRetryByTheCreatorIsIdempotent(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	repoBytes := fixture.object("meta-1", RepoKey(repoId))
	fixture.clock.Advance(time.Minute)
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatalf("retry: %d", status)
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(repoBytes) {
		t.Error("a retry rewrote repo/")
	}
}

func TestPlaceRefusesARepoTheProjectionDoesNotHold(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.auth.grant(creator, repoId, sidecar.AclEvsAdmin)
	recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(creator, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
	// another network's repo
	fixture.auth.setRepo(repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: testId("network-b")})
	recorder = fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(creator, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if fixture.placement(repoId) != nil {
		t.Error("placed without its RepoCreate")
	}
}

func TestPlaceCreateTakesAdmin(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(creator, repoScope(repoId, "rw")), nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

func TestPlaceBudgetRefusalAnswers429AndWritesNothing(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	fixture.host.Budget.RefuseP1("meta-1", fixture.networkId, true)
	recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(creator, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	if refusalOf(t, recorder).GetRetryAfterMs() == 0 || recorder.Header().Get("Retry-After") == "" {
		t.Error("a 429 with no retry")
	}
	if fixture.placement(repoId) != nil {
		t.Error("placed past a refused budget")
	}
}

func TestPlaceUnparseablePlacementAlarmsAndRefuses(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	cluster, err := fixture.host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(sidecar.WithWriteClass(fixture.ctx, sidecar.WriteClassP1), sidecar.EvsPlaceKey(repoId), []byte("not a placement"), nil); err != nil {
		t.Fatal(err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusServiceUnavailable {
		t.Errorf("create over a broken place/: %d", status)
	}
	if fixture.host.Metrics.Value("urnetwork_evs_alarms_total", "place_invalid") != 1 {
		t.Error("no alarm")
	}
}

func TestParseEvsRepoPlaceHoldsItsShape(t *testing.T) {
	place := &sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: testId("sidecar-a")}
	placeBytes, err := place.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sidecar.ParseEvsRepoPlace(placeBytes)
	if err != nil || *parsed != *place {
		t.Errorf("round trip: %v %v", parsed, err)
	}
	for i, bad := range []*sidecar.EvsRepoPlace{
		{ClusterId: "", CreatorSidecarId: testId("sidecar-a")},
		{ClusterId: "meta-1"},
		{ClusterId: strings.Repeat("m", 300), CreatorSidecarId: testId("sidecar-a")},
	} {
		if _, err := bad.Marshal(); !errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid) {
			t.Errorf("%d: %v", i, err)
		}
	}
	for i, bad := range [][]byte{[]byte{0xff}, make([]byte, 300), []byte("\n\x06meta-1\x12\x03abc")} {
		if _, err := sidecar.ParseEvsRepoPlace(bad); !errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid) {
			t.Errorf("bytes %d: %v", i, err)
		}
	}
}

func TestRepoCacheKeepsAnAnswerAtMostItsTtl(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	cluster, err := fixture.host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	repos := NewRepoCache(fixture.clock, fixture.engine.Settings())
	if _, err := repos.Read(fixture.ctx, cluster, repoId); !errors.Is(err, ErrEvsRepoNotFound) {
		t.Fatalf("before: %v", err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	fixture.clock.Advance(4 * time.Second)
	if _, err := repos.Read(fixture.ctx, cluster, repoId); !errors.Is(err, ErrEvsRepoNotFound) {
		t.Errorf("a cached 404 at 4 s: %v", err)
	}
	fixture.clock.Advance(time.Second)
	read, err := repos.Read(fixture.ctx, cluster, repoId)
	if err != nil || !read.Format1() {
		t.Fatalf("at 5 s: %v %v", read, err)
	}
	if _, err := repos.Read(fixture.ctx, cluster, repoId); err != nil {
		t.Fatal(err)
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; got != 1 {
		t.Errorf("%d GETs for three reads", got)
	}
}
