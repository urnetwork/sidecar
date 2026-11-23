package evsservice

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
	object, err := sidecar.ParseEvsRepoObject(repoId, repoBytes)
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

// PUT /evs/v1/repos/<id> by sidecarId, its whole answer.
func (self *evsFixture) putRepoAnswer(repoId sidecar.Id, sidecarId sidecar.Id) *httptest.ResponseRecorder {
	return self.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), self.token(sidecarId, repoScope(repoId, "admin")), nil)
}

// FS-63: two creators race at place/'s If-None-Match: one places the repo, the other gets 409 REPO_PLACED (QD-927),
// final, its own code apart from STATEMENT_MISSING's, while the first creator's repeat answers 200 as before.
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
	repoBytes := fixture.object("meta-1", RepoKey(repoId))
	refused := fixture.putRepoAnswer(repoId, creatorB)
	requireRefusal(t, refused, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
	if reply := refusalOf(t, refused); reply.GetRecorded() || reply.GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_SETTLED {
		t.Errorf("REPO_PLACED answered %v", reply)
	}
	if entry := fixture.serviceLog.last(); entry.Status != http.StatusConflict || entry.Code != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED {
		t.Errorf("evs-7 logged %d %s", entry.Status, entry.Code)
	}
	if place := fixture.placement(repoId); place.CreatorSidecarId != creatorA {
		t.Errorf("placed by %v", place.CreatorSidecarId)
	}
	// the first creator's repeat answers as before, and B's refusal changed nothing
	if status := fixture.putRepo(repoId, creatorA); status != http.StatusOK {
		t.Errorf("A's repeat: %d", status)
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(repoBytes) {
		t.Error("repo/ was rewritten")
	}
	requireRefusal(t, fixture.putRepoAnswer(repoId, creatorB), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
	// and the other order on another id: B's create landed first, so A gets REPO_PLACED, whatever place_new says
	otherRepoId := testId("repo-2")
	fixture.projectRepo(otherRepoId, creatorA, creatorB)
	if status := fixture.putRepo(otherRepoId, creatorB); status != http.StatusOK {
		t.Fatalf("B: %d", status)
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-2")
	requireRefusal(t, fixture.putRepoAnswer(otherRepoId, creatorA), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
	if keys := fixture.keysUnder("meta-2", "repo/"); len(keys) != 0 {
		t.Errorf("a refused creator wrote %v", keys)
	}
	if status := fixture.putRepo(otherRepoId, creatorB); status != http.StatusOK {
		t.Errorf("B's repeat: %d", status)
	}
}

// A repo/ that stands as another repo than the creator's own create makes, its kind or network not the
// projection's, is a fault that alarms, and the creator's PUT answers 409 REPO_PLACED: the id is not one it can
// create, so it picks another, and nothing is written over what stands.
func TestPlaceRepoObjectOfAnotherRepoAnswersRepoPlaced(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	repoBytes := fixture.object("meta-1", RepoKey(repoId))
	fixture.auth.setRepo(repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_RECORD, NetworkId: sidecar.Id(fixture.networkId)})
	requireRefusal(t, fixture.putRepoAnswer(repoId, creator), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
	if fixture.host.Metrics.Value("urnetwork_evs_alarms_total", "repo_mismatch") != 1 {
		t.Error("no alarm")
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(repoBytes) {
		t.Error("repo/ was rewritten")
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

// EvsSettings.CreateWriteCount bounds the sends of one create, held positive: at 1, a create of place/ or of repo/
// whose send was lost and whose read finds nothing is not sent again and answers 503 unknown, where the default's
// second send lands (TestPlaceLostResponseOnPlaceItselfReadsItBack); the client's retry then lands it.
func TestPlaceCreateWriteCountBoundsTheSends(t *testing.T) {
	for _, createWriteCount := range []int{0, -1} {
		settings := DefaultEvsSettings()
		settings.CreateWriteCount = createWriteCount
		if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
			t.Errorf("a create sent %d times: %v", createWriteCount, err)
		}
	}
	fixture := newEvsFixtureWith(t, func(hostSettings *sidecartest.FakeHostSettings, settings *EvsSettings) {
		settings.CreateWriteCount = 1
	})
	creator := testId("sidecar-a")
	requireUnknown := func(label string, recorder *httptest.ResponseRecorder) {
		t.Helper()
		requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
		if outcome := refusalOf(t, recorder).GetOutcome(); outcome != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
			t.Errorf("%s: outcome %s", label, outcome)
		}
	}
	// place/'s one send is lost before it reaches the store
	placeRepoId := testId("repo-place")
	fixture.projectRepo(placeRepoId, creator)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: sidecar.EvsPlaceKey(placeRepoId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	requireUnknown("place/", fixture.putRepoAnswer(placeRepoId, creator))
	if fixture.placement(placeRepoId) != nil {
		t.Fatal("place/ was sent again")
	}
	if status := fixture.putRepo(placeRepoId, creator); status != http.StatusOK {
		t.Errorf("place/'s retry: %d", status)
	}
	// repo/'s one send is lost the same way, after place/ landed
	repoRepoId := testId("repo-object")
	fixture.projectRepo(repoRepoId, creator)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: RepoKey(repoRepoId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	requireUnknown("repo/", fixture.putRepoAnswer(repoRepoId, creator))
	if fixture.placement(repoRepoId) == nil || fixture.object("meta-1", RepoKey(repoRepoId)) != nil {
		t.Fatal("repo/ was sent again, or place/ never landed")
	}
	if status := fixture.putRepo(repoRepoId, creator); status != http.StatusOK || fixture.object("meta-1", RepoKey(repoRepoId)) == nil {
		t.Errorf("repo/'s retry: %d", status)
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
	// a repo placed before continues on its own cluster, and another creator still gets 409 REPO_PLACED
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
	requireRefusal(t, fixture.putRepoAnswer(placedRepoId, testId("sidecar-b")), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
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

// The network's config repo as the projection holds it from the Genesis (QD-719): kind config with no owner, its
// admin granted to each config writer (QD-894).
func (self *evsFixture) projectConfigRepo(repoId sidecar.Id, configWriterIds ...sidecar.Id) {
	self.auth.setRepo(repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_CONFIG, NetworkId: sidecar.Id(self.networkId)})
	for _, configWriterId := range configWriterIds {
		self.auth.grant(configWriterId, repoId, sidecar.AclEvsAdmin)
	}
}

// place/ for repoId on the first cluster with no repo/, as a restore that brought back place/ alone leaves it:
// naming clusterId and creatorSidecarId. Its bytes.
func (self *evsFixture) standPlacement(repoId sidecar.Id, clusterId string, creatorSidecarId sidecar.Id) []byte {
	self.t.Helper()
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: clusterId, CreatorSidecarId: creatorSidecarId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	cluster, err := self.host.Blobs.Cluster("meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(sidecar.WithWriteClass(self.ctx, sidecar.WriteClassP1), sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return placeBytes
}

// repo/ of a config repo as a create writes it: kind config, keying, format 1, the fixture's network and no owner.
func (self *evsFixture) requireConfigRepoObject(clusterId string, repoId sidecar.Id) []byte {
	self.t.Helper()
	repoBytes := self.object(clusterId, RepoKey(repoId))
	if repoBytes == nil {
		self.t.Fatalf("no repo/ on %s", clusterId)
	}
	object, err := sidecar.ParseEvsRepoObject(repoId, repoBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	if object.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING ||
		object.GetFormat() != sidecar.EvsRepoFormat1 || sidecar.Id(object.GetNetworkId()) != sidecar.Id(self.networkId) ||
		len(object.GetOwnerMemberId()) != 0 {
		self.t.Fatalf("repo/ %v", object)
	}
	return repoBytes
}

// QD-982, owner decision 567: the bootstrap sidecar's create of the config repo stops between place/ and repo/, and
// that sidecar is gone. Another config writer's PUT continues the placement: place/ keeps the cluster and creator it
// names, byte for byte, even once place_new names another cluster, and repo/ is written there. Its retry answers 200
// again and changes nothing, and the gone creator's admin is refused at the guard.
func TestPlaceConfigRepoStoppedBeforeRepoObjectIsContinuedByAnotherConfigWriter(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("config")
	bootstrap := testId("sidecar-a")
	configWriter := testId("sidecar-b")
	fixture.projectConfigRepo(repoId, bootstrap, configWriter)
	// place/ lands, repo/'s write is lost and its read-back fails: the create ends 503 with no repo/
	for _, plan := range []*sidecartest.FaultPlan{
		{Op: sidecartest.FaultOpPut, KeyPrefix: RepoKey(repoId), Result: sidecartest.FailBeforeApply},
		{Op: sidecartest.FaultOpGet, KeyPrefix: RepoKey(repoId), Result: sidecartest.FailBeforeApply},
	} {
		if _, err := fixture.host.Blobs.Faults().Add(plan); err != nil {
			t.Fatal(err)
		}
	}
	if status := fixture.putRepo(repoId, bootstrap); status != http.StatusServiceUnavailable {
		t.Fatalf("the bootstrap's create: %d", status)
	}
	placeBytes := fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))
	if place := fixture.placement(repoId); place == nil || place.ClusterId != "meta-1" || place.CreatorSidecarId != bootstrap {
		t.Fatalf("place/ %+v", place)
	}
	if fixture.object("meta-1", RepoKey(repoId)) != nil {
		t.Fatal("repo/ was written")
	}
	// the bootstrap sidecar is gone: the state no longer honors its admin
	fixture.auth.grantOnly(bootstrap, repoId, 0)
	requireRefusal(t, fixture.putRepoAnswer(repoId, bootstrap), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	fixture.host.Blobs.SetNewRepoClusterId("meta-2")
	if status := fixture.putRepo(repoId, configWriter); status != http.StatusOK {
		t.Fatalf("the config writer's create: %d", status)
	}
	if string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(placeBytes) {
		t.Error("place/ was rewritten")
	}
	repoBytes := fixture.requireConfigRepoObject("meta-1", repoId)
	if keys := fixture.keysUnder("meta-2", "repo/"); len(keys) != 0 {
		t.Errorf("repo/ on a cluster place/ does not name: %v", keys)
	}
	if entry := fixture.serviceLog.last(); entry.Status != http.StatusOK {
		t.Errorf("evs-7 logged %d", entry.Status)
	}
	fixture.clock.Advance(time.Minute)
	if status := fixture.putRepo(repoId, configWriter); status != http.StatusOK {
		t.Errorf("the config writer's retry: %d", status)
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(repoBytes) || string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(placeBytes) {
		t.Error("a retry rewrote place/ or repo/")
	}
}

// QD-982: a restore brought back the config repo's place/ alone, naming a creator that is no config writer now and a
// cluster place_new no longer names. A config writer's PUT writes repo/ on the cluster place/ names, and another
// config writer's, with place_new naming a cluster this process cannot reach, continues on it too and answers 200 on
// the repo/ that stands, place/ untouched throughout.
func TestPlaceConfigRepoWhosePlaceAloneWasRestoredIsPlacedByAConfigWriter(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("config")
	gone := testId("sidecar-gone")
	configWriterA := testId("sidecar-a")
	configWriterB := testId("sidecar-b")
	fixture.projectConfigRepo(repoId, configWriterA, configWriterB)
	placeBytes := fixture.standPlacement(repoId, "meta-2", gone)
	if status := fixture.putRepo(repoId, configWriterA); status != http.StatusOK {
		t.Fatalf("a config writer's create: %d", status)
	}
	repoBytes := fixture.requireConfigRepoObject("meta-2", repoId)
	if fixture.object("meta-1", RepoKey(repoId)) != nil {
		t.Error("repo/ on place_new's cluster, not place/'s")
	}
	fixture.host.Blobs.SetNewRepoClusterId("meta-9")
	if status := fixture.putRepo(repoId, configWriterB); status != http.StatusOK {
		t.Errorf("another config writer's create with place_new unreachable: %d", status)
	}
	if string(fixture.object("meta-2", RepoKey(repoId))) != string(repoBytes) {
		t.Error("repo/ was rewritten")
	}
	if string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(placeBytes) {
		t.Error("place/ was rewritten")
	}
}

// QD-982 holds for config writers alone: a sidecar whose config admin the state does not honor, with a token that
// claims it or one that holds only the config's r, is refused at the guard, 403 SCOPE, before place/ is read, and
// writes nothing; a config writer's create then continues the same placement.
func TestPlaceConfigRepoRefusesASidecarThatIsNotAConfigWriter(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("config")
	configWriter := testId("sidecar-a")
	member := testId("sidecar-m")
	fixture.projectConfigRepo(repoId, configWriter)
	// a member device reads the config and administers nothing of it
	fixture.auth.grant(member, repoId, sidecar.AclEvsRead)
	placeBytes := fixture.standPlacement(repoId, "meta-1", testId("sidecar-gone"))
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	for _, scope := range []string{"admin", "r"} {
		recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(member, repoScope(repoId, scope)), nil)
		requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	if gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; gets != 0 {
		t.Errorf("a refused create read the cluster %d times", gets)
	}
	if fixture.object("meta-1", RepoKey(repoId)) != nil || string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(placeBytes) {
		t.Fatal("a refused create wrote place/ or repo/")
	}
	if status := fixture.putRepo(repoId, configWriter); status != http.StatusOK {
		t.Fatalf("the config writer's create: %d", status)
	}
	fixture.requireConfigRepoObject("meta-1", repoId)
}

// QD-982 is the config kind's alone: for every other kind of §11.12's nine, a repo another creator placed answers an
// admin's create 409 REPO_PLACED and writes nothing (QD-927), whether its repo/ stands or place/ stands alone with its
// creator gone, since its client can pick another id.
func TestPlaceEveryOtherKindKeepsRepoPlacedForAnotherCreator(t *testing.T) {
	fixture := newEvsFixture(t)
	creator := testId("sidecar-a")
	other := testId("sidecar-b")
	gone := testId("sidecar-gone")
	kinds := []protocol.RepoKind{}
	for value := range protocol.RepoKind_name {
		if kind := protocol.RepoKind(value); sidecar.EvsRepoKindKnown(kind) && kind != protocol.RepoKind_REPO_KIND_CONFIG {
			kinds = append(kinds, kind)
		}
	}
	slices.Sort(kinds)
	if len(kinds) != 8 {
		t.Fatalf("%d kinds besides config, want §11.12's nine less one", len(kinds))
	}
	refusedPlaced := func(kind protocol.RepoKind, label string, repoId sidecar.Id) {
		t.Helper()
		recorder := fixture.putRepoAnswer(repoId, other)
		if recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED {
			t.Errorf("%s, %s: another admin's create answered %d %s", kind, label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	for _, kind := range kinds {
		facts := &EvsRepoFacts{Kind: kind, NetworkId: sidecar.Id(fixture.networkId)}
		if sidecar.EvsRepoKindOwnerBound(kind) {
			facts.OwnerMemberId = testId("owner-member")
		}
		// placed and created by its creator
		placedRepoId := testId(fmt.Sprintf("kind-%d-placed", kind))
		fixture.auth.setRepo(placedRepoId, facts)
		fixture.auth.grant(creator, placedRepoId, sidecar.AclEvsAdmin)
		fixture.auth.grant(other, placedRepoId, sidecar.AclEvsAdmin)
		if status := fixture.putRepo(placedRepoId, creator); status != http.StatusOK {
			t.Fatalf("%s: the creator's create: %d", kind, status)
		}
		placeBytes := fixture.object("meta-1", sidecar.EvsPlaceKey(placedRepoId))
		repoBytes := fixture.object("meta-1", RepoKey(placedRepoId))
		refusedPlaced(kind, "repo/ standing", placedRepoId)
		if string(fixture.object("meta-1", sidecar.EvsPlaceKey(placedRepoId))) != string(placeBytes) || string(fixture.object("meta-1", RepoKey(placedRepoId))) != string(repoBytes) {
			t.Errorf("%s: a refused create rewrote place/ or repo/", kind)
		}
		// place/ standing alone, its creator gone
		aloneRepoId := testId(fmt.Sprintf("kind-%d-alone", kind))
		fixture.auth.setRepo(aloneRepoId, facts)
		fixture.auth.grant(other, aloneRepoId, sidecar.AclEvsAdmin)
		alonePlaceBytes := fixture.standPlacement(aloneRepoId, "meta-1", gone)
		refusedPlaced(kind, "place/ alone", aloneRepoId)
		if fixture.object("meta-1", RepoKey(aloneRepoId)) != nil || string(fixture.object("meta-1", sidecar.EvsPlaceKey(aloneRepoId))) != string(alonePlaceBytes) {
			t.Errorf("%s: a refused create wrote over a placement standing alone", kind)
		}
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

// With a keying ttl of the whole RepoCacheTtl, a 404 and a keying repo/ are kept as long as any answer; by default
// neither is kept (repo_keying_window_test.go).
func TestRepoCacheKeepsAnAnswerAtMostItsTtl(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creator := testId("sidecar-a")
	fixture.projectRepo(repoId, creator)
	cluster, err := fixture.host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	settings := *fixture.engine.Settings()
	settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	repos := NewRepoCache(fixture.clock, &settings)
	if _, err := repos.Read(fixture.ctx, cluster, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		t.Fatalf("before: %v", err)
	}
	if status := fixture.putRepo(repoId, creator); status != http.StatusOK {
		t.Fatal(status)
	}
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	fixture.clock.Advance(4 * time.Second)
	if _, err := repos.Read(fixture.ctx, cluster, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		t.Errorf("a cached 404 at 4 s: %v", err)
	}
	fixture.clock.Advance(time.Second)
	read, err := repos.Read(fixture.ctx, cluster, repoId)
	if err != nil || read.Object.GetFormat() != sidecar.EvsRepoFormat1 {
		t.Fatalf("at 5 s: %v %v", read, err)
	}
	if _, err := repos.Read(fixture.ctx, cluster, repoId); err != nil {
		t.Fatal(err)
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; got != 1 {
		t.Errorf("%d GETs for three reads", got)
	}
}
