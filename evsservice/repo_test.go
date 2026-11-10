package evsservice

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The raw cluster a test writes gkm's and evs's objects to by hand, no budget between.
func (self *evsFixture) rawCluster(clusterId string) sidecar.BlobCluster {
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// gkm's objects of a formed group, as KF1 leaves them: the repo's GroupForm 1 naming groupId and, with generation,
// the group's gen/1.
func (self *evsFixture) formGroup(repoId sidecar.Id, groupId sidecar.Id, generation bool) {
	cluster := self.rawCluster("meta-1")
	body, _ := proto.Marshal(&protocol.GroupForm{RepoId: repoId.Bytes(), GroupId: groupId.Bytes(), Generation: 1})
	signed, _ := proto.Marshal(&bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM), Body: body, SignerId: testId("form signer").Bytes()})
	if _, err := cluster.PutIfNoneMatch(self.ctx, gkmservice.GkmFormKey(repoId, 1), signed, nil); err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
		self.t.Fatal(err)
	}
	if generation {
		if _, err := cluster.PutIfNoneMatch(self.ctx, sidecar.GkmGenerationPath(groupId, 1), []byte("a signed GenRotate"), nil); err != nil {
			self.t.Fatal(err)
		}
	}
}

// One lifecycle request by sidecarId with an admin token: method on /evs/v1/repos/<id> plus suffix.
func (self *evsFixture) lifecycle(method string, repoId sidecar.Id, suffix string, sidecarId sidecar.Id) int {
	return self.serve(method, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+suffix, self.token(sidecarId, repoScope(repoId, "admin")), nil).Code
}

// A repo projected, placed, its group formed and activated, admin given to admin.
func (self *evsFixture) activeRepo(repoId sidecar.Id, admin sidecar.Id) {
	self.projectRepo(repoId, admin)
	if status := self.putRepo(repoId, admin); status != http.StatusOK {
		self.t.Fatalf("create: %d", status)
	}
	self.formGroup(repoId, testId("group "+string(repoId[:4])), true)
	if status := self.lifecycle(http.MethodPost, repoId, "/activate", admin); status != http.StatusOK {
		self.t.Fatalf("activate: %d", status)
	}
}

// Sets the projection's newest RepoDelete of a repo.
func (self *evsFixture) projectDeletion(repoId sidecar.Id, deletion *EvsRepoDeletionFacts) {
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	facts := *self.auth.repoFacts[repoId]
	facts.Deletion = deletion
	self.auth.repoFacts[repoId] = &facts
}

// repo/ as the cluster holds it.
func (self *evsFixture) repoObject(repoId sidecar.Id) *protocol.EvsRepoObject {
	object, _, err := sidecar.ReadEvsRepoObject(self.ctx, self.rawCluster("meta-1"), repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return object
}

// The shred passes queued for a repo.
func (self *evsFixture) shredRequests(repoId sidecar.Id) []*sidecar.TaskRequest {
	requests := []*sidecar.TaskRequest{}
	for _, request := range self.host.Tasks.Pending() {
		if request.Name == EvsShredTaskName && strings.Contains(request.OnceKey, sidecar.EvsKeyId(repoId)) {
			requests = append(requests, request)
		}
	}
	return requests
}

// gkm's form key is the one evs lists.
func TestRepoActivateListsGkmsFormKeys(t *testing.T) {
	repoId := testId("repo")
	if !strings.HasPrefix(gkmservice.GkmFormKey(repoId, 1), evsGkmFormPrefix(repoId)) || gkmservice.GkmFormPrefix(repoId) != evsGkmFormPrefix(repoId) {
		t.Errorf("gkm writes %s, evs lists %s", gkmservice.GkmFormPrefix(repoId), evsGkmFormPrefix(repoId))
	}
}

// §11.12's kinds: each of the nine creates, the directory included, with an owner exactly for the owner-bound kinds;
// a kind this build does not know, or an owner on the wrong kind, is refused before anything is placed.
func TestRepoKindsKnownOrRefusedAtCreation(t *testing.T) {
	fixture := newEvsFixture(t)
	admin := testId("sidecar-a")
	owner := testId("owner member")
	for kindNumber := range protocol.RepoKind_name {
		kind := protocol.RepoKind(kindNumber)
		if kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
			continue
		}
		repoId := testId(kind.String()[10:])
		facts := &EvsRepoFacts{Kind: kind, NetworkId: sidecar.Id(fixture.networkId)}
		if sidecar.EvsRepoKindOwnerBound(kind) {
			facts.OwnerMemberId = owner
		}
		fixture.auth.setRepo(repoId, facts)
		fixture.auth.grant(admin, repoId, sidecar.AclEvsAdmin)
		if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
			t.Errorf("%s: %d", kind, status)
			continue
		}
		if object := fixture.repoObject(repoId); object.GetKind() != kind || (len(object.GetOwnerMemberId()) == 16) != sidecar.EvsRepoKindOwnerBound(kind) {
			t.Errorf("%s: repo/ %v", kind, object)
		}
	}
	refused := []*EvsRepoFacts{
		{Kind: protocol.RepoKind(99), NetworkId: sidecar.Id(fixture.networkId)},
		{Kind: protocol.RepoKind_REPO_KIND_VAULT, NetworkId: sidecar.Id(fixture.networkId)},
		{Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, OwnerMemberId: owner, NetworkId: sidecar.Id(fixture.networkId)},
	}
	for i, facts := range refused {
		repoId := testId("refused " + string(rune('a'+i)))
		fixture.auth.setRepo(repoId, facts)
		fixture.auth.grant(admin, repoId, sidecar.AclEvsAdmin)
		if status := fixture.putRepo(repoId, admin); status != http.StatusBadRequest {
			t.Errorf("refused %d: %d", i, status)
		}
		if fixture.placement(repoId) != nil {
			t.Errorf("refused %d was placed", i)
		}
	}
}

// plan-EVS1-repo-activate-route: activate waits for the newest GroupForm and its group's gen/1, then swaps keying for
// active, and answers a retry 200.
func TestRepoActivateNeedsTheGroupsFirstGeneration(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin, groupId := testId("repo"), testId("sidecar-a"), testId("group")
	fixture.projectRepo(repoId, admin)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("create: %d", status)
	}
	activate := func() *protocol.EvsRefusalReply {
		recorder := fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/activate", fixture.token(admin, repoScope(repoId, "admin")), nil)
		if recorder.Code == http.StatusOK {
			return nil
		}
		return refusalOf(t, recorder)
	}
	if refusal := activate(); refusal.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY {
		t.Fatalf("no form: %v", refusal)
	}
	fixture.formGroup(repoId, groupId, false)
	if refusal := activate(); refusal.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY {
		t.Fatalf("no gen/1: %v", refusal)
	}
	fixture.formGroup(repoId, groupId, true)
	if refusal := activate(); refusal != nil {
		t.Fatalf("formed: %v", refusal)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || object.GetStateMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("repo/ %v", object)
	}
	if refusal := activate(); refusal != nil {
		t.Errorf("a retry: %v", refusal)
	}
	// a reader's token does not activate
	recorder := fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/activate", fixture.token(admin, repoScope(repoId, "r")), nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

// §11.12's delete and restore on a fake clock: DELETE needs its projected RepoDelete, takes deleted{its id, its
// entry's time and signer}, closes GET and queues the start 7 d 10 min after the entry; restore needs its projected
// RepoRestore and brings the repo back; each answers its retry 200.
func TestRepoDeleteThenRestore(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin, reader := testId("repo"), testId("sidecar-a"), testId("sidecar-r")
	fixture.activeRepo(repoId, admin)
	fixture.auth.grant(reader, repoId, sidecar.AclEvsRead)
	get := func() int {
		return fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(reader, repoScope(repoId, "r")), nil).Code
	}
	if status := get(); status != http.StatusOK {
		t.Fatalf("get: %d", status)
	}
	if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusConflict {
		t.Fatalf("a delete with no RepoDelete: %d", status)
	}
	entryTime := fixture.clock.Now().Add(-time.Minute)
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: entryTime, SignerSidecarId: admin}
	fixture.projectDeletion(repoId, deletion)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusConflict {
		t.Fatalf("now beside a RepoDelete without it: %d", status)
	}
	for range 2 {
		if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
			t.Fatalf("delete: %d", status)
		}
	}
	object := fixture.repoObject(repoId)
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || sidecar.Id(object.GetDeletionId()) != deletion.DeletionId ||
		object.GetStateMs() != entryTime.UnixMilli() || sidecar.Id(object.GetStateSigner()) != admin {
		t.Fatalf("repo/ %v", object)
	}
	if status := get(); status != http.StatusConflict {
		t.Errorf("get while deleted: %d", status)
	}
	if requests := fixture.shredRequests(repoId); len(requests) != 1 || !requests[0].RunAt.Equal(entryTime.Add(evsShredStartAfter)) {
		t.Errorf("the start queued %v", requests)
	}
	if status := fixture.lifecycle(http.MethodPost, repoId, "/restore", admin); status != http.StatusConflict {
		t.Fatalf("a restore with no RepoRestore: %d", status)
	}
	restored := *deletion
	restored.Restored = true
	fixture.projectDeletion(repoId, &restored)
	for range 2 {
		if status := fixture.lifecycle(http.MethodPost, repoId, "/restore", admin); status != http.StatusOK {
			t.Fatalf("restore: %d", status)
		}
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || len(object.GetDeletionId()) != 0 {
		t.Fatalf("restored repo/ %v", object)
	}
	if status := get(); status != http.StatusOK {
		t.Errorf("get after the restore: %d", status)
	}
	// the restored deletion is spent: a DELETE needs a new RepoDelete
	if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusConflict {
		t.Errorf("a delete on a restored RepoDelete: %d", status)
	}
}

// --now: an active repo goes to shredding at once, never restorable, its shred queued now; a deleted repo goes there
// too under a newer RepoDelete{now}.
func TestRepoDeleteNowShredsAtOnceAndRefusesRestore(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	first := &EvsRepoDeletionFacts{DeletionId: testId("deletion 1"), Time: fixture.clock.Now(), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, first)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
		t.Fatalf("delete: %d", status)
	}
	// a newer RepoDelete without now while deleted is refused
	fixture.projectDeletion(repoId, &EvsRepoDeletionFacts{DeletionId: testId("deletion 2"), Time: fixture.clock.Now(), SignerSidecarId: admin})
	recorder := fixture.serve(http.MethodDelete, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(admin, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	now := &EvsRepoDeletionFacts{DeletionId: testId("deletion 3"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, now)
	fixture.clock.Advance(time.Second)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
		t.Fatalf("delete now: %d", status)
	}
	object := fixture.repoObject(repoId)
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDING || sidecar.Id(object.GetDeletionId()) != now.DeletionId ||
		object.GetStateMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("repo/ %v", object)
	}
	queuedNow := false
	for _, request := range fixture.shredRequests(repoId) {
		queuedNow = queuedNow || (request.RunAt.Equal(fixture.clock.Now()) && strings.Contains(request.OnceKey, sidecar.EvsKeyId(now.DeletionId)))
	}
	if !queuedNow {
		t.Errorf("no shred queued now: %v", fixture.shredRequests(repoId))
	}
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
		t.Errorf("a retry of the delete: %d", status)
	}
	restoredFirst := *first
	restoredFirst.Restored = true
	fixture.projectDeletion(repoId, &restoredFirst)
	recorder = fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/restore", fixture.token(admin, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
}

// FS-6: a restore raced against a --now delete at repo/'s If-Match. Both read the deleted repo; the delete's CAS lands
// between the restore's read and its CAS, so the restore's 412 rereads a shredding repo and answers SHREDDING: one
// winner. And the other order: the restore lands first, and the now delete, a newer statement, shreds the active repo.
func TestRepoRestoreRacedAgainstNowHasOneWinner(t *testing.T) {
	for _, restoreFirst := range []bool{false, true} {
		fixture := newEvsFixture(t)
		repoId, admin := testId("repo"), testId("sidecar-a")
		fixture.activeRepo(repoId, admin)
		deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion 1"), Time: fixture.clock.Now(), SignerSidecarId: admin}
		fixture.projectDeletion(repoId, deletion)
		if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
			t.Fatalf("delete: %d", status)
		}
		cluster := fixture.rawCluster("meta-1")
		repos := NewRepoCache(fixture.clock, fixture.engine.settings)
		class := fixture.engine.p0Class(cluster, sidecar.WriteP0KindLifecycle)
		restored := *deletion
		restored.Restored = true
		now := &EvsRepoDeletionFacts{DeletionId: testId("deletion 2"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
		var innerErr error
		// the competitor's whole transition, run between the outer one's read and its CAS
		raceIn := func(decide repoDecide, competitor repoDecide) repoDecide {
			ran := false
			return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
				if !ran {
					ran = true
					_, innerErr = transitionRepo(fixture.ctx, cluster, repos, repoId, 8, class, competitor)
				}
				return decide(read)
			}
		}
		var outerErr error
		if restoreFirst {
			_, outerErr = transitionRepo(fixture.ctx, cluster, repos, repoId, 8, class, raceIn(decideDelete(now, fixture.clock.Now()), decideRestore(&restored, fixture.clock.Now())))
		} else {
			_, outerErr = transitionRepo(fixture.ctx, cluster, repos, repoId, 8, class, raceIn(decideRestore(&restored, fixture.clock.Now()), decideDelete(now, fixture.clock.Now())))
		}
		object := fixture.repoObject(repoId)
		if object.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDING || sidecar.Id(object.GetDeletionId()) != now.DeletionId {
			t.Errorf("restore first %t: repo/ %v", restoreFirst, object)
		}
		var refusal *EvsRepoRefusal
		switch {
		case restoreFirst && (innerErr != nil || outerErr != nil):
			t.Errorf("the restore and the newer delete in turn: %v, %v", innerErr, outerErr)
		case !restoreFirst && (innerErr != nil || !errors.As(outerErr, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING):
			t.Errorf("the restore after the now delete: %v, %v", innerErr, outerErr)
		}
	}
}

// The repo's objects of every family, written by hand on its cluster and the segment cluster, and its Redis keys.
func (self *evsFixture) plantRepoObjects(repoId sidecar.Id) {
	cluster := self.rawCluster("meta-1")
	refId := testId("ref")
	token, _ := sidecar.ParseEvsToken(strings.Repeat("a", 26))
	keys := []string{
		SlotKey(repoId, testId("slot")),
		IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{token}),
		HeadKey(repoId, refId),
		LogPageKey(repoId, refId, 0),
		PathMapKey(repoId, refId, 2, make([]byte, 32), 1),
		PidxKey(repoId, refId, 1, testId("container")),
		SpidxKey(repoId, 0),
		ParcelKey(repoId, testId("parcel")),
		DropsKey(repoId),
	}
	for _, key := range keys {
		if _, err := cluster.PutIfNoneMatch(self.ctx, key, []byte("ciphertext"), nil); err != nil {
			self.t.Fatal(err)
		}
	}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	for _, key := range []string{SegmentKey(repoId, [32]byte{1}), PackKey(repoId, testId("pack")), DropscanKey(repoId, testId("job"), "snap")} {
		if _, err := segmentCluster.PutIfNoneMatch(self.ctx, key, []byte("ciphertext"), nil); err != nil {
			self.t.Fatal(err)
		}
	}
	for _, key := range []string{PushSequenceKey(repoId), LeaseVersionKey(repoId), HeadCacheKey(repoId)} {
		if err := self.host.Redis.Set(self.ctx, key, []byte("1"), time.Hour); err != nil {
			self.t.Fatal(err)
		}
	}
}

// What of the repo's planted objects stand: keys by family, repo/ and place/ aside.
func (self *evsFixture) repoFamilies(repoId sidecar.Id) []string {
	families := []string{}
	for key := range self.host.Blobs.Dump() {
		_, objectKey, _ := strings.Cut(key, "/")
		if strings.Contains(objectKey, sidecar.EvsKeyId(repoId)) && !strings.HasPrefix(objectKey, "repo/") && !strings.HasPrefix(objectKey, "place/") &&
			!strings.HasPrefix(objectKey, "gkm/") {
			family, _, _ := strings.Cut(objectKey, "/")
			if !slices.Contains(families, family) {
				families = append(families, family)
			}
		}
	}
	slices.Sort(families)
	return families
}

// A shred's deps on the fixture: gkm's step recorded.
type shredProbe struct {
	groupCalls []bool
	failGroup  error
}

func (self *shredProbe) deps(deletions EvsRepoDeletionSource) *EvsShredDeps {
	return &EvsShredDeps{
		ShredGroup: func(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool) error {
			if self.failGroup != nil {
				return self.failGroup
			}
			self.groupCalls = append(self.groupCalls, final)
			return nil
		},
		Deletions: deletions,
	}
}

// The projection a shred reads, from the fixture's fake state.
type fixtureDeletions struct {
	auth *fakeAuthState
}

func (self *fixtureDeletions) RepoDeletion(ctx context.Context, networkId sidecar.Id, repoId sidecar.Id) (*EvsRepoDeletionFacts, error) {
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	facts := self.auth.repoFacts[repoId]
	if facts == nil {
		return nil, nil
	}
	return facts.Deletion, nil
}

// FS-6 and §22.5 on a fake clock: a --now shred waits 20 s, deletes keys, then every other family, queues its final
// pass 10 min on, which repeats them and writes the tombstone, place/ kept; restore stays refused throughout.
func TestRepoShredRunsItsPhasesAndLeavesATombstone(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	fixture.plantRepoObjects(repoId)
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, deletion)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
		t.Fatalf("delete now: %d", status)
	}
	probe := &shredProbe{}
	host := fixture.host.ServiceHost()
	args := EvsShredArgs(repoId, deletion.DeletionId, false)
	outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), args)
	if err != nil || outcome != EvsShredWaiting || len(probe.groupCalls) != 0 {
		t.Fatalf("before 20 s: %v %v %v", outcome, err, probe.groupCalls)
	}
	fixture.clock.Advance(evsShredSettleWait)
	outcome, err = RunShred(fixture.ctx, host, probe.deps(nil), args)
	if err != nil || outcome != EvsShredFirstPassDone {
		t.Fatalf("first pass: %v %v", outcome, err)
	}
	if families := fixture.repoFamilies(repoId); len(families) != 0 || !slices.Equal(probe.groupCalls, []bool{false}) {
		t.Fatalf("after the first pass: %v, gkm %v", families, probe.groupCalls)
	}
	for _, key := range []string{PushSequenceKey(repoId), LeaseVersionKey(repoId), HeadCacheKey(repoId)} {
		if _, found, _ := fixture.host.Redis.Get(fixture.ctx, key); found {
			t.Errorf("%s stands", key)
		}
	}
	final := false
	for _, request := range fixture.shredRequests(repoId) {
		_, _, isFinal, _ := ParseEvsShredArgs(request.Args)
		final = final || (isFinal && request.RunAt.Equal(fixture.clock.Now().Add(evsShredStragglerWait)))
	}
	if !final {
		t.Fatalf("no final pass queued: %v", fixture.shredRequests(repoId))
	}
	// a straggler landing between the passes goes in the final one
	fixture.plantRepoObjects(testId("other repo"))
	if _, err := fixture.rawCluster("meta-1").PutIfNoneMatch(fixture.ctx, SlotKey(repoId, testId("late slot")), []byte("late"), nil); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(evsShredStragglerWait)
	outcome, err = RunShred(fixture.ctx, host, probe.deps(nil), EvsShredArgs(repoId, deletion.DeletionId, true))
	if err != nil || outcome != EvsShredShredded || !slices.Equal(probe.groupCalls, []bool{false, true}) {
		t.Fatalf("final pass: %v %v %v", outcome, err, probe.groupCalls)
	}
	if families := fixture.repoFamilies(repoId); len(families) != 0 {
		t.Errorf("after the final pass: %v", families)
	}
	if len(fixture.repoFamilies(testId("other repo"))) == 0 {
		t.Error("another repo's objects went")
	}
	object := fixture.repoObject(repoId)
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDED || sidecar.Id(object.GetDeletionId()) != deletion.DeletionId || fixture.placement(repoId) == nil {
		t.Fatalf("tombstone %v, place/ %v", object, fixture.placement(repoId))
	}
	// a rerun of either pass finds the tombstone
	if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), args); err != nil || outcome != EvsShredShredded {
		t.Errorf("rerun: %v %v", outcome, err)
	}
}

// FS-6: the worker killed at each step: a failure at any step leaves the run to its retry, which finishes, and no step
// runs out of order: gkm's keys before the ciphertext.
func TestRepoShredResumesAfterAKillAtEachStep(t *testing.T) {
	steps := []*sidecartest.FaultPlan{
		{Op: sidecartest.FaultOpDelete, KeyPrefix: "slot/", Result: sidecartest.FailBeforeApply},
		nil, // gkm's step fails
		{Op: sidecartest.FaultOpDelete, KeyPrefix: "idx/", Result: sidecartest.FailBeforeApply},
		{Op: sidecartest.FaultOpDelete, KeyPrefix: "seg/", Result: sidecartest.ApplyThenDrop},
		{Op: sidecartest.FaultOpPut, KeyPrefix: "repo/", Result: sidecartest.ApplyThenDrop},
	}
	for i, plan := range steps {
		fixture := newEvsFixture(t)
		repoId, admin := testId("repo"), testId("sidecar-a")
		fixture.activeRepo(repoId, admin)
		fixture.plantRepoObjects(repoId)
		deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
		fixture.projectDeletion(repoId, deletion)
		if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
			t.Fatalf("step %d: delete now: %d", i, status)
		}
		fixture.clock.Advance(evsShredSettleWait)
		probe := &shredProbe{}
		if plan == nil {
			probe.failGroup = errors.New("killed")
		} else if _, err := fixture.host.Blobs.Faults().Add(plan); err != nil {
			t.Fatal(err)
		}
		host := fixture.host.ServiceHost()
		final := i == len(steps)-1
		if final {
			// the tombstone's lost answer is the final pass's step
			if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), EvsShredArgs(repoId, deletion.DeletionId, false)); err == nil && outcome != EvsShredFirstPassDone {
				t.Fatalf("step %d: first pass %v", i, outcome)
			}
			fixture.clock.Advance(evsShredStragglerWait)
		}
		args := EvsShredArgs(repoId, deletion.DeletionId, final)
		_, firstErr := RunShred(fixture.ctx, host, probe.deps(nil), args)
		if plan == nil && (firstErr == nil || len(fixture.repoFamilies(repoId)) == 0) {
			t.Errorf("step %d: gkm failed and the ciphertext went: %v", i, fixture.repoFamilies(repoId))
		}
		probe.failGroup = nil
		for range 3 {
			if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), args); err == nil && (outcome == EvsShredFirstPassDone || outcome == EvsShredShredded) {
				break
			}
		}
		if families := fixture.repoFamilies(repoId); len(families) != 0 {
			t.Errorf("step %d: %v stand after the retry (first run %v)", i, families, firstErr)
		}
		if final && fixture.repoObject(repoId).GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDED {
			t.Errorf("step %d: repo/ %v", i, fixture.repoObject(repoId))
		}
	}
}

// FS-6: a --now shred under a hold: the keys go, gkm's included, and the ciphertext stays until the hold ends, the job
// queued again at its end; a hold does not stop the user's shred, only its deletions of ciphertext.
func TestRepoShredUnderAHoldKeepsCiphertextAndDeletesKeys(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	fixture.plantRepoObjects(repoId)
	expires := fixture.clock.Now().Add(12 * time.Hour)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: sidecar.Id(fixture.networkId), CaseId: testId("case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(repoId), PlaceTime: fixture.clock.Now().Add(-time.Hour), ExpireTime: expires,
	}); err != nil {
		t.Fatal(err)
	}
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, deletion)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
		t.Fatalf("delete now: %d", status)
	}
	fixture.clock.Advance(evsShredSettleWait)
	probe := &shredProbe{}
	host := fixture.host.ServiceHost()
	args := EvsShredArgs(repoId, deletion.DeletionId, false)
	outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), args)
	if err != nil || outcome != EvsShredHeld {
		t.Fatalf("held: %v %v", outcome, err)
	}
	families := fixture.repoFamilies(repoId)
	if slices.Contains(families, "slot") || len(probe.groupCalls) != 1 || !slices.Contains(families, "idx") || !slices.Contains(families, "seg") {
		t.Fatalf("under the hold: %v, gkm %v", families, probe.groupCalls)
	}
	// asked for at the hold's end, which a run's successor keeps (a direct call here, beside the DELETE's own request)
	requeued := false
	for _, request := range fixture.host.Tasks.AllRequests() {
		requeued = requeued || (request.Name == EvsShredTaskName && request.RunAt.Equal(expires))
	}
	if !requeued {
		t.Errorf("not queued at the hold's end: %v", fixture.host.Tasks.AllRequests())
	}
	fixture.clock.AdvanceTo(expires)
	if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), args); err != nil || outcome != EvsShredFirstPassDone || len(fixture.repoFamilies(repoId)) != 0 {
		t.Fatalf("after the hold: %v %v %v", outcome, err, fixture.repoFamilies(repoId))
	}
}

// A stale job of an earlier deletion deletes nothing: repo/ shows another incarnation.
func TestRepoShredOfAnotherDeletionDeletesNothing(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	fixture.plantRepoObjects(repoId)
	before := fixture.repoFamilies(repoId)
	probe := &shredProbe{}
	host := fixture.host.ServiceHost()
	// active: a job of a restored deletion
	if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), EvsShredArgs(repoId, testId("old deletion"), false)); err != nil || outcome != EvsShredStale {
		t.Fatalf("active: %v %v", outcome, err)
	}
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Now: true, Time: fixture.clock.Now(), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, deletion)
	if status := fixture.lifecycle(http.MethodDelete, repoId, "?now=1", admin); status != http.StatusOK {
		t.Fatalf("delete now: %d", status)
	}
	fixture.clock.Advance(time.Hour)
	if outcome, err := RunShred(fixture.ctx, host, probe.deps(nil), EvsShredArgs(repoId, testId("old deletion"), true)); err != nil || outcome != EvsShredStale {
		t.Fatalf("shredding under another deletion: %v %v", outcome, err)
	}
	if after := fixture.repoFamilies(repoId); !slices.Equal(before, after) || len(probe.groupCalls) != 0 {
		t.Errorf("a stale job deleted: %v to %v, gkm %v", before, after, probe.groupCalls)
	}
}

// §11.12's start on a fake clock: a deleted repo waits 7 d 10 min after its RepoDelete's entry, then goes to shredding
// unless the projection holds its RepoRestore, and a restore after the start answers SHREDDING; exactly one wins.
func TestRepoShredStartsSevenDaysAfterTheEntryUnlessRestored(t *testing.T) {
	for _, restore := range []bool{false, true} {
		fixture := newEvsFixture(t)
		repoId, admin := testId("repo"), testId("sidecar-a")
		fixture.activeRepo(repoId, admin)
		entryTime := fixture.clock.Now()
		deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: entryTime, SignerSidecarId: admin}
		fixture.projectDeletion(repoId, deletion)
		if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
			t.Fatalf("delete: %d", status)
		}
		probe := &shredProbe{}
		host := fixture.host.ServiceHost()
		deletions := &fixtureDeletions{auth: fixture.auth}
		args := EvsShredArgs(repoId, deletion.DeletionId, false)
		fixture.clock.AdvanceTo(entryTime.Add(evsShredStartAfter - time.Second))
		if outcome, err := RunShred(fixture.ctx, host, probe.deps(deletions), args); err != nil || outcome != EvsShredWaiting {
			t.Fatalf("restore %t: a second early: %v %v", restore, outcome, err)
		}
		if restore {
			restored := *deletion
			restored.Restored = true
			fixture.projectDeletion(repoId, &restored)
		}
		fixture.clock.AdvanceTo(entryTime.Add(evsShredStartAfter))
		outcome, err := RunShred(fixture.ctx, host, probe.deps(deletions), args)
		state := fixture.repoObject(repoId).GetState()
		switch {
		case restore && (err != nil || outcome != EvsShredRestored || state != protocol.EvsRepoState_EVS_REPO_DELETED):
			t.Errorf("restored: %v %v %s", outcome, err, state)
		case !restore && (err != nil || outcome != EvsShredWaiting || state != protocol.EvsRepoState_EVS_REPO_SHREDDING):
			t.Errorf("started: %v %v %s", outcome, err, state)
		}
		if restore {
			if status := fixture.lifecycle(http.MethodPost, repoId, "/restore", admin); status != http.StatusOK {
				t.Errorf("the restore: %d", status)
			}
			continue
		}
		restored := *deletion
		restored.Restored = true
		fixture.projectDeletion(repoId, &restored)
		recorder := fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/restore", fixture.token(admin, repoScope(repoId, "admin")), nil)
		requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
	}
}

// FS-6: a device killed between filing RepoDelete and calling DELETE: the reconciler applies the projected statement
// repo/ lacks and queues the start, and a restore filed and never called is applied the same way.
func TestRepoReconcilerAppliesAStatementTheRouteNeverGot(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: fixture.clock.Now().Add(-time.Hour), SignerSidecarId: admin}
	fixture.projectDeletion(repoId, deletion)
	host := fixture.host.ServiceHost()
	deps := &EvsReconcileDeps{Deletions: &fixtureDeletions{auth: fixture.auth}}
	counts, err := RunReconcile(fixture.ctx, host, deps)
	if err != nil || counts.Applied != 1 || counts.Queued != 1 {
		t.Fatalf("reconcile: %+v %v", counts, err)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || object.GetStateMs() != deletion.Time.UnixMilli() {
		t.Fatalf("repo/ %v", object)
	}
	if requests := fixture.shredRequests(repoId); len(requests) != 1 || !requests[0].RunAt.Equal(deletion.Time.Add(evsShredStartAfter)) {
		t.Errorf("the start %v", requests)
	}
	// a second walk applies nothing again
	if counts, err := RunReconcile(fixture.ctx, host, deps); err != nil || counts.Applied != 0 {
		t.Errorf("again: %+v %v", counts, err)
	}
	restored := *deletion
	restored.Restored = true
	fixture.projectDeletion(repoId, &restored)
	if counts, err := RunReconcile(fixture.ctx, host, deps); err != nil || counts.Applied != 1 {
		t.Fatalf("the restore: %+v %v", counts, err)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %v", object)
	}
	// with no projection, the walk applies nothing and only queues
	if counts, err := RunReconcile(fixture.ctx, host, nil); err != nil || counts.Applied != 0 || counts.Repos != 1 {
		t.Errorf("no projection: %+v %v", counts, err)
	}
}

// §11.12's refused row on routes with no state of their own: an upload to a deleted repo answers REPO_DELETED, and
// GET past deleted SHREDDING.
func TestRepoRefusedRowClosesRoutesWhileDeleted(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin := testId("repo"), testId("sidecar-a")
	fixture.activeRepo(repoId, admin)
	fixture.projectDeletion(repoId, &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: fixture.clock.Now(), SignerSidecarId: admin})
	if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
		t.Fatalf("delete: %d", status)
	}
	fixture.clock.Advance(10 * time.Second)
	recorder := fixture.serve(http.MethodPut, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/segments/"+strings.Repeat("07", 32)+"?push="+sidecar.EvsKeyId(testId("push")),
		fixture.token(admin, repoScope(repoId, "admin")), []byte("x"))
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	recorder = fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/activate", fixture.token(admin, repoScope(repoId, "admin")), nil)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
}
