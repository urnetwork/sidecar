package gkmservice

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// gkm rereads evs's repo/ by the key evs writes, which this package builds without linking evs.
func TestGkmEvsRepoKeyIsEvssOwn(t *testing.T) {
	repoId := testId("repo-r")
	if GkmEvsRepoKey(repoId) != evsservice.RepoKey(repoId) {
		t.Errorf("gkm reads %s, evs writes %s", GkmEvsRepoKey(repoId), evsservice.RepoKey(repoId))
	}
}

// QD-442's forms, which testdata/gkm/wrap_paths.json pins for the root's builders: 20-digit numbers and 32-hex ids.
func TestGkmObjectKeysHoldQd442sForms(t *testing.T) {
	groupId := testId("group-g")
	repoId := testId("repo-r")
	sidecarId := testId("sc-a")
	hexGroup := sidecar.EvsKeyId(groupId)
	for _, key := range []struct {
		got  string
		want string
	}{
		{got: GkmEpochKey(groupId, 7), want: "gkm/" + hexGroup + "/epoch/00000000000000000007"},
		{got: GkmGenerationKey(groupId, 2), want: "gkm/" + hexGroup + "/gen/00000000000000000002"},
		{got: GkmFormKey(repoId, 1), want: "gkm/repo/" + sidecar.EvsKeyId(repoId) + "/00000000000000000001"},
		{got: GkmGroupInfoKey(groupId), want: "gkm/" + hexGroup + "/group-info"},
		{got: GkmWelcomeKey(groupId, 3), want: "gkm/" + hexGroup + "/welcome/00000000000000000003"},
		{got: GkmReaderKeyKey(sidecarId), want: "gkm/rk/" + sidecar.EvsKeyId(sidecarId)},
	} {
		if key.got != key.want {
			t.Errorf("%s, want %s", key.got, key.want)
		}
	}
	ref := bytes.Repeat([]byte{0xab}, gkmKeyPackageRefByteCount)
	key, err := GkmKeyPackageKey(sidecarId, ref)
	if err != nil || key != "gkm/kp/"+sidecar.EvsKeyId(sidecarId)+"/"+string(bytes.Repeat([]byte("ab"), 32)) {
		t.Errorf("a KeyPackage's key %s: %v", key, err)
	}
	if _, err := GkmKeyPackageKey(sidecarId, ref[:31]); !errors.Is(err, sidecar.ErrGkmMalformed) {
		t.Errorf("a short ref: %v", err)
	}
	gotRef, claim, ok := parseGkmKeyPackageListKey(GkmKeyPackagePrefix(sidecarId), key+gkmKeyPackageClaimKeySuffix)
	if !ok || !claim || !bytes.Equal(gotRef, ref) {
		t.Errorf("a claim's key read back as %x %v %v", gotRef, claim, ok)
	}
	if number, ok := parseGkmKeyNumber("18446744073709551615"); !ok || number != ^uint64(0) {
		t.Errorf("the largest number: %d %v", number, ok)
	}
	if _, ok := parseGkmKeyNumber("18446744073709551616"); ok {
		t.Error("a number past uint64 read back")
	}
}

// FS-63's gkm leg: a group's objects land on the cluster its repo's place/ names, even once place_new names another,
// and a restarted process resolves the same cluster; a place/ 404 is cached for 5 s and then clears.
func TestGkmGroupObjectsLandOnTheReposClusterAcrossARestart(t *testing.T) {
	repoId := testId("repo-r")
	groupId := testId("group-g")
	writes := 0
	fixture := newGkmFixtureWith(t, func(settings *GkmServiceSettings, deps *GkmEngineDeps) {
		deps.testServes = map[string]func(engine *GkmEngine, request *GkmRequest){
			// a commit, as KEYS-M2-14's handler writes it: on the request's cluster
			"POST /gkm/groups/{group_id}/epochs/{n}": func(engine *GkmEngine, request *GkmRequest) {
				writes += 1
				key := GkmEpochKey(*request.GroupId, uint64(writes))
				writeCtx, ok := request.SpendWrites(request.Cluster, "", engine.settings.Prices.create(len("epoch")))
				if !ok {
					return
				}
				if _, err := createGkmObject(writeCtx, request.Cluster, key, []byte("epoch"), engine.settings.ObjectMaxByteCount); err != nil {
					request.Unavailable()
					return
				}
				request.Reply(nil)
			},
		}
	})
	writer := testId("sc-writer")
	fixture.auth.admit(writer, memberDeviceFacts(testId("member-m")))
	fixture.auth.grant(writer, repoId, sidecar.AclEvsWrite)
	token := fixture.token(writer, repoScope(repoId, "rw"))
	commitPath := "/gkm/groups/" + sidecar.EvsKeyId(groupId) + "/epochs/1"
	formsPath := "/gkm/repos/" + sidecar.EvsKeyId(repoId) + "/forms"

	// before evs places the repo: 404, which the process keeps 5 s
	if recorder := fixture.serve(http.MethodGet, formsPath, token, nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("an unplaced repo: %d", recorder.Code)
	}
	fixture.placeRepo(repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(repoId, "meta-2", 1, groupId)
	if recorder := fixture.serve(http.MethodGet, formsPath, token, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a 404 within its 5 s: %d", recorder.Code)
	}
	fixture.clock.Advance(fixture.settings.Place.NotFoundTtl)
	if recorder := fixture.serve(http.MethodGet, formsPath, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a placed repo once the 404 cleared: %d", recorder.Code)
	}

	if recorder := fixture.serve(http.MethodPost, commitPath, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("a commit: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmEpochKey(groupId, 1)) == nil || fixture.object("meta-1", GkmEpochKey(groupId, 1)) != nil {
		t.Error("the group's object is not on the repo's cluster alone")
	}
	// place_new moves to the first cluster, and the process restarts with nothing cached
	fixture.host.Blobs.SetNewRepoClusterId("meta-1")
	fixture.start()
	if recorder := fixture.serve(http.MethodPost, commitPath, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("a commit after the restart: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmEpochKey(groupId, 2)) == nil || fixture.object("meta-1", GkmEpochKey(groupId, 2)) != nil {
		t.Error("the restarted process resolved another cluster")
	}
}

// A create answers the winner on a 412 and nothing for equal bytes, reads back a lost answer, and sends once more a
// create that never landed (§11.8's unknown row).
func TestGkmCreateAnswersTheWinnerAndResolvesLostAnswers(t *testing.T) {
	fixture := newGkmFixture(t)
	ctx := fixture.spentCtx()
	cluster := fixture.cluster("meta-1")
	key := "gkm/" + sidecar.EvsKeyId(testId("group-g")) + "/gen/00000000000000000002"
	if winner, err := createGkmObject(ctx, cluster, key, []byte("mine"), 1024); err != nil || winner != nil {
		t.Fatalf("the first create: %q %v", winner, err)
	}
	if winner, err := createGkmObject(ctx, cluster, key, []byte("mine"), 1024); err != nil || winner != nil {
		t.Errorf("a retry of equal bytes: %q %v", winner, err)
	}
	if winner, err := createGkmObject(ctx, cluster, key, []byte("theirs"), 1024); err != nil || string(winner) != "mine" {
		t.Errorf("a loser: %q %v", winner, err)
	}
	// the store took the create and the answer was lost: the read finds it
	lostKey := "gkm/" + sidecar.EvsKeyId(testId("group-g")) + "/gen/00000000000000000003"
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: lostKey, Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if winner, err := createGkmObject(ctx, cluster, lostKey, []byte("mine"), 1024); err != nil || winner != nil {
		t.Errorf("a lost answer: %q %v", winner, err)
	}
	// the create never reached the store: it goes again
	sentKey := "gkm/" + sidecar.EvsKeyId(testId("group-g")) + "/gen/00000000000000000004"
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: sentKey, Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if winner, err := createGkmObject(ctx, cluster, sentKey, []byte("mine"), 1024); err != nil || winner != nil {
		t.Errorf("a create that never landed: %q %v", winner, err)
	}
	if !bytes.Equal(fixture.object("meta-1", sentKey), []byte("mine")) {
		t.Error("the second send did not land")
	}
}

// repo/ and the GroupForms are cached at most 5 s, so a state change is seen within that.
func TestGkmRepoAndFormCachesHoldAnAnswerAtMostTheirTtl(t *testing.T) {
	fixture := newGkmFixture(t)
	repoId := testId("repo-r")
	fixture.placeRepo(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_KEYING)
	cluster := fixture.cluster("meta-1")
	object, err := fixture.engine.repos.read(fixture.ctx, cluster, repoId)
	if err != nil || object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("repo/: %v %v", object, err)
	}
	info, err := cluster.Head(fixture.ctx, GkmEvsRepoKey(repoId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfMatch(fixture.ctx, GkmEvsRepoKey(repoId), info.Etag, fixture.marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1,
	}), nil); err != nil {
		t.Fatal(err)
	}
	if object, _ := fixture.engine.repos.read(fixture.ctx, cluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Error("the cache did not hold its answer")
	}
	fixture.clock.Advance(fixture.settings.RepoCacheTtl)
	if object, _ := fixture.engine.repos.read(fixture.ctx, cluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Error("the cache held its answer past its ttl")
	}

	groupId := testId("group-g")
	fixture.fileForm(repoId, "meta-1", 1, groupId)
	forms, err := fixture.engine.forms.forms(fixture.ctx, cluster, repoId)
	if err != nil || len(forms) != 1 || forms[0].GroupId != groupId {
		t.Fatalf("forms: %v %v", forms, err)
	}
	if repoOf, ok := fixture.engine.forms.groupRepo(groupId); !ok || repoOf != repoId {
		t.Error("the group's repo was not remembered")
	}
	// a stored form of another repo is a fault, never a group of this one
	otherRepoId := testId("repo-other")
	fixture.put("meta-1", GkmFormKey(otherRepoId, 1), fixture.object("meta-1", GkmFormKey(repoId, 1)))
	if _, err := fixture.engine.forms.forms(fixture.ctx, cluster, otherRepoId); !errors.Is(err, errGkmStoreFault) {
		t.Errorf("another repo's form: %v", err)
	}
}
