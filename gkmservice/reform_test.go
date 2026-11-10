package gkmservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A world whose group holds generations 1 and 2, re-formed by its admin at generation 2 into a new group, which the
// world then names: the old group's statements are kept for the ladder.
type gkmReformWorld struct {
	*gkmGroupWorld
	oldGroupId sidecar.Id
	key2       *sidecar.EvsRepoKey
	rotate2    *bridge.Signed
}

// POST /gkm/repos/<id>/forms: a re-form of the world's repo into groupId at generation.
func (self *gkmGroupWorld) postReform(groupId sidecar.Id, previousGroupId sidecar.Id, generation uint64) *httptest.ResponseRecorder {
	request := &protocol.GkmGroupReformRequest{
		Form:            self.form(self.admin, groupId, &previousGroupId, generation),
		GenWrap:         bytes.Repeat([]byte{5}, gkmSealedKeyByteCount),
		SealedGroupInfo: []byte("sealed group info of the re-formed epoch 0"),
		CipherSuite:     gkmCipherSuiteXWing,
	}
	path := "/gkm/repos/" + sidecar.EvsKeyId(self.repoId) + "/forms"
	return self.fixture.serve(http.MethodPost, path, self.adminToken, self.fixture.marshal(request))
}

// POST /gkm/groups/<id>/ladder for the world's group, with token.
func (self *gkmGroupWorld) postLadder(token string, generations ...*bridge.Signed) *httptest.ResponseRecorder {
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/ladder"
	return self.fixture.serve(http.MethodPost, path, token, self.fixture.marshal(&protocol.GkmLadderRequest{Generations: generations}))
}

// The generation after parent in groupId, the group that re-formed parent's, signed by the admin at the log's
// position 10 and now.
func (self *gkmGroupWorld) nextGenerationIn(groupId sidecar.Id, parent *sidecar.EvsRepoKey) (*sidecar.EvsRepoKey, *bridge.Signed) {
	self.t.Helper()
	key, rotate, err := parent.NextGenerationIn(groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          fakeGkmPin(10),
		Time:          self.fixture.clock.Now(),
		HoldersSha256: gkmTestHoldersSha256(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, self.admin.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return key, signed
}

// The world after its re-form, gen/2's pin at the log's position pinVersion.
func newGkmReformWorld(t *testing.T, pinVersion uint64) *gkmReformWorld {
	world := newGkmGroupWorld(t)
	world.fixture.auth.advanceLog(max(10, pinVersion), 1)
	world.createAndActivate()
	reformWorld := &gkmReformWorld{gkmGroupWorld: world, oldGroupId: world.groupId}
	reformWorld.key2, reformWorld.rotate2 = world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) {
		args.Auth = fakeGkmPin(pinVersion)
	})
	world.fixture.put("meta-2", GkmGenerationKey(world.groupId, 2), world.fixture.marshal(reformWorld.rotate2))
	reformedGroupId := testId("group-reformed")
	if recorder := world.postReform(reformedGroupId, world.groupId, 2); recorder.Code != http.StatusOK {
		t.Fatalf("a re-form: %d", recorder.Code)
	}
	world.groupId = reformedGroupId
	return reformWorld
}

// QD-074 rules 3 and 4: the ladder route gives a re-formed group its old generations byte for byte, each naming its
// old group, in ascending order from generation 1; the same call again answers success; and once gen/<the form's
// generation> stands, the next generation is claimed as in any group.
func TestGkmLadderCarriesAReformedGroupsGenerations(t *testing.T) {
	world := newGkmReformWorld(t, 10)
	fixture := world.fixture
	if recorder := world.postLadder(world.adminToken, world.rotate1); recorder.Code != http.StatusOK {
		t.Fatalf("the ladder's first call: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate1, world.rotate2); recorder.Code != http.StatusOK {
		t.Fatalf("the ladder's second call, repeating the first: %d", recorder.Code)
	}
	for generation := uint64(1); generation <= 2; generation += 1 {
		carried := fixture.object("meta-2", GkmGenerationKey(world.groupId, generation))
		original := fixture.object("meta-2", GkmGenerationKey(world.oldGroupId, generation))
		if carried == nil || !bytes.Equal(carried, original) {
			t.Errorf("gen/%d of the re-formed group is not the old group's bytes", generation)
		}
		facts, err := parseGkmGenerationFacts(carried)
		if err != nil || facts.generation != generation {
			t.Errorf("gen/%d of the re-formed group: %v", generation, err)
		}
	}
	if recorder := world.postLadder(world.adminToken, world.rotate1, world.rotate2); recorder.Code != http.StatusOK {
		t.Errorf("the whole ladder sent again: %d", recorder.Code)
	}
	// a statement naming the old group is no claim of the new one
	_, strayClaim3 := world.nextGeneration(world.admin, world.key2, nil)
	if recorder := world.postClaim(world.adminToken, 3, strayClaim3); recorder.Code != http.StatusBadRequest {
		t.Errorf("a claim naming the group the re-form replaced: %d", recorder.Code)
	}
	_, claim3 := world.nextGenerationIn(world.groupId, world.key2)
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusCreated {
		t.Errorf("a claim past the ladder: %d", recorder.Code)
	}
}

// The ladder route's refusals, each beside the call that passes: a reader's token, an empty call and one past 64, a
// statement of another repo, a statement out of order, a generation whose parent the group does not hold yet, a
// parent commitment that is not gen/<k-1>'s, a statement past the form's generation, other bytes at a generation
// the group holds, a group no re-form made, and a group that already took its first commit.
func TestGkmLadderRefusesWhatItsChecksDoNotPass(t *testing.T) {
	world := newGkmReformWorld(t, 10)
	fixture := world.fixture
	readerToken := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "rw"))
	if recorder := world.postLadder(readerToken, world.rotate1); recorder.Code != http.StatusForbidden {
		t.Errorf("a ladder under rw: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken); recorder.Code != http.StatusBadRequest {
		t.Errorf("an empty ladder: %d", recorder.Code)
	}
	many := []*bridge.Signed{}
	for count := 0; count <= gkmLadderMaxCount; count += 1 {
		many = append(many, world.rotate1)
	}
	if recorder := world.postLadder(world.adminToken, many...); recorder.Code != http.StatusBadRequest {
		t.Errorf("a ladder of %d statements: %d", len(many), recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate2, world.rotate1); recorder.Code != http.StatusBadRequest {
		t.Errorf("a ladder out of order: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate2); recorder.Code != http.StatusForbidden {
		t.Errorf("gen/2 before gen/1: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 2)) != nil {
		t.Fatalf("a refused ladder wrote")
	}

	// another repo's statement, and a second generation 2 that chains on another gen/1
	otherWorld := &gkmGroupWorld{t: t, fixture: fixture, repoId: testId("repo-other")}
	_, otherRotate1 := otherWorld.firstGeneration(world.admin, world.oldGroupId, fixture.clock.Now(), fakeGkmPin(10))
	if recorder := world.postLadder(world.adminToken, otherRotate1); recorder.Code != http.StatusBadRequest {
		t.Errorf("another repo's statement: %d", recorder.Code)
	}
	strayKey1, strayRotate1 := world.firstGeneration(world.admin, world.oldGroupId, fixture.clock.Now(), fakeGkmPin(10))
	_, strayRotate2 := world.nextGeneration(world.admin, strayKey1, nil)
	if recorder := world.postLadder(world.adminToken, world.rotate1, strayRotate2); recorder.Code != http.StatusForbidden {
		t.Errorf("a generation 2 that chains on another gen/1, in one call: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate1); recorder.Code != http.StatusOK {
		t.Fatalf("gen/1: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, strayRotate2); recorder.Code != http.StatusForbidden {
		t.Errorf("a generation 2 that chains on another gen/1, against the store: %d", recorder.Code)
	}
	if recorder := world.postLadder(world.adminToken, strayRotate1); recorder.Code != http.StatusConflict {
		t.Errorf("other bytes at gen/1: %d", recorder.Code)
	}
	_, rotate3 := world.nextGeneration(world.admin, world.key2, nil)
	if recorder := world.postLadder(world.adminToken, world.rotate2, rotate3); recorder.Code != http.StatusForbidden {
		t.Errorf("a statement past the form's generation: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 2)) != nil {
		t.Errorf("a ladder refused for its last statement wrote its first")
	}

	// a group a creation formed takes no ladder, nor does the re-formed one's predecessor
	reformedGroupId := world.groupId
	world.groupId = world.oldGroupId
	if recorder := world.postLadder(world.adminToken, world.rotate1); recorder.Code != http.StatusForbidden {
		t.Errorf("a ladder to the group the re-form replaced: %d", recorder.Code)
	}
	world.groupId = reformedGroupId

	// after the group's first commit the ladder is closed
	if recorder := world.postLadder(world.adminToken, world.rotate2); recorder.Code != http.StatusOK {
		t.Fatalf("gen/2: %d", recorder.Code)
	}
	world.startMlsGroup()
	world.commitAndAdopt(2, true)
	if recorder := world.postLadder(world.adminToken, world.rotate2); recorder.Code != http.StatusForbidden {
		t.Errorf("a ladder after epoch 1: %d", recorder.Code)
	}
}

// TestAReformsFirstCommitFloorsAtTheFormsGeneration (DESIGN-DETAILS 6.6): epoch 1 of a re-formed group is refused
// before the ladder reaches the form's generation, refused below gen/<form.generation>'s auth, and taken at it.
func TestAReformsFirstCommitFloorsAtTheFormsGeneration(t *testing.T) {
	world := newGkmReformWorld(t, 12)
	world.startMlsGroup()
	commit := func(pinVersion uint64) int {
		staged := world.stageSelfUpdate(2, fakeGkmPin(pinVersion))
		defer staged.Discard()
		return world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 2, true)).Code
	}
	if code := commit(12); code != http.StatusForbidden {
		t.Errorf("a commit before the ladder: %d", code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate1); recorder.Code != http.StatusOK {
		t.Fatalf("gen/1: %d", recorder.Code)
	}
	if code := commit(12); code != http.StatusForbidden {
		t.Errorf("a commit before the ladder reached the form's generation: %d", code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate2); recorder.Code != http.StatusOK {
		t.Fatalf("gen/2: %d", recorder.Code)
	}
	if code := commit(11); code != http.StatusForbidden {
		t.Errorf("a commit below gen/2's pin: %d", code)
	}
	if world.storedEpoch(1) != nil {
		t.Fatalf("a refused commit stands at epoch 1")
	}
	if code := commit(12); code != http.StatusOK {
		t.Errorf("a commit at gen/2's pin: %d", code)
	}
	if stored := world.storedEpoch(1); stored == nil || stored.GetHeader().GetGeneration() != 2 || stored.GetHeader().GetAuth().GetVersion() != 12 {
		t.Errorf("epoch 1 of the re-formed group: %v", stored)
	}
}

// QD-074 rule 5: a re-formed group takes no wrap until its ladder has reached its form's generation, and then a
// rotation's STAGED deliveries as any group does.
func TestGkmReformedGroupTakesNoWrapBeforeItsLadder(t *testing.T) {
	world := newGkmReformWorld(t, 10)
	fixture := world.fixture
	reader := world.newReader("sc-reader")
	key3, _ := world.nextGenerationIn(world.groupId, world.key2)
	delivery := world.readerWrap(world.admin, key3, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, fakeGkmPin(10), fixture.clock.Now())
	if code := world.postWrap(world.adminToken, 3, gkmTestC8(key3), delivery); code != http.StatusForbidden {
		t.Errorf("a staged delivery before the ladder: %d", code)
	}
	if recorder := world.postLadder(world.adminToken, world.rotate1, world.rotate2); recorder.Code != http.StatusOK {
		t.Fatalf("the ladder: %d", recorder.Code)
	}
	if code := world.postWrap(world.adminToken, 3, gkmTestC8(key3), delivery); code != http.StatusCreated {
		t.Errorf("a staged delivery after the ladder: %d", code)
	}
}

// §10.8's re-seed (owner decision 82; FS-6's gkm leg at the route): a repo re-seeded as deleted takes its GroupForm,
// with its epoch 0, and its ladder while §19.10's re-seed mode is on, and nothing else: no commit, claim or wrap;
// with the mode off it takes none of them.
func TestGkmDeletedRepoTakesOnlyAReseedsFormAndLadder(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	world.createAndActivate()
	key2, rotate2 := world.nextGeneration(world.admin, world.key1, nil)
	oldGroupId := world.groupId
	fixture.setRepoState(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_DELETED)
	reseededGroupId := testId("group-reseeded")
	if recorder := world.postReform(reseededGroupId, oldGroupId, 2); recorder.Code != http.StatusForbidden {
		t.Errorf("a GroupForm for a deleted repo outside re-seed mode: %d", recorder.Code)
	}
	if err := fixture.host.Gates.Set("sidecar:\n  gkm: {enabled: true, networks: [" + sidecar.Id(fixture.networkId).String() + "]}\n  reseed: true\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := world.postReform(reseededGroupId, oldGroupId, 2); recorder.Code != http.StatusOK {
		t.Fatalf("a re-seed's GroupForm: %d", recorder.Code)
	}
	world.groupId = reseededGroupId
	if recorder := world.postLadder(world.adminToken, world.rotate1, rotate2); recorder.Code != http.StatusOK {
		t.Fatalf("a re-seed's ladder: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmEpochKey(reseededGroupId, 0)) == nil || fixture.object("meta-2", GkmGenerationKey(reseededGroupId, 2)) == nil {
		t.Errorf("the re-seeded group lacks its epoch 0 or its ladder")
	}
	// every other route refuses the deleted repo
	world.startMlsGroup()
	staged := world.stageSelfUpdate(2, fakeGkmPin(10))
	defer staged.Discard()
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 2, true)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit to a deleted repo's group: %d", recorder.Code)
	}
	key3, claim3 := world.nextGenerationIn(world.groupId, key2)
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusForbidden {
		t.Errorf("a claim in a deleted repo's group: %d", recorder.Code)
	}
	reader := world.newReader("sc-reader")
	delivery := world.readerWrap(world.admin, key3, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, fakeGkmPin(10), fixture.clock.Now())
	if code := world.postWrap(world.adminToken, 3, gkmTestC8(key3), delivery); code != http.StatusForbidden {
		t.Errorf("a wrap in a deleted repo's group: %d", code)
	}
	// restored, the group takes its first commit at the ladder's floor
	fixture.setRepoState(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 2, true)); recorder.Code != http.StatusOK {
		t.Errorf("a commit once the repo is restored: %d", recorder.Code)
	}
}
