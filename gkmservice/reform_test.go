package gkmservice

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

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

// A v0 restore keeps installed signed history across a service change and an interrupted reseed.
func TestKeyDeliveryReseedRetainsInstalledLadder(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	_, rotate2 := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) {
		args.LeafWrapKek = bytes.Repeat([]byte{3}, 32)
	})
	fixture.put("meta-2", GkmGenerationKey(world.groupId, 2), fixture.marshal(rotate2))
	old := world.groupId
	fixture.settings = DefaultGkmServiceSettings()
	fixture.start()
	if answer := world.postClaim(world.adminToken, 2, rotate2); answer.Code != http.StatusCreated {
		t.Fatalf("retry of the installed signed generation: %d", answer.Code)
	}
	world.groupId = testId("restored-keydelivery")
	request := &protocol.GkmGroupReformRequest{Form: world.form(world.admin, world.groupId, &old, 2)}
	path := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/forms"
	for range 2 {
		if answer := fixture.serve(http.MethodPost, path, world.adminToken, fixture.marshal(request)); answer.Code != http.StatusOK {
			t.Fatalf("restore form: %d", answer.Code)
		}
	}
	if answer := world.postLadder(world.adminToken, world.rotate1); answer.Code != http.StatusOK {
		t.Fatalf("first ladder item: %d", answer.Code)
	}
	fixture.start()
	if answer := world.postLadder(world.adminToken, world.rotate1, rotate2); answer.Code != http.StatusOK {
		t.Fatalf("resumed ladder: %d", answer.Code)
	}
	for generation := uint64(1); generation <= 2; generation++ {
		original := fixture.object("meta-2", GkmGenerationKey(old, generation))
		restored := fixture.object("meta-2", GkmGenerationKey(world.groupId, generation))
		if len(original) == 0 || !bytes.Equal(original, restored) {
			t.Fatalf("the signed generation %d changed on restore", generation)
		}
	}
	if world.storedEpoch(0) != nil {
		t.Fatal("the restored group acquired an epoch")
	}
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
	for count := 0; count <= fixture.settings.LadderMaxCount; count += 1 {
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

// The bytes of the admin's GroupForm re-forming previousGroupId into groupId at generation, as postReform posts them
// and the old group's closing marker holds them.
func (self *gkmGroupWorld) reformBytes(groupId sidecar.Id, previousGroupId sidecar.Id, generation uint64) []byte {
	self.t.Helper()
	return self.fixture.marshal(self.form(self.admin, groupId, &previousGroupId, generation))
}

// What a key of the world's cluster holds, and whether it stands at all: an empty object stands.
func (self *gkmGroupWorld) stored(key string) ([]byte, bool) {
	self.t.Helper()
	objectBytes, _, err := readGkmObject(self.fixture.ctx, self.fixture.cluster("meta-2"), key, self.fixture.settings.StatementMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, false
	}
	if err != nil {
		self.t.Fatal(err)
	}
	return objectBytes, true
}

// Empties groupId's closing marker by If-Match, as a void closing does.
func (self *gkmGroupWorld) emptyClosingMarker(groupId sidecar.Id) {
	self.t.Helper()
	cluster := self.fixture.cluster("meta-2")
	info, err := cluster.Head(self.fixture.ctx, GkmGroupClosedKey(groupId))
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfMatch(self.fixture.ctx, GkmGroupClosedKey(groupId), info.Etag, []byte{}, nil); err != nil {
		self.t.Fatal(err)
	}
}

// The numbers of the generations a route serves of groupId after since: GET gen, or with dropKey the repo's drop-key
// route, which serves the newest form's group.
func (self *gkmGroupWorld) servedGenerations(groupId sidecar.Id, since uint64, dropKey bool) []uint64 {
	self.t.Helper()
	path := "/gkm/groups/" + sidecar.EvsKeyId(groupId) + "/gen?since=" + strconv.FormatUint(since, 10)
	if dropKey {
		path = "/gkm/repos/" + sidecar.EvsKeyId(self.repoId) + "/drop-key?since=" + strconv.FormatUint(since, 10)
	}
	recorder := self.fixture.serve(http.MethodGet, path, self.adminToken, nil)
	reply := &protocol.GkmGenerationsReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
		self.t.Fatalf("%s: %d", path, recorder.Code)
	}
	numbers := []uint64{}
	for _, signed := range reply.GetGenerations() {
		rotate := &protocol.GenRotate{}
		if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
			self.t.Fatal(err)
		}
		numbers = append(numbers, rotate.GetGeneration())
	}
	return numbers
}

// QD-1186: a re-form closes the group it re-forms before its form is filed. The old group's closing marker holds the
// form byte for byte, naming the new group, and the closing's verdict is sealed, the form's bytes again; the new
// group stands open.
func TestGkmReformClosesTheGroupItReformsBeforeItsForm(t *testing.T) {
	world := newGkmReformWorld(t, 10)
	form := world.reformBytes(world.groupId, world.oldGroupId, 2)
	if marker, found := world.stored(GkmGroupClosedKey(world.oldGroupId)); !found || !bytes.Equal(marker, form) {
		t.Fatalf("the old group's closing marker is not the re-form's GroupForm")
	}
	closing, err := parseGkmGroupClosing(world.oldGroupId, form, "")
	if err != nil || closing.newGroupId != world.groupId || closing.generation != 2 {
		t.Fatalf("the closing marker names group %s at generation %d: %v", closing.newGroupId, closing.generation, err)
	}
	if verdict, found := world.stored(GkmGroupClosingKey(world.oldGroupId, sha256Of(form))); !found || !bytes.Equal(verdict, form) {
		t.Errorf("the closing's verdict is not sealed")
	}
	if _, found := world.stored(GkmGroupClosedKey(world.groupId)); found {
		t.Errorf("the new group stands closed")
	}
}

// QD-1186's fence, with a re-form's closing marker standing before its form is filed, so the repo's newest form still
// names the group and the guard and the claim's forms check pass: a commit is refused before its PUT; a claim is
// refused 409 with the marker, naming the new group, writing nothing; a generation a claim that started before the
// marker wrote past the closing form's is served by neither GET gen nor the drop key, and no claim of or on it is
// answered 412 or 201; a staged delivery is refused too; and once a void closing empties the marker, the group serves
// that generation as its own and takes claims again.
func TestGkmClosedGroupTakesNoClaimWrapOrCommitAndServesNothingPastItsForm(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	oldGroupId := world.groupId
	marker := world.reformBytes(testId("group-new"), oldGroupId, 1)
	fixture.put("meta-2", GkmGroupClosedKey(oldGroupId), marker)

	staged := world.stageSelfUpdate(1, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 1, false)); recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), marker) {
		t.Errorf("a commit to the closed group: %d", recorder.Code)
	}
	staged.Discard()
	if world.storedEpoch(1) != nil {
		t.Errorf("a commit refused by the fence wrote epoch/1")
	}

	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	recorder := world.postClaim(world.adminToken, 2, claim2)
	if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), marker) {
		t.Fatalf("a claim of the closed group: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(oldGroupId, 2)) != nil {
		t.Fatalf("a claim that started once the marker stood wrote gen/2")
	}
	// what a claim checked before the marker and created after it leaves, refused by the read after its create
	fixture.put("meta-2", GkmGenerationKey(oldGroupId, 2), fixture.marshal(claim2))
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1}) {
		t.Errorf("GET gen of the closed group serves %v", served)
	}
	if served := world.servedGenerations(oldGroupId, 0, true); !slices.Equal(served, []uint64{1}) {
		t.Errorf("the drop key of the closed group serves %v", served)
	}
	_, rival2 := world.nextGeneration(world.admin, world.key1, nil)
	if recorder := world.postClaim(world.adminToken, 2, rival2); recorder.Code != http.StatusConflict {
		t.Errorf("a rival claim of generation 2 in the closed group: %d", recorder.Code)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusConflict {
		t.Errorf("the refused claim sent again: %d", recorder.Code)
	}
	key3, claim3 := world.nextGeneration(world.admin, key2, nil)
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusConflict {
		t.Errorf("a claim on top of the refused one: %d", recorder.Code)
	}
	reader := world.newReader("sc-reader")
	key4, _ := world.nextGeneration(world.admin, key3, nil)
	delivery := world.readerWrap(world.admin, key4, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, fakeGkmPin(10), fixture.clock.Now())
	if code := world.postWrap(world.adminToken, 4, gkmTestC8(key4), delivery); code != http.StatusConflict {
		t.Errorf("a staged delivery to the closed group: %d", code)
	}

	if fixture.object("meta-2", GkmGenerationKey(oldGroupId, 3)) != nil {
		t.Errorf("a claim on top of the refused generation wrote gen/3")
	}

	// a void closing opens the group again: what the refused claim wrote is the group's, its claimer's same bytes are
	// answered as won, and a claim on it lands
	world.emptyClosingMarker(oldGroupId)
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("GET gen of the group opened again serves %v", served)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Errorf("the claim of generation 2 sent again once the group is open: %d", recorder.Code)
	}
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusCreated {
		t.Errorf("a claim of the group opened again: %d", recorder.Code)
	}
}

// QD-1186: a re-form drafted before a claim of the group it re-forms landed carries a generation behind the group's.
// It is refused 409 with the generation it does not carry, its closing comes to void, which empties the marker, and
// the group takes claims again; the same request sent again answers the same. A re-form at the group's newest
// generation then stands, its ladder carrying every generation the old group took byte for byte, so the two groups
// never hold two generations of one number.
func TestGkmReformTheGroupMovedPastIsRefusedAndOpensItAgain(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim of generation 2: %d", recorder.Code)
	}
	staleGroupId := testId("group-stale")
	staleForm := world.reformBytes(staleGroupId, oldGroupId, 1)
	for range 2 {
		recorder := world.postReform(staleGroupId, oldGroupId, 1)
		if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), fixture.marshal(claim2)) {
			t.Fatalf("a re-form at generation 1 of a group at generation 2: %d", recorder.Code)
		}
		if marker, found := world.stored(GkmGroupClosedKey(oldGroupId)); !found || len(marker) != 0 {
			t.Errorf("the void closing left the marker %x", marker)
		}
		if verdict, found := world.stored(GkmGroupClosingKey(oldGroupId, sha256Of(staleForm))); !found || len(verdict) != 0 {
			t.Errorf("the stale form's closing is not void")
		}
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 2)) != nil {
		t.Fatalf("the stale form was filed")
	}
	key3, claim3 := world.nextGeneration(world.admin, key2, nil)
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusCreated {
		t.Fatalf("a claim of the group opened again: %d", recorder.Code)
	}

	newGroupId := testId("group-reformed")
	if recorder := world.postReform(newGroupId, oldGroupId, 3); recorder.Code != http.StatusOK {
		t.Fatalf("a re-form at the group's newest generation: %d", recorder.Code)
	}
	if marker, _ := world.stored(GkmGroupClosedKey(oldGroupId)); !bytes.Equal(marker, world.reformBytes(newGroupId, oldGroupId, 3)) {
		t.Errorf("the standing re-form did not take the marker the void closing left")
	}
	world.groupId = newGroupId
	if recorder := world.postLadder(world.adminToken, world.rotate1, claim2, claim3); recorder.Code != http.StatusOK {
		t.Fatalf("the ladder of generations 1 to 3: %d", recorder.Code)
	}
	for generation := uint64(1); generation <= 3; generation += 1 {
		carried := fixture.object("meta-2", GkmGenerationKey(newGroupId, generation))
		if carried == nil || !bytes.Equal(carried, fixture.object("meta-2", GkmGenerationKey(oldGroupId, generation))) {
			t.Errorf("the new group does not carry the old group's generation %d byte for byte", generation)
		}
	}
	_, claim4 := world.nextGenerationIn(newGroupId, key3)
	if recorder := world.postClaim(world.adminToken, 4, claim4); recorder.Code != http.StatusCreated {
		t.Errorf("the new group's first claim past its ladder: %d", recorder.Code)
	}
}

// QD-1186: another re-form finding the group's closing marker under way, or sealed, answers 409 with that closing's
// form, which its client reads as another re-form standing (ErrGkmWait); a closing that came to nothing gives way, and
// so does one with no verdict yet whose form the group has moved past, which the second re-form voids, as that
// closing's own request would, before it takes the marker.
func TestGkmSecondReformAnswersAClosingUnderWayAndTakesOneThatCameToNothing(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	oldGroupId := world.groupId
	firstForm := world.reformBytes(testId("group-first"), oldGroupId, 1)
	fixture.put("meta-2", GkmGroupClosedKey(oldGroupId), firstForm)
	secondGroupId := testId("group-second")
	if recorder := world.postReform(secondGroupId, oldGroupId, 1); recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), firstForm) {
		t.Errorf("a re-form beside a closing under way: %d", recorder.Code)
	}
	firstVerdictKey := GkmGroupClosingKey(oldGroupId, sha256Of(firstForm))
	if _, found := world.stored(firstVerdictKey); found {
		t.Errorf("the second re-form decided the first's closing, whose form the group has not moved past")
	}
	fixture.put("meta-2", firstVerdictKey, firstForm)
	if recorder := world.postReform(secondGroupId, oldGroupId, 1); recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), firstForm) {
		t.Errorf("a re-form beside a sealed closing: %d", recorder.Code)
	}

	// a claim the fence refused left generation 2 in the group; a re-form under way at generation 1 then cannot be
	// sealed, so a re-form at generation 2 voids it and stands
	staleWorld := newGkmCommitWorld(t)
	staleFixture := staleWorld.fixture
	staleForm := staleWorld.reformBytes(testId("group-first"), staleWorld.groupId, 1)
	staleFixture.put("meta-2", GkmGroupClosedKey(staleWorld.groupId), staleForm)
	_, claim2 := staleWorld.nextGeneration(staleWorld.admin, staleWorld.key1, nil)
	staleFixture.put("meta-2", GkmGenerationKey(staleWorld.groupId, 2), staleFixture.marshal(claim2))
	reformedGroupId := testId("group-reformed")
	if recorder := staleWorld.postReform(reformedGroupId, staleWorld.groupId, 2); recorder.Code != http.StatusOK {
		t.Fatalf("a re-form at generation 2 beside a closing at generation 1: %d", recorder.Code)
	}
	if verdict, found := staleWorld.stored(GkmGroupClosingKey(staleWorld.groupId, sha256Of(staleForm))); !found || len(verdict) != 0 {
		t.Errorf("the closing at generation 1 was not voided")
	}
	if marker, _ := staleWorld.stored(GkmGroupClosedKey(staleWorld.groupId)); !bytes.Equal(marker, staleWorld.reformBytes(reformedGroupId, staleWorld.groupId, 2)) {
		t.Errorf("the re-form at generation 2 does not hold the marker")
	}

	// a closing that came to nothing gives way at once
	voidWorld := newGkmCommitWorld(t)
	voidForm := voidWorld.reformBytes(testId("group-first"), voidWorld.groupId, 1)
	voidWorld.fixture.put("meta-2", GkmGroupClosedKey(voidWorld.groupId), voidForm)
	voidWorld.fixture.put("meta-2", GkmGroupClosingKey(voidWorld.groupId, sha256Of(voidForm)), []byte{})
	if recorder := voidWorld.postReform(secondGroupId, voidWorld.groupId, 1); recorder.Code != http.StatusOK {
		t.Errorf("a re-form beside a void closing: %d", recorder.Code)
	}
}

// A re-form request sent again after its form stood is the same answer, whatever the old group holds past it: the
// fence ran before the form, and voids no closing whose form is filed. A try that finds its closing sealed but its form
// not yet filed files it, though a claim the fence refused stands past its generation.
func TestGkmReformTryFollowsItsSealedClosingPastAClaimTheFenceRefused(t *testing.T) {
	world := newGkmReformWorld(t, 10)
	fixture := world.fixture
	form := world.reformBytes(world.groupId, world.oldGroupId, 2)
	_, orphan := world.nextGeneration(world.admin, world.key2, nil)
	fixture.put("meta-2", GkmGenerationKey(world.oldGroupId, 3), fixture.marshal(orphan))
	if recorder := world.postReform(world.groupId, world.oldGroupId, 2); recorder.Code != http.StatusOK {
		t.Errorf("the re-form sent again after its form stood: %d", recorder.Code)
	}
	if marker, _ := world.stored(GkmGroupClosedKey(world.oldGroupId)); !bytes.Equal(marker, form) {
		t.Errorf("the re-form sent again moved the marker of its filed form")
	}
	if served := world.servedGenerations(world.oldGroupId, 0, false); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("GET gen of the re-formed group serves %v", served)
	}

	sealedWorld := newGkmCommitWorld(t)
	sealedFixture := sealedWorld.fixture
	sealedGroupId := testId("group-sealed")
	sealedForm := sealedWorld.reformBytes(sealedGroupId, sealedWorld.groupId, 1)
	sealedFixture.put("meta-2", GkmGroupClosedKey(sealedWorld.groupId), sealedForm)
	sealedFixture.put("meta-2", GkmGroupClosingKey(sealedWorld.groupId, sha256Of(sealedForm)), sealedForm)
	_, claim2 := sealedWorld.nextGeneration(sealedWorld.admin, sealedWorld.key1, nil)
	sealedFixture.put("meta-2", GkmGenerationKey(sealedWorld.groupId, 2), sealedFixture.marshal(claim2))
	if recorder := sealedWorld.postReform(sealedGroupId, sealedWorld.groupId, 1); recorder.Code != http.StatusOK {
		t.Fatalf("a try whose closing is sealed: %d", recorder.Code)
	}
	if !bytes.Equal(sealedFixture.object("meta-2", GkmFormKey(sealedWorld.repoId, 2)), sealedForm) {
		t.Errorf("the sealed closing's form was not filed")
	}
}
