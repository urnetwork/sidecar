package gkmservice

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world a group test runs in: one repo on the second cluster, keying, its admin's member device, the fake log
// at position 10 with its previous base at 1, and the group's id.
type gkmGroupWorld struct {
	t          *testing.T
	fixture    *gkmFixture
	repoId     sidecar.Id
	groupId    sidecar.Id
	memberId   sidecar.Id
	admin      *gkmTestSidecar
	adminToken string
	// generation 1 of the group, once createRequest drew it
	key1    *sidecar.EvsRepoKey
	rotate1 *bridge.Signed
	// the admin's MLS group, once mlsGroup made it
	mls      sidecar.MlsEngine
	mlsGroup sidecar.MlsGroup
}

func newGkmGroupWorld(t *testing.T) *gkmGroupWorld {
	fixture := newGkmFixture(t)
	fixture.auth.advanceLog(10, 1)
	world := &gkmGroupWorld{
		t:        t,
		fixture:  fixture,
		repoId:   testId("repo-g"),
		groupId:  testId("group-g"),
		memberId: testId("member-a"),
	}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_KEYING)
	world.admin = fixture.newSidecar("sc-admin", memberDeviceFacts(world.memberId))
	fixture.auth.grant(world.admin.sidecarId, world.repoId, sidecar.AclEvsAdmin)
	world.adminToken = fixture.token(world.admin.sidecarId, repoScope(world.repoId, "admin"))
	return world
}

// A Signed GroupForm of the world's repo by signer.
func (self *gkmGroupWorld) form(signer *gkmTestSidecar, groupId sidecar.Id, previousGroupId *sidecar.Id, generation uint64) *bridge.Signed {
	self.t.Helper()
	body := &protocol.GroupForm{RepoId: self.repoId.Bytes(), GroupId: groupId.Bytes(), Generation: generation}
	if previousGroupId != nil {
		body.PreviousGroupId = previousGroupId.Bytes()
	}
	signed, err := signer.sign(gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, self.fixture.marshal(body), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// A synthetic holders hash: gkm never recomputes it.
func gkmTestHoldersSha256() []byte {
	holders := sha256.Sum256([]byte("holders"))
	return holders[:]
}

// Generation 1 of groupId, signed by signer at at and pin.
func (self *gkmGroupWorld) firstGeneration(signer *gkmTestSidecar, groupId sidecar.Id, at time.Time, pin *bridge.AuthPin) (*sidecar.EvsRepoKey, *bridge.Signed) {
	self.t.Helper()
	key, rotate, err := sidecar.NewGkmFirstGeneration(self.repoId, groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          pin,
		Time:          at,
		HoldersSha256: gkmTestHoldersSha256(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return key, signed
}

// KF1's request for groupId by the admin, generation 1 at the fake log's position 10.
func (self *gkmGroupWorld) createRequest(groupId sidecar.Id) *protocol.GkmGroupCreateRequest {
	self.t.Helper()
	self.key1, self.rotate1 = self.firstGeneration(self.admin, groupId, self.fixture.clock.Now(), fakeGkmPin(10))
	return &protocol.GkmGroupCreateRequest{
		Form:            self.form(self.admin, groupId, nil, 1),
		GenRotate:       self.rotate1,
		GenWrap:         bytes.Repeat([]byte{7}, gkmSealedKeyByteCount),
		SealedGroupInfo: []byte("sealed group info of epoch 0"),
		CipherSuite:     gkmCipherSuiteXWing,
	}
}

// POST /gkm/groups with the admin's token.
func (self *gkmGroupWorld) postCreate(request *protocol.GkmGroupCreateRequest) *httptest.ResponseRecorder {
	return self.fixture.serve(http.MethodPost, "/gkm/groups", self.adminToken, self.fixture.marshal(request))
}

// Creates the world's group and activates the repo, as KF1 does once its first wraps exist.
func (self *gkmGroupWorld) createAndActivate() {
	self.t.Helper()
	if recorder := self.postCreate(self.createRequest(self.groupId)); recorder.Code != http.StatusOK {
		self.t.Fatalf("a group's creation: %d", recorder.Code)
	}
	self.fixture.setRepoState(self.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
}

// Sets repo/'s state as evs would, by If-Match, and lets the engine's 5 s cache of it lapse.
func (self *gkmFixture) setRepoState(repoId sidecar.Id, clusterId string, state protocol.EvsRepoState) {
	self.t.Helper()
	cluster := self.cluster(clusterId)
	held, info, err := readGkmObject(self.ctx, cluster, GkmEvsRepoKey(repoId), gkmEvsRepoMaxByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(held, object); err != nil {
		self.t.Fatal(err)
	}
	object.State = state
	if _, err := cluster.PutIfMatch(self.ctx, GkmEvsRepoKey(repoId), info.Etag, self.marshal(object), nil); err != nil {
		self.t.Fatal(err)
	}
	self.clock.Advance(self.settings.RepoCacheTtl)
}

// The member device's real MLS engine, taking every credential another leaf brings: gkm's state is what the test
// says, and members' own checks are not under test here.
func (self *gkmTestSidecar) acceptingMlsEngine(t *testing.T, clock sidecar.Clock) sidecar.MlsEngine {
	t.Helper()
	admission := sha256.Sum256(append([]byte("admission of "), self.sidecarId.Bytes()...))
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.publicKey,
		AdmissionSha256:   admission[:],
		Sign:              self.sign,
		Store:             sidecartest.NewFakeStore().Root(),
		CheckCredential:   func(credential *protocol.UrMlsCredential) error { return nil },
		Clock:             clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// The admin's MLS group of the world's group, at epoch 0.
func (self *gkmGroupWorld) startMlsGroup() {
	self.t.Helper()
	self.mls = self.admin.acceptingMlsEngine(self.t, self.fixture.clock)
	group, err := self.mls.CreateGroup(self.groupId, &sidecar.MlsUrGroup{
		NetworkId: sidecar.Id(self.fixture.networkId),
		RepoId:    self.repoId,
		Kind:      protocol.RepoKind_REPO_KIND_GENERAL,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.mlsGroup = group
}

// A GkmCommitHeader's encoding.
func gkmTestCommitHeader(t *testing.T, generation uint64, pin *bridge.AuthPin) []byte {
	t.Helper()
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: generation, Auth: pin})
	if err != nil {
		t.Fatal(err)
	}
	return header
}

// A self-update staged on the admin's group, carrying the header.
func (self *gkmGroupWorld) stageSelfUpdate(generation uint64, pin *bridge.AuthPin) sidecar.MlsStagedCommit {
	self.t.Helper()
	staged, err := self.mlsGroup.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: gkmTestCommitHeader(self.t, generation, pin)})
	if err != nil {
		self.t.Fatal(err)
	}
	return staged
}

// The epoch request of a commit: a 72-byte GenWrap unless generation is 0, and with sealed a GroupInfo sealed under
// generation's key.
func gkmTestEpochRequest(commit []byte, generation uint64, sealed bool) *protocol.GkmEpochRequest {
	request := &protocol.GkmEpochRequest{Commit: commit}
	if generation != 0 {
		request.GenWrap = bytes.Repeat([]byte{9}, gkmSealedKeyByteCount)
	}
	if sealed {
		request.SealedGroupInfo = []byte("a sealed GroupInfo")
		request.GroupInfoGeneration = max(1, generation)
	}
	return request
}

// POST epochs/<epoch> with token.
func (self *gkmGroupWorld) postEpoch(token string, epoch uint64, request *protocol.GkmEpochRequest) *httptest.ResponseRecorder {
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/epochs/" + strconv.FormatUint(epoch, 10)
	return self.fixture.serve(http.MethodPost, path, token, self.fixture.marshal(request))
}

// Commits a self-update at generation and the log's position 10, with or without a sealed GroupInfo, expecting 200,
// and adopts it.
func (self *gkmGroupWorld) commitAndAdopt(generation uint64, sealed bool) {
	self.t.Helper()
	staged := self.stageSelfUpdate(generation, fakeGkmPin(10))
	recorder := self.postEpoch(self.adminToken, staged.Epoch(), gkmTestEpochRequest(staged.Message(), generation, sealed))
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("a commit to epoch %d: %d", staged.Epoch(), recorder.Code)
	}
	group, err := staged.Adopt()
	if err != nil {
		self.t.Fatal(err)
	}
	self.mlsGroup = group
}

// The stored epoch object, or nil.
func (self *gkmGroupWorld) storedEpoch(epoch uint64) *protocol.GkmEpochObject {
	self.t.Helper()
	objectBytes := self.fixture.object("meta-2", GkmEpochKey(self.groupId, epoch))
	if objectBytes == nil {
		return nil
	}
	object, err := parseGkmEpochObject(objectBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	return object
}

// Writes gen/<g> of the world's group in the store as a claim would have, signed by signer, its parent key parent.
func (self *gkmGroupWorld) putGeneration(signer *gkmTestSidecar, parent *sidecar.EvsRepoKey) (*sidecar.EvsRepoKey, *bridge.Signed) {
	self.t.Helper()
	key, rotate, err := parent.NextGeneration(&sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRemove,
		Auth:          fakeGkmPin(10),
		Time:          self.fixture.clock.Now(),
		HoldersSha256: gkmTestHoldersSha256(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	self.fixture.put("meta-2", GkmGenerationKey(self.groupId, key.Generation()), self.fixture.marshal(signed))
	return key, signed
}

// KF1: a creation writes the GroupForm, epoch/0 and gen/1 on the repo's cluster, and the group reads back by both
// routes.
func TestGkmGroupCreateWritesItsFormEpochZeroAndFirstGeneration(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	request := world.createRequest(world.groupId)
	if recorder := world.postCreate(request); recorder.Code != http.StatusOK {
		t.Fatalf("a creation: %d", recorder.Code)
	}
	if held := fixture.object("meta-2", GkmFormKey(world.repoId, 1)); !bytes.Equal(held, fixture.marshal(request.GetForm())) {
		t.Errorf("the form at seq 1 holds other bytes")
	}
	if held := fixture.object("meta-2", GkmGenerationKey(world.groupId, 1)); !bytes.Equal(held, fixture.marshal(world.rotate1)) {
		t.Errorf("gen/1 holds other bytes")
	}
	epochZero := world.storedEpoch(0)
	if epochZero == nil {
		t.Fatal("no epoch/0")
	}
	if epochZero.GetHeader().GetGeneration() != 1 || !proto.Equal(epochZero.GetHeader().GetAuth(), fakeGkmPin(10)) ||
		!bytes.Equal(epochZero.GetUploader(), world.admin.sidecarId.Bytes()) ||
		!bytes.Equal(epochZero.GetNetworkId(), fixture.networkId.Bytes()) || epochZero.GetCipherSuite() != gkmCipherSuiteXWing ||
		len(epochZero.GetCommit()) != 0 || epochZero.GetGroupInfoGeneration() != 1 {
		t.Errorf("epoch/0 as stored: %v", epochZero)
	}
	if fixture.object("meta-1", GkmEpochKey(world.groupId, 0)) != nil {
		t.Errorf("a group object on the first cluster, not the repo's")
	}
	readerToken := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "r"))
	recorder := fixture.serve(http.MethodGet, "/gkm/groups/"+sidecar.EvsKeyId(world.groupId), readerToken, nil)
	reply := &protocol.GkmGroupReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil || !proto.Equal(reply.GetForm(), request.GetForm()) {
		t.Errorf("GET the group: %d", recorder.Code)
	}
	recorder = fixture.serve(http.MethodGet, "/gkm/repos/"+sidecar.EvsKeyId(world.repoId)+"/forms", readerToken, nil)
	forms := &protocol.GkmFormsReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), forms) != nil || len(forms.GetForms()) != 1 {
		t.Errorf("GET the forms: %d", recorder.Code)
	}
}

// QD-464: a creation whose answer was lost, or that crashed between its writes, is sent again and finishes; nothing
// is written twice.
func TestGkmGroupCreateResumesAfterACrash(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	request := world.createRequest(world.groupId)
	// both of the create's sends fail, so the request answers 503 with gen/1 unwritten
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpPut,
		KeyPrefix: GkmGenerationKey(world.groupId, 1),
		Result:    sidecartest.FailBeforeApply,
		Repeat:    1,
	}); err != nil {
		t.Fatal(err)
	}
	if recorder := world.postCreate(request); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a creation whose gen/1 PUT failed: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 1)) != nil {
		t.Fatal("gen/1 written by the failed PUT")
	}
	fixture.clock.Advance(time.Second)
	if recorder := world.postCreate(request); recorder.Code != http.StatusOK {
		t.Fatalf("the creation sent again: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 1)) == nil || world.storedEpoch(0) == nil {
		t.Errorf("the retry did not finish the creation")
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 2)) != nil {
		t.Errorf("the retry filed a second form")
	}
	if recorder := world.postCreate(request); recorder.Code != http.StatusOK {
		t.Errorf("a third send of the finished creation: %d", recorder.Code)
	}
}

// DESIGN-DETAILS 6.6: a group belongs to one repo from its first byte. A form for repo b naming repo a's group
// answers 409 at the owner marker and writes nothing, even in the race where a's creation has written only its
// marker; equal bytes resume a's crashed creation; a form of b that names a's group in the store reaches none of
// a's routes with a b-scoped token; and the shred deletes the marker with the group's other objects.
func TestAGroupBelongsToOneRepo(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	// a's creation crashed after its first write: only the marker stands
	ownerBytes, err := gkmGroupOwnerBytes(world.repoId, sidecar.Id(fixture.networkId))
	if err != nil {
		t.Fatal(err)
	}
	fixture.put("meta-2", GkmGroupOwnerKey(world.groupId), ownerBytes)
	otherRepoId := testId("repo-other")
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_KEYING)
	fixture.auth.grant(world.admin.sidecarId, otherRepoId, sidecar.AclEvsAdmin)
	otherToken := fixture.token(world.admin.sidecarId, repoScope(otherRepoId, "admin"))
	other := &gkmGroupWorld{t: t, fixture: fixture, repoId: otherRepoId, groupId: world.groupId, admin: world.admin, adminToken: otherToken}
	if recorder := other.postCreate(other.createRequest(world.groupId)); recorder.Code != http.StatusConflict {
		t.Errorf("a form for another repo naming the group, before the group's first form: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmFormKey(otherRepoId, 1)) != nil || fixture.object("meta-2", GkmEpochKey(world.groupId, 0)) != nil ||
		fixture.object("meta-2", GkmGenerationKey(world.groupId, 1)) != nil {
		t.Errorf("the refused creation wrote something")
	}
	if held := fixture.object("meta-2", GkmGroupOwnerKey(world.groupId)); !bytes.Equal(held, ownerBytes) {
		t.Errorf("the marker changed")
	}
	// equal bytes resume the crashed creation
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("the owner's creation resumed: %d", recorder.Code)
	}
	// a form of the other repo naming the group, written past gkm's checks, resolves nothing
	formBody := fixture.marshal(&protocol.GroupForm{RepoId: otherRepoId.Bytes(), GroupId: world.groupId.Bytes(), Generation: 1})
	fixture.put("meta-2", GkmFormKey(otherRepoId, 1), fixture.marshal(&bridge.Signed{
		Body: formBody, SignerId: world.admin.sidecarId.Bytes(), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM),
	}))
	groupPath := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId)
	for _, path := range []string{groupPath, groupPath + "/epochs?after=0", groupPath + "/gen?since=0"} {
		if recorder := fixture.serve(http.MethodGet, path, otherToken, nil); recorder.Code != http.StatusForbidden {
			t.Errorf("GET %s with the other repo's token: %d", path, recorder.Code)
		}
	}
	if recorder := other.postEpoch(otherToken, 1, gkmTestEpochRequest([]byte("a commit"), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit to the group with the other repo's token: %d", recorder.Code)
	}
	ownerToken := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "r"))
	if recorder := fixture.serve(http.MethodGet, groupPath, ownerToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("GET the group with its repo's token: %d", recorder.Code)
	}
	// the shred deletes the marker with the group's other objects
	if err := ShredGroup(fixture.ctx, fixture.host.ServiceHost(), fixture.cluster("meta-2"), world.repoId, true, fixture.settings); err != nil {
		t.Fatal(err)
	}
	if fixture.object("meta-2", GkmGroupOwnerKey(world.groupId)) != nil {
		t.Errorf("the shred left the owner marker")
	}
}

// A creation is a repo's first form, and no form names a group another repo owns: the owner marker answers 409
// before anything is written (DESIGN-DETAILS 6.2.2).
func TestGkmGroupCreateRefusesASecondGroupAndATakenGroup(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("a creation: %d", recorder.Code)
	}
	recorder := world.postCreate(world.createRequest(testId("group-second")))
	if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), fixture.object("meta-2", GkmFormKey(world.repoId, 1))) {
		t.Errorf("a second group of the repo: %d", recorder.Code)
	}
	// another repo on the same cluster, whose admin names the first repo's group
	otherRepoId := testId("repo-other")
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_KEYING)
	fixture.auth.grant(world.admin.sidecarId, otherRepoId, sidecar.AclEvsAdmin)
	other := &gkmGroupWorld{t: t, fixture: fixture, repoId: otherRepoId, groupId: world.groupId, admin: world.admin,
		adminToken: fixture.token(world.admin.sidecarId, repoScope(otherRepoId, "admin"))}
	if recorder := other.postCreate(other.createRequest(world.groupId)); recorder.Code != http.StatusConflict {
		t.Errorf("a form naming another repo's group: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmFormKey(otherRepoId, 1)) != nil {
		t.Errorf("the refused form was filed")
	}
}

// §10.6's signer rule and the claim checks gen/1 can meet: a form its uploader did not sign, a gen/1 by a parked
// signer, out of gkm's clock skew or at a pin gkm has not reached, are refused, and nothing is written.
func TestGkmGroupCreateRefusesWhatItsChecksDoNotPass(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	other := fixture.newSidecar("sc-other", memberDeviceFacts(world.memberId))
	parked := fixture.newSidecar("sc-parked", memberDeviceFacts(world.memberId))
	fixture.auth.update(parked.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = true })

	request := world.createRequest(world.groupId)
	request.Form = world.form(other, world.groupId, nil, 1)
	if recorder := world.postCreate(request); recorder.Code != http.StatusForbidden {
		t.Errorf("a form another sidecar signed: %d", recorder.Code)
	}
	request = world.createRequest(world.groupId)
	_, request.GenRotate = world.firstGeneration(parked, world.groupId, fixture.clock.Now(), fakeGkmPin(10))
	if recorder := world.postCreate(request); recorder.Code != http.StatusForbidden {
		t.Errorf("gen/1 by a parked signer: %d", recorder.Code)
	}
	request = world.createRequest(world.groupId)
	_, request.GenRotate = world.firstGeneration(world.admin, world.groupId, fixture.clock.Now().Add(11*time.Minute), fakeGkmPin(10))
	if recorder := world.postCreate(request); recorder.Code != http.StatusForbidden {
		t.Errorf("gen/1 eleven minutes ahead: %d", recorder.Code)
	}
	request = world.createRequest(world.groupId)
	_, request.GenRotate = world.firstGeneration(world.admin, world.groupId, fixture.clock.Now(), fakeGkmPin(11))
	if recorder := world.postCreate(request); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("gen/1 at a pin past gkm's state: %d", recorder.Code)
	}
	request = world.createRequest(world.groupId)
	request.CipherSuite = 0x0001
	if recorder := world.postCreate(request); recorder.Code != http.StatusBadRequest {
		t.Errorf("a creation under another cipher suite: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 1)) != nil || world.storedEpoch(0) != nil {
		t.Errorf("a refused creation wrote")
	}
}

// §10.8: a re-form files the repo's next form, naming its newest group, and the new group's epoch/0 with the form's
// generation and no auth pin; a re-form naming another group as its previous one is refused, and a commit onto the
// pinless epoch 0 is refused until question keys-wire-reform-epoch-zero is answered.
func TestGkmReformFilesTheNextFormAndAPinlessEpochZero(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	world.createAndActivate()
	newGroupId := testId("group-reformed")
	reform := func(previousGroupId sidecar.Id) *httptest.ResponseRecorder {
		request := &protocol.GkmGroupReformRequest{
			Form:            world.form(world.admin, newGroupId, &previousGroupId, 1),
			GenWrap:         bytes.Repeat([]byte{5}, gkmSealedKeyByteCount),
			SealedGroupInfo: []byte("sealed group info of the re-formed epoch 0"),
			CipherSuite:     gkmCipherSuiteXWing,
		}
		path := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/forms"
		return fixture.serve(http.MethodPost, path, world.adminToken, fixture.marshal(request))
	}
	if recorder := reform(testId("group-elsewhere")); recorder.Code != http.StatusConflict {
		t.Errorf("a re-form naming another previous group: %d", recorder.Code)
	}
	if recorder := reform(world.groupId); recorder.Code != http.StatusOK {
		t.Fatalf("a re-form: %d", recorder.Code)
	}
	if recorder := reform(world.groupId); recorder.Code != http.StatusOK {
		t.Errorf("the re-form sent again: %d", recorder.Code)
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 2)) == nil || fixture.object("meta-2", GkmFormKey(world.repoId, 3)) != nil {
		t.Errorf("the re-form's form is not the repo's second, once")
	}
	held := fixture.object("meta-2", GkmEpochKey(newGroupId, 0))
	epochZero, err := parseGkmEpochObject(held)
	if err != nil || epochZero.GetHeader().GetGeneration() != 1 || epochZero.GetHeader().GetAuth() != nil {
		t.Fatalf("the re-formed epoch 0: %v", err)
	}
	world.groupId = newGroupId
	world.startMlsGroup()
	staged := world.stageSelfUpdate(1, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit onto the pinless epoch 0: %d", recorder.Code)
	}
}
