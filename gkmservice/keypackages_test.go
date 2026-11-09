package gkmservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A world for KeyPackages: one active repo with a group, a target member device that reads it, and a writer that
// claims for it.
type gkmKeyPackageWorld struct {
	fixture *gkmFixture
	repoId  sidecar.Id
	groupId sidecar.Id
	target  *gkmTestSidecar
	engine  sidecar.MlsEngine
	writer  sidecar.Id
	// the target's own token, and the writer's
	targetToken string
	writerToken string
}

func newGkmKeyPackageWorld(t *testing.T, adjust func(settings *GkmServiceSettings)) *gkmKeyPackageWorld {
	fixture := newGkmFixtureWith(t, func(settings *GkmServiceSettings, deps *GkmEngineDeps) {
		if adjust != nil {
			adjust(settings)
		}
	})
	world := &gkmKeyPackageWorld{fixture: fixture, repoId: testId("repo-r"), groupId: testId("group-g"), writer: testId("sc-writer")}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(world.repoId, "meta-2", 1, world.groupId)
	world.target = fixture.newSidecar("sc-target", memberDeviceFacts(testId("member-t")))
	fixture.auth.grant(world.target.sidecarId, world.repoId, sidecar.AclEvsRead)
	world.engine = world.target.mlsEngine(t, fixture.clock)
	fixture.auth.admit(world.writer, memberDeviceFacts(testId("member-w")))
	fixture.auth.grant(world.writer, world.repoId, sidecar.AclEvsWrite)
	world.targetToken = fixture.token(world.target.sidecarId, repoScope(world.repoId, "r"))
	world.writerToken = fixture.token(world.writer, repoScope(world.repoId, "rw"))
	fixture.clientOf(world.target.sidecarId)
	fixture.clientOf(world.writer)
	return world
}

// count KeyPackages of the target's, one-time unless lastResort.
func (self *gkmKeyPackageWorld) keyPackages(count int, lastResort bool) []*sidecar.MlsKeyPackage {
	self.fixture.t.Helper()
	keyPackages := []*sidecar.MlsKeyPackage{}
	for i := 0; i < count; i += 1 {
		keyPackage, err := self.engine.CreateKeyPackage(lastResort)
		if err != nil {
			self.fixture.t.Fatal(err)
		}
		keyPackages = append(keyPackages, keyPackage)
	}
	return keyPackages
}

// POST /gkm/key-packages of keyPackages under token.
func (self *gkmKeyPackageWorld) upload(token string, keyPackages []*sidecar.MlsKeyPackage) *httptest.ResponseRecorder {
	request := &protocol.GkmKeyPackagesRequest{}
	for _, keyPackage := range keyPackages {
		request.KeyPackages = append(request.KeyPackages, keyPackage.Encoded)
	}
	return self.fixture.serve(http.MethodPost, "/gkm/key-packages", token, self.fixture.marshal(request))
}

// POST /gkm/key-packages/claim for the target under token, its reply when 200.
func (self *gkmKeyPackageWorld) claim(token string) (int, *protocol.GkmKeyPackageClaimReply) {
	self.fixture.t.Helper()
	body := self.fixture.marshal(&protocol.GkmKeyPackageClaimRequest{GroupId: self.groupId.Bytes(), Target: self.target.sidecarId.Bytes()})
	recorder := self.fixture.serve(http.MethodPost, "/gkm/key-packages/claim", token, body)
	if recorder.Code != http.StatusOK {
		return recorder.Code, nil
	}
	reply := &protocol.GkmKeyPackageClaimReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		self.fixture.t.Fatal(err)
	}
	return recorder.Code, reply
}

// The key of the target's KeyPackage ref.
func (self *gkmKeyPackageWorld) key(ref []byte) string {
	self.fixture.t.Helper()
	key, err := GkmKeyPackageKey(self.target.sidecarId, ref)
	if err != nil {
		self.fixture.t.Fatal(err)
	}
	return key
}

// The claim stored for a ref.
func (self *gkmKeyPackageWorld) claimOf(ref []byte) *protocol.GkmKeyPackageClaim {
	self.fixture.t.Helper()
	claimBytes := self.fixture.object("meta-1", self.key(ref)+gkmKeyPackageClaimKeySuffix)
	if claimBytes == nil {
		return nil
	}
	claim := &protocol.GkmKeyPackageClaim{}
	if err := proto.Unmarshal(claimBytes, claim); err != nil {
		self.fixture.t.Fatal(err)
	}
	return claim
}

// Uploads land on the first cluster, each at its ref; a sidecar's first upload hints pending to who adds it, naming
// the repo's group, and a later one hints nothing more.
func TestGkmKeyPackageUploadLandsOnTheFirstClusterAndHintsItsFirst(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	fixture.auth.setPendingTargets(world.target.sidecarId, []*GkmPendingTarget{{RepoId: world.repoId, SidecarIds: []sidecar.Id{world.writer}}})
	keyPackages := append(world.keyPackages(3, false), world.keyPackages(1, true)...)
	if recorder := world.upload(world.targetToken, keyPackages); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	for _, keyPackage := range keyPackages {
		if !bytes.Equal(fixture.object("meta-1", world.key(keyPackage.Ref)), keyPackage.Encoded) {
			t.Errorf("KeyPackage %x not at its key on the first cluster", keyPackage.Ref[:4])
		}
		if fixture.object("meta-2", world.key(keyPackage.Ref)) != nil {
			t.Error("a KeyPackage on the repo's cluster")
		}
	}
	hints := fixture.hints(world.writer)
	if len(hints) != 1 || hints[0].GetKind() != protocol.GkmHintKind_GKM_HINT_PENDING || !bytes.Equal(hints[0].GetGroupId(), world.groupId.Bytes()) {
		t.Fatalf("the first upload's hints: %v", hints)
	}
	if recorder := world.upload(world.targetToken, world.keyPackages(1, false)); recorder.Code != http.StatusOK {
		t.Fatalf("a second upload: %d", recorder.Code)
	}
	if hints := fixture.hints(world.writer); len(hints) != 1 {
		t.Errorf("a second upload hinted again: %v", hints)
	}
	// a retry of the same bytes is the same upload
	if recorder := world.upload(world.targetToken, keyPackages[:1]); recorder.Code != http.StatusOK {
		t.Errorf("a retry: %d", recorder.Code)
	}
}

// KeyPackages only from member devices, each the uploader's own under the identity key the log admits for it.
func TestGkmKeyPackageRefusedFromAnAgentOrUnderAnotherCredential(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	keyPackages := world.keyPackages(1, false)

	// an agent: admitted, reading, tagged
	agent := fixture.newSidecar("sc-agent", &GkmSidecarFacts{})
	fixture.auth.grant(agent.sidecarId, world.repoId, sidecar.AclEvsRead)
	agentEngine := agent.mlsEngine(t, fixture.clock)
	agentKeyPackage, err := agentEngine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	agentToken := fixture.token(agent.sidecarId, repoScope(world.repoId, "r"))
	if recorder := world.upload(agentToken, []*sidecar.MlsKeyPackage{agentKeyPackage}); recorder.Code != http.StatusForbidden {
		t.Errorf("an agent's KeyPackage: %d", recorder.Code)
	}

	// another member device uploading the target's KeyPackage under its own token
	other := fixture.newSidecar("sc-other", memberDeviceFacts(testId("member-o")))
	fixture.auth.grant(other.sidecarId, world.repoId, sidecar.AclEvsRead)
	otherToken := fixture.token(other.sidecarId, repoScope(world.repoId, "r"))
	if recorder := world.upload(otherToken, keyPackages); recorder.Code != http.StatusForbidden {
		t.Errorf("another sidecar's KeyPackage: %d", recorder.Code)
	}

	// the target's own, while the log admits another identity key for it
	fixture.auth.update(world.target.sidecarId, func(facts *GkmSidecarFacts) { facts.IdentityPublicKey = other.publicKey })
	if recorder := world.upload(world.targetToken, keyPackages); recorder.Code != http.StatusForbidden {
		t.Errorf("a credential under a key the log does not admit: %d", recorder.Code)
	}

	// bytes that are no KeyPackage
	fixture.auth.update(world.target.sidecarId, func(facts *GkmSidecarFacts) { facts.IdentityPublicKey = world.target.publicKey })
	if recorder := fixture.serve(http.MethodPost, "/gkm/key-packages", world.targetToken,
		fixture.marshal(&protocol.GkmKeyPackagesRequest{KeyPackages: [][]byte{[]byte("not an MLSMessage")}})); recorder.Code != http.StatusBadRequest {
		t.Errorf("bytes that are no KeyPackage: %d", recorder.Code)
	}
	if keys, _, _ := fixture.cluster("meta-1").List(fixture.ctx, GkmKeyPackagePrefix(world.target.sidecarId), "", 10); len(keys) != 0 {
		t.Errorf("a refused upload stored %d keys", len(keys))
	}
}

// Up to the one-time count per sidecar, beside its last-resort: past it, 429.
func TestGkmKeyPackageUploadPastTheCountRefused(t *testing.T) {
	world := newGkmKeyPackageWorld(t, func(settings *GkmServiceSettings) {
		settings.KeyPackageOneTimeMaxCount = 4
		settings.KeyPackageLowCount = 2
	})
	if recorder := world.upload(world.targetToken, append(world.keyPackages(4, false), world.keyPackages(1, true)...)); recorder.Code != http.StatusOK {
		t.Fatalf("up to the count: %d", recorder.Code)
	}
	if recorder := world.upload(world.targetToken, world.keyPackages(1, false)); recorder.Code != http.StatusTooManyRequests {
		t.Errorf("past the count: %d", recorder.Code)
	}
	// two last-resorts in one upload are refused
	if recorder := world.upload(world.targetToken, world.keyPackages(2, true)); recorder.Code != http.StatusBadRequest {
		t.Errorf("two last-resorts: %d", recorder.Code)
	}
}

// A one-time KeyPackage serves one claim: two claimers take two KeyPackages, and with one left the second claimer
// finds none.
func TestGkmKeyPackageServesOneClaim(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	otherWriter := testId("sc-writer-2")
	fixture.auth.admit(otherWriter, memberDeviceFacts(testId("member-w2")))
	fixture.auth.grant(otherWriter, world.repoId, sidecar.AclEvsWrite)
	otherToken := fixture.token(otherWriter, repoScope(world.repoId, "rw"))
	keyPackages := world.keyPackages(2, false)
	if recorder := world.upload(world.targetToken, keyPackages); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	statusA, replyA := world.claim(world.writerToken)
	statusB, replyB := world.claim(otherToken)
	if statusA != http.StatusOK || statusB != http.StatusOK {
		t.Fatalf("claims: %d %d", statusA, statusB)
	}
	if bytes.Equal(replyA.GetKeyPackageRef(), replyB.GetKeyPackageRef()) {
		t.Fatal("one KeyPackage served two claims")
	}
	for _, reply := range []*protocol.GkmKeyPackageClaimReply{replyA, replyB} {
		if fixture.object("meta-1", world.key(reply.GetKeyPackageRef())) != nil {
			t.Error("a claimed KeyPackage was not deleted")
		}
		if world.claimOf(reply.GetKeyPackageRef()) == nil {
			t.Error("a claim was not recorded")
		}
	}
	if !bytes.Equal(world.claimOf(replyA.GetKeyPackageRef()).GetClaimer(), world.writer.Bytes()) {
		t.Error("the claim names another claimer")
	}
	if status, _ := world.claim(world.writerToken); status != http.StatusNotFound {
		t.Errorf("with none left: %d", status)
	}
}

// §22.5: the claim's If-None-Match decides a race, and the loser takes the next KeyPackage. Here the store answers
// the loser's create as taken, as it does when another claim of the first KeyPackage landed between the loser's
// LIST and its create; sidecar_testhooks's keypackages_race_test.go runs the two claims themselves.
func TestGkmKeyPackageClaimLoserTakesTheNext(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	keyPackages := world.keyPackages(2, false)
	if recorder := world.upload(world.targetToken, keyPackages); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	first := keyPackages[0].Ref
	if bytes.Compare(keyPackages[1].Ref, first) < 0 {
		first = keyPackages[1].Ref
	}
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: world.key(first) + gkmKeyPackageClaimKeySuffix, Result: sidecartest.Precondition,
	}); err != nil {
		t.Fatal(err)
	}
	status, reply := world.claim(world.writerToken)
	if status != http.StatusOK {
		t.Fatalf("the loser's claim: %d", status)
	}
	if bytes.Equal(reply.GetKeyPackageRef(), first) {
		t.Error("the loser was served the KeyPackage another claim holds")
	}
}

// FI-2: a claim whose answer is lost wastes one KeyPackage and breaks nothing: the retry takes the next, and a lost
// answer from the store itself is read back as this claim's.
func TestGkmLostClaimResponseWastesOneAndBreaksNothing(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	if recorder := world.upload(world.targetToken, world.keyPackages(3, false)); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	_, lost := world.claim(world.writerToken)
	_, retried := world.claim(world.writerToken)
	if lost == nil || retried == nil || bytes.Equal(lost.GetKeyPackageRef(), retried.GetKeyPackageRef()) {
		t.Fatal("the retry did not take another KeyPackage")
	}
	if fixture.object("meta-1", world.key(lost.GetKeyPackageRef())) != nil || world.claimOf(lost.GetKeyPackageRef()) == nil {
		t.Error("the wasted KeyPackage is not claimed and gone")
	}
	// the store took the next claim's create and lost its answer: the read back finds this claim's bytes
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: GkmKeyPackagePrefix(world.target.sidecarId), Result: sidecartest.ApplyThenDrop,
	}); err != nil {
		t.Fatal(err)
	}
	status, reply := world.claim(world.writerToken)
	if status != http.StatusOK || world.claimOf(reply.GetKeyPackageRef()) == nil {
		t.Errorf("a claim whose store answer was lost: %d", status)
	}
}

// §10.6: a claim leaving fewer than 32 one-time KeyPackages hints key-packages-low to the target: at 31, not at 32.
func TestGkmKeyPackagesLowHintedAt31AndNotAt32(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	if recorder := world.upload(world.targetToken, world.keyPackages(33, false)); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	lowHints := func() int {
		count := 0
		for _, hint := range fixture.hints(world.target.sidecarId) {
			if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW {
				count += 1
			}
		}
		return count
	}
	if status, _ := world.claim(world.writerToken); status != http.StatusOK {
		t.Fatalf("claim: %d", status)
	}
	if count := lowHints(); count != 0 {
		t.Errorf("at 32 left: %d hints", count)
	}
	if status, _ := world.claim(world.writerToken); status != http.StatusOK {
		t.Fatalf("claim: %d", status)
	}
	if count := lowHints(); count != 1 {
		t.Errorf("at 31 left: %d hints", count)
	}
}

// A claim serves only a target the newest state lists as a reader of the group's repo, at 10 a minute per
// (claimer, target).
func TestGkmKeyPackageClaimNeedsAReaderTargetAndKeepsItsRate(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	if recorder := world.upload(world.targetToken, world.keyPackages(12, false)); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	fixture.auth.drop(world.target.sidecarId, world.repoId)
	if status, _ := world.claim(world.writerToken); status != http.StatusForbidden {
		t.Errorf("a target that reads no more: %d", status)
	}
	fixture.auth.grant(world.target.sidecarId, world.repoId, sidecar.AclEvsRead)
	// the refused claim spent one of the minute's ten
	for i := 0; i < 9; i += 1 {
		if status, _ := world.claim(world.writerToken); status != http.StatusOK {
			t.Fatalf("claim %d: %d", i, status)
		}
	}
	recorder := fixture.serve(http.MethodPost, "/gkm/key-packages/claim", world.writerToken,
		fixture.marshal(&protocol.GkmKeyPackageClaimRequest{GroupId: world.groupId.Bytes(), Target: world.target.sidecarId.Bytes()}))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Errorf("the eleventh in a minute: %d", recorder.Code)
	}
	fixture.clock.Advance(6 * time.Second)
	if status, _ := world.claim(world.writerToken); status != http.StatusOK {
		t.Errorf("once a sixth of the minute refilled one: %d", status)
	}
}

// The last-resort KeyPackage serves only once no one-time one remains, is never deleted, and its claim is
// overwritten by each claimer.
func TestGkmLastResortServesOnlyOnceNoOneTimeRemains(t *testing.T) {
	world := newGkmKeyPackageWorld(t, nil)
	fixture := world.fixture
	oneTime := world.keyPackages(1, false)[0]
	lastResort := world.keyPackages(1, true)[0]
	if recorder := world.upload(world.targetToken, []*sidecar.MlsKeyPackage{lastResort, oneTime}); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d", recorder.Code)
	}
	// a restarted process has no ref's kind cached, and reads it from the object
	fixture.start()
	if _, reply := world.claim(world.writerToken); reply == nil || !bytes.Equal(reply.GetKeyPackageRef(), oneTime.Ref) {
		t.Fatal("the one-time KeyPackage did not serve first")
	}
	for i, token := range []string{world.writerToken, world.writerToken} {
		_, reply := world.claim(token)
		if reply == nil || !bytes.Equal(reply.GetKeyPackageRef(), lastResort.Ref) {
			t.Fatalf("claim %d did not take the last-resort", i)
		}
	}
	if !bytes.Equal(fixture.object("meta-1", world.key(lastResort.Ref)), lastResort.Encoded) {
		t.Error("the last-resort KeyPackage was deleted")
	}
	otherWriter := testId("sc-writer-2")
	fixture.auth.admit(otherWriter, memberDeviceFacts(testId("member-w2")))
	fixture.auth.grant(otherWriter, world.repoId, sidecar.AclEvsWrite)
	if _, reply := world.claim(fixture.token(otherWriter, repoScope(world.repoId, "rw"))); reply == nil {
		t.Fatal("another claimer of the last-resort")
	}
	if claim := world.claimOf(lastResort.Ref); claim == nil || !bytes.Equal(claim.GetClaimer(), otherWriter.Bytes()) {
		t.Error("the last-resort's claim was not overwritten by its newest claimer")
	}
}
