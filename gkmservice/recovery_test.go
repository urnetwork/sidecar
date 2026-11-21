package gkmservice

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A RecoveryWrap's bytes for a test: gkm holds them to their size alone.
func gkmTestRecoveryCiphertext(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, gkmRecoveryWrapByteCount)
}

// POST recovery-wraps/<g>/<c8> with token: the status and, on 200, each result.
func (self *gkmGroupWorld) postRecoveryWraps(token string, generation uint64, c8 string, items ...*protocol.GkmRecoveryWrapItem) (int, []*protocol.GkmWrapResult) {
	self.t.Helper()
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/recovery-wraps/" + strconv.FormatUint(generation, 10) + "/" + c8
	recorder := self.fixture.serve(http.MethodPost, path, token, self.fixture.marshal(&protocol.GkmRecoveryWrapBatch{Items: items}))
	reply := &protocol.GkmWrapBatchReply{}
	if recorder.Code == http.StatusOK {
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
			self.t.Fatal(err)
		}
	}
	return recorder.Code, reply.GetResults()
}

// GET /gkm/recovery/<member_id>/wraps with token.
func (self *gkmGroupWorld) readRecoveryWraps(token string, memberId sidecar.Id) (int, []*protocol.GkmRecoveryWrap) {
	self.t.Helper()
	recorder := self.fixture.serve(http.MethodGet, "/gkm/recovery/"+sidecar.EvsKeyId(memberId)+"/wraps", token, nil)
	reply := &protocol.GkmRecoveryWrapsReply{}
	if recorder.Code == http.StatusOK {
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
			self.t.Fatal(err)
		}
	}
	return recorder.Code, reply.GetWraps()
}

// §10.8's recovery wraps: a rotator stages them while gen/<g> is absent, on the repo's cluster; a fetch, by the
// member's device or its unadmitted client under recovery:<member_id>, serves the newest whose c8 is gen/<g>'s and
// passes a lost claim's; recovery:<member_id> reaches no other member's; after a rebind the member's device re-wraps
// to the new binding and deletes the old binding's.
func TestGkmRecoveryWrapsStageReadRewrapAndDelete(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	oldBinding := bytes.Repeat([]byte{0xb1}, gkmPrefixByteCount)
	newBinding := bytes.Repeat([]byte{0xb2}, gkmPrefixByteCount)
	fixture.auth.recovery[world.memberId] = &RecoveryWrapCoverage{
		Current: bytes.Repeat([]byte{0xb2}, 32), Retired: [][]byte{bytes.Repeat([]byte{0xb1}, 32)}, RepoIds: []sidecar.Id{world.repoId},
	}
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	lostKey, _ := world.nextGeneration(world.admin, world.key1, nil)
	item := &protocol.GkmRecoveryWrapItem{MemberId: world.memberId.Bytes(), BindingPrefix: oldBinding, Ciphertext: gkmTestRecoveryCiphertext(1)}
	code, results := world.postRecoveryWraps(world.adminToken, 2, gkmTestC8(key2), item, &protocol.GkmRecoveryWrapItem{MemberId: world.memberId.Bytes(), BindingPrefix: oldBinding, Ciphertext: []byte("short")})
	if code != http.StatusOK || results[0].GetStatus() != http.StatusCreated || results[1].GetStatus() != http.StatusForbidden {
		t.Fatalf("staging a recovery wrap and a malformed one: %d", code)
	}
	if code, results := world.postRecoveryWraps(world.adminToken, 2, gkmTestC8(lostKey), item); code != http.StatusOK || results[0].GetStatus() != http.StatusCreated {
		t.Fatalf("staging a lost claim's recovery wrap: %d", code)
	}
	key := GkmRecoveryWrapKey(world.memberId, world.groupId, 2, gkmTestC8(key2), hex.EncodeToString(oldBinding))
	if fixture.object("meta-2", key) == nil || fixture.object("meta-1", key) != nil {
		t.Errorf("a recovery wrap off its repo's cluster")
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	if code, results := world.postRecoveryWraps(world.adminToken, 2, gkmTestC8(key2), item); code != http.StatusOK || results[0].GetStatus() != http.StatusConflict {
		t.Errorf("a staged recovery wrap once gen/2 exists: %d", code)
	}

	device := fixture.newSidecar("sc-device", memberDeviceFacts(world.memberId))
	fixture.auth.grant(device.sidecarId, world.repoId, sidecar.AclEvsRead)
	deviceToken := fixture.token(device.sidecarId, repoScope(world.repoId, "r"))
	code, wraps := world.readRecoveryWraps(deviceToken, world.memberId)
	if code != http.StatusOK || len(wraps) != 1 || wraps[0].GetGeneration() != 2 || !bytes.Equal(wraps[0].GetBindingPrefix(), oldBinding) ||
		!bytes.Equal(wraps[0].GetCommitmentPrefix(), key2.Commitment()[:8]) {
		t.Fatalf("the member's device's fetch: %d, %d wraps", code, len(wraps))
	}
	unadmittedToken := fixture.token(testId("sc-unadmitted"), "recovery:"+world.memberId.String())
	if code, wraps := world.readRecoveryWraps(unadmittedToken, world.memberId); code != http.StatusOK || len(wraps) != 1 {
		t.Errorf("the unadmitted client under recovery:<member_id>: %d", code)
	}
	if code, _ := world.readRecoveryWraps(unadmittedToken, testId("member-other")); code != http.StatusForbidden {
		t.Errorf("recovery:<member_id> for another member: %d", code)
	}

	rewrap := &protocol.GkmRecoveryWrap{
		GroupId:          world.groupId.Bytes(),
		Generation:       2,
		CommitmentPrefix: key2.Commitment()[:8],
		BindingPrefix:    newBinding,
		Ciphertext:       gkmTestRecoveryCiphertext(2),
	}
	rewrapPath := "/gkm/recovery/" + sidecar.EvsKeyId(world.memberId) + "/wraps"
	stranger := fixture.newSidecar("sc-stranger", memberDeviceFacts(testId("member-other")))
	fixture.auth.grant(stranger.sidecarId, world.repoId, sidecar.AclEvsRead)
	strangerToken := fixture.token(stranger.sidecarId, repoScope(world.repoId, "r"))
	if recorder := fixture.serve(http.MethodPost, rewrapPath, strangerToken, fixture.marshal(rewrap)); recorder.Code != http.StatusForbidden {
		t.Errorf("a re-wrap by another member's device: %d", recorder.Code)
	}
	wrongCommitment := proto.Clone(rewrap).(*protocol.GkmRecoveryWrap)
	wrongCommitment.CommitmentPrefix = lostKey.Commitment()[:8]
	if recorder := fixture.serve(http.MethodPost, rewrapPath, deviceToken, fixture.marshal(wrongCommitment)); recorder.Code != http.StatusConflict {
		t.Errorf("a re-wrap naming another commitment than gen/2's: %d", recorder.Code)
	}
	completePath := rewrapPath + "?complete=" + hex.EncodeToString(newBinding)
	deletePath := rewrapPath + "?binding=" + hex.EncodeToString(oldBinding)
	if reply := fixture.serve(http.MethodGet, completePath, deviceToken, nil); reply.Code != http.StatusConflict {
		t.Fatalf("coverage before replacement: %d", reply.Code)
	}
	if reply := fixture.serve(http.MethodDelete, deletePath, deviceToken, nil); reply.Code != http.StatusConflict || fixture.object("meta-2", key) == nil {
		t.Fatalf("a missing replacement must preserve the old wrap: %d", reply.Code)
	}
	if recorder := fixture.serve(http.MethodPost, rewrapPath, deviceToken, fixture.marshal(rewrap)); recorder.Code != http.StatusCreated {
		t.Fatalf("the member's device's re-wrap: %d", recorder.Code)
	}
	if reply := fixture.serve(http.MethodGet, completePath, deviceToken, nil); reply.Code != http.StatusOK {
		t.Fatalf("completed current-generation coverage: %d", reply.Code)
	}
	if recorder := fixture.serve(http.MethodDelete, deletePath, strangerToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a delete by another member's device: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodDelete, deletePath, deviceToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("the old binding's delete: %d", recorder.Code)
	}
	code, wraps = world.readRecoveryWraps(deviceToken, world.memberId)
	if code != http.StatusOK || len(wraps) != 1 || !bytes.Equal(wraps[0].GetBindingPrefix(), newBinding) {
		t.Errorf("after the rebind: %d, %d wraps", code, len(wraps))
	}
}

// A native claim cannot overtake a rebind with the retired wrap. Replaying the winning bytes after another
// binding change still returns their original result.
func TestGkmGenerationRequiresTheEffectiveRecoveryWrap(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	fixture.settings.DraftMls = false
	fixture.start()
	create := world.createRequest(world.groupId)
	create.CipherSuite, create.GenWrap, create.SealedGroupInfo = 0, nil, nil
	if reply := world.postCreate(create); reply.Code != http.StatusOK {
		t.Fatalf("formation: %d", reply.Code)
	}
	fixture.setRepoState(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	old := bytes.Repeat([]byte{1}, 32)
	next := bytes.Repeat([]byte{2}, 32)
	coverage := &RecoveryWrapCoverage{RepoIds: []sidecar.Id{world.repoId}, Current: old}
	fixture.auth.recovery[world.memberId] = coverage
	key, claim := world.nextGeneration(world.admin, world.key1, nil)
	stage := func(binding []byte, want uint32) {
		t.Helper()
		code, results := world.postRecoveryWraps(world.adminToken, 2, gkmTestC8(key), &protocol.GkmRecoveryWrapItem{
			MemberId: world.memberId.Bytes(), BindingPrefix: binding[:8], Ciphertext: gkmTestRecoveryCiphertext(binding[0]),
		})
		if code != http.StatusOK || len(results) != 1 || results[0].GetStatus() != want {
			t.Fatalf("stage: %d %v", code, results)
		}
	}
	stage(old, http.StatusCreated)
	coverage.Current, coverage.Retired = next, [][]byte{old}
	if reply := world.postClaim(world.adminToken, 2, claim); reply.Code != http.StatusConflict {
		t.Fatalf("claim waiting for replacement: %d", reply.Code)
	}
	stage(old, http.StatusConflict)
	stage(next, http.StatusCreated)
	if reply := world.postClaim(world.adminToken, 2, claim); reply.Code != http.StatusCreated {
		t.Fatalf("covered claim: %d", reply.Code)
	}
	coverage.Current = bytes.Repeat([]byte{3}, 32)
	if reply := world.postClaim(world.adminToken, 2, claim); reply.Code != http.StatusCreated {
		t.Fatalf("winning retry: %d", reply.Code)
	}
}
