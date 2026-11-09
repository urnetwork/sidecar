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
	if recorder := fixture.serve(http.MethodPost, rewrapPath, deviceToken, fixture.marshal(rewrap)); recorder.Code != http.StatusCreated {
		t.Fatalf("the member's device's re-wrap: %d", recorder.Code)
	}
	deletePath := rewrapPath + "?binding=" + hex.EncodeToString(oldBinding)
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
