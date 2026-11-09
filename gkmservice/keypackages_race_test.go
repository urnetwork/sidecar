//go:build sidecar_testhooks

package gkmservice

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
)

// §22.5: two claimers race one KeyPackage, and one wins. Claimer A is held at gkm.kp_claim.before, its LIST done and
// its KeyPackage chosen; claimer B claims the same one meanwhile and wins; released, A's If-None-Match finds B's
// claim and A takes the next KeyPackage.
func TestGkmTwoClaimersRaceOneKeyPackageOneWins(t *testing.T) {
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

	arrivals := 0
	var replyB []byte
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierKeyPackageClaimBefore {
			return
		}
		arrivals += 1
		if arrivals != 1 {
			return
		}
		// A holds here: B runs its whole claim, on this goroutine, before A's create
		status, reply := world.claim(otherToken)
		if status != http.StatusOK {
			t.Errorf("B's claim: %d", status)
			return
		}
		replyB = reply.GetKeyPackageRef()
	}})
	defer sidecar.SetTestHooks(nil)

	status, replyA := world.claim(world.writerToken)
	if status != http.StatusOK || replyB == nil {
		t.Fatalf("A's claim: %d", status)
	}
	if bytes.Equal(replyA.GetKeyPackageRef(), replyB) {
		t.Fatal("one KeyPackage served both claimers")
	}
	if !bytes.Equal(world.claimOf(replyB).GetClaimer(), otherWriter.Bytes()) {
		t.Error("the raced KeyPackage's claim is not the winner's")
	}
	if !bytes.Equal(world.claimOf(replyA.GetKeyPackageRef()).GetClaimer(), world.writer.Bytes()) {
		t.Error("the loser's KeyPackage's claim is not the loser's")
	}
	// A arrived twice: at the KeyPackage it lost and at the next, with B's arrival between
	if arrivals != 3 {
		t.Errorf("%d arrivals at the claim barrier", arrivals)
	}
}
