//go:build sidecar_testhooks

package gkmservice

import (
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// FS-6's gkm leg (owner decision 82; §10.6's checks row, §11.12): a commit held at its epoch PUT, its repo/ reread
// already passed, and a delayed ack held at its Redis write, across a --now shred. Each write in flight lands after
// the shred's first pass, which is what the pass ten minutes later is for: after it nothing of the group stands, no
// epoch, generation, form, owner marker or ack, and no route of the shredded repo writes anything again.
func TestGkmCommitAndAckHeldAcrossAShredRecreateNothing(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	groupId := world.groupId
	shred := func(final bool) {
		t.Helper()
		if err := ShredGroup(fixture.ctx, fixture.host.ServiceHost(), fixture.cluster("meta-2"), world.repoId, final, fixture.settings); err != nil {
			t.Fatalf("the shred: %v", err)
		}
	}
	ackPath := "/gkm/groups/" + sidecar.EvsKeyId(groupId) + "/ack"
	readerToken := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "r"))
	commitHeld, ackHeld := 0, 0
	ackCode := 0
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch name {
		case BarrierEpochPutBefore:
			commitHeld += 1
			if commitHeld != 1 {
				return
			}
			// the commit holds here; an ack arrives and is held at its own write, and with both in flight evs
			// marks the repo and runs the shred's first pass, on this goroutine
			ackCode = fixture.serve(http.MethodPost, ackPath, readerToken, fixture.marshal(&protocol.GkmAckRequest{Epoch: 0})).Code
		case BarrierAckWriteBefore:
			ackHeld += 1
			if ackHeld != 1 {
				return
			}
			fixture.setRepoState(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_SHREDDING)
			shred(false)
			if world.storedEpoch(0) != nil || fixture.object("meta-2", GkmGenerationKey(groupId, 1)) != nil {
				t.Errorf("the shred's first pass left the group's objects")
			}
		}
	}})
	defer sidecar.SetTestHooks(nil)

	staged := world.stageSelfUpdate(1, fakeGkmPin(10))
	recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 1, true))
	if commitHeld != 1 || ackHeld != 1 {
		t.Fatalf("the commit was held %d times and the ack %d", commitHeld, ackHeld)
	}
	// both writes were in flight at the first pass and landed after it
	if recorder.Code != http.StatusOK || ackCode != http.StatusOK {
		t.Fatalf("the writes in flight answered %d and %d", recorder.Code, ackCode)
	}
	acks, err := fixture.host.Redis.HashGetAll(fixture.ctx, GkmAckRedisKey(groupId))
	if err != nil {
		t.Fatal(err)
	}
	if world.storedEpoch(1) == nil || len(acks) == 0 {
		t.Fatalf("the writes in flight did not land after the first pass: the schedule held nothing")
	}
	// nothing new starts on the shredding repo
	staged.Discard()
	second := world.stageSelfUpdate(1, fakeGkmPin(10))
	defer second.Discard()
	if code := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(second.Message(), 1, true)).Code; code != http.StatusForbidden {
		t.Errorf("a commit to a shredding repo: %d", code)
	}
	if recorder := world.postCreate(world.createRequest(testId("group-again"))); recorder.Code != http.StatusForbidden {
		t.Errorf("a creation in a shredding repo: %d", recorder.Code)
	}

	// §11.12's step 6, ten minutes later: the stragglers go, and the forms last
	fixture.clock.Advance(10 * time.Minute)
	shred(true)
	for _, key := range []string{
		GkmEpochKey(groupId, 0), GkmEpochKey(groupId, 1), GkmGenerationKey(groupId, 1), GkmGroupOwnerKey(groupId), GkmFormKey(world.repoId, 1),
	} {
		if fixture.object("meta-2", key) != nil {
			t.Errorf("the shred left %s", key)
		}
	}
	acks, err = fixture.host.Redis.HashGetAll(fixture.ctx, GkmAckRedisKey(groupId))
	if err != nil || len(acks) != 0 {
		t.Errorf("the shred left the group's acks: %v", err)
	}
	// and the repo, shredded, takes nothing: a re-seed's form alone would, in re-seed mode, of a repo marked deleted
	fixture.setRepoState(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_SHREDDED)
	if recorder := world.postReform(testId("group-reseeded"), groupId, 1); recorder.Code != http.StatusForbidden {
		t.Errorf("a GroupForm for a shredded repo: %d", recorder.Code)
	}
}
