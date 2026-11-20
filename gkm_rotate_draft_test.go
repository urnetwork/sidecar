//go:build !sidecar_http

// A rotation's draft resumed only while gkm's claim check could still take it (QD-1147; §10.5's Rotate, §10.6's claim
// checks, which refuse a time_ms more than 10 minutes off gkm's clock): a claim gkm refused and tried again past
// RotateDraftMaxAge draws afresh and lands with the later try's time, while one tried again within it resumes the
// draft's bytes; and a re-form claims no draft of the old group in the new one, even one whose delivery count and
// leaf wrap epoch match there. The re-form's finishing try drawing at its own time is gkm_reform_resume_test.go's.

package sidecar_test

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A writer's rotation whose claim gkm refused, as it does while its state is ahead of the rotator's or while repo/ is
// not active, leaves its draft; the rotation tried again delay later answers generation 2's statement as gkm took it.
func gkmRotateAgainAfter(t *testing.T, world *gkmFlowWorld, delay time.Duration) (refusedAt time.Time, gen2 *sidecar.GkmGeneration) {
	t.Helper()
	a := world.flows[world.a]
	world.store.refuseOnce("ClaimGeneration", http.StatusForbidden)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("the refused claim: %v", err)
	}
	if !a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("the refused claim left no draft")
	}
	refusedAt = world.clock.Now()
	world.advance(delay)
	key, err := a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation tried again: %v", err)
	}
	gen2 = world.storedGeneration(world.log.Tip(), 2)
	if !bytes.Equal(gen2.Rotate.GetCommitment(), key.Commitment()) || a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("gen/2 is not the claim the rotation answered, or its draft outlived it")
	}
	return refusedAt, gen2
}

// A claim gkm refused, tried again more than RotateDraftMaxAge later: the stale draft is dropped and a fresh one lands,
// carrying the later try's time, which gkm's claim check takes, and a member opens it.
func TestGkmRotateDrawsAfreshOverADraftPastItsBound(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	refusedAt, gen2 := gkmRotateAgainAfter(t, world, sidecar.DefaultGkmSettings().RotateDraftMaxAge+time.Millisecond)
	if gen2.Rotate.GetTimeMs() != world.clock.Now().UnixMilli() || gen2.Rotate.GetTimeMs() == refusedAt.UnixMilli() {
		t.Fatalf("gen/2 was drawn at %d; the refused try was at %d and the landing one at %d", gen2.Rotate.GetTimeMs(), refusedAt.UnixMilli(), world.clock.Now().UnixMilli())
	}
	b := world.flows[world.b]
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if key, err := b.client.RepoKey(world.ctx, world.repoId, 2); err != nil || !bytes.Equal(key.Commitment(), gen2.Rotate.GetCommitment()) {
		t.Errorf("b does not open the generation that landed: %v", err)
	}
}

// A claim gkm refused, tried again within RotateDraftMaxAge: the rotation resumes its draft, the same RK' and bytes
// going to the claim, so the generation that lands carries the refused try's time.
func TestGkmRotateResumesADraftWithinItsBound(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	refusedAt, gen2 := gkmRotateAgainAfter(t, world, sidecar.DefaultGkmSettings().RotateDraftMaxAge-time.Millisecond)
	if gen2.Rotate.GetTimeMs() != refusedAt.UnixMilli() {
		t.Fatalf("gen/2 was drawn at %d, not at the refused try's %d", gen2.Rotate.GetTimeMs(), refusedAt.UnixMilli())
	}
}

// A re-form claims no rotation draft of the old group in the new one: the group's only leaf is its creator a, at epoch
// 0, and a's rotation to generation 2 dies at its claim, its answer's read failing too, leaving a draft that names the
// old group with a leaf wrap at epoch 0 and no other delivery. After a site loss a re-forms the group, whose epoch 0
// again seats a alone, so that draft's delivery count and leaf wrap epoch match the new group's; the re-form's rotation
// draws afresh all the same, and generation 2 names the new group.
func TestAReformClaimsNoDraftOfTheOldGroupInTheNewOne(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	key1, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.groupId = key1.GroupId()
	oldGroupId := world.groupId
	world.store.plantHook("a", "ClaimGeneration", func() { world.store.plant("Generations", true) })
	world.store.plant("ClaimGeneration", true)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, errGkmFakeFault) {
		t.Fatalf("the killed rotation of the old group: %v", err)
	}
	if !a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("the killed rotation left no draft")
	}

	world.store.loseSite()
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil || newGroupId == oldGroupId {
		t.Fatalf("the re-form: %s, %v", newGroupId, err)
	}
	statements := world.store.groupGenerations[newGroupId]
	gen2 := &protocol.GenRotate{}
	if len(statements) != 2 || proto.Unmarshal(statements[1].GetBody(), gen2) != nil || !bytes.Equal(gen2.GetGroupId(), newGroupId.Bytes()) {
		t.Fatalf("gen/2 at gkm does not name the new group: %d generations", len(statements))
	}
	if held, _, found, err := a.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil || !bytes.Equal(held.Commitment(), gen2.GetCommitment()) {
		t.Errorf("a does not hold the generation that landed: %v", err)
	}
	if a.client.TestHasRotateDraft(world.repoId) {
		t.Errorf("the old group's draft outlived the re-form")
	}
}
