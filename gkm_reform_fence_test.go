//go:build !sidecar_http

// The client's side of gkm's fence at a re-form (QD-1186; gkmservice/reform_fence.go), on the fake gkm, which runs
// none of gkm's checks and so answers here as the fence does: a rotator whose claim of the old group gkm refuses 409,
// naming the new group, holds nothing of that claim, follows the form at its next sync and rotates the new group; and
// a re-former answered 409 with the form of another re-form's closing, standing or under way, drops its draft and
// waits (ErrGkmWait), adopting the group that stands at its next sync.

package sidecar_test

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A general repo whose admins, a and b, may each re-form its group, every other device holding KeyPackages for the
// re-former's Adds.
func newGkmFenceWorld(t *testing.T) *gkmFlowWorld {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.members[0].Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
	world.repo.Admins = []*protocol.AclRepoAdminRow{
		{SidecarId: world.a.id.Bytes(), Signer: world.a.id.Bytes(), At: 1},
		{SidecarId: world.b.id.Bytes(), Signer: world.a.id.Bytes(), At: 1},
	}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, false)
	}
	return world
}

// b's rotation has drafted and staged in the group when, just before its claim acts, a re-forms the repo whole, and
// gkm's fence answers b's claim of the old group 409. b answers ErrGkmWait and pins nothing of its claim; its next
// sync follows the form to the new group, whose Welcome it joins; and its next rotation lands in the new group, past
// every generation there, its old group's draft dropped (QD-1147).
func TestARotatorRefusedByTheFenceFollowsTheForm(t *testing.T) {
	world := newGkmFenceWorld(t)
	a, b := world.flows[world.a], world.flows[world.b]
	oldGroupId := world.groupId
	var newGroupId sidecar.Id
	var reformErr error
	world.store.plantHook(world.b.label, "ClaimGeneration", func() {
		newGroupId, reformErr = a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
		world.store.refuseOnce("ClaimGeneration", http.StatusConflict)
	})
	if _, err := b.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("b's rotation refused by the fence: %v", err)
	}
	if reformErr != nil || newGroupId == (sidecar.Id{}) {
		t.Fatalf("a's re-form: %v", reformErr)
	}
	if generation := world.store.newestGeneration(oldGroupId); generation != 1 {
		t.Fatalf("the old group holds generation %d", generation)
	}
	if groupId, _, generation, err := b.client.TestPins(world.repoId); err != nil || groupId != oldGroupId || generation != 1 {
		t.Fatalf("b's pins after its refused claim: generation %d, %v", generation, err)
	}

	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("b's sync after the re-form: %v", err)
	}
	if joined, err := b.client.JoinWelcomes(world.ctx); err != nil || !slices.Contains(joined, world.repoId) {
		t.Fatalf("b joins the re-formed group: %v %v", joined, err)
	}
	newest := world.store.newestGeneration(newGroupId)
	if groupId, _, generation, err := b.client.TestPins(world.repoId); err != nil || groupId != newGroupId || generation != newest {
		t.Fatalf("b follows the form: pinned generation %d of %d, %v", generation, newest, err)
	}
	key, err := b.client.RotateRepo(world.ctx, world.repoId)
	if err != nil || key.Generation() != newest+1 {
		t.Fatalf("b's rotation of the new group: %v", err)
	}
	if world.store.newestGeneration(newGroupId) != newest+1 || world.store.newestGeneration(oldGroupId) != 1 {
		t.Errorf("b's rotation did not land in the new group alone")
	}
	if len(b.alarms) != 0 {
		t.Errorf("b alarmed: %+v", b.alarms[0])
	}
}

// b's re-form is drafted when, just before its POST acts, a's re-form of the same group stands: gkm answers 409 with
// a's form, as it answers a closing that stands or is under way. b drops its draft and answers ErrGkmWait, and its
// next sync adopts a's group.
func TestAReformAnsweredWithAnotherClosingWaits(t *testing.T) {
	world := newGkmFenceWorld(t)
	a, b := world.flows[world.a], world.flows[world.b]
	var newGroupId sidecar.Id
	var reformErr error
	world.store.plantHook(world.b.label, "Reform", func() {
		newGroupId, reformErr = a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	})
	if _, err := b.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("b's re-form beside a's: %v", err)
	}
	if reformErr != nil {
		t.Fatalf("a's re-form: %v", reformErr)
	}
	if forms := world.store.repoForms[world.repoId]; len(forms) != 2 {
		t.Fatalf("the repo holds %d forms", len(forms))
	}
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("b's sync after the re-forms: %v", err)
	}
	if joined, err := b.client.JoinWelcomes(world.ctx); err != nil || !slices.Contains(joined, world.repoId) {
		t.Fatalf("b joins a's group: %v %v", joined, err)
	}
	if groupId, _, _, err := b.client.TestPins(world.repoId); err != nil || groupId != newGroupId {
		t.Errorf("b adopts a's group: %v", err)
	}
	if len(b.alarms) != 0 {
		t.Errorf("b alarmed: %+v", b.alarms[0])
	}
}
