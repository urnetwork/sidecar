//go:build !sidecar_http

// QD-1191's re-form case on the fake gkm, whose POST forms answers as the fence does (gkm_reform_redraft_test.go): an
// owner-bound repo's list may drop a device between a re-form's first check and the redraft that follows gkm's 409 for
// a claim that outran its form, so the redraft holds the GroupForm signer rule at the state it pins the new form at,
// where every member judges it (gkm_reform.go's draftReform). A re-former the list dropped meanwhile drafts nothing
// again, and no form of its is filed for its members to refuse.

package sidecar_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// a vault of the world's member, every device listed: b's rotation of the old group lands just before a's POST of its
// re-form acts, and the list drops a in the same moment, as the config's step does at the entry that ends a's consent.
// gkm refuses a's form 409 with gen/2; a takes gen/2 and redrafts at the state that no longer lists it, which refuses
// it as no GroupForm signer: one POST, the repo's creation form alone, and no re-form record left.
func TestAReformRedraftedAfterTheListDroppedItsSignerDraftsNothing(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_VAULT)
	world.repo.OwnerMemberId = world.memberId.Bytes()
	for _, device := range world.devices {
		world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, device.id.Bytes())
	}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, false)
	}
	a, b := world.flows[world.a], world.flows[world.b]
	var rotateErr error
	world.store.plantHook(world.a.label, "Reform", func() {
		_, rotateErr = b.client.RotateRepo(world.ctx, world.repoId)
		world.repo.ConsentedSidecarIds = slices.DeleteFunc(world.repo.ConsentedSidecarIds, func(sidecarId []byte) bool {
			return bytes.Equal(sidecarId, world.a.id.Bytes())
		})
		world.stateFor()
	})
	_, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if rotateErr != nil {
		t.Fatalf("b's rotation before a's POST: %v", rotateErr)
	}
	if !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Fatalf("a's redraft after the list dropped it: %v", err)
	}
	if calls := world.store.callCount("Reform"); calls != 1 {
		t.Errorf("a's re-form posted %d times, want 1", calls)
	}
	if forms := world.store.repoForms[world.repoId]; len(forms) != 1 {
		t.Errorf("the repo holds %d forms, want only the creation's", len(forms))
	}
	if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
		t.Errorf("a's re-form record stands after its refused redraft: %v", err)
	}
}
