//go:build !sidecar_http

// KEYS-M2-26's test of `ur keys rotate`, which is GkmClient.RotateRepo (DESIGN-DETAILS 6.2.5): a rotation on request
// claims cause REQUEST, never REMOVE, unless a REMOVE is due at the rotator's state, and then REMOVE whatever was
// asked, so §11.7's rule (4) rewrites files exactly when a holder left.

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestKeysRotateIsARequestAndARemoveOnlyWhenOneIsDue(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	first := world.stateFor()
	a := world.flows[world.a]
	claimed := func(view sidecar.GkmAuthView, key *sidecar.EvsRepoKey, generation uint64, cause sidecar.GkmCause, what string) {
		t.Helper()
		stored := world.storedGeneration(view, generation)
		if key.Generation() != generation || key.Cause() != cause || sidecar.GkmCause(stored.Rotate.GetCause()) != cause {
			t.Fatalf("%s: generation %d, the key's cause %d, gen/%d's cause %d; want generation %d, cause %d",
				what, key.Generation(), key.Cause(), generation, stored.Rotate.GetCause(), generation, cause)
		}
	}

	// nothing is due: a request
	key, err := a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	claimed(first, key, 2, sidecar.GkmCauseRequest, "ur keys rotate with nothing due")

	// a REMOVE asked for with none due is still a request
	key, err = a.client.Rotate(world.ctx, world.repoId, sidecar.GkmCauseRemove)
	if err != nil {
		t.Fatal(err)
	}
	claimed(first, key, 3, sidecar.GkmCauseRequest, "a REMOVE asked for with none due")

	// a holder left since gen/3: the request is the REMOVE that covers it
	world.revoke(world.x)
	second := world.stateFor()
	key, err = a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	claimed(second, key, 4, sidecar.GkmCauseRemove, "ur keys rotate after a revocation")

	// gen/4 covers the revocation: the next is a request again
	key, err = a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	claimed(second, key, 5, sidecar.GkmCauseRequest, "ur keys rotate once the revocation is covered")
}
