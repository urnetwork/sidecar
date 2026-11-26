//go:build !sidecar_http

// SKILL-M11-01's key half (DESIGN-COMPUTE §16.6's table, key distributors): the member's devices form and rotate the
// agents and agent repos' groups as for every owner-bound kind, so a device that leaves the member's readers takes no
// part in the next generation, which carries the drop key both kinds take, an agent repo's for its inbox's deposits and
// an agents repo's for its readers' receipts.

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A member's device leaves (its revocation shrinks the readers): the next rotation of each kind's group is REMOVE's,
// delivered to the readers that stand and not the device that left, with a drop key living DropKeyLifetime, and a
// member that stands judges it sound.
func TestAgentReposGroupsRotateWhenADeviceLeaves(t *testing.T) {
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT} {
		world := newGkmFlowWorld(t, kind)
		world.holdAll()
		a := world.flows[world.a]
		world.revoke(world.x)
		second := world.stateFor()
		key, err := a.client.RotateRepo(world.ctx, world.repoId)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		gen2 := world.storedGeneration(second, 2)
		if key.Generation() != 2 || sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRemove {
			t.Fatalf("%s: gen/2 at %d, cause %d", kind, key.Generation(), gen2.Rotate.GetCause())
		}
		recipients := world.deliveryRecipients(2)
		if _, delivered := recipients["s:x"]; delivered || recipients["s:b"] != sidecar.GkmDeliveryStaged {
			t.Errorf("%s: deliveries of generation 2: %v", kind, recipients)
		}
		lifetime := sidecar.DefaultGkmSettings().DropKeyLifetime
		if len(gen2.Rotate.GetDropPublicKey()) == 0 || gen2.Rotate.GetDropNotAfterMs() != gen2.Rotate.GetTimeMs()+lifetime.Milliseconds() {
			t.Errorf("%s: drop key of %d bytes until %d", kind, len(gen2.Rotate.GetDropPublicKey()), gen2.Rotate.GetDropNotAfterMs())
		}
		if verdict := world.memberAccepts(second, 2, world.b); !verdict.Passed() {
			t.Errorf("%s: a member's check: %+v", kind, verdict)
		}
	}
}
