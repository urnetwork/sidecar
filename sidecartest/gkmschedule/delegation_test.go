package gkmschedule

// FS-18's cases on the real subset that KEYS-M8-01's forwarding schedule (sidecartest's fs_keys_delegation_test.go)
// leaves to KEYS-M2-28.

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// FS-18's wrapped writer case (KEYS-M2-28; D-KEYS-16, §10.6's gate), on the real subset: an agent that writes the
// repo by its wraps is revoked, and while gkm's state still trails the revocation the agent, from its own stale state,
// rotates: gkm takes the claim, whose pin is before the drop, and that generation never satisfies the gate at a state
// that holds the revocation; the writer leaf's EnsureWritable there rotates past it with cause REMOVE, and the
// revoked agent opens nothing of that generation.
func TestFsKeysDelegationADroppedWrappedWritersStaleClaimNeverSatisfiesTheGate(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	writer := world.AddAgent("w")
	reader := world.AddAgent("r")
	world.Grant(true, a, writer)
	world.Grant(false, reader)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	if _, err := writer.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}

	// the revocation lands in the log; gkm's state and the writer's own trail it
	world.Revoke(writer)
	writer.Offline = true
	world.GkmBehind = 1
	view := world.Advance()
	stale, err := writer.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the revoked writer's stale rotation: %v", err)
	}
	generation := world.Generation(stale.Generation())
	if view.Pin().GetVersion() <= generation.Rotate.GetAuth().GetVersion() {
		t.Fatalf("the stale claim's pin is not before the revocation")
	}
	if sidecar.GkmGatePasses(view, world.RepoId, generation.Rotate.GetAuth(), world.GenerationTime(generation), world.Clock.Now()) {
		t.Errorf("a dropped writer's generation from before its drop satisfies the gate")
	}

	// gkm reads the revocation: the leaf rotates past the stale generation, REMOVE, wrapped to the reader alone
	world.GkmBehind = 0
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the leaf's EnsureWritable: %v", err)
	}
	if key.Generation() != stale.Generation()+1 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("the leaf seals to generation %d, cause %d", key.Generation(), key.Cause())
	}
	recipients := world.WrapRecipients(key.Generation())
	if recipients[writer.SidecarId()] || !recipients[reader.SidecarId()] {
		t.Errorf("the REMOVE generation's ReaderWraps: %v", recipients)
	}
	if reached := world.RemovedReach(writer); key.Generation() <= reached {
		t.Errorf("the revoked writer reaches generation %d", reached)
	}
	if held, err := reader.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() < 1 {
		t.Errorf("the reader's key: %v", err)
	}
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if held, err := reader.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != key.Generation() {
		t.Errorf("the reader does not hold the REMOVE generation: %v", err)
	}
}

func TestFsKeysDelegationACoveredAgentsSuspendLeavesItNothingNewUntilItsOwnLateWrap(t *testing.T) {
	FsKeysScheduleCoveredAgentSuspended(t, FsKeysT2(t))
}

func TestFsKeysDelegationADelegationRevokeExcludesItsKey(t *testing.T) {
	FsKeysScheduleDelegationRevoked(t, FsKeysT2(t))
}

func TestFsKeysDelegationAReapedCoveredAgentReadsUntilTheKeyDrops(t *testing.T) {
	FsKeysScheduleCoveredAgentReaped(t, FsKeysT2(t))
}

func TestFsKeysDelegationAnEphemeralCoveredAgentPastItsNotAfterStartsNoRotation(t *testing.T) {
	FsKeysScheduleEphemeralCoveredAgentPastItsNotAfter(t, FsKeysT2(t))
}

func TestFsKeysDelegationACopiedBundleAfterACompromiseOpensNothingNew(t *testing.T) {
	FsKeysScheduleCopiedBundleCompromise(t, FsKeysT2(t))
}

func TestFsKeysDelegationACopiedBundleAfterARemovalAdmitsOnlyUncoveredReaders(t *testing.T) {
	FsKeysScheduleCopiedBundleRemoved(t, FsKeysT2(t))
}
