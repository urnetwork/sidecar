package sidecartest_test

// S4a (§22.7; F9's device form, KF4): the revocation suite's device form, a device revoked from a repo's readers, as
// one scenario under the harness and the guard on gkm's group client, the real MLS subset and gkmservice's engine on
// the scenario Net's stores. Its own KF4 flow, whose devices' names are canaries: x revoked, the writer's next
// EnsureWritable claims a REMOVE generation wrapped to no device of x's and commits the Remove, and x, keeping its
// MLS state and every ReaderKey it signed as a malicious server lets it, opens nothing of the new generation however
// much of the store it reads. KEYS's schedules run beside it as clauses: FS-15's wrapped rotation, whose removed leaf
// opens nothing of the REMOVE generation, and its kills between writes, x reaching nothing of either generation.
//
// Composed: writers-seal-nothing-to-x and next-generation-fails-under-xs-keys. Not composed yet, and so missing at
// M2-out: the gates' 412 GATE_CLOSED until a covering generation (EVS1-M2-11's gate), members refusing a commit that
// adds a non-reader or omits a Remove (KEYS-M2-28's revocation_test.go, whose schedules are test-only), tokens failing
// in their windows, and the path epoch and first-write checkpoint: TEST-M2-12's revocation suite holds them whole.

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

func TestScenarioS4a(t *testing.T) {
	scenario := &sidecartest.Scenario{Id: "S4a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := scenarioGkmWorlds(t, run)

		world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
		writer := world.AddMember(run.CanaryText("a device name"), false)
		x := world.AddMember(run.CanaryText("a device name"), false)
		world.Grant(true, writer)
		world.Grant(false, x)
		world.Admin(writer)
		world.Advance()
		world.Publish()
		world.Create(writer)
		world.AddPending(writer)
		before, err := writer.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("the writer's first key: %v", err)
		}
		if reach := world.RemovedReach(x); reach < before.Generation() {
			t.Fatalf("x reaches generation %d before its revocation, not %d", reach, before.Generation())
		}

		// KF4: x's revocation drops it from the repo's holders; the writer's next write key is a REMOVE generation
		world.Revoke(x)
		world.Advance()
		after, err := writer.Client.EnsureWritable(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("the writer's rotation past x: %v", err)
		}
		if after.Generation() <= before.Generation() {
			t.Fatalf("the writer kept generation %d past x's revocation", after.Generation())
		}
		// writers-seal-nothing-to-x
		if world.WrapRecipients(after.Generation())[x.SidecarId()] {
			t.Errorf("a ReaderWrap of generation %d to the revoked device", after.Generation())
		}
		// next-generation-fails-under-xs-keys: every ReaderKey x signed, and its MLS state's every epoch
		if world.OpensWrapOf(x, after.Generation(), x.CopyReaderKeys()) {
			t.Errorf("x's ReaderKeys open generation %d", after.Generation())
		}
		if reach := world.RemovedReach(x); after.Generation() <= reach {
			t.Errorf("x's MLS state reaches generation %d of %d", reach, after.Generation())
		}

		gkmschedule.FsKeysScheduleWrappedRotation(t, newWorld)
		gkmschedule.FsKeysScheduleKillsBetweenWrites(t, newWorld)
		return nil
	}}
	runScenarioOnTheMlsSubset(t, scenario)
}
