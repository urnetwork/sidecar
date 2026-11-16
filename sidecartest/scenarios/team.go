// S3b and S4b (§22.7; TEAM-M6-12 with KEYS-M6-03 and ACL-M6-05): F3's and F9's member forms, each one builder that
// sidecartest's T2 test and server's sidecart3 T3 test both run, composed of its owners' parts as clauses on the
// scenario's Net, so composition adds no mechanism and a failure goes back to the area named:
//
//   - S3b: TEAM's member admission statements (fault.TeamMemberAdmitStatements: in a Team at k = 2 an Admin's lone
//     MemberAdmit of a member outside the AdminSet and its first device from an invite land, the admission's signer
//     the granting device the log names, while a stranger's and a non-admin's MemberAdmit are refused by api and
//     every reader, a malicious api's append of either refused at its position); ACL's adds only for readers
//     (fault.AclMemberAddsOnlyForReaders); KEYS's key part (gkmschedule.FsKeysScheduleDirectoryMemberAdd: the granting
//     device commits the joining device's Add in the directory group and writes the first wrap of one with no
//     KeyPackage, and wraps to no device that does not read the directory); and a directory flow of its own whose
//     devices' names are canaries, the joiner taking its Welcome.
//   - S4b: TEAM's member removal statements (fault.TeamMemberRevokeStatements: TEAM-M6-11's plan, an Admin's lone
//     MemberRevoke of a member outside the AdminSet revoking, masking and unseating every device of the member at its
//     position at every reader, its tagged agent kept, a non-admin's MemberRevoke refused); ACL's every right dropped
//     (fault.AclMemberRemovalDropsEveryRight); KEYS's key part (gkmschedule.FsKeysScheduleDirectoryMemberRemoval: one
//     commit of the member's Removes, a rotation reaching leaves and wrapped readers and no device of the removed
//     member); and a directory flow of its own whose devices' names are canaries, the removed member's devices reaching
//     no generation past the removal.
//
// Each runs under sidecar_testhooks whole, every key the MLS subset hooks searched for in every store. The revocation
// suite's member form, S4's other half, runs on its own (fault's TestRevocationSuiteMemberForm), since the suite builds
// a Net of its own for each check.

package scenarios

import (
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/fault"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

// One clause a fault schedule's builder holds.
type teamClause struct {
	name    string
	builder fault.Builder
}

// Runs the clauses' schedules as one on the scenario's Net, their steps in clause order and every clause's checks after
// each step, since a run of the driver ends the Net's barriers with it: a step's failure names its clause, and is the
// scenario's.
func runClauses(ctx context.Context, run *sidecartest.ScenarioRun, id string, clauses ...teamClause) error {
	composed := &fault.Schedule{Id: id}
	for _, clause := range clauses {
		schedule := clause.builder(run.Net)
		for _, step := range schedule.Steps {
			copied := *step
			if action := step.Action; action != nil {
				name := clause.name
				copied.Action = func(ctx context.Context, net *fault.Net) error {
					if err := action(ctx, net); err != nil {
						return fmt.Errorf("%s: %w", name, err)
					}
					return nil
				}
			}
			composed.Steps = append(composed.Steps, &copied)
		}
		composed.Check = append(composed.Check, schedule.Check...)
	}
	if result := fault.Run(ctx, composed, run.Net); result.Err != nil {
		return fmt.Errorf("%s", result)
	}
	return nil
}

// S3b, failing t through KEYS's schedules where they fail.
func S3b(t testing.TB) *sidecartest.Scenario {
	return &sidecartest.Scenario{Id: "S3b", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := gkmWorlds(t, run)

		// a directory flow whose devices' names are canaries: the admin's device adds a joining member's device, which
		// joins from its Welcome
		world := newWorld(protocol.RepoKind_REPO_KIND_DIRECTORY)
		admin := world.AddMember(run.CanaryText("a device name"), false)
		joining := world.AddMemberOf(world.NewMember(), run.CanaryText("a device name"))
		world.Grant(true, admin, joining)
		world.Admin(admin)
		world.Advance()
		world.Publish()
		world.Create(admin)
		world.AddPending(admin)
		if _, err := joining.Client.JoinWelcomes(world.Ctx); err != nil {
			t.Fatalf("the joining device's join: %v", err)
		}
		world.AgreeOnEpoch(admin, joining)

		// directory-add-and-first-wrap
		gkmschedule.FsKeysScheduleDirectoryMemberAdd(t, newWorld)
		return runClauses(ctx, run, "S3b",
			teamClause{name: "member-admit-statements", builder: fault.TeamMemberAdmitStatements},
			teamClause{name: "adds-only-for-readers", builder: fault.AclMemberAddsOnlyForReaders},
		)
	}}
}

// S4b, failing t through KEYS's schedules where they fail.
func S4b(t testing.TB) *sidecartest.Scenario {
	return &sidecartest.Scenario{Id: "S4b", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := gkmWorlds(t, run)

		// a directory flow whose devices' names are canaries: a member whose devices read the directory is removed,
		// and the signer's commit and rotation leave both of its devices reaching nothing past the generation they held
		world := newWorld(protocol.RepoKind_REPO_KIND_DIRECTORY)
		admin := world.AddMember(run.CanaryText("a device name"), false)
		leaving := world.NewMember()
		x := world.AddMemberOf(leaving, run.CanaryText("a device name"))
		y := world.AddMemberOf(leaving, run.CanaryText("a device name"))
		world.Grant(true, admin, x, y)
		world.Admin(admin)
		world.Advance()
		world.Publish()
		world.Create(admin)
		world.AddPending(admin)
		world.RevokeMember(leaving)
		world.VoidTokens(x)
		world.VoidTokens(y)
		world.Advance()
		world.Again("the signer's pending run", func() error { return admin.Client.RunPending(world.Ctx, world.RepoId) })
		after, err := admin.Client.EnsureWritable(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("the signer's write past the removal: %v", err)
		}
		for _, device := range []*gkmschedule.FsKeysDevice{x, y} {
			if world.WrapRecipients(after.Generation())[device.SidecarId()] {
				t.Errorf("a ReaderWrap of generation %d to a device of the removed member", after.Generation())
			}
			if reach := world.RemovedReach(device); after.Generation() <= reach {
				t.Errorf("a device of the removed member reaches generation %d of %d", reach, after.Generation())
			}
		}

		// directory-removes-and-rotation
		gkmschedule.FsKeysScheduleDirectoryMemberRemoval(t, newWorld)
		return runClauses(ctx, run, "S4b",
			teamClause{name: "member-revoke-statements", builder: fault.TeamMemberRevokeStatements},
			teamClause{name: "every-right-dropped", builder: fault.AclMemberRemovalDropsEveryRight},
		)
	}}
}
