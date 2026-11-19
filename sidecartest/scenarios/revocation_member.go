// §22.7's revocation suite's member form (TEST-M6-01; R-TEST-4, D-TEST-6, I-15, owner decision 83): the checks TEST
// composes from KEYS's and ACL's exported parts, registered with sidecartest's suite beside TEAM's own
// (fault.TeamMemberRevocationCheck, the log's clause). Composition adds no mechanism: a failure goes back to the area
// named.
//
//   - keys/member-opens-nothing-claimed-after (KEYS, the gate off): member X holds two devices that read and write the
//     directory's group at generation g; X is removed; the signer's pending run commits the Removes and rotates, its
//     next write key generation g+1 or later, wrapped to neither device, and with everything gkm stores delivered to
//     each (a malicious server's), neither device's ReaderKeys, MLS state nor any key it ever held opens it, while one
//     each held opens g, so the check is no vacuous pass. It runs with evs's gate off (D-TEST-6): what refuses X is
//     the members' own rotation. Without the hooks the gate cannot be switched and the held keys reach no record, so
//     the suite reads it open.
//   - acl/removed-members-tagged-agents-keep-their-grants (ACL; owner decision 83): fault.AclRevocationTaggedAgents, a
//     removed member's tagged agent keeping its tag's rule and RepoGrant, and autogroup:sponsor resolving to
//     autogroup:admin until an admin's SponsorSet, at every reader.
//   - acl/removed-member-drops-every-right (ACL; I-15): fault.AclMemberRemovalDropsEveryRight, S4b's part.
//
// The two ways differ in who signs the MemberRevoke: an Admin's device (member-remove) or the sidecar
// ServiceSettings.scim_signer names (scim-active-false). TEAM's check judges that, each way with its own signer, and
// shows the log's effect is the same removal at the same position. The keys check takes the removal as that effect,
// which KEYS's world applies as the log's position (FsKeysWorld.RevokeMember), so it runs alike in both ways. ACL's
// two builders sign the removal as the Owner, inside themselves, and take no signer: they judge member-remove and read
// open under scim-active-false, so a report names the clause there, never counts it passed.
//
// RevocationMemberKeysCheck's mutant, a signer that writes on under the generation it held before the removal, is the
// suite's own test that a removed member still reading fails.

package scenarios

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/fault"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

var (
	RevocationMemberKeys = sidecartest.RegisterRevocationCheck(RevocationMemberKeysCheck(false))

	RevocationMemberTaggedAgents = sidecartest.RegisterRevocationCheck(revocationMemberAclCheck(
		"acl/removed-members-tagged-agents-keep-their-grants", fault.AclRevocationTaggedAgents))
	RevocationMemberRightsDropped = sidecartest.RegisterRevocationCheck(revocationMemberAclCheck(
		"acl/removed-member-drops-every-right", fault.AclMemberRemovalDropsEveryRight))
)

// Why an ACL builder judges nothing under SCIM's way.
const revocationOpenAclScim = "ACL's schedule signs the removal as the Owner and takes no signer, so the scim_signer's MemberRevoke is not composed with it: TEAM's check judges that removal's effect in the log"

// One of ACL's member-removal schedules as a check of the member form: judged where an Admin removes the member, open
// where SCIM does.
func revocationMemberAclCheck(id string, builder fault.Builder) *sidecartest.RevocationCheck {
	return &sidecartest.RevocationCheck{
		Id:   id,
		Area: "ACL",
		Ways: sidecartest.RevocationFormMember.Ways(),
		Run: func(run *sidecartest.RevocationRun) (string, error) {
			if run.Way != sidecartest.RevocationMemberRemove {
				return revocationOpenAclScim, nil
			}
			if result := fault.Run(run.Ctx, builder(run.Net), run.Net); result.Err != nil {
				return "", fmt.Errorf("%s", result)
			}
			return "", nil
		},
	}
}

// The keys check of the member form; writesOn makes the signer write under the generation it held before the removal,
// the mutant the suite must fail.
func RevocationMemberKeysCheck(writesOn bool) *sidecartest.RevocationCheck {
	id := "keys/member-opens-nothing-claimed-after"
	if writesOn {
		id += "/mutant-writing-on-under-the-old-generation"
	}
	return &sidecartest.RevocationCheck{
		Id:      id,
		Area:    "KEYS",
		Ways:    sidecartest.RevocationFormMember.Ways(),
		GateOff: true,
		Run: func(run *sidecartest.RevocationRun) (string, error) {
			return revocationMemberKeysRun(run, writesOn)
		},
	}
}

// See the file header.
func revocationMemberKeysRun(run *sidecartest.RevocationRun, writesOn bool) (string, error) {
	if !run.GateOff {
		return "", errors.New("the member form's keys check runs with evs's gate off")
	}
	failer := &revocationFailer{ctx: run.Ctx}
	var world *gkmschedule.FsKeysWorld
	var signer *gkmschedule.FsKeysDevice
	var leaving sidecar.Id
	// X's devices, each its own actor, so each one's held keys are its own record
	devices := map[string]*gkmschedule.FsKeysDevice{}
	actors := []string{"x phone", "x laptop"}
	var before, after *sidecar.EvsRepoKey
	open := ""
	addDevice := func(actor string) *fault.Step {
		return failer.step(actor, func(ctx context.Context) error {
			devices[actor] = world.AddMemberOf(leaving, actor)
			return nil
		})
	}
	readsBefore := func(actor string) *fault.Step {
		return failer.step(actor, func(ctx context.Context) error {
			held, err := devices[actor].Client.CurrentRepoKey(ctx, world.RepoId)
			if err != nil {
				return fmt.Errorf("%s reads nothing before the removal, so the check proves nothing: %w", actor, err)
			}
			if held.Generation() != before.Generation() {
				return fmt.Errorf("%s holds generation %d, the signer %d", actor, held.Generation(), before.Generation())
			}
			return nil
		})
	}
	steps := []*fault.Step{
		failer.step("setup", func(ctx context.Context) error {
			world = gkmschedule.NewFsKeysWorldOnNet(failer, protocol.RepoKind_REPO_KIND_DIRECTORY, run.Net)
			signer = world.AddMember("signer", false)
			leaving = world.NewMember()
			return nil
		}),
		addDevice(actors[0]),
		addDevice(actors[1]),
		failer.step("setup", func(ctx context.Context) error {
			world.Grant(true, signer, devices[actors[0]], devices[actors[1]])
			world.Admin(signer)
			world.Advance()
			world.Publish()
			return nil
		}),
		failer.step("signer", func(ctx context.Context) error {
			world.Create(signer)
			world.AddPending(signer)
			var err error
			before, err = signer.Client.CurrentRepoKey(ctx, world.RepoId)
			return err
		}),
		readsBefore(actors[0]),
		readsBefore(actors[1]),
		failer.step("api", func(ctx context.Context) error {
			// the removal as the log holds it, whoever signed it: the member's row gone and each device revoked at
			// the next position, and api's rev/ objects voiding their tokens at gkm
			world.RevokeMember(leaving)
			for _, actor := range actors {
				world.VoidTokens(devices[actor])
			}
			world.Advance()
			return nil
		}),
		failer.step("signer", func(ctx context.Context) error {
			var err error
			if writesOn {
				after, err = signer.Client.CurrentRepoKey(ctx, world.RepoId)
				return err
			}
			world.Again("the signer's pending run", func() error { return signer.Client.RunPending(ctx, world.RepoId) })
			after, err = signer.Client.EnsureWritable(ctx, world.RepoId)
			return err
		}),
		failer.step("check", func(ctx context.Context) error {
			errs := []error{}
			if after.Generation() <= before.Generation() {
				errs = append(errs, fmt.Errorf("the signer writes under generation %d after the member's %s, which X holds", after.Generation(), run.Way))
			}
			ladder := []*sidecar.GkmGeneration{}
			for generation := uint64(1); generation <= uint64(world.GenerationCount()); generation += 1 {
				ladder = append(ladder, world.Generation(generation))
			}
			for _, actor := range actors {
				device := devices[actor]
				if world.WrapRecipients(after.Generation())[device.SidecarId()] {
					errs = append(errs, fmt.Errorf("a wrap of generation %d to %s", after.Generation(), actor))
				}
				if world.OpensWrapOf(device, after.Generation(), device.CopyReaderKeys()) {
					errs = append(errs, fmt.Errorf("%s's ReaderKeys open generation %d's wraps", actor, after.Generation()))
				}
				if reach := world.RemovedReach(device); !writesOn && after.Generation() <= reach {
					errs = append(errs, fmt.Errorf("%s's MLS state reaches generation %d of %d", actor, reach, after.Generation()))
				}
				revoked := run.RevokedActor(actor)
				switch {
				case !sidecartest.HooksLinked:
					open = revocationOpenWithoutHooks
				case !revoked.OpensGeneration(ladder, before.Generation()):
					errs = append(errs, fmt.Errorf("no key %s held opens generation %d, which it read: the check proves nothing", actor, before.Generation()))
				case before.Generation() < after.Generation() && revoked.OpensGeneration(ladder, after.Generation()):
					errs = append(errs, fmt.Errorf("a key %s held opens generation %d, claimed after the member's %s", actor, after.Generation(), run.Way))
				}
			}
			return errors.Join(errs...)
		}),
		failer.cleanup(),
	}
	result := fault.Run(run.Ctx, &fault.Schedule{Id: "revocation " + string(run.Way), Steps: steps}, run.Net)
	return open, result.Err
}
