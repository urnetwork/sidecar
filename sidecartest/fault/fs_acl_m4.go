// ACL-M4-04's schedules (§22.8's FS-19 at M4-out; §8.6's ceiling, D-ACL-19, R-ACL-9, I-15): FS-19's row again in a Pro
// network, whose document the writer saved, the sidecar tagged and ephemeral. On the admission world with ACL's own
// compile, as fs_acl.go's are, so every reader standing, each new device and gate at a base and the writer's follower
// gives each answer, and the world fails a step the moment one stands elsewhere than the reference.
//
// Registered, each on T2 and on T3 through server's sidecart3:
//
//   - FS-19's grant: a tagged ephemeral agent, its sponsor a member device: only its tag's grants add, so it writes the
//     repo its tag's RepoGrant names and reads no repo the members' document grant opens to every member device; a
//     RepoGrant naming it opens exactly that repo at once, a read and an agent's wrap; its RepoRevoke drops both at
//     every reader and shrinks the repo's key holders at the revoke's position.
//   - FS-19's share: the agent sponsored by a member, which deposits into its sponsor's vault by the kind default and
//     reads none of it; the member's consented device's EvsShare opens exactly that vault at once, and the share's
//     revocation, the member's RepoRevoke, drops the read and shrinks the vault's key holders.

package fault

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs19GrantCase = Register("FS-19", "grant", []Tier{TierT2, TierT3}, Fs19Grant)
	Fs19ShareCase = Register("FS-19", "share", []Tier{TierT2, TierT3}, Fs19Share)
)

// The Pro network's document: the members' reach and every action on the network's general repos, tag:ci for its
// tagOwners, and the tag named in a rule, since the compile writes a tag's atom only for a tag a rule names
// (acl-m2-16-tag-atoms): tag:ci dials its sponsor's devices on tcp:443, as the implicit document's tagged rule does.
const fs19M4Policy = `{
	"tagOwners": { "tag:ci": ["autogroup:member"] },
	"grants": [
		{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
		{ "src": ["tag:ci"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
	],
}`

// The start of both cases: a member and its consented device, the document saved, tag:ci's atom, and the agent the
// member's device admits, tagged ci and ephemeral, for a day.
func fs19M4Start(world *fsTeamWorld) *Step {
	return aclSetup(world, func(net *sidecartest.AdmissionNet) error {
		_, first := net.ConsentedMember("m")
		world.devices["m first"] = first
		// the compile expands tagOwners over the folded members, so the member is folded before the save
		net.Fold(true)
		plan, _ := net.SaveAclPolicy([]byte(fs19M4Policy), nil)
		if !plan.Rows.GetHasDocument() {
			return errors.New("the saved head has no document")
		}
		tagId, found := sidecartest.AclTagAtom(plan, "ci")
		if !found {
			return errors.New("the saved head names no tag:ci")
		}
		world.ids["tag ci"] = tagId.Bytes()
		agent := net.Device("m ci agent", sidecar.Id{})
		world.devices["agent"] = agent
		net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
			net.Admission(agent, []sidecar.Id{tagId}, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
		net.Fold(true)
		return nil
	})
}

// Fails unless, at every reader, the sidecar's evs rights on each repo are exactly the ones given, it is a key holder
// as an agent exactly of the repos it reads, and no leaf of any.
func fs19M4ExpectRights(net *sidecartest.AdmissionNet, sidecarId sidecar.Id, repoRights map[sidecar.Id]sidecar.AclEvsRights) error {
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for repoId, want := range repoRights {
			if err := aclExpectRights(fmt.Sprintf("on %s", repoId), aclRights(net, acl, sidecarId, repoId, sidecar.AclTokenAudienceEvs), want); err != nil {
				return err
			}
			reads := want.Has(sidecar.AclEvsRead)
			if slices.Contains(acl.RepoReaders(repoId, at), sidecarId) != reads {
				return fmt.Errorf("%s among %s's readers: %t", sidecarId, repoId, !reads)
			}
			if err := aclExpectHolder(state, repoId, at, sidecarId, reads, sidecar.GkmHolderAgent); err != nil {
				return err
			}
			if err := aclExpectHolder(state, repoId, at, sidecarId, false, sidecar.GkmHolderLeaf); err != nil {
				return err
			}
		}
		return nil
	})
	return nil
}

// FS-19's grant (M4-out); see the file header.
func Fs19Grant(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-19 grant", world,
		fs19M4Start(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent, tagId := world.devices["m first"], world.devices["agent"], sidecar.Id(world.ids["tag ci"])
			ci := aclCreateRepo(net, first, "ci", protocol.RepoKind_REPO_KIND_GENERAL)
			notes := aclCreateRepo(net, first, "notes", protocol.RepoKind_REPO_KIND_GENERAL)
			shared := aclCreateRepo(net, first, "shared", protocol.RepoKind_REPO_KIND_GENERAL)
			world.ids["ci"], world.ids["notes"], world.ids["shared"] = ci.Bytes(), notes.Bytes(), shared.Bytes()
			// the tag's grant adds: the agent writes ci by its tag
			net.MustLand(aclRepoGrant(net, first, ci, tagId, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER))
			// the members' rule gives every member device all of notes and shared, and the agent none of either
			return fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				ci:     sidecar.AclEvsRead | sidecar.AclEvsWrite,
				notes:  0,
				shared: 0,
			})
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent := world.devices["m first"], world.devices["agent"]
			ci, notes, shared := sidecar.Id(world.ids["ci"]), sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["shared"])
			// a read grant naming it opens exactly that repo, at once
			net.MustLand(aclRepoGrant(net, first, shared, agent.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			return fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				ci:     sidecar.AclEvsRead | sidecar.AclEvsWrite,
				notes:  0,
				shared: sidecar.AclEvsRead,
			})
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent := world.devices["m first"], world.devices["agent"]
			ci, notes, shared := sidecar.Id(world.ids["ci"]), sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["shared"])
			// the grant's removal is a shrink
			revoke := net.MustLand(aclRepoRevoke(net, first, shared, agent.SidecarId))
			if err := fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				ci:     sidecar.AclEvsRead | sidecar.AclEvsWrite,
				notes:  0,
				shared: 0,
			}); err != nil {
				return err
			}
			return aclExpectShrunkAt(net, shared, revoke.Pin.GetVersion())
		}),
	)
}

// FS-19's share (M4-out); see the file header.
func Fs19Share(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-19 share", world,
		fs19M4Start(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent := world.devices["m first"], world.devices["agent"]
			vault := aclCreateRepo(net, first, "m vault", protocol.RepoKind_REPO_KIND_VAULT)
			mailbox := aclCreateRepo(net, first, "m mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
			world.ids["vault"], world.ids["mailbox"] = vault.Bytes(), mailbox.Bytes()
			// the kind default: a tagged subject its member sponsors deposits into the member's vault and mailbox
			return fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				vault:   sidecar.AclEvsDeposit,
				mailbox: sidecar.AclEvsDeposit,
			})
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent := world.devices["m first"], world.devices["agent"]
			vault, mailbox := sidecar.Id(world.ids["vault"]), sidecar.Id(world.ids["mailbox"])
			// the member's consented device shares its vault with the agent: exactly that repo opens, at once
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
				Header: net.Header(), RepoId: vault.Bytes(), Subject: agent.SidecarId.Bytes(),
			}))
			return fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				vault:   sidecar.AclEvsDeposit | sidecar.AclEvsRead,
				mailbox: sidecar.AclEvsDeposit,
			})
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, agent := world.devices["m first"], world.devices["agent"]
			vault, mailbox := sidecar.Id(world.ids["vault"]), sidecar.Id(world.ids["mailbox"])
			// the share's revocation is a shrink
			revoke := net.MustLand(aclRepoRevoke(net, first, vault, agent.SidecarId))
			if err := fs19M4ExpectRights(net, agent.SidecarId, map[sidecar.Id]sidecar.AclEvsRights{
				vault:   sidecar.AclEvsDeposit,
				mailbox: sidecar.AclEvsDeposit,
			}); err != nil {
				return err
			}
			return aclExpectShrunkAt(net, vault, revoke.Pin.GetVersion())
		}),
	)
}
