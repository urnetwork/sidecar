// ACL-M2-16's schedules (§22.8, §22.5's §8 row, §22.7; R-ACL-7, R-ACL-12, D-ACL-14, D-ACL-15, D-ACL-19, I-4, I-15,
// I-16): the authorization log's acl cases on the admission world (sidecartest.AdmissionNet) with ACL's own compile
// (sidecartest.AclAdmissionCompile), so every base compiles the network's real policy, the implicit document when it
// has none, every full reader compiles it again, every gate takes the rows, and the world fails a step the moment any
// reader stands elsewhere than the reference (fs_team.go's agreement). A decision is asked of every reader standing
// (AdmissionNet.EveryAcl), so a reference, each new device and gate started at a base, and the writer's follower must
// each give it.
//
// Registered:
//
//   - FS-19's config-read (T2+T3): an untagged ephemeral sidecar admitted under a personal network's Owner, with no
//     policy, deposits into the Owner's vault and mailbox and nothing else, holds no generation of any repo but the
//     config, fails every general and record read, write and admin and every owner-bound write, gets no evs or gkm rw
//     on the config from the exchange, and is no config writer, so every reader refuses its config head and api
//     refuses its base, which on T2 a malicious api then appends and every reader forks at, though its member is in
//     the AdminSet; Delegation-admitted, after the DelegationRevoke it reads the config's next generation by its own
//     ReaderWrap, as an agent holder the Delegation no longer covers.
//
// The config read itself waits on question team-m2-15-config-repo-acl-row: no compile writes the config repo's own
// AclRepo row, so the rows refuse every config scope to every sidecar alike, the closed direction. Until it is
// answered the schedule holds the ephemeral's config rights to a member device's on the rows as they are, and judges
// the read, the key holders and the head writers on sidecartest.AclConfigRowView, the row every option gives.
//
// The other cases are named clauses a T2 test runs (fs_acl_test.go), and server's T3 tests where the row runs on T3.

package fault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs19ConfigReadCase = Register("FS-19", "config-read", []Tier{TierT2, TierT3}, Fs19ConfigRead)
)

// The first step of an acl schedule: the network bootstrapped on the Net's tier with ACL's compile, its owner's first
// device the writer, then body.
func aclSetup(world *fsTeamWorld, body func(net *sidecartest.AdmissionNet) error) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			tier.AclCompile = sidecartest.AclAdmissionCompile
			world.net = sidecartest.NewAdmissionNet(fsTeamFailer{}, tier)
			if body == nil {
				return nil
			}
			return body(world.net)
		})
	}}
}

// A repo created by signer, which must land; its id.
func aclCreateRepo(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, label string, kind protocol.RepoKind) sidecar.Id {
	repoId := net.Id("repo " + label)
	net.MustLand(net.Sign(signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.Header(), RepoId: repoId.Bytes(), Kind: kind,
	}))
	return repoId
}

// The rights a sidecar holds on a repo for a token of audience, at the world's time.
func aclRights(net *sidecartest.AdmissionNet, acl *sidecar.AclState, sidecarId sidecar.Id, repoId sidecar.Id, audience sidecar.AclTokenAudience) sidecar.AclEvsRights {
	return acl.EvsAccess(sidecar.AclSidecarSubject(sidecarId), repoId, audience, net.Clock().Now()).Rights
}

// Fails unless the rights are exactly want.
func aclExpectRights(what string, rights sidecar.AclEvsRights, want sidecar.AclEvsRights) error {
	if rights != want {
		return fmt.Errorf("%s: rights %04b, want %04b", what, rights, want)
	}
	return nil
}

// A scope as a daemon asks the exchange for it (§7.8).
func aclScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// Fails unless the exchange, at state, grants the sidecar exactly granted of scopes and refuses the rest.
func aclExpectScopes(net *sidecartest.AdmissionNet, state *sidecar.ConfigState, sidecarId sidecar.Id, audience sidecar.AclTokenAudience, scopes []string, granted []string) error {
	grant, err := sidecar.AclExchangeScopes(state, &sidecar.AclExchangeRequest{
		SidecarId: sidecarId, Audience: audience, Scopes: scopes, Now: net.Clock().Now(),
	})
	if err != nil {
		return err
	}
	refused := []string{}
	for _, scope := range scopes {
		if !slices.Contains(granted, scope) {
			refused = append(refused, scope)
		}
	}
	if !slices.Equal(grant.Scopes, granted) || !slices.Equal(grant.Refused, refused) {
		return fmt.Errorf("the exchange at audience %d granted %v and refused %v, want %v and %v", audience, grant.Scopes, grant.Refused, granted, refused)
	}
	return nil
}

// Fails unless the repo's key holders at state, through view, hold the sidecar exactly when holds says, as kinds.
func aclExpectHolder(view sidecar.GkmAuthView, repoId sidecar.Id, at time.Time, sidecarId sidecar.Id, holds bool, kinds ...sidecar.GkmHolderKind) error {
	holders, err := sidecar.KeyHolders(view, repoId, at)
	if err != nil {
		return fmt.Errorf("the key holders of %s: %w", repoId, err)
	}
	if sidecartest.AclHolds(holders, sidecarId, kinds...) != holds {
		return fmt.Errorf("the key holders of %s hold %s as %v: %t, want %t", repoId, sidecarId, kinds, !holds, holds)
	}
	return nil
}

// What FS-19's config read makes in its first step and checks after: the Owner's laptop, the burner, and the repos.
type fs19World struct {
	*fsTeamWorld
	burner                                                     *sidecartest.AdmissionDevice
	notesId, recordId, vaultId, mailboxId, secretId, configId sidecar.Id
}

// FS-19's config read, the row's M2 case; see the file header.
func Fs19ConfigRead(net *Net) *Schedule {
	world := &fs19World{fsTeamWorld: newFsTeamWorld()}
	return fsTeamSchedule("FS-19 config-read", world.fsTeamWorld,
		aclSetup(world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			owner := net.Owner()
			world.configId = net.ConfigRepoId()
			world.notesId = aclCreateRepo(net, owner, "notes", protocol.RepoKind_REPO_KIND_GENERAL)
			world.recordId = aclCreateRepo(net, owner, "record", protocol.RepoKind_REPO_KIND_RECORD)
			world.vaultId = aclCreateRepo(net, owner, "vault", protocol.RepoKind_REPO_KIND_VAULT)
			world.mailboxId = aclCreateRepo(net, owner, "mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
			world.secretId = aclCreateRepo(net, owner, "secret", protocol.RepoKind_REPO_KIND_SECRET)
			// the burner: untagged, ephemeral, under the Owner, whom the AdminSet holds
			world.burner = net.Device("burner", owner.MemberId)
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(world.burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			net.Fold(true)
			return nil
		}),
		fsTeamDo("check", world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			return fs19CheckCeiling(net, world)
		}),
		fsTeamDo("check", world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			return fs19CheckExchange(net, world)
		}),
		fsTeamDo("check", world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			return fs19CheckHeadWriters(net, world)
		}),
		fsTeamDo("owner", world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			return fs19DelegationRevoked(net, world)
		}),
		fsTeamDo("burner", world.fsTeamWorld, func(net *sidecartest.AdmissionNet) error {
			return fs19BaseRefused(net, world)
		}),
	)
}

// §8.6's ceiling at every reader: no document, so the implicit one, and the burner's rights are the kind defaults'
// deposits and nothing else, while the laptop, a member device and config writer, holds what the implicit document
// and the kind defaults give it.
func fs19CheckCeiling(net *sidecartest.AdmissionNet, world *fs19World) error {
	laptop, burner := net.Owner().SidecarId, world.burner.SidecarId
	evs, gkm := sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if acl.HasDocument() {
			return errors.New("the personal network's rows say has_document")
		}
		// the implicit document's first rule allows every action, deposit included
		member := sidecar.AclEvsDeposit | sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin
		// the consented owner's device, the repo's admin as its creator
		ownerBound := sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin
		for _, check := range []struct {
			what   string
			rights sidecar.AclEvsRights
			want   sidecar.AclEvsRights
		}{
			// general and record repos: the implicit document's autogroup:member write and admin on evs:*, which the
			// ceiling withholds from the burner, read included
			{what: "the burner on a general repo", rights: aclRights(net, acl, burner, world.notesId, evs), want: 0},
			{what: "the burner on a record repo", rights: aclRights(net, acl, burner, world.recordId, evs), want: 0},
			{what: "the laptop on a general repo", rights: aclRights(net, acl, laptop, world.notesId, evs), want: member},
			{what: "the laptop on a record repo", rights: aclRights(net, acl, laptop, world.recordId, evs), want: member},
			// owner-bound repos: the kind default's deposit for the owner's other untagged subjects, no write, no read
			{what: "the burner on the vault", rights: aclRights(net, acl, burner, world.vaultId, evs), want: sidecar.AclEvsDeposit},
			{what: "the burner on the mailbox", rights: aclRights(net, acl, burner, world.mailboxId, evs), want: sidecar.AclEvsDeposit},
			{what: "the burner on the secret", rights: aclRights(net, acl, burner, world.secretId, evs), want: 0},
			{what: "the laptop on the vault", rights: aclRights(net, acl, laptop, world.vaultId, evs), want: ownerBound},
			// the config on the rows as they are: whatever they give a member device, never more to the burner
			{what: "the burner's config read beside the laptop's, at evs", rights: aclRights(net, acl, burner, world.configId, evs) & sidecar.AclEvsRead,
				want: aclRights(net, acl, laptop, world.configId, evs) & sidecar.AclEvsRead},
			{what: "the burner's config write at evs", rights: aclRights(net, acl, burner, world.configId, evs) & sidecar.AclEvsWrite, want: 0},
			{what: "the burner's config write at gkm", rights: aclRights(net, acl, burner, world.configId, gkm) & sidecar.AclEvsWrite, want: 0},
		} {
			if err := aclExpectRights(check.what, check.rights, check.want); err != nil {
				return err
			}
		}
		for _, repoId := range []sidecar.Id{world.notesId, world.recordId, world.vaultId, world.mailboxId, world.secretId} {
			if slices.Contains(acl.RepoReaders(repoId, at), burner) || slices.Contains(acl.RepoWriters(repoId, at), burner) {
				return fmt.Errorf("the burner reads or writes %s", repoId)
			}
			// it holds no generation of any repo but the config: no leaf, no wrap
			if err := aclExpectHolder(state, repoId, at, burner, false, sidecar.GkmHolderLeaf, sidecar.GkmHolderAgent); err != nil {
				return err
			}
		}
		if err := aclExpectHolder(state, world.notesId, at, laptop, true, sidecar.GkmHolderLeaf); err != nil {
			return err
		}

		// the config read on the config row every answer to team-m2-15-config-repo-acl-row gives
		view, err := sidecartest.NewAclConfigRowView(state)
		if err != nil {
			return err
		}
		for _, check := range []struct {
			what   string
			rights sidecar.AclEvsRights
			want   sidecar.AclEvsRights
		}{
			{what: "the burner on the config at evs", rights: aclRights(net, view.Acl(), burner, world.configId, evs), want: sidecar.AclEvsRead},
			{what: "the burner on the config at gkm", rights: aclRights(net, view.Acl(), burner, world.configId, gkm), want: sidecar.AclEvsRead},
			{what: "the laptop on the config at evs", rights: aclRights(net, view.Acl(), laptop, world.configId, evs), want: sidecar.AclEvsRead | sidecar.AclEvsWrite},
			{what: "the laptop on the config at gkm", rights: aclRights(net, view.Acl(), laptop, world.configId, gkm), want: sidecar.AclEvsRead | sidecar.AclEvsWrite},
		} {
			if err := aclExpectRights(check.what, check.rights, check.want); err != nil {
				return err
			}
		}
		// the burner reads the config by a wrap of its own, the laptop as a leaf
		if err := aclExpectHolder(view, world.configId, at, burner, true, sidecar.GkmHolderAgent); err != nil {
			return err
		}
		if err := aclExpectHolder(view, world.configId, at, laptop, true, sidecar.GkmHolderLeaf); err != nil {
			return err
		}
		return nil
	})
	return nil
}

// The exchange (§7.8, ACL-M2-14) at every reader's state: the burner gets the owner-bound deposits and no other scope,
// no evs or gkm rw on the config among them, while the laptop gets what it holds.
func fs19CheckExchange(net *sidecartest.AdmissionNet, world *fs19World) error {
	laptop, burner := net.Owner().SidecarId, world.burner.SidecarId
	evs, gkm := sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm
	scopes := []string{
		aclScope(world.notesId, "r"), aclScope(world.notesId, "rw"), aclScope(world.notesId, "admin"),
		aclScope(world.recordId, "r"), aclScope(world.recordId, "rw"),
		aclScope(world.vaultId, "deposit"), aclScope(world.vaultId, "r"), aclScope(world.vaultId, "rw"),
		aclScope(world.mailboxId, "deposit"), aclScope(world.mailboxId, "rw"),
		aclScope(world.secretId, "deposit"), aclScope(world.secretId, "r"),
		aclScope(world.configId, "rw"), aclScope(world.configId, "admin"),
	}
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if err := aclExpectScopes(net, state, burner, evs, scopes, []string{aclScope(world.vaultId, "deposit"), aclScope(world.mailboxId, "deposit")}); err != nil {
			return fmt.Errorf("the burner's: %w", err)
		}
		if err := aclExpectScopes(net, state, burner, gkm, []string{aclScope(world.configId, "rw"), aclScope(world.notesId, "rw")}, []string{}); err != nil {
			return fmt.Errorf("the burner's: %w", err)
		}
		// whatever the config's r gives a member device, it gives the burner (question team-m2-15-config-repo-acl-row)
		configR := []string{aclScope(world.configId, "r")}
		laptopGrant, err := sidecar.AclExchangeScopes(state, &sidecar.AclExchangeRequest{SidecarId: laptop, Audience: evs, Scopes: configR, Now: net.Clock().Now()})
		if err != nil {
			return err
		}
		if err := aclExpectScopes(net, state, burner, evs, configR, laptopGrant.Scopes); err != nil {
			return fmt.Errorf("the burner's config read beside the laptop's: %w", err)
		}
		if err := aclExpectScopes(net, state, laptop, evs, []string{aclScope(world.notesId, "rw"), aclScope(world.vaultId, "rw")},
			[]string{aclScope(world.notesId, "rw"), aclScope(world.vaultId, "rw")}); err != nil {
			return fmt.Errorf("the laptop's: %w", err)
		}
		return nil
	})
	return nil
}

// No reader takes the burner for a config writer, though its member is in the AdminSet: its config head is refused at
// every reader's head check and among the config's writers, and the laptop's stands.
func fs19CheckHeadWriters(net *sidecartest.AdmissionNet, world *fs19World) error {
	laptop, burner := net.Owner().SidecarId, world.burner.SidecarId
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if role := state.Member(net.Owner().MemberId).GetRole(); role != bridge.MemberRole_MEMBER_ROLE_OWNER {
			return fmt.Errorf("the burner's member is a %s", role)
		}
		if state.IsConfigWriter(burner) || !state.IsConfigWriter(laptop) {
			return fmt.Errorf("config writers: the burner %t, the laptop %t", state.IsConfigWriter(burner), state.IsConfigWriter(laptop))
		}
		if err := sidecar.CheckConfigHeadWriter(state, burner); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
			return fmt.Errorf("the burner's config head: %v", err)
		}
		if err := sidecar.CheckConfigHeadWriter(state, laptop); err != nil {
			return fmt.Errorf("the laptop's config head: %w", err)
		}
		view, err := sidecartest.NewAclConfigRowView(state)
		if err != nil {
			return err
		}
		if writers := view.Acl().RepoWriters(world.configId, at); !slices.Equal(writers, []sidecar.Id{laptop}) {
			return fmt.Errorf("the config's writers are %v", writers)
		}
		return nil
	})
	return nil
}

// Delegation-admitted (§10.5's covered row): a Delegation of the Owner's laptop admits an ephemeral agent, which reads
// the config through the Delegation's key, not as a holder of its own; after the DelegationRevoke the Delegation holds
// no key and the agent, still admitted, holds the config as an agent, so the next generation reaches it by its own
// ReaderWrap. A Delegation needs a tag its signer may apply, so the network takes a document whose tagOwners give the
// Owner tag:ci, whose first rule keeps the implicit document's member reach, and whose second, the implicit document's
// tagged dial, names the tag, since the compile writes a tag's atom only for a tag a rule names (acl-m2-16-tag-atoms).
func fs19DelegationRevoked(net *sidecartest.AdmissionNet, world *fs19World) error {
	owner := net.Owner()
	plan, _ := net.SaveAclPolicy([]byte(`{
		"tagOwners": { "tag:ci": ["autogroup:admin"] },
		"grants": [
			{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
			{ "src": ["tag:ci"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
		],
	}`), nil)
	tagId, found := sidecartest.AclTagAtom(plan, "ci")
	if !found {
		return errors.New("the saved head names no tag:ci")
	}
	delegation := net.Delegate(owner, "ci", []sidecar.Id{tagId}, 4, net.Clock().Now().Add(7*24*time.Hour).UnixMilli())
	agent := net.Device("ci agent", sidecar.Id{})
	net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.Admission(agent, []sidecar.Id{tagId}, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		view, err := sidecartest.NewAclConfigRowView(state)
		if err != nil {
			return err
		}
		holders, err := sidecar.KeyHolders(view, world.configId, at)
		if err != nil {
			return err
		}
		if !holders.Contains(sidecar.GkmHolderDelegation, delegation.Id) || holders.Contains(sidecar.GkmHolderAgent, agent.SidecarId.Bytes()) {
			return errors.New("before the revoke the Delegation covers its agent's config read")
		}
		if rights := aclRights(net, view.Acl(), agent.SidecarId, world.configId, sidecar.AclTokenAudienceEvs); rights != sidecar.AclEvsRead {
			return fmt.Errorf("the agent's config rights: %04b", rights)
		}
		return nil
	})
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.DelegationRevoke(delegation.Id, 0)))
	if !net.Admitted(agent) {
		return errors.New("the DelegationRevoke removed its agent")
	}
	at = net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		view, err := sidecartest.NewAclConfigRowView(state)
		if err != nil {
			return err
		}
		holders, err := sidecar.KeyHolders(view, world.configId, at)
		if err != nil {
			return err
		}
		if holders.Contains(sidecar.GkmHolderDelegation, delegation.Id) || !holders.Contains(sidecar.GkmHolderAgent, agent.SidecarId.Bytes()) {
			return errors.New("after the revoke the agent holds the config as an agent of its own")
		}
		if rights := aclRights(net, view.Acl(), agent.SidecarId, world.configId, sidecar.AclTokenAudienceEvs); rights != sidecar.AclEvsRead {
			return fmt.Errorf("the agent's config rights after the revoke: %04b", rights)
		}
		// and no other repo's: the agent's tag reaches nothing here
		for _, repoId := range []sidecar.Id{world.notesId, world.vaultId} {
			if err := aclExpectHolder(state, repoId, at, agent.SidecarId, false, sidecar.GkmHolderAgent, sidecar.GkmHolderLeaf); err != nil {
				return err
			}
		}
		return nil
	})
	return nil
}

// api refuses the burner's base (403); on T2 a malicious api appends it anyway, and every reader forks there, since no
// config writer signed it.
func fs19BaseRefused(net *sidecartest.AdmissionNet, world *fs19World) error {
	signedHeader, rows := net.BaseKeepingTheFold(world.burner, nil)
	if _, err := net.AppendBase(signedHeader, rows); !fsTeamRefused(err) {
		return fmt.Errorf("api's answer to the burner's base: %v, want 403", err)
	}
	if !net.ForgedAppends() {
		return nil
	}
	net.AllowForks()
	pin := net.SequenceAnyway(bridge.AuthEntryKindBase, signedHeader)
	return fsTeamEveryReaderForkedAt(net, pin.GetVersion())
}

// A suspend_id from a label, fixed by the network: 16 bytes, as §8.8's Suspend carries.
func aclSuspendId(net *sidecartest.AdmissionNet, label string) []byte {
	id := net.Id("suspend id " + label)
	return id.Bytes()
}

// A Suspend or Unsuspend of device under suspendId, signed by signer.
func aclSuspend(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, device *sidecartest.AdmissionDevice, suspendId []byte) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.Header(), Subject: device.SidecarId.Bytes(), SuspendId: suspendId})
}

func aclUnsuspend(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, device *sidecartest.AdmissionDevice, suspendId []byte) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.Header(), Subject: device.SidecarId.Bytes(), SuspendId: suspendId})
}

// Fails unless every reader holds device suspended exactly when suspended says, §8.6's hard deny with it: no read of
// repoId, no reach to the owner's laptop, and none of the repo's key holders.
func aclExpectSuspended(net *sidecartest.AdmissionNet, device *sidecartest.AdmissionDevice, suspended bool, repoId sidecar.Id) error {
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if acl.Suspended(device.SidecarId) != suspended || state.Suspended(device.SidecarId) != suspended {
			return fmt.Errorf("%s suspended: %t, want %t", device.Name, acl.Suspended(device.SidecarId), suspended)
		}
		reach := acl.Reach(sidecar.AclSidecarSubject(device.SidecarId), sidecar.AclSidecarSubject(net.Owner().SidecarId), at)
		reads := slices.Contains(acl.RepoReaders(repoId, at), device.SidecarId)
		if suspended && (reach.Allowed || reach.Reason != sidecar.AclReasonSuspended || reads) {
			return fmt.Errorf("suspended, %s reaches the laptop %t (%s) and reads %t", device.Name, reach.Allowed, reach.Reason, reads)
		}
		if !suspended && (!reach.Allowed || !reads) {
			return fmt.Errorf("standing, %s reaches the laptop %t (%s) and reads %t", device.Name, reach.Allowed, reach.Reason, reads)
		}
		return aclExpectHolder(state, repoId, at, device.SidecarId, !suspended, sidecar.GkmHolderLeaf)
	})
	return nil
}

// Fails unless every reader holds the subject's Suspend under suspendId in the class given.
func aclExpectSuspensionClass(net *sidecartest.AdmissionNet, device *sidecartest.AdmissionDevice, suspendId []byte, class uint32) error {
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for _, suspension := range acl.Rows().GetSuspensions() {
			if sidecar.Id(suspension.GetSubject()) == device.SidecarId && string(suspension.GetSuspendId()) == string(suspendId) {
				if suspension.GetSignerClass() != class {
					return fmt.Errorf("the Suspend's class is %d, want %d", suspension.GetSignerClass(), class)
				}
				return nil
			}
		}
		return errors.New("no such Suspend in force")
	})
	return nil
}

// A member, its consented first device and its phone, which the first admitted, and a general repo the first created:
// FS-14's acl clauses' shared start, then a base folding through it.
func fs14AclStart(world *fsTeamWorld) *Step {
	return aclSetup(world, func(net *sidecartest.AdmissionNet) error {
		memberId, first := net.ConsentedMember("m")
		phone := net.Device("m phone", memberId)
		net.AdmitDevice(first, phone, 0)
		world.devices["m first"], world.devices["m phone"] = first, phone
		world.ids["notes"] = aclCreateRepo(net, first, "notes", protocol.RepoKind_REPO_KIND_GENERAL).Bytes()
		net.Fold(true)
		return nil
	})
}

// A base keeping the newest fold, its head changed only in ServiceSettings, so the entries since that fold are its
// tail and every new device and gate started at it re-applies them by their verdicts (DESIGN-DETAILS 5.2.3).
func aclBaseKeepingTheFold(net *sidecartest.AdmissionNet, hours uint32) *bridge.AuthPin {
	before := net.State().Base().GetFoldedThrough()
	pin := net.SetServiceSettings(&protocol.ServiceSettings{WitnessBoundHours: hours})
	if net.State().Base().GetFoldedThrough() != before {
		panic(fsTeamFailure{err: fmt.Errorf("the head change folded through %d, not %d", net.State().Base().GetFoldedThrough(), before)})
	}
	return pin
}

// FS-14's Suspend and Unsuspend in both orders, and a stale suspend_id a no-op (§8.8, §8.6's one switch), at every
// reader, across a base whose tail re-applies them: an admin's Suspend then its Unsuspend leaves the phone standing; an
// Unsuspend of a suspend_id not in force lands and lifts nothing, so the Suspend after it holds, re-applied at every
// new device and gate with its admin class; another stale id lifts nothing; the owner's class lifts no admin's
// Suspend; the admin's Unsuspend does.
func Fs14AclSuspendOrders(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 acl suspend orders", world,
		fs14AclStart(world),
		fsTeamDo("admin", world, func(net *sidecartest.AdmissionNet) error {
			phone, notes := world.devices["m phone"], sidecar.Id(world.ids["notes"])
			if err := aclExpectSuspended(net, phone, false, notes); err != nil {
				return err
			}
			first := aclSuspendId(net, "first")
			net.MustLand(aclSuspend(net, net.Owner(), phone, first))
			if err := aclExpectSuspended(net, phone, true, notes); err != nil {
				return err
			}
			if err := aclExpectSuspensionClass(net, phone, first, sidecar.AclSuspendClassAdmin); err != nil {
				return err
			}
			// a suspend_id already in force is refused, since one Unsuspend names one Suspend
			net.MustRefuse(aclSuspend(net, net.Owner(), phone, first), sidecar.ErrConfigRule)
			net.MustLand(aclUnsuspend(net, net.Owner(), phone, first))
			return aclExpectSuspended(net, phone, false, notes)
		}),
		fsTeamDo("admin", world, func(net *sidecartest.AdmissionNet) error {
			phone, notes := world.devices["m phone"], sidecar.Id(world.ids["notes"])
			second := aclSuspendId(net, "second")
			// the other order: the Unsuspend first is stale, lands, and lifts nothing ahead of time
			net.MustLand(aclUnsuspend(net, net.Owner(), phone, second))
			if err := aclExpectSuspended(net, phone, false, notes); err != nil {
				return err
			}
			net.MustLand(aclSuspend(net, net.Owner(), phone, second))
			if err := aclExpectSuspended(net, phone, true, notes); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 48)
			if err := aclExpectSuspended(net, phone, true, notes); err != nil {
				return err
			}
			if err := aclExpectSuspensionClass(net, phone, second, sidecar.AclSuspendClassAdmin); err != nil {
				return err
			}
			// a stale suspend_id lifts nothing
			net.MustLand(aclUnsuspend(net, net.Owner(), phone, aclSuspendId(net, "stale")))
			if err := aclExpectSuspended(net, phone, true, notes); err != nil {
				return err
			}
			// the phone's owner, class 1, lifts no admin's Suspend, and the phone never lifts its own
			net.MustRefuse(aclUnsuspend(net, world.devices["m first"], phone, second), sidecar.ErrConfigAuthority)
			net.MustRefuse(aclUnsuspend(net, phone, phone, second), sidecar.ErrConfigAuthority)
			net.MustLand(aclUnsuspend(net, net.Owner(), phone, second))
			if err := aclExpectSuspended(net, phone, false, notes); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 72)
			return aclExpectSuspended(net, phone, false, notes)
		}),
	)
}

// A RepoGrant or RepoRevoke of subject on repoId, signed by signer.
func aclRepoGrant(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, repoId sidecar.Id, subject sidecar.Id, role protocol.RepoGrantRole) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{Header: net.Header(), RepoId: repoId.Bytes(), Subject: subject.Bytes(), Role: role})
}

func aclRepoRevoke(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, repoId sidecar.Id, subject sidecar.Id) []byte {
	return net.Sign(signer, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.Header(), RepoId: repoId.Bytes(), Subject: subject.Bytes()})
}

// Fails unless every reader gives the sidecar read on the repo exactly when reads says, with it among the repo's key
// holders as an agent then.
func aclExpectReads(net *sidecartest.AdmissionNet, sidecarId sidecar.Id, repoId sidecar.Id, reads bool) error {
	at := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		rights := aclRights(net, acl, sidecarId, repoId, sidecar.AclTokenAudienceEvs)
		if rights.Has(sidecar.AclEvsRead) != reads || slices.Contains(acl.RepoReaders(repoId, at), sidecarId) != reads {
			return fmt.Errorf("%s reads %s: rights %04b, want reading %t", sidecarId, repoId, rights, reads)
		}
		return aclExpectHolder(state, repoId, at, sidecarId, reads, sidecar.GkmHolderAgent)
	})
	return nil
}

// Fails unless every reader holds the repo's holders_shrunk_at at n.
func aclExpectShrunkAt(net *sidecartest.AdmissionNet, repoId sidecar.Id, n uint64) error {
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if shrunkAt := state.ShrunkAt(repoId); shrunkAt != n {
			return fmt.Errorf("%s's holders_shrunk_at is %d, want %d", repoId, shrunkAt, n)
		}
		return nil
	})
	return nil
}

// FS-14's RepoRevoke (the ledger's missing case; §8.8's access log): a repo admin that is no config writer grants an
// ephemeral sidecar read, a config writer's RepoRevoke drops it at every reader and shrinks the repo's key holders at its
// position, the admin's grant again leaves the standing revoke in force, re-applied across a base's tail at every new
// device and gate, and only a config writer's grant lifts it.
func Fs14AclRepoRevoke(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 acl repo revoke", world,
		fs14AclStart(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, notes := world.devices["m first"], sidecar.Id(world.ids["notes"])
			burner := net.Device("m burner", first.MemberId)
			world.devices["m burner"] = burner
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			if err := aclExpectReads(net, burner.SidecarId, notes, false); err != nil {
				return err
			}
			net.MustLand(aclRepoGrant(net, first, notes, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			return aclExpectReads(net, burner.SidecarId, notes, true)
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			first, burner, notes := world.devices["m first"], world.devices["m burner"], sidecar.Id(world.ids["notes"])
			revoke := net.MustLand(aclRepoRevoke(net, net.Owner(), notes, burner.SidecarId))
			if err := aclExpectReads(net, burner.SidecarId, notes, false); err != nil {
				return err
			}
			if err := aclExpectShrunkAt(net, notes, revoke.Pin.GetVersion()); err != nil {
				return err
			}
			// a repo admin's grant again lands and lifts nothing: the config writer's revoke stands
			net.MustLand(aclRepoGrant(net, first, notes, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			if err := aclExpectReads(net, burner.SidecarId, notes, false); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 48)
			if err := aclExpectReads(net, burner.SidecarId, notes, false); err != nil {
				return err
			}
			if err := aclExpectShrunkAt(net, notes, revoke.Pin.GetVersion()); err != nil {
				return err
			}
			// a sidecar that is neither the repo's admin nor a config writer revokes nothing
			net.MustRefuse(aclRepoRevoke(net, world.devices["m phone"], notes, first.SidecarId), sidecar.ErrConfigAuthority)
			// a config writer's grant lifts its standing revoke
			net.MustLand(aclRepoGrant(net, net.Owner(), notes, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			return aclExpectReads(net, burner.SidecarId, notes, true)
		}),
	)
}

// FS-14's OwnerConfirm (the ledger's missing case; §8.5's confirmed clause, owner decision 126): an admin admits a
// device under a member, which no consent of the member's names, so it reads none of the member's vault; an admin's
// OwnerConfirm is refused at api and every reader; the member's consented device's lands, the device is consented at
// every reader and reads and writes the vault, and stays so across a base whose tail re-applies the confirmation.
func Fs14AclOwnerConfirm(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 acl owner confirm", world,
		fs14AclStart(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first := world.devices["m first"]
			world.ids["vault"] = aclCreateRepo(net, first, "m vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			tablet := net.Device("m tablet", first.MemberId)
			world.devices["m tablet"] = tablet
			net.AdmitDevice(net.Owner(), tablet, 0)
			return fs14AclExpectConfirmed(net, world, false)
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			tablet := world.devices["m tablet"]
			net.MustRefuse(net.Sign(net.Owner(), bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)), sidecar.ErrConfigAuthority)
			// nor does the device confirm itself
			net.MustRefuse(net.Sign(tablet, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)), sidecar.ErrConfigRule)
			return fs14AclExpectConfirmed(net, world, false)
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, tablet := world.devices["m first"], world.devices["m tablet"]
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)))
			if row := net.Row(tablet); sidecar.Id(row.GetOwnerConfirmSigner()) != first.SidecarId {
				return fmt.Errorf("the tablet's owner_confirm_signer is %x", row.GetOwnerConfirmSigner())
			}
			if err := fs14AclExpectConfirmed(net, world, true); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 48)
			return fs14AclExpectConfirmed(net, world, true)
		}),
	)
}

// Fails unless every reader holds the tablet consented for its member, and its rights on the member's vault the
// consented device's, exactly when confirmed says.
func fs14AclExpectConfirmed(net *sidecartest.AdmissionNet, world *fsTeamWorld, confirmed bool) error {
	tablet, vault := world.devices["m tablet"], sidecar.Id(world.ids["vault"])
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if acl.ConsentedFor(tablet.SidecarId, tablet.MemberId) != confirmed {
			return fmt.Errorf("the tablet consented: %t, want %t", !confirmed, confirmed)
		}
		rights := aclRights(net, acl, tablet.SidecarId, vault, sidecar.AclTokenAudienceEvs)
		want := sidecar.AclEvsDeposit
		if confirmed {
			want = sidecar.AclEvsRead | sidecar.AclEvsWrite
		}
		return aclExpectRights("the tablet on its member's vault", rights, want)
	})
	return nil
}

// FS-14's rotation covering one of two removals in one base's tail (the ledger's missing case; §7.9's shrink row,
// §10.6's gate): two RepoRevokes at n1 < n2 after one base drop two readers of a repo; a generation pinned at n1
// covers the first alone, so the gate refuses a write under it and a rotation from it must be REMOVE, at every
// reader, while one pinned at n2 passes; a base keeping the fold re-applies both, and every new device and gate gives
// the same answers.
func Fs14AclTwoRemovals(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 acl two removals", world,
		fs14AclStart(world),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			notes := sidecar.Id(world.ids["notes"])
			for _, label := range []string{"one", "two"} {
				burner := net.Device("burner "+label, net.Owner().MemberId)
				world.devices["burner "+label] = burner
				net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_SIDECAR_ADMIT,
					net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
				net.MustLand(aclRepoGrant(net, net.Owner(), notes, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			}
			net.Fold(true)
			for _, label := range []string{"one", "two"} {
				verdict := net.MustLand(aclRepoRevoke(net, net.Owner(), notes, world.devices["burner "+label].SidecarId))
				world.positions[label] = verdict.Pin.GetVersion()
				world.signed[label] = verdict.Pin.GetChain()
			}
			return fs14AclExpectCovers(net, world)
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			aclBaseKeepingTheFold(net, 48)
			return fs14AclExpectCovers(net, world)
		}),
	)
}

// The two-removal answers at every reader.
func fs14AclExpectCovers(net *sidecartest.AdmissionNet, world *fsTeamWorld) error {
	notes := sidecar.Id(world.ids["notes"])
	n1, n2 := world.positions["one"], world.positions["two"]
	pin1 := &bridge.AuthPin{Version: n1, Chain: world.signed["one"]}
	pin2 := &bridge.AuthPin{Version: n2, Chain: world.signed["two"]}
	now := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if shrunkAt := state.ShrunkAt(notes); shrunkAt != n2 {
			return fmt.Errorf("holders_shrunk_at %d, want the second removal's %d", shrunkAt, n2)
		}
		if !state.OnChain(pin1) || !state.OnChain(pin2) {
			return errors.New("a removal's pin is off this reader's chain")
		}
		drop := sidecar.GkmHolderDrop{ShrinkAt: n2}
		if sidecar.GkmGenerationCovers(state, pin1, now, drop) || !sidecar.GkmGenerationCovers(state, pin2, now, drop) {
			return errors.New("the generation at the first removal covers the second, or the one at the second does not")
		}
		if err := sidecar.GkmGateCheck(state, notes, pin1, now, now); !errors.Is(err, sidecar.ErrGkmGateClosed) {
			return fmt.Errorf("the gate under the first removal's generation: %v", err)
		}
		if err := sidecar.GkmGateCheck(state, notes, pin2, now, now); err != nil {
			return fmt.Errorf("the gate under the second removal's generation: %w", err)
		}
		if remove, err := sidecar.GkmRemoveDue(state, notes, pin1, now, now); err != nil || !remove {
			return fmt.Errorf("a rotation from the first removal's generation is REMOVE: %t, %v", remove, err)
		}
		if remove, err := sidecar.GkmRemoveDue(state, notes, pin2, now, now); err != nil || remove {
			return fmt.Errorf("a rotation from the second removal's generation is REMOVE: %t, %v", remove, err)
		}
		return nil
	})
	return nil
}

// FS-14's two readers forked at n+1 (§7.9's statement and fork rows, FI-10): a server serves two full readers, restored
// at one base, different statements at the next position, a socket GrantRevoke to one and a KeyRegister to the other,
// and a gate the first; each takes its own as it would from an honest api, so their pins differ at n+1; served the
// other's entry, each refuses it as a fork naming both A_{n+1}, and the gate refuses it as a second A_n at one n,
// keeping the pin it held. The socket grant's id is one no activation carries, since no process installs §16.6's spend
// check yet, so an admin revokes it ahead (§8.8's GrantRevoke row). Forged, so T2 alone.
func Fs14AclForkedReaders(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 acl forked readers", world,
		fs14AclStart(world),
		fsTeamDo("server", world, func(net *sidecartest.AdmissionNet) error {
			first := world.devices["m first"]
			n := net.Tip().GetVersion()
			readerOne, readerTwo, gate := net.ForkedReader(false), net.ForkedReader(false), net.ForkedReader(true)
			// a socket dial's grant, as a requested grant's CanonicalAction names it (§16.8, plan-ACL-folded-grant-state
			// #2: a sock: grant_dst holds §9.4's token path in hex)
			action, err := protoMarshal(&protocol.CanonicalAction{
				RuleId:     net.Id("socket rule").Bytes(),
				Subject:    first.SidecarId.Bytes(),
				GrantDst:   []string{"sock:" + fmt.Sprintf("%x", net.Id("socket db").Bytes())},
				GrantAllow: []string{"dial"},
			})
			if err != nil {
				return err
			}
			grantId := sidecar.AclGrantId(net.Id("socket approval"), sha256Sum(action))
			revoke := net.NextEntry(net.Sign(net.Owner(), bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{Header: net.Header(), GrantId: grantId[:]}))
			register := net.NextEntry(net.PresenceKeyRegister(first, sidecartest.NewFixturePresenceKey("fs14 fork key", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)))

			for _, served := range []struct {
				name  string
				log   *sidecar.ConfigLog
				entry []byte
			}{
				{name: "the first reader", log: readerOne, entry: revoke},
				{name: "the second reader", log: readerTwo, entry: register},
				{name: "the gate", log: gate, entry: revoke},
			} {
				verdict, err := net.ServeEntry(served.log, served.entry)
				if err != nil || !verdict.Accepted() {
					return fmt.Errorf("%s's own entry at %d: %v, %v", served.name, n+1, err, verdict.Refusal)
				}
			}
			pinOne, pinTwo := readerOne.Pin(), readerTwo.Pin()
			if pinOne.GetVersion() != n+1 || pinTwo.GetVersion() != n+1 || string(pinOne.GetChain()) == string(pinTwo.GetChain()) {
				return fmt.Errorf("the readers stand at %d and %d, chains equal %t", pinOne.GetVersion(), pinTwo.GetVersion(),
					string(pinOne.GetChain()) == string(pinTwo.GetChain()))
			}
			// the revoke took effect where it landed: the id is spent, for the network's life, as no activation carried it
			acl, err := readerOne.State().Acl()
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(acl.Rows().GetSpentGrants(), func(spent *protocol.AclSpentGrant) bool {
				return string(spent.GetGrantId()) == string(grantId[:]) && spent.GetRetainUntilMs() == 0
			}) {
				return errors.New("the first reader holds the revoked grant_id unspent")
			}
			// connected, each is shown the other's n+1, and refuses it as a fork naming both digests
			for _, crossed := range []struct {
				name   string
				log    *sidecar.ConfigLog
				entry  []byte
				local  []byte
				remote []byte
			}{
				{name: "the first reader", log: readerOne, entry: register, local: pinOne.GetChain(), remote: pinTwo.GetChain()},
				{name: "the second reader", log: readerTwo, entry: revoke, local: pinTwo.GetChain(), remote: pinOne.GetChain()},
			} {
				_, err := net.ServeEntry(crossed.log, crossed.entry)
				fork := &sidecar.ConfigForkError{}
				if !errors.As(err, &fork) || fork.N != n+1 || !fork.HasLocalChain ||
					string(fork.LocalChain[:]) != string(crossed.local) || string(fork.RemoteChain[:]) != string(crossed.remote) {
					return fmt.Errorf("%s served the other's entry: %v", crossed.name, err)
				}
				if crossed.log.Fork() == nil {
					return fmt.Errorf("%s stood on after the fork", crossed.name)
				}
			}
			gatePin := gate.Pin()
			if _, err := net.ServeEntry(gate, register); !errors.Is(err, sidecar.ErrConfigFork) && !errors.Is(err, sidecar.ErrConfigRunRefused) {
				return fmt.Errorf("the gate served a second A_%d: %v", n+1, err)
			}
			if gate.Pin().GetVersion() != gatePin.GetVersion() || string(gate.Pin().GetChain()) != string(gatePin.GetChain()) {
				return fmt.Errorf("the gate moved from %d to %d", gatePin.GetVersion(), gate.Pin().GetVersion())
			}
			// the honest api sequenced neither
			if net.Tip().GetVersion() != n {
				return fmt.Errorf("api's tip moved to %d", net.Tip().GetVersion())
			}
			return nil
		}),
	)
}

// Deterministic bytes of a message.
func protoMarshal(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// SHA-256 of data.
func sha256Sum(data []byte) [sha256.Size]byte {
	return sha256.Sum256(data)
}
