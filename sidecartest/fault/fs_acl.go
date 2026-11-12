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
// Named clauses, each a T2 test in fs_acl_test.go and a T3 test in server's sidecart3 where its row runs on T3:
//
//   - FS-14's acl cases (forged row, T2): Suspend and Unsuspend in both orders with a stale suspend_id a no-op, a config
//     writer's standing RepoRevoke, an OwnerConfirm, a rotation covering one of two removals in one base's tail, and
//     two readers a server forks at n+1 with a socket GrantRevoke and a KeyRegister, each refusing the other's entry
//     as a fork, while HeadCheck between two device followers forked the same way reports a fork with both A_{n+1} and
//     refreshes no witnessed_at, under FI-10. Its dispatchers' Hello alone is not on the forked log: the admission
//     world's devices are fixtures with no dispatcher, so the HeadCheck sidecars stand on the Net's default network.
//   - FS-62's gate case (T2+T3): api's, evs's and gkm's gate caches over AclGateDirectSource with {acl_}e current, lost,
//     stale and short.
//
// And, holding no FS row, schedules for §22.5's §8 row (AclRowsEqualTheWriters, AclRowsALyingWriter,
// AclVersionsRefused, AclNoDocumentRules), §22.7's revocation suite's acl clause (AclRevocationTaggedAgents), and S3a's
// and S4a's acl checks (AclAddsOnlyForReaders, AclRemovalDropsEveryRight).

package fault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
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
	burner                                                    *sidecartest.AdmissionDevice
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

// FS-14's forked readers' world: the admission world, the two device followers HeadCheck compares, the HeadCheck
// sidecars over them, one and two, api's tip where the views part, and when the followers witnessed each other there.
type fs14ForkWorld struct {
	*fsTeamWorld
	clients     []*sidecar.ConfigClient
	headCheck   *sidecartest.HeadCheckNet
	parted      *bridge.AuthPin
	witnessedAt time.Time
}

// A step of a forked readers' schedule, given both the Net, where HeadCheck's sidecars run, and the admission world.
func fs14ForkDo(actor string, world *fs14ForkWorld, body func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			return body(ctx, net, world.net)
		})
	}}
}

// The HeadCheck sidecars over the two followers, one's then two's, each with the other as its peer.
func (self *fs14ForkWorld) pairs() [][2]*sidecartest.HeadCheckSidecar {
	one, two := self.headCheck.Sidecar("one"), self.headCheck.Sidecar("two")
	return [][2]*sidecartest.HeadCheckSidecar{{one, two}, {two, one}}
}

// The second step: the followers clients makes at api's tip, and the HeadCheck sidecars comparing them.
func fs14AclFollowersAtTheTip(world *fs14ForkWorld, clients func(admission *sidecartest.AdmissionNet) []*sidecar.ConfigClient) *Step {
	return fs14ForkDo("setup", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		world.parted = admission.Tip()
		world.clients = clients(admission)
		headCheck, err := net.AddHeadCheckSidecarsOver(admission.NetworkId(),
			[]sidecar.HeadCheckAuthSource{world.clients[0], world.clients[1]}, "one", "two")
		if err != nil {
			return err
		}
		world.headCheck = headCheck
		return nil
	})
}

// Each runs one exchange with the other, one first, each counting it as a witness exactly when witnessed says.
func fs14AclExchanges(ctx context.Context, world *fs14ForkWorld, witnessed bool) error {
	for _, pair := range world.pairs() {
		counted, err := pair[0].HeadCheckWith(ctx, pair[1])
		if err != nil || counted != witnessed {
			return fmt.Errorf("%s's exchange with %s counted %t, want %t: %v", pair[0].Name, pair[1].Name, counted, witnessed, err)
		}
	}
	return nil
}

// The third step: on one base at api's tip, each counts the other, one as the first exchange's initiator, two as the
// second's, so both have witnessed api's tip now.
func fs14AclWitnessTheTip(world *fs14ForkWorld) *Step {
	return fs14ForkDo("one", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		if err := fs14AclExchanges(ctx, world, true); err != nil {
			return err
		}
		world.witnessedAt = admission.Clock().Now()
		return fs14AclExpectWitnessed(world, world.parted, world.witnessedAt)
	})
}

// Fails unless each HeadCheck sidecar's newest consistent witness compared pin, at witnessedAt.
func fs14AclExpectWitnessed(world *fs14ForkWorld, pin *bridge.AuthPin, witnessedAt time.Time) error {
	for _, side := range world.headCheck.Sidecars() {
		if !side.Stop.WitnessedAt().Equal(witnessedAt) || !proto.Equal(side.Stop.WitnessedPin(), pin) {
			return fmt.Errorf("%s witnessed %d at %s, want %d at %s", side.Name, side.Stop.WitnessedPin().GetVersion(),
				side.Stop.WitnessedAt(), pin.GetVersion(), witnessedAt)
		}
	}
	return nil
}

// A socket dial's grant, as a requested grant's CanonicalAction names it (§16.8, plan-ACL-folded-grant-state #2: a
// sock: grant_dst holds §9.4's token path in hex), revoked by an admin ahead of any activation (§8.8's GrantRevoke
// row): the GrantRevoke's Signed bytes, and the grant_id.
func fs14AclSocketGrantRevoke(net *sidecartest.AdmissionNet, world *fsTeamWorld) ([]byte, [sha256.Size]byte, error) {
	action, err := protoMarshal(&protocol.CanonicalAction{
		RuleId:     net.Id("socket rule").Bytes(),
		Subject:    world.devices["m first"].SidecarId.Bytes(),
		GrantDst:   []string{"sock:" + fmt.Sprintf("%x", net.Id("socket db").Bytes())},
		GrantAllow: []string{"dial"},
	})
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	grantId := sidecar.AclGrantId(net.Id("socket approval"), sha256Sum(action))
	return net.Sign(net.Owner(), bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{Header: net.Header(), GrantId: grantId[:]}), grantId, nil
}

// FS-14's two readers forked at n+1 (§7.9's statement and fork rows, §6.4's auth, fork and witness rows, FI-10): two
// device followers, TEAM-M2-10's ConfigClients, read api's entries to its tip n and stand on one base, and HeadCheck
// sidecars comparing them each count the other as a witness there. A server then serves two full readers restored at
// that base, the two followers and a gate different statements at n+1, a socket GrantRevoke to the first reader, the
// first follower and the gate, and a KeyRegister to the others; each takes its own as it would from an honest api, so
// the pins differ at n+1. Served the other's entry, each reader refuses it as a fork naming both A_{n+1}, and the gate
// refuses it as a second A_n at one n, keeping the pin it held. Connected, a minute on, both ways, HeadCheck reports
// a fork on each side with both A_{n+1}, its own first, naming the other, stops sealing in every shared group, and
// refreshes no witnessed_at, which stays the witness at api's tip once every responder's work has ended. The socket
// grant's id is one no activation carries, since no process installs §16.6's spend check yet, so an admin revokes it
// ahead. Forged, so T2 alone; its twin, Fs14AclConnectedReaders, is the honest server's. FI-10 reads both HeadCheck
// sidecars after every step.
func Fs14AclForkedReaders(net *Net) *Schedule {
	world := &fs14ForkWorld{fsTeamWorld: newFsTeamWorld()}
	followers := []*sidecartest.AdmissionForkedFollower{}
	connected := fs14ForkDo("one", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		if err := fs14AclExchanges(ctx, world, false); err != nil {
			return fmt.Errorf("across the fork: %w", err)
		}
		// every exchange and act either side still runs, a responder's witness among them, ends here
		for _, pair := range world.pairs() {
			pair[0].Detach()
		}
		pins := map[sidecar.Id]*bridge.AuthPin{}
		for i, pair := range world.pairs() {
			pins[pair[0].SidecarId] = world.clients[i].Pin()
		}
		for _, pair := range world.pairs() {
			side, peer := pair[0], pair[1]
			alarms := side.Alarms(sidecar.SidecarHeadAlarmFork)
			if len(alarms) != 1 {
				return fmt.Errorf("%s raised %d fork alarms, want one", side.Name, len(alarms))
			}
			alarm := alarms[0]
			if alarm.SidecarId == nil || *alarm.SidecarId != peer.SidecarId {
				return fmt.Errorf("%s's fork alarm names %v, not %s", side.Name, alarm.SidecarId, peer.Name)
			}
			local, remote := &bridge.AuthPin{}, &bridge.AuthPin{}
			if proto.Unmarshal(alarm.Evidence[0], local) != nil || proto.Unmarshal(alarm.Evidence[1], remote) != nil {
				return fmt.Errorf("%s's fork alarm carries no pins", side.Name)
			}
			if !proto.Equal(local, pins[side.SidecarId]) || !proto.Equal(remote, pins[peer.SidecarId]) {
				return fmt.Errorf("%s's fork alarm carries %d and %d, not its own A_%d and %s's", side.Name, local.GetVersion(),
					remote.GetVersion(), world.parted.GetVersion()+1, peer.Name)
			}
			// an auth fork stops sealing at once in every shared group, which every group is here (§6.4's fork row)
			stopped := &sidecar.HeadStopError{}
			if err := side.Stop.SealAllowed(admission.Id("a shared group")); !errors.As(err, &stopped) || stopped.Cause != sidecar.HeadStopFork {
				return fmt.Errorf("%s seals after the fork: %v", side.Name, err)
			}
		}
		// the witness at api's tip stands, a minute old: no exchange across the fork refreshed it
		if now := admission.Clock().Now(); !world.witnessedAt.Before(now) {
			return fmt.Errorf("the clock stands at %s, the witness at %s", now, world.witnessedAt)
		}
		return fs14AclExpectWitnessed(world, world.parted, world.witnessedAt)
	})
	// a minute on, once both followers stand at n+1, so a responder's witness still running from the exchanges at api's
	// tip writes that witness again, while a refresh across the fork would show
	connected.Advance = time.Minute
	schedule := fsTeamSchedule("FS-14 acl forked readers", world.fsTeamWorld,
		fs14AclStart(world.fsTeamWorld),
		fs14AclFollowersAtTheTip(world, func(admission *sidecartest.AdmissionNet) []*sidecar.ConfigClient {
			followers = []*sidecartest.AdmissionForkedFollower{admission.ForkedFollower(), admission.ForkedFollower()}
			return []*sidecar.ConfigClient{followers[0].Client, followers[1].Client}
		}),
		fs14AclWitnessTheTip(world),
		fs14ForkDo("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			return fs14AclServeTheFork(admission, world, followers)
		}),
		connected,
	)
	schedule.Check = append(schedule.Check, FI(10))
	schedule.Refuses = "each reader the other's entry at n+1, the gate a second A_{n+1}, and each follower's HeadCheck its peer's pin, as a fork naming both A_{n+1}"
	schedule.Twin = Fs14AclConnectedReaders
	return schedule
}

// The forked readers' twin, the honest server's (§22.8's twins): the same followers on api's own projection witness
// each other at its tip; api sequences the socket GrantRevoke at n+1, both followers read it, and connected, a minute
// on, both ways, each counts the other at n+1, raising no fork alarm, sealing allowed, witnessed_at refreshed to now at
// api's new tip. It carries T3 by §22.8's cadence rule.
func Fs14AclConnectedReaders(net *Net) *Schedule {
	world := &fs14ForkWorld{fsTeamWorld: newFsTeamWorld()}
	var tip *bridge.AuthPin
	connected := fs14ForkDo("one", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		if err := fs14AclExchanges(ctx, world, true); err != nil {
			return fmt.Errorf("at api's tip %d: %w", tip.GetVersion(), err)
		}
		for _, pair := range world.pairs() {
			pair[0].Detach()
		}
		for _, pair := range world.pairs() {
			side := pair[0]
			if alarms := side.Alarms(sidecar.SidecarHeadAlarmFork); len(alarms) != 0 {
				return fmt.Errorf("%s raised %d fork alarms on one history", side.Name, len(alarms))
			}
			if err := side.Stop.SealAllowed(admission.Id("a shared group")); err != nil {
				return fmt.Errorf("%s may not seal: %w", side.Name, err)
			}
		}
		return fs14AclExpectWitnessed(world, tip, admission.Clock().Now())
	})
	connected.Advance = time.Minute
	schedule := fsTeamSchedule("FS-14 acl connected readers", world.fsTeamWorld,
		fs14AclStart(world.fsTeamWorld),
		fs14AclFollowersAtTheTip(world, func(admission *sidecartest.AdmissionNet) []*sidecar.ConfigClient {
			return []*sidecar.ConfigClient{admission.Follower(), admission.Follower()}
		}),
		fs14AclWitnessTheTip(world),
		fs14ForkDo("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			revoke, _, err := fs14AclSocketGrantRevoke(admission, world.fsTeamWorld)
			if err != nil {
				return err
			}
			tip = admission.MustLand(revoke).Pin
			for i, client := range world.clients {
				if _, err := client.WaitFor(ctx, tip.GetVersion()); err != nil {
					return fmt.Errorf("follower %d at %d: %w", i+1, tip.GetVersion(), err)
				}
				if !proto.Equal(client.Pin(), tip) {
					return fmt.Errorf("follower %d stands at %d, not api's tip %d", i+1, client.Pin().GetVersion(), tip.GetVersion())
				}
			}
			return nil
		}),
		connected,
	)
	schedule.Check = append(schedule.Check, FI(10))
	schedule.Tiers = []Tier{TierT2, TierT3}
	return schedule
}

// The server's half of the forked readers' schedule: the statements at n+1, each reader, follower and the gate served
// its own, and each reader shown the other's.
func fs14AclServeTheFork(net *sidecartest.AdmissionNet, world *fs14ForkWorld, followers []*sidecartest.AdmissionForkedFollower) error {
	n := net.Tip().GetVersion()
	readerOne, readerTwo, gate := net.ForkedReader(false), net.ForkedReader(false), net.ForkedReader(true)
	signedRevoke, grantId, err := fs14AclSocketGrantRevoke(net, world.fsTeamWorld)
	if err != nil {
		return err
	}
	revoke := net.NextEntry(signedRevoke)
	register := net.NextEntry(net.PresenceKeyRegister(world.devices["m first"], sidecartest.NewFixturePresenceKey("fs14 fork key", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)))

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
	// each follower, served the same entry as the reader beside it, takes it and stands on the same A_{n+1}
	for i, served := range []struct {
		entry []byte
		pin   *bridge.AuthPin
	}{
		{entry: revoke, pin: pinOne},
		{entry: register, pin: pinTwo},
	} {
		if pin := followers[i].Fork(served.entry); !proto.Equal(pin, served.pin) {
			return fmt.Errorf("follower %d stands at %d on another A_%d than its reader", i+1, pin.GetVersion(), n+1)
		}
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
	// shown the other's n+1, each reader refuses it as a fork naming both digests
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
}

// Deterministic bytes of a message.
func protoMarshal(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// SHA-256 of data.
func sha256Sum(data []byte) [sha256.Size]byte {
	return sha256.Sum256(data)
}

// A gate's store, its reads counted: what tells a load from {acl_}e from one from proj/.
type fs62AclCountingBlobs struct {
	sidecar.BlobStore
	reads *atomic.Int64
}

func (self fs62AclCountingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return fs62AclCountingCluster{BlobCluster: cluster, reads: self.reads}, nil
}

type fs62AclCountingCluster struct {
	sidecar.BlobCluster
	reads *atomic.Int64
}

func (self fs62AclCountingCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	self.reads.Add(1)
	return self.BlobCluster.Get(ctx, key)
}

func (self fs62AclCountingCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	self.reads.Add(1)
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// One process's gate cache over the direct source, api's, evs's or gkm's, its store reads counted and each load's
// outcome sent on loads.
type fs62AclGate struct {
	name  string
	cache *sidecar.AclGateCache
	reads atomic.Int64
	loads chan *bridge.AuthPin
}

// FS-62's gate case's world: the admission world, and the gates.
type fs62AclWorld struct {
	*fsTeamWorld
	gates []*fs62AclGate
}

// What api's one script does after the entry at n (TEAM-M2-14's, server/model/config_log_redis.go), on the Net's
// Redis: with write, {acl_}e gains the entry and the tip, with the newest base's position, and records the value
// {acl_}v is raised to; then the INCR, whose event reaches every gate. Without write, the INCR alone, as when the
// hash was lost or its write never landed.
func fs62AclScript(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet, n uint64, write bool) error {
	redis := net.Host().Redis
	networkId := admission.NetworkId()
	if write {
		current, _, err := redis.Get(ctx, sidecar.AclVersionKey(networkId))
		if err != nil {
			return err
		}
		version := int64(0)
		if 0 < len(current) {
			if version, err = strconv.ParseInt(string(current), 10, 64); err != nil {
				return err
			}
		}
		entryBytes := admission.Entry(n)
		if entryBytes == nil {
			return fmt.Errorf("no entry at %d", n)
		}
		if err := redis.HashSet(ctx, sidecar.AclEntryCacheKey(networkId), map[string][]byte{
			sidecar.AclEntryCacheField(n):     entryBytes,
			sidecar.AclEntryCacheFieldBase:    []byte(strconv.FormatUint(admission.State().Base().GetVersion(), 10)),
			sidecar.AclEntryCacheFieldTip:     []byte(strconv.FormatUint(n, 10)),
			sidecar.AclEntryCacheFieldVersion: []byte(strconv.FormatInt(version+1, 10)),
		}); err != nil {
			return err
		}
	}
	_, err := redis.Increment(ctx, sidecar.AclVersionKey(networkId), 48*time.Hour)
	return err
}

// Appends a member admit through api, then api's script with or without the hash write; each gate told, as its
// subscriber's event tells it, and waited for. The new tip.
func fs62AclAppend(ctx context.Context, net *Net, world *fs62AclWorld, label string, write bool) (uint64, error) {
	admission := world.net
	verdict := admission.MustLand(admission.Sign(admission.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT,
		admission.MemberAdmit(admission.Id("fs62 member "+label), bridge.MemberRole_MEMBER_ROLE_MEMBER)))
	n := verdict.Pin.GetVersion()
	if err := fs62AclScript(ctx, net, admission, n, write); err != nil {
		return 0, err
	}
	return n, nil
}

// Tells every gate the network changed and waits for each one's load: none may land below the pin it held, every one
// must reach want, and each one's store reads must be some exactly when fromStore says.
func fs62AclLoad(world *fs62AclWorld, want uint64, fromStore bool) error {
	networkId := world.net.NetworkId()
	for _, gate := range world.gates {
		before, _ := gate.cache.State(networkId)
		readsBefore := gate.reads.Load()
		gate.cache.Changed(networkId)
		// the world's context ends at the suite's RowTimeout, a failure's bound only
		select {
		case <-gate.loads:
		case <-world.net.Context().Done():
			return fmt.Errorf("%s: no load finished: %w", gate.name, world.net.Context().Err())
		}
		snapshot, status := gate.cache.State(networkId)
		if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Pin.GetVersion() != want {
			held := uint64(0)
			if snapshot != nil {
				held = snapshot.Pin.GetVersion()
			}
			return fmt.Errorf("%s holds %d (status %d), want %d", gate.name, held, status, want)
		}
		if before != nil && snapshot.Pin.GetVersion() < before.Pin.GetVersion() {
			return fmt.Errorf("%s fell from %d to %d", gate.name, before.Pin.GetVersion(), snapshot.Pin.GetVersion())
		}
		if !proto.Equal(snapshot.Pin, world.net.VerdictAt(want).Pin) {
			return fmt.Errorf("%s holds another A_%d than api's", gate.name, want)
		}
		if readStore := gate.reads.Load() != readsBefore; readStore != fromStore {
			return fmt.Errorf("%s read the store: %t, want %t", gate.name, readStore, fromStore)
		}
	}
	return nil
}

// FS-62's {acl_}e case (§7.9's read cache, §8.9, owner decision 136): api's, evs's and gkm's gate caches, each over
// AclGateDirectSource on the Net's Redis and first metadata cluster, load the log's tip from {acl_}e while it records
// {acl_}v's current value and holds every position they need, with no read of proj/; with the hash lost, then stale
// (recording an older {acl_}v and an older tip), then short of a position, each reads proj/ instead and reaches api's
// tip; and a hash that is current but holds a tip below a gate's pin moves no gate down. T2 and T3: on T3 the Redis is
// server's and the store the local stack's MinIO, while api's script is the schedule's own until sidecart3's sequencer
// installs model.NewConfigLogRedisEntryCache.
func Fs62AclGate(net *Net) *Schedule {
	world := &fs62AclWorld{fsTeamWorld: newFsTeamWorld()}
	steps := []*Step{
		aclSetup(world.fsTeamWorld, func(admission *sidecartest.AdmissionNet) error {
			for _, name := range []string{"api", "evs", "gkm"} {
				gate := &fs62AclGate{name: name, loads: make(chan *bridge.AuthPin, 64)}
				settings := sidecar.DefaultAclGateSettings()
				settings.Log = sidecar.NewNoopLogger()
				settings.PollInterval = 0
				settings.FailureBackoff = 0
				settings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
					gate.loads <- pin
				}
				blobs := fs62AclCountingBlobs{BlobStore: net.Host().Blobs, reads: &gate.reads}
				gate.cache = sidecar.NewAclGateCache(admission.Context(), sidecar.NewAclGateDirectSource(net.Host().Redis, blobs, settings), net.Clock(), settings)
				world.gates = append(world.gates, gate)
			}
			// a cold start reads proj/ from position 1
			return fs62AclLoad(world, admission.Tip().GetVersion(), true)
		}),
		fsTeamDo("api", world.fsTeamWorld, func(admission *sidecartest.AdmissionNet) error {
			// current: two appends load from {acl_}e alone
			for _, label := range []string{"one", "two"} {
				n, err := fs62AclAppend(admission.Context(), net, world, label, true)
				if err != nil {
					return err
				}
				if err := fs62AclLoad(world, n, false); err != nil {
					return fmt.Errorf("{acl_}e current: %w", err)
				}
			}
			return nil
		}),
		fsTeamDo("api", world.fsTeamWorld, func(admission *sidecartest.AdmissionNet) error {
			// lost: {acl_}e gone, and the next append's script writes no hash
			if err := net.Host().Redis.Delete(admission.Context(), []string{sidecar.AclEntryCacheKey(admission.NetworkId())}); err != nil {
				return err
			}
			n, err := fs62AclAppend(admission.Context(), net, world, "lost", false)
			if err != nil {
				return err
			}
			if err := fs62AclLoad(world, n, true); err != nil {
				return fmt.Errorf("{acl_}e lost: %w", err)
			}
			// written again for the next, so it serves
			n, err = fs62AclAppend(admission.Context(), net, world, "again", true)
			if err != nil {
				return err
			}
			if err := fs62AclLoad(world, n, false); err != nil {
				return fmt.Errorf("{acl_}e current again: %w", err)
			}
			// stale: {acl_}v raised past what the hash records, the hash's tip an older one
			n, err = fs62AclAppend(admission.Context(), net, world, "stale", false)
			if err != nil {
				return err
			}
			if err := fs62AclLoad(world, n, true); err != nil {
				return fmt.Errorf("{acl_}e stale: %w", err)
			}
			return nil
		}),
		fsTeamDo("api", world.fsTeamWorld, func(admission *sidecartest.AdmissionNet) error {
			networkId := admission.NetworkId()
			redis := net.Host().Redis
			// short of a position: current, but missing one the gates need
			first, err := fs62AclAppend(admission.Context(), net, world, "short one", true)
			if err != nil {
				return err
			}
			second, err := fs62AclAppend(admission.Context(), net, world, "short two", true)
			if err != nil {
				return err
			}
			if err := redis.HashDelete(admission.Context(), sidecar.AclEntryCacheKey(networkId), []string{sidecar.AclEntryCacheField(first)}); err != nil {
				return err
			}
			if err := fs62AclLoad(world, second, true); err != nil {
				return fmt.Errorf("{acl_}e short of %d: %w", first, err)
			}
			// current but holding a tip below every gate's pin, as a hash some older write left: no gate moves down,
			// and none reads the store for what the hash claims it holds
			current, _, err := redis.Get(admission.Context(), sidecar.AclVersionKey(networkId))
			if err != nil {
				return err
			}
			if err := redis.HashSet(admission.Context(), sidecar.AclEntryCacheKey(networkId), map[string][]byte{
				sidecar.AclEntryCacheFieldTip:     []byte(strconv.FormatUint(first-1, 10)),
				sidecar.AclEntryCacheFieldVersion: current,
			}); err != nil {
				return err
			}
			if err := fs62AclLoad(world, second, false); err != nil {
				return fmt.Errorf("{acl_}e below the gates' pin: %w", err)
			}
			return nil
		}),
	}
	return fsTeamSchedule("FS-62 acl gate", world.fsTeamWorld, steps...)
}

// §22.5's §8 row and §22.7's revocation suite's acl clauses, as schedules on the same world, which the T2 tests run
// fixed (fs_acl_test.go): no FS row holds them, so none registers.

// Deterministic bytes of an AclRows, for comparing two.
func aclRowsBytes(rows *protocol.AclRows) []byte {
	encoded, err := protoMarshal(rows)
	if err != nil {
		panic(fsTeamFailure{err: err})
	}
	return encoded
}

// Fails unless every reader's acl rows are the writer's compile, byte for byte.
func aclExpectWritersRows(net *sidecartest.AdmissionNet, plan *sidecar.AclSavePlan) error {
	want := aclRowsBytes(plan.Rows)
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if got := aclRowsBytes(acl.Rows()); string(got) != string(want) {
			return fmt.Errorf("acl rows of %d bytes, the writer's compile %d", len(got), len(want))
		}
		return nil
	})
	return nil
}

// The member the §8 row's documents name, and a resolver for it.
func aclRowMember(net *sidecartest.AdmissionNet, world *fsTeamWorld) sidecartest.AclSaveMembers {
	return sidecartest.AclSaveMembers{"m@acme.example": world.devices["m first"].MemberId}
}

// §22.5's §8 row, "readers' AclRows equal the writer's" (§8.8, D-ACL-15, R-ACL-12): a document naming a group, a tag,
// a request and evs:* is saved on the writer's device; every reader's rows, the reference's, each new device's and
// gate's at the base, and the writer's follower's, are the writer's compile byte for byte; a second save keeps the
// ids of the rules it did not change and every reader again holds its compile. AclRowsALyingWriter is the alarm half.
func AclRowsEqualTheWriters(net *Net) *Schedule {
	world := newFsTeamWorld()
	first := `{
		"groups": { "group:eng": ["m@acme.example"] },
		"tagOwners": { "tag:ci": ["group:eng"] },
		"grants": [
			{ "src": ["autogroup:member"], "dst": ["evs:*"], "allow": ["write"] },
			{ "src": ["group:eng"], "dst": ["tag:ci"], "allow": ["dial"] },
			{ "src": ["tag:ci"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
		],
		"requests": [
			{ "src": ["tag:ci"], "dst": ["autogroup:member"], "allow": ["route"], "approver": ["autogroup:sponsor"], "maxExpiry": "7d" },
		],
	}`
	second := `{
		"groups": { "group:eng": ["m@acme.example"] },
		"tagOwners": { "tag:ci": ["group:eng"] },
		"grants": [
			{ "src": ["autogroup:member"], "dst": ["evs:*"], "allow": ["write"] },
			{ "src": ["tag:ci"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
		],
	}`
	return fsTeamSchedule("§8 rows equal the writer's", world,
		aclSetup(world, func(net *sidecartest.AdmissionNet) error {
			_, device := net.ConsentedMember("m")
			world.devices["m first"] = device
			net.Fold(true)
			return nil
		}),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			plan, _ := net.SaveAclPolicy([]byte(first), aclRowMember(net, world))
			if !plan.Rows.GetHasDocument() || len(plan.Rows.GetRequests()) != 1 {
				return fmt.Errorf("the compile: has_document %t, %d requests", plan.Rows.GetHasDocument(), len(plan.Rows.GetRequests()))
			}
			if err := aclExpectWritersRows(net, plan); err != nil {
				return err
			}
			world.ids["first rules"] = aclRuleIds(plan.Rows)
			return nil
		}),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			plan, _ := net.SaveAclPolicy([]byte(second), aclRowMember(net, world))
			if err := aclExpectWritersRows(net, plan); err != nil {
				return err
			}
			// the evs:* write and the tagged dial keep their ids; the dropped dial's leaves with it
			kept := 0
			for _, ruleId := range aclRuleIdList(plan.Rows) {
				if slices.Contains(aclRuleIdList(&protocol.AclRows{Rules: aclRulesOf(world.ids["first rules"])}), ruleId) {
					kept += 1
				}
			}
			if want := len(plan.Rows.GetRules()); kept != want {
				return fmt.Errorf("%d of the second save's %d rules kept the first's ids", kept, want)
			}
			return nil
		}),
	)
}

// §8.8's alarm half of "readers recompile rows": a writer whose base names rows that are not its head's compile, one
// rule more, granting tagged sidecars every general repo's admin, is taken by api, which sees ids alone, and forked off
// by every full reader that judges it, each recompiling the head, while every gate takes the rows it cannot check, for
// HeadCheck between them and a full reader to settle (§6.4). The gates then stand where the reference does not, so the
// schedule leaves out the world's agreement check, which every entry before the base still ran inside the world.
func AclRowsALyingWriter(net *Net) *Schedule {
	world := newFsTeamWorld()
	return &Schedule{Id: "§8 rows a lying writer", Steps: []*Step{
		aclSetup(world, func(net *sidecartest.AdmissionNet) error {
			_, device := net.ConsentedMember("m")
			world.devices["m first"] = device
			net.Fold(true)
			net.SaveAclPolicy([]byte(`{
				"grants": [ { "src": ["autogroup:member"], "dst": ["evs:*"], "allow": ["write"] } ],
			}`), nil)
			return nil
		}),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			// a writer signing rows that are not its head's compile: one more rule, granting tagged sidecars every general
			// repo's admin
			_, rowsBytes := net.BaseKeepingTheFold(net.WriterDevice(), nil)
			projection := &bridge.ProjectionRows{}
			if err := proto.Unmarshal(rowsBytes, projection); err != nil {
				return err
			}
			aclRows := &protocol.AclRows{}
			if err := proto.Unmarshal(projection.GetAcl(), aclRows); err != nil {
				return err
			}
			aclRows.Rules = append(aclRows.Rules, &protocol.AclRule{
				RuleId:   net.Id("a rule no head holds").Bytes(),
				SrcAtoms: [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED).Bytes()},
				Targets:  []*protocol.AclTarget{{RepoId: make([]byte, 16)}},
				Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_ADMIN)},
			})
			slices.SortFunc(aclRows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int {
				return compareBytes(a.GetRuleId(), b.GetRuleId())
			})
			projection.Acl = aclRowsBytes(aclRows)
			forged, err := protoMarshal(projection)
			if err != nil {
				return err
			}
			forgedSha256 := sha256Sum(forged)
			signedHeader, _ := net.BaseKeepingTheFold(net.WriterDevice(), func(header *bridge.ProjectionHeader) {
				header.RowsSha256 = forgedSha256[:]
				header.RowsByteCount = uint32(len(forged))
			})
			net.AllowForks()
			pin, err := net.AppendBase(signedHeader, forged)
			if err != nil {
				return fmt.Errorf("api, which sees ids alone, refused the rows: %w", err)
			}
			forks := net.Forks()
			if _, forked := forks["the reference"]; !forked {
				return fmt.Errorf("the reference took rows its head does not compile: %v", forks)
			}
			for name, n := range forks {
				if n != pin.GetVersion() || strings.HasPrefix(name, "a gate") {
					return fmt.Errorf("%s forked at %d, the base at %d", name, n, pin.GetVersion())
				}
			}
			// every full reader that judged the base refused it; each gate took it, holding rows it cannot open a head
			// for, which HeadCheck between them and a full reader settles (§6.4)
			gates := 0
			for _, reader := range net.ReaderStates() {
				atBase := reader.Config.Pin().GetVersion() == pin.GetVersion()
				isGate := strings.HasPrefix(reader.Name, "a gate")
				if atBase != isGate {
					return fmt.Errorf("%s stands at %d, the forged base at %d", reader.Name, reader.Config.Pin().GetVersion(), pin.GetVersion())
				}
				if isGate {
					gates += 1
				}
			}
			if gates == 0 {
				return errors.New("no gate ran")
			}
			return nil
		}),
		fsTeamClose(world),
	}}
}

// A rows' rule ids, joined, for a world's ids map, and back.
func aclRuleIds(rows *protocol.AclRows) []byte {
	joined := []byte{}
	for _, rule := range rows.GetRules() {
		joined = append(joined, rule.GetRuleId()...)
	}
	return joined
}

func aclRulesOf(joined []byte) []*protocol.AclRule {
	rules := []*protocol.AclRule{}
	for i := 0; i+16 <= len(joined); i += 16 {
		rules = append(rules, &protocol.AclRule{RuleId: joined[i : i+16]})
	}
	return rules
}

func aclRuleIdList(rows *protocol.AclRows) []string {
	ids := []string{}
	for _, rule := range rows.GetRules() {
		ids = append(ids, string(rule.GetRuleId()))
	}
	return ids
}

func compareBytes(a []byte, b []byte) int {
	return strings.Compare(string(a), string(b))
}

// The states an AclEngine reads pushes' pins at: a reader's, by ConfigState.StateAt.
type aclEngineStates struct {
	state *sidecar.ConfigState
}

func (self aclEngineStates) AclStateAt(pin *bridge.AuthPin) (*sidecar.AclState, error) {
	state, err := self.state.StateAt(pin)
	if err != nil {
		return nil, err
	}
	return state.Acl()
}

// §22.5's §8 row, "lower or forked versions refused" (I-16, §8.9): a device's AclEngine takes its follower's state at
// each position and refuses a lower one and a second A_n at the n it holds, alarming and keeping what it held; and a
// push whose pin is off the engine's chain gets no head signer.
func AclVersionsRefused(net *Net) *Schedule {
	world := newFsTeamWorld()
	var engine *sidecar.AclEngine
	alarms := []sidecar.AclEngineAlarm{}
	return fsTeamSchedule("§8 lower or forked versions refused", world,
		fs14AclStart(world),
		fsTeamDo("device", world, func(net *sidecartest.AdmissionNet) error {
			first, notes := world.devices["m first"], sidecar.Id(world.ids["notes"])
			engine = sidecar.NewAclEngine(first.SidecarId, aclEngineStates{state: net.State()}, func(alarm sidecar.AclEngineAlarm) {
				alarms = append(alarms, alarm)
			}, nil)
			older, err := net.State().Acl()
			if err != nil {
				return err
			}
			if err := engine.Install(older, nil); err != nil {
				return err
			}
			// a server forking this device's view at the next position, before api sequences the honest entry there
			forked := net.ForkedReader(false)
			honest := net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT,
				net.MemberAdmit(net.Id("honest member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)))
			if _, err := net.ServeEntry(forked, net.ForkEntryAt(honest.Pin.GetVersion(), net.Sign(net.Owner(),
				bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id("forked member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)))); err != nil {
				return fmt.Errorf("the forked view's entry: %w", err)
			}
			current, err := net.State().Acl()
			if err != nil {
				return err
			}
			if err := engine.Install(current, nil); err != nil {
				return fmt.Errorf("the next state: %w", err)
			}
			if err := engine.Install(older, nil); !errors.Is(err, sidecar.ErrAclEnginePinLower) {
				return fmt.Errorf("a lower state: %v", err)
			}
			forkedAcl, err := forked.State().Acl()
			if err != nil {
				return err
			}
			if err := engine.Install(forkedAcl, nil); !errors.Is(err, sidecar.ErrAclEngineFork) {
				return fmt.Errorf("a second A_%d: %v", honest.Pin.GetVersion(), err)
			}
			if !proto.Equal(engine.Pin(), honest.Pin) {
				return fmt.Errorf("the engine holds %d, not the honest %d", engine.Pin().GetVersion(), honest.Pin.GetVersion())
			}
			if len(alarms) != 2 || alarms[0].Kind != sidecar.AclEngineAlarmPinLower || alarms[1].Kind != sidecar.AclEngineAlarmFork {
				return fmt.Errorf("alarms %v", alarms)
			}
			// heads only from writers, at a pin on this device's chain
			engine = sidecar.NewAclEngine(first.SidecarId, aclEngineStates{state: net.State()}, nil, nil)
			if err := engine.Install(current, nil); err != nil {
				return err
			}
			now := net.Clock().Now()
			if err := engine.VerifyHeadSigner(notes, first.SidecarId, honest.Pin, now); err != nil {
				return fmt.Errorf("the repo's admin's head at an honest pin: %w", err)
			}
			if err := engine.VerifyHeadSigner(notes, first.SidecarId, forked.Pin(), now); err == nil {
				return errors.New("a head at a forked pin passed")
			}
			return nil
		}),
	)
}

// §22.5's §8 row, "§8.5's no-document rules" (owner decisions 50, 105, 120; D-ACL-20): with no document every reader
// compiles the implicit one: member devices and app devices keep today's reach, legacy clients too, member devices
// write and administer general repos, no one holds a standing publish or tls/ listen, and the implicit requests rules
// stand with their approvers, evidence and expiries.
func AclNoDocumentRules(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("§8 no-document rules", world,
		fs14AclStart(world),
		fsTeamDo("check", world, func(net *sidecartest.AdmissionNet) error {
			first, phone, notes := world.devices["m first"], world.devices["m phone"], sidecar.Id(world.ids["notes"])
			laptop := sidecar.AclSidecarSubject(net.Owner().SidecarId)
			appDevice := sidecar.AclClientSubject(net.Id("m app client"), first.MemberId, nil, "")
			legacy := sidecar.AclClientSubject(net.Id("legacy client"), sidecar.Id{}, nil, "")
			now := net.Clock().Now()
			net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				if acl.HasDocument() {
					return errors.New("has_document with no document")
				}
				for _, reach := range []struct {
					what                string
					source, destination sidecar.AclSubject
				}{
					{what: "a member device to another member's", source: sidecar.AclSidecarSubject(phone.SidecarId), destination: laptop},
					{what: "a member device to its member's app device", source: sidecar.AclSidecarSubject(first.SidecarId), destination: appDevice},
					{what: "an app device to a member device", source: appDevice, destination: laptop},
					{what: "a legacy client to a member device", source: legacy, destination: laptop},
					{what: "a member device to a legacy client", source: laptop, destination: legacy},
				} {
					if decision := acl.Reach(reach.source, reach.destination, now); !decision.Allowed {
						return fmt.Errorf("%s: %s", reach.what, decision.Reason)
					}
				}
				if rights := aclRights(net, acl, phone.SidecarId, notes, sidecar.AclTokenAudienceEvs); !rights.Has(sidecar.AclEvsAdmin | sidecar.AclEvsWrite) {
					return fmt.Errorf("a member device's rights on a general repo: %04b", rights)
				}
				if decision := acl.MayListen(laptop, sidecar.AclSocketName{PublicName: "tls/443/blog"}, now); decision.Allowed {
					return errors.New("a standing tls/ listen with no document")
				}
				if decision := acl.MayPublish(laptop, "blog", now); decision.Allowed {
					return errors.New("a standing publish with no document")
				}
				// the implicit document's four requests rules: publish and listen by an admin for 7 days, a tagged
				// sidecar's own asks by its owner or sponsor for 30, shares by an admin for 30, the directory's reach by
				// the destination's owner on a device or presence key for 30
				requests := acl.Rows().GetRequests()
				if len(requests) != 4 {
					return fmt.Errorf("%d requests rules", len(requests))
				}
				want := []struct {
					approver  protocol.AclAutogroup
					maxExpiry time.Duration
				}{
					{approver: protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN, maxExpiry: 7 * 24 * time.Hour},
					{approver: protocol.AclAutogroup_ACL_AUTOGROUP_SELF, maxExpiry: 30 * 24 * time.Hour},
					{approver: protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN, maxExpiry: 30 * 24 * time.Hour},
					{approver: protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER, maxExpiry: 30 * 24 * time.Hour},
				}
				for _, rule := range want {
					if !slices.ContainsFunc(requests, func(request *protocol.AclRequestRule) bool {
						return len(request.GetApproverAtoms()) == 1 && sidecar.Id(request.GetApproverAtoms()[0]) == sidecar.AclAutogroupAtom(rule.approver) &&
							request.GetMaxExpirySeconds() == int64(rule.maxExpiry/time.Second) && request.GetDefaultExpirySeconds() == int64(time.Hour/time.Second)
					}) {
						return fmt.Errorf("no requests rule approved by %s for %s", rule.approver, rule.maxExpiry)
					}
				}
				directory := slices.IndexFunc(requests, func(request *protocol.AclRequestRule) bool {
					return sidecar.Id(request.GetApproverAtoms()[0]) == sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)
				})
				evidence := requests[directory].GetEvidence()
				if !slices.Equal(evidence, []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)}) {
					return fmt.Errorf("the directory's reach requests take evidence %v", evidence)
				}
				return nil
			})
			return nil
		}),
	)
}

// §22.7's revocation suite's acl clause (owner decision 83): a member's tagged agent keeps its tag's grants once the
// member is removed, its rule's reach and its RepoGrant alike, and the requests rule's autogroup:sponsor, which named
// the member, resolves to autogroup:admin until an admin's SponsorSet names another, at every reader.
func AclRevocationTaggedAgents(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("§22.7 a removed member's tagged agents", world,
		aclSetup(world, func(net *sidecartest.AdmissionNet) error {
			_, first := net.ConsentedMember("m")
			world.devices["m first"] = first
			_, other := net.ConsentedMember("n")
			world.devices["n first"] = other
			net.Fold(true)
			plan, _ := net.SaveAclPolicy([]byte(`{
				"tagOwners": { "tag:ci": ["autogroup:member"] },
				"grants": [
					{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
					{ "src": ["tag:ci"], "dst": ["autogroup:member"], "allow": ["dial"] },
				],
				"requests": [
					{ "src": ["tag:ci"], "dst": ["autogroup:member"], "allow": ["route"], "approver": ["autogroup:sponsor"] },
				],
			}`), nil)
			tagId, found := sidecartest.AclTagAtom(plan, "ci")
			if !found {
				return errors.New("the saved head names no tag:ci")
			}
			world.ids["tag ci"] = tagId.Bytes()
			world.ids["ci notes"] = aclCreateRepo(net, net.Owner(), "ci notes", protocol.RepoKind_REPO_KIND_GENERAL).Bytes()
			net.MustLand(aclRepoGrant(net, net.Owner(), sidecar.Id(world.ids["ci notes"]), tagId, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER))
			agent := net.Device("m ci agent", sidecar.Id{})
			world.devices["agent"] = agent
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(agent, []sidecar.Id{tagId}, false, net.Clock().Now().Add(7*24*time.Hour).UnixMilli(), 0)))
			return aclExpectTaggedAgent(net, world, first.MemberId)
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(world.devices["m first"].MemberId)))
			if !net.Admitted(world.devices["agent"]) {
				return errors.New("the member's removal removed its tagged agent")
			}
			return aclExpectTaggedAgent(net, world, sidecar.Id{})
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			agent, other := world.devices["agent"], world.devices["n first"]
			net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_SPONSOR_SET, &protocol.SponsorSet{
				Header: net.Header(), SidecarId: agent.SidecarId.Bytes(), SponsorMemberId: other.MemberId.Bytes(),
			}))
			return aclExpectTaggedAgent(net, world, other.MemberId)
		}),
	)
}

// Fails unless, at every reader, the tagged agent dials the owner's laptop by its tag's rule and writes the repo its
// tag's RepoGrant names, and the requests rule's sponsor resolves to sponsor, or with none to autogroup:admin.
func aclExpectTaggedAgent(net *sidecartest.AdmissionNet, world *fsTeamWorld, sponsor sidecar.Id) error {
	agent, tagId, notes := world.devices["agent"], sidecar.Id(world.ids["tag ci"]), sidecar.Id(world.ids["ci notes"])
	now := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if decision := acl.MayDial(sidecar.AclSidecarSubject(agent.SidecarId), sidecar.AclSidecarSubject(net.Owner().SidecarId), now); !decision.Allowed {
			return fmt.Errorf("the agent's tag rule: %s", decision.Reason)
		}
		if rights := aclRights(net, acl, agent.SidecarId, notes, sidecar.AclTokenAudienceEvs); !rights.Has(sidecar.AclEvsWrite) {
			return fmt.Errorf("the agent's tag's RepoGrant: %04b", rights)
		}
		requests := acl.Rows().GetRequests()
		index := slices.IndexFunc(requests, func(request *protocol.AclRequestRule) bool {
			return slices.ContainsFunc(request.GetSrcAtoms(), func(atom []byte) bool { return sidecar.Id(atom) == tagId })
		})
		if index < 0 {
			return errors.New("no requests rule from tag:ci")
		}
		approvers := acl.ResolveApprovers(requests[index].GetApproverAtoms(), sidecar.AclSidecarSubject(agent.SidecarId), nil, now)
		if sponsor == (sidecar.Id{}) {
			if !approvers.HasAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) || 0 < len(approvers.MemberIds) {
				return fmt.Errorf("with its sponsor removed, the approvers are %v and autogroups %b", approvers.MemberIds, approvers.Autogroups)
			}
			if !acl.Approves(approvers, net.Owner().MemberId) || acl.Approves(approvers, world.devices["n first"].MemberId) {
				return errors.New("autogroup:admin approves another than the Owner")
			}
			return nil
		}
		if approvers.HasAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) || !slices.Equal(approvers.MemberIds, []sidecar.Id{sponsor}) {
			return fmt.Errorf("the approvers are %v and autogroups %b, want the sponsor %s", approvers.MemberIds, approvers.Autogroups, sponsor)
		}
		return nil
	})
	return nil
}

// S3a's acl checks (§22.7's S3, F3; R-ACL-7, §10.9, §8.12): who a commit or a wrap may add to a repo's key holders,
// judged by every reader on the state as the log built it, so a breached server can neither admit a ghost nor grant a
// reader. A member device reads a general repo and takes a leaf, an ephemeral sidecar neither until a repo admin's
// RepoGrant names it, and then a wrap only; a device an admin admitted under a member takes no part of the member's
// vault until the member's OwnerConfirm; a sidecar the log never admitted takes nothing; no tree passes 1,000
// leaves; and on T2 a malicious api's RepoGrant by a sidecar that is no repo admin is refused at its position by
// every reader, so it adds no reader.
func AclAddsOnlyForReaders(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("S3a's acl checks", world,
		fs14AclStart(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first := world.devices["m first"]
			burner := net.Device("m burner", first.MemberId)
			world.devices["m burner"] = burner
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			world.ids["vault"] = aclCreateRepo(net, first, "m vault", protocol.RepoKind_REPO_KIND_VAULT).Bytes()
			tablet := net.Device("m tablet", first.MemberId)
			world.devices["m tablet"] = tablet
			net.AdmitDevice(net.Owner(), tablet, 0)
			return aclExpectMembers(net, world, false, false)
		}),
		fsTeamDo("server", world, func(net *sidecartest.AdmissionNet) error {
			burner, notes := world.devices["m burner"], sidecar.Id(world.ids["notes"])
			// the phone is no admin of the repo: api refuses its grant, and on T2 a malicious api lands it anyway, which
			// every reader refuses at its position
			grant := aclRepoGrant(net, world.devices["m phone"], notes, burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER)
			net.MustRefuse(grant, sidecar.ErrConfigAuthority)
			if net.ForgedAppends() {
				pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, grant)
				if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigAuthority) {
					return fmt.Errorf("the forged grant at %d: %v", pin.GetVersion(), verdict.Refusal)
				}
			}
			return aclExpectMembers(net, world, false, false)
		}),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, burner, tablet := world.devices["m first"], world.devices["m burner"], world.devices["m tablet"]
			net.MustLand(aclRepoGrant(net, first, sidecar.Id(world.ids["notes"]), burner.SidecarId, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER))
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)))
			if err := aclExpectMembers(net, world, true, true); err != nil {
				return err
			}
			aclBaseKeepingTheFold(net, 48)
			return aclExpectMembers(net, world, true, true)
		}),
	)
}

// Fails unless every reader judges S3a's Adds and wraps as granted and confirmed say.
func aclExpectMembers(net *sidecartest.AdmissionNet, world *fsTeamWorld, granted bool, confirmed bool) error {
	first, phone, burner, tablet := world.devices["m first"], world.devices["m phone"], world.devices["m burner"], world.devices["m tablet"]
	notes, vault := sidecar.Id(world.ids["notes"]), sidecar.Id(world.ids["vault"])
	now := net.Clock().Now()
	leaf := func(sidecarId sidecar.Id, count int) sidecar.AclRepoMember {
		return sidecar.AclRepoMember{SidecarId: sidecarId, Form: sidecar.AclRepoMemberLeaf, LeafCount: count}
	}
	wrap := func(sidecarId sidecar.Id) sidecar.AclRepoMember {
		return sidecar.AclRepoMember{SidecarId: sidecarId, Form: sidecar.AclRepoMemberWrap}
	}
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		for _, check := range []struct {
			what   string
			repoId sidecar.Id
			member sidecar.AclRepoMember
			allow  bool
			reason sidecar.AclReason
		}{
			{what: "the phone's leaf", repoId: notes, member: leaf(phone.SidecarId, 2), allow: true},
			{what: "the phone's leaf past 1,000", repoId: notes, member: leaf(phone.SidecarId, 1001), reason: sidecar.AclReasonSeatsFull},
			{what: "a ghost's wrap", repoId: notes, member: wrap(net.Id("ghost")), reason: sidecar.AclReasonUnadmitted},
			{what: "the burner's wrap", repoId: notes, member: wrap(burner.SidecarId), allow: granted},
			{what: "the burner's leaf", repoId: notes, member: leaf(burner.SidecarId, 3)},
			{what: "the burner's vault wrap, a depositor's", repoId: vault, member: wrap(burner.SidecarId)},
			{what: "the first device's vault leaf", repoId: vault, member: leaf(first.SidecarId, 1), allow: true},
			{what: "the tablet's vault leaf", repoId: vault, member: leaf(tablet.SidecarId, 2), allow: confirmed},
		} {
			decision := acl.CheckRepoMember(check.repoId, check.member, now)
			if decision.Allowed != check.allow || (check.reason != 0 && decision.Reason != check.reason) {
				return fmt.Errorf("%s: allowed %t (%s), want %t", check.what, decision.Allowed, decision.Reason, check.allow)
			}
		}
		// a holder the projection no longer gives read is named for a Remove before a writer seals
		want := []sidecar.Id{}
		if !granted {
			want = append(want, burner.SidecarId)
		}
		nonReaders := []sidecar.Id{}
		for _, nonReader := range acl.NonReaders(notes, []sidecar.Id{first.SidecarId, phone.SidecarId, burner.SidecarId}, now) {
			nonReaders = append(nonReaders, nonReader.SidecarId)
		}
		if !slices.Equal(nonReaders, want) {
			return fmt.Errorf("non-readers %v, want %v", nonReaders, want)
		}
		return nil
	})
	return nil
}

// S4a's acl checks (§22.7's S4, F9, the revocation suite's first rows; I-15, D-ACL-21, §7.9's shrink and expiry
// rows): the phone, a member device reading a general repo, is revoked by its member's consented device, and the
// burner's RepoGrant expires: at every reader each loses every right and scope at once, is named a non-reader, and
// leaves the repo's key holders, and the gate refuses a write under a generation from before the revocation, while
// the expiry is found at its own time with no entry.
func AclRemovalDropsEveryRight(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("S4a's acl checks", world,
		fs14AclStart(world),
		fsTeamDo("m first", world, func(net *sidecartest.AdmissionNet) error {
			first, notes := world.devices["m first"], sidecar.Id(world.ids["notes"])
			burner := net.Device("m burner", first.MemberId)
			world.devices["m burner"] = burner
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			expires := net.Clock().Now().Add(time.Hour).UnixMilli()
			net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
				Header: net.Header(), RepoId: notes.Bytes(), Subject: burner.SidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires,
			}))
			world.positions["grant expires"] = uint64(expires)
			before := net.Tip()
			world.positions["before"], world.signed["before"] = before.GetVersion(), before.GetChain()
			verdict := net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				net.Revocation(world.devices["m phone"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
			world.positions["revoke"], world.signed["revoke"] = verdict.Pin.GetVersion(), verdict.Pin.GetChain()
			return aclExpectRemoved(net, world, world.devices["m phone"], sidecar.AclReasonRevoked)
		}),
		fsTeamDo("clock", world, func(net *sidecartest.AdmissionNet) error {
			notes := sidecar.Id(world.ids["notes"])
			expires := time.UnixMilli(int64(world.positions["grant expires"]))
			after := net.Clock().Now()
			// the expiry is found at its time, with no entry, by every reader
			net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				at, found, err := state.ExpiriesFor(notes, after, expires.Add(time.Minute))
				if err != nil || !found || at.After(expires) || at.Before(after) {
					return fmt.Errorf("the grant's expiry: %v at %s, %v", found, at, err)
				}
				return nil
			})
			net.Wait(time.Hour + time.Minute)
			return aclExpectRemoved(net, world, world.devices["m burner"], sidecar.AclReasonNoGrant)
		}),
	)
}

// Fails unless, at every reader, removed holds no right and no scope on the general repo, is a non-reader of it, holds
// no key of it, and the repo's gate refuses a generation from before the revocation and takes one at it.
func aclExpectRemoved(net *sidecartest.AdmissionNet, world *fsTeamWorld, removed *sidecartest.AdmissionDevice, reason sidecar.AclReason) error {
	notes := sidecar.Id(world.ids["notes"])
	now := net.Clock().Now()
	before := &bridge.AuthPin{Version: world.positions["before"], Chain: world.signed["before"]}
	revoke := &bridge.AuthPin{Version: world.positions["revoke"], Chain: world.signed["revoke"]}
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if rights := aclRights(net, acl, removed.SidecarId, notes, sidecar.AclTokenAudienceEvs); rights != 0 {
			return fmt.Errorf("%s keeps rights %04b", removed.Name, rights)
		}
		scopes := []string{aclScope(notes, "r"), aclScope(notes, "rw"), aclScope(notes, "deposit")}
		for _, audience := range []sidecar.AclTokenAudience{sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm} {
			if err := aclExpectScopes(net, state, removed.SidecarId, audience, scopes, []string{}); err != nil {
				return fmt.Errorf("%s's: %w", removed.Name, err)
			}
		}
		nonReaders := acl.NonReaders(notes, []sidecar.Id{removed.SidecarId, world.devices["m first"].SidecarId}, now)
		if len(nonReaders) != 1 || nonReaders[0].SidecarId != removed.SidecarId || nonReaders[0].Reason != reason {
			return fmt.Errorf("non-readers %+v, want %s for %s", nonReaders, reason, removed.Name)
		}
		if err := aclExpectHolder(state, notes, now, removed.SidecarId, false, sidecar.GkmHolderLeaf, sidecar.GkmHolderAgent); err != nil {
			return err
		}
		if shrunkAt := state.ShrunkAt(notes); shrunkAt < revoke.GetVersion() {
			return fmt.Errorf("holders_shrunk_at %d, below the revocation's %d", shrunkAt, revoke.GetVersion())
		}
		if err := sidecar.GkmGateCheck(state, notes, before, now, now); !errors.Is(err, sidecar.ErrGkmGateClosed) {
			return fmt.Errorf("a generation from before the revocation: %v", err)
		}
		if err := sidecar.GkmGateCheck(state, notes, revoke, now, now); err != nil {
			return fmt.Errorf("a generation at the revocation: %w", err)
		}
		return nil
	})
	return nil
}
