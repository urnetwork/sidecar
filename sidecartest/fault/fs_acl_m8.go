// ACL-M8-01's schedules (§22.8's FS-19 and FS-85 at M8-out; §18.8's quick burner and lease, §18.7's wake pushes and
// D-SDK-28's directory notices, §16.11's notify row; D-ACL-19, §8.6's ceiling, owner decision 126, I-15, WK4): the code
// is earlier tasks', and these land the rows' last parts at the milestone that ships their last mechanism. Both run on
// the admission world with ACL's own compile, as fs_acl.go's do, so every reader standing, each new device and gate at
// a base and the writer's follower gives each answer, and the world fails a step the moment one stands elsewhere than
// the reference.
//
// Registered, on T2 and on T3, where server's sidecart3 runs every T3 registration (TestT3Rows):
//
//   - FS-19's quick-burner: an untagged ephemeral sidecar of a personal network's Owner, enrolled as §18.8 enrolls a
//     quick burner: the key origin's client on the Net's api (sidecartest.TestHttpPage), ephemeral with a lease and the
//     close capability its mint returns once, strict_exp and admin_refused, bound under an identity key of its own, and
//     admitted by the Owner's consented laptop by that sidecar_id and key. Before any share it holds §8.6's ceiling
//     alone: the config's read by a wrap and its member's vault's and mailbox's deposits. Another ephemeral's EvsShare
//     of the mailbox is refused at api and every reader; the laptop's opens exactly the mailbox at once, a read and a
//     deposit, its key by a wrap and never a leaf, the exchange issuing the mailbox's r and nothing else new, and
//     nothing else readable. The share's end is a shrink each way it ends: the laptop's RepoRevoke drops the read and
//     shrinks the mailbox's key holders at its position; a new share's expires ends it at its own time with no entry
//     and no device online; and a third ends with the page's close beacon, which reaps its client at once, api's tick
//     then reaping its admission (§7.10), so the mailbox's and the config's key holders shrink there and the vault's do
//     not, a deposit holding no key. The lease's own reap, 30-36 min after the last poll, is FS-37's.
//
// FS-85's acl wakes, a T2 clause RunClause runs beside RECORD-M8-01's registered wakes case (fs100_wake_test.go, which
// holds a woken phone's reads and the requester's receipt on fixtures of the state): which phones a request's notice
// wakes is which phones lease its target's notice prefix, and each phone computes that from its own state now
// (§16.11's notify row, directory_notice.go's approverPrefixes), here the admission world's real one through
// sidecar.NewDirectoryAuthView, so ACL's approver resolution decides who is woken. In a Team network on Team's starting
// document, with m's general repo notes, whose admins are m's first device and m's phone, and m's vault, four phones
// resync over T4's phone surrogate (sidecartest.FakeDirectoryPhone): m's phone, the Owner's and the Admin's, each a
// consented device of its member, and m's tablet, which the Owner admitted and m has not confirmed. m's phone alone
// leases notes' and the vault's prefixes, so b's requests to read each wake it once and no other phone, the Owner's and
// the Admin's never, an owner-bound repo's requests being its owner's consented devices' alone (owner decision 126); m's
// OwnerConfirm of the tablet gives it the vault's prefix at its next resync, and the next vault request wakes both; the
// removal of m's phone as notes' admin releases its notes prefix, and the next notes request wakes no phone. Each wake
// is the directory's evs class at the push sequence its notice's commit raised, at that commit plus at most §11.15's
// p99 for a hint to an online subscriber (AclM8Settings.HintWithin), naming nothing (WK4). On T2's fake clock a wake
// comes at its commit, so the bound proves delivery, never time; real time is T3's and T4's.
//
// The clause writes each requester's notice as §16.11's filing writes it once the request's entry lands, by path CAS
// from absent at the requester's tip. The entry itself, and what a woken phone reads at its wake, are RECORD's
// (fs85_test.go, fs100_wake_test.go): no RecordAuthView reads the real state yet and sidecartest.FakeRecordAuth's pins
// are its own, so the entry is not written here, and a woken phone's resync finds none and shows no request.

package fault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs19QuickBurnerCase = Register("FS-19", "quick-burner", []Tier{TierT2, TierT3}, Fs19QuickBurner)

// What ACL-M8-01's schedules take: §11.15's bound, and the lives FS-19's burner and shares take.
type AclM8Settings struct {
	// The bound a leasing approver's phone's wake meets from its notice's commit: §11.15's p99 for a commit's hint to an
	// online subscriber, 2 s, which §11.10's leases are held to. On T2's fake clock a wake comes at its commit, so the
	// bound proves delivery, never time. Positive.
	HintWithin time.Duration
	// How long the run's ephemeral admissions last, the quick burner's among them: past the run.
	BurnerLife time.Duration
	// The first share's expires: past the run, so its revocation ends it.
	ShareLife time.Duration
	// The second share's expires, which the clock passes: short of §18.8's reap, 30 min after the burner's last poll,
	// so its lease stands meanwhile without another poll.
	ExpiringShareLife time.Duration
	// How far past the second share's expires the clock moves, within the same 30 min. Positive.
	ExpiryMargin time.Duration
}

func DefaultAclM8Settings() *AclM8Settings {
	return &AclM8Settings{
		HintWithin:        2 * time.Second,
		BurnerLife:        24 * time.Hour,
		ShareLife:         time.Hour,
		ExpiringShareLife: 10 * time.Minute,
		ExpiryMargin:      time.Minute,
	}
}

// What FS-19's quick-burner run makes and its steps read.
type fs19M8World struct {
	*fsTeamWorld
	settings *AclM8Settings
	// the quick burner's page: its ephemeral client, lease and close capability on the Net's api
	page *sidecartest.TestHttpPage
	// the page's sidecar, which the laptop admits
	burner sidecar.Id
	// another ephemeral sidecar of the Owner's, whose share is refused
	other *sidecartest.AdmissionDevice

	// the config and a repo of each kind besides
	notesId, recordId, vaultId, mailboxId, secretId, configId sidecar.Id
}

// FS-19's quick-burner run, the row's M8 case; see the file header.
func Fs19QuickBurner(net *Net) *Schedule {
	return Fs19QuickBurnerWith(nil)(net)
}

// FS-19's quick-burner run on settings, nil for the defaults.
func Fs19QuickBurnerWith(settings *AclM8Settings) Builder {
	return func(net *Net) *Schedule {
		if settings == nil {
			settings = DefaultAclM8Settings()
		}
		world := &fs19M8World{fsTeamWorld: newFsTeamWorld(), settings: settings}
		return fsTeamSchedule("FS-19 quick-burner", world.fsTeamWorld,
			aclSetup(world.fsTeamWorld, world.setup),
			world.burnerStep(world.enroll),
			fsTeamDo("laptop", world.fsTeamWorld, world.share),
			fsTeamDo("laptop", world.fsTeamWorld, world.revoke),
			fsTeamDo("laptop", world.fsTeamWorld, world.shareExpiring),
			fsTeamDo("clock", world.fsTeamWorld, world.expire),
			fsTeamDo("laptop", world.fsTeamWorld, world.shareUntilTheEnd),
			world.burnerStep(world.unload),
		)
	}
}

// A step of the burner's own, given both the Net, whose api holds its page's client, and the admission world.
func (self *fs19M8World) burnerStep(body func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error) *Step {
	world := self
	return &Step{Actor: "burner", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			if world.net == nil {
				return errors.New("the quick burner's network was not set up")
			}
			return body(ctx, net, world.net)
		})
	}}
}

// The network: no policy, so the implicit document; the Owner's laptop, the writer and its member's one consented
// device; a repo of each kind the burner must not read and the Owner's vault and mailbox; and another ephemeral of the
// Owner's, which the laptop admits for the burner's life.
func (self *fs19M8World) setup(net *sidecartest.AdmissionNet) error {
	owner := net.Owner()
	self.configId = net.ConfigRepoId()
	self.notesId = aclCreateRepo(net, owner, "notes", protocol.RepoKind_REPO_KIND_GENERAL)
	self.recordId = aclCreateRepo(net, owner, "record", protocol.RepoKind_REPO_KIND_RECORD)
	self.vaultId = aclCreateRepo(net, owner, "vault", protocol.RepoKind_REPO_KIND_VAULT)
	self.mailboxId = aclCreateRepo(net, owner, "mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
	self.secretId = aclCreateRepo(net, owner, "secret", protocol.RepoKind_REPO_KIND_SECRET)
	self.other = net.Device("other burner", owner.MemberId)
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.Admission(self.other, nil, true, net.Clock().Now().Add(self.settings.BurnerLife).UnixMilli(), 0)))
	net.Fold(true)
	return nil
}

// The quick burner's enrollment (§18.8's identity, admission and lease rows): its client minted on the Net's api,
// ephemeral with a lease and the close capability, its Worker's first poll answered at once, and its sidecar admitted
// by the laptop, untagged under the Owner and ephemeral. It then holds the ceiling alone.
func (self *fs19M8World) enroll(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
	page, err := net.AddHttpPage("quick burner", &sidecartest.TestHttpPageSettings{NetworkId: admission.NetworkId(), Ephemeral: true})
	if err != nil {
		return err
	}
	self.page, self.burner = page, page.SidecarId()
	api, err := net.Api()
	if err != nil {
		return err
	}
	if _, leased := api.LeaseSeenTime(page.ClientId()); !leased || page.CloseCapability() == "" {
		return errors.New("the quick burner's client is not an ephemeral one: no lease or no close capability")
	}
	response, status, err := page.Poll(ctx)
	if err != nil || status != http.StatusOK || response.GetReset_() == nil {
		return fmt.Errorf("the quick burner's first poll: %d %v", status, err)
	}
	owner := admission.Owner()
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            admission.Header(),
		NetworkId:         admission.NetworkId().Bytes(),
		SidecarId:         page.SidecarId().Bytes(),
		IdentityPublicKey: page.IdentityPublicKey(),
		IdentityAlg:       "ed25519",
		MemberId:          owner.MemberId.Bytes(),
		Ephemeral:         true,
		NotAfter:          admission.Clock().Now().Add(self.settings.BurnerLife).UnixMilli(),
	}))
	admission.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		row := state.SidecarRow(self.burner)
		if row == nil || !row.GetEphemeral() || len(row.GetTagIds()) != 0 || !bytes.Equal(row.GetMemberId(), owner.MemberId.Bytes()) {
			return fmt.Errorf("the quick burner's row: %v", row)
		}
		return nil
	})
	return self.expectBurner(admission, sidecar.AclEvsDeposit)
}

// An EvsShare of the mailbox to the burner, signed by signer, ending at expires; the zero time ends it never.
func (self *fs19M8World) mailboxShare(net *sidecartest.AdmissionNet, signer *sidecartest.AdmissionDevice, expires time.Time) []byte {
	share := &protocol.EvsShare{Header: net.Header(), RepoId: self.mailboxId.Bytes(), Subject: self.burner.Bytes()}
	if !expires.IsZero() {
		share.Expires = expires.UnixMilli()
	}
	return net.Sign(signer, bridge.SignedType_SIGNED_EVS_SHARE, share)
}

// Fails unless, at every reader, the burner holds §8.6's ceiling and, on the mailbox, exactly the rights mailbox names,
// and nothing else: the config's read by a wrap, the vault's deposit, nothing on the general, record and secret repos,
// and the mailbox's key by a wrap exactly when it reads it, never by a leaf; it is no config writer, consented device
// or approver; and the exchange issues it exactly those scopes at both audiences.
func (self *fs19M8World) expectBurner(net *sidecartest.AdmissionNet, mailbox sidecar.AclEvsRights) error {
	if err := fs19M4ExpectRights(net, self.burner, map[sidecar.Id]sidecar.AclEvsRights{
		self.configId:  sidecar.AclEvsRead,
		self.notesId:   0,
		self.recordId:  0,
		self.vaultId:   sidecar.AclEvsDeposit,
		self.mailboxId: mailbox,
		self.secretId:  0,
	}); err != nil {
		return fmt.Errorf("the quick burner: %w", err)
	}
	reads := mailbox.Has(sidecar.AclEvsRead)
	now := net.Clock().Now()
	evs, gkm := sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm
	evsScopes := []string{
		aclScope(self.mailboxId, "r"), aclScope(self.mailboxId, "rw"), aclScope(self.mailboxId, "admin"), aclScope(self.mailboxId, "deposit"),
		aclScope(self.vaultId, "r"), aclScope(self.vaultId, "deposit"),
		aclScope(self.notesId, "r"), aclScope(self.recordId, "r"),
		aclScope(self.secretId, "r"), aclScope(self.secretId, "deposit"),
		aclScope(self.configId, "r"), aclScope(self.configId, "rw"),
	}
	evsGranted := []string{}
	if reads {
		evsGranted = append(evsGranted, aclScope(self.mailboxId, "r"))
	}
	evsGranted = append(evsGranted, aclScope(self.mailboxId, "deposit"), aclScope(self.vaultId, "deposit"), aclScope(self.configId, "r"))
	gkmScopes := []string{
		aclScope(self.mailboxId, "r"), aclScope(self.mailboxId, "rw"),
		aclScope(self.vaultId, "r"), aclScope(self.notesId, "r"),
		aclScope(self.configId, "r"), aclScope(self.configId, "rw"),
	}
	gkmGranted := []string{}
	if reads {
		gkmGranted = append(gkmGranted, aclScope(self.mailboxId, "r"))
	}
	gkmGranted = append(gkmGranted, aclScope(self.configId, "r"))
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if state.IsConfigWriter(self.burner) || acl.Consented(self.burner) || acl.ApprovalCapable(self.burner) {
			return errors.New("the quick burner writes the config, is consented or approves")
		}
		wrap := acl.CheckRepoMember(self.mailboxId, sidecar.AclRepoMember{SidecarId: self.burner, Form: sidecar.AclRepoMemberWrap}, now)
		leaf := acl.CheckRepoMember(self.mailboxId, sidecar.AclRepoMember{SidecarId: self.burner, Form: sidecar.AclRepoMemberLeaf, LeafCount: 2}, now)
		if wrap.Allowed != reads || leaf.Allowed {
			return fmt.Errorf("the quick burner's mailbox wrap %t and leaf %t, want %t and false", wrap.Allowed, leaf.Allowed, reads)
		}
		if err := aclExpectScopes(net, state, self.burner, evs, evsScopes, evsGranted); err != nil {
			return fmt.Errorf("the quick burner's: %w", err)
		}
		if err := aclExpectScopes(net, state, self.burner, gkm, gkmScopes, gkmGranted); err != nil {
			return fmt.Errorf("the quick burner's: %w", err)
		}
		return nil
	})
	return nil
}

// The laptop's share opens exactly the mailbox, at once; another ephemeral's opens nothing.
func (self *fs19M8World) share(net *sidecartest.AdmissionNet) error {
	expires := net.Clock().Now().Add(self.settings.ShareLife)
	// only a consented device of the owner shares an owner-bound repo (§8.5, §18.8's admission row); on T2 a
	// malicious api's append of the other ephemeral's share is refused at its position by every reader
	refused := self.mailboxShare(net, self.other, expires)
	net.MustRefuse(refused, sidecar.ErrConfigAuthority)
	if net.ForgedAppends() {
		pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, refused)
		if verdict := net.VerdictAt(pin.GetVersion()); verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigAuthority) {
			return fmt.Errorf("the other ephemeral's forged share at %d: %v", pin.GetVersion(), verdict.Refusal)
		}
	}
	if err := self.expectBurner(net, sidecar.AclEvsDeposit); err != nil {
		return err
	}
	net.MustLand(self.mailboxShare(net, net.Owner(), expires))
	return self.expectBurner(net, sidecar.AclEvsRead|sidecar.AclEvsDeposit)
}

// The share's revocation, the laptop's RepoRevoke, drops the read and shrinks the mailbox's key holders at its
// position.
func (self *fs19M8World) revoke(net *sidecartest.AdmissionNet) error {
	verdict := net.MustLand(aclRepoRevoke(net, net.Owner(), self.mailboxId, self.burner))
	if err := self.expectBurner(net, sidecar.AclEvsDeposit); err != nil {
		return err
	}
	return aclExpectShrunkAt(net, self.mailboxId, verdict.Pin.GetVersion())
}

// A new share, the laptop's, lifting the revocation (§8.8's owner-bound standing revoke), opens the mailbox again,
// ending at its expires, which every reader finds as the mailbox's key holders' first expiry.
func (self *fs19M8World) shareExpiring(net *sidecartest.AdmissionNet) error {
	expires := net.Clock().Now().Add(self.settings.ExpiringShareLife)
	net.MustLand(self.mailboxShare(net, net.Owner(), expires))
	if err := self.expectBurner(net, sidecar.AclEvsRead|sidecar.AclEvsDeposit); err != nil {
		return err
	}
	return aclM6ExpectExpiry(net, self.mailboxId, time.UnixMilli(expires.UnixMilli()))
}

// The clock passes the share's expires, with no entry and no device online: the read ends at every reader, and the
// burner is no longer among the mailbox's key holders.
func (self *fs19M8World) expire(net *sidecartest.AdmissionNet) error {
	before := net.Tip()
	net.Wait(self.settings.ExpiringShareLife + self.settings.ExpiryMargin)
	if tip := net.Tip(); tip.GetVersion() != before.GetVersion() {
		return fmt.Errorf("the log moved from %d to %d while no device was online", before.GetVersion(), tip.GetVersion())
	}
	return self.expectBurner(net, sidecar.AclEvsDeposit)
}

// A third share, with no expires, opens the mailbox until the burner's end.
func (self *fs19M8World) shareUntilTheEnd(net *sidecartest.AdmissionNet) error {
	net.MustLand(self.mailboxShare(net, net.Owner(), time.Time{}))
	return self.expectBurner(net, sidecar.AclEvsRead|sidecar.AclEvsDeposit)
}

// The page's pagehide beacon reaps its client at once (§18.8's close row), and api's tick reaps its admission (§7.10's
// TICK, ephemeral admissions only): at every reader the burner is revoked at the tick, holds nothing, and the mailbox's
// and the config's key holders shrink there, the vault's not; its page's next poll is refused.
func (self *fs19M8World) unload(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
	api, err := net.Api()
	if err != nil {
		return err
	}
	if status, err := self.page.Unload(ctx); err != nil || status != http.StatusNoContent {
		return fmt.Errorf("the quick burner's close beacon: %d %v", status, err)
	}
	reaps := api.Reaps()
	if len(reaps) != 1 || reaps[0].ClientId != self.page.ClientId() || !reaps[0].Close {
		return fmt.Errorf("the close beacon's reaps: %+v", reaps)
	}
	if _, leased := api.LeaseSeenTime(self.page.ClientId()); leased {
		return errors.New("the reaped client's lease stayed")
	}
	pin, err := admission.Tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{self.burner.Bytes()}})
	if err != nil {
		return fmt.Errorf("api's tick reaping the quick burner: %w", err)
	}
	tick := pin.GetVersion()
	if verdict := admission.VerdictAt(tick); !verdict.Accepted() {
		return fmt.Errorf("the tick at %d: %v", tick, verdict.Refusal)
	}
	if err := fs19M4ExpectRights(admission, self.burner, map[sidecar.Id]sidecar.AclEvsRights{
		self.configId:  0,
		self.notesId:   0,
		self.recordId:  0,
		self.vaultId:   0,
		self.mailboxId: 0,
		self.secretId:  0,
	}); err != nil {
		return fmt.Errorf("the reaped burner: %w", err)
	}
	now := admission.Clock().Now()
	admission.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if revokedAt := state.SidecarRow(self.burner).GetRevokedAt(); revokedAt != tick {
			return fmt.Errorf("the reaped burner revoked at %d, not the tick's %d", revokedAt, tick)
		}
		nonReaders := acl.NonReaders(self.mailboxId, []sidecar.Id{self.burner}, now)
		if len(nonReaders) != 1 || nonReaders[0].Reason != sidecar.AclReasonRevoked {
			return fmt.Errorf("the mailbox's non-readers: %+v", nonReaders)
		}
		for _, repoId := range []sidecar.Id{self.mailboxId, self.configId} {
			if shrunkAt := state.ShrunkAt(repoId); shrunkAt != tick {
				return fmt.Errorf("%s's holders_shrunk_at %d, not the tick's %d", repoId, shrunkAt, tick)
			}
		}
		if shrunkAt := state.ShrunkAt(self.vaultId); tick <= shrunkAt {
			return fmt.Errorf("the vault, whose key the burner never held, shrank at %d", shrunkAt)
		}
		return nil
	})
	if _, status, err := self.page.Poll(ctx); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("the reaped page's poll: %d %v", status, err)
	}
	return nil
}

// One phone of FS-85's acl wakes: its device, its surrogate at evs, its directory client's phone part, and the wakes
// the schedule has counted for it.
type aclM8Phone struct {
	name      string
	device    *sidecartest.AdmissionDevice
	surrogate *sidecartest.FakeDirectoryPhone
	notices   *sidecar.DirectoryPhoneNotices
	wakes     int
}

// What FS-85's acl wakes build: the Team world, the directory's evs as the phones and the requester reach it, and the
// phones, in name order.
type aclM8WakeWorld struct {
	*aclM6World
	settings *AclM8Settings
	streams  *sidecartest.FakeRecordStreams
	cards    *sidecartest.FakeDirectoryCards
	phones   []*aclM8Phone
}

// The phones FS-85's acl wakes resync, in name order: each a device of its member, admitted by that member's first
// device but the tablet, which the Owner admitted.
var aclM8PhoneNames = []string{"admin phone", "m phone", "m tablet", "owner phone"}

// FS-85's acl wakes (§22.8; §16.11's notify row, D-SDK-28, owner decision 126, WK4); see the file header.
func Fs85AclWakes(net *Net) *Schedule {
	return Fs85AclWakesWith(nil)(net)
}

// FS-85's acl wakes on settings, nil for the defaults.
func Fs85AclWakesWith(settings *AclM8Settings) Builder {
	return func(net *Net) *Schedule {
		if settings == nil {
			settings = DefaultAclM8Settings()
		}
		world := &aclM8WakeWorld{aclM6World: newAclM6World(), settings: settings}
		schedule := world.schedule("FS-85 acl wakes",
			world.startWithEvs(),
			world.do("phones", world.openPhones),
			world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
				return world.request(net, "notes", "notes", []string{"m first", "m phone"}, "m phone")
			}),
			world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
				return world.request(net, "vault", "vault", []string{"m first", "m phone"}, "m phone")
			}),
			world.do("mFirst", world.confirmTablet),
			world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
				return world.request(net, "vault again", "vault", []string{"m first", "m phone", "m tablet"}, "m phone", "m tablet")
			}),
			world.do("mFirst", world.removePhoneAdmin),
			world.do("bFirst", func(net *sidecartest.AdmissionNet) error {
				return world.request(net, "notes again", "notes", []string{"m first"})
			}),
			world.do("phones", world.closePhones),
		)
		schedule.Check = append(schedule.Check, NewInvariant("WK4/acl-wakes", func(ctx context.Context, oracle *Oracle) error {
			return world.wakesNameNothing()
		}))
		return schedule
	}
}

// The first step: the directory's evs made first, so the world creates the directory under its id, then
// startRepos's Team world: m's phone, which m's first device admitted, m's tablet, which the Owner admitted, m's
// ephemeral, notes, whose admins are m's first device and its phone, and m's vault.
func (self *aclM8WakeWorld) startWithEvs() *Step {
	world := self
	repos := self.startRepos()
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		world.streams = sidecartest.NewFakeRecordStreams(net.Clock(), nil, nil)
		directoryId, err := world.streams.NewRepo(ctx)
		if err != nil {
			return err
		}
		world.cards = sidecartest.NewFakeDirectoryCards(world.streams, nil)
		world.directoryId = directoryId
		return repos.Action(ctx, net)
	}}
}

// The Owner's and the Admin's phones admitted by their members' first devices; every sidecar's scopes on the
// directory at evs as its rights there give them; and each phone's directory client, its phone part bound over its
// surrogate, reading the admission world's state now. Resynced, m's phone alone leases notes' and the vault's prefixes.
func (self *aclM8WakeWorld) openPhones(net *sidecartest.AdmissionNet) error {
	for _, name := range []string{"owner", "admin"} {
		first := self.devices[name+" first"]
		phone := net.Device(name+" phone", first.MemberId)
		net.AdmitDevice(first, phone, 0)
		self.devices[name+" phone"] = phone
	}
	net.Fold(true)
	acl, err := net.State().Acl()
	if err != nil {
		return err
	}
	now := net.Clock().Now()
	for name, device := range self.devices {
		rights := acl.EvsAccess(sidecar.AclSidecarSubject(device.SidecarId), self.directoryId, sidecar.AclTokenAudienceEvs, now).Rights
		scope := sidecartest.RecordStreamsScope{Read: rights.Has(sidecar.AclEvsRead), Write: rights.Has(sidecar.AclEvsWrite)}
		if err := self.streams.Grant(self.directoryId, device.SidecarId, scope); err != nil {
			return fmt.Errorf("%s's directory scope: %w", name, err)
		}
	}
	for _, name := range aclM8PhoneNames {
		device := self.devices[name]
		store, err := sidecartest.NewFakeStore().Root().Directory("directory", "search")
		if err != nil {
			return err
		}
		surrogate := sidecartest.NewFakeDirectoryPhone(self.cards, device.SidecarId, nil)
		client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
			SidecarId: device.SidecarId,
			Store:     store,
			Cards:     surrogate,
			Auth:      func() sidecar.DirectoryAuthView { return sidecar.NewDirectoryAuthView(net.State()) },
			Clock:     net.Clock(),
			Settings:  sidecar.DefaultSidecarSettings().Directory,
			NetworkId: net.NetworkId(),
		})
		if err != nil {
			return err
		}
		notices, err := client.BindPhoneNotices(nil)
		if err != nil {
			return fmt.Errorf("%s's phone part: %w", name, err)
		}
		self.phones = append(self.phones, &aclM8Phone{name: name, device: device, surrogate: surrogate, notices: notices})
	}
	return self.expectLeases(net, map[string][]string{"m phone": {"notes", "vault"}})
}

// Each phone resynced, its leases at evs: fails unless each holds a live lease of one holder on exactly the notice
// prefixes of the repos named for it.
func (self *aclM8WakeWorld) expectLeases(net *sidecartest.AdmissionNet, leased map[string][]string) error {
	for _, phone := range self.phones {
		if _, err := phone.notices.Resync(net.Context()); err != nil {
			return fmt.Errorf("%s's resync: %w", phone.name, err)
		}
		prefixes := []string{}
		for _, lease := range phone.surrogate.Leases() {
			if !lease.Live || lease.Holders != 1 || lease.RepoId != self.directoryId {
				return fmt.Errorf("%s's lease %+v", phone.name, lease)
			}
			prefixes = append(prefixes, lease.Prefix)
		}
		want := []string{}
		for _, repo := range leased[phone.name] {
			prefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: self.ids[repo]})
			if err != nil {
				return err
			}
			want = append(want, prefix)
		}
		slices.Sort(prefixes)
		slices.Sort(want)
		if !slices.Equal(prefixes, want) {
			return fmt.Errorf("%s leases %v, want %v", phone.name, prefixes, want)
		}
	}
	return nil
}

// b's request to read the repo named, its deciders exactly those named at every reader, and its notice written: each
// phone named is woken once by it, the rest not at all.
func (self *aclM8WakeWorld) request(net *sidecartest.AdmissionNet, name string, repo string, deciders []string, woken ...string) error {
	request := self.repoRequest(net, name, self.devices["b first"], sidecar.Id(self.ids[repo]), protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		net.Clock().Now().Add(2*time.Hour).UnixMilli())
	if err := self.expectDeciders(net, request, self.cast(), deciders...); err != nil {
		return err
	}
	committedAt, sequence, err := self.writeNotice(net, request)
	if err != nil {
		return err
	}
	return self.expectWoken(committedAt, sequence, woken...)
}

// The requester's pending notice of request, as §16.11's filing writes it once the request's entry lands: at
// q/<h>/<tgt>/<rid>, by path CAS from absent, at the requester's tip, naming the request, its requester and the entry's
// seq, never an approver. When it committed, and the directory's push sequence its commit raised.
func (self *aclM8WakeWorld) writeNotice(net *sidecartest.AdmissionNet, request *aclM6Request) (time.Time, uint64, error) {
	requestId := sidecar.Id(request.request.GetRequestId())
	path, err := sidecar.DirectoryNoticePath(request.request.GetTarget(), requestId)
	if err != nil {
		return time.Time{}, 0, err
	}
	notice := &protocol.DirectoryNotice{
		RequestId:          requestId.Bytes(),
		RequesterSidecarId: request.requester.Bytes(),
		EntrySeq:           1,
		NotAfterMillis:     request.request.GetNotAfterMillis(),
		State:              uint32(sidecar.DirectoryNoticeStatePending),
	}
	if err := sidecar.DirectoryCheckNotice(notice); err != nil {
		return time.Time{}, 0, err
	}
	content, err := protoMarshal(notice)
	if err != nil {
		return time.Time{}, 0, err
	}
	committedAt := net.Clock().Now()
	if _, err := self.cards.For(request.requester).PutCard(net.Context(), self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: net.Id("notice push " + request.name), Path: path, Content: content, AuthPin: net.Tip(),
	}); err != nil {
		return time.Time{}, 0, fmt.Errorf("%s's notice: %w", request.name, err)
	}
	sequence, err := self.streams.PushSequence(self.directoryId)
	if err != nil {
		return time.Time{}, 0, err
	}
	return committedAt, sequence.Sequence, nil
}

// Fails unless each phone has taken exactly the wakes counted for it, those woken one more, each such wake the
// directory's evs class at the sequence its notice's commit raised and within HintWithin of that commit.
func (self *aclM8WakeWorld) expectWoken(committedAt time.Time, sequence uint64, woken ...string) error {
	for _, phone := range self.phones {
		wasWoken := slices.Contains(woken, phone.name)
		if wasWoken {
			phone.wakes += 1
		}
		wakes := phone.surrogate.Wakes()
		if len(wakes) != phone.wakes {
			return fmt.Errorf("%s took %d wakes, want %d", phone.name, len(wakes), phone.wakes)
		}
		if !wasWoken {
			continue
		}
		wake := wakes[len(wakes)-1]
		if wake.Payload.TopicClass != "evs" || wake.Payload.Version != sequence {
			return fmt.Errorf("%s's wake carries %s at %d, want evs at the notice's %d", phone.name, wake.Payload.TopicClass, wake.Payload.Version, sequence)
		}
		if wake.At.Before(committedAt) || committedAt.Add(self.settings.HintWithin).Before(wake.At) {
			return fmt.Errorf("%s woke %s after its notice's commit, past %s", phone.name, wake.At.Sub(committedAt), self.settings.HintWithin)
		}
	}
	return nil
}

// m's OwnerConfirm of its tablet: the tablet decides m's vault's requests at every reader, and at its next resync
// leases the vault's prefix, never notes', of which it is no admin.
func (self *aclM8WakeWorld) confirmTablet(net *sidecartest.AdmissionNet) error {
	mFirst, tablet := self.devices["m first"], self.devices["m tablet"]
	net.MustLand(net.Sign(mFirst, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(tablet)))
	if err := self.expectDeciders(net, self.requests[1], self.cast(), "m first", "m phone", "m tablet"); err != nil {
		return err
	}
	return self.expectLeases(net, map[string][]string{"m phone": {"notes", "vault"}, "m tablet": {"vault"}})
}

// m's first device removes m's phone as notes' admin: notes' requests are its first device's alone at every reader,
// and m's phone's next resync releases notes' prefix.
func (self *aclM8WakeWorld) removePhoneAdmin(net *sidecartest.AdmissionNet) error {
	mFirst, phone, notes := self.devices["m first"], self.devices["m phone"], sidecar.Id(self.ids["notes"])
	net.MustLand(net.Sign(mFirst, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
		Header: net.Header(), RepoId: notes.Bytes(), SidecarId: phone.SidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE,
	}))
	if err := self.expectDeciders(net, self.requests[0], self.cast(), "m first"); err != nil {
		return err
	}
	return self.expectLeases(net, map[string][]string{"m phone": {"vault"}, "m tablet": {"vault"}})
}

// The phones' parts close, as each app's process ends.
func (self *aclM8WakeWorld) closePhones(net *sidecartest.AdmissionNet) error {
	for _, phone := range self.phones {
		phone.notices.Close()
	}
	return nil
}

// WK4 at every phone (§18.7; owner decision 88): each wake APNs' body of the evs class and a version alone, naming no
// directory, repo, device or request.
func (self *aclM8WakeWorld) wakesNameNothing() error {
	ids := []sidecar.Id{self.directoryId}
	for _, id := range self.ids {
		if len(id) == len(sidecar.Id{}) {
			ids = append(ids, sidecar.Id(id))
		}
	}
	for _, device := range self.devices {
		ids = append(ids, device.SidecarId, device.MemberId)
	}
	for _, request := range self.requests {
		ids = append(ids, sidecar.Id(request.request.GetRequestId()))
	}
	for _, phone := range self.phones {
		for _, wake := range phone.surrogate.Wakes() {
			body := fmt.Sprintf(`{"aps":{"content-available":1},"t":"evs","v":%d}`, wake.Payload.Version)
			if wake.Payload.TopicClass != "evs" || string(wake.Body) != body {
				return fmt.Errorf("%s's wake %q", phone.name, wake.Body)
			}
			text := strings.ToLower(string(wake.Body))
			for _, id := range ids {
				if id == (sidecar.Id{}) {
					continue
				}
				if strings.Contains(text, hex.EncodeToString(id.Bytes())) || strings.Contains(text, strings.ToLower(id.String())) {
					return fmt.Errorf("%s's wake names %s", phone.name, id)
				}
			}
		}
	}
	return nil
}
