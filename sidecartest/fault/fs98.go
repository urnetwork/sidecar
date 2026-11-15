//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's and FS-124's CLI cases (§22.8; §5.6's revocation, D-CORE-20, D-CORE-13; CORE-M3-04): a member's laptop, a
// real Sidecar in a real Daemon (sidecartest.Fs98World), revokes another of the member's devices the way
// `ur devices revoke` does, by the daemon's devices methods, the signing one as the confirmed control call ur sends
// after the person's yes on /dev/tty, on the tier's api: a FakeApi on T2, server's sequencer on T3. Every entry a host
// lands is applied by the world's reference, new devices, gates and writer follower, compared after each, and
// Fs98Agreement checks the same after every step.
//
// Registered, each a refusal beside the twin that must succeed:
//
//   - FS-98's cli (T2+T3): a harness hook's session, an unconfirmed control call, and an MCP tool's and a hook
//     handler's reach of the Sidecar are each refused the revocation with nothing signed, as are the device's own
//     revocation (REVOKE_SELF), another member's device (REVOKE_NOT_OWN) and a read-only device's
//     (REVOKE_NOT_CAPABLE), and the phone stands; its twin, the
//     owner's laptop in a personal network revoking the phone as lost, lands once and every reader drops the phone.
//   - FS-124's cli (T2+T3): with a presence key registered through the daemon's prompt, the laptop's revocation is
//     REVOKE_CANCELLED while the authenticator refuses, nothing signed, and a second key's registration and a key's
//     removal are refused alike; its twin registers the key and revokes the phone under one check, the phone's
//     registered key revoked with it, then adds and removes a key under the prompt.
//
// The rest of the rows' CLI clauses are named schedules a T2 test runs (fs98_test.go), and server's T3 test the same
// (server/api/fs98_db_test.go): a non-admin member's laptop; a compromise revocation, its cascade parking what the
// phone admitted from since_n on, REVOKE_SINCE and REVOKE_PARKS_SELF; and at k = 2 the proposal and the phone's
// Suspend, another admin's laptop approving it as `ur approve <proposal_id>` does, and a proposal that expires
// unsigned at its not_after leaving the phone suspended.
//
// FS-124's other CLI acts run the same way through the daemon's prompt: an admission and an alarm's OwnerConfirm as
// `ur approve` signs them (Fs124CliApprovals), `ur approve <proposal_id>`'s cosign (Fs124CliCosign), and
// `ur keychain recovery-rotate` (Fs124CliRecoveryRotate).
//
// What waits: the phone and remote-mode rows (CORE-M8-03), and the Team rows with self_admit on and off (the rows' team
// case, M6-out).

package fault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs98Cli  = Register("FS-98", "cli", []Tier{TierT2, TierT3}, Twin(Fs98CliRefusedPaths, Fs98CliLost))
	Fs124Cli = Register("FS-124", "cli", []Tier{TierT2, TierT3}, Twin(Fs124CliCheckRefused, Fs124CliUnderTheCheck))
)

// §22.7's revocation suite, the own-device form (M3): X is a member's phone, which the member's laptop revokes as lost
// and as a compromise the way `ur devices revoke` does. CORE's clause is the log's: before the loss X's identity key
// admits a device of its member, so the check judges a key that held something; after it every reader drops X, a
// compromise parks what X admitted from since_n on, and nothing X signs afterwards is taken, an admission, a
// revocation of the laptop or a presence key. What X can still read is the other areas' clauses, whose checks name
// these two ways as they compose them.
var Fs98RevocationCheck = sidecartest.RegisterRevocationCheck(&sidecartest.RevocationCheck{
	Id:   "core/own-device-revoked-signs-nothing",
	Area: "CORE",
	Ways: []sidecartest.RevocationWay{sidecartest.RevocationOwnDeviceRevokeLost, sidecartest.RevocationOwnDeviceRevokeCompromise},
	Run: func(run *sidecartest.RevocationRun) (string, error) {
		return "", fsTeamCatch(func() error {
			world := sidecartest.NewFs98World(fsTeamFailer{}, run.Net, nil)
			defer world.Close()
			net := world.Admission()
			memberId, first := net.ConsentedMember("m")
			laptop := world.AddHost("laptop", memberId, first, 0)
			phone := net.Device("m phone", memberId)
			net.AdmitDevice(first, phone, 0)
			// what X's key did while X stood: one admission before the loss, one after it
			tablet, watch := net.Device("m tablet", memberId), net.Device("m watch", memberId)
			net.AdmitDevice(phone, tablet, 0)
			net.AdmitDevice(phone, watch, 0)
			lostAt := net.Tip().GetVersion()
			world.Settle()

			reason, sinceN := sidecar.DeviceRevokeLost, uint64(0)
			if run.Way == sidecartest.RevocationOwnDeviceRevokeCompromise {
				reason, sinceN = sidecar.DeviceRevokeCompromise, lostAt
			}
			preview := laptop.Preview(phone.SidecarId, reason, sinceN, time.Time{})
			if preview.Refusal != nil {
				return fmt.Errorf("the preview: %+v", preview.Refusal)
			}
			if reply := laptop.Revoke(preview.Plan); reply.Refusal != nil || reply.Position == 0 {
				return fmt.Errorf("the revocation: %+v", reply)
			}
			if net.Admitted(phone) {
				return errors.New("X stands after its revocation")
			}
			if !net.Admitted(tablet) {
				return errors.New("what X admitted before the loss is out")
			}
			if compromised := run.Way == sidecartest.RevocationOwnDeviceRevokeCompromise; net.Admitted(watch) == compromised {
				return fmt.Errorf("what X admitted from since_n on stands %t, compromise %t", net.Admitted(watch), compromised)
			}
			// X keeps its key and signs on: none of it is taken
			before := net.Tip().GetVersion()
			spare := net.Device("m spare", memberId)
			for name, signed := range map[string][]byte{
				"an admission":               net.Sign(phone, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(spare, nil, false, 0, 0)),
				"a revocation of the laptop": net.Sign(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(laptop.Device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)),
			} {
				if _, err := net.Post(signed); err == nil {
					return fmt.Errorf("api took %s X signed after its revocation", name)
				}
			}
			if net.Tip().GetVersion() != before || net.Admitted(spare) || !net.Admitted(laptop.Device) {
				return fmt.Errorf("X's statements moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			return nil
		})
	},
})

// What one schedule builds in its first step and its later steps read.
type fs98World struct {
	world *sidecartest.Fs98World
	// the world's tunables, nil for its defaults
	settings *sidecartest.Fs98Settings
	hosts    map[string]*sidecartest.Fs98Host
	devices  map[string]*sidecartest.AdmissionDevice
	// what a step notes for a later one
	positions map[string]uint64
	ids       map[string][]byte
	keys      map[string]*sidecartest.FixturePresenceKey
}

func newFs98World() *fs98World {
	return &fs98World{
		hosts:     map[string]*sidecartest.Fs98Host{},
		devices:   map[string]*sidecartest.AdmissionDevice{},
		positions: map[string]uint64{},
		ids:       map[string][]byte{},
		keys:      map[string]*sidecartest.FixturePresenceKey{},
	}
}

// The network's log, for a step.
func (self *fs98World) net() *sidecartest.AdmissionNet {
	return self.world.Admission()
}

// The verifiers' agreement, as FsTeamAgreement's: every reader that stands holds the reference's state at the tip.
func Fs98Agreement(world *fs98World) Invariant {
	return NewInvariant("FI-2/agreement", func(ctx context.Context, oracle *Oracle) error {
		if world.world == nil {
			return nil
		}
		return fsTeamCatch(func() error {
			world.net().CheckAgreement()
			return nil
		})
	})
}

// A step by actor on the world, its failures the step's.
func fs98Do(actor string, world *fs98World, body func() error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(body)
	}}
}

// The first step: the network on the Net's tier, then body.
func fs98Setup(world *fs98World, body func() error) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			world.world = sidecartest.NewFs98World(fsTeamFailer{}, net, world.settings)
			return body()
		})
	}}
}

// A schedule of steps on world, closed at its end and checked by the agreement after every step.
func fs98Schedule(id string, world *fs98World, steps ...*Step) *Schedule {
	closeWorld := &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		if world.world != nil {
			world.world.Close()
		}
		return nil
	}}
	return &Schedule{Id: id, Steps: append(steps, closeWorld), Check: []Invariant{Fs98Agreement(world)}, Tiers: []Tier{TierT2, TierT3}}
}

// A personal network: the owner's first device, a fixture, admits the owner's laptop, a host, and phone.
func fs98Personal(world *fs98World) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		owner := net.Owner()
		world.devices["first"] = owner
		world.hosts["laptop"] = world.world.AddHost("laptop", owner.MemberId, owner, 0)
		phone := net.Device("phone", owner.MemberId)
		net.AdmitDevice(owner, phone, 0)
		world.devices["phone"] = phone
		return nil
	})
}

// A member outside the AdminSet: its invited first device, a fixture, admits the member's laptop, a host, and phone.
func fs98Member(world *fs98World) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		memberId, first := net.ConsentedMember("m")
		world.devices["first"] = first
		world.hosts["laptop"] = world.world.AddHost("laptop", memberId, first, 0)
		phone := net.Device("m phone", memberId)
		net.AdmitDevice(first, phone, 0)
		world.devices["phone"] = phone
		return nil
	})
}

// The plan the laptop's `ur devices revoke <phone>` prints, lost.
func fs98LostPlan(world *fs98World) (*sidecar.DaemonDeviceRevokePlan, error) {
	preview := world.hosts["laptop"].Preview(world.devices["phone"].SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{})
	if preview.Refusal != nil || preview.Plan == nil {
		return nil, fmt.Errorf("the preview: %+v", preview.Refusal)
	}
	return preview.Plan, nil
}

// The laptop lists its member's devices, reads the phone's plan and revokes it as lost: one entry, and every reader
// drops the phone.
func fs98RevokeLost(world *fs98World, signatures int) *Step {
	return fs98Do("laptop", world, func() error {
		net := world.net()
		laptop, phone := world.hosts["laptop"], world.devices["phone"]
		devices := laptop.Devices()
		if len(devices) != 3 || !devices[0].This || devices[0].SidecarId != laptop.Device.SidecarId {
			return fmt.Errorf("ur devices lists %d devices, this one first: %+v", len(devices), devices)
		}
		listed := false
		for _, device := range devices {
			listed = listed || (device.SidecarId == phone.SidecarId && device.State == sidecar.MemberDeviceLive)
		}
		if !listed {
			return errors.New("ur devices does not list the phone as live")
		}
		plan, err := fs98LostPlan(world)
		if err != nil {
			return err
		}
		if plan.SidecarId != phone.SidecarId || plan.Reason != sidecar.DeviceRevokeLost || plan.Signatures != signatures || plan.Presence {
			return fmt.Errorf("the plan: %+v", plan)
		}
		before := net.Tip().GetVersion()
		reply := laptop.Revoke(plan)
		if reply.Refusal != nil || reply.Pending || reply.ProposalId != "" {
			return fmt.Errorf("the revocation: %+v", reply)
		}
		if reply.Position != before+1 || net.Tip().GetVersion() != before+1 {
			return fmt.Errorf("the revocation landed at %d, the tip %d, after %d", reply.Position, net.Tip().GetVersion(), before)
		}
		if net.Admitted(phone) {
			return errors.New("the phone stands after its revocation")
		}
		// the plan is spent
		if again := laptop.Revoke(plan); again.Refusal == nil || again.Refusal.Code != sidecar.DeviceRevokeCodeStale {
			return fmt.Errorf("a spent plan: %+v", again)
		}
		return nil
	})
}

// FS-98's cli twin: in a personal network the owner's laptop revokes the phone as lost.
func Fs98CliLost(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 cli a lost phone", world, fs98Personal(world), fs98RevokeLost(world, 1))
}

// FS-98's cli, a member outside the AdminSet: its consented laptop revokes its phone, whatever self_admit says.
func Fs98CliMember(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 cli a member's lost phone", world, fs98Member(world), fs98RevokeLost(world, 1))
}

// Whether err is the daemon's refusal of a Confirm method to a call that is no confirmed control call.
func fs98ConfirmationRequired(err error) bool {
	var rpcError *sidecar.DaemonRpcError
	return errors.As(err, &rpcError) && rpcError.Code == sidecar.DaemonRpcConfirmationRequired
}

// FS-98's cli: every path but the person's confirmation is refused the revocation with nothing signed, and so are the
// device's own revocation and another member's device.
func Fs98CliRefusedPaths(net *Net) *Schedule {
	world := newFs98World()
	schedule := fs98Schedule("FS-98 cli the refused paths", world,
		fs98Personal(world),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop, phone := world.hosts["laptop"], world.devices["phone"]
			_, stranger := net.ConsentedMember("stranger")
			plan, err := fs98LostPlan(world)
			if err != nil {
				return err
			}
			before := net.Tip().GetVersion()
			params := &sidecar.DaemonDevicesRevokeParams{PlanId: plan.PlanId, RevokeKeyIds: []string{}}
			// a harness hook's session, its confirmation flag set or not, and a control call with none
			for _, call := range []struct {
				mode      string
				confirmed bool
			}{
				{mode: sidecar.DaemonModeHook, confirmed: true},
				{mode: sidecar.DaemonModeHook, confirmed: false},
				{mode: sidecar.DaemonModeControl, confirmed: false},
			} {
				reply := &sidecar.DaemonDevicesRevokeReply{}
				if err := laptop.Call(call.mode, call.confirmed, sidecar.DaemonMethodDevicesRevoke, params, reply); !fs98ConfirmationRequired(err) {
					return fmt.Errorf("devices.revoke from a %s session, confirmed %t: %v", call.mode, call.confirmed, err)
				}
			}
			// an MCP session reaches no daemon method at all: the daemon serves it by its MCP server, which holds no
			// such tool, and here by nothing
			var helloRefusal *sidecar.DaemonHelloRefusal
			if err := laptop.Call(sidecar.DaemonModeMcp, true, sidecar.DaemonMethodDevicesRevoke, params, nil); !errors.As(err, &helloRefusal) {
				return fmt.Errorf("devices.revoke from an mcp session: %v", err)
			}
			// what an MCP tool's handler or a hook's would reach past the daemon
			for _, origin := range []sidecar.SidecarActOrigin{sidecar.SidecarActMcp, sidecar.SidecarActHook, sidecar.SidecarActUnconfirmed} {
				if revokeErr, _ := laptop.Act(origin, plan.PlanId, nil); !errors.Is(revokeErr, sidecar.ErrSidecarActMode) {
					return fmt.Errorf("the Sidecar's revocation from origin %d: %v", origin, revokeErr)
				}
			}
			// the device's own revocation, and another member's device
			if own := laptop.Preview(laptop.Device.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{}); own.Refusal == nil || own.Refusal.Code != sidecar.DeviceRevokeCodeSelf {
				return fmt.Errorf("this device's own revocation: %+v", own)
			}
			if other := laptop.Preview(stranger.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{}); other.Refusal == nil || other.Refusal.Code != sidecar.DeviceRevokeCodeNotOwn {
				return fmt.Errorf("another member's device: %+v", other)
			}
			if net.Tip().GetVersion() != before || !net.Admitted(phone) || !net.Admitted(stranger) {
				return fmt.Errorf("a refused path moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			// a read-only device of the member, a page Worker's kind, revokes nothing
			reader := world.world.AddHost("reader", laptop.Device.MemberId, world.devices["first"], uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
			if readOnly := reader.Preview(phone.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{}); readOnly.Refusal == nil || readOnly.Refusal.Code != sidecar.DeviceRevokeCodeNotCapable {
				return fmt.Errorf("a read-only device's revocation: %+v", readOnly)
			}
			if !net.Admitted(phone) {
				return errors.New("a read-only device revoked the phone")
			}
			return nil
		}),
	)
	schedule.Refuses = "a device revocation asked by a harness hook, an MCP call or an unconfirmed control call, of this device or of another member's"
	return schedule
}

// The compromise clauses: the phone admits a tablet, then a watch; the laptop revokes the phone as compromise from the
// watch's admission on, so the watch parks and the tablet stands. A since past the tip is REVOKE_SINCE, and one that
// reaches the laptop's own admission by the phone would park the laptop too, REVOKE_PARKS_SELF naming that entry.
func Fs98CliCompromise(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 cli a compromised phone", world,
		fs98Setup(world, func() error {
			net := world.net()
			memberId, phone := net.ConsentedMember("m")
			world.devices["phone"] = phone
			// the phone, the member's first device, admitted the laptop
			world.hosts["laptop"] = world.world.AddHost("laptop", memberId, phone, 0)
			world.positions["laptop admitted"] = net.Tip().GetVersion()
			tablet, watch := net.Device("m tablet", memberId), net.Device("m watch", memberId)
			net.AdmitDevice(phone, tablet, 0)
			net.AdmitDevice(phone, watch, 0)
			world.positions["watch admitted"] = net.Tip().GetVersion()
			world.devices["tablet"], world.devices["watch"] = tablet, watch
			return nil
		}),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop, phone := world.hosts["laptop"], world.devices["phone"]
			if neither := laptop.Preview(phone.SidecarId, sidecar.DeviceRevokeCompromise, 0, time.Time{}); neither.Refusal == nil || neither.Refusal.Code != sidecar.DeviceRevokeCodeSince {
				return fmt.Errorf("a compromise revocation with no since: %+v", neither)
			}
			if past := laptop.Preview(phone.SidecarId, sidecar.DeviceRevokeCompromise, net.Tip().GetVersion()+5, time.Time{}); past.Refusal == nil || past.Refusal.Code != sidecar.DeviceRevokeCodeSince {
				return fmt.Errorf("a since past the tip: %+v", past)
			}
			parksSelf := laptop.Preview(phone.SidecarId, sidecar.DeviceRevokeCompromise, world.positions["laptop admitted"], time.Time{})
			if parksSelf.Refusal == nil || parksSelf.Refusal.Code != sidecar.DeviceRevokeCodeParksSelf || parksSelf.Refusal.Position != world.positions["laptop admitted"] {
				return fmt.Errorf("a since that parks this device: %+v", parksSelf.Refusal)
			}
			preview := laptop.Preview(phone.SidecarId, sidecar.DeviceRevokeCompromise, world.positions["watch admitted"], time.Time{})
			if preview.Refusal != nil {
				return fmt.Errorf("the preview: %+v", preview.Refusal)
			}
			plan := preview.Plan
			parked := false
			for _, item := range plan.Items {
				if item.Id == hex.EncodeToString(world.devices["tablet"].SidecarId.Bytes()) && item.Effect == sidecar.DeviceRevokeEffectPark {
					return errors.New("the plan parks the tablet, admitted before since_n")
				}
				parked = parked || (item.Id == hex.EncodeToString(world.devices["watch"].SidecarId.Bytes()) && item.Effect == sidecar.DeviceRevokeEffectPark)
			}
			if plan.Reason != sidecar.DeviceRevokeCompromise || plan.SinceN != world.positions["watch admitted"] || !parked {
				return fmt.Errorf("the plan: %+v, items %+v", plan, plan.Items)
			}
			if reply := laptop.Revoke(plan); reply.Refusal != nil || reply.Position == 0 {
				return fmt.Errorf("the revocation: %+v", reply)
			}
			if net.Admitted(phone) || net.Admitted(world.devices["watch"]) || !net.Admitted(world.devices["tablet"]) {
				return errors.New("the cascade: the phone and the watch should be out, the tablet in")
			}
			if row := net.Row(world.devices["watch"]); row.GetParkedAt() == 0 {
				return errors.New("the watch is not parked")
			}
			return nil
		}),
	)
}

// A team at k = 2, as the admission suite's: the owner and admins b and c, whose first devices, fixtures, the owner
// admitted from invites. Before the AdminSet names them, while one signer still admits, the owner's first device
// admits the owner's laptop, a host, and phone, and b's first device admits b's laptop, a host.
func fs98Team(world *fs98World) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		owner := net.Owner()
		memberB := net.AdmitMember(owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		memberC := net.AdmitMember(owner, "admin c", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		adminB, adminC := net.Device("admin b first device", memberB), net.Device("admin c first device", memberC)
		net.AdmitDevice(owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		net.AdmitDevice(owner, adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		world.devices["first"], world.devices["admin b"], world.devices["admin c"] = owner, adminB, adminC
		world.hosts["laptop"] = world.world.AddHost("laptop", owner.MemberId, owner, 0)
		world.hosts["desk"] = world.world.AddHost("desk", memberB, adminB, 0)
		phone := net.Device("phone", owner.MemberId)
		net.AdmitDevice(owner, phone, 0)
		world.devices["phone"] = phone
		net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB, memberC}, 0)))
		if k, n := net.State().Threshold(); k != 2 || n != 3 {
			return fmt.Errorf("k %d of n %d", k, n)
		}
		world.world.Settle()
		return nil
	})
}

// At k = 2 the laptop's revocation signs the proposal and the phone's Suspend: the phone is suspended at once and
// stands admitted until another admin's device approves.
func fs98Propose(world *fs98World) *Step {
	return fs98Do("laptop", world, func() error {
		net := world.net()
		laptop, phone := world.hosts["laptop"], world.devices["phone"]
		plan, err := fs98LostPlan(world)
		if err != nil {
			return err
		}
		if plan.Signatures != 2 {
			return fmt.Errorf("the plan asks %d signatures", plan.Signatures)
		}
		reply := laptop.Revoke(plan)
		if reply.Refusal != nil || reply.ProposalId == "" {
			return fmt.Errorf("the proposal: %+v", reply)
		}
		proposalId, err := hex.DecodeString(reply.ProposalId)
		if err != nil {
			return err
		}
		world.ids["proposal"] = proposalId
		if !net.Admitted(phone) || !net.State().Suspended(phone.SidecarId) {
			return errors.New("the phone should stand admitted and suspended while the proposal waits")
		}
		return nil
	})
}

// FS-98's cli at k = 2: admin b's laptop reads the proposal and approves it as `ur approve <proposal_id>`
// does, which revokes the phone; the proposing laptop, and a second cosign of the same device, are refused.
func Fs98CliProposal(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 cli a proposal approved", world,
		fs98Team(world),
		fs98Propose(world),
		fs98Do("desk", world, func() error {
			net := world.net()
			laptop, desk, phone := world.hosts["laptop"], world.hosts["desk"], world.devices["phone"]
			proposalId := hex.EncodeToString(world.ids["proposal"])
			// the proposer signed already, and a hook's session signs nothing
			if own := laptop.Cosign(proposalId); own.Refusal == nil || own.Refusal.Code != sidecar.DeviceRevokeCodeNotCapable {
				return fmt.Errorf("the proposer's own cosign: %+v", own)
			}
			if err := desk.Call(sidecar.DaemonModeHook, true, sidecar.DaemonMethodDevicesCosign, &sidecar.DaemonDevicesProposalParams{ProposalId: proposalId}, nil); !fs98ConfirmationRequired(err) {
				return fmt.Errorf("devices.cosign from a hook session: %v", err)
			}
			if _, cosignErr := desk.Act(sidecar.SidecarActMcp, sidecar.Id{}, world.ids["proposal"]); !errors.Is(cosignErr, sidecar.ErrSidecarActMode) {
				return fmt.Errorf("the Sidecar's cosign from MCP: %v", cosignErr)
			}
			shown := desk.Proposal(proposalId)
			if shown.Unknown || shown.Proposal == nil {
				return errors.New("admin b's laptop does not read the proposal")
			}
			proposal := shown.Proposal
			if proposal.SidecarId != phone.SidecarId || proposal.Reason != sidecar.DeviceRevokeLost || !proposal.Suspended || len(proposal.Signers) != 1 ||
				proposal.Signers[0] != hex.EncodeToString(laptop.Device.SidecarId.Bytes()) {
				return fmt.Errorf("the proposal: %+v", proposal)
			}
			if !net.Admitted(phone) {
				return errors.New("a refused cosign revoked the phone")
			}
			reply := desk.Cosign(proposalId)
			if reply.Refusal != nil || reply.Unknown || reply.Position == 0 {
				return fmt.Errorf("the cosign: %+v", reply)
			}
			if net.Admitted(phone) {
				return errors.New("the phone stands after admin b's approval")
			}
			if again := desk.Proposal(proposalId); !again.Unknown {
				return errors.New("the proposal is still open after it applied")
			}
			return nil
		}),
	)
}

// FS-98's cli at k = 2, unsigned: past its not_after the proposal is no longer open at any device, nothing approves
// it, and the phone stays suspended and admitted.
func Fs98CliProposalExpires(net *Net) *Schedule {
	world := newFs98World()
	// a proposal that lives minutes, so the clock passes its not_after with every host still unlocked and enrolled
	world.settings = &sidecartest.Fs98Settings{StatementTimeout: 10 * time.Minute}
	return fs98Schedule("FS-98 cli a proposal expired", world,
		fs98Team(world),
		fs98Propose(world),
		fs98Do("desk", world, func() error {
			net := world.net()
			desk, phone := world.hosts["desk"], world.devices["phone"]
			proposalId := hex.EncodeToString(world.ids["proposal"])
			shown := desk.Proposal(proposalId)
			if shown.Proposal == nil {
				return errors.New("the proposal is not open before its not_after")
			}
			// past not_after, and an entry whose time says so
			net.Wait(time.UnixMilli(shown.Proposal.NotAfterMs).Sub(net.Clock().Now()) + time.Minute)
			_, late := net.ConsentedMember("late")
			world.devices["late"] = late
			world.world.Settle()
			if expired := desk.Proposal(proposalId); !expired.Unknown {
				return fmt.Errorf("the proposal is open past its not_after: %+v", expired.Proposal)
			}
			before := net.Tip().GetVersion()
			if reply := desk.Cosign(proposalId); !reply.Unknown || reply.Position != 0 {
				return fmt.Errorf("a cosign of an expired proposal: %+v", reply)
			}
			if net.Tip().GetVersion() != before || !net.Admitted(phone) || !net.State().Suspended(phone.SidecarId) {
				return errors.New("the phone should stay admitted and suspended once the proposal expired")
			}
			return nil
		}),
	)
}

// FS-124's cli start: a member's laptop, a host, and phone; the phone registered a presence key of its own, and the
// laptop registers its first through the daemon's authenticator, which needs no check.
func fs124CliStart(world *fs98World) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		memberId, first := net.ConsentedMember("m")
		world.devices["first"] = first
		laptop := world.world.AddHost("laptop", memberId, first, 0)
		world.hosts["laptop"] = laptop
		phone := net.Device("m phone", memberId)
		net.AdmitDevice(first, phone, 0)
		world.devices["phone"] = phone
		phoneKey := sidecartest.NewFixturePresenceKey("fs-124 cli phone", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
		net.RegisterPresenceKey(phone, phoneKey, nil)
		world.keys["phone"] = phoneKey
		world.world.Settle()
		keyId, err := laptop.AddPresenceKey()
		if err != nil {
			return fmt.Errorf("the laptop's first presence key: %w", err)
		}
		world.ids["laptop key"] = keyId
		// the new key's own proof is its one assertion: a first key is under no other's check
		world.positions["asserts"] = uint64(laptop.Presence.AssertCount())
		return nil
	})
}

// The plan of the phone's revocation under Presence, listing the phone's registered key.
func fs124CliPlan(world *fs98World) (*sidecar.DaemonDeviceRevokePlan, error) {
	plan, err := fs98LostPlan(world)
	if err != nil {
		return nil, err
	}
	listed := false
	for _, item := range plan.Items {
		listed = listed || (item.Effect == sidecar.DeviceRevokeEffectKey && item.Id == hex.EncodeToString(world.keys["phone"].KeyId))
	}
	if !plan.Presence || !listed {
		return nil, fmt.Errorf("the plan under Presence: %+v, items %+v", plan, plan.Items)
	}
	return plan, nil
}

// FS-124's cli: while the authenticator refuses, the laptop's revocation is REVOKE_CANCELLED, a second key's
// registration and a key's removal fail, and nothing is signed: the log does not move and the phone stands.
func Fs124CliCheckRefused(net *Net) *Schedule {
	world := newFs98World()
	schedule := fs98Schedule("FS-124 cli a refused check", world,
		fs124CliStart(world),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop, phone := world.hosts["laptop"], world.devices["phone"]
			plan, err := fs124CliPlan(world)
			if err != nil {
				return err
			}
			before := net.Tip().GetVersion()
			laptop.Presence.Refuse(errors.New("the person refused"))
			if reply := laptop.Revoke(plan, world.keys["phone"].KeyId); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeCancelled {
				return fmt.Errorf("a revocation whose check was refused: %+v", reply)
			}
			if _, err := laptop.AddPresenceKey(); err == nil {
				return errors.New("a second presence key registered with its check refused")
			}
			if err := laptop.RemovePresenceKey(world.ids["laptop key"]); err == nil {
				return errors.New("a presence key removed with its check refused")
			}
			if uint64(laptop.Presence.AssertCount()) == world.positions["asserts"] {
				return errors.New("the daemon's prompt asked the authenticator nothing")
			}
			if net.Tip().GetVersion() != before || !net.Admitted(phone) {
				return fmt.Errorf("a refused check moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			return nil
		}),
	)
	schedule.Refuses = "a covered revocation, key registration and key removal whose presence check the person refused"
	return schedule
}

// FS-124's cli, the approvals: with the laptop's presence key registered, a new device's admission and the
// OwnerConfirm of a device an admin admitted for the member are each signed by `ur approve` under the daemon's
// prompt, and neither while the authenticator refuses.
func Fs124CliApprovals(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-124 cli the approvals", world,
		fs124CliStart(world),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop := world.hosts["laptop"]
			memberId := laptop.Device.MemberId
			// the member's new tablet asks this laptop to admit it
			tablet := net.Device("m tablet", memberId)
			admissionId := laptop.OpenAdmission(tablet, 0)
			// an admin admits a watch for the member, which the member never confirmed
			watch := net.Device("m watch", memberId)
			net.AdmitDevice(net.Owner(), watch, 0)
			world.world.Settle()
			if net.Consented(watch, memberId) {
				return errors.New("an admin's admission is consented before the member's OwnerConfirm")
			}
			alarmId, found := sidecar.Id{}, false
			for _, item := range laptop.Pending() {
				if item.Kind == sidecar.SidecarApprovalAdmissionAlarm && item.SidecarId != nil && *item.SidecarId == watch.SidecarId {
					alarmId, found = item.ApprovalId, true
				}
			}
			if !found {
				return fmt.Errorf("the laptop lists no alarm for the watch: %+v", laptop.Pending())
			}
			before, asked := net.Tip().GetVersion(), laptop.Presence.AssertCount()
			laptop.Presence.Refuse(errors.New("the person refused"))
			if err := laptop.Decide(admissionId, sidecar.SidecarDecisionApprove); err == nil {
				return errors.New("an admission signed with its check refused")
			}
			if err := laptop.Decide(alarmId, sidecar.SidecarDecisionApprove); err == nil {
				return errors.New("an OwnerConfirm signed with its check refused")
			}
			if net.Tip().GetVersion() != before || laptop.Presence.AssertCount() == asked {
				return fmt.Errorf("refused checks moved the log from %d to %d, or asked nothing", before, net.Tip().GetVersion())
			}
			laptop.Presence.Refuse(nil)
			if err := laptop.Decide(admissionId, sidecar.SidecarDecisionApprove); err != nil {
				return fmt.Errorf("the admission under the check: %w", err)
			}
			if !net.Admitted(tablet) {
				return errors.New("the tablet is not admitted after ur approve")
			}
			if err := laptop.Decide(alarmId, sidecar.SidecarDecisionApprove); err != nil {
				return fmt.Errorf("the OwnerConfirm under the check: %w", err)
			}
			if !net.Consented(watch, memberId) {
				return errors.New("the watch is not consented after the member's OwnerConfirm")
			}
			return nil
		}),
	)
}

// FS-124's cli, `ur approve <proposal_id>`: admin b's laptop registered a presence key, so its cosign of the phone's
// revocation is covered: REVOKE_CANCELLED with nothing signed while the authenticator refuses, and under the check it
// lands and revokes the phone.
func Fs124CliCosign(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-124 cli a cosign", world,
		fs98Team(world),
		fs98Do("desk", world, func() error {
			if _, err := world.hosts["desk"].AddPresenceKey(); err != nil {
				return fmt.Errorf("the desk's presence key: %w", err)
			}
			return nil
		}),
		fs98Propose(world),
		fs98Do("desk", world, func() error {
			net := world.net()
			desk, phone := world.hosts["desk"], world.devices["phone"]
			proposalId := hex.EncodeToString(world.ids["proposal"])
			if shown := desk.Proposal(proposalId); shown.Proposal == nil || !shown.Proposal.Presence {
				return fmt.Errorf("the proposal's plan does not ask the check: %+v", shown.Proposal)
			}
			before, asked := net.Tip().GetVersion(), desk.Presence.AssertCount()
			desk.Presence.Refuse(errors.New("the person refused"))
			if reply := desk.Cosign(proposalId); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeCancelled {
				return fmt.Errorf("a cosign whose check was refused: %+v", reply)
			}
			if net.Tip().GetVersion() != before || !net.Admitted(phone) || desk.Presence.AssertCount() == asked {
				return fmt.Errorf("a refused check moved the log from %d to %d, or asked nothing", before, net.Tip().GetVersion())
			}
			desk.Presence.Refuse(nil)
			if reply := desk.Cosign(proposalId); reply.Refusal != nil || reply.Position == 0 {
				return fmt.Errorf("the cosign under the check: %+v", reply)
			}
			if net.Admitted(phone) {
				return errors.New("the phone stands after the countersigned cosign")
			}
			return nil
		}),
	)
}

// FS-124's cli, the recovery code: `ur keychain recovery-rotate` binds a first code with no check, the member holding
// no presence key yet; once the laptop registered one, a rotation is refused while the authenticator refuses, and
// under the check the rebind lands and the member's binding is the new one.
func Fs124CliRecoveryRotate(net *Net) *Schedule {
	world := newFs98World()
	world.settings = &sidecartest.Fs98Settings{RecoveryBindings: true}
	return fs98Schedule("FS-124 cli a recovery rotation", world,
		fs98Member(world),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop := world.hosts["laptop"]
			memberId := laptop.Device.MemberId
			first, err := laptop.RotateRecovery(false)
			if err != nil || first == nil || first.Entry == nil || first.PreviousKeySha256 != nil {
				return fmt.Errorf("the first binding: %+v %v", first, err)
			}
			if laptop.Presence.AssertCount() != 0 {
				return errors.New("a member with no presence key was asked a check")
			}
			if _, err := laptop.AddPresenceKey(); err != nil {
				return fmt.Errorf("the laptop's presence key: %w", err)
			}
			before, asked := net.Tip().GetVersion(), laptop.Presence.AssertCount()
			laptop.Presence.Refuse(errors.New("the person refused"))
			if rotation, err := laptop.RotateRecovery(false); err == nil {
				return fmt.Errorf("a rotation signed with its check refused: %+v", rotation)
			}
			if net.Tip().GetVersion() != before || laptop.Presence.AssertCount() == asked {
				return fmt.Errorf("a refused check moved the log from %d to %d, or asked nothing", before, net.Tip().GetVersion())
			}
			laptop.Presence.Refuse(nil)
			second, err := laptop.RotateRecovery(false)
			if err != nil || second == nil || second.Entry == nil || !bytes.Equal(second.PreviousKeySha256, first.KeySha256) {
				return fmt.Errorf("the rotation under the check: %+v %v", second, err)
			}
			if bound := net.State().Member(memberId).GetRecoveryKeySha256(); !bytes.Equal(bound, second.KeySha256) {
				return fmt.Errorf("the member's binding is %x, not the rotation's %x", bound, second.KeySha256)
			}
			return nil
		}),
	)
}

// FS-124's cli twin: under the daemon's prompt the laptop revokes the phone and the key the phone registered in one
// act, registers a second key, covered now, and removes it.
func Fs124CliUnderTheCheck(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-124 cli under the check", world,
		fs124CliStart(world),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop, phone := world.hosts["laptop"], world.devices["phone"]
			plan, err := fs124CliPlan(world)
			if err != nil {
				return err
			}
			reply := laptop.Revoke(plan, world.keys["phone"].KeyId)
			if reply.Refusal != nil || reply.Position == 0 || len(reply.RevokedKeyIds) != 1 || reply.RevokedKeyIds[0] != hex.EncodeToString(world.keys["phone"].KeyId) {
				return fmt.Errorf("the revocation under the check: %+v", reply)
			}
			if asked := uint64(laptop.Presence.AssertCount()) - world.positions["asserts"]; asked != 1 {
				return fmt.Errorf("the act asked %d checks, not one", asked)
			}
			if net.Admitted(phone) {
				return errors.New("the phone stands after the countersigned revocation")
			}
			secondKeyId, err := laptop.AddPresenceKey()
			if err != nil {
				return fmt.Errorf("a second presence key under the check: %w", err)
			}
			if err := laptop.RemovePresenceKey(secondKeyId); err != nil {
				return fmt.Errorf("removing a presence key under the check: %w", err)
			}
			// the registration asks its act's check and the new key's own proof
			if asked := uint64(laptop.Presence.AssertCount()) - world.positions["asserts"]; asked != 4 {
				return fmt.Errorf("three acts and a new key's proof asked %d assertions", asked)
			}
			return nil
		}),
	)
}
