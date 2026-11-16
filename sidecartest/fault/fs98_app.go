//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's and FS-124's app-host cases (§22.8; §5.8's two calls, §18.5's SidecarApprovals, D-SDK-30, D-CORE-20,
// D-CORE-13; CORE-M8-03), on the CLI world (sidecartest.Fs98World) and its apps (sidecartest.Fs98AppHost): a phone's
// app runs its host's Sidecar in process under its SidecarPresenceSigner, and a desktop app in remote mode reaches its
// host's daemon by the two calls, signing each first call's bytes. Each runs on the tier's api, a FakeApi on T2 and
// server's sequencer on T3, every entry a host lands applied by the world's reference, new devices, gates and writer
// follower, and Fs98Agreement checks the same after every step.
//
// Registered, each a refusal beside the twin that must succeed:
//
//   - FS-98's app-host (T2+T3): with both apps' presence keys registered, a remote second call sending no presence
//     evidence under Presence, one with evidence over other bytes than its first call's, the remote app's refused
//     check and the phone app's are each REVOKE_CANCELLED with nothing signed; a harness hook's first call and an
//     unconfirmed control call's are refused; the laptop stands. Its twin: the phone's app revokes the lost laptop
//     and the desktop app, by two calls, the evicted page Worker not yet stale, both as lost, each landing once with
//     the act's one countersignature, which api and every reader check, and each target dropped by every reader.
//   - FS-124's app-host (T2+T3): with both apps' keys registered, the desktop app's admission of the member's new
//     tablet and OwnerConfirm of a watch an admin admitted, by two calls, and the phone app's admission of a pad sign
//     nothing while the app's SignWithPresence refuses or a second call sends no evidence. Its twin signs each, the
//     countersignature riding each.
//
// Named clauses a T2 test runs (fs98_app_test.go), and server's T3 test the same (server/api/fs98_app_db_test.go): the
// phone as the member's only device online revoking a lost laptop and then an evicted page Worker (FS-98's phone
// row), and a desktop app registering its key by three calls and revoking the lost phone by two (its remote-mode row).
//
// What waits: the sdk's gomobile, C-ABI and js adapters (§18's T4, SDK-M8-15) and both profiles' vectors byte-equal on
// every leg.

package fault

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs98AppHost  = Register("FS-98", "app-host", []Tier{TierT2, TierT3}, Twin(Fs98AppHostRefused, Fs98AppHostLost))
	Fs124AppHost = Register("FS-124", "app-host", []Tier{TierT2, TierT3}, Twin(Fs124AppHostRefused, Fs124AppHostDecisions))
)

// What an app-host schedule's steps share: the CLI world's, and its apps.
type fs98AppWorld struct {
	*fs98World
	apps map[string]*sidecartest.Fs98AppHost
}

func newFs98AppWorld() *fs98AppWorld {
	return &fs98AppWorld{fs98World: newFs98World(), apps: map[string]*sidecartest.Fs98AppHost{}}
}

// The hosts and apps a setup adds: name, and whether the app reaches its host's daemon in remote mode.
type fs98AppSpec struct {
	name   string
	remote bool
}

// The phone's app, in process with a Secure Enclave key's profile, and the desktop app, in remote mode with a FIDO
// key's.
var (
	fs98AppPhone   = fs98AppSpec{name: "phone"}
	fs98AppDesktop = fs98AppSpec{name: "desktop", remote: true}
)

// Adds the hosts and apps of specs as devices of memberId that admitter admits, each app then registering its own
// presence key, a first one needing no check, which every reader then holds live.
func fs98AddApps(world *fs98AppWorld, memberId sidecar.Id, admitter *sidecartest.AdmissionDevice, specs ...fs98AppSpec) error {
	net := world.net()
	for _, spec := range specs {
		host := world.world.AddHost(spec.name, memberId, admitter, 0)
		world.hosts[spec.name] = host
		alg := bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256
		if spec.remote {
			alg = bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256
		}
		world.apps[spec.name] = world.world.AddApp(spec.name, host, spec.remote, alg)
	}
	for _, spec := range specs {
		app := world.apps[spec.name]
		if err := app.RegisterPresenceKey(); err != nil {
			return fmt.Errorf("the %s app's presence key: %w", spec.name, err)
		}
		live := false
		for _, key := range net.State().LiveKeys(app.Host.Device.SidecarId) {
			live = live || bytes.Equal(key.GetKeyId(), app.Signer.KeyId())
		}
		if !live {
			return fmt.Errorf("the %s app's key is not live after its KeyRegister", spec.name)
		}
	}
	return nil
}

// A personal network: the owner's first device, a fixture, admits the apps' hosts of specs, the laptop and an evicted
// page Worker, a read-only device not yet stale; each app registers its key.
func fs98AppPersonal(world *fs98AppWorld, specs ...fs98AppSpec) *Step {
	return fs98Setup(world.fs98World, func() error {
		net := world.net()
		owner := net.Owner()
		world.devices["first"] = owner
		laptop := net.Device("laptop", owner.MemberId)
		net.AdmitDevice(owner, laptop, 0)
		worker := net.Device("page worker", owner.MemberId)
		net.AdmitDevice(owner, worker, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
		world.devices["laptop"], world.devices["worker"] = laptop, worker
		world.world.Settle()
		return fs98AddApps(world, owner.MemberId, owner, specs...)
	})
}

// Whether the entry at n is a statement of signedType carrying a countersignature by keyId.
func fs98AppCountersigned(net *sidecartest.AdmissionNet, n uint64, signedType bridge.SignedType, keyId []byte) error {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.Entry(n), entry); err != nil {
		return fmt.Errorf("the entry at %d: %w", n, err)
	}
	// a statement's entry, whose body is one Signed statement
	if entry.GetKind() != bridge.AuthEntryKindStatement {
		return fmt.Errorf("the entry at %d is of kind %d, no statement", n, entry.GetKind())
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return fmt.Errorf("the statement at %d: %w", n, err)
	}
	if bridge.SignedType(signed.GetType()) != signedType {
		return fmt.Errorf("the entry at %d is a %s, not a %s", n, bridge.SignedType(signed.GetType()), signedType)
	}
	if signed.GetWebauthn() == nil || !bytes.Equal(signed.GetWebauthn().GetKeyId(), keyId) {
		return fmt.Errorf("the %s at %d carries no countersignature by the app's key", signedType, n)
	}
	return nil
}

// The app named appName lists its member's devices, this one first and target live, previews target's revocation as
// lost, which asks the check from the log, and revokes it after the person's confirmation: one entry, the act's one
// check by the app's key riding it, and every reader drops target.
func fs98AppRevokeLost(world *fs98AppWorld, appName string, targetName string) *Step {
	return fs98Do(appName, world.fs98World, func() error {
		net := world.net()
		app, target := world.apps[appName], world.devices[targetName]
		devices := app.Devices()
		if len(devices) == 0 || !devices[0].This || devices[0].SidecarId != app.Host.Device.SidecarId {
			return fmt.Errorf("GetDevices does not list this device first: %+v", devices)
		}
		listed := false
		for _, device := range devices {
			listed = listed || (device.SidecarId == target.SidecarId && device.State == sidecar.MemberDeviceLive)
		}
		if !listed {
			return fmt.Errorf("GetDevices does not list the %s as live", targetName)
		}
		preview := app.Preview(target.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{})
		if preview.Refusal != nil || preview.Plan == nil {
			return fmt.Errorf("the preview: %+v", preview.Refusal)
		}
		plan := preview.Plan
		if plan.SidecarId != target.SidecarId || plan.Reason != sidecar.DeviceRevokeLost || plan.Signatures != 1 || !plan.Presence {
			return fmt.Errorf("the plan: %+v", plan)
		}
		before, asked := net.Tip().GetVersion(), len(app.Signer.Asked())
		reply := app.Revoke(plan)
		if reply.Refusal != nil || reply.Pending || reply.ProposalId != "" {
			return fmt.Errorf("the revocation: %+v", reply)
		}
		if reply.Position != before+1 || net.Tip().GetVersion() != before+1 {
			return fmt.Errorf("the revocation landed at %d, the tip %d, after %d", reply.Position, net.Tip().GetVersion(), before)
		}
		if signed := len(app.Signer.Asked()) - asked; signed != 1 {
			return fmt.Errorf("the act asked the app's key %d times, not once", signed)
		}
		if err := fs98AppCountersigned(net, reply.Position, bridge.SignedType_SIGNED_SIDECAR_REVOKE, app.Signer.KeyId()); err != nil {
			return err
		}
		if net.Admitted(target) {
			return fmt.Errorf("the %s stands after its revocation", targetName)
		}
		return nil
	})
}

// FS-98's app-host twin: the phone's app revokes the lost laptop in process, and the desktop app the evicted page
// Worker by the two calls.
func Fs98AppHostLost(net *Net) *Schedule {
	world := newFs98AppWorld()
	return fs98Schedule("FS-98 app-host a lost laptop and an evicted Worker", world.fs98World,
		fs98AppPersonal(world, fs98AppPhone, fs98AppDesktop),
		fs98AppRevokeLost(world, "phone", "laptop"),
		fs98AppRevokeLost(world, "desktop", "worker"),
	)
}

// FS-98's phone row: with the phone the member's only device online and no alarm pending, its app revokes a lost
// laptop and then an evicted page Worker not yet stale, both as lost.
func Fs98AppHostPhone(net *Net) *Schedule {
	world := newFs98AppWorld()
	return fs98Schedule("FS-98 app-host the phone alone", world.fs98World,
		fs98AppPersonal(world, fs98AppPhone),
		fs98Do("phone", world.fs98World, func() error {
			if pending := world.apps["phone"].Pending(); len(pending) != 0 {
				return fmt.Errorf("an alarm is pending on the phone: %+v", pending)
			}
			return nil
		}),
		fs98AppRevokeLost(world, "phone", "laptop"),
		fs98AppRevokeLost(world, "phone", "worker"),
	)
}

// FS-98's remote-mode row: a desktop app paired to its daemon registers its key by three calls and revokes the
// member's lost phone, a fixture, by two, signing the first call's bytes.
func Fs98AppHostRemote(net *Net) *Schedule {
	world := newFs98AppWorld()
	return fs98Schedule("FS-98 app-host a remote-mode desktop", world.fs98World,
		fs98Setup(world.fs98World, func() error {
			net := world.net()
			owner := net.Owner()
			world.devices["first"] = owner
			phone := net.Device("phone", owner.MemberId)
			net.AdmitDevice(owner, phone, 0)
			world.devices["phone"] = phone
			world.world.Settle()
			return fs98AddApps(world, owner.MemberId, owner, fs98AppDesktop)
		}),
		fs98Do("desktop", world.fs98World, func() error {
			app := world.apps["desktop"]
			// the proof's bytes, then nothing else: a first key is under no check
			if asked := app.Signer.Asked(); len(asked) != 1 {
				return fmt.Errorf("the desktop app's registration asked its key %d times, not once", len(asked))
			}
			return nil
		}),
		fs98AppRevokeLost(world, "desktop", "phone"),
	)
}

// FS-98's app-host: every refused path signs nothing. Over the daemon, a second call with no evidence under Presence,
// one with evidence over other bytes than its first call's, and the app's refused check; in process, the phone app's
// refused check; and a harness hook's and an unconfirmed control call's first call.
func Fs98AppHostRefused(net *Net) *Schedule {
	world := newFs98AppWorld()
	schedule := fs98Schedule("FS-98 app-host the refused paths", world.fs98World,
		fs98AppPersonal(world, fs98AppPhone, fs98AppDesktop),
		fs98Do("desktop", world.fs98World, func() error {
			net := world.net()
			desktop, phone, laptop := world.apps["desktop"], world.apps["phone"], world.devices["laptop"]
			preview := desktop.Preview(laptop.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{})
			if preview.Refusal != nil || preview.Plan == nil || !preview.Plan.Presence {
				return fmt.Errorf("the preview under Presence: %+v", preview)
			}
			plan := preview.Plan
			before := net.Tip().GetVersion()
			for name, evidenceOf := range map[string]func(countersigned []byte) []byte{
				"no evidence": func(countersigned []byte) []byte { return nil },
				"evidence over other bytes": func(countersigned []byte) []byte {
					// the app's own key, over the bytes with one more
					evidence, _ := desktop.Signer.Sign(append(bytes.Clone(countersigned), 0x01))
					return evidence
				},
			} {
				if reply := desktop.RevokeSending(plan, evidenceOf); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeCancelled {
					return fmt.Errorf("a second call with %s: %+v", name, reply)
				}
			}
			// the app's refused check: no second call, and the session's end ends the act
			desktop.Signer.Refuse(true)
			if reply := desktop.Revoke(plan); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeCancelled {
				return fmt.Errorf("the desktop app's refused check: %+v", reply)
			}
			desktop.Signer.Refuse(false)
			// the phone app's refused check, in process
			phonePlan := phone.Preview(laptop.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{})
			if phonePlan.Refusal != nil || phonePlan.Plan == nil || !phonePlan.Plan.Presence {
				return fmt.Errorf("the phone's preview: %+v", phonePlan)
			}
			phone.Signer.Refuse(true)
			if reply := phone.Revoke(phonePlan.Plan); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeCancelled {
				return fmt.Errorf("the phone app's refused check: %+v", reply)
			}
			phone.Signer.Refuse(false)
			// a harness hook's first call and an unconfirmed control call's
			for _, call := range []struct {
				mode      string
				confirmed bool
			}{
				{mode: sidecar.DaemonModeHook, confirmed: true},
				{mode: sidecar.DaemonModeControl, confirmed: false},
			} {
				if begin, err := desktop.BeginFrom(call.mode, call.confirmed, plan); !fs98ConfirmationRequired(err) {
					return fmt.Errorf("a first call from a %s session, confirmed %t: %+v, %v", call.mode, call.confirmed, begin, err)
				}
			}
			if net.Tip().GetVersion() != before || !net.Admitted(laptop) {
				return fmt.Errorf("a refused path moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			return nil
		}),
	)
	schedule.Refuses = "an app's device revocation whose presence check is refused or sends no verifying evidence over the act's bytes, and a two-call act a hook or an unconfirmed call begins"
	return schedule
}

// A member's network for FS-124's app-host case: the member's invited first device, a fixture, admits the apps' hosts
// of specs, each app registering its key.
func fs124AppMember(world *fs98AppWorld, specs ...fs98AppSpec) *Step {
	return fs98Setup(world.fs98World, func() error {
		net := world.net()
		memberId, first := net.ConsentedMember("m")
		world.devices["first"] = first
		world.world.Settle()
		return fs98AddApps(world, memberId, first, specs...)
	})
}

// The member's new tablet asks the desktop to admit it, an admin admits a watch for the member, which raises the
// desktop's admission alarm, and the member's new pad asks the phone: each item's id noted.
func fs124AppItems(world *fs98AppWorld) *Step {
	return fs98Do("network", world.fs98World, func() error {
		net := world.net()
		desktop, phone := world.apps["desktop"], world.apps["phone"]
		memberId := desktop.Host.Device.MemberId
		tablet, watch, pad := net.Device("m tablet", memberId), net.Device("m watch", memberId), net.Device("m pad", memberId)
		world.devices["tablet"], world.devices["watch"], world.devices["pad"] = tablet, watch, pad
		world.ids["tablet item"] = desktop.Host.OpenAdmission(tablet, 0).Bytes()
		world.ids["pad item"] = phone.Host.OpenAdmission(pad, 0).Bytes()
		net.AdmitDevice(net.Owner(), watch, 0)
		world.world.Settle()
		if net.Consented(watch, memberId) {
			return errors.New("an admin's admission is consented before the member's OwnerConfirm")
		}
		for _, item := range desktop.Pending() {
			if item.Kind == sidecar.SidecarApprovalAdmissionAlarm && item.SidecarId != nil && *item.SidecarId == watch.SidecarId {
				world.ids["watch alarm"] = item.ApprovalId.Bytes()
			}
		}
		if world.ids["watch alarm"] == nil {
			return fmt.Errorf("the desktop lists no alarm for the watch: %+v", desktop.Pending())
		}
		return nil
	})
}

// An item id a step noted.
func fs124AppItem(world *fs98AppWorld, name string) sidecar.Id {
	itemId, _ := sidecar.IdFromBytes(world.ids[name])
	return itemId
}

// FS-124's app-host twin: the desktop app admits the tablet and confirms the watch by the two calls, and the phone's
// app admits the pad in process, each under the app's SignWithPresence, the countersignature riding each.
func Fs124AppHostDecisions(net *Net) *Schedule {
	world := newFs98AppWorld()
	return fs98Schedule("FS-124 app-host the decisions", world.fs98World,
		fs124AppMember(world, fs98AppPhone, fs98AppDesktop),
		fs124AppItems(world),
		fs98Do("desktop", world.fs98World, func() error {
			net := world.net()
			desktop := world.apps["desktop"]
			memberId := desktop.Host.Device.MemberId
			for _, decision := range []struct {
				item       string
				signedType bridge.SignedType
			}{
				{item: "tablet item", signedType: bridge.SignedType_SIGNED_SIDECAR_ADMIT},
				{item: "watch alarm", signedType: bridge.SignedType_SIGNED_OWNER_CONFIRM},
			} {
				before := net.Tip().GetVersion()
				if err := desktop.Decide(fs124AppItem(world, decision.item), sidecar.SidecarDecisionApprove); err != nil {
					return fmt.Errorf("the desktop app's decision of the %s: %w", decision.item, err)
				}
				if net.Tip().GetVersion() != before+1 {
					return fmt.Errorf("the %s's decision landed %d entries", decision.item, net.Tip().GetVersion()-before)
				}
				if err := fs98AppCountersigned(net, before+1, decision.signedType, desktop.Signer.KeyId()); err != nil {
					return err
				}
			}
			if !net.Admitted(world.devices["tablet"]) || !net.Consented(world.devices["watch"], memberId) {
				return errors.New("the tablet is not admitted, or the watch not consented, after the desktop app's decisions")
			}
			return nil
		}),
		fs98Do("phone", world.fs98World, func() error {
			net := world.net()
			phone := world.apps["phone"]
			before := net.Tip().GetVersion()
			if err := phone.Decide(fs124AppItem(world, "pad item"), sidecar.SidecarDecisionApprove); err != nil {
				return fmt.Errorf("the phone app's admission of the pad: %w", err)
			}
			if err := fs98AppCountersigned(net, before+1, bridge.SignedType_SIGNED_SIDECAR_ADMIT, phone.Signer.KeyId()); err != nil {
				return err
			}
			if !net.Admitted(world.devices["pad"]) {
				return errors.New("the pad is not admitted after the phone app's decision")
			}
			return nil
		}),
	)
}

// FS-124's app-host: while the app's SignWithPresence refuses, the desktop app's admission and OwnerConfirm by the two
// calls and the phone app's admission in process sign nothing, and so does a remote decision whose second call sends
// no evidence; every item stays open and the log does not move.
func Fs124AppHostRefused(net *Net) *Schedule {
	world := newFs98AppWorld()
	schedule := fs98Schedule("FS-124 app-host the refused checks", world.fs98World,
		fs124AppMember(world, fs98AppPhone, fs98AppDesktop),
		fs124AppItems(world),
		fs98Do("desktop", world.fs98World, func() error {
			net := world.net()
			desktop, phone := world.apps["desktop"], world.apps["phone"]
			before := net.Tip().GetVersion()
			desktop.Signer.Refuse(true)
			phone.Signer.Refuse(true)
			for _, item := range []string{"tablet item", "watch alarm"} {
				if err := desktop.Decide(fs124AppItem(world, item), sidecar.SidecarDecisionApprove); err == nil {
					return fmt.Errorf("the desktop app's %s signed with its check refused", item)
				}
			}
			if err := phone.Decide(fs124AppItem(world, "pad item"), sidecar.SidecarDecisionApprove); err == nil {
				return errors.New("the phone app's admission signed with its check refused")
			}
			desktop.Signer.Refuse(false)
			phone.Signer.Refuse(false)
			var cancelled *sidecar.DeviceRevokeError
			if err := desktop.DecideSending(fs124AppItem(world, "tablet item"), sidecar.SidecarDecisionApprove, nil); !errors.As(err, &cancelled) ||
				cancelled.Code != sidecar.DeviceRevokeCodeCancelled {
				return fmt.Errorf("a decision's second call with no evidence: %v", err)
			}
			if net.Tip().GetVersion() != before || net.Admitted(world.devices["tablet"]) || net.Admitted(world.devices["pad"]) ||
				net.Consented(world.devices["watch"], desktop.Host.Device.MemberId) {
				return fmt.Errorf("a refused check moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			return nil
		}),
	)
	schedule.Refuses = "an app's admission and OwnerConfirm whose presence check is refused or whose second call sends no evidence"
	return schedule
}
