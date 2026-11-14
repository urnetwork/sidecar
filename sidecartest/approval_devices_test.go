// §22.7's devices row and its presence row through the real gate on an approval world (MCP-M3-25; §16.6's harness_ok
// and spend check, D-MCP-9, D-MCP-14, D-MCP-19, I-8, I-9): each host pairing M3 has, with and without a presence key,
// reaches every channel its pairing allows and no other.
//
//	pairing                    no presence key        with a presence key
//	one CLI                    harness                presence
//	two CLIs                   device                 device, presence
//	a CLI and a page Worker    harness                presence
//	a CLI and a quick burner   harness                presence
//
// The rule's evidence list names device, presence and harness in every pairing, so what a pairing reaches is the
// pairing's doing: a device decision needs another approval-capable device of the member, one the requester signed
// itself is refused, and a Worker or a burner signs none; a presence decision needs the member's key; and harness_ok
// needs the member alone, no other approval-capable device and no presence key, which a Worker or a burner admitted
// beside the CLI keeps and a second CLI clears. `ur approve` on that second CLI, a real Sidecar's approver side, signs
// the device evidence the first daemon then spends. Each refusal runs beside the pairing that must succeed. The
// harness here always asked (ApprovalWorldHarness): which hook event may ask is FS-28's (fault/fs28_test.go). The
// remote-mode and phone pairings are MCP-M8-01's.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A host pairing: what the member has beside the requesting CLI, and whether the member holds a presence key.
type approvalDevicesPairing struct {
	name        string
	secondCli   bool
	other       string
	presenceKey bool
}

// The pairings M3 has, each with and without a presence key.
func approvalDevicesPairings() []*approvalDevicesPairing {
	pairings := []*approvalDevicesPairing{}
	for _, presenceKey := range []bool{false, true} {
		suffix := ""
		if presenceKey {
			suffix = " with a presence key"
		}
		pairings = append(pairings,
			&approvalDevicesPairing{name: "one CLI" + suffix, presenceKey: presenceKey},
			&approvalDevicesPairing{name: "two CLIs" + suffix, secondCli: true, presenceKey: presenceKey},
			&approvalDevicesPairing{name: "a CLI and a page Worker" + suffix, other: "worker", presenceKey: presenceKey},
			&approvalDevicesPairing{name: "a CLI and a quick burner" + suffix, other: "burner", presenceKey: presenceKey},
		)
	}
	return pairings
}

// A world of the pairing on a Net of its own: its evidence list naming every channel, its harness one that always
// asked, and the second device and presence key the pairing has, nil where it has none.
type approvalDevicesWorld struct {
	t      *testing.T
	net    *Net
	world  *ApprovalWorld
	second *ApprovalWorldDevice
	key    *FixturePresenceKey
}

func newApprovalDevicesWorld(t *testing.T, pairing *approvalDevicesPairing) *approvalDevicesWorld {
	t.Helper()
	net := NewNet(t.Context(), nil)
	world, err := NewApprovalWorldWith(net, "daemon", &ApprovalWorldOptions{Harness: NewApprovalWorldHarness})
	if err != nil {
		t.Fatal(err)
	}
	devices := &approvalDevicesWorld{t: t, net: net, world: world}
	world.SetEvidence(false,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS,
	)
	capable := []*ApprovalWorldDevice{}
	others := []*ApprovalWorldDevice{}
	if pairing.secondCli {
		devices.second = NewApprovalWorldDevice("second cli", world.Member)
		capable = append(capable, devices.second)
	}
	if pairing.other != "" {
		devices.second = NewApprovalWorldDevice(pairing.other, world.Member)
		others = append(others, devices.second)
	}
	world.SetMemberDevices(capable, others)
	if pairing.presenceKey {
		devices.key = NewFixturePresenceKey("approval devices", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		world.SetPresenceKeys(devices.key.KeyRow(world.Member.Bytes(), world.Laptop.SidecarId.Bytes(), 3))
	}
	return devices
}

// Runs body on a world of each pairing, one world at a time: a Net holds the process's test hooks while it is open.
func forEachApprovalDevicesPairing(t *testing.T, body func(pairing *approvalDevicesPairing, devices *approvalDevicesWorld)) {
	t.Helper()
	for _, pairing := range approvalDevicesPairings() {
		func() {
			devices := newApprovalDevicesWorld(t, pairing)
			defer devices.net.Close()
			body(pairing, devices)
		}()
	}
}

// The mail to recipient, called once: nil with its outcome where harness evidence spent it at once, or the approval
// it waits under.
func (self *approvalDevicesWorld) call(recipient string) (*sidecar.StoredCanonicalAction, *sidecar.SidecarAction, sidecar.Id) {
	self.t.Helper()
	stored, err := self.world.MailAction(recipient)
	if err != nil {
		self.t.Fatal(err)
	}
	action := self.world.Action(stored)
	err = self.world.Authorize(self.t.Context(), action)
	if err == nil {
		return stored, action, sidecar.Id{}
	}
	pending := &sidecar.ApprovalPendingError{}
	if !errors.As(err, &pending) {
		self.t.Fatalf("the call: %v", err)
	}
	return stored, action, pending.ApprovalId
}

// The channels of the decisions kept for approvalId.
func (self *approvalDevicesWorld) channels(approvalId sidecar.Id) []protocol.ApprovalChannel {
	self.t.Helper()
	decisions, err := self.world.Decisions(approvalId)
	if err != nil {
		self.t.Fatal(err)
	}
	channels := []protocol.ApprovalChannel{}
	for _, decision := range decisions {
		channels = append(channels, protocol.ApprovalChannel(decision.Decision.GetChannel()))
	}
	return channels
}

// When a decision signed now runs to: the request's own bound.
func (self *approvalDevicesWorld) deadline() time.Time {
	return self.net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
}

// The call presenting signed, a decision as stored: its error and its action.
func (self *approvalDevicesWorld) spend(stored *sidecar.StoredCanonicalAction, signed []byte) (*sidecar.SidecarAction, error) {
	self.t.Helper()
	action := self.world.Action(stored)
	return action, self.world.Gate().Authorize(self.t.Context(), action, approvalSuiteSigned(self.t, signed))
}

// Whether err is the spend check's refusal of the decision's signer.
func approvalDevicesSignerRefused(err error) bool {
	refusal := &sidecar.SpendRefusal{}
	return errors.As(err, &refusal) && refusal.Code == sidecar.SpendRefusalSigner
}

// The harness channel across the pairings: a call spends at once on a harness decision exactly where the member has
// the CLI alone, a Worker or a burner beside it or nothing, and no presence key; in every other pairing it waits for a
// person and nothing runs.
func TestPairingsReachHarness(t *testing.T) {
	forEachApprovalDevicesPairing(t, func(pairing *approvalDevicesPairing, devices *approvalDevicesWorld) {
		_, action, approvalId := devices.call("someone@recipient.example")
		sink := devices.world.Sink(sidecar.SidecarActionMail)
		allowed := !pairing.secondCli && !pairing.presenceKey
		if allowed {
			if approvalId != (sidecar.Id{}) || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 1 {
				t.Errorf("%s: harness evidence did not spend: pending %s, outcome %+v, %d effects", pairing.name, approvalId, action.Outcome, sink.EffectCount())
				return
			}
			ids := devices.world.Log().ApprovalIds()
			if len(ids) != 1 {
				t.Errorf("%s: %d requests", pairing.name, len(ids))
				return
			}
			channels := devices.channels(ids[0])
			if len(channels) != 1 || channels[0] != protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
				t.Errorf("%s: the decision's channels: %v", pairing.name, channels)
			}
		} else if approvalId == (sidecar.Id{}) || sink.EffectCount() != 0 {
			t.Errorf("%s: a harness decision spent where harness_ok is false: %d effects", pairing.name, sink.EffectCount())
		} else if channels := devices.channels(approvalId); len(channels) != 0 {
			t.Errorf("%s: decisions kept with no person's answer: %v", pairing.name, channels)
		}
		if err := devices.world.CheckEffects(true); err != nil {
			t.Errorf("%s: %v", pairing.name, err)
		}
	})
}

// The device channel across the pairings, a harness that never asks beside it so the request waits: a second CLI's
// decision spends; the requester's own, a Worker's and a burner's are each refused and run nothing.
func TestPairingsReachDevice(t *testing.T) {
	forEachApprovalDevicesPairing(t, func(pairing *approvalDevicesPairing, devices *approvalDevicesWorld) {
		// no harness: every pairing's request waits for a device
		devices.world.SetEvidence(false, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)
		sink := devices.world.Sink(sidecar.SidecarActionMail)

		// a device decision the requester signed itself, in every pairing
		stored, _, approvalId := devices.call("own@recipient.example")
		own, err := devices.world.SignDecision(approvalId, 1, devices.deadline(), devices.world.Laptop, devices.world.State().Pin())
		if err != nil {
			t.Fatal(err)
		}
		if action, err := devices.spend(stored, own); !approvalDevicesSignerRefused(err) || sink.EffectCount() != 0 {
			t.Errorf("%s: a device decision the requester signed itself spent: %v %+v", pairing.name, err, action.Outcome)
		}

		if devices.second == nil {
			return
		}
		stored, _, approvalId = devices.call("second@recipient.example")
		signed, err := devices.world.SignDecision(approvalId, 1, devices.deadline(), devices.second, devices.world.State().Pin())
		if err != nil {
			t.Fatal(err)
		}
		action, err := devices.spend(stored, signed)
		if pairing.secondCli {
			if err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 1 {
				t.Errorf("%s: the second CLI's decision: %v %+v, %d effects", pairing.name, err, action.Outcome, sink.EffectCount())
			}
		} else if !approvalDevicesSignerRefused(err) || sink.EffectCount() != 0 {
			t.Errorf("%s: a %s's device decision spent: %v, %d effects", pairing.name, pairing.other, err, sink.EffectCount())
		}
		if err := devices.world.CheckEffects(true); err != nil {
			t.Errorf("%s: %v", pairing.name, err)
		}
	})
}

// The presence channel across the pairings: where the member holds a key, a decision the key signs on the CLI's own
// request spends, whatever else the member has; where the member holds none, the same decision under a key P does not
// hold is refused and runs nothing.
func TestPairingsReachPresence(t *testing.T) {
	forEachApprovalDevicesPairing(t, func(pairing *approvalDevicesPairing, devices *approvalDevicesWorld) {
		devices.world.SetEvidence(false, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)
		sink := devices.world.Sink(sidecar.SidecarActionMail)
		stored, _, approvalId := devices.call("someone@recipient.example")
		key := devices.key
		if key == nil {
			key = NewFixturePresenceKey("a key no state holds", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		}
		signed, err := devices.world.SignPresenceDecision(approvalId, devices.deadline(), key)
		if err != nil {
			t.Fatal(err)
		}
		action, err := devices.spend(stored, signed)
		if pairing.presenceKey {
			if err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 1 {
				t.Errorf("%s: the presence decision: %v %+v, %d effects", pairing.name, err, action.Outcome, sink.EffectCount())
				return
			}
			channels := devices.channels(approvalId)
			if len(channels) != 1 || channels[0] != protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
				t.Errorf("%s: the decision's channels: %v", pairing.name, channels)
			}
		} else if !approvalDevicesSignerRefused(err) || sink.EffectCount() != 0 {
			t.Errorf("%s: a presence decision under a key the member does not hold spent: %v, %d effects", pairing.name, err, sink.EffectCount())
		}
		if err := devices.world.CheckEffects(true); err != nil {
			t.Errorf("%s: %v", pairing.name, err)
		}
	})
}

// harness_ok as devices are admitted to one world: the CLI alone has it; a page Worker admitted beside it keeps it; a
// second CLI admitted clears it, and the next call waits for a person; with the second CLI gone it holds again.
func TestWorkerKeepsHarnessSecondCliClearsIt(t *testing.T) {
	devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "one CLI"})
	defer devices.net.Close()
	sink := devices.world.Sink(sidecar.SidecarActionMail)
	worker := NewApprovalWorldDevice("worker", devices.world.Member)
	secondCli := NewApprovalWorldDevice("second cli", devices.world.Member)

	if _, action, approvalId := devices.call("alone@recipient.example"); approvalId != (sidecar.Id{}) || action.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("the CLI alone: pending %s", approvalId)
	}
	devices.world.SetMemberDevices(nil, []*ApprovalWorldDevice{worker})
	if _, action, approvalId := devices.call("worker@recipient.example"); approvalId != (sidecar.Id{}) || action.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("a Worker admitted cleared harness_ok: pending %s", approvalId)
	}
	if sink.EffectCount() != 2 {
		t.Fatalf("%d effects of two harness decisions", sink.EffectCount())
	}
	devices.world.SetMemberDevices([]*ApprovalWorldDevice{secondCli}, []*ApprovalWorldDevice{worker})
	if _, _, approvalId := devices.call("second@recipient.example"); approvalId == (sidecar.Id{}) || sink.EffectCount() != 2 {
		t.Fatalf("a second CLI admitted kept harness_ok: %d effects", sink.EffectCount())
	}
	// twin: the same call once the second CLI is gone
	devices.world.SetMemberDevices(nil, []*ApprovalWorldDevice{worker})
	if _, action, approvalId := devices.call("second@recipient.example"); approvalId != (sidecar.Id{}) || action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 3 {
		t.Fatalf("the CLI and its Worker again: pending %s, %d effects", approvalId, sink.EffectCount())
	}
	if err := devices.world.CheckEffects(true); err != nil {
		t.Error(err)
	}
}

// The world's requests as a real second Sidecar's approver side takes them. The embedded interface supplies
// ApproverLog's unexported log listing, which a cancel alone calls and this test never does.
type approvalDevicesLog struct {
	sidecar.ApproverLog
	requests *ApprovalWorldRequests
}

func (self *approvalDevicesLog) Pending(ctx context.Context) ([]*sidecar.RecordPendingApproval, error) {
	return self.requests.Pending(ctx)
}

func (self *approvalDevicesLog) FileDecision(ctx context.Context, logId sidecar.Id, storedSigned []byte, runId *sidecar.Id) (*sidecar.RecordEntryRef, error) {
	return self.requests.FileDecision(ctx, logId, storedSigned, runId)
}

func (self *approvalDevicesLog) FileCancel(ctx context.Context, logId sidecar.Id, storedSigned []byte) (*sidecar.RecordEntryRef, error) {
	return self.requests.FileCancel(ctx, logId, storedSigned)
}

// The devices row's last clause: with a second CLI admitted, the first daemon's call waits, `ur approve` on the second
// CLI, a real Sidecar's approver side over the request it reads, signs a device decision under its identity key, and
// the first daemon spends it. Before the second CLI is the member's consented device it signs nothing.
func TestSecondCliApprovalAccepted(t *testing.T) {
	devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "one CLI"})
	defer devices.net.Close()
	world := devices.world
	second, err := devices.net.AddSidecar("second", nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := second.Sidecar().Identity()
	world.SetMemberDevices([]*ApprovalWorldDevice{{SidecarId: identity.SidecarId, MemberId: world.Member, PublicKey: identity.IdentityPublicKey}}, nil)

	stored, _, approvalId := devices.call("someone@recipient.example")
	if approvalId == (sidecar.Id{}) {
		t.Fatal("the call spent with a second CLI admitted")
	}
	approver := sidecar.NewApprovalApprover(second.Sidecar(), &approvalDevicesLog{requests: world.Requests()})
	approve := &sidecar.SidecarRequestDecision{Decision: sidecar.SidecarDecisionApprove}

	// the second CLI's own verified state: admitted under the member, not yet consented
	authority := NewFakeAuthority()
	authority.SetPin(world.State().Pin())
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: identity.SidecarId, MemberId: world.Member, IdentityPublicKey: identity.IdentityPublicKey})
	defer second.Sidecar().InstallAuthority(authority)()
	if err := approver.Decide(t.Context(), approvalId, approve, sidecar.SidecarActConfirmed, nil); !errors.Is(err, sidecar.ErrSidecarApprovalNotEligible) {
		t.Fatalf("a device with no consent decided: %v", err)
	}
	if channels := devices.channels(approvalId); len(channels) != 0 {
		t.Fatalf("decisions kept: %v", channels)
	}
	// a hook's word decides nothing there
	authority.SetConsented(identity.SidecarId, world.Member, true)
	if err := approver.Decide(t.Context(), approvalId, approve, sidecar.SidecarActHook, nil); !errors.Is(err, sidecar.ErrSidecarActMode) {
		t.Fatal("a decision with no person's confirmation was signed")
	}

	// twin: consented, on a person's confirmation
	if err := approver.Decide(t.Context(), approvalId, approve, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	action := world.Action(stored)
	if err := world.Authorize(t.Context(), action); err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("the first daemon's spend of the second CLI's decision: %v %+v", err, action.Outcome)
	}
	decisions, err := world.Decisions(approvalId)
	if err != nil || len(decisions) != 1 {
		t.Fatalf("%d decisions, %v", len(decisions), err)
	}
	if decisions[0].Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) || !bytes.Equal(decisions[0].Signed.GetSignerId(), identity.SidecarId.Bytes()) {
		t.Errorf("the decision: channel %d, signer %x", decisions[0].Decision.GetChannel(), decisions[0].Signed.GetSignerId())
	}
	if world.Sink(sidecar.SidecarActionMail).EffectCount() != 1 {
		t.Errorf("%d effects", world.Sink(sidecar.SidecarActionMail).EffectCount())
	}
	if err := world.CheckEffects(true); err != nil {
		t.Error(err)
	}
}
