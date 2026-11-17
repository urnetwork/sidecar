// §22.7's devices row and its presence row through the real gate on an approval world (MCP-M3-25, MCP-M8-01; §16.6's
// host table, harness_ok and spend check, D-MCP-9, D-MCP-14, D-MCP-19, D-SDK-9, I-8, I-9, FS-124): each host pairing,
// with and without a presence key, reaches every channel its pairing allows and no other.
//
//	pairing                    no presence key        with a presence key
//	one CLI                    harness                presence
//	two CLIs                   device                 device, presence
//	a CLI and a page Worker    harness                presence
//	a CLI and a quick burner   harness                presence
//	two remote-mode desktops   device                 device, presence
//	a phone app with a CLI     device                 device, presence
//
// The rule's evidence list names device, presence and harness in every pairing, so what a pairing reaches is the
// pairing's doing: a device decision needs another approval-capable device of the member, one the requester signed
// itself is refused, and a Worker or a burner signs none; a presence decision needs the member's key; and harness_ok
// needs the member alone, no other approval-capable device and no presence key, which a Worker or a burner admitted
// beside the CLI keeps and a second CLI, a second desktop or a phone clears. `ur approve` on that second CLI, a real
// Sidecar's approver side, signs the device evidence the first daemon then spends. Each refusal runs beside the pairing
// that must succeed. The harness here always asked (ApprovalWorldHarness): which hook event may ask is FS-28's
// (fault/fs28_test.go).
//
// M8's pairings run their hosts' real paths as well. Two remote-mode desktops: the second desktop's app lists and
// decides over its own ur daemon's app methods on a socket, signing the first desktop's request by device after the
// app's confirmation, which the first daemon spends, and listing its daemon's own request with no decision, refused if
// sent (D-SDK-9). A phone app with a CLI: the phone's approver side in local mode signs the CLI's request by device,
// which the CLI spends, and its own request by presence through its presence signer over the decision's bytes, which
// the spend check takes from the phone alone (FS-124's app-host decision case); with no signer, or a key the member
// does not hold, its own request signs nothing. The phone's approval part leases the world's log: a request reaches the
// open app by its hint and the closed app by one wake whose payload is a topic class and a version alone (WK4).

package sidecartest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A host pairing: what the member has beside the requesting CLI, and whether the member holds a presence key. app names
// M8's pairings, whose second device is approval-capable: a second remote-mode desktop, or a phone app in local mode.
type approvalDevicesPairing struct {
	name        string
	secondCli   bool
	other       string
	app         string
	presenceKey bool
}

// M8's second devices.
const (
	approvalDevicesAppRemoteDesktop = "remote desktop"
	approvalDevicesAppPhone         = "phone"
)

// Whether the member's second device is approval-capable, as a second CLI, a second desktop and a phone are.
func (self *approvalDevicesPairing) capableSecond() bool {
	return self.secondCli || self.app != ""
}

// Every pairing §22.7's devices row names, each with and without a presence key.
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
			&approvalDevicesPairing{name: "two remote-mode desktops" + suffix, app: approvalDevicesAppRemoteDesktop, presenceKey: presenceKey},
			&approvalDevicesPairing{name: "a phone app with a CLI" + suffix, app: approvalDevicesAppPhone, presenceKey: presenceKey},
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
	switch {
	case pairing.secondCli:
		devices.second = NewApprovalWorldDevice("second cli", world.Member)
		capable = append(capable, devices.second)
	case pairing.app != "":
		devices.second = NewApprovalWorldDevice(pairing.app, world.Member)
		capable = append(capable, devices.second)
	case pairing.other != "":
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
		allowed := !pairing.capableSecond() && !pairing.presenceKey
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

// The device channel across the pairings, a harness that never asks beside it so the request waits: a second CLI's,
// a second desktop's and a phone's decision spends; the requester's own, a Worker's and a burner's are each refused
// and run nothing.
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
		if pairing.capableSecond() {
			if err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 1 {
				t.Errorf("%s: the second device's decision: %v %+v, %d effects", pairing.name, err, action.Outcome, sink.EffectCount())
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

// The world's requests as a real second Sidecar's approver side takes them, beside requests a test files there for
// another device itself, and the decisions filed through it. The embedded interface supplies ApproverLog's unexported
// log listing, which a cancel alone calls and these tests never do.
type approvalDevicesLog struct {
	sidecar.ApproverLog
	requests *ApprovalWorldRequests

	stateLock sync.Mutex
	// another device's own requests, waiting until the world's log holds a decision on each
	extra []*sidecar.RecordPendingApproval
	filed [][]byte
}

func (self *approvalDevicesLog) Pending(ctx context.Context) ([]*sidecar.RecordPendingApproval, error) {
	pending, err := self.requests.Pending(ctx)
	if err != nil {
		return nil, err
	}
	extra := func() []*sidecar.RecordPendingApproval {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.extra)
	}()
	for _, waiting := range extra {
		if _, err := self.requests.world.Log().Decision(ctx, waiting.Request.ApprovalId()); errors.Is(err, sidecar.ErrRecordApprovalPending) {
			pending = append(pending, waiting)
		}
	}
	return pending, nil
}

func (self *approvalDevicesLog) FileDecision(ctx context.Context, logId sidecar.Id, storedSigned []byte, runId *sidecar.Id) (*sidecar.RecordEntryRef, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.filed = append(self.filed, bytes.Clone(storedSigned))
	}()
	return self.requests.FileDecision(ctx, logId, storedSigned, runId)
}

func (self *approvalDevicesLog) FileCancel(ctx context.Context, logId sidecar.Id, storedSigned []byte) (*sidecar.RecordEntryRef, error) {
	return self.requests.FileCancel(ctx, logId, storedSigned)
}

// The decisions filed through the log so far, parsed.
func (self *approvalDevicesLog) decisions(t *testing.T) []*sidecar.StoredApprovalDecision {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	decisions := []*sidecar.StoredApprovalDecision{}
	for _, filed := range self.filed {
		decision, err := sidecar.ParseStoredApprovalDecision(filed)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, decision)
	}
	return decisions
}

// A request requester files for stored, the member its approver, waiting in log beside the laptop's, as another
// device's own outward call files one.
func (self *approvalDevicesWorld) fileOwnRequest(log *approvalDevicesLog, requester sidecar.Id, stored *sidecar.StoredCanonicalAction) *sidecar.StoredApprovalRequest {
	self.t.Helper()
	approvalId := sidecar.NewId()
	actionId := stored.ActionId(approvalId)
	payloadSha256 := stored.PayloadSha256()
	requestBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], CanonicalAction: stored.Bytes, PayloadSha256: payloadSha256[:],
		Risk: uint32(sidecar.SidecarRiskNormal), RequesterSidecarId: requester.Bytes(), Approvers: [][]byte{self.world.Member.Bytes()},
		NotAfterMillis: self.deadline().UnixMilli(), Version: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	request, err := sidecar.ParseStoredApprovalRequest(requestBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	log.extra = append(log.extra, &sidecar.RecordPendingApproval{LogId: self.world.LogId(), EntryId: sidecar.NewId(), Request: request, WriterSidecarId: requester})
	return request
}

// A real Sidecar of the member beside the laptop, approval-capable at P and consented in its own verified state: a
// second desktop or a phone. Its approver side reads the log it returns.
func (self *approvalDevicesWorld) addMemberSidecar(name string) (*TestSidecar, *FakeAuthority, *approvalDevicesLog) {
	self.t.Helper()
	member, err := self.net.AddSidecar(name, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	identity := member.Sidecar().Identity()
	self.world.SetMemberDevices([]*ApprovalWorldDevice{{SidecarId: identity.SidecarId, MemberId: self.world.Member, PublicKey: identity.IdentityPublicKey}}, nil)
	authority := NewFakeAuthority()
	authority.SetPin(self.world.State().Pin())
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: identity.SidecarId, MemberId: self.world.Member, IdentityPublicKey: identity.IdentityPublicKey})
	authority.SetConsented(identity.SidecarId, self.world.Member, true)
	self.t.Cleanup(member.Sidecar().InstallAuthority(authority))
	log := &approvalDevicesLog{requests: self.world.Requests()}
	self.t.Cleanup(member.Sidecar().InstallApproverLog(log))
	return member, authority, log
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

// desktop's ur daemon serving a remote-mode app's request methods on a socket of its own, and the control session the
// app holds on it, both ended when the test ends.
func startApprovalDevicesDaemon(t *testing.T, net *Net, desktop *TestSidecar) *sidecar.DaemonClient {
	t.Helper()
	// a short path, since a Unix socket's name is bounded
	directory, err := os.MkdirTemp("/tmp", "ur-approval-app-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "s")
	ctx, cancel := context.WithCancel(context.Background())
	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		daemon.Close()
		<-done
	})
	for _, method := range sidecar.DaemonApprovalsAppMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			close(done)
			t.Fatal(err)
		}
	}
	if err := daemon.AddSidecar(net.DefaultNetworkId(), desktop.Sidecar()); err != nil {
		close(done)
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		daemon.Run()
	}()
	app, err := sidecar.DialDaemon(t.Context(), socketPath, &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl, Version: sidecar.Version, Pid: int64(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app
}

// The item of approvalId in reply, nil for none.
func approvalDevicesAppItem(reply *sidecar.DaemonApprovalsAppReply, approvalId sidecar.Id) *sidecar.DaemonApprovalsAppItem {
	for _, item := range reply.Items {
		if item.ApprovalId != nil && *item.ApprovalId == approvalId {
			return item
		}
	}
	return nil
}

// Two remote-mode desktops, with and without a presence key: the second desktop's app, over its daemon's app methods,
// lists the first desktop's request on channel device and its own daemon's request with no decision; an unconfirmed
// decision runs nothing and the daemon's own is refused whatever is sent (D-SDK-9); the confirmed decision on the
// first desktop's request is signed by the second desktop's identity key, and the first daemon spends it. The first
// desktop's own request then takes the member's presence key, by its daemon's prompt: it spends where the member holds
// the key, and is refused where it does not.
func TestRemoteDesktopsDecideOverTheAppMethods(t *testing.T) {
	for _, presenceKey := range []bool{false, true} {
		func() {
			devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "two remote-mode desktops", presenceKey: presenceKey})
			defer devices.net.Close()
			world := devices.world
			desktop, _, log := devices.addMemberSidecar("second desktop")
			desktopId := desktop.Sidecar().Identity().SidecarId
			app := startApprovalDevicesDaemon(t, devices.net, desktop)
			sink := world.Sink(sidecar.SidecarActionMail)

			stored, _, approvalId := devices.call("first@recipient.example")
			if approvalId == (sidecar.Id{}) {
				t.Fatalf("key %t: the first desktop's call spent beside a second desktop", presenceKey)
			}
			ownAction, err := world.MailAction("own@recipient.example")
			if err != nil {
				t.Fatal(err)
			}
			own := devices.fileOwnRequest(log, desktopId, ownAction)

			reply := &sidecar.DaemonApprovalsAppReply{}
			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequests, &sidecar.DaemonApprovalsAppParams{}, false, reply); err != nil {
				t.Fatal(err)
			}
			first := approvalDevicesAppItem(reply, approvalId)
			if first == nil || first.Channel != "device" || !slices.Equal(first.Decisions, []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionDeny}) ||
				first.SidecarId == nil || *first.SidecarId != world.Laptop.SidecarId || first.Kind != "mail_send" {
				t.Fatalf("key %t: the first desktop's request on the app: %+v", presenceKey, first)
			}
			ownItem := approvalDevicesAppItem(reply, own.ApprovalId())
			if ownItem == nil || ownItem.Channel != "" || len(ownItem.Decisions) != 0 || ownItem.SidecarId == nil || *ownItem.SidecarId != desktopId {
				t.Fatalf("key %t: its daemon's own request on the app: %+v", presenceKey, ownItem)
			}

			approveFirst := &sidecar.DaemonApprovalsAppDecideParams{ApprovalId: approvalId, Decision: sidecar.SidecarDecisionApprove}
			rpcErr := &sidecar.DaemonRpcError{}
			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, approveFirst, false, nil); !errors.As(err, &rpcErr) || rpcErr.Code != sidecar.DaemonRpcConfirmationRequired {
				t.Fatalf("key %t: an unconfirmed decision: %v", presenceKey, err)
			}
			for _, decision := range []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionDeny} {
				params := &sidecar.DaemonApprovalsAppDecideParams{ApprovalId: own.ApprovalId(), Decision: decision}
				if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, params, true, nil); err == nil || !strings.Contains(err.Error(), sidecar.ErrSidecarApprovalNotEligible.Error()) {
					t.Fatalf("key %t: the app's %s of its daemon's own request: %v", presenceKey, decision, err)
				}
			}
			if filed := log.decisions(t); len(filed) != 0 {
				t.Fatalf("key %t: %d decisions filed before the confirmed one", presenceKey, len(filed))
			}

			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, approveFirst, true, nil); err != nil {
				t.Fatal(err)
			}
			action := world.Action(stored)
			if err := world.Authorize(t.Context(), action); err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
				t.Fatalf("key %t: the first daemon's spend of the app's decision: %v %+v", presenceKey, err, action.Outcome)
			}
			decisions, err := world.Decisions(approvalId)
			if err != nil || len(decisions) != 1 || decisions[0].Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) ||
				!bytes.Equal(decisions[0].Signed.GetSignerId(), desktopId.Bytes()) {
				t.Fatalf("key %t: the decision kept: %+v, %v", presenceKey, decisions, err)
			}

			// the first desktop's own request by the member's presence key, as its daemon's prompt signs it
			stored, _, approvalId = devices.call("presence@recipient.example")
			key := devices.key
			if key == nil {
				key = NewFixturePresenceKey("a key no state holds", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
			}
			signed, err := world.SignPresenceDecision(approvalId, devices.deadline(), key)
			if err != nil {
				t.Fatal(err)
			}
			action, err = devices.spend(stored, signed)
			wantEffects := 1
			if presenceKey {
				wantEffects = 2
				if err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
					t.Fatalf("the presence decision: %v %+v", err, action.Outcome)
				}
			} else if !approvalDevicesSignerRefused(err) {
				t.Fatalf("a presence decision under a key P does not hold: %v", err)
			}
			if sink.EffectCount() != wantEffects {
				t.Errorf("key %t: %d effects", presenceKey, sink.EffectCount())
			}
			if err := world.CheckEffects(true); err != nil {
				t.Error(err)
			}
		}()
	}
}

// A presence check over key, as an app's SidecarPresenceSigner answers one: the key's assertion over the bytes asked,
// each ask counted.
func approvalDevicesPresenceCheck(key *FixturePresenceKey, asked *int) sidecar.SidecarPresenceCheck {
	return func(message []byte) (*bridge.WebAuthnEvidence, error) {
		*asked += 1
		evidence, signature := key.Assert(message)
		if evidence == nil {
			evidence = &bridge.WebAuthnEvidence{}
		}
		evidence.KeyId = bytes.Clone(key.KeyId)
		evidence.Signature = signature
		return evidence, nil
	}
}

// A phone app with a CLI, with and without a presence key, on both of §16.6's profiles: the phone's approver side in
// local mode signs the CLI's request by device, which the CLI spends; the phone's own request, with the member's live
// key, by presence through its signer over the decision's §6.9 bytes, which the spend check takes from the phone and
// from no other spender (FS-124's app-host decision case); with no signer, or a key the member does not hold, its own
// request signs nothing.
func TestPhoneAppWithACliDecides(t *testing.T) {
	for _, alg := range []bridge.KeyAlg{bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256} {
		for _, presenceKey := range []bool{false, true} {
			func() {
				devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "a phone app with a CLI"})
				defer devices.net.Close()
				world := devices.world
				phone, authority, log := devices.addMemberSidecar("phone")
				phoneId := phone.Sidecar().Identity().SidecarId
				key := NewFixturePresenceKey("phone "+alg.String(), alg)
				keyRow := key.KeyRow(world.Member.Bytes(), phoneId.Bytes(), 3)
				if presenceKey {
					world.SetPresenceKeys(keyRow)
					authority.AddLiveKey(phoneId, keyRow)
				}
				approver, err := phone.Sidecar().ApprovalApprover()
				if err != nil {
					t.Fatal(err)
				}
				approver = approver.ForHost(sidecar.ApprovalHostAppLocal)
				approve := &sidecar.SidecarRequestDecision{Decision: sidecar.SidecarDecisionApprove}

				// the CLI's request, by the phone's device evidence
				stored, _, approvalId := devices.call("cli@recipient.example")
				if approvalId == (sidecar.Id{}) {
					t.Fatal("the CLI's call spent beside a phone")
				}
				if err := approver.Decide(t.Context(), approvalId, approve, sidecar.SidecarActConfirmed, nil); err != nil {
					t.Fatal(err)
				}
				action := world.Action(stored)
				if err := world.Authorize(t.Context(), action); err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
					t.Fatalf("%s, key %t: the CLI's spend of the phone's decision: %v %+v", alg, presenceKey, err, action.Outcome)
				}

				// the phone's own request
				ownAction, err := world.MailAction("phone@recipient.example")
				if err != nil {
					t.Fatal(err)
				}
				own := devices.fileOwnRequest(log, phoneId, ownAction)
				items, err := approver.Pending(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				ownListed := slices.ContainsFunc(items, func(item *sidecar.SidecarRequestItem) bool {
					return item.ApprovalId == own.ApprovalId() && item.Channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE && len(item.Decisions) == 2
				})
				if !ownListed {
					t.Fatalf("%s, key %t: the phone's own request is not listed for presence: %+v", alg, presenceKey, items)
				}
				if err := approver.Decide(t.Context(), own.ApprovalId(), approve, sidecar.SidecarActConfirmed, nil); !errors.Is(err, sidecar.ErrApprovalOwnRequest) {
					t.Fatalf("%s, key %t: its own request with no signer: %v", alg, presenceKey, err)
				}
				asked := 0
				err = approver.Decide(t.Context(), own.ApprovalId(), approve, sidecar.SidecarActConfirmed, approvalDevicesPresenceCheck(key, &asked))
				if !presenceKey {
					if !errors.Is(err, sidecar.ErrSidecarActPresence) || len(log.decisions(t)) != 1 {
						t.Fatalf("%s: its own request under a key the member does not hold: %v, %d filed", alg, err, len(log.decisions(t)))
					}
					return
				}
				if err != nil || asked != 1 {
					t.Fatalf("%s: its own request by presence: %v, asked %d", alg, err, asked)
				}
				filed := log.decisions(t)
				decision := filed[len(filed)-1]
				if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE) || !bytes.Equal(decision.Signed.GetKeyId(), key.KeyId) {
					t.Fatalf("%s: the phone's presence decision: %+v", alg, decision.Decision)
				}
				now := devices.net.Clock().Now()
				if err := sidecar.Spendable(decision, &sidecar.SpendInput{Action: ownAction, Spender: phoneId, Now: now}, world.State(), nil); err != nil {
					t.Fatalf("%s: the phone's presence decision does not spend for the phone: %v", alg, err)
				}
				// twin: no other spender takes it
				refusal := &sidecar.SpendRefusal{}
				err = sidecar.Spendable(decision, &sidecar.SpendInput{Action: ownAction, Spender: world.Laptop.SidecarId, Now: now}, world.State(), nil)
				if !errors.As(err, &refusal) || refusal.Code != sidecar.SpendRefusalRequester {
					t.Fatalf("%s: the CLI spends the phone's decision: %v", alg, err)
				}
			}()
		}
	}
}

// A wake names nothing (WK4): APNs' body is exactly {"aps":{"content-available":1},"t":"evs","v":<sequence>}, FCM's
// data exactly t and v, the version the log's push sequence, and no id's text appears in either.
func approvalDevicesWakeNamesNothing(t *testing.T, wake *FakeApprovalWake, sequence uint64, ids ...sidecar.Id) {
	t.Helper()
	body := map[string]json.RawMessage{}
	if err := json.Unmarshal(wake.Body, &body); err != nil {
		t.Fatalf("a wake's body %q: %v", wake.Body, err)
	}
	keys := []string{}
	for key := range body {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"aps", "t", "v"}) || string(body["aps"]) != `{"content-available":1}` || string(body["t"]) != `"evs"` ||
		string(body["v"]) != strconv.FormatUint(sequence, 10) {
		t.Fatalf("a wake's body %q", wake.Body)
	}
	if wake.Payload.TopicClass != "evs" || wake.Payload.Version != sequence {
		t.Fatalf("a wake's payload %+v", wake.Payload)
	}
	message := struct {
		Message struct {
			Data map[string]string `json:"data"`
		} `json:"message"`
	}{}
	if err := json.Unmarshal(wake.FcmMessage, &message); err != nil {
		t.Fatal(err)
	}
	dataKeys := []string{}
	for key := range message.Message.Data {
		dataKeys = append(dataKeys, key)
	}
	slices.Sort(dataKeys)
	if !slices.Equal(dataKeys, []string{"t", "v"}) || message.Message.Data["t"] != "evs" || message.Message.Data["v"] != strconv.FormatUint(sequence, 10) {
		t.Fatalf("FCM's data %+v", message.Message.Data)
	}
	for _, text := range []string{strings.ToLower(string(wake.Body)), strings.ToLower(string(wake.FcmMessage))} {
		for _, id := range ids {
			if strings.Contains(text, id.String()) || strings.Contains(text, strings.ReplaceAll(id.String(), "-", "")) {
				t.Fatalf("a wake names %s: %q", id, text)
			}
		}
	}
}

// An ApprovalRequest reaches a phone by its evs hint, else §18.7's wake (§16.6's flow): the phone's approval part leases
// the world's log; while the app runs, the CLI's request is a hint to it and wakes nothing, and its next resync raises
// approval_pending once; once the app is closed, its lease kept at evs, the next request is one wake naming nothing
// but a topic class and a version, and the next process's resync takes the lease again, raises approval_pending for
// what waits and decides the request by device, which the CLI spends; a lease left to lapse wakes nothing.
func TestPhoneReachedByHintElseWake(t *testing.T) {
	devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "a phone app with a CLI"})
	defer devices.net.Close()
	world := devices.world
	phone, _, _ := devices.addMemberSidecar("phone")
	phoneId := phone.Sidecar().Identity().SidecarId
	surrogate := NewFakeApprovalPhone(devices.net.Clock(), nil)
	defer surrogate.Follow(world.LogId(), world.Log())()
	var eventsLock sync.Mutex
	events := []sidecar.SidecarEvent{}
	defer phone.Sidecar().AddEventCallback(func(event sidecar.SidecarEvent) {
		if event.Kind != sidecar.SidecarEventApprovalPending {
			return
		}
		eventsLock.Lock()
		defer eventsLock.Unlock()
		events = append(events, event)
	})()
	raised := func() []sidecar.SidecarEvent {
		eventsLock.Lock()
		defer eventsLock.Unlock()
		return slices.Clone(events)
	}
	var hints atomic.Int32
	bind := func() *sidecar.ApprovalPhone {
		part, err := phone.Sidecar().BindApprovalPhone(&sidecar.ApprovalPhoneArgs{
			Leaser: surrogate,
			Logs:   func() ([]sidecar.Id, error) { return []sidecar.Id{world.LogId()}, nil },
			Hinted: func() { hints.Add(1) },
		})
		if err != nil {
			t.Fatal(err)
		}
		return part
	}

	part := bind()
	if resynced, err := part.Resync(t.Context()); err != nil || resynced.LeasesTaken != 1 {
		t.Fatalf("the open app's first resync: %+v, %v", resynced, err)
	}
	_, _, firstId := devices.call("first@recipient.example")
	if hints.Load() != 1 || surrogate.Counts().Hints != 1 || len(surrogate.Wakes()) != 0 {
		t.Fatalf("the open app: %d hints, %d wakes", hints.Load(), len(surrogate.Wakes()))
	}
	resynced, err := part.Resync(t.Context())
	if err != nil || !slices.Equal(resynced.Raised, []sidecar.Id{firstId}) || len(raised()) != 1 || *raised()[0].ApprovalId != firstId {
		t.Fatalf("the hinted resync: %+v, %v, raised %+v", resynced, err, raised())
	}

	// the app closes: its part releases nothing, and the process ends
	part.Close()
	surrogate.Kill()
	if leases := surrogate.Leases(); len(leases) != 1 || !leases[0].Live || leases[0].Holders != 0 {
		t.Fatalf("the closed app's lease: %+v", leases)
	}
	stored, _, secondId := devices.call("second@recipient.example")
	wakes := surrogate.Wakes()
	if len(wakes) != 1 || hints.Load() != 1 {
		t.Fatalf("the closed app: %d wakes, %d hints", len(wakes), hints.Load())
	}
	approvalDevicesWakeNamesNothing(t, wakes[0], world.Log().PushSequence(), firstId, secondId, world.LogId(), world.Member, world.Laptop.SidecarId, phoneId)

	// the wake's process: its resync takes the lease again and raises what waits
	devices.net.Clock().Advance(time.Hour)
	part = bind()
	defer part.Close()
	resynced, err = part.Resync(t.Context())
	if err != nil || resynced.LeasesTaken != 1 || !slices.Equal(resynced.Pending, []sidecar.Id{firstId, secondId}) {
		t.Fatalf("the woken app's resync: %+v, %v", resynced, err)
	}
	if count := len(raised()); count != 3 {
		t.Fatalf("%d approval_pending events: one at the open app, two at the next process", count)
	}
	if leases := surrogate.Leases(); len(leases) != 1 || leases[0].Holders != 1 || surrogate.Counts().LeasesRenewed != 1 {
		t.Fatalf("the lease taken again: %+v, %+v", leases, surrogate.Counts())
	}
	approver, err := phone.Sidecar().ApprovalApprover()
	if err != nil {
		t.Fatal(err)
	}
	if err := approver.ForHost(sidecar.ApprovalHostAppLocal).Decide(t.Context(), secondId, &sidecar.SidecarRequestDecision{Decision: sidecar.SidecarDecisionApprove}, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	// the decision's own push hints the running process and wakes nothing
	if len(surrogate.Wakes()) != 1 || hints.Load() != 2 {
		t.Fatalf("after the decision: %d wakes, %d hints", len(surrogate.Wakes()), hints.Load())
	}
	action := world.Action(stored)
	if err := world.Authorize(t.Context(), action); err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("the CLI's spend of the woken phone's decision: %v %+v", err, action.Outcome)
	}

	// a lease left to lapse: the process ends, a week passes, a request wakes nothing
	part.Close()
	surrogate.Kill()
	devices.net.Clock().Advance(8 * 24 * time.Hour)
	devices.call("lapsed@recipient.example")
	if len(surrogate.Wakes()) != 1 {
		t.Fatalf("a lapsed lease woke the phone: %d wakes", len(surrogate.Wakes()))
	}
}
