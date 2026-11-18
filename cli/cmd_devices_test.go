// ur devices, ur devices revoke and ur approve <proposal_id> against an in-process daemon (CORE-M3-04; D-CORE-20,
// D-CORE-13, FS-98's CLI rows): the plan on the terminal, a signature only after a yes on /dev/tty, never without a
// terminal, and the signing methods refused to a harness hook's session and an unconfirmed control call. The daemon
// here answers the devices methods as a test scripts them and records each call; the root's own handlers are tested
// in daemon_devices_test.go, and through a real daemon and Sidecar in sidecartest's FS-98 schedules.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One devices call the daemon took.
type testUrDevicesCall struct {
	method    string
	confirmed bool
	params    json.RawMessage
}

// The devices methods, scripted: each answers what a test set and records its call.
type testUrDevices struct {
	stateLock sync.Mutex
	calls     []*testUrDevicesCall
	list      *sidecar.DaemonDevicesListReply
	preview   *sidecar.DaemonDevicesPreviewReply
	revoke    *sidecar.DaemonDevicesRevokeReply
	proposal  *sidecar.DaemonDevicesProposalReply
	cosign    *sidecar.DaemonDevicesCosignReply
}

func (self *testUrDevices) methods() []*sidecar.DaemonMethod {
	method := func(name string, confirm bool, answer func() any) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{Name: name, Confirm: confirm, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.calls = append(self.calls, &testUrDevicesCall{method: name, confirmed: call.Confirmed, params: call.Params})
			return answer(), nil
		}}
	}
	return []*sidecar.DaemonMethod{
		method(sidecar.DaemonMethodDevicesList, false, func() any { return self.list }),
		method(sidecar.DaemonMethodDevicesPreview, false, func() any { return self.preview }),
		method(sidecar.DaemonMethodDevicesRevoke, true, func() any { return self.revoke }),
		method(sidecar.DaemonMethodDevicesProposal, false, func() any { return self.proposal }),
		method(sidecar.DaemonMethodDevicesCosign, true, func() any { return self.cosign }),
	}
}

// The calls of method so far.
func (self *testUrDevices) callsOf(method string) []*testUrDevicesCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := []*testUrDevicesCall{}
	for _, call := range self.calls {
		if call.method == method {
			calls = append(calls, call)
		}
	}
	return calls
}

// A daemon serving the scripted devices methods, and a ur on its socket.
func startTestDevicesDaemon(t *testing.T, devices *testUrDevices) *testUrDaemon {
	t.Helper()
	return startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range devices.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A plan of a lost revocation of deviceId under Presence, listing two keys the device registered.
func testDevicesPlan(deviceId sidecar.Id, keyIds ...string) *sidecar.DaemonDeviceRevokePlan {
	plan := &sidecar.DaemonDeviceRevokePlan{
		PlanId:     sidecar.NewId(),
		SidecarId:  deviceId,
		Reason:     sidecar.DeviceRevokeLost,
		Items:      []*sidecar.DaemonDeviceRevokeItem{},
		Signatures: 1,
		Presence:   true,
	}
	for _, keyId := range keyIds {
		plan.Items = append(plan.Items, &sidecar.DaemonDeviceRevokeItem{
			Effect: sidecar.DeviceRevokeEffectKey, Kind: sidecar.DeviceRevokeKindKey, Id: keyId, Name: "presence", Position: 8,
		})
	}
	return plan
}

// ur devices prints each device a line, this one first as the daemon lists them.
func TestDevicesListsEachDevice(t *testing.T) {
	thisId, phoneId := sidecar.NewId(), sidecar.NewId()
	devices := &testUrDevices{list: &sidecar.DaemonDevicesListReply{Devices: []*sidecar.DaemonDevice{
		{SidecarId: thisId, This: true, State: sidecar.MemberDeviceLive, AdmittedAtMs: 1_800_000_000_000},
		{SidecarId: phoneId, Name: "phone", State: sidecar.MemberDevicePending, ReadOnly: true},
	}}}
	daemon := startTestDevicesDaemon(t, devices)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "devices"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], thisId.String()) || !strings.Contains(lines[0], "this device") ||
		!strings.Contains(lines[0], "admitted 2027-01-15T08:00:00Z") || !strings.HasPrefix(lines[1], phoneId.String()+"  phone  pending, read-only") {
		t.Errorf("the list: %q", stdout.String())
	}
}

// D-CORE-13: ur devices revoke signs only after a yes typed on the terminal. With no terminal it refuses and no
// signing call reaches the daemon, whatever stdin holds; a no changes nothing; a yes sends the confirmed call with the
// plan the person read and the keys they left selected.
func TestRevokeNeedsTty(t *testing.T) {
	phoneId := sidecar.NewId()
	keptKeyId, goneKeyId := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	plan := testDevicesPlan(phoneId, keptKeyId, goneKeyId)
	devices := &testUrDevices{
		preview: &sidecar.DaemonDevicesPreviewReply{Plan: plan},
		revoke:  &sidecar.DaemonDevicesRevokeReply{Position: 41, RevokedKeyIds: []string{goneKeyId}},
	}
	daemon := startTestDevicesDaemon(t, devices)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	args := []string{"ur", "devices", "revoke", phoneId.String(), "--keep-key=" + keptKeyId}

	// no terminal: stdin's yes counts for nothing
	cli.stdin = strings.NewReader("yes\n")
	if code := cli.main(context.Background(), args); code != urExitFailed || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("with no terminal: exit %d: %q", code, stderr.String())
	}
	// a no
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || !strings.Contains(stdout.String(), "nothing changed") {
		t.Fatalf("a no: exit %d: %q %q", code, stdout.String(), stderr.String())
	}
	if calls := devices.callsOf(sidecar.DaemonMethodDevicesRevoke); len(calls) != 0 {
		t.Fatalf("%d signing calls reached the daemon before a yes", len(calls))
	}
	// the plan was on the terminal before the question
	shown := tty.written.String()
	if !strings.Contains(shown, phoneId.String()) || !strings.Contains(shown, "as lost") || !strings.Contains(shown, keptKeyId+" (presence), entry 8: kept") ||
		!strings.Contains(shown, goneKeyId+" (presence), entry 8: revoked with the device") || !strings.Contains(shown, "authenticator") {
		t.Errorf("the terminal showed %q", shown)
	}
	// a yes
	tty = &testTty{lines: []string{"yes"}}
	stdout.Reset()
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("a yes: exit %d: %q", code, stderr.String())
	}
	calls := devices.callsOf(sidecar.DaemonMethodDevicesRevoke)
	if len(calls) != 1 || !calls[0].confirmed {
		t.Fatalf("the signing calls: %+v", calls)
	}
	params := &sidecar.DaemonDevicesRevokeParams{}
	if err := json.Unmarshal(calls[0].params, params); err != nil {
		t.Fatal(err)
	}
	if params.PlanId != plan.PlanId || len(params.RevokeKeyIds) != 1 || params.RevokeKeyIds[0] != goneKeyId {
		t.Errorf("the confirmed call: %+v", params)
	}
	if !strings.Contains(stdout.String(), "revoked at entry 41") || !strings.Contains(stdout.String(), "key "+goneKeyId+" revoked") {
		t.Errorf("the result: %q", stdout.String())
	}
	// a key the device never registered is no key to keep
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--keep-key=" + strings.Repeat("ef", 32)}); code != urExitFailed {
		t.Errorf("an unknown --keep-key: exit %d", code)
	}
}

// With no presence key the plan sets no Presence, and no key is sent for revocation, selected or not.
func TestRevokeWithoutPresenceRevokesNoKey(t *testing.T) {
	phoneId := sidecar.NewId()
	plan := testDevicesPlan(phoneId, strings.Repeat("ab", 32))
	plan.Presence = false
	devices := &testUrDevices{preview: &sidecar.DaemonDevicesPreviewReply{Plan: plan}, revoke: &sidecar.DaemonDevicesRevokeReply{Position: 12}}
	daemon := startTestDevicesDaemon(t, devices)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String()}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	params := &sidecar.DaemonDevicesRevokeParams{}
	calls := devices.callsOf(sidecar.DaemonMethodDevicesRevoke)
	if len(calls) != 1 || json.Unmarshal(calls[0].params, params) != nil || len(params.RevokeKeyIds) != 0 {
		t.Fatalf("the confirmed call: %+v %+v", calls, params)
	}
	if !strings.Contains(tty.written.String(), "no key is revoked") {
		t.Errorf("the terminal showed %q", tty.written.String())
	}
}

// --compromise takes --since as a position or a loss time, asks the loss time on the terminal when none is given, and
// --since alone is refused.
func TestRevokeCompromiseTakesSince(t *testing.T) {
	phoneId := sidecar.NewId()
	plan := testDevicesPlan(phoneId)
	plan.Reason = sidecar.DeviceRevokeCompromise
	plan.SinceN = 17
	plan.Items = []*sidecar.DaemonDeviceRevokeItem{{Effect: sidecar.DeviceRevokeEffectPark, Kind: sidecar.DeviceRevokeKindDevice, Id: hex.EncodeToString(sidecar.NewId().Bytes()), Position: 19}}
	devices := &testUrDevices{preview: &sidecar.DaemonDevicesPreviewReply{Plan: plan}, revoke: &sidecar.DaemonDevicesRevokeReply{Position: 30}}
	daemon := startTestDevicesDaemon(t, devices)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	previewParams := func(index int) *sidecar.DaemonDevicesPreviewParams {
		t.Helper()
		calls := devices.callsOf(sidecar.DaemonMethodDevicesPreview)
		params := &sidecar.DaemonDevicesPreviewParams{}
		if len(calls) <= index || json.Unmarshal(calls[index].params, params) != nil {
			t.Fatalf("preview %d of %d", index, len(calls))
		}
		return params
	}
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--since=17"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "--compromise") {
		t.Fatalf("--since alone: exit %d: %q", code, stderr.String())
	}
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--compromise", "--since=17"}); code != urExitOk {
		t.Fatalf("a position: exit %d: %q", code, stderr.String())
	}
	if params := previewParams(0); params.Reason != sidecar.DeviceRevokeCompromise || params.SinceN != 17 || params.LostAtMs != 0 {
		t.Errorf("a position: %+v", params)
	}
	if shown := tty.written.String(); !strings.Contains(shown, "as compromise, from entry 17") || !strings.Contains(shown, "parks ") {
		t.Errorf("the terminal showed %q", shown)
	}
	// a plan that voids no recovery binding says nothing of one
	if shown := tty.written.String(); strings.Contains(shown, "ur keychain recovery-rotate") {
		t.Errorf("a plan voiding no binding showed %q", shown)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--compromise", "--since=2027-01-15T08:00:00Z"}); code != urExitOk {
		t.Fatalf("a time: exit %d: %q", code, stderr.String())
	}
	if params := previewParams(1); params.SinceN != 0 || params.LostAtMs != 1_800_000_000_000 {
		t.Errorf("a time: %+v", params)
	}
	// none given: the terminal asks, then asks to confirm
	tty = &testTty{lines: []string{"2027-01-15T08:00:00Z", "yes"}}
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--compromise"}); code != urExitOk {
		t.Fatalf("asked: exit %d: %q", code, stderr.String())
	}
	if params := previewParams(2); params.LostAtMs != 1_800_000_000_000 {
		t.Errorf("asked: %+v", params)
	}
	if len(devices.callsOf(sidecar.DaemonMethodDevicesRevoke)) != 3 {
		t.Errorf("%d signing calls", len(devices.callsOf(sidecar.DaemonMethodDevicesRevoke)))
	}
}

// A plan that voids a member's recovery binding says what the void leaves (QD-1034; owner decision 126): the member
// has no code, a device of theirs outside the cascade binds a fresh one with ur keychain recovery-rotate, and an
// admin's admission reads no owner-bound repo until the owner's consented device approves it.
func TestRevokeSaysWhatAVoidedRecoveryCodeLeaves(t *testing.T) {
	phoneId := sidecar.NewId()
	plan := testDevicesPlan(phoneId)
	plan.Reason = sidecar.DeviceRevokeCompromise
	plan.SinceN = 17
	plan.Items = []*sidecar.DaemonDeviceRevokeItem{
		{Effect: sidecar.DeviceRevokeEffectPark, Kind: sidecar.DeviceRevokeKindDevice, Id: hex.EncodeToString(sidecar.NewId().Bytes()), Position: 19},
		{Effect: sidecar.DeviceRevokeEffectVoid, Kind: "recovery_binding", Id: strings.Repeat("ab", 32), Position: 21},
	}
	devices := &testUrDevices{preview: &sidecar.DaemonDevicesPreviewReply{Plan: plan}, revoke: &sidecar.DaemonDevicesRevokeReply{Position: 30}}
	daemon := startTestDevicesDaemon(t, devices)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String(), "--compromise", "--since=17"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	shown := tty.written.String()
	for _, said := range []string{"voids   recovery_binding " + strings.Repeat("ab", 32), "leaves its member none", "ur keychain recovery-rotate", "this revocation does not cover",
		"an admin admits one", "no owner-bound repo until its owner's consented device approves it"} {
		if !strings.Contains(shown, said) {
			t.Errorf("the terminal did not say %q: %q", said, shown)
		}
	}
	if strings.Contains(shown, "restore") {
		t.Errorf("the terminal promised a restored code: %q", shown)
	}
}

// A refusal ends the command with its code and what it means, REVOKE_PARKS_SELF naming its entry, before any question;
// a refused presence check after the yes is REVOKE_CANCELLED; and at k > 1 the command prints the proposal to approve.
func TestRevokePrintsRefusalsAndTheProposal(t *testing.T) {
	phoneId := sidecar.NewId()
	devices := &testUrDevices{preview: &sidecar.DaemonDevicesPreviewReply{
		Refusal: &sidecar.DaemonDeviceRefusal{Code: sidecar.DeviceRevokeCodeParksSelf, Position: 23},
	}}
	daemon := startTestDevicesDaemon(t, devices)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	args := []string{"ur", "devices", "revoke", phoneId.String(), "--compromise", "--since=20"}
	if code := cli.main(context.Background(), args); code != urExitFailed || !strings.Contains(stderr.String(), "REVOKE_PARKS_SELF") ||
		!strings.Contains(stderr.String(), "entry 23") || tty.written.Len() != 0 {
		t.Fatalf("a plan that parks this device: exit %d: %q, terminal %q", code, stderr.String(), tty.written.String())
	}
	plan := testDevicesPlan(phoneId)
	plan.Signatures = 2
	devices.stateLock.Lock()
	devices.preview = &sidecar.DaemonDevicesPreviewReply{Plan: plan}
	devices.revoke = &sidecar.DaemonDevicesRevokeReply{Refusal: &sidecar.DaemonDeviceRefusal{Code: sidecar.DeviceRevokeCodeCancelled}}
	devices.stateLock.Unlock()
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String()}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "REVOKE_CANCELLED") {
		t.Fatalf("a refused presence check: exit %d: %q", code, stderr.String())
	}
	proposalId := strings.Repeat("9a", 32)
	devices.stateLock.Lock()
	devices.revoke = &sidecar.DaemonDevicesRevokeReply{ProposalId: proposalId}
	devices.stateLock.Unlock()
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phoneId.String()}); code != urExitOk ||
		!strings.Contains(stdout.String(), "authority_pending") || !strings.Contains(stdout.String(), "ur approve "+proposalId) {
		t.Fatalf("at k = 2: exit %d: %q %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(tty.written.String(), "it takes 2 admins") {
		t.Errorf("the terminal showed %q", tty.written.String())
	}
}

// ur approve <proposal_id>: the proposal's plan on the terminal, then this device's cosign only after a yes there;
// with no terminal nothing is signed, --deny takes no proposal, and an id no open proposal has is said so.
func TestApproveProposalCosignsOnTheTerminal(t *testing.T) {
	phoneId, memberId := sidecar.NewId(), sidecar.NewId()
	proposalId := strings.Repeat("9a", 32)
	proposerId := hex.EncodeToString(sidecar.NewId().Bytes())
	devices := &testUrDevices{
		proposal: &sidecar.DaemonDevicesProposalReply{Proposal: &sidecar.DaemonDeviceRevokeProposal{
			ProposalId: proposalId, SidecarId: phoneId, MemberId: memberId, Reason: sidecar.DeviceRevokeLost, Items: []*sidecar.DaemonDeviceRevokeItem{},
			ProposedAt: 31, NotAfterMs: 1_800_000_000_000, Signers: []string{proposerId}, Suspended: true, Presence: true,
		}},
		cosign: &sidecar.DaemonDevicesCosignReply{Position: 33},
	}
	daemon := startTestDevicesDaemon(t, devices)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "approve", proposalId}); code != urExitFailed || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("with no terminal: exit %d: %q", code, stderr.String())
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", proposalId}); code != urExitOk || len(devices.callsOf(sidecar.DaemonMethodDevicesCosign)) != 0 {
		t.Fatalf("a no: exit %d, %d cosigns", code, len(devices.callsOf(sidecar.DaemonMethodDevicesCosign)))
	}
	shown := tty.written.String()
	if !strings.Contains(shown, "revoke device - "+phoneId.String()+" of member "+memberId.String()+" as lost") || !strings.Contains(shown, proposerId) ||
		!strings.Contains(shown, "suspended while the proposal waits") || !strings.Contains(shown, "2027-01-15T08:00:00Z") {
		t.Errorf("the terminal showed %q", shown)
	}
	if code := cli.main(context.Background(), []string{"ur", "approve", proposalId, "--deny"}); code != urExitFailed {
		t.Errorf("--deny of a proposal: exit %d", code)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", strings.ToUpper(proposalId)}); code != urExitOk {
		t.Fatalf("a yes: exit %d: %q", code, stderr.String())
	}
	calls := devices.callsOf(sidecar.DaemonMethodDevicesCosign)
	params := &sidecar.DaemonDevicesProposalParams{}
	if len(calls) != 1 || !calls[0].confirmed || json.Unmarshal(calls[0].params, params) != nil || params.ProposalId != proposalId {
		t.Fatalf("the cosign call: %+v %+v", calls, params)
	}
	if !strings.Contains(stdout.String(), "approved at entry 33") {
		t.Errorf("the result: %q", stdout.String())
	}
	devices.stateLock.Lock()
	devices.proposal = &sidecar.DaemonDevicesProposalReply{Unknown: true}
	devices.stateLock.Unlock()
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "approve", proposalId}); code != urExitFailed || !strings.Contains(stderr.String(), "no open revocation proposal") {
		t.Errorf("an unknown proposal: exit %d: %q", code, stderr.String())
	}
}

// An alarm's revoke answer shows the plan it signs before the person confirms.
func TestApproveRevokeShowsThePlan(t *testing.T) {
	approvalId, subject := sidecar.NewId(), sidecar.NewId()
	parkedId := sidecar.NewId()
	target := &testUrApprovalsTarget{
		items: []*sidecar.SidecarApprovalItem{{
			ApprovalId: approvalId,
			Kind:       sidecar.SidecarApprovalAdmissionAlarm,
			SidecarId:  &subject,
			Decisions:  []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionRevoke, sidecar.SidecarDecisionDeny},
		}},
		revokePlan: &sidecar.DeviceRevokePlan{
			PlanId: sidecar.NewId(), SidecarId: subject, Reason: sidecar.DeviceRevokeCompromise, SinceN: 14, Signatures: 1,
			Items: []sidecar.DeviceRevokeItem{{Effect: sidecar.DeviceRevokeEffectPark, Kind: sidecar.DeviceRevokeKindDevice, Id: parkedId.Bytes(), Position: 15}},
		},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String(), "--revoke"}); code != urExitOk ||
		len(target.decisions) != 1 || target.decisions[0] != approvalId.String()+" revoke" {
		t.Fatalf("exit %d, %v: %q", code, target.decisions, stderr.String())
	}
	shown := tty.written.String()
	if !strings.Contains(shown, "compromise revocation of device "+subject.String()+" from entry 14") ||
		!strings.Contains(shown, "device "+hex.EncodeToString(parkedId.Bytes())+", entry 15") {
		t.Errorf("the terminal showed %q", shown)
	}
	// a device that may sign no revocation is told so before any question
	target.revokePlan = nil
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String(), "--revoke"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "REVOKE_NOT_CAPABLE") || tty.written.Len() != 0 || len(target.decisions) != 1 {
		t.Errorf("a device that may not revoke: exit %d: %q", code, stderr.String())
	}
}

// A daemon target on a daemon, as ur daemon's is.
type testUrDevicesTarget struct {
	testUrDaemonTarget
	daemon *sidecar.Daemon
}

func (self *testUrDevicesTarget) devicesDaemon() *sidecar.Daemon {
	return self.daemon
}

// The methods ur daemon serves over a target with a daemon hold the root's devices methods and a remote-mode app's
// two-call methods (CORE-M8-03), every one that signs marked Confirm and only the three readers not; a harness hook's
// session and an unconfirmed control call are refused each signing one at the daemon, their confirmation flag set or
// not (D-CORE-13), and a target with no daemon serves none.
func TestDevicesSigningMethodsAreConfirmOnly(t *testing.T) {
	if methods := urDevicesMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no daemon serves the devices methods")
	}
	target := &testUrDevicesTarget{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		target.daemon = daemon
		for _, method := range urDevicesMethods(target) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	confirm := map[string]bool{}
	for _, method := range urDevicesMethods(target) {
		confirm[method.Name] = method.Confirm
	}
	readers := []string{sidecar.DaemonMethodDevicesList, sidecar.DaemonMethodDevicesPreview, sidecar.DaemonMethodDevicesProposal}
	signers := []string{
		sidecar.DaemonMethodDevicesRevoke, sidecar.DaemonMethodDevicesCosign,
		sidecar.DaemonMethodDevicesRevokeBegin, sidecar.DaemonMethodDevicesRevokeFinish,
		sidecar.DaemonMethodDevicesCosignBegin, sidecar.DaemonMethodDevicesCosignFinish,
		sidecar.DaemonMethodApprovalsDecideBegin, sidecar.DaemonMethodApprovalsDecideFinish,
		sidecar.DaemonMethodKeysPresenceBegin, sidecar.DaemonMethodKeysPresenceProve, sidecar.DaemonMethodKeysPresenceFinish,
	}
	if len(confirm) != len(readers)+len(signers) {
		t.Fatalf("the devices methods: %v", confirm)
	}
	for _, name := range readers {
		if registered, ok := confirm[name]; !ok || registered {
			t.Errorf("%s: registered %t, Confirm %t", name, ok, registered)
		}
	}
	for _, name := range signers {
		if !confirm[name] {
			t.Errorf("%s is no Confirm method", name)
		}
	}
	cli, _, _ := newTestUrCli(daemon.socketPath)
	for _, c := range []struct {
		mode      string
		confirmed bool
	}{
		{mode: sidecar.DaemonModeHook, confirmed: false},
		{mode: sidecar.DaemonModeHook, confirmed: true},
		{mode: sidecar.DaemonModeControl, confirmed: false},
	} {
		hello := cli.hello(c.mode)
		if c.mode == sidecar.DaemonModeHook {
			hello.Harness = "claude-code"
		}
		client, err := cli.connectDaemon(context.Background(), hello, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.mode, err)
		}
		for _, method := range signers {
			var rpcError *sidecar.DaemonRpcError
			err := client.Call(context.Background(), method, map[string]string{}, c.confirmed, nil)
			if !errors.As(err, &rpcError) || rpcError.Code != sidecar.DaemonRpcConfirmationRequired {
				t.Errorf("%s from %s, confirmed %t: %v", method, c.mode, c.confirmed, err)
			}
		}
		client.Close()
	}
}

// FS-98's CLI row end to end on T2: ur itself, against a real daemon hosting a real Sidecar admitted in a log the fake
// api sequences and verifies (sidecartest.Fs98World). `ur devices` lists the member's devices; `ur devices revoke`
// signs nothing with no terminal or on a no, and after a yes on the terminal the revocation is one entry every reader
// applies.
func TestUrDevicesRevokeLandsInTheLog(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world := sidecartest.NewFs98World(t, net, nil)
	defer world.Close()
	admission := world.Admission()
	memberId, first := admission.ConsentedMember("m")
	laptop := world.AddHost("laptop", memberId, first, 0)
	phone := admission.Device("m phone", memberId)
	admission.AdmitDevice(first, phone, 0)
	world.Settle()

	cli, stdout, stderr := newTestUrCli(laptop.SocketPath)
	if code := cli.main(context.Background(), []string{"ur", "devices"}); code != urExitOk {
		t.Fatalf("ur devices: exit %d: %q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], laptop.Device.SidecarId.String()) || !strings.Contains(lines[0], "this device") ||
		!strings.Contains(stdout.String(), phone.SidecarId.String()) {
		t.Fatalf("ur devices: %q", stdout.String())
	}
	before := admission.Tip().GetVersion()
	args := []string{"ur", "devices", "revoke", phone.SidecarId.String()}
	cli.stdin = strings.NewReader("yes\n")
	if code := cli.main(context.Background(), args); code != urExitFailed {
		t.Fatalf("with no terminal: exit %d", code)
	}
	tty := &testTty{lines: []string{"no"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("a no: exit %d: %q", code, stderr.String())
	}
	world.Settle()
	if admission.Tip().GetVersion() != before || !admission.Admitted(phone) {
		t.Fatalf("the log moved from %d to %d before a yes on the terminal", before, admission.Tip().GetVersion())
	}
	if shown := tty.written.String(); !strings.Contains(shown, "Revoke device - "+phone.SidecarId.String()+" as lost") {
		t.Errorf("the terminal showed %q", shown)
	}
	// its own revocation is refused before any question
	tty = &testTty{lines: []string{"yes"}}
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", laptop.Device.SidecarId.String()}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "REVOKE_SELF") || tty.written.Len() != 0 {
		t.Errorf("this device's own revocation: exit %d: %q", code, stderr.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("a yes: exit %d: %q", code, stderr.String())
	}
	world.Settle()
	if admission.Tip().GetVersion() != before+1 || admission.Admitted(phone) {
		t.Fatalf("after a yes the tip is %d, from %d, the phone admitted %t", admission.Tip().GetVersion(), before, admission.Admitted(phone))
	}
	if !strings.Contains(stdout.String(), fmt.Sprintf("device %s revoked at entry %d", phone.SidecarId, before+1)) {
		t.Errorf("the result: %q", stdout.String())
	}
}

// FS-98's CLI row at k = 2 end to end on T2: the owner's `ur devices revoke` files the proposal and suspends the
// phone, printing the proposal's id; another admin's `ur approve <proposal_id>` shows the proposal and, after a yes on
// its terminal, revokes the phone.
func TestUrApproveProposalRevokesAtK2(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world := sidecartest.NewFs98World(t, net, nil)
	defer world.Close()
	admission := world.Admission()
	owner := admission.Owner()
	memberB := admission.AdmitMember(owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	memberC := admission.AdmitMember(owner, "admin c", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	adminB, adminC := admission.Device("admin b first device", memberB), admission.Device("admin c first device", memberC)
	admission.AdmitDevice(owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	admission.AdmitDevice(owner, adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	laptop := world.AddHost("laptop", owner.MemberId, owner, 0)
	desk := world.AddHost("desk", memberB, adminB, 0)
	phone := admission.Device("phone", owner.MemberId)
	admission.AdmitDevice(owner, phone, 0)
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, admission.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB, memberC}, 0)))
	world.Settle()

	cli, stdout, stderr := newTestUrCli(laptop.SocketPath)
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "devices", "revoke", phone.SidecarId.String()}); code != urExitOk {
		t.Fatalf("ur devices revoke: exit %d: %q", code, stderr.String())
	}
	world.Settle()
	_, proposalId, found := strings.Cut(stdout.String(), "ur approve ")
	proposalId = strings.TrimSpace(proposalId)
	if !found || len(proposalId) != 64 || !strings.Contains(tty.written.String(), "it takes 2 admins") {
		t.Fatalf("the proposal: %q, terminal %q", stdout.String(), tty.written.String())
	}
	if !admission.Admitted(phone) || !admission.State().Suspended(phone.SidecarId) {
		t.Fatal("the phone should stand admitted and suspended while the proposal waits")
	}

	deskCli, deskStdout, deskStderr := newTestUrCli(desk.SocketPath)
	if code := deskCli.main(context.Background(), []string{"ur", "approve", proposalId}); code != urExitFailed {
		t.Fatalf("ur approve with no terminal: exit %d", code)
	}
	world.Settle()
	if !admission.Admitted(phone) {
		t.Fatal("ur approve with no terminal revoked the phone")
	}
	deskTty := &testTty{lines: []string{"yes"}}
	deskCli.openTty = func() (urTty, error) { return deskTty, nil }
	if code := deskCli.main(context.Background(), []string{"ur", "approve", proposalId}); code != urExitOk {
		t.Fatalf("ur approve: exit %d: %q", code, deskStderr.String())
	}
	world.Settle()
	if shown := deskTty.written.String(); !strings.Contains(shown, "A proposal to revoke device - "+phone.SidecarId.String()) ||
		!strings.Contains(shown, hex.EncodeToString(laptop.Device.SidecarId.Bytes())) || !strings.Contains(shown, "suspended while the proposal waits") {
		t.Errorf("the terminal showed %q", shown)
	}
	if admission.Admitted(phone) || !strings.Contains(deskStdout.String(), "approved at entry") {
		t.Fatalf("after the approval the phone is admitted %t: %q", admission.Admitted(phone), deskStdout.String())
	}
}
