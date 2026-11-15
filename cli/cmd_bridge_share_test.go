package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A target is <host>=<cidr> with an optional protocol and port range; anything else is refused with an example.
func TestUrBridgeShareTargetParsesEachForm(t *testing.T) {
	for text, want := range map[string]sidecar.DaemonBridgeShareTargetParams{
		"laptop=192.168.7.9/24":         {Host: "laptop", Prefix: "192.168.7.0/24"},
		"db=100.80.3.7/32,tcp:5432":     {Host: "db", Prefix: "100.80.3.7/32", Protocol: "tcp", FirstPort: 5432, LastPort: 5432},
		"dns=10.0.0.0/20,udp:5000-5010": {Host: "dns", Prefix: "10.0.0.0/20", Protocol: "udp", FirstPort: 5000, LastPort: 5010},
	} {
		got, err := parseUrBridgeShareTarget(text)
		if err != nil || *got != want {
			t.Errorf("%s: %+v, %v", text, got, err)
		}
	}
	for _, text := range []string{"laptop", "=10.0.0.0/24", "laptop=fd00::/64", "laptop=10.0.0.0", "laptop=10.0.0.0/24,tcp", "laptop=10.0.0.0/24,icmp:1", "laptop=10.0.0.0/24,tcp:0", "laptop=10.0.0.0/24,tcp:90-80"} {
		if _, err := parseUrBridgeShareTarget(text); err == nil {
			t.Errorf("%s parsed", text)
		}
	}
}

// ur bridge invite and accept-invite ask on the terminal before they call the daemon, call it confirmed, print the
// code once with what to do with it, and say why an invite was refused.
func TestUrBridgeInviteAndAcceptAskForConfirmation(t *testing.T) {
	setTestUrBridgeWait(t, defaultUrBridgeSettings())
	daemon := &testUrBridgeDaemon{}
	shareId := sidecar.NewId()
	sharing := sidecar.NewId()
	code := sidecar.FormatBridgeShareCode([]byte(strings.Repeat("k", 32)))
	expireTime := time.Date(2027, time.January, 2, 3, 4, 0, 0, time.UTC)
	accept := &sidecar.DaemonBridgeAcceptInviteReply{ShareId: &shareId, SharingNetworkId: &sharing, Status: "active",
		Aliases: []*sidecar.DaemonBridgeShareAlias{{Index: 0, HostBits: 0x8001, Length: 32}}, ShareKeyFingerprint: "5c5c 0a0b"}
	cli, out, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodBridgeInvite, true, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeInviteReply{ShareId: shareId, Code: code, UseCount: 1, ExpireTime: &expireTime}, nil
		}),
		daemon.method(sidecar.DaemonMethodBridgeAcceptInvite, true, func(callCount int) (any, error) {
			return accept, nil
		}),
	)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	for _, args := range [][]string{{"ur", "bridge", "invite", "laptop=192.168.7.0/24"}, {"ur", "bridge", "accept-invite", code}} {
		if exit := cli.main(context.Background(), args); exit != urExitFailed {
			t.Fatalf("%v unconfirmed: exit %d", args[:3], exit)
		}
	}
	if calls, _ := daemon.calls(); len(calls) != 0 {
		t.Fatalf("an unconfirmed command called the daemon %d times", len(calls))
	}
	// a target or a code out of form is refused before any question
	cli.openTty = func() (urTty, error) { t.Fatal("asked"); return nil, nil }
	for _, args := range [][]string{{"ur", "bridge", "invite", "laptop"}, {"ur", "bridge", "accept-invite", "not-a-code"}} {
		if exit := cli.main(context.Background(), args); exit == urExitOk {
			t.Fatalf("%v ran", args[:3])
		}
	}

	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if exit := cli.main(context.Background(), []string{"ur", "bridge", "invite", "laptop=192.168.7.0/24", "db=100.80.3.7/32,tcp:5432"}); exit != urExitOk {
		t.Fatalf("invite: exit %d", exit)
	}
	printed := out.String()
	if strings.Count(printed, code) != 1 || !strings.Contains(printed, shareId.String()) || !strings.Contains(printed, "shown once") || !strings.Contains(printed, "2027-01-02 03:04 UTC") {
		t.Fatalf("the invite's answer: %s", printed)
	}
	out.Reset()
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if exit := cli.main(context.Background(), []string{"ur", "bridge", "accept-invite", code}); exit != urExitOk {
		t.Fatalf("accept-invite: exit %d", exit)
	}
	if printed := out.String(); strings.Contains(printed, code) || !strings.Contains(printed, "target 0 at .128.1/32") || !strings.Contains(printed, "activates it") ||
		!strings.Contains(printed, "share key  5c5c 0a0b") {
		t.Fatalf("the accept's answer: %s", printed)
	}
	calls, confirmed := daemon.calls()
	if len(calls) != 2 || !confirmed[0] || !confirmed[1] {
		t.Fatalf("%d calls, confirmed %v", len(calls), confirmed)
	}
	invite := &sidecar.DaemonBridgeInviteParams{}
	if err := json.Unmarshal(calls[0], invite); err != nil || len(invite.Targets) != 2 || invite.Targets[1].Protocol != "tcp" || invite.Targets[1].FirstPort != 5432 {
		t.Fatalf("invite params: %+v, %v", invite, err)
	}
	accepted := &sidecar.DaemonBridgeAcceptInviteParams{}
	if err := json.Unmarshal(calls[1], accepted); err != nil || accepted.Code != code {
		t.Fatalf("accept params: %v", err)
	}

	// a refusal says what did not fit and what to do
	accept = &sidecar.DaemonBridgeAcceptInviteReply{Status: "refused_no_space", RefusedIndex: 2, RefusedLength: 20, FreeAddressCount: 900, LargestFreeLength: 23}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if exit := cli.main(context.Background(), []string{"ur", "bridge", "accept-invite", code}); exit != urExitFailed {
		t.Fatalf("a refused accept: exit %d", exit)
	}
	accept = &sidecar.DaemonBridgeAcceptInviteReply{Status: "refused_too_large", RefusedIndex: 1, RefusedLength: 16}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if exit := cli.main(context.Background(), []string{"ur", "bridge", "accept-invite", code}); exit != urExitFailed {
		t.Fatalf("a too-large accept: exit %d", exit)
	}
}

// What the fake bridge.activate answers, set by the test between commands: the preview to a call with no digest; to a
// confirmation, pending approvals first, then a refusal or the filing.
type testUrBridgeActivate struct {
	stateLock   sync.Mutex
	preview     *sidecar.DaemonBridgeSharePreview
	refusal     error
	pending     int
	approvalId  sidecar.Id
	activations int
}

func (self *testUrBridgeActivate) set(update func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	update()
}

func (self *testUrBridgeActivate) answer(params *sidecar.DaemonBridgeActivateParams) (any, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if params.PreviewDigest == "" {
		return self.preview, nil
	}
	self.activations += 1
	if 0 < self.pending {
		self.pending -= 1
		approvalId := self.approvalId
		return &sidecar.DaemonBridgeFilingReply{ApprovalPendingId: &approvalId}, nil
	}
	if self.refusal != nil {
		return nil, self.refusal
	}
	approvalId := self.approvalId
	return &sidecar.DaemonBridgeFilingReply{GrantId: "0a0b0c0d", ApprovalId: &approvalId}, nil
}

// ur bridge activate (QD-831): with a terminal to ask on, it reads the share by a confirmed call, shows it on the
// terminal and not on stdout (the other network, each target with its alias, the ShareKey's fingerprint and both
// tables' hashes), asks, and only on a yes sends the confirmed activation carrying the preview's digest, waiting out
// an approval as the bridge's other filings do. A declined prompt activates nothing. A share id out of form, or a
// caller with no terminal, is refused before the daemon is called. A share not yet accepted, or refused, is shown and
// not asked about. A refused activation prints the filer's reason.
func TestUrBridgeActivateShowsTheShareThenAsks(t *testing.T) {
	waits := setTestUrBridgeWait(t, defaultUrBridgeSettings())
	daemon := &testUrBridgeDaemon{}
	activate := &testUrBridgeActivate{approvalId: sidecar.NewId()}
	shareId, accepting, host := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	targetSha256, aliasSha256 := strings.Repeat("1a", 32), strings.Repeat("2b", 32)
	fingerprint := "5c5c 0a0b 0c0d 0e0f 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627"
	digest := strings.Repeat("3c", 32)
	active := &sidecar.DaemonBridgeSharePreview{
		ShareId: shareId, AcceptingNetworkId: &accepting, Status: "active",
		Targets: []*sidecar.DaemonBridgeShareTarget{
			{Index: 0, HostSidecarId: host, Prefix: "192.168.7.0/24", Alias: &sidecar.DaemonBridgeShareAlias{Index: 0, HostBits: 0x8100, Length: 24}},
			{Index: 1, HostSidecarId: host, Prefix: "192.168.9.9/32", Protocol: "tcp", Ports: []string{"443", "8000-8080"},
				Alias: &sidecar.DaemonBridgeShareAlias{Index: 1, HostBits: 0x8001, Length: 32}},
		},
		ShareKeyFingerprint: fingerprint,
		TargetTableSha256:   targetSha256, TargetTableVersion: 1, AliasTableSha256: aliasSha256, AliasTableVersion: 1,
		PreviewDigest: digest,
	}
	activate.set(func() { activate.preview = active })
	cli, out, errOut := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodBridgeActivate, true, func(callCount int) (any, error) {
		calls, _ := daemon.calls()
		params := &sidecar.DaemonBridgeActivateParams{}
		if err := json.Unmarshal(calls[len(calls)-1], params); err != nil {
			return nil, err
		}
		return activate.answer(params)
	}))
	args := []string{"ur", "bridge", "activate", shareId.String()}

	// declined: the preview is the one call, and it is shown on the terminal alone
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if exit := cli.main(context.Background(), args); exit != urExitFailed {
		t.Fatalf("declined: exit %d", exit)
	}
	calls, confirmed := daemon.calls()
	if len(calls) != 1 || !confirmed[0] {
		t.Fatalf("declined: %d calls, confirmed %v", len(calls), confirmed)
	}
	asked := &sidecar.DaemonBridgeActivateParams{}
	if err := json.Unmarshal(calls[0], asked); err != nil || asked.ShareId != shareId || asked.PreviewDigest != "" {
		t.Fatalf("the preview's params: %+v, %v", asked, err)
	}
	shown := tty.written.String()
	for _, want := range []string{
		"share      " + shareId.String(), "network    " + accepting.String() + " accepted the invite",
		"target 0   192.168.7.0/24, every protocol on host " + host.String() + ", alias .129.0/24 of that network's block",
		"target 1   192.168.9.9/32 tcp 443,8000-8080 on host " + host.String() + ", alias .128.1/32 of that network's block",
		"share key  " + fingerprint, "targets    sha256 " + targetSha256 + ", version 1", "aliases    sha256 " + aliasSha256 + ", version 1",
		"Activate this share? Network " + accepting.String(),
	} {
		if !strings.Contains(shown, want) {
			t.Fatalf("the terminal lacks %q:\n%s", want, shown)
		}
	}
	if printed := out.String(); strings.Contains(printed, targetSha256) || strings.Contains(printed, fingerprint) || strings.Contains(printed, "activated") {
		t.Fatalf("stdout carried the preview or an activation: %s", printed)
	}
	if !strings.Contains(errOut.String(), "not confirmed") {
		t.Fatalf("stderr: %s", errOut.String())
	}

	// a share id out of form, and a caller with no terminal, are refused before the daemon is called
	cli.openTty = func() (urTty, error) { t.Fatal("asked"); return nil, nil }
	if exit := cli.main(context.Background(), []string{"ur", "bridge", "activate", "not-a-share"}); exit == urExitOk {
		t.Fatal("a share id out of form ran")
	}
	cli.openTty = func() (urTty, error) { return nil, errors.New("no terminal in this test") }
	if exit := cli.main(context.Background(), args); exit != urExitFailed {
		t.Fatalf("no terminal: exit %d", exit)
	}
	if calls, _ := daemon.calls(); len(calls) != 1 {
		t.Fatalf("a refused command called the daemon: %d calls", len(calls))
	}

	// confirmed: the activation sends back the preview's digest, confirmed, and waits out its approval
	activate.set(func() { activate.pending = 1 })
	out.Reset()
	tty = &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if exit := cli.main(context.Background(), args); exit != urExitOk {
		t.Fatalf("confirmed: exit %d, stderr %s", exit, errOut.String())
	}
	calls, confirmed = daemon.calls()
	if len(calls) != 4 || !confirmed[1] || !confirmed[2] || !confirmed[3] {
		t.Fatalf("confirmed: %d calls, confirmed %v", len(calls), confirmed)
	}
	for _, call := range calls[2:] {
		sent := &sidecar.DaemonBridgeActivateParams{}
		if err := json.Unmarshal(call, sent); err != nil || sent.ShareId != shareId || sent.PreviewDigest != digest {
			t.Fatalf("the activation's params: %+v, %v", sent, err)
		}
	}
	printed := out.String()
	if !strings.Contains(printed, "ur approve "+activate.approvalId.String()) || !strings.Contains(printed, "activated  share "+shareId.String()) ||
		!strings.Contains(printed, "grant 0a0b0c0d") || *waits != 1 {
		t.Fatalf("the activation's answer (%d waits): %s", *waits, printed)
	}

	// a refused activation prints the filer's reason
	activate.set(func() {
		activate.refusal = errors.New("bridge filing refused: bridge share table is not the one pinned: the share changed after it was shown")
	})
	errOut.Reset()
	tty = &testTty{lines: []string{"y"}}
	if exit := cli.main(context.Background(), args); exit != urExitFailed {
		t.Fatalf("a refused activation: exit %d", exit)
	}
	if refused := errOut.String(); !strings.Contains(refused, "the share was not activated") || !strings.Contains(refused, "the share changed after it was shown") {
		t.Fatalf("a refused activation's stderr: %s", refused)
	}

	// a share not yet accepted, or refused, is shown and not asked about
	for _, preview := range []*sidecar.DaemonBridgeSharePreview{
		{ShareId: shareId, Targets: active.Targets[:1], TargetTableSha256: targetSha256, TargetTableVersion: 1, PreviewDigest: digest},
		{ShareId: shareId, AcceptingNetworkId: &accepting, Status: "refused_no_space", Targets: active.Targets[:1], TargetTableSha256: targetSha256,
			TargetTableVersion: 1, AliasTableSha256: aliasSha256, AliasTableVersion: 1, RefusedIndex: 0, RefusedLength: 24, PreviewDigest: digest},
	} {
		activate.set(func() { activate.preview = preview })
		before, _ := daemon.calls()
		tty = &testTty{lines: []string{"y"}}
		if exit := cli.main(context.Background(), args); exit != urExitFailed {
			t.Fatalf("status %q: exit %d", preview.Status, exit)
		}
		after, _ := daemon.calls()
		if len(after) != len(before)+1 || strings.Contains(tty.written.String(), "Activate this share?") || len(tty.lines) != 1 {
			t.Fatalf("status %q was asked about or activated", preview.Status)
		}
	}
}
