package main

import (
	"context"
	"encoding/json"
	"strings"
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
		Aliases: []*sidecar.DaemonBridgeShareAlias{{Index: 0, HostBits: 0x8001, Length: 32}}}
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
	if printed := out.String(); strings.Contains(printed, code) || !strings.Contains(printed, "target 0 at .128.1/32") || !strings.Contains(printed, "activates it") {
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
