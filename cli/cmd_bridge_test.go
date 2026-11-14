// ur bridge's command lines, its approval wait and its confirmations, on a daemon whose bridge methods a test answers.

package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A daemon's bridge method answering with answer, recording each call's params and whether it came confirmed.
type testUrBridgeDaemon struct {
	stateLock sync.Mutex
	params    []json.RawMessage
	confirmed []bool
}

func (self *testUrBridgeDaemon) method(name string, confirm bool, answer func(callCount int) (any, error)) *sidecar.DaemonMethod {
	return &sidecar.DaemonMethod{
		Name:    name,
		Confirm: confirm,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			callCount := func() int {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.params = append(self.params, call.Params)
				self.confirmed = append(self.confirmed, call.Confirmed)
				return len(self.params)
			}()
			return answer(callCount)
		},
	}
}

func (self *testUrBridgeDaemon) calls() ([]json.RawMessage, []bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]json.RawMessage{}, self.params...), append([]bool{}, self.confirmed...)
}

// Replaces ur bridge's wait with one that counts and returns at once, for the test.
func setTestUrBridgeWait(t *testing.T, settings *urBridgeSettings) *int {
	t.Helper()
	waits := 0
	previousWait, previousSettings := urBridgeWait, urBridgeCommandSettings
	urBridgeWait = func(ctx context.Context, timeout time.Duration) error {
		waits += 1
		return nil
	}
	urBridgeCommandSettings = settings
	t.Cleanup(func() {
		urBridgeWait, urBridgeCommandSettings = previousWait, previousSettings
	})
	return &waits
}

// expose's forms: subnets are a route, 0.0.0.0/0 alone the exit, and :<port>[=<ip>:<port>] a map.
func TestUrBridgeExposeParsesEachForm(t *testing.T) {
	route, err := parseUrBridgeExpose([]string{"10.1.2.3/24", "192.168.0.0/16"}, "", true)
	if err != nil || !reflect.DeepEqual(route, &sidecar.DaemonBridgeExposeParams{Prefixes: []string{"10.1.2.0/24", "192.168.0.0/16"}, Remap: true}) {
		t.Fatalf("a route: %+v, %v", route, err)
	}
	exit, err := parseUrBridgeExpose([]string{"0.0.0.0/0"}, "", false)
	if err != nil || !reflect.DeepEqual(exit, &sidecar.DaemonBridgeExposeParams{Exit: true}) {
		t.Fatalf("an exit: %+v, %v", exit, err)
	}
	port, err := parseUrBridgeExpose([]string{":5432"}, "", false)
	if err != nil || !reflect.DeepEqual(port, &sidecar.DaemonBridgeExposeParams{Port: 5432}) {
		t.Fatalf("a port: %+v, %v", port, err)
	}
	mapped, err := parseUrBridgeExpose([]string{":53=10.0.0.7:5353"}, "udp", false)
	if err != nil || !reflect.DeepEqual(mapped, &sidecar.DaemonBridgeExposeParams{Port: 53, Protocol: "udp", Target: "10.0.0.7", TargetPort: 5353}) {
		t.Fatalf("a map: %+v, %v", mapped, err)
	}
	for name, ranges := range map[string][]string{
		"nothing":             {},
		"two ports":           {":80", ":81"},
		"port zero":           {":0"},
		"a target's name":     {":80=localhost:80"},
		"a target's port":     {":80=10.0.0.1"},
		"an ipv6 range":       {"fd00::/8"},
		"an exit and a range": {"0.0.0.0/0", "10.0.0.0/8"},
		"a bare address":      {"10.0.0.1"},
	} {
		if _, err := parseUrBridgeExpose(ranges, "", false); err == nil {
			t.Fatalf("%s parsed", name)
		}
	}
	if _, err := parseUrBridgeExpose([]string{"10.0.0.0/8"}, "udp", false); err == nil {
		t.Fatal("--udp with a route parsed")
	}
}

// forward's <client>:<port>[:<local ip>]:<local port>, with --listen narrowing as a local ip does.
func TestUrBridgeForwardParsesItsSpec(t *testing.T) {
	plain, err := parseUrBridgeForward("peer:5432:15432", "", "")
	if err != nil || !reflect.DeepEqual(plain, &sidecar.DaemonBridgeForwardParams{Target: "peer", Port: 5432, LocalPort: 15432}) {
		t.Fatalf("the short form: %+v, %v", plain, err)
	}
	local, err := parseUrBridgeForward("peer:53:127.0.0.1:5353", "", "udp")
	if err != nil || !reflect.DeepEqual(local, &sidecar.DaemonBridgeForwardParams{Target: "peer", Port: 53, Protocol: "udp", LocalPort: 5353, Listen: []string{"127.0.0.1"}}) {
		t.Fatalf("a local ip: %+v, %v", local, err)
	}
	bracketed, err := parseUrBridgeForward("peer:22:[::1]:2222", "", "")
	if err != nil || len(bracketed.Listen) != 1 || bracketed.Listen[0] != "::1" || bracketed.LocalPort != 2222 {
		t.Fatalf("an ipv6 local ip: %+v, %v", bracketed, err)
	}
	listen, err := parseUrBridgeForward("peer:22:2222", "127.0.0.1", "")
	if err != nil || len(listen.Listen) != 1 || listen.Listen[0] != "127.0.0.1" {
		t.Fatalf("--listen: %+v, %v", listen, err)
	}
	if both, err := parseUrBridgeForward("peer:22:127.0.0.1:2222", "127.0.0.1", ""); err != nil || len(both.Listen) != 1 {
		t.Fatalf("a local ip and the same --listen: %+v, %v", both, err)
	}
	for name, attempt := range map[string][2]string{
		"no ports":             {"peer", ""},
		"one port":             {"peer:22", ""},
		"no client":            {":22:2222", ""},
		"a port's name":        {"peer:ssh:2222", ""},
		"a local port's name":  {"peer:22:ssh", ""},
		"a local name":         {"peer:22:localhost:2222", ""},
		"--listen a name":      {"peer:22:2222", "localhost"},
		"two listen addresses": {"peer:22:127.0.0.1:2222", "127.0.0.2"},
	} {
		if _, err := parseUrBridgeForward(attempt[0], attempt[1], ""); err == nil {
			t.Fatalf("%s parsed", name)
		}
	}
}

// egress's forms.
func TestUrBridgeEgressParsesEachForm(t *testing.T) {
	for spec, want := range map[string]*sidecar.DaemonBridgeEgressParams{
		"auto":        {Mode: "auto"},
		"none":        {Mode: "none"},
		"tag:exits":   {Mode: "tag:exits"},
		"exit1":       {Exits: []string{"exit1"}},
		"exit1,exit2": {Exits: []string{"exit1", "exit2"}},
	} {
		if got, err := parseUrBridgeEgress(spec); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v, %v", spec, got, err)
		}
	}
	for _, spec := range []string{"", "exit1,,exit2", ","} {
		if _, err := parseUrBridgeEgress(spec); err == nil {
			t.Fatalf("%q parsed", spec)
		}
	}
}

// Without an active grant a forward prints the approval prompt once and waits, asking the daemon again, then proceeds
// on the decision: it prints the listener, LAN-exposed with the warning that it serves every host reaching it
// (§16.6, D-BRIDGE-10).
func TestUrBridgeForwardPrintsThePromptWaitsThenProceeds(t *testing.T) {
	waits := setTestUrBridgeWait(t, &urBridgeSettings{ApprovalPollInterval: time.Second, ApprovalWaitTimeout: time.Minute})
	daemon := &testUrBridgeDaemon{}
	approvalId := sidecar.NewId()
	target := sidecar.NewId()
	cli, out, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodBridgeForward, false, func(callCount int) (any, error) {
		if callCount < 3 {
			return &sidecar.DaemonBridgeFilingReply{ApprovalPendingId: &approvalId}, nil
		}
		return &sidecar.DaemonBridgeFilingReply{GrantId: "0a0b", Forward: &sidecar.DaemonBridgeForwardStatus{
			ForwardId: "f00d", Target: target, Protocol: "tcp", Port: 5432, LocalPort: 15432,
			LocalAddresses: []string{"0.0.0.0:15432", "[::]:15432"}, LanExposed: true,
		}}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "bridge", "forward", "peer:5432:15432", "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	printed := out.String()
	if strings.Count(printed, "approval pending: run ur approve "+approvalId.String()) != 1 {
		t.Fatalf("the prompt, once: %s", printed)
	}
	if *waits != 2 {
		t.Fatalf("%d waits", *waits)
	}
	for _, want := range []string{"0.0.0.0:15432, [::]:15432", "LAN-exposed", "warning: this forward serves every host that reaches the listener", "ur bridge close f00d"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in: %s", want, printed)
		}
	}
	calls, confirmed := daemon.calls()
	if len(calls) != 3 || confirmed[0] {
		t.Fatalf("%d calls, confirmed %v", len(calls), confirmed)
	}
	params := &sidecar.DaemonBridgeForwardParams{}
	if err := json.Unmarshal(calls[2], params); err != nil || params.Network != "acme" || params.Target != "peer" || params.Port != 5432 || params.LocalPort != 15432 || len(params.Listen) != 0 {
		t.Fatalf("the params: %+v, %v", params, err)
	}
}

// A forward narrowed to loopback prints no warning; an approval still pending when the wait runs out exits 1, naming
// it, with nothing forwarded.
func TestUrBridgeForwardNarrowedAndTheWaitRunningOut(t *testing.T) {
	waits := setTestUrBridgeWait(t, &urBridgeSettings{ApprovalPollInterval: time.Second, ApprovalWaitTimeout: 3 * time.Second})
	daemon := &testUrBridgeDaemon{}
	approvalId := sidecar.NewId()
	pending := false
	cli, out, stderr := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodBridgeForward, false, func(callCount int) (any, error) {
		if pending {
			return &sidecar.DaemonBridgeFilingReply{ApprovalPendingId: &approvalId}, nil
		}
		return &sidecar.DaemonBridgeFilingReply{Forward: &sidecar.DaemonBridgeForwardStatus{ForwardId: "f00d", Protocol: "tcp", Port: 22, LocalAddresses: []string{"127.0.0.1:2222"}}}, nil
	}))
	if code := cli.main(context.Background(), []string{"ur", "bridge", "forward", "peer:22:2222", "--listen=127.0.0.1"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if printed := out.String(); strings.Contains(printed, "warning") || !strings.Contains(printed, "loopback only") {
		t.Fatalf("a narrowed forward: %s", printed)
	}
	calls, _ := daemon.calls()
	params := &sidecar.DaemonBridgeForwardParams{}
	if err := json.Unmarshal(calls[0], params); err != nil || len(params.Listen) != 1 || params.Listen[0] != "127.0.0.1" {
		t.Fatalf("the params: %+v, %v", params, err)
	}
	pending = true
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "forward", "peer:22:2222"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if *waits != 3 || !strings.Contains(stderr.String(), "still pending") || strings.Contains(out.String(), "forward    ") {
		t.Fatalf("%d waits; out %s; err %s", *waits, out.String(), stderr.String())
	}
}

// egress and block ask on the terminal first: an n sends nothing, a yes sends the call confirmed, and block with no
// argument only shows the block.
func TestUrBridgeEgressAndBlockAskForConfirmation(t *testing.T) {
	setTestUrBridgeWait(t, defaultUrBridgeSettings())
	daemon := &testUrBridgeDaemon{}
	cli, out, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodBridgeEgress, true, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeFilingReply{}, nil
		}),
		daemon.method(sidecar.DaemonMethodBridgeBlock, true, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeFilingReply{Block: "100.90.0.0/16", PreviousBlock: "100.80.0.0/16"}, nil
		}),
		daemon.method(sidecar.DaemonMethodBridgeStatus, false, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeStatusReply{List: &sidecar.DaemonBridgeList{Block: "100.80.0.0/16", SharedBlock: true}}, nil
		}),
	)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	for _, args := range [][]string{{"ur", "bridge", "egress", "none"}, {"ur", "bridge", "block", "cycle"}} {
		if code := cli.main(context.Background(), args); code != urExitFailed {
			t.Fatalf("%v unconfirmed: exit %d", args, code)
		}
	}
	if calls, _ := daemon.calls(); len(calls) != 0 {
		t.Fatalf("an unconfirmed command called the daemon %d times", len(calls))
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "bridge", "egress", "tag:exits"}); code != urExitOk {
		t.Fatalf("egress: exit %d", code)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "bridge", "block", "100.90.0.0/16"}); code != urExitOk {
		t.Fatalf("block: exit %d", code)
	}
	calls, confirmed := daemon.calls()
	if len(calls) != 2 || !confirmed[0] || !confirmed[1] {
		t.Fatalf("%d calls, confirmed %v", len(calls), confirmed)
	}
	egress := &sidecar.DaemonBridgeEgressParams{}
	block := &sidecar.DaemonBridgeBlockParams{}
	if err := json.Unmarshal(calls[0], egress); err != nil || egress.Mode != "tag:exits" {
		t.Fatalf("egress params: %+v, %v", egress, err)
	}
	if err := json.Unmarshal(calls[1], block); err != nil || block.Block != "100.90.0.0/16" {
		t.Fatalf("block params: %+v, %v", block, err)
	}
	if printed := out.String(); !strings.Contains(printed, "block      100.90.0.0/16") || !strings.Contains(printed, "draining   100.80.0.0/16") {
		t.Fatalf("the block's answer: %s", printed)
	}
	// a block that is no /16 is refused before any question
	cli.openTty = func() (urTty, error) { t.Fatal("asked"); return nil, nil }
	if code := cli.main(context.Background(), []string{"ur", "bridge", "block", "10.0.0.0/8"}); code == urExitOk {
		t.Fatal("a /8 block")
	}
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "block"}); code != urExitOk {
		t.Fatalf("showing the block: exit %d", code)
	}
	if printed := out.String(); !strings.Contains(printed, "100.80.0.0/16") || !strings.Contains(printed, "another network on this host holds the same block") {
		t.Fatalf("the block shown: %s", printed)
	}
}

// ur bridge prints the listing: addresses, names, rules by id, pin counts, waits, the shared block, carved overlaps
// and forwards; expose and close print what they filed.
func TestUrBridgePrintsTheListingAndItsFilings(t *testing.T) {
	setTestUrBridgeWait(t, defaultUrBridgeSettings())
	daemon := &testUrBridgeDaemon{}
	networkId := sidecar.NewId()
	owner := sidecar.NewId()
	cli, out, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodBridgeStatus, false, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeStatusReply{
				List: &sidecar.DaemonBridgeList{
					NetworkId: networkId, State: "enforcing_doc", Waits: map[string]int{"seal": 2, "state": 1, "link": 3},
					Block: "100.80.0.0/16", PreviousBlock: "100.70.0.0/16", SharedBlock: true,
					Addresses: []string{"100.80.3.9"},
					Names:     []*sidecar.DaemonBridgeName{{Name: "db.acme.internal", Address: "100.80.4.10"}},
					Rules: []*sidecar.DaemonBridgeRule{
						{RuleId: "aa01", Kind: "route", Owner: owner, State: "active", Prefixes: []string{"10.1.0.0/24"}},
						{RuleId: "bb02", Kind: "map", Owner: owner, Own: true, State: "pending", Prefixes: []string{"100.80.3.9/32"}, Ports: []string{"tcp:5432"}},
					},
					PinnedCount: 7, UnpinnedCount: 4, CarvedOverlapCount: 1, RouteConflictCount: 2,
					Alarms: []string{"carved_address"}, EgressMode: "exits",
				},
				Forwards: []*sidecar.DaemonBridgeForwardStatus{{ForwardId: "f00d", Target: owner, Protocol: "udp", Port: 53, LocalAddresses: []string{"127.0.0.1:5353"}, ExpiresMs: 1767323045000}},
			}, nil
		}),
		daemon.method(sidecar.DaemonMethodBridgeExpose, false, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeFilingReply{RuleId: "cc03", Address: "100.80.3.9", AddressFiled: true}, nil
		}),
		daemon.method(sidecar.DaemonMethodBridgeClose, false, func(callCount int) (any, error) {
			return &sidecar.DaemonBridgeFilingReply{ForwardClosed: true}, nil
		}),
	)
	if code := cli.main(context.Background(), []string{"ur", "bridge"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	printed := out.String()
	for _, want := range []string{
		"network " + networkId.String() + " (enforcing_doc)",
		"waiting    for the network's verified bridge state",
		"waiting    2 rules for a key this device does not hold yet",
		"waiting    3 for link",
		"block      100.80.0.0/16", "draining   100.70.0.0/16", "another network on this host holds the same block",
		"address    100.80.3.9", "name       100.80.4.10 db.acme.internal",
		"route      10.1.0.0/24 by " + owner.String() + " (active), aa01",
		"map        100.80.3.9/32 tcp:5432 by this host (pending), bb02",
		"pins       7 pinned, 4 routed unpinned", "carved     1 local addresses", "conflicts  2 routes",
		"alarm      carved_address", "egress     exits",
		"forward    udp 127.0.0.1:5353 to " + owner.String() + ":53 (loopback only), 0 open, until 2026-01-02T03:04:05Z, f00d",
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("no %q in:\n%s", want, printed)
		}
	}
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "expose", ":5432"}); code != urExitOk {
		t.Fatalf("expose: exit %d", code)
	}
	if printed := out.String(); !strings.Contains(printed, "exposed    100.80.3.9:5432, rule cc03") || !strings.Contains(printed, "claimed for this host") {
		t.Fatalf("the exposure: %s", printed)
	}
	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "bridge", "close", "f00d"}); code != urExitOk {
		t.Fatalf("close: exit %d", code)
	}
	if printed := out.String(); !strings.Contains(printed, "closed     forward f00d") {
		t.Fatalf("the close: %s", printed)
	}
}
