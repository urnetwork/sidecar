// ur bridge (§17.11; BRIDGE-M4-20): the network's bridge from the terminal. The bridge lives in the daemon, as a
// socket does, so each command returns once the daemon holds what it asked for.
//
//	ur bridge [--network=<name>]              lists the bridge: addresses, private names, rules and forwards, with
//	                                          pinned and unpinned counts, what it waits on, a shared block and
//	                                          carved overlaps (§17.17)
//	ur bridge expose <ranges>...              advertises this host's subnets, a route; 0.0.0.0/0 alone is its exit
//	ur bridge expose :<port>[=<ip>:<port>]    maps a port of this host's overlay address, to 127.0.0.1 unless an
//	                                          address is given; --udp for UDP
//	ur bridge forward <client>:<port>[:<local ip>]:<local port>
//	                                          listens locally and dials the client's port over the userspace stack,
//	                                          on every interface unless a local ip or --listen narrows it (owner
//	                                          decision 84); it serves every host that reaches the listener
//	ur bridge close <id>                      ends a forward, or withdraws a rule or revokes a grant by its id
//	ur bridge egress auto|<exit>[,<exit>]|tag:<t>|none
//	                                          this device's default route; a person's confirmation
//	ur bridge block [cycle|<cidr>]            shows the network's block, or re-rolls or chooses it, an admin's; a
//	                                          person's confirmation
//
// Without an active grant, expose and forward print the approval prompt and wait: the command asks the daemon again
// until the decision lands or the wait runs out (§16.6). close is a reading: §17.11 names no spelling for ending a
// forward or a rule, and bridge_close is its MCP twin. Readable addresses reach the person's terminal only; the
// daemon's logs name opaque ids alone (I-13). `ur bridge public-tls` is §13's (bridge_public_tls_cmd.go), and invite and
// accept-invite are BRIDGE-M6-03's.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// Tunables of ur bridge.
type urBridgeSettings struct {
	// How long a command waiting on an approval lets pass before it asks the daemon again: 2 s.
	ApprovalPollInterval time.Duration
	// How long it waits in all before it gives up, leaving the request for a later run: 10 min.
	ApprovalWaitTimeout time.Duration
}

// The values above.
func defaultUrBridgeSettings() *urBridgeSettings {
	return &urBridgeSettings{
		ApprovalPollInterval: 2 * time.Second,
		ApprovalWaitTimeout:  10 * time.Minute,
	}
}

// ur bridge's settings, and how it lets an interval pass, which a test replaces.
var (
	urBridgeCommandSettings = defaultUrBridgeSettings()
	urBridgeWait            = func(ctx context.Context, timeout time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return nil
		}
	}
)

// A command line ur bridge cannot take.
var errUrBridgeUsage = errors.New("ur bridge: see ur bridge --help")

func init() {
	registerUrCommand(&urCommand{
		name: "bridge",
		usage: strings.Join(append([]string{
			"  ur bridge [--network=<name>]",
			"  ur bridge expose <ranges>... [--udp] [--remap] [--network=<name>]",
			"  ur bridge forward <spec> [--listen=<ip>] [--udp] [--network=<name>]",
			"  ur bridge close <id> [--reset] [--network=<name>]",
			"  ur bridge egress <egress> [--network=<name>]",
			"  ur bridge block [<block>] [--network=<name>]",
		}, urBridgePublicTlsUsage...), "\n"),
		summary: "list the network's bridge, expose subnets and ports, forward a client's port",
		run:     runUrBridge,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urBridgeMethods)
}

func runUrBridge(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	udp, _ := options.Bool("--udp")
	protocol := ""
	if udp {
		protocol = "udp"
	}
	switch {
	case options["public-tls"] == true:
		// §13's (bridge_public_tls_cmd.go)
		return runUrBridgePublicTls(ctx, cli, options)
	case options["expose"] == true:
		ranges, _ := options["<ranges>"].([]string)
		remap, _ := options.Bool("--remap")
		params, err := parseUrBridgeExpose(ranges, protocol, remap)
		if err != nil {
			return err
		}
		params.Network = network
		return runUrBridgeExpose(ctx, cli, params)
	case options["forward"] == true:
		spec, _ := options.String("<spec>")
		listen, _ := options.String("--listen")
		params, err := parseUrBridgeForward(spec, listen, protocol)
		if err != nil {
			return err
		}
		params.Network = network
		return runUrBridgeForward(ctx, cli, params)
	case options["close"] == true:
		id, _ := options.String("<id>")
		reset, _ := options.Bool("--reset")
		return runUrBridgeClose(ctx, cli, &sidecar.DaemonBridgeCloseParams{Network: network, Id: id, Reset: reset})
	case options["egress"] == true:
		spec, _ := options.String("<egress>")
		params, err := parseUrBridgeEgress(spec)
		if err != nil {
			return err
		}
		params.Network = network
		return runUrBridgeEgress(ctx, cli, spec, params)
	case options["block"] == true:
		block, _ := options.String("<block>")
		return runUrBridgeBlock(ctx, cli, network, block)
	}
	return runUrBridgeStatus(ctx, cli, network)
}

// A port from 1 to 65535.
func parseUrBridgePort(text string) (uint32, error) {
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%q is not a port", text)
	}
	return uint32(port), nil
}

// expose's arguments as the daemon's params: one :<port>[=<ip>:<port>] is a map, anything else subnets, and
// 0.0.0.0/0 alone the exit.
func parseUrBridgeExpose(ranges []string, protocol string, remap bool) (*sidecar.DaemonBridgeExposeParams, error) {
	if len(ranges) == 0 {
		return nil, errUrBridgeUsage
	}
	if strings.HasPrefix(ranges[0], ":") {
		if 1 < len(ranges) || remap {
			return nil, errors.New("ur bridge expose maps one port at a time")
		}
		portText, targetText, hasTarget := strings.Cut(strings.TrimPrefix(ranges[0], ":"), "=")
		port, err := parseUrBridgePort(portText)
		if err != nil {
			return nil, err
		}
		params := &sidecar.DaemonBridgeExposeParams{Port: port, Protocol: protocol}
		if hasTarget {
			target, err := netip.ParseAddrPort(targetText)
			if err != nil || target.Port() == 0 {
				return nil, fmt.Errorf("%q is not <ip>:<port>", targetText)
			}
			params.Target = target.Addr().String()
			params.TargetPort = uint32(target.Port())
		}
		return params, nil
	}
	if protocol != "" {
		return nil, errors.New("--udp goes with a port: a route carries every protocol")
	}
	params := &sidecar.DaemonBridgeExposeParams{Remap: remap}
	for _, text := range ranges {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 range like 10.1.0.0/24", text)
		}
		if prefix.Bits() == 0 {
			if 1 < len(ranges) || remap {
				return nil, errors.New("0.0.0.0/0 is this host's exit, advertised alone")
			}
			return &sidecar.DaemonBridgeExposeParams{Exit: true}, nil
		}
		params.Prefixes = append(params.Prefixes, prefix.Masked().String())
	}
	return params, nil
}

// forward's <client>:<port>[:<local ip>]:<local port> as the daemon's params. An IPv6 local ip is bracketed. A local
// ip and --listen both narrow the listener, and must agree when both are given.
func parseUrBridgeForward(spec string, listen string, protocol string) (*sidecar.DaemonBridgeForwardParams, error) {
	malformed := fmt.Errorf("%q is not <client>:<port>[:<local ip>]:<local port>", spec)
	target, rest, ok := strings.Cut(spec, ":")
	if !ok || target == "" {
		return nil, malformed
	}
	portText, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return nil, malformed
	}
	port, err := parseUrBridgePort(portText)
	if err != nil {
		return nil, malformed
	}
	localIp := ""
	localPortText := rest
	if at := strings.LastIndex(rest, ":"); 0 <= at {
		localIp = strings.TrimSuffix(strings.TrimPrefix(rest[:at], "["), "]")
		localPortText = rest[at+1:]
	}
	localPort, err := parseUrBridgePort(localPortText)
	if err != nil {
		return nil, malformed
	}
	params := &sidecar.DaemonBridgeForwardParams{Target: target, Port: port, Protocol: protocol, LocalPort: localPort}
	for _, text := range []string{localIp, listen} {
		if text == "" {
			continue
		}
		address, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("%q is not an ip to listen on", text)
		}
		if 0 < len(params.Listen) && params.Listen[0] != address.String() {
			return nil, errors.New("the local ip and --listen name different addresses")
		}
		params.Listen = []string{address.String()}
	}
	return params, nil
}

// egress's auto|<exit>[,<exit>]|tag:<t>|none as the daemon's params.
func parseUrBridgeEgress(spec string) (*sidecar.DaemonBridgeEgressParams, error) {
	switch {
	case spec == "":
		return nil, errUrBridgeUsage
	case spec == "auto" || spec == "none" || strings.HasPrefix(spec, "tag:"):
		return &sidecar.DaemonBridgeEgressParams{Mode: spec}, nil
	}
	params := &sidecar.DaemonBridgeEgressParams{}
	for _, exit := range strings.Split(spec, ",") {
		if exit == "" {
			return nil, fmt.Errorf("%q names an empty exit", spec)
		}
		params.Exits = append(params.Exits, exit)
	}
	return params, nil
}

// Calls a filing method, and while it answers an approval to wait on, prints the prompt once and asks again each
// ApprovalPollInterval until the decision lands or ApprovalWaitTimeout has passed (§16.6). The gate answers a
// decided use from its record, so asking again files nothing twice.
func callUrBridgeFiling(ctx context.Context, cli *urCli, method string, params any, confirmed bool) (*sidecar.DaemonBridgeFilingReply, error) {
	settings := urBridgeCommandSettings
	waited := time.Duration(0)
	prompted := false
	for {
		reply := &sidecar.DaemonBridgeFilingReply{}
		if err := cli.callDaemon(ctx, method, params, confirmed, reply); err != nil {
			return nil, err
		}
		if reply.ApprovalPendingId == nil {
			return reply, nil
		}
		if !prompted {
			cli.printf("approval pending: run ur approve %s on an approval-capable device; waiting\n", reply.ApprovalPendingId)
			prompted = true
		}
		if settings.ApprovalWaitTimeout <= waited {
			return nil, &urExitError{code: urExitFailed, err: fmt.Errorf("approval %s is still pending: run this again once it is decided", reply.ApprovalPendingId)}
		}
		if err := urBridgeWait(ctx, settings.ApprovalPollInterval); err != nil {
			return nil, err
		}
		waited += max(settings.ApprovalPollInterval, time.Millisecond)
	}
}

func runUrBridgeExpose(ctx context.Context, cli *urCli, params *sidecar.DaemonBridgeExposeParams) error {
	reply, err := callUrBridgeFiling(ctx, cli, sidecar.DaemonMethodBridgeExpose, params, false)
	if err != nil {
		return err
	}
	switch {
	case 0 < params.Port && reply.Address != "":
		cli.printf("exposed    %s:%d, rule %s\n", reply.Address, params.Port, reply.RuleId)
		if reply.AddressFiled {
			cli.printf("address    %s, claimed for this host\n", reply.Address)
		}
	case 0 < params.Port:
		cli.printf("exposed    port %d, rule %s\n", params.Port, reply.RuleId)
	case params.Exit:
		cli.printf("exposed    this host as an exit, rule %s\n", reply.RuleId)
	default:
		cli.printf("exposed    %s, rule %s\n", strings.Join(params.Prefixes, ", "), reply.RuleId)
	}
	cli.printf("ur bridge close %s withdraws it\n", reply.RuleId)
	return nil
}

func runUrBridgeForward(ctx context.Context, cli *urCli, params *sidecar.DaemonBridgeForwardParams) error {
	reply, err := callUrBridgeFiling(ctx, cli, sidecar.DaemonMethodBridgeForward, params, false)
	if err != nil {
		return err
	}
	if reply.Forward == nil {
		return errors.New("the daemon answered no forward")
	}
	cli.printf("%s\n", formatUrBridgeForward(reply.Forward))
	if reply.Forward.LanExposed {
		cli.printf("warning: this forward serves every host that reaches the listener, not this machine alone; " +
			"--listen=127.0.0.1 keeps it here\n")
	}
	cli.printf("the daemon holds the forward until its grant ends: ur bridge close %s ends it\n", reply.Forward.ForwardId)
	return nil
}

func runUrBridgeClose(ctx context.Context, cli *urCli, params *sidecar.DaemonBridgeCloseParams) error {
	reply := &sidecar.DaemonBridgeFilingReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeClose, params, false, reply); err != nil {
		return err
	}
	switch {
	case reply.ForwardClosed:
		cli.printf("closed     forward %s; its grant stays until it ends or is revoked\n", params.Id)
	case reply.GrantId != "":
		cli.printf("revoked    grant %s\n", reply.GrantId)
	default:
		cli.printf("withdrawn  rule %s\n", reply.RuleId)
	}
	return nil
}

func runUrBridgeEgress(ctx context.Context, cli *urCli, spec string, params *sidecar.DaemonBridgeEgressParams) error {
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Set this device's default route to %s?", spec))
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: errors.New("not confirmed: the egress stays as it is")}
	}
	if _, err := callUrBridgeFiling(ctx, cli, sidecar.DaemonMethodBridgeEgress, params, true); err != nil {
		return err
	}
	cli.printf("egress     %s\n", spec)
	return nil
}

func runUrBridgeBlock(ctx context.Context, cli *urCli, network string, block string) error {
	if block == "" {
		reply := &sidecar.DaemonBridgeStatusReply{}
		if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeStatus, &sidecar.DaemonBridgeStatusParams{Network: network}, false, reply); err != nil {
			return err
		}
		printUrBridgeBlock(cli, reply.List)
		return nil
	}
	question := fmt.Sprintf("Move the network to the block %s? Every address in the block in force changes.", block)
	if block == "cycle" {
		question = "Re-roll the network's block? Every address in the block in force changes."
	} else if prefix, err := netip.ParsePrefix(block); err != nil || !prefix.Addr().Is4() || prefix.Bits() != 16 {
		return fmt.Errorf("%q is not cycle or a /16 like 100.80.0.0/16", block)
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: errors.New("not confirmed: the block stays as it is")}
	}
	reply, err := callUrBridgeFiling(ctx, cli, sidecar.DaemonMethodBridgeBlock, &sidecar.DaemonBridgeBlockParams{Network: network, Block: block}, true)
	if err != nil {
		return err
	}
	cli.printf("block      %s\n", reply.Block)
	if reply.PreviousBlock != "" {
		cli.printf("draining   %s\n", reply.PreviousBlock)
	}
	return nil
}

func runUrBridgeStatus(ctx context.Context, cli *urCli, network string) error {
	reply := &sidecar.DaemonBridgeStatusReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeStatus, &sidecar.DaemonBridgeStatusParams{Network: network}, false, reply); err != nil {
		return err
	}
	printUrBridgeStatus(cli, reply)
	return nil
}

// The block lines of a listing.
func printUrBridgeBlock(cli *urCli, list *sidecar.DaemonBridgeList) {
	if list == nil || list.Block == "" {
		cli.printf("  block      none yet: the network's next config head gets one\n")
		return
	}
	cli.printf("  block      %s\n", list.Block)
	if list.PreviousBlock != "" {
		cli.printf("  draining   %s\n", list.PreviousBlock)
	}
	if list.SharedBlock {
		cli.printf("  shared     another network on this host holds the same block: ur bridge block cycle moves this one\n")
	}
}

// One forward as a line: what it listens on, where it dials and how exposed it is.
func formatUrBridgeForward(forward *sidecar.DaemonBridgeForwardStatus) string {
	exposure := "loopback only"
	if forward.LanExposed {
		exposure = "LAN-exposed"
	}
	until := ""
	if 0 < forward.ExpiresMs {
		until = ", until " + time.UnixMilli(forward.ExpiresMs).UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("forward    %s %s to %s:%d (%s), %d open%s, %s", forward.Protocol, strings.Join(forward.LocalAddresses, ", "),
		forward.Target, forward.Port, exposure, forward.ConnCount, until, forward.ForwardId)
}

// Prints the bridge's listing, for the person.
func printUrBridgeStatus(cli *urCli, reply *sidecar.DaemonBridgeStatusReply) {
	list := reply.List
	if list == nil {
		list = &sidecar.DaemonBridgeList{}
	}
	cli.printf("ur bridge: network %s (%s)\n", list.NetworkId, list.State)
	kinds := make([]string, 0, len(list.Waits))
	for kind := range list.Waits {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		switch kind {
		case "state":
			cli.printf("  waiting    for the network's verified bridge state: nothing private routes until then\n")
		case "seal":
			cli.printf("  waiting    %d rules for a key this device does not hold yet\n", list.Waits[kind])
		default:
			cli.printf("  waiting    %d for %s\n", list.Waits[kind], kind)
		}
	}
	printUrBridgeBlock(cli, list)
	if len(list.Addresses) == 0 {
		cli.printf("  address    none: ur tun ip <ip> claims one\n")
	} else {
		cli.printf("  address    %s\n", strings.Join(list.Addresses, ", "))
	}
	for _, name := range list.Names {
		cli.printf("  name       %s %s\n", name.Address, name.Name)
	}
	for _, rule := range list.Rules {
		what := strings.Join(append(append([]string{}, rule.Prefixes...), rule.Ports...), " ")
		owner := rule.Owner.String()
		if rule.Own {
			owner = "this host"
		}
		cli.printf("  %-10s %s by %s (%s), %s\n", rule.Kind, what, owner, rule.State, rule.RuleId)
	}
	cli.printf("  pins       %d pinned, %d routed unpinned\n", list.PinnedCount, list.UnpinnedCount)
	if 0 < list.CarvedOverlapCount {
		cli.printf("  carved     %d local addresses are a host's overlay address, reached on the LAN instead: "+
			"ur bridge block cycle moves the block\n", list.CarvedOverlapCount)
	}
	if 0 < list.RouteConflictCount {
		cli.printf("  conflicts  %d routes overlap a local network, which wins\n", list.RouteConflictCount)
	}
	for _, alarm := range list.Alarms {
		cli.printf("  alarm      %s\n", alarm)
	}
	if list.EgressMode != "" {
		cli.printf("  egress     %s\n", list.EgressMode)
	}
	for _, forward := range reply.Forwards {
		cli.printf("  %s\n", formatUrBridgeForward(forward))
	}
}
