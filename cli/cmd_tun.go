// ur tun (§17.11; BRIDGE-M4-18): the OS tun ur-<instance> for one network's bridge, which lives in the daemon, as a
// socket does, so each command returns once the daemon holds what it asked for, and the daemon stays up while its
// bridge is on (the bridge component is an active one, §5.8).
//
//	ur tun [--network=<name>]                 brings the tun up over the network's bridge: the block and the granted
//	                                          prefixes, and the default route under the egress mode exits, the
//	                                          daemon's own transport kept off it by connect's egress mark (QD-800);
//	                                          it yields to an app's bridge
//	ur tun down                               ends it, removing its routes
//	ur tun ip [<ip> | auto] [--network=<name>]
//	                                          shows this host's overlay address and the block, or claims an address in
//	                                          the block's lower /17, which BridgeFiler.ClaimAddress files; auto waits
//	                                          for §22.9's browsers check (plan-BRIDGE-small-readings #18, QD-424)
//
// down is a reading: §17.11 names no spelling for ending the tun, and the daemon holds it until something ends it.
// Readable addresses and prefixes reach the person's terminal only; the daemon's logs name the network's id alone
// (I-13).

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The tun's control methods.
const (
	urMethodTunUp   = "tun.up"
	urMethodTunDown = "tun.down"
	urMethodTunIp   = "tun.ip"
)

// What ur tun ip takes for an address the daemon picks.
const urTunIpAuto = "auto"

// BridgeFiler.ClaimAddress's call (BRIDGE-M4-19), which files this host's BridgeAddress for an address in the
// network's block: nil until the filer lands, and ur tun ip <ip> refuses.
var urBridgeClaimAddress func(ctx context.Context, running *sidecar.Sidecar, networkId sidecar.Id, address netip.Addr) error

// ur tun ip <ip> before the filer lands.
var errUrTunIpUnfiled = errors.New("claiming an address waits for the bridge's filings (BRIDGE-M4-19)")

// ur tun ip auto while §22.9's check has not passed.
var errUrTunIpAuto = errors.New("ur tun ip auto waits for the check that no browser leaks an overlay address " +
	"through WebRTC; claim one with ur tun ip <ip>")

func init() {
	registerUrCommand(&urCommand{
		name: "tun",
		usage: strings.Join([]string{
			"  ur tun [--network=<name>]",
			"  ur tun down",
			"  ur tun ip [<ip>] [--network=<name>]",
		}, "\n"),
		summary: "carry the network's private addresses through an OS tun (Linux)",
		run:     runUrTun,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urTunMethods)
}

// tun.up's and tun.ip's params: the network argument, and ur tun ip's address, "auto", or empty to show.
type urTunParams struct {
	Network string `json:"network,omitempty"`
	Address string `json:"address,omitempty"`
}

// tun.down's reply.
type urTunDownReply struct {
	// Whether a tun was up.
	Down bool `json:"down"`
}

// tun.ip's reply: the network's block and this host's overlay addresses. Nothing secret.
type urTunIpReply struct {
	NetworkId     sidecar.Id `json:"network_id"`
	Block         string     `json:"block,omitempty"`
	PreviousBlock string     `json:"previous_block,omitempty"`
	Addresses     []string   `json:"addresses,omitempty"`
	// The address claimed, for a claim.
	Claimed string `json:"claimed,omitempty"`
}

// The tun's methods over a target that hosts its networks.
func urTunMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.bridges == nil {
		return nil
	}
	return urTunDaemonMethods(network.bridges)
}

// The tun's methods over bridges.
func urTunDaemonMethods(bridges *urBridgeDaemon) []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodTunUp,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return bridges.tunUp(call.NetworkId, call.Sidecar)
			},
		},
		{
			Name: urMethodTunDown,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return &urTunDownReply{Down: bridges.tunDown()}, nil
			},
		},
		{
			Name:    urMethodTunIp,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urTunParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("tun.ip takes an address, auto, or none")
				}
				return urTunIp(ctx, bridges, call.NetworkId, call.Sidecar, params.Address)
			},
		},
	}
}

// Shows the network's block and this host's overlay addresses, or claims address, "auto" refused while its check has
// not passed. A claim is checked against the block first: in its lower /17, outside <block>.0.0/24, never x.y.z.0 or
// x.y.z.255 (§17.4); the filer checks it against the log.
func urTunIp(ctx context.Context, bridges *urBridgeDaemon, networkId sidecar.Id, running *sidecar.Sidecar, address string) (*urTunIpReply, error) {
	network, err := bridges.bridgeNetwork(networkId, running)
	if err != nil {
		return nil, err
	}
	status := network.bridge.Status()
	reply := &urTunIpReply{NetworkId: networkId}
	if status.Block.IsValid() {
		reply.Block = status.Block.String()
	}
	if status.PreviousBlock.IsValid() {
		reply.PreviousBlock = status.PreviousBlock.String()
	}
	for _, held := range status.Addresses {
		reply.Addresses = append(reply.Addresses, held.String())
	}
	switch address {
	case "":
		return reply, nil
	case urTunIpAuto:
		if network.componentSettings == nil || !network.componentSettings.AutoAddressEnabled {
			return nil, errUrTunIpAuto
		}
		// an assignment the daemon picks is the filer's, which allocates from the log (AllocateBridgeAddress)
		return nil, errUrTunIpUnfiled
	}
	claimed, err := netip.ParseAddr(address)
	if err != nil || !claimed.Is4() {
		return nil, errors.New("ur tun ip takes an IPv4 address, or auto")
	}
	if !status.Block.IsValid() {
		return nil, errors.New("the network has no block yet: its next config head gets one")
	}
	if err := urTunCheckClaim(status.Block, claimed); err != nil {
		return nil, err
	}
	if urBridgeClaimAddress == nil {
		return nil, errUrTunIpUnfiled
	}
	if err := urBridgeClaimAddress(ctx, running, networkId, claimed); err != nil {
		return nil, err
	}
	reply.Claimed = claimed.String()
	return reply, nil
}

// §17.4's shape of a chosen address: in block's lower /17, outside <block>.0.0/24, and never x.y.z.0 or x.y.z.255.
func urTunCheckClaim(block netip.Prefix, address netip.Addr) error {
	block = block.Masked()
	octets := block.Addr().As4()
	lower := netip.PrefixFrom(block.Addr(), block.Bits()+1)
	services := netip.PrefixFrom(netip.AddrFrom4([4]byte{octets[0], octets[1], 0, 0}), 24)
	addressOctets := address.As4()
	switch {
	case !block.Contains(address):
		return fmt.Errorf("%s is not in the network's block %s", address, block)
	case !lower.Contains(address):
		return fmt.Errorf("a chosen address lies in the block's lower half, %s", lower)
	case services.Contains(address):
		return fmt.Errorf("%s holds the network's services: choose another", services)
	case addressOctets[3] == 0 || addressOctets[3] == 255:
		return errors.New("an address never ends in .0 or .255")
	}
	return nil
}

func runUrTun(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	switch {
	case options["down"] == true:
		return runUrTunDown(ctx, cli)
	case options["ip"] == true:
		address, _ := options.String("<ip>")
		return runUrTunIp(ctx, cli, network, address)
	}
	return runUrTunUp(ctx, cli, network)
}

// Asks the daemon to bring the tun up and prints what it carries.
func runUrTunUp(ctx context.Context, cli *urCli, network string) error {
	// the daemon is this binary on this host, so a platform with no tun refuses before one is spawned
	if urTunPlatform == nil {
		return errUrTunPlatform
	}
	status := &urTunStatus{}
	if err := cli.callDaemon(ctx, urMethodTunUp, &urTunParams{Network: network}, false, status); err != nil {
		return err
	}
	printUrTunStatus(cli, status)
	return nil
}

// Asks the daemon to end the tun.
func runUrTunDown(ctx context.Context, cli *urCli) error {
	reply := &urTunDownReply{}
	if err := cli.callDaemon(ctx, urMethodTunDown, nil, false, reply); err != nil {
		return err
	}
	if reply.Down {
		cli.printf("ur tun: down, its routes removed\n")
	} else {
		cli.printf("ur tun: was not up\n")
	}
	return nil
}

// Shows or claims this host's overlay address.
func runUrTunIp(ctx context.Context, cli *urCli, network string, address string) error {
	reply := &urTunIpReply{}
	if err := cli.callDaemon(ctx, urMethodTunIp, &urTunParams{Network: network, Address: address}, false, reply); err != nil {
		return err
	}
	if reply.Block == "" {
		cli.printf("block      none yet: the network's next config head gets one\n")
	} else {
		cli.printf("block      %s\n", reply.Block)
	}
	if reply.PreviousBlock != "" {
		cli.printf("draining   %s\n", reply.PreviousBlock)
	}
	switch {
	case reply.Claimed != "":
		cli.printf("claimed    %s, the first claim in the log wins\n", reply.Claimed)
	case len(reply.Addresses) == 0:
		cli.printf("address    none: ur tun ip <ip> claims one\n")
	default:
		cli.printf("address    %s\n", strings.Join(reply.Addresses, ", "))
	}
	return nil
}

// Prints what the tun carries, for the person.
func printUrTunStatus(cli *urCli, status *urTunStatus) {
	cli.printf("ur tun: %s carries network %s (%s)\n", status.Device, status.NetworkId, status.State)
	for _, wait := range status.Waits {
		switch wait {
		case "state":
			cli.printf("  waiting    for the network's verified bridge state: nothing private routes until then\n")
		default:
			cli.printf("  waiting    for %s\n", wait)
		}
	}
	if status.Block != "" {
		cli.printf("  block      %s\n", status.Block)
	}
	if status.PreviousBlock != "" {
		cli.printf("  draining   %s\n", status.PreviousBlock)
	}
	if len(status.Addresses) == 0 {
		cli.printf("  address    none: ur tun ip <ip> claims one\n")
	} else {
		cli.printf("  address    %s\n", strings.Join(status.Addresses, ", "))
	}
	cli.printf("  routes     %d\n", len(status.Routes))
	for _, route := range status.Routes {
		cli.printf("             %s\n", route)
	}
	if 0 < status.RouteConflictCount {
		cli.printf("  conflicts  %d routes another interface holds at the same prefix, left to it\n", status.RouteConflictCount)
	}
	switch {
	case status.Resolver == "":
	case status.ResolverStep == "":
		cli.printf("  names      %s through %s\n", strings.Join(status.Zones, ", "), status.Resolver)
	default:
		cli.printf("  names      not set on this host's resolver; %s\n", status.ResolverStep)
	}
	cli.printf("  egress     %s\n", status.EgressMode)
	switch {
	case status.DefaultRoute:
		cli.printf("  exits      the default route rides ur tun to the network's exits; the daemon's own transport " +
			"keeps today's route by its mark\n")
	case status.ExitsHeld && status.ExitsHeldReason != "":
		cli.printf("  exits      held: %s; other traffic keeps today's route, and ur tun tries again\n", status.ExitsHeldReason)
	case status.ExitsHeld:
		cli.printf("  exits      held: other traffic keeps today's route, and ur tun tries again\n")
	}
	if status.SyncError != "" {
		cli.printf("  error      %s, tried again\n", status.SyncError)
	}
}
