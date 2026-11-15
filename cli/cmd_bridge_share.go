// ur bridge invite and ur bridge accept-invite (§17.9, §17.11; BRIDGE-M6-03): a share from the terminal. Both are an
// admin's, and a person's confirmation: each asks on the terminal before it calls the daemon, and the daemon runs
// neither for an agent.
//
//	ur bridge invite <target>...       shares what hosts of this network reach with one other network. A target is
//	                                   <host>=<cidr>[,tcp:<port>[-<port>]|,udp:<port>[-<port>]]: the host by its id,
//	                                   private name or overlay address, and the IPv4 prefix it reaches. Prints the
//	                                   share's id and the invite's code. The code is shown once: this device keeps
//	                                   none, and whoever holds it can accept the invite
//	ur bridge accept-invite <code>     accepts another network's invite: gives each target an alias in this
//	                                   network's block and tells the other network. Prints the aliases, or why
//	                                   there was no room
//
// The other network's admin then activates the share on its side. The code reaches the terminal alone; the daemon's
// logs name opaque ids (I-13).

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The usage lines ur bridge adds for shares.
var urBridgeShareUsage = []string{
	"  ur bridge invite <target>... [--network=<name>]",
	"  ur bridge accept-invite <code> [--network=<name>]",
}

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urBridgeShareMethods)
}

// The share methods of a network's daemon target, beside urBridgeMethods'.
func urBridgeShareMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok {
		return nil
	}
	bridges := network.sharedDaemonBridges()
	if bridges == nil {
		return nil
	}
	return bridges.ShareMethods()
}

// One invite target as typed: <host>=<cidr>[,tcp:<port>[-<port>]|,udp:<port>[-<port>]].
func parseUrBridgeShareTarget(text string) (*sidecar.DaemonBridgeShareTargetParams, error) {
	usage := fmt.Errorf("%q is not a target like laptop=192.168.7.0/24 or laptop=100.80.3.7/32,tcp:443", text)
	spec, ports, hasPorts := strings.Cut(text, ",")
	host, cidr, ok := strings.Cut(spec, "=")
	if !ok || host == "" {
		return nil, usage
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return nil, usage
	}
	target := &sidecar.DaemonBridgeShareTargetParams{Host: host, Prefix: prefix.Masked().String()}
	if !hasPorts {
		return target, nil
	}
	protocol, portRange, ok := strings.Cut(ports, ":")
	if !ok || (protocol != "tcp" && protocol != "udp") {
		return nil, usage
	}
	first, last, ranged := strings.Cut(portRange, "-")
	firstPort, err := parseUrBridgePort(first)
	if err != nil {
		return nil, usage
	}
	lastPort := firstPort
	if ranged {
		if lastPort, err = parseUrBridgePort(last); err != nil || lastPort < firstPort {
			return nil, usage
		}
	}
	target.Protocol, target.FirstPort, target.LastPort = protocol, uint32(firstPort), uint32(lastPort)
	return target, nil
}

func runUrBridgeInvite(ctx context.Context, cli *urCli, network string, targets []string) error {
	params := &sidecar.DaemonBridgeInviteParams{Network: network}
	for _, text := range targets {
		target, err := parseUrBridgeShareTarget(text)
		if err != nil {
			return err
		}
		params.Targets = append(params.Targets, target)
	}
	if len(params.Targets) == 0 {
		return errUrBridgeUsage
	}
	question := fmt.Sprintf("Invite one other network to reach %s? Its admin sees these addresses, and reaches them once you activate the share.", strings.Join(targets, ", "))
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: errors.New("not confirmed: nothing was shared")}
	}
	reply := &sidecar.DaemonBridgeInviteReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeInvite, params, true, reply); err != nil {
		return err
	}
	cli.printf("share      %s\n", reply.ShareId)
	cli.printf("code       %s\n", reply.Code)
	if reply.ExpireTime != nil {
		cli.printf("expires    %s\n", reply.ExpireTime.UTC().Format("2006-01-02 15:04 UTC"))
	}
	cli.printf("Give the code to the other network's admin, who runs ur bridge accept-invite <code>. It is shown once: this device keeps no copy, and anyone who holds it can accept the invite.\n")
	return nil
}

func runUrBridgeAcceptInvite(ctx context.Context, cli *urCli, network string, code string) error {
	// held to its form before any question, and never echoed
	if _, err := sidecar.ParseBridgeShareCode(code); err != nil {
		return errors.New("that is not an invite's code: paste the code ur bridge invite printed")
	}
	confirmed, err := confirmOnTty(cli, "Accept this invite? Each address the other network shares gets an alias in this network's block, which this network's devices can then reach.")
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: errors.New("not confirmed: the invite was not accepted")}
	}
	reply := &sidecar.DaemonBridgeAcceptInviteReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeAcceptInvite, &sidecar.DaemonBridgeAcceptInviteParams{Network: network, Code: code}, true, reply); err != nil {
		return err
	}
	switch sidecar.BridgeShareAcceptStatus(reply.Status) {
	case sidecar.BridgeShareAcceptStatusActive:
		if reply.ShareId != nil {
			cli.printf("share      %s\n", reply.ShareId)
		}
		if reply.SharingNetworkId != nil {
			cli.printf("from       network %s\n", reply.SharingNetworkId)
		}
		for _, alias := range reply.Aliases {
			cli.printf("alias      target %d at .%d.%d/%d of this network's block\n", alias.Index, alias.HostBits>>8&0xff, alias.HostBits&0xff, alias.Length)
		}
		cli.printf("Accepted. The share carries traffic once the other network's admin activates it.\n")
		return nil
	case sidecar.BridgeShareAcceptStatusRefusedTooLarge:
		return &urExitError{code: urExitFailed, err: fmt.Errorf(
			"the invite was refused and the other network told: target %d is a /%s, wider than the /17 a network keeps for aliases. Ask for an invite with narrower targets",
			reply.RefusedIndex, strconv.FormatUint(uint64(reply.RefusedLength), 10))}
	case sidecar.BridgeShareAcceptStatusRefusedNoSpace:
		largest := "no free block"
		if 0 < reply.LargestFreeLength && reply.LargestFreeLength <= 32 {
			largest = fmt.Sprintf("the largest free block is a /%d", reply.LargestFreeLength)
		}
		return &urExitError{code: urExitFailed, err: fmt.Errorf(
			"the invite was refused and the other network told: no room for target %d, a /%d: %d alias addresses are free and %s. Ask for an invite with fewer or narrower targets",
			reply.RefusedIndex, reply.RefusedLength, reply.FreeAddressCount, largest)}
	}
	return fmt.Errorf("the daemon answered a status this ur does not know: %q", reply.Status)
}

// The share acts of a network's backend: its filer's, where the filer offers them, as sidecar.BridgeFiler does.
func (self *urBridgeBackend) shareFiler() (sidecar.DaemonBridgeShareBackend, error) {
	shares, ok := self.config.Filer.(sidecar.DaemonBridgeShareBackend)
	if !ok {
		return nil, errUrBridgeUnwired
	}
	return shares, nil
}

// sidecar.DaemonBridgeShareBackend's invite, the filer's.
func (self *urBridgeBackend) Invite(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeShareInviteRequest) (*sidecar.BridgeShareInvite, error) {
	shares, err := self.shareFiler()
	if err != nil {
		return nil, err
	}
	return shares.Invite(ctx, origin, request)
}

// sidecar.DaemonBridgeShareBackend's accept, the filer's.
func (self *urBridgeBackend) AcceptInvite(ctx context.Context, origin *sidecar.BridgeFileOrigin, code []byte) (*sidecar.BridgeShareAccepted, error) {
	shares, err := self.shareFiler()
	if err != nil {
		return nil, err
	}
	return shares.AcceptInvite(ctx, origin, code)
}

var _ sidecar.DaemonBridgeShareBackend = (*urBridgeBackend)(nil)
