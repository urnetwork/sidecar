// ur bridge invite, ur bridge accept-invite and ur bridge activate (§17.9, §17.11; BRIDGE-M6-03; QD-831): a share from
// the terminal. Each is an admin's, and a person's confirmation: each asks on the terminal before the daemon acts, and
// the daemon runs none for an agent.
//
//	ur bridge invite <target>...       shares what hosts of this network reach with one other network. A target is
//	                                   <host>=<cidr>[,tcp:<port>[-<port>]|,udp:<port>[-<port>]]: the host by its id,
//	                                   private name or overlay address, and the IPv4 prefix it reaches. Prints the
//	                                   share's id and the invite's code. The code is shown once: this device keeps
//	                                   none, and whoever holds it can accept the invite
//	ur bridge accept-invite <code>     accepts another network's invite: gives each target an alias in this
//	                                   network's block and tells the other network. Prints the aliases and the
//	                                   ShareKey's fingerprint, or why there was no room
//	ur bridge activate <share_id>      the inviting network's approving admin, on a device that made the invite:
//	                                   shows the accepted share on the terminal (the other network, each target with
//	                                   its alias, the ShareKey's fingerprint, both tables' hashes), asks, and on a yes
//	                                   activates exactly what was shown; a share that changed in between is refused
//
// The code reaches the terminal alone; the daemon's logs name opaque ids (I-13). activate needs a terminal before it
// reads the share, and shows the share there rather than on stdout: what the person confirms reaches the person, and
// no process reading ur's output sees it.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The usage lines ur bridge adds for shares.
var urBridgeShareUsage = []string{
	"  ur bridge invite <target>... [--network=<name>]",
	"  ur bridge accept-invite <code> [--network=<name>]",
	"  ur bridge activate <share_id> [--network=<name>]",
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
			cli.printf("alias      target %d at %s of this network's block\n", alias.Index, formatUrBridgeShareAlias(alias))
		}
		cli.printf("Accepted. The share carries traffic once the other network's admin activates it.\n")
		if reply.ShareKeyFingerprint != "" {
			cli.printf("share key  %s\n", reply.ShareKeyFingerprint)
			cli.printf("That admin is shown this fingerprint before activating: read it to them to compare.\n")
		}
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

// An alias's block in its network's upper half as a person reads it: the last two octets and the length.
func formatUrBridgeShareAlias(alias *sidecar.DaemonBridgeShareAlias) string {
	return fmt.Sprintf(".%d.%d/%d", alias.HostBits>>8&0xff, alias.HostBits&0xff, alias.Length)
}

// Prints a share as its approving admin is shown it before activating, to the terminal (the file's comment).
func printUrBridgeSharePreview(out io.Writer, preview *sidecar.DaemonBridgeSharePreview) {
	fmt.Fprintf(out, "share      %s\n", preview.ShareId)
	if preview.AcceptingNetworkId != nil {
		fmt.Fprintf(out, "network    %s accepted the invite\n", preview.AcceptingNetworkId)
	} else {
		fmt.Fprintf(out, "network    none yet: the invite is open\n")
	}
	for _, target := range preview.Targets {
		what := target.Prefix + ", every protocol"
		if target.Protocol != "" {
			what = target.Prefix + " " + target.Protocol + " " + strings.Join(target.Ports, ",")
		}
		alias := "no alias yet"
		if target.Alias != nil {
			alias = "alias " + formatUrBridgeShareAlias(target.Alias) + " of that network's block"
		}
		fmt.Fprintf(out, "%-10s %s on host %s, %s\n", fmt.Sprintf("target %d", target.Index), what, target.HostSidecarId, alias)
	}
	if preview.ShareKeyFingerprint != "" {
		fmt.Fprintf(out, "share key  %s\n", preview.ShareKeyFingerprint)
	}
	fmt.Fprintf(out, "targets    sha256 %s, version %d\n", preview.TargetTableSha256, preview.TargetTableVersion)
	if preview.AliasTableSha256 != "" {
		fmt.Fprintf(out, "aliases    sha256 %s, version %d\n", preview.AliasTableSha256, preview.AliasTableVersion)
	}
}

// A refusal the daemon's filer answered, as the person reads it: what was not done, and the filer's reason.
func urBridgeShareRefusal(err error, what string) error {
	var rpcError *sidecar.DaemonRpcError
	if errors.As(err, &rpcError) && rpcError.Code == sidecar.DaemonRpcFailed {
		return &urExitError{code: urExitFailed, err: fmt.Errorf("%s: %s", what, rpcError.Message)}
	}
	return err
}

// ur bridge activate: the share on the terminal, the person's yes, then the activation of exactly that preview.
func runUrBridgeActivate(ctx context.Context, cli *urCli, network string, shareIdText string) error {
	shareId, err := sidecar.ParseId(shareIdText)
	if err != nil {
		return errors.New("that is not a share's id: give the share ur bridge invite printed")
	}
	// a caller with no terminal is refused before the share is read: what it shows is the person's to see
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: ur bridge activate needs a person on a terminal: %w", errUrNoTty, err)
	}
	tty.Close()
	params := &sidecar.DaemonBridgeActivateParams{Network: network, ShareId: shareId}
	preview := &sidecar.DaemonBridgeSharePreview{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeActivate, params, true, preview); err != nil {
		return urBridgeShareRefusal(err, "the share was not read")
	}
	if preview.ShareId != shareId || preview.PreviewDigest == "" {
		return errors.New("the daemon answered another share's preview, or none")
	}
	tty, err = cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	printUrBridgeSharePreview(tty, preview)
	tty.Close()
	switch sidecar.BridgeShareAcceptStatus(preview.Status) {
	case sidecar.BridgeShareAcceptStatusActive:
	case "":
		return &urExitError{code: urExitFailed, err: errors.New("the other network has not accepted the invite yet: there is nothing to activate")}
	case sidecar.BridgeShareAcceptStatusRefusedTooLarge:
		return &urExitError{code: urExitFailed, err: fmt.Errorf(
			"the other network refused the invite: target %d, a /%d, is wider than the /17 a network keeps for aliases. There is nothing to activate: invite again with narrower targets",
			preview.RefusedIndex, preview.RefusedLength)}
	case sidecar.BridgeShareAcceptStatusRefusedNoSpace:
		return &urExitError{code: urExitFailed, err: fmt.Errorf(
			"the other network refused the invite: it had no room for target %d, a /%d, with %d alias addresses free. There is nothing to activate: invite again with fewer or narrower targets",
			preview.RefusedIndex, preview.RefusedLength, preview.FreeAddressCount)}
	default:
		return fmt.Errorf("the daemon answered a status this ur does not know: %q", preview.Status)
	}
	if preview.AcceptingNetworkId == nil {
		return errors.New("the daemon answered an active share with no accepting network")
	}
	question := fmt.Sprintf("Activate this share? Network %s then reaches each target above through its alias, until the share's grant is revoked.", preview.AcceptingNetworkId)
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: errors.New("not confirmed: the share was not activated")}
	}
	params.PreviewDigest = preview.PreviewDigest
	reply, err := callUrBridgeFiling(ctx, cli, sidecar.DaemonMethodBridgeActivate, params, true)
	if err != nil {
		return urBridgeShareRefusal(err, "the share was not activated")
	}
	if reply.GrantId == "" {
		return errors.New("the daemon answered the activation with no grant")
	}
	cli.printf("activated  share %s for network %s, under grant %s\n", shareId, preview.AcceptingNetworkId, reply.GrantId)
	if reply.ApprovalId != nil {
		cli.printf("approval   %s\n", reply.ApprovalId)
	}
	cli.printf("Each host of this network serves the share once its next state takes the grant.\n")
	return nil
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

// sidecar.DaemonBridgeShareBackend's preview, the filer's.
func (self *urBridgeBackend) PreviewShare(ctx context.Context, origin *sidecar.BridgeFileOrigin, shareId sidecar.Id) (*sidecar.BridgeSharePreview, error) {
	shares, err := self.shareFiler()
	if err != nil {
		return nil, err
	}
	return shares.PreviewShare(ctx, origin, shareId)
}

// sidecar.DaemonBridgeShareBackend's activation, the filer's.
func (self *urBridgeBackend) ActivateShare(ctx context.Context, origin *sidecar.BridgeFileOrigin, preview *sidecar.BridgeSharePreview, lifetime time.Duration) (*sidecar.BridgeFiling, error) {
	shares, err := self.shareFiler()
	if err != nil {
		return nil, err
	}
	return shares.ActivateShare(ctx, origin, preview, lifetime)
}

var _ sidecar.DaemonBridgeShareBackend = (*urBridgeBackend)(nil)
