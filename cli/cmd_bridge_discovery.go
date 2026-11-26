// ur bridge devices, share, unshare and discovery (§17.11's rows; §17.7.1; owner decision 778): service discovery from
// the terminal.
//
//	ur bridge devices [--json]                      this host's LAN devices that discovery finds, shared or not, what
//	                                                this host publishes, and the instances this device sees from the
//	                                                network's hosts, each with its address and why any is withheld; it
//	                                                shows the own-services notice until seen
//	ur bridge share <device>                        shows the disclosure on /dev/tty, asks, and on a yes shares the
//	                                                device, filing its /32 route where none serves it, and waits for
//	                                                that route's approval as expose does
//	ur bridge unshare <device>                      stops publishing it, withdrawing a /32 route its share filed;
//	                                                confirmed on /dev/tty
//	ur bridge discovery on|off                      publish Bonjour names for this device's own services and listed
//	                                                entries, or not; the Listeners section lists the entries still
//	ur bridge discovery hide|unhide <x>             one hide set with ur listeners hide: <x> is a port, <port>/udp, an
//	                                                instance <name>.<_service>.<_tcp|_udp>, or device; unhide is
//	                                                confirmed on /dev/tty, since it reopens what the hide closed
//	ur bridge discovery proxy on|off                run the advertising proxy or not
//
// share, unshare and unhide are the person's acts: the daemon takes them only from control with ur's confirmation, and
// refuses them under a harness process. Names and addresses reach the person's terminal alone.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The usage lines ur bridge adds for discovery.
var urBridgeDiscoveryUsage = []string{
	"  ur bridge devices [--json] [--network=<name>]",
	"  ur bridge share <device> [--network=<name>]",
	"  ur bridge unshare <device> [--network=<name>]",
	"  ur bridge discovery <setting> [<value>] [--network=<name>]",
}

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urBridgeDiscoveryMethods)
}

// The discovery methods over a network's daemon target, beside urBridgeMethods'.
func urBridgeDiscoveryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.bridges == nil {
		return nil
	}
	bridges := network.bridges
	return sidecar.NewDaemonBridgeDiscovery(&sidecar.DaemonBridgeDiscoveryArgs{
		Component: func(networkId sidecar.Id, running *sidecar.Sidecar) *sidecar.BridgeDiscoveryComponent {
			built, err := bridges.bridgeNetwork(networkId, running)
			if err != nil || built == nil || built.discovery == nil {
				return nil
			}
			return built.discovery.component
		},
	}).Methods()
}

// Runs ur bridge devices, share, unshare or discovery from the parsed options; false where options name none of them.
func runUrBridgeDiscovery(ctx context.Context, cli *urCli, options map[string]any, network string) (bool, error) {
	device, _ := options["<device>"].(string)
	switch {
	case options["devices"] == true:
		asJson, _ := options["--json"].(bool)
		return true, runUrBridgeDevices(ctx, cli, network, asJson)
	case options["share"] == true:
		return true, runUrBridgeShareDevice(ctx, cli, network, device, false)
	case options["unshare"] == true:
		return true, runUrBridgeShareDevice(ctx, cli, network, device, true)
	case options["discovery"] == true:
		setting, _ := options["<setting>"].(string)
		value, _ := options["<value>"].(string)
		return true, runUrBridgeDiscoverySetting(ctx, cli, network, setting, value)
	}
	return false, nil
}

func runUrBridgeDevices(ctx context.Context, cli *urCli, network string, asJson bool) error {
	reply := &sidecar.DaemonBridgeDevicesReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeDevices, &sidecar.DaemonBridgeDevicesParams{Network: network}, false, reply); err != nil {
		return err
	}
	if asJson {
		data, err := json.MarshalIndent(reply, "", "  ")
		if err != nil {
			return err
		}
		cli.printf("%s\n", data)
		return nil
	}
	printUrBridgeDevices(cli, reply)
	return nil
}

// The listing for a person: the notice first, then the switches, this host's LAN, what it publishes and what it sees.
func printUrBridgeDevices(cli *urCli, reply *sidecar.DaemonBridgeDevicesReply) {
	if reply.Notice != "" {
		cli.printf("%s\n\n", reply.Notice)
	}
	onOff := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	cli.printf("own        %s\n", onOff(reply.Own))
	cli.printf("proxy      %s\n", onOff(reply.Proxy))
	if status := reply.ProxyStatus; status != nil && reply.Proxy {
		switch {
		case status.Note != "":
			cli.printf("           %s\n", status.Note)
		case 0 < status.RefusedCount:
			cli.printf("           %d registered on this machine, %d refused\n", status.RegisteredCount, status.RefusedCount)
		default:
			cli.printf("           %d registered on this machine\n", status.RegisteredCount)
		}
	}
	if reply.HiddenDevice {
		cli.printf("hidden     this device, whole\n")
	}
	for _, hide := range reply.Hides {
		cli.printf("hidden     %s\n", hide)
	}
	for _, device := range reply.Lan {
		share := device.Share
		if share == "" {
			share = "not shared"
		}
		line := fmt.Sprintf("lan        %s %s", device.HostLabel, device.Address)
		if device.Model != "" {
			line += " (" + device.Model + ")"
		}
		cli.printf("%s, %s\n", line, share)
		if device.ApprovalId != "" {
			cli.printf("           waiting on approval %s: run ur bridge share %s again once it is decided\n", device.ApprovalId, device.HostLabel)
		}
		if share == "moved" || share == "absent" {
			cli.printf("           its route was withdrawn: run ur bridge share %s to share it again\n", device.HostLabel)
		}
		switch {
		case device.RouteClosed:
			cli.printf("           at %s: no route rule reaches it on any port\n", device.SharedAddress)
		case 0 < len(device.RoutePorts):
			cli.printf("           at %s: an admin narrowed its route to %s, so a client whose tunnel picks other ports "+
				"cannot reach it\n", device.SharedAddress, strings.Join(device.RoutePorts, ", "))
		case device.SharedAddress != "":
			cli.printf("           at %s, every port\n", device.SharedAddress)
		}
		for _, service := range device.Services {
			withheld := ""
			if service.Withheld != "" {
				withheld = ", " + service.Withheld
			}
			cli.printf("           %s %s :%d%s\n", service.Name, service.Service, service.Port, withheld)
		}
	}
	for _, instance := range reply.Published {
		cli.printf("published  %s %s %s:%d\n", instance.Name, instance.Service, instance.Address, instance.Port)
	}
	for _, host := range reply.Remote {
		name := host.Name
		if name == "" {
			name = host.SidecarId.String()
		}
		cli.printf("host       %s\n", name)
		if 0 < host.DroppedCount {
			cli.printf("           %d instances dropped: addresses this host does not serve, or this router sends elsewhere\n", host.DroppedCount)
		}
		for _, instance := range host.Instances {
			cli.printf("           %s %s %s:%d\n", instance.Name, instance.Service, instance.Address, instance.Port)
		}
	}
}

// Shares or unshares device on the person's confirmation, the disclosure shown first for a share.
func runUrBridgeShareDevice(ctx context.Context, cli *urCli, network string, device string, unshare bool) error {
	if device == "" {
		return errUrBridgeUsage
	}
	question := fmt.Sprintf("Stop sharing %s?", device)
	if !unshare {
		disclosure := &sidecar.DaemonBridgeShareReply{}
		params := &sidecar.DaemonBridgeShareParams{Network: network, Device: device, Disclosure: true}
		if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeShare, params, true, disclosure); err != nil {
			return err
		}
		question = disclosure.Disclosure + "\n\nShare it?"
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return &urExitError{code: urExitFailed, err: fmt.Errorf("not confirmed: %s stays as it is", device)}
	}
	params := &sidecar.DaemonBridgeShareParams{Network: network, Device: device, Unshare: unshare}
	waited := false
	for {
		reply := &sidecar.DaemonBridgeShareReply{}
		if err := cli.callDaemon(ctx, sidecar.DaemonMethodBridgeShare, params, true, reply); err != nil {
			return err
		}
		if unshare {
			cli.printf("unshared   %s\n", device)
			return nil
		}
		if reply.ApprovalPendingId == nil {
			cli.printf("shared     %s, %s\n", device, reply.State)
			if reply.RuleId != "" {
				cli.printf("route      rule %s\n", reply.RuleId)
			}
			return nil
		}
		if waited {
			return &urExitError{code: urExitFailed, err: fmt.Errorf("approval %s is still pending: run this again once it is decided", reply.ApprovalPendingId)}
		}
		cli.printf("approval pending: run ur approve %s on an approval-capable device; waiting\n", reply.ApprovalPendingId)
		if err := urBridgeWait(ctx, urBridgeCommandSettings.ApprovalWaitTimeout); err != nil {
			return err
		}
		waited = true
	}
}

// One of discovery's switches; unhide on the person's confirmation.
func runUrBridgeDiscoverySetting(ctx context.Context, cli *urCli, network string, setting string, value string) error {
	params := &sidecar.DaemonBridgeDiscoveryParams{Network: network, Setting: setting, Value: value}
	method := sidecar.DaemonMethodBridgeDiscovery
	confirmed := false
	switch setting {
	case sidecar.DaemonBridgeDiscoveryOn, sidecar.DaemonBridgeDiscoveryOff:
		params.Setting, params.Value = sidecar.DaemonBridgeDiscoveryOwn, setting
	case sidecar.DaemonBridgeDiscoveryProxy, sidecar.DaemonBridgeDiscoveryHide:
	case "unhide":
		ok, err := confirmOnTty(cli, fmt.Sprintf("Unhide %s? It shows in Bonjour browsers and the Listeners section again.", value))
		if err != nil {
			return err
		}
		if !ok {
			return &urExitError{code: urExitFailed, err: fmt.Errorf("not confirmed: %s stays hidden", value)}
		}
		params.Setting = sidecar.DaemonBridgeDiscoveryHide
		method, confirmed = sidecar.DaemonMethodBridgeDiscoveryUnhide, true
	default:
		return errUrBridgeUsage
	}
	reply := &sidecar.DaemonBridgeDevicesReply{}
	if err := cli.callDaemon(ctx, method, params, confirmed, reply); err != nil {
		return err
	}
	if params.Setting == sidecar.DaemonBridgeDiscoveryOwn && params.Value == sidecar.DaemonBridgeDiscoveryOff {
		cli.printf("own        off: this device's own services take no Bonjour name; the Listeners section still lists them, and ur listeners hide --device hides them there\n")
		return nil
	}
	cli.printf("%s %s\n", strings.TrimSpace(params.Setting), value)
	return nil
}
