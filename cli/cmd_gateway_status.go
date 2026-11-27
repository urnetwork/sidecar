// The gateway's lines in `ur status` (DESIGN-COMPUTE §8.4, GW-M12-01): the port and, for each loopback address, whether
// this daemon holds it, from its unit or by its own bind, or who else does where the OS shows it, since a token goes
// only to a port the daemon is shown to hold (`ur gateway token` refuses otherwise). Nothing is printed for an instance
// with no gateway port. The daemon's reply names no key and no token.

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
)

func init() {
	urStatusSections = append(urStatusSections, printUrGatewayStatus)
}

// The gateway's lines, after status's own; nothing for a daemon that does not answer or an instance with no port.
func printUrGatewayStatus(ctx context.Context, cli *urCli) {
	status := &sidecar.GatewayServerStatus{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayStatus, struct{}{}, false, status); err != nil {
		return
	}
	for _, line := range urGatewayStatusLines(status) {
		fmt.Fprintf(cli.stdout, "%s\n", line)
	}
}

// What status says of the gateway's port, a line each.
func urGatewayStatusLines(status *sidecar.GatewayServerStatus) []string {
	if status.Port == 0 && !status.Hold {
		return nil
	}
	lines := []string{}
	if !status.Hold || !status.Serving {
		lines = append(lines, fmt.Sprintf("gateway:    port %d, not served: %s", status.Port, status.Reason))
	} else {
		served := []string{}
		for _, address := range status.Addresses {
			if !address.Serving {
				continue
			}
			text := address.Address
			if address.Inherited {
				text += " (held by the daemon's unit across restarts)"
			}
			served = append(served, text)
		}
		lines = append(lines, fmt.Sprintf("gateway:    port %d, held by this daemon on %s", status.Port, strings.Join(served, " and ")))
	}
	for _, address := range status.Addresses {
		switch {
		case address.Serving:
		case address.InUse && address.Holder != "":
			lines = append(lines, fmt.Sprintf("  warning:  %s is held by another process, %s: ur gateway token refuses until it is gone",
				address.Address, address.Holder))
		case address.InUse:
			lines = append(lines, fmt.Sprintf("  warning:  %s is held by another process, which this system does not name: ur gateway token refuses until it is gone",
				address.Address))
		default:
			lines = append(lines, fmt.Sprintf("  address:  %s not served: %s", address.Address, address.Reason))
		}
	}
	if 0 < status.RefusedInherited {
		lines = append(lines, fmt.Sprintf("  warning:  %d socket(s) the daemon's unit handed over were bound elsewhere and closed: run ur install-daemon again",
			status.RefusedInherited))
	}
	return lines
}
