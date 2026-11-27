// ur daemon's gateway (DESIGN-COMPUTE §8.4, §8.7; R-GW-4, D-GW-3, GW-M12-01): the root's GatewayServer, started with
// the daemon's other services on a desktop (Q-GW-5), serving the instance's port on 127.0.0.1 and [::1] while a grant
// stands, whatever --listen says. Its standing grants are the daemon's busy rule (DaemonSettings.Busy), so a daemon
// holding a grant never idles out (DESIGN §5.8's idle exit, amended by Appendix D). It takes the sockets the daemon's
// unit hands over, launchd's Sockets or a systemd socket unit's (unit_darwin.go, unit_linux.go), so the unit holds the
// port across the daemon's restarts, and where another process holds the port it names that process, where the OS
// shows it (gateway_holder_*.go). An ephemeral daemon, whose state stays in memory, runs no gateway.

package main

import (
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The gateway a daemon of stateDirectory runs, not started: its unit's sockets taken now, before anything else
// opens a file, so their numbers are still the unit's.
func newUrDaemonGateway(stateDirectory string, settings *sidecar.SidecarSettings, log sidecar.Logger) *sidecar.GatewayServer {
	return sidecar.NewGatewayServer(&sidecar.GatewayServerArgs{
		StateDirectory: stateDirectory,
		Settings:       settings.Gateway,
		Inherited:      urGatewayInheritedListeners(log),
		Holder:         urGatewayPortHolder(settings.Gateway),
		Clock:          settings.Clock,
		Log:            log,
	})
}

// Registers gateway's control methods on daemon, over the networks it hosts, and holds its port where a grant stands. A
// port it could not bind is logged and named by ur status; nothing here fails the daemon's start.
func startUrDaemonGateway(daemon *sidecar.Daemon, gateway *sidecar.GatewayServer, log sidecar.Logger) error {
	gateway.SetHosts(sidecar.GatewayDaemonHosts(daemon))
	for _, method := range gateway.DaemonMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			return err
		}
	}
	status := gateway.Start()
	if status.Hold && !status.Serving {
		log.Warningf("[gateway]port %d is not served: %s", status.Port, status.Reason)
	}
	return nil
}

// The daemon's busy rule over gateway: whether a grant stands; nil, which keeps nothing up, for a daemon with none.
func urDaemonGatewayBusy(gateway *sidecar.GatewayServer) func() bool {
	if gateway == nil {
		return nil
	}
	return gateway.Active
}

// The gateway's port a daemon unit of the instance holds: the state's while a grant stands, else 0, which renders a
// unit with no sockets. A state that does not read holds none, and says why on stderr.
func urGatewayUnitPort(cli *urCli) int {
	stateDirectory, err := cli.stateDirectory(cli.instance)
	if err != nil {
		return 0
	}
	state, err := sidecar.ReadGatewayState(stateDirectory, sidecar.DefaultGatewaySettings().StateFileByteCount)
	if err != nil {
		fmt.Fprintf(cli.stderr, "the gateway's state does not read, so the unit holds no port for it: %s\n", err)
		return 0
	}
	if !state.Holds() {
		return 0
	}
	return state.Port
}
