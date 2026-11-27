// The Linux host's unit environment: systemd's user directory, and whether the host is headless, which needs linger
// to start the unit at boot (§5.8). And the gateway's sockets the unit's socket unit passes the daemon (DESIGN-COMPUTE
// §8.4; unit.go's systemdGatewayListeners), the variables unset once read, as sd_listen_fds does, so no child takes
// them for its own.

package main

import (
	"net"
	"os"
	"syscall"

	"github.com/urnetwork/sidecar"
)

// This user's environment for a systemd user unit. With no display, the host is headless.
func hostUnitEnv() (*unitEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &unitEnv{
		goos:          "linux",
		home:          home,
		xdgConfigHome: os.Getenv("XDG_CONFIG_HOME"),
		uid:           os.Getuid(),
		headless:      os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "",
	}, nil
}

// The gateway's sockets systemd passed this daemon, none where it was not started by its socket unit's service.
func urGatewayInheritedListeners(log sidecar.Logger) []net.Listener {
	listeners, err := systemdGatewayListeners(os.Getenv, os.Getpid(), os.NewFile, syscall.CloseOnExec)
	for _, name := range []string{unitListenPidVariable, unitListenFdsVariable, unitListenFdNamesVariable} {
		os.Unsetenv(name)
	}
	if err != nil {
		log.Warningf("[gateway]a socket the unit passed is not taken: %s", err)
	}
	return listeners
}
