// The Linux host's unit environment: systemd's user directory, and whether the host is headless, which needs linger
// to start the unit at boot (§5.8).

package main

import (
	"os"
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
