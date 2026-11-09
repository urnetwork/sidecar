// The macOS host's unit environment: the user's LaunchAgents and gui domain (§5.8).

package main

import (
	"os"
)

// This user's environment for a LaunchAgent.
func hostUnitEnv() (*unitEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &unitEnv{goos: "darwin", home: home, uid: os.Getuid()}, nil
}
