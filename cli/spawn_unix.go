//go:build !windows

package main

import (
	"syscall"
)

// Starts `ur daemon args...` in its own session, detached from this terminal, with no stdio: an auto-spawned daemon
// logs to its own log, never to the stdout a relay owns.
func spawnDetachedDaemon(args []string) error {
	command, err := urDaemonCommand(args)
	if err != nil {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
