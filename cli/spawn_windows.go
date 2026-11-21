//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Starts `ur daemon args...` detached from this console, with no stdio: an auto-spawned daemon logs to its own log,
// never to the stdout a relay owns.
func spawnDetachedDaemon(args []string) error {
	command, err := urDaemonCommand(args)
	if err != nil {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
