//go:build !js && !ios && !android && !sdk_mobile_bind && !windows

// The instance lock (§5.8): an exclusive flock on <state>/lock, held for the daemon's life, so one daemon serves an
// instance. flock binds the lock to the open file, so a second open fails it even in one process, and the kernel
// drops it when the daemon dies.

package sidecar

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The lock file's name in <state>.
const daemonLockFileName = "lock"

// Takes the instance's lock, making <state> 0700 if it is missing. ErrDaemonRunning when another holds it.
func acquireDaemonLock(stateDirectory string) (io.Closer, error) {
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(stateDirectory, daemonLockFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrDaemonRunning
		}
		return nil, err
	}
	return file, nil
}
