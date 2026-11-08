//go:build windows && !sdk_mobile_bind

// The instance lock (§5.8) on Windows: LockFileEx, exclusive and failing at once, on <state>/lock, held for the
// daemon's life and dropped by the system when it dies.

package sidecar

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The lock file's name in <state>.
const daemonLockFileName = "lock"

// Takes the instance's lock. ErrDaemonRunning when another holds it.
func acquireDaemonLock(stateDirectory string) (io.Closer, error) {
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(stateDirectory, daemonLockFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := &windows.Overlapped{}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
	if err != nil {
		file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrDaemonRunning
		}
		return nil, err
	}
	return file, nil
}
