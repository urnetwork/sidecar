//go:build linux && !android && !sdk_mobile_bind

// §16.7's install and back on linux: renameat2's RENAME_NOREPLACE on the parent's descriptor, which renames only
// while no file has the new name, so a write that lands at p meanwhile is never replaced (D-MCP-8).

package mcp

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// from renamed to to in dir, only while no to exists. dirPath is unused here: the rename is on dir's descriptor.
func restoreRenameNoReplace(dir *os.File, dirPath string, from string, to string) error {
	raw, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var renameErr error
	if err := raw.Control(func(fd uintptr) {
		renameErr = unix.Renameat2(int(fd), from, int(fd), to, unix.RENAME_NOREPLACE)
	}); err != nil {
		return err
	}
	if renameErr != nil {
		return &os.LinkError{Op: "renameat2", Old: from, New: to, Err: renameErr}
	}
	return nil
}

// Whether err says the kernel or the volume takes no no-replace rename.
func restoreRenameUnsupported(err error) bool {
	return errors.Is(err, errRestoreRenameUnsupported) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

// Whether err says the volume takes no hard link of the file.
func restoreLinkUnsupported(err error) bool {
	return errors.Is(err, errRestoreLinkUnsupported) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EMLINK) || errors.Is(err, unix.ENOSYS)
}

// Whether err says p is open where it cannot move: Windows' sharing rule alone.
func restoreInUse(err error) bool {
	return errors.Is(err, errRestoreInUse)
}

// The device info's file is on, for §16.7's mount point rule.
func restoreDevice(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}
