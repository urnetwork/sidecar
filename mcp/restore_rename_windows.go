//go:build windows && !sdk_mobile_bind

// §16.7's install and back on Windows: MoveFileExW without MOVEFILE_REPLACE_EXISTING, which renames only while no file
// has the new name, so a write that lands at p meanwhile is never replaced (D-MCP-8). It takes paths, not a
// directory's handle, so dirPath, the directory as resolved through the worktree's root, names where it acts. A file
// open without FILE_SHARE_DELETE refuses the move: §16.7's in-use. The device rule reads nothing here, since a
// volume's mount point is a reparse point Lstat already reports as another kind.

package mcp

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// from renamed to to in the directory dirPath names, only while no to exists.
func restoreRenameNoReplace(dir *os.File, dirPath string, from string, to string) error {
	fromPath, err := windows.UTF16PtrFromString(filepath.Join(dirPath, from))
	if err != nil {
		return err
	}
	toPath, err := windows.UTF16PtrFromString(filepath.Join(dirPath, to))
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(fromPath, toPath, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "MoveFileEx", Old: from, New: to, Err: err}
	}
	return nil
}

// Whether err says the volume takes no such rename.
func restoreRenameUnsupported(err error) bool {
	return errors.Is(err, errRestoreRenameUnsupported) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION)
}

// Whether err says the volume takes no hard link of the file.
func restoreLinkUnsupported(err error) bool {
	return errors.Is(err, errRestoreLinkUnsupported) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) || errors.Is(err, windows.ERROR_TOO_MANY_LINKS) ||
		errors.Is(err, windows.ERROR_NOT_SAME_DEVICE)
}

// Whether err says p is open without FILE_SHARE_DELETE, so it cannot move: §16.7's in-use.
func restoreInUse(err error) bool {
	return errors.Is(err, errRestoreInUse) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

// No device is read on Windows.
func restoreDevice(info os.FileInfo) (uint64, bool) {
	return 0, false
}
