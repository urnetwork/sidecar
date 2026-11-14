//go:build !linux && !darwin && !windows && !js && !ios && !android && !sdk_mobile_bind

// §16.7's install and back where this build knows no no-replace rename: every one answers unsupported, so an apply
// takes Go's Root.Link and the staged name's removal instead, and a volume that takes no hard link either is
// unsupported before anything moves.

package mcp

import (
	"errors"
	"os"
)

// Unsupported: no no-replace rename is built here.
func restoreRenameNoReplace(dir *os.File, dirPath string, from string, to string) error {
	return &os.LinkError{Op: "rename", Old: from, New: to, Err: errRestoreRenameUnsupported}
}

// Whether err is that answer.
func restoreRenameUnsupported(err error) bool {
	return errors.Is(err, errRestoreRenameUnsupported)
}

// Whether err says the volume takes no hard link of the file.
func restoreLinkUnsupported(err error) bool {
	return errors.Is(err, errRestoreLinkUnsupported) || errors.Is(err, errors.ErrUnsupported)
}

// Whether err says p is open where it cannot move: Windows' sharing rule alone.
func restoreInUse(err error) bool {
	return errors.Is(err, errRestoreInUse)
}

// No device is read here.
func restoreDevice(info os.FileInfo) (uint64, bool) {
	return 0, false
}
