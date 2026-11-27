//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The evs tools' reading of the local tier's errors, on the legs that commit git-mode refs through it
// (evs_local_write.go): its tip moved on every try, or the write changed nothing.

package sidecar

import (
	"errors"
)

// Whether err is WriteAtTip's tries running out on a moving tip.
func harnessEvsGitTipMoved(err error) bool {
	return errors.Is(err, ErrEvsGitTipMoved)
}

// Whether err is a git-mode write that changes nothing.
func harnessEvsGitUnchanged(err error) bool {
	return errors.Is(err, ErrEvsGitWriteUnchanged)
}
