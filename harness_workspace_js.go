//go:build js && !sidecar_http && !ios_extension

// The browser's workspace (DESIGN-COMPUTE §7.5: 64 MiB in memory, with an OPFS spill) comes with the browser Harness,
// which is Later (§19.5, Q-HARN-3). On js no workspace is made, so the Harness starts no local agent there; the loop and
// its types build, so the browser Harness can build on them.

package sidecar

import (
	"errors"
)

// No workspace is made on js.
var ErrHarnessWorkspaceUnavailable = errors.New("no workspace is built for the browser yet, so no local agent starts here")

// What a workspace is made with, as on the other legs.
type harnessWorkspaceArgs struct {
	Parent       string
	CapByteCount int64
}

// The browser's workspace, which this build does not make.
type harnessWorkspace struct{}

// Refuses: the browser's workspace is Later.
func newHarnessWorkspace(args *harnessWorkspaceArgs) (*harnessWorkspace, error) {
	return nil, ErrHarnessWorkspaceUnavailable
}

// Nothing to remove.
func (self *harnessWorkspace) Remove() error {
	return nil
}

// No host path.
func (self *harnessWorkspace) HostPath() string {
	return ""
}
