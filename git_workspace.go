//go:build !ios_extension && !sidecar_http && !js

// A worktree in a local agent's workspace (DESIGN-COMPUTE §7.5's workspace and caps, §13.7's limits; GIT-M13-01): the
// worktree's file system is a directory of the workspace, every byte it writes, .git's among them, counted against the
// workspace's cap before it lands, from what the workspace held when the worktree opened. The file tools' writes
// land beside it and the workspace checks them against the same cap (harness_workspace.go), so the two together stay
// within it, up to what one side wrote while the other's count was taken.
//
// Safe for concurrent use as the workspace and the file system are.

package sidecar

import (
	"path/filepath"
)

// The file system of a worktree at name in workspace, a path the workspace's rules take (no .git, no ..), its writes
// counted against the workspace's cap; close releases it.
func newGitWorkspaceFileSystem(workspace *harnessWorkspace, name string) (GitFileSystem, func() error, error) {
	if err := workspace.usable(); err != nil {
		return nil, nil, err
	}
	held, err := harnessWorkspacePath(name)
	if err != nil {
		return nil, nil, err
	}
	if err := workspace.root.MkdirAll(harnessWorkspaceHostName(held), 0o700); err != nil {
		return nil, nil, harnessWorkspaceError(err)
	}
	used, err := workspace.Usage()
	if err != nil {
		return nil, nil, err
	}
	return NewGitOsFileSystem(filepath.Join(workspace.HostPath(), harnessWorkspaceHostName(held)), NewGitCapBudget(workspace.CapByteCount(), used))
}
