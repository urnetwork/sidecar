//go:build !ios_extension && !sidecar_http

// The app's host as the Harness reads it (DESIGN-COMPUTE §7.5's workspace, §7.6's delivery, §6.5, §20.7; HARN-M11-10):
// where an app's local agents make their workspaces, whether the app is a phone, whose workspace cap is the phone's,
// and whether it is in the foreground. The apps implement it through the sdk (sdk/sidecar_harness.go), which adapts the
// app's lifecycle to it; a desktop daemon sets none, its agents' workspaces in the OS temp directory and always in the
// foreground.
//
//   - Workspaces: an agent that starts while a host is set makes its workspace in the host's directory, under the
//     phone's cap on a phone (HarnessSettings.WorkspacePhoneByteCount), else the desktop's.
//   - Foreground: while the host says the app is in the background, the loop starts no model call and no tool call:
//     each running agent settles backgrounded at its next item boundary, keeping what it left (harness_turn.go), and
//     HostForegroundChanged takes each such agent up again, from where it left, once the app is back.
//   - keep: false details reach the app's listeners in memory only: the Harness journals none of them
//     (harness_tools_run.go), and the sdk writes nothing of an event to the app's storage.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
)

// The app's host (§7.5, §6.5).
type HarnessHost interface {
	// The directory local agents' workspaces are made in: the app's cache directory.
	WorkspaceDirectory() string
	// Whether the app runs on a phone, whose workspace cap is the phone's.
	Mobile() bool
	// Whether the app is in the foreground now: agents answer only then.
	Foreground() bool
}

// The host as the Harness holds it.
type harnessHostSlot struct {
	host HarnessHost
}

// Sets the app's host, nil taking it away: agents started from now on make their workspaces where it says, and every
// agent reads the foreground from it at each item boundary.
func (self *Harness) SetHost(host HarnessHost) {
	if host == nil {
		self.host.Store(nil)
		return
	}
	self.host.Store(&harnessHostSlot{host: host})
}

// The host set, or nil.
func (self *Harness) appHost() HarnessHost {
	slot := self.host.Load()
	if slot == nil {
		return nil
	}
	return slot.host
}

// Whether the loop may start an item now: the host's foreground where one is set, else the foreground source's, and
// always on a desktop with neither.
func (self *Harness) inForeground() bool {
	if host := self.appHost(); host != nil {
		return host.Foreground()
	}
	return self.foreground == nil || self.foreground.Foreground()
}

// Where an agent starting now makes its workspace, and its cap: the host's directory and the phone's cap on a phone,
// else the Harness's own.
func (self *Harness) workspaceArgs() *harnessWorkspaceArgs {
	host := self.appHost()
	if host == nil {
		return &harnessWorkspaceArgs{Parent: self.workspaceParent, CapByteCount: self.workspaceCap}
	}
	args := &harnessWorkspaceArgs{Parent: host.WorkspaceDirectory(), CapByteCount: self.settings.WorkspaceDesktopByteCount}
	if args.Parent == "" {
		args.Parent = self.workspaceParent
	}
	if host.Mobile() {
		args.CapByteCount = self.settings.WorkspacePhoneByteCount
	}
	return args
}

// Tells the Harness the app's foreground state changed: back in the foreground, each agent paused at an item boundary
// takes up its run again from where it left (§6.5, §20.7); in the background nothing is started, and each running
// agent pauses at its own next boundary.
func (self *Harness) HostForegroundChanged(ctx context.Context) {
	if !self.inForeground() {
		return
	}
	agents := func() []*harnessAgent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		agents := []*harnessAgent{}
		for _, agent := range self.agents {
			agents = append(agents, agent)
		}
		return agents
	}()
	for _, agent := range agents {
		if err := agent.Resume(ctx); err != nil && self.log != nil {
			self.log.Warningf("[harness]an agent did not resume in the foreground: %v", err)
		}
	}
}

// The open agents, in no order: what an app's view of the Harness lists (sdk/sidecar_harness.go).
func (self *Harness) Agents() []HarnessAgent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	agents := []HarnessAgent{}
	for _, agent := range self.agents {
		if !agent.isClosed() {
			agents = append(agents, agent)
		}
	}
	return agents
}

// The canonical name agent's next call runs on, "" for an agent this Harness did not start.
func HarnessAgentModel(agent HarnessAgent) string {
	inner, ok := agent.(*harnessAgent)
	if !ok {
		return ""
	}
	return inner.currentModel()
}

// The tokens agent's context holds now, estimated as Pi does, and its model's window: what an app's session pill and
// its Compact screen show (DESIGN-UI.md's T1, T11). Zeroes for an agent this Harness did not start.
func HarnessAgentContext(ctx context.Context, agent HarnessAgent) (int64, int64) {
	inner, ok := agent.(*harnessAgent)
	if !ok {
		return 0, 0
	}
	tokens := func() int64 {
		inner.stateLock.Lock()
		defer inner.stateLock.Unlock()
		tokens := int64(0)
		for _, node := range inner.contextNodes {
			tokens += node.tokens
		}
		return tokens
	}()
	window := int64(0)
	if resolution, err := inner.harness.modelEntry(ctx, inner.currentModel()); err == nil {
		window = resolution.Entry.ContextWindow
	}
	return tokens, window
}
