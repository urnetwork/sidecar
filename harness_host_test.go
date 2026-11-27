//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The app's host as a test sets it.
type harnessTestHost struct {
	directory string
	mobile    bool

	stateLock  sync.Mutex
	foreground bool
}

func (self *harnessTestHost) WorkspaceDirectory() string {
	return self.directory
}

func (self *harnessTestHost) Mobile() bool {
	return self.mobile
}

func (self *harnessTestHost) Foreground() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.foreground
}

// Moves the app in or out of the foreground.
func (self *harnessTestHost) setForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.foreground = foreground
}

// An agent started while a phone's host is set makes its workspace in the app's directory, under the phone's cap; with
// the host taken away, the Harness's own directory and cap again.
func TestHarnessHostWorkspaceInTheAppsDirectory(t *testing.T) {
	world := newHarnessTestWorld(t, nil, nil, nil)
	host := &harnessTestHost{directory: t.TempDir(), mobile: true, foreground: true}
	world.harness.SetHost(host)
	agent := world.agent(t, &HarnessAgentSpec{Name: "phone"}).(*harnessAgent)
	if !strings.HasPrefix(agent.workspace.hostPath, host.directory+string(filepath.Separator)) ||
		agent.workspace.capByteCount != world.harness.settings.WorkspacePhoneByteCount {
		t.Fatalf("the workspace %s, cap %d", agent.workspace.hostPath, agent.workspace.capByteCount)
	}
	world.harness.SetHost(nil)
	desktop := world.agent(t, &HarnessAgentSpec{Name: "desktop"}).(*harnessAgent)
	if strings.HasPrefix(desktop.workspace.hostPath, host.directory) || desktop.workspace.capByteCount != world.harness.workspaceCap {
		t.Fatalf("with no host: %s, cap %d", desktop.workspace.hostPath, desktop.workspace.capByteCount)
	}
}

// In the background a prompt starts no model call and settles backgrounded at its item boundary; back in the
// foreground the agent takes up from where it left, the model called once, and ends.
func TestHarnessHostBackgroundResumesFromWhereItLeft(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessTestWorld(t, router, nil, nil)
	host := &harnessTestHost{directory: t.TempDir(), mobile: true}
	world.harness.SetHost(host)
	agent := world.agent(t, &HarnessAgentSpec{Name: "phone"})
	log := harnessCollect(t, agent)
	router.script(harnessTextCall("done"))
	if err := agent.Prompt(context.Background(), "work", nil); err != nil {
		t.Fatal(err)
	}
	events := log.until(t, HarnessEventAgentSettled)
	if reason := harnessStopReason(events[len(events)-1]); reason != HarnessStopBackgrounded || len(router.made()) != 0 {
		t.Fatalf("in the background: %s, %d calls", reason, len(router.made()))
	}
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// still in the background, nothing resumes
	world.harness.HostForegroundChanged(context.Background())
	if len(router.made()) != 0 {
		t.Fatalf("a background change resumed the agent")
	}
	host.setForeground(true)
	world.harness.HostForegroundChanged(context.Background())
	events = log.until(t, HarnessEventAgentSettled)
	if reason := harnessStopReason(events[len(events)-1]); reason != HarnessStopEnded || len(router.made()) != 1 {
		t.Fatalf("back in the foreground: %s, %d calls", reason, len(router.made()))
	}
	last := router.made()[0].Messages
	if text := last[len(last)-1].Text(); text != "work" {
		t.Fatalf("the resumed call's last message: %q", text)
	}
}
