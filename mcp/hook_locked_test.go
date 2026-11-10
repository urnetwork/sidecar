//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's Locked taint on a T2 sidecar: while the keychain is closed a web tool's taint goes to the spool, sealed to
// the epoch's public key, as the ack's precondition, and after unlock the first call applies it before anything else,
// even in a process that kept nothing of it in memory.

package mcp

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A daemon's restart over a hosted network: new run store and spool objects over the same files and instance, which
// keep nothing in memory, the Sidecar's state read through.
type testRestartedNetwork struct {
	hosted *sidecar.Sidecar
	runs   *sidecar.RunStore
	spool  *sidecar.Spool
}

func (self *testRestartedNetwork) Status() sidecar.SidecarStatus {
	return self.hosted.Status()
}

func (self *testRestartedNetwork) Runs() (*sidecar.RunStore, error) {
	return self.runs, nil
}

func (self *testRestartedNetwork) Spool() (*sidecar.Spool, error) {
	return self.spool, nil
}

func TestLockedTaintReplaysFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, sidecartest.DefaultNetSettings())
	defer net.Close()
	testSidecar, err := net.AddSidecar("daemon", nil)
	if err != nil {
		t.Fatal(err)
	}
	hosted := testSidecar.Sidecar()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	table := sidecartest.NewFakeProcessTable(clock)
	daemon := newFakeMcpDaemon()
	networkId := testSidecar.NetworkId()
	daemon.hostNetwork(networkId, hosted)
	newServer := func() *McpServer {
		settings := NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
		settings.Clock = clock
		settings.Processes = table
		server := NewMcpServer(daemon, settings)
		server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) { return false, nil })
		return server
	}
	server := newServer()
	terminal := table.Spawn(1, "zsh")
	claude := sidecartest.NewFakeHarness(table, terminal.Identity.Pid, sidecartest.FakeHarnessClaudeCode, hookTestCwd,
		func(hello *sidecar.DaemonHello, payload []byte) error {
			network, _ := daemon.Network(networkId)
			return server.HandleHook(ctx, hello, networkId, network, &HookEventParams{Payload: payload, ByteCount: int64(len(payload))})
		})
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runs, err := hosted.Runs()
	if err != nil {
		t.Fatal(err)
	}
	index, err := server.binder.indexFor(ctx, runs)
	if err != nil {
		t.Fatal(err)
	}
	runId := index.sessionRunIds[runSessionKey{harness: "claude-code", sessionId: "s1"}]

	testSidecar.Instance().Lock()
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateLocked); err != nil {
		t.Fatal(err)
	}
	if err := claude.ToolCall("s1", true, "WebFetch", map[string]any{"url": "https://docs.example/locked"}); err != nil {
		t.Fatalf("a web tool's hook while Locked: %s", err)
	}
	if !runs.Tainted(runId) {
		t.Error("this process forgot the taint it spooled")
	}

	// a daemon that kept nothing in memory: new run store and spool objects over the same files, and a new server
	settings := sidecar.DefaultSidecarSettings()
	restartedRuns, err := sidecar.NewRunStore(hosted.LocalStore(), settings.Mcp, clock)
	if err != nil {
		t.Fatal(err)
	}
	restartedSpool, err := sidecar.NewSpool(hosted.LocalStore(), settings.Ingest)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &testRestartedNetwork{hosted: hosted, runs: restartedRuns, spool: restartedSpool}
	daemon.hostNetwork(networkId, restarted)
	server = newServer()
	if err := testSidecar.Instance().Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	if restartedRuns.TaintRecorded(runId) {
		t.Fatal("the run's file held the taint before the replay: the spool carried nothing")
	}
	call := &McpCall{Session: server.newSession(claude.RelayHello("")), NetworkId: networkId, Network: restarted}
	if err := server.binder.readyCall(ctx, call); err != nil {
		t.Fatal(err)
	}
	if call.RunId != runId || !call.Tainted() || !restartedRuns.TaintRecorded(runId) {
		t.Errorf("the first call after unlock acts in %s, tainted %t", call.RunId, call.Tainted())
	}
}
