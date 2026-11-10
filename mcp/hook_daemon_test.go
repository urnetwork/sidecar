//go:build !js && !ios && !android && !sdk_mobile_bind

// hook.event through a real daemon: hook mode's JSON-RPC, the network resolved from the session as §5.8 says, the
// peer pid read from the socket, and the payload bound to a run on a T2 sidecar.

package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestHookMethodThroughDaemon(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, sidecartest.DefaultNetSettings())
	defer net.Close()
	testSidecar, err := net.AddSidecar("daemon", nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := shortMcpTestDirectory(t)
	socketPath := filepath.Join(directory, "s")
	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddSidecar(testSidecar.NetworkId(), testSidecar.Sidecar()); err != nil {
		t.Fatal(err)
	}
	server := NewMcpServer(DaemonOf(daemon), NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version))
	server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) { return false, nil })
	for _, method := range server.DaemonMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	defer func() {
		daemon.Close()
		<-done
	}()

	call := func(harness string, payload string) error {
		client, err := sidecar.DialDaemon(ctx, socketPath, &sidecar.DaemonHello{
			Mode: sidecar.DaemonModeHook, Version: sidecar.Version, Harness: harness,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		return client.Call(ctx, McpHookMethod, &HookEventParams{Payload: json.RawMessage(payload), ByteCount: int64(len(payload))}, false, nil)
	}
	if err := call("codex", `{"session_id":"e2e","hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Update File: a.go\n"}}`); err != nil {
		t.Fatal(err)
	}
	runs, err := testSidecar.Sidecar().Runs()
	if err != nil {
		t.Fatal(err)
	}
	index, err := server.binder.indexFor(ctx, runs)
	if err != nil {
		t.Fatal(err)
	}
	runId, ok := index.sessionRunIds[runSessionKey{harness: "codex", sessionId: "e2e"}]
	if !ok {
		t.Fatal("the hook bound no run")
	}
	run, err := runs.Get(runId)
	if err != nil || run.Tainted || run.ProcessId == 0 {
		t.Fatalf("the run's file: %+v %v", run, err)
	}
	if err := call("codex", `{"session_id":"e2e","hook_event_name":"PostToolUse","tool_name":"shell","tool_input":{"command":["bash","-lc","curl -s https://api.example/x"]}}`); err != nil {
		t.Fatal(err)
	}
	if !runs.TaintRecorded(runId) {
		t.Error("a web tool's hook was acked with its run untainted")
	}
	if err := call("no-such-harness", `{}`); err == nil {
		t.Error("a harness no adapter reads was taken")
	}
	if err := call("codex", `not json`); err == nil {
		t.Error("an unreadable payload was taken without a word")
	}
}
