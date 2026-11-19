//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !ios_extension

// SEARCH-M10-29's session test of the control-mode search (§16.10's wire row; §5.8): over a real control session on
// the daemon's Unix socket, search.progress notifications before a search's answer and none after it; and MCP-M10-02's,
// the session's cursors ending with it (D-MCP-25).

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// §16.10's wire row: a search that asks for progress gets search.progress notifications on its session before its
// answer, each holding numbers and fixed words only; one sent once the call answered is dropped, and the next call's
// answer is the next line.
func TestDaemonSearchProgressStreamsBeforeTheAnswer(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 8 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), "rate limiter notes"))
	}
	world := newTestEngineWorld(t, func(settings *SidecarSearchSettings) { settings.PageByteCount = 600 }, documents...)
	fakes := &testSearchBackends{tools: testSearchTools(t, world)}
	started := startTestDaemon(t, nil)
	if err := started.daemon.AddSidecar(NewId(), newSidecarBase(nil, cheapKeychainSettings())); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonSearchMethods(fakes.backends()) {
		if err := started.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	var kept func(method string, params any) error
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.keep", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		kept = call.Notify
		return "kept", nil
	}}); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	notified := []json.RawMessage{}
	result := &SearchToolResult{}
	err := client.CallNotified(context.Background(), DaemonMethodSearch, map[string]any{"query": "limiter", "limit": 8, "progress": true}, false, result,
		func(method string, params json.RawMessage) {
			if method != DaemonMethodSearchProgress {
				t.Errorf("a notification %q", method)
			}
			notified = append(notified, params)
		})
	if err != nil || len(result.Hits) == 0 || len(notified) == 0 {
		t.Fatalf("a streamed search: %v, %d hits, %d notifications", err, len(result.Hits), len(notified))
	}
	for _, params := range notified {
		progress := &SearchToolProgress{}
		if err := json.Unmarshal(params, progress); err != nil || progress.Total == 0 || strings.Contains(string(params), "limiter") {
			t.Fatalf("a notification: %s", params)
		}
	}
	// a search that did not ask streams nothing, and a plain Call reads its answer
	if err := client.Call(context.Background(), DaemonMethodSearch, map[string]any{"query": "limiter"}, false, result); err != nil {
		t.Fatal(err)
	}
	var answer string
	if err := client.Call(context.Background(), "synthetic.keep", nil, false, &answer); err != nil || answer != "kept" || kept == nil {
		t.Fatalf("the keeper: %v %q", err, answer)
	}
	if err := kept("synthetic.late", map[string]int{"n": 1}); err == nil {
		t.Fatal("a notification after its call's answer was sent")
	}
	if err := client.Call(context.Background(), "synthetic.keep", nil, false, &answer); err != nil || answer != "kept" {
		t.Fatalf("the call after a dropped notification: %v %q", err, answer)
	}
}

// How long a test waits for a closed session's end before calling itself broken.
const testDaemonSearchEndTimeout = 30 * time.Second

// D-MCP-25 (MCP-M10-02): a control session's search cursors end with the session, as an MCP session's do: once `ur
// search`'s connection closes, the engine holds no cursor, hit id or limits of it.
func TestDaemonSearchSessionEndEndsCursors(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 4 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), "rate limiter notes"))
	}
	world := newTestEngineWorld(t, nil, documents...)
	fakes := &testSearchBackends{tools: testSearchTools(t, world)}
	backends := fakes.backends()
	ended := make(chan Id, 1)
	backends.sessionEnded = func(session Id) {
		ended <- session
	}
	started := startTestDaemon(t, nil)
	if err := started.daemon.AddSidecar(NewId(), newSidecarBase(nil, cheapKeychainSettings())); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonSearchMethods(backends) {
		if err := started.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	cursorSessions := func() map[Id]bool {
		world.engine.cursors.stateLock.Lock()
		defer world.engine.cursors.stateLock.Unlock()
		sessions := map[Id]bool{}
		for _, cursor := range world.engine.cursors.cursors {
			sessions[cursor.session] = true
		}
		return sessions
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	result := &SearchToolResult{}
	if err := client.Call(context.Background(), DaemonMethodSearch, map[string]any{"query": "limiter", "limit": 1}, false, result); err != nil {
		t.Fatal(err)
	}
	if result.Status.NextCursor == "" || len(cursorSessions()) != 1 {
		t.Fatalf("a first page with a cursor: %+v, %d sessions holding cursors", result.Status, len(cursorSessions()))
	}
	client.Close()
	var session Id
	select {
	case session = <-ended:
	case <-time.After(testDaemonSearchEndTimeout):
		// a bound on a hang, which proves nothing
		t.Fatal("the session's end ended nothing")
	}
	if cursorSessions()[session] || len(cursorSessions()) != 0 {
		t.Fatal("an ended control session's cursor stays")
	}
	world.engine.limits.stateLock.Lock()
	defer world.engine.limits.stateLock.Unlock()
	if _, kept := world.engine.limits.sessions[session]; kept {
		t.Fatal("an ended control session's limits stay")
	}
}
