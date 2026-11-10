//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.4's session limits on a fake clock: a ninth call waits for a slot, a twenty-first W call in a second is refused,
// and a call ends at 30 s.

package mcp

import (
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// With eight calls in flight a ninth waits rather than being refused, and runs once one of the eight returns.
func TestNinthCallWaits(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	block := newTestBlockTool()
	block.install(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	session := server.Sessions()[0]
	waiting := make(chan struct{}, 1)
	session.limits.waitHook = func() {
		waiting <- struct{}{}
	}

	slotCount := server.settings.Mcp.SessionCallCount
	if slotCount != 8 {
		t.Fatalf("SessionCallCount is %d, want §16.4's 8", slotCount)
	}
	responses := []<-chan *testMcpResponse{}
	for i := 0; i < slotCount; i += 1 {
		response := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "x"}})
		select {
		case answer, ok := <-response:
			if !ok {
				conn.stateLock.Lock()
				t.Fatalf("call %d: the session ended: serve %v, read %v", i, conn.serveErr, conn.readErr)
			}
			t.Fatalf("call %d answered before it blocked: %+v %s", i, answer.Error, answer.Result)
		case <-block.entered:
		case <-contextDone(t):
			t.Fatal("no call entered")
		}
		responses = append(responses, response)
	}
	ninth := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "ninth"}})
	select {
	case <-waiting:
	case <-contextDone(t):
		t.Fatal("the ninth call did not wait")
	}
	select {
	case <-block.entered:
		t.Fatal("a ninth call ran with eight in flight")
	default:
	}
	if count := session.limits.inFlightCount(); count != slotCount {
		t.Fatalf("%d calls in flight", count)
	}
	block.released <- struct{}{}
	block.awaitEntered(t)
	for i := 0; i < slotCount; i += 1 {
		block.released <- struct{}{}
	}
	for _, response := range append(responses, ninth) {
		if answer := conn.await(response); answer.Error != nil {
			t.Errorf("a call failed: %s", answer.Error.Message)
		}
	}
}

// Twenty W calls in a second pass and the twenty-first is refused, retryably; time refills the bucket at the rate.
func TestTwentyFirstWriteRefused(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	session := server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	rate := server.settings.Mcp.SessionWriteRate
	if rate.Count != 20 || rate.Burst != 20 || rate.Interval != time.Second {
		t.Fatalf("SessionWriteRate is %+v, want §16.4's 20 a second", rate)
	}
	for i := 0; i < 20; i += 1 {
		if err := session.AdmitWrite(); err != nil {
			t.Fatalf("write %d refused: %s", i+1, err)
		}
	}
	err := session.AdmitWrite()
	if err == nil {
		t.Fatal("the twenty-first write passed")
	}
	if code, retryable := mcpErrorCode(t, err); code != McpCodeRateLimited || !retryable {
		t.Errorf("refused with %d, retryable %t", code, retryable)
	}
	// one token comes back each 50 ms
	clock.Advance(49 * time.Millisecond)
	if session.AdmitWrite() == nil {
		t.Error("a write passed before a token came back")
	}
	clock.Advance(1 * time.Millisecond)
	if err := session.AdmitWrite(); err != nil {
		t.Errorf("a write after 50 ms: %s", err)
	}
	if session.AdmitWrite() == nil {
		t.Error("two writes on one token")
	}
	// a second's idle refills the burst and no more
	clock.Advance(10 * time.Second)
	for i := 0; i < 20; i += 1 {
		if err := session.AdmitWrite(); err != nil {
			t.Fatalf("write %d after an idle second refused: %s", i+1, err)
		}
	}
	if session.AdmitWrite() == nil {
		t.Error("the burst grew past 20 while idle")
	}
}

// A call still running at 30 s is answered with a retryable timeout at once, and its context ends then, not before.
func TestCallTimesOutAt30s(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	block := newTestBlockTool()
	block.install(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	if timeout := server.settings.Mcp.CallTimeout; timeout != 30*time.Second {
		t.Fatalf("CallTimeout is %s, want §16.4's 30 s", timeout)
	}

	response := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "x"}})
	callCtx := block.awaitEntered(t)
	clock.Advance(30*time.Second - time.Nanosecond)
	if callCtx.Err() != nil {
		t.Fatal("the call's context ended before 30 s")
	}
	select {
	case <-response:
		t.Fatal("answered before 30 s")
	default:
	}
	clock.Advance(time.Nanosecond)
	if callCtx.Err() == nil {
		t.Fatal("the call's context outlived 30 s")
	}
	answer := conn.await(response)
	wantMcpError(t, answer, McpCodeTimeout, "time limit")
	if code, retryable := mcpErrorCode(t, responseError(answer)); code != McpCodeTimeout || !retryable {
		t.Errorf("timeout %d, retryable %t", code, retryable)
	}
}

// An error's code and retryable bit, as the wire carries them.
func mcpErrorCode(t *testing.T, err error) (int64, bool) {
	t.Helper()
	code, retryable, ok := McpErrorCode(err)
	if !ok {
		t.Fatalf("not an mcp error: %s", err)
	}
	return code, retryable
}

// A test response's error, as a handler's error would read.
func responseError(response *testMcpResponse) error {
	return &jsonrpc.Error{Code: response.Error.Code, Message: response.Error.Message, Data: response.Error.Data}
}
