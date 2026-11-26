//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A session over an in-process link with header: the caller's and receiver's codecs, the caller's raw end, with the
// handshake in mode done.
func newTestHarnessRpcSession(t *testing.T, header *HarnessAttachHeader, mode HarnessRpcMode, settings *HarnessSettings) (*HarnessRpcCodec, *HarnessRpcCodec, HarnessAttachLink) {
	t.Helper()
	callerLink, receiverLink := NewHarnessAttachPipe(header, settings)
	caller := NewHarnessRpcCodec(callerLink, HarnessRpcCaller, settings)
	receiver := NewHarnessRpcCodec(receiverLink, HarnessRpcReceiver, settings)
	t.Cleanup(func() {
		caller.Close()
		receiver.Close()
	})
	accepted := make(chan error, 1)
	go func() {
		_, err := receiver.AcceptHello(NewHarnessRpcHelloArgs(mode, HarnessRpcHarnessUr))
		accepted <- err
	}()
	if _, err := caller.Hello(NewHarnessRpcHelloArgs(mode, HarnessRpcHarnessUr)); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	return caller, receiver, callerLink
}

// The person's carried header, as a session ur ssh carries.
func testHarnessPersonHeader() *HarnessAttachHeader {
	return &HarnessAttachHeader{SidecarId: NewId(), Mode: HarnessAttachModeCarried, Origin: HarnessPersonOrigin()}
}

// Sends line raw from the caller's end, and answers what the receiver read of it, with the response the caller read
// where the receiver refused it.
func testHarnessRpcSend(t *testing.T, caller *HarnessRpcCodec, receiver *HarnessRpcCodec, callerLink HarnessAttachLink, line string) (*HarnessRpcCommand, *HarnessRpcResponse) {
	t.Helper()
	if _, err := callerLink.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	command, err := receiver.ReadCommand()
	if err == nil {
		return command, nil
	}
	refusal := &HarnessRpcRefusal{}
	if !errors.As(err, &refusal) {
		t.Fatalf("%s: %v", line, err)
	}
	response, _, err := caller.ReadRecord()
	if err != nil || response == nil {
		t.Fatalf("%s: no response, %v", line, err)
	}
	return nil, response
}

// The lines of a golden file.
func testHarnessRpcGolden(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "harness", "rpc", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// line compacted, as Pi's JSON.stringify writes it.
func testHarnessRpcCompact(t *testing.T, line string) string {
	t.Helper()
	compacted := &bytes.Buffer{}
	if err := json.Compact(compacted, []byte(line)); err != nil {
		t.Fatal(err)
	}
	return compacted.String()
}

// Pi 1.5.0's command and response lines, as the pinned PiG's documentation and tests write them, read and written back
// member for member in Pi's order; the codec's own responses are those bytes, its unknown-command refusal among them.
func TestHarnessRpcGoldensMatchPig(t *testing.T) {
	for _, line := range testHarnessRpcGolden(t, "commands.jsonl") {
		command, origin, err := ParseHarnessRpcCommand([]byte(line))
		if err != nil || origin != nil {
			t.Fatalf("%s: %v", line, err)
		}
		encoded, err := command.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != testHarnessRpcCompact(t, line) {
			t.Errorf("%s wrote back as %s", line, encoded)
		}
	}
	responses := testHarnessRpcGolden(t, "responses.jsonl")
	for _, line := range responses {
		response, err := ParseHarnessRpcResponse([]byte(line))
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		encoded, err := response.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != testHarnessRpcCompact(t, line) {
			t.Errorf("%s wrote back as %s", line, encoded)
		}
	}
	built := func(response *HarnessRpcResponse, err error) string {
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := response.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	for _, c := range []struct {
		built string
		line  int
	}{
		{built: built(NewHarnessRpcSuccess("req-2", HarnessRpcPrompt, map[string]string{"disposition": "started"})), line: 7},
		{built: built(NewHarnessRpcFailure("req-3", HarnessRpcSetModel, "Model not found: invalid/model"), nil), line: 8},
		{built: built(NewHarnessRpcSuccess("", HarnessRpcAbort, nil)), line: 4},
	} {
		if want := testHarnessRpcCompact(t, responses[c.line-1]); c.built != want {
			t.Errorf("built %s, Pi writes %s", c.built, want)
		}
	}

	caller, receiver, callerLink := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeSession, nil)
	if _, response := testHarnessRpcSend(t, caller, receiver, callerLink, `{"id":"test-id","type":"does_not_exist"}`); response == nil ||
		built(response, nil) != responses[9] {
		t.Fatalf("the unknown command answered %+v, Pi writes %s", response, responses[9])
	}
}

// A command with no id, an empty one or one that is no string is refused with a failed response and run never, the
// session going on; the calling end refuses to send one.
func TestHarnessRpcCommandWithoutIdRefused(t *testing.T) {
	caller, receiver, callerLink := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeSession, nil)
	for _, line := range []string{`{"type":"get_state"}`, `{"id":"","type":"get_state"}`, `{"id":7,"type":"get_state"}`} {
		command, response := testHarnessRpcSend(t, caller, receiver, callerLink, line)
		if command != nil || response == nil || response.Success || response.Id != "" {
			t.Errorf("%s: %+v, %+v", line, command, response)
		}
	}
	if command, _ := testHarnessRpcSend(t, caller, receiver, callerLink, `{"id":"g","type":"get_state"}`); command == nil ||
		command.Id != "g" || command.Origin.Kind != HarnessOriginPerson {
		t.Fatalf("the session did not go on: %+v", command)
	}
	if err := caller.WriteCommand(nil, NewHarnessRpcCommand("", HarnessRpcGetState)); !errors.Is(err, ErrHarnessRpcRefused) {
		t.Fatalf("the caller sent a command with no id: %v", err)
	}
}

// In the management mode Pi's six commands and ui_response each name their agent, one without is refused, Pi's other
// commands stay in the session mode, and the Harness's own commands are read; the session mode refuses those.
func TestHarnessManageCommandWithoutAgentRefused(t *testing.T) {
	caller, receiver, callerLink := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeManage, nil)
	refused := []string{
		`{"id":"1","type":"prompt","message":"hi"}`,
		`{"id":"2","type":"abort"}`,
		`{"id":"3","type":"get_messages","agent":""}`,
		`{"id":"4","type":"ui_response","request_id":"ask_1","value":"retry"}`,
		`{"id":"5","type":"set_model","agent":"build-main","provider":"engy","modelId":"glm-5.2"}`,
		`{"id":"6","type":"fork","agent":"build-main","entryId":"abc123"}`,
		`{"id":"7","type":"ui_response","agent":"build-main","value":"retry"}`,
	}
	for _, line := range refused {
		if command, response := testHarnessRpcSend(t, caller, receiver, callerLink, line); command != nil || response == nil || response.Success {
			t.Errorf("%s: %+v, %+v", line, command, response)
		}
	}
	read := []string{
		`{"id":"8","type":"prompt","agent":"build-main","message":"hi","streamingBehavior":"steer"}`,
		`{"id":"9","type":"ur_list_agents"}`,
		`{"id":"10","type":"ur_launch_agent","name":"tester","model":"engy-glm-5.2-high","instructions":"Run the tests.","parent":"build-main","effectKey":"k1"}`,
		`{"id":"11","type":"ur_subscribe","from":{"build-main":12},"level":"status"}`,
		`{"id":"12","type":"ui_response","agent":"build-main","request_id":"ask_1","value":"retry"}`,
		`{"id":"13","type":"ur_continue","run":"r","at":"n","act":"continue","confirmation":"c"}`,
	}
	for _, line := range read {
		command, response := testHarnessRpcSend(t, caller, receiver, callerLink, line)
		if command == nil {
			t.Errorf("%s was refused: %+v", line, response)
		}
	}
	sessionCaller, sessionReceiver, sessionLink := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeSession, nil)
	if command, response := testHarnessRpcSend(t, sessionCaller, sessionReceiver, sessionLink, `{"id":"1","type":"ur_list_agents"}`); command != nil || response == nil {
		t.Fatalf("the session mode read ur_list_agents: %+v", command)
	}
	agentless := NewHarnessRpcCommand("x", HarnessRpcPrompt)
	agentless.SetField("message", "hi")
	if err := caller.WriteCommand(nil, agentless); !errors.Is(err, ErrHarnessRpcRefused) {
		t.Fatalf("the caller sent a manage command naming no agent: %v", err)
	}
}

// A handshake whose version, Pi, mode or harness differs is refused and ends the session, as is a first line that is no
// hello; the calling end refuses a receiver whose answer differs.
func TestHarnessRpcHandshakeVersionMismatchRefused(t *testing.T) {
	cases := []struct {
		name   string
		caller *HarnessRpcHelloArgs
	}{
		{name: "version", caller: &HarnessRpcHelloArgs{Version: HarnessRpcProtocolVersion + 1, Pi: HarnessRpcPiVersion, Mode: HarnessRpcModeSession, Harness: HarnessRpcHarnessUr}},
		{name: "pi", caller: &HarnessRpcHelloArgs{Version: HarnessRpcProtocolVersion, Pi: "1.6.0", Mode: HarnessRpcModeSession, Harness: HarnessRpcHarnessUr}},
		{name: "mode", caller: NewHarnessRpcHelloArgs(HarnessRpcModeManage, HarnessRpcHarnessUr)},
		{name: "harness", caller: NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessPig)},
	}
	for _, c := range cases {
		callerLink, receiverLink := NewHarnessAttachPipe(testHarnessPersonHeader(), nil)
		caller := NewHarnessRpcCodec(callerLink, HarnessRpcCaller, nil)
		receiver := NewHarnessRpcCodec(receiverLink, HarnessRpcReceiver, nil)
		accepted := make(chan error, 1)
		go func() {
			_, err := receiver.AcceptHello(NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr))
			accepted <- err
		}()
		if _, err := caller.Hello(c.caller); !errors.Is(err, ErrHarnessRpcHandshake) {
			t.Errorf("%s: the caller's hello answered %v", c.name, err)
		}
		if err := <-accepted; !errors.Is(err, ErrHarnessRpcHandshake) {
			t.Errorf("%s: the receiver accepted: %v", c.name, err)
		}
		if _, err := receiverLink.Write([]byte("{}\n")); err == nil {
			t.Errorf("%s: the session did not end", c.name)
		}
	}

	// a first line that is no hello
	callerLink, receiverLink := NewHarnessAttachPipe(testHarnessPersonHeader(), nil)
	receiver := NewHarnessRpcCodec(receiverLink, HarnessRpcReceiver, nil)
	callerLink.Write([]byte(`{"id":"1","type":"prompt","message":"hi"}` + "\n"))
	if _, err := receiver.AcceptHello(NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr)); !errors.Is(err, ErrHarnessRpcHandshake) {
		t.Errorf("a prompt before the hello: %v", err)
	}

	// a receiver that answers another version
	callerLink, receiverLink = NewHarnessAttachPipe(testHarnessPersonHeader(), nil)
	caller := NewHarnessRpcCodec(callerLink, HarnessRpcCaller, nil)
	go func() {
		reader := NewHarnessRpcCodec(receiverLink, HarnessRpcReceiver, nil)
		line, err := reader.readLine()
		if err != nil {
			return
		}
		command, _, _ := ParseHarnessRpcCommand(line)
		other := NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr)
		other.Pi = "1.6.0"
		response, _ := NewHarnessRpcSuccess(command.Id, HarnessRpcHello, other)
		reader.WriteResponse(response)
	}()
	if _, err := caller.Hello(NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr)); !errors.Is(err, ErrHarnessRpcHandshake) {
		t.Errorf("a receiver of another Pi: %v", err)
	}
}

// A line past the settings' line bound ends the session, at whichever end reads it, without the line being held whole;
// a line of the bound, its CR and LF aside, passes; an end refuses to write one past the bound; and a receiver whose
// handshake answer is past its bound ends the session rather than leave the caller waiting.
func TestHarnessRpcLineBoundEndsSession(t *testing.T) {
	settings := DefaultHarnessSettings()
	// room for the handshake's answer, the longest line the test does not choose
	settings.RpcLineByteCount = 192
	caller, receiver, callerLink := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeSession, settings)
	prefix := `{"id":"a","type":"prompt","message":"`
	fit := prefix + strings.Repeat("x", settings.RpcLineByteCount-len(prefix)-2) + `"}`
	if len(fit) != settings.RpcLineByteCount {
		t.Fatalf("the fitting line is %d bytes", len(fit))
	}
	if command, response := testHarnessRpcSend(t, caller, receiver, callerLink, fit+"\r"); command == nil {
		t.Fatalf("a line of the bound was refused: %+v", response)
	}
	long := NewHarnessRpcCommand("b", HarnessRpcPrompt)
	long.SetField("message", strings.Repeat("y", settings.RpcLineByteCount))
	if err := caller.WriteCommand(nil, long); !errors.Is(err, ErrHarnessRpcLineTooLong) {
		t.Fatalf("writing past the bound: %v", err)
	}
	if _, err := callerLink.Write([]byte(prefix + strings.Repeat("z", 4*settings.RpcLineByteCount) + "\"}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.ReadCommand(); !errors.Is(err, ErrHarnessRpcLineTooLong) {
		t.Fatalf("a line past the bound: %v", err)
	}
	if _, err := receiver.ReadCommand(); !errors.Is(err, ErrHarnessRpcLineTooLong) {
		t.Fatalf("the session went on: %v", err)
	}
	if _, err := callerLink.Write([]byte("{}\n")); err == nil {
		t.Fatal("the link stayed open")
	}

	tiny := DefaultHarnessSettings()
	tiny.RpcLineByteCount = 96
	tinyCaller, tinyReceiver := NewHarnessAttachPipe(testHarnessPersonHeader(), tiny)
	accepted := make(chan error, 1)
	go func() {
		_, err := NewHarnessRpcCodec(tinyReceiver, HarnessRpcReceiver, tiny).AcceptHello(NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr))
		accepted <- err
	}()
	if _, err := NewHarnessRpcCodec(tinyCaller, HarnessRpcCaller, tiny).Hello(NewHarnessRpcHelloArgs(HarnessRpcModeSession, HarnessRpcHarnessUr)); err == nil {
		t.Fatal("a handshake whose answer is past the bound passed")
	}
	if err := <-accepted; !errors.Is(err, ErrHarnessRpcHandshake) {
		t.Fatalf("the receiver whose answer is past its bound: %v", err)
	}
}

// In a stamped session each command's origin is the stamp the caller's Harness wrote, which no line's writer sets: a
// command refuses an origin member, a stamped line without one or with one that does not read is refused. In a carried
// session every command takes the session's one origin, and a line carrying its own is refused, as is a caller that
// tries to stamp one.
func TestHarnessStampedLineOriginOnlyFromCallersHarness(t *testing.T) {
	stamped := &HarnessAttachHeader{SidecarId: NewId(), Mode: HarnessAttachModeStamped}
	caller, receiver, callerLink := newTestHarnessRpcSession(t, stamped, HarnessRpcModeSession, nil)
	runId, agentId := NewId(), NewId()
	command := NewHarnessRpcCommand("1", HarnessRpcPrompt)
	command.SetField("message", "build it")
	if err := command.SetField("origin", map[string]string{"kind": "person"}); err == nil {
		t.Fatal("a command's writer set its origin")
	}
	if err := caller.WriteCommand(HarnessRunOrigin(runId, agentId, true), command); err != nil {
		t.Fatal(err)
	}
	read, err := receiver.ReadCommand()
	if err != nil {
		t.Fatal(err)
	}
	if read.Origin.Kind != HarnessOriginRun || *read.Origin.RunId != runId || *read.Origin.AgentId != agentId || !read.Origin.Tainted {
		t.Fatalf("the stamp read as %+v", read.Origin)
	}
	if read.Field("origin") != nil {
		t.Fatal("the stamp stayed among the command's members")
	}
	if err := caller.WriteCommand(nil, NewHarnessRpcCommand("2", HarnessRpcGetState)); err == nil {
		t.Fatal("a stamped session's caller sent a line with no origin")
	}
	for _, line := range []string{
		`{"id":"3","type":"get_state"}`,
		`{"id":"4","type":"get_state","origin":{"kind":"admin"}}`,
		`{"id":"5","type":"get_state","origin":{"kind":"run","tainted":false}}`,
		`{"id":"6","type":"get_state","origin":{"kind":"person","extra":1}}`,
	} {
		if command, response := testHarnessRpcSend(t, caller, receiver, callerLink, line); command != nil || response == nil || response.Success {
			t.Errorf("%s: %+v, %+v", line, command, response)
		}
	}

	carried := &HarnessAttachHeader{SidecarId: NewId(), Mode: HarnessAttachModeCarried, Origin: HarnessRunOrigin(runId, agentId, false)}
	caller, receiver, callerLink = newTestHarnessRpcSession(t, carried, HarnessRpcModeSession, nil)
	if command, response := testHarnessRpcSend(t, caller, receiver, callerLink, `{"id":"7","type":"get_state","origin":{"kind":"person"}}`); command != nil || response == nil {
		t.Fatalf("a carried line that named itself the person: %+v", command)
	}
	read, response := testHarnessRpcSend(t, caller, receiver, callerLink, `{"id":"8","type":"get_state"}`)
	if read == nil || read.Origin.Kind != HarnessOriginRun || read.Origin.Tainted || *read.Origin.RunId != runId {
		t.Fatalf("a carried line: %+v, %+v", read, response)
	}
	if err := caller.WriteCommand(HarnessPersonOrigin(), NewHarnessRpcCommand("9", HarnessRpcGetState)); !errors.Is(err, ErrHarnessAttachOriginInvalid) {
		t.Fatalf("a carried session's caller stamped a line: %v", err)
	}

	unknown := HarnessAttachUnknownHeader(NewId())
	caller, receiver, callerLink = newTestHarnessRpcSession(t, unknown, HarnessRpcModeSession, nil)
	if read, _ := testHarnessRpcSend(t, caller, receiver, callerLink, `{"id":"10","type":"get_state"}`); read == nil ||
		read.Origin.Kind != HarnessOriginUnknown || read.Origin.Trusted() {
		t.Fatalf("a session with no origin: %+v", read)
	}
}

// The calling end reads responses and events as they come, an event keeping every member it carried, those this build
// does not know among them.
func TestHarnessRpcRecordsReadResponsesAndEvents(t *testing.T) {
	caller, receiver, _ := newTestHarnessRpcSession(t, testHarnessPersonHeader(), HarnessRpcModeSession, nil)
	response, _ := NewHarnessRpcSuccess("1", HarnessRpcPrompt, map[string]string{"disposition": "started"})
	if err := receiver.WriteResponse(response); err != nil {
		t.Fatal(err)
	}
	event := NewHarnessAgentStartEvent()
	event.Agent, event.Seq = NewId().String(), 1
	event.SetField("futureMember", map[string]bool{"kept": true})
	if err := receiver.WriteEvent(event); err != nil {
		t.Fatal(err)
	}
	readResponse, readEvent, err := caller.ReadRecord()
	if err != nil || readResponse == nil || readEvent != nil || readResponse.Id != "1" || !readResponse.Success {
		t.Fatalf("the response: %+v, %+v, %v", readResponse, readEvent, err)
	}
	readResponse, readEvent, err = caller.ReadRecord()
	if err != nil || readEvent == nil || readResponse != nil || readEvent.Type != HarnessEventAgentStart ||
		readEvent.Field("futureMember") == nil {
		t.Fatalf("the event: %+v, %+v, %v", readResponse, readEvent, err)
	}
}
