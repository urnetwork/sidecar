//go:build !ios_extension && !sidecar_http

// The attach link's RPC (DESIGN-COMPUTE §7.10, §7.15, D-HARN-4, D-HARN-5, D-HARN-6; HARN-M14-01): Pi 1.5.0's RPC mode
// on a byte stream, which an attach carries over the bundled SSH (§12) between a caller's Harness and the receiving
// `ur harness rpc` (HARN-M14-02) or PiG's own `pig --mode rpc` behind it: commands from the caller, each with an id;
// responses repeating that id, and §7.6's events, from the receiver.
//
//	framing    one JSON object a line, split on LF alone, never on U+2028 or U+2029, which JSON strings may hold, an
//	           optional CR before it stripped; each line at most HarnessSettings.RpcLineByteCount, a protocol limit
//	           both ends read, and a longer one ends the session, its bytes never held past the bound
//	handshake  the caller's first line is ur_hello {version, pi, mode, harness}: this protocol's version, Pi's whose
//	           RPC it speaks, session or manage, and ur or pig; the receiver answers with its own, or, where any of them
//	           differs, refuses and ends the session, as it does a first line that is no hello (§7.15)
//	session    Pi's prompt (with streamingBehavior), steer, follow_up, abort, get_state, set_model, compact,
//	           get_messages, get_tree, switch_session, fork and clone; sidecar's list_sessions, subscribe {from_seq} and
//	           ui_response {request_id, …}
//	manage     Pi's prompt, steer, follow_up, abort, get_state and get_messages, each naming its agent, Pi's other
//	           commands staying in the session mode; and the Harness's ur_list_agents {}, ur_launch_agent {name, model,
//	           instructions, tools?, budget?, parent, effectKey}, ur_subscribe {from?, agents?, level?},
//	           ui_response {agent, request_id, …} and ur_continue {run, at, act, agent?, model?, confirmation}
//	refusals   a command with no id (a non-empty JSON string), one its mode does not take, a manage command naming no
//	           agent, a ui_response naming no request: each answered with Pi's failed response, the command run never
//	origin     carried: every command's origin is the session's one, from the verified header, and a line that carries
//	           an origin of its own is refused, since no line's writer sets one; stamped: each line's origin member,
//	           which the caller's own Harness stamps (WriteCommand) and never a line's writer, a line without one refused
//
// Pi's member names stay as Pi writes them (streamingBehavior, customInstructions, entryId, sessionPath), sidecar's as
// the design writes them (from_seq, request_id), and a member this build does not know is kept and passed on.
// HarnessAttachLink is the seam SSH's client and server carry, a duplex line stream and the session's verified origin
// header; NewHarnessAttachPipe is one in process, for tests and an in-process attach.
//
// A codec reads on one goroutine at a time and writes whole lines on any (writeLock).

package sidecar

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
)

// This protocol's version, which the handshake carries (§7.15), and the Pi release whose RPC it speaks (§7.3).
const (
	HarnessRpcProtocolVersion = 1
	HarnessRpcPiVersion       = "1.5.0"
)

// A link's RPC mode: one session, or the whole Harness (§7.10's management mode).
type HarnessRpcMode string

const (
	HarnessRpcModeSession HarnessRpcMode = "session"
	HarnessRpcModeManage  HarnessRpcMode = "manage"
)

// The harness that answers on the receiving end (§7.10's harness row).
const (
	HarnessRpcHarnessUr  = "ur"
	HarnessRpcHarnessPig = "pig"
)

// The command types of Pi's RPC the link carries, and sidecar's.
const (
	HarnessRpcPrompt        = "prompt"
	HarnessRpcSteer         = "steer"
	HarnessRpcFollowUp      = "follow_up"
	HarnessRpcAbort         = "abort"
	HarnessRpcGetState      = "get_state"
	HarnessRpcSetModel      = "set_model"
	HarnessRpcCompact       = "compact"
	HarnessRpcGetMessages   = "get_messages"
	HarnessRpcGetTree       = "get_tree"
	HarnessRpcSwitchSession = "switch_session"
	HarnessRpcFork          = "fork"
	HarnessRpcClone         = "clone"

	HarnessRpcListSessions = "list_sessions"
	HarnessRpcSubscribe    = "subscribe"
	HarnessRpcUiResponse   = "ui_response"

	HarnessRpcHello           = "ur_hello"
	HarnessRpcListAgents      = "ur_list_agents"
	HarnessRpcLaunchAgent     = "ur_launch_agent"
	HarnessRpcManageSubscribe = "ur_subscribe"
	HarnessRpcContinue        = "ur_continue"
)

// A response line's type, and the command Pi's response names for a line that did not parse.
const (
	harnessRpcResponseType = "response"
	harnessRpcParseCommand = "parse"
)

// The commands each mode takes, beside the hello; in manage, Pi's that name their agent.
var (
	harnessRpcSessionCommands = []string{
		HarnessRpcPrompt, HarnessRpcSteer, HarnessRpcFollowUp, HarnessRpcAbort, HarnessRpcGetState, HarnessRpcSetModel,
		HarnessRpcCompact, HarnessRpcGetMessages, HarnessRpcGetTree, HarnessRpcSwitchSession, HarnessRpcFork, HarnessRpcClone,
		HarnessRpcListSessions, HarnessRpcSubscribe, HarnessRpcUiResponse,
	}
	harnessRpcManageAgentCommands = []string{
		HarnessRpcPrompt, HarnessRpcSteer, HarnessRpcFollowUp, HarnessRpcAbort, HarnessRpcGetState, HarnessRpcGetMessages,
	}
	harnessRpcManageCommands = append(slices.Clone(harnessRpcManageAgentCommands),
		HarnessRpcListAgents, HarnessRpcLaunchAgent, HarnessRpcManageSubscribe, HarnessRpcUiResponse, HarnessRpcContinue)
)

var (
	// A line past HarnessSettings.RpcLineByteCount: the session ends.
	ErrHarnessRpcLineTooLong = errors.New("an rpc line is past the line bound, so the session ends")
	// The session ended: the link closed, or a line ended it.
	ErrHarnessRpcClosed = errors.New("the rpc session ended")
	// The handshake's versions, mode or harness differ, or the first line is no hello: the session ends.
	ErrHarnessRpcHandshake = errors.New("the rpc handshake does not match, so the session ends")
	// A command refused and answered with a failed response, the session going on.
	ErrHarnessRpcRefused = errors.New("the rpc command was refused")
	// A line that is no command or response this build reads.
	ErrHarnessRpcMalformed = errors.New("the rpc line is malformed")
)

// A refused command: the failed response written for it, and why.
type HarnessRpcRefusal struct {
	Response *HarnessRpcResponse
}

// The response's error.
func (self *HarnessRpcRefusal) Error() string {
	return fmt.Sprintf("%s: %s", ErrHarnessRpcRefused, self.Response.Error)
}

// A refusal is ErrHarnessRpcRefused.
func (self *HarnessRpcRefusal) Unwrap() error {
	return ErrHarnessRpcRefused
}

// One command line: its id, its type, its origin, and its other members as written.
type HarnessRpcCommand struct {
	// A non-empty string a command must carry; empty where the line had none.
	Id   string
	Type string
	// The command's origin: on the receiving end the session's (carried) or the line's stamp (stamped), set by the
	// codec; on the calling end WriteCommand takes it from its caller, never from a member.
	Origin *HarnessOrigin

	fields harnessPiObject
}

// A command of commandType with id and no members yet.
func NewHarnessRpcCommand(id string, commandType string) *HarnessRpcCommand {
	return &HarnessRpcCommand{Id: id, Type: commandType}
}

// The members only the codec writes: the envelope's and the stamp's.
func harnessRpcCommandEnvelope(name string) bool {
	return name == "id" || name == "type" || name == "origin"
}

// Sets the member named name where it stands, or appends it. id, type and origin are refused: the origin is stamped by
// the codec from its caller, never set by a line's writer.
func (self *HarnessRpcCommand) SetField(name string, value any) error {
	if harnessRpcCommandEnvelope(name) {
		return fmt.Errorf("%w: %s is the envelope's", ErrHarnessRpcMalformed, name)
	}
	return self.fields.set(name, value)
}

// The member named name, as written, or nil.
func (self *HarnessRpcCommand) Field(name string) json.RawMessage {
	return self.fields.get(name)
}

// Decodes the member named name into v; false where there is none or it does not decode.
func (self *HarnessRpcCommand) Decode(name string, v any) bool {
	return self.fields.decode(name, v)
}

// The agent a management command names, or empty.
func (self *HarnessRpcCommand) Agent() string {
	return self.fields.str("agent")
}

// The command as Pi writes a line: id where set, type, then its members in order.
func (self *HarnessRpcCommand) MarshalJSON() ([]byte, error) {
	object := harnessPiObject{}
	if self.Id != "" {
		object.set("id", self.Id)
	}
	object.set("type", self.Type)
	object = append(object, self.fields...)
	return object.MarshalJSON()
}

// Reads a command line in Pi's grammar: a JSON object with a string type, an id that is a string where it is there, and
// any other members, kept as written. An origin member is kept apart, for the codec to judge.
func ParseHarnessRpcCommand(line []byte) (*HarnessRpcCommand, json.RawMessage, error) {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(line); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrHarnessRpcMalformed, err)
	}
	command := &HarnessRpcCommand{}
	var origin json.RawMessage
	for _, field := range object {
		switch field.name {
		case "id":
			if json.Unmarshal(field.value, &command.Id) != nil {
				return nil, nil, fmt.Errorf("%w: a command's id is a string", ErrHarnessRpcMalformed)
			}
		case "type":
			if json.Unmarshal(field.value, &command.Type) != nil {
				return nil, nil, fmt.Errorf("%w: a command's type is a string", ErrHarnessRpcMalformed)
			}
		case "origin":
			origin = field.value
		default:
			command.fields = append(command.fields, field)
		}
	}
	if command.Type == "" {
		return nil, nil, fmt.Errorf("%w: no type", ErrHarnessRpcMalformed)
	}
	return command, origin, nil
}

// One response line (Pi's RpcResponse): the command's id where it had one, its type, whether it succeeded, and its data
// or its error.
type HarnessRpcResponse struct {
	Id      string
	Command string
	Success bool
	// Nil leaves data out; "null" writes it null, as Pi's rpcSuccessNull does.
	Data  json.RawMessage
	Error string
}

// A success response to command id with data, JSON-encoded, nil for none.
func NewHarnessRpcSuccess(id string, command string, data any) (*HarnessRpcResponse, error) {
	response := &HarnessRpcResponse{Id: id, Command: command, Success: true}
	if data != nil {
		encoded, err := harnessPiMarshal(data)
		if err != nil {
			return nil, err
		}
		response.Data = encoded
	}
	return response, nil
}

// A failed response to command id, its error message as Pi writes one.
func NewHarnessRpcFailure(id string, command string, message string) *HarnessRpcResponse {
	return &HarnessRpcResponse{Id: id, Command: command, Error: message}
}

// The response as Pi writes it: id where set, type, command, success, then data or error.
func (self *HarnessRpcResponse) MarshalJSON() ([]byte, error) {
	object := harnessPiObject{}
	if self.Id != "" {
		object.set("id", self.Id)
	}
	object.set("type", harnessRpcResponseType)
	object.set("command", self.Command)
	object.set("success", self.Success)
	if self.Data != nil {
		compacted, err := harnessPiCompact(self.Data)
		if err != nil {
			return nil, err
		}
		object.setRaw("data", compacted)
	}
	if !self.Success || self.Error != "" {
		object.set("error", self.Error)
	}
	return object.MarshalJSON()
}

// Reads a response line.
func ParseHarnessRpcResponse(line []byte) (*HarnessRpcResponse, error) {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(line); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessRpcMalformed, err)
	}
	if object.str("type") != harnessRpcResponseType {
		return nil, fmt.Errorf("%w: no response", ErrHarnessRpcMalformed)
	}
	response := &HarnessRpcResponse{Id: object.str("id"), Command: object.str("command"), Error: object.str("error"), Data: object.get("data")}
	if !object.decode("success", &response.Success) {
		return nil, fmt.Errorf("%w: a response says whether it succeeded", ErrHarnessRpcMalformed)
	}
	return response, nil
}

// The handshake both ends state (§7.15).
type HarnessRpcHelloArgs struct {
	Version int            `json:"version"`
	Pi      string         `json:"pi"`
	Mode    HarnessRpcMode `json:"mode"`
	Harness string         `json:"harness"`
}

// This build's handshake for mode and harness.
func NewHarnessRpcHelloArgs(mode HarnessRpcMode, harness string) *HarnessRpcHelloArgs {
	return &HarnessRpcHelloArgs{Version: HarnessRpcProtocolVersion, Pi: HarnessRpcPiVersion, Mode: mode, Harness: harness}
}

// Why two handshakes do not match, empty where they do.
func (self *HarnessRpcHelloArgs) mismatch(other *HarnessRpcHelloArgs) string {
	switch {
	case other == nil:
		return "no handshake"
	case self.Version != other.Version:
		return fmt.Sprintf("protocol version %d, this end %d", other.Version, self.Version)
	case self.Pi != other.Pi:
		return fmt.Sprintf("Pi %q, this end %q", other.Pi, self.Pi)
	case self.Mode != other.Mode:
		return fmt.Sprintf("mode %q, this end %q", other.Mode, self.Mode)
	case self.Harness != other.Harness:
		return fmt.Sprintf("harness %q, this end %q", other.Harness, self.Harness)
	}
	return ""
}

// The link both ends speak over: SSH's exec channel (§12.4, §12.8), or an in-process pipe; a duplex stream of lines and
// the session's origin header: on the receiving end what SSH's server verified (§12.5's step 5), on the calling end
// what its sidecar signed.
type HarnessAttachLink interface {
	io.Reader
	io.Writer
	Header() *HarnessAttachHeader
	Close() error
}

// One direction of an in-process link: the bytes written and not yet read, at most capacity of them past the first
// write, so a writer waits for its reader past one line.
type harnessAttachPipeBuffer struct {
	capacity int

	stateLock sync.Mutex
	data      []byte
	closed    bool
	// closed and replaced at each change, so a waiter selects on the channel it read with the state
	changed chan struct{}
}

// A direction holding at most capacity bytes past what an empty one takes.
func newHarnessAttachPipeBuffer(capacity int) *harnessAttachPipeBuffer {
	return &harnessAttachPipeBuffer{capacity: capacity, changed: make(chan struct{})}
}

// Notifies every waiter. With stateLock held.
func (self *harnessAttachPipeBuffer) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// Writes p whole, waiting while the direction is full; io.ErrClosedPipe once it closed.
func (self *harnessAttachPipeBuffer) write(p []byte) (int, error) {
	for {
		changed, err := func() (chan struct{}, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil, io.ErrClosedPipe
			}
			if len(self.data) == 0 || len(self.data)+len(p) <= self.capacity {
				self.data = append(self.data, p...)
				self.notifyWithLock()
				return nil, nil
			}
			return self.changed, nil
		}()
		if err != nil {
			return 0, err
		}
		if changed == nil {
			return len(p), nil
		}
		<-changed
	}
}

// Reads what was written, waiting for some; io.EOF once it closed and was read through.
func (self *harnessAttachPipeBuffer) read(p []byte) (int, error) {
	for {
		n, changed, err := func() (int, chan struct{}, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if 0 < len(self.data) {
				n := copy(p, self.data)
				self.data = self.data[n:]
				self.notifyWithLock()
				return n, nil, nil
			}
			if self.closed {
				return 0, nil, io.EOF
			}
			return 0, self.changed, nil
		}()
		if changed == nil {
			return n, err
		}
		<-changed
	}
}

// Ends the direction: writes fail, and reads end once what was written is read.
func (self *harnessAttachPipeBuffer) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.closed {
		self.closed = true
		self.notifyWithLock()
	}
}

// One end of an in-process link.
type harnessAttachPipeEnd struct {
	reads  *harnessAttachPipeBuffer
	writes *harnessAttachPipeBuffer
	header *HarnessAttachHeader
}

// Reads what the other end wrote.
func (self *harnessAttachPipeEnd) Read(p []byte) (int, error) {
	return self.reads.read(p)
}

// Writes for the other end to read, waiting while its direction holds a line.
func (self *harnessAttachPipeEnd) Write(p []byte) (int, error) {
	return self.writes.write(p)
}

// The session's fixed header, a copy.
func (self *harnessAttachPipeEnd) Header() *HarnessAttachHeader {
	header := *self.header
	if self.header.Origin != nil {
		origin := *self.header.Origin
		header.Origin = &origin
	}
	return &header
}

// Ends both directions, as a closed channel does.
func (self *harnessAttachPipeEnd) Close() error {
	self.reads.close()
	self.writes.close()
	return nil
}

// An in-process link with header as both ends' verified origin, the caller's end and the receiver's, each reading what
// the other writes, each direction holding one line at settings' RpcLineByteCount before a writer waits.
func NewHarnessAttachPipe(header *HarnessAttachHeader, settings *HarnessSettings) (HarnessAttachLink, HarnessAttachLink) {
	if settings == nil {
		settings = DefaultHarnessSettings()
	}
	toReceiver := newHarnessAttachPipeBuffer(settings.RpcLineByteCount + 2)
	toCaller := newHarnessAttachPipeBuffer(settings.RpcLineByteCount + 2)
	caller := &harnessAttachPipeEnd{reads: toCaller, writes: toReceiver, header: header}
	receiver := &harnessAttachPipeEnd{reads: toReceiver, writes: toCaller, header: header}
	return caller, receiver
}

// Which end of a link a codec speaks for.
type HarnessRpcRole int

const (
	HarnessRpcCaller HarnessRpcRole = iota + 1
	HarnessRpcReceiver
)

// One end's codec over a link.
type HarnessRpcCodec struct {
	settings *HarnessSettings
	link     HarnessAttachLink
	role     HarnessRpcRole
	header   *HarnessAttachHeader
	reader   *bufio.Reader
	// one whole line at a time
	writeLock sync.Mutex

	stateLock sync.Mutex
	// the session's mode once the handshake passed, empty before
	mode   HarnessRpcMode
	ended  error
	nextId uint64
}

// A codec for role over link, its line bound settings' RpcLineByteCount.
func NewHarnessRpcCodec(link HarnessAttachLink, role HarnessRpcRole, settings *HarnessSettings) *HarnessRpcCodec {
	if settings == nil {
		settings = DefaultHarnessSettings()
	}
	header := link.Header()
	if header == nil {
		// a link that states no origin is an unknown run's
		header = HarnessAttachUnknownHeader(Id{})
	}
	return &HarnessRpcCodec{settings: settings, link: link, role: role, header: header, reader: bufio.NewReader(link)}
}

// The session's verified header.
func (self *HarnessRpcCodec) Header() *HarnessAttachHeader {
	return self.header
}

// The session's mode once the handshake passed, else empty.
func (self *HarnessRpcCodec) Mode() HarnessRpcMode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mode
}

// Ends the session with err, closing the link; the first error stands.
func (self *HarnessRpcCodec) end(err error) error {
	self.stateLock.Lock()
	if self.ended == nil {
		self.ended = err
	}
	ended := self.ended
	self.stateLock.Unlock()
	self.link.Close()
	return ended
}

// Ends the session: the link closes.
func (self *HarnessRpcCodec) Close() error {
	self.end(ErrHarnessRpcClosed)
	return nil
}

// The error that ended the session, nil while it runs.
func (self *HarnessRpcCodec) endedErr() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

// The next line, its LF and an optional CR stripped, never holding more than the bound past it: a longer line ends the
// session.
func (self *HarnessRpcCodec) readLine() ([]byte, error) {
	if err := self.endedErr(); err != nil {
		return nil, err
	}
	bound := self.settings.RpcLineByteCount
	if bound <= 0 {
		return nil, self.end(ErrHarnessRpcLineTooLong)
	}
	line := []byte{}
	for {
		chunk, err := self.reader.ReadSlice('\n')
		line = append(line, chunk...)
		// the content, its CR and LF aside, may take the bound
		if bound+2 < len(line) {
			return nil, self.end(ErrHarnessRpcLineTooLong)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil, self.end(ErrHarnessRpcClosed)
		}
		return nil, self.end(fmt.Errorf("%w: %w", ErrHarnessRpcClosed, err))
	}
	line = bytes.TrimSuffix(line[:len(line)-1], []byte("\r"))
	if bound < len(line) {
		return nil, self.end(ErrHarnessRpcLineTooLong)
	}
	return line, nil
}

// Writes value's JSON as one line, refusing one past the bound, which the other end would refuse.
func (self *HarnessRpcCodec) writeLine(encoded []byte) error {
	if err := self.endedErr(); err != nil {
		return err
	}
	if self.settings.RpcLineByteCount < len(encoded) {
		return fmt.Errorf("%w: %d bytes", ErrHarnessRpcLineTooLong, len(encoded))
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if _, err := self.link.Write(append(encoded, '\n')); err != nil {
		return self.end(fmt.Errorf("%w: %w", ErrHarnessRpcClosed, err))
	}
	return nil
}

// Writes a response line.
func (self *HarnessRpcCodec) WriteResponse(response *HarnessRpcResponse) error {
	encoded, err := response.MarshalJSON()
	if err != nil {
		return err
	}
	return self.writeLine(encoded)
}

// Writes an event line, as the event's Json writes it.
func (self *HarnessRpcCodec) WriteEvent(event *HarnessEvent) error {
	encoded, err := event.Json()
	if err != nil {
		return err
	}
	return self.writeLine(encoded)
}

// Answers command with a failed response and refuses it, the session going on; a refusal that cannot be written ends
// the session, so the caller never waits on an answer that will not come.
func (self *HarnessRpcCodec) refuse(id string, command string, message string) error {
	response := NewHarnessRpcFailure(id, command, message)
	if err := self.WriteResponse(response); err != nil {
		return self.end(fmt.Errorf("%w: %w", ErrHarnessRpcClosed, err))
	}
	return &HarnessRpcRefusal{Response: response}
}

// The receiving end's handshake: reads the caller's first line, which must be ur_hello with an id, and answers own
// where the caller's version, Pi, mode and harness are own's; otherwise answers why and ends the session (§7.15).
func (self *HarnessRpcCodec) AcceptHello(own *HarnessRpcHelloArgs) (*HarnessRpcHelloArgs, error) {
	if self.role != HarnessRpcReceiver {
		return nil, fmt.Errorf("%w: only the receiving end accepts a handshake", ErrHarnessRpcHandshake)
	}
	line, err := self.readLine()
	if err != nil {
		return nil, err
	}
	command, _, err := ParseHarnessRpcCommand(line)
	if err != nil || command.Type != HarnessRpcHello || command.Id == "" {
		id, commandType := "", harnessRpcParseCommand
		if command != nil {
			id, commandType = command.Id, command.Type
		}
		self.WriteResponse(NewHarnessRpcFailure(id, commandType, "the session starts with ur_hello"))
		return nil, self.end(ErrHarnessRpcHandshake)
	}
	theirs := &HarnessRpcHelloArgs{}
	encoded, _ := command.fields.MarshalJSON()
	json.Unmarshal(encoded, theirs)
	if mismatch := own.mismatch(theirs); mismatch != "" {
		self.WriteResponse(NewHarnessRpcFailure(command.Id, HarnessRpcHello, "the handshake does not match: "+mismatch))
		return nil, self.end(fmt.Errorf("%w: %s", ErrHarnessRpcHandshake, mismatch))
	}
	response, err := NewHarnessRpcSuccess(command.Id, HarnessRpcHello, own)
	if err == nil {
		err = self.WriteResponse(response)
	}
	if err != nil {
		// an answer that cannot be written ends the session, so the caller never waits on it
		return nil, self.end(fmt.Errorf("%w: %w", ErrHarnessRpcHandshake, err))
	}
	self.stateLock.Lock()
	self.mode = own.Mode
	self.stateLock.Unlock()
	return theirs, nil
}

// The calling end's handshake: writes ur_hello stating own and reads its answer, which must be the receiver's own
// handshake, matching; a refusal or a mismatch ends the session (§7.15).
func (self *HarnessRpcCodec) Hello(own *HarnessRpcHelloArgs) (*HarnessRpcHelloArgs, error) {
	if self.role != HarnessRpcCaller {
		return nil, fmt.Errorf("%w: only the calling end sends a handshake", ErrHarnessRpcHandshake)
	}
	command := NewHarnessRpcCommand(self.newId(), HarnessRpcHello)
	command.SetField("version", own.Version)
	command.SetField("pi", own.Pi)
	command.SetField("mode", own.Mode)
	command.SetField("harness", own.Harness)
	encoded, err := command.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := self.writeLine(encoded); err != nil {
		return nil, err
	}
	line, err := self.readLine()
	if err != nil {
		return nil, err
	}
	response, err := ParseHarnessRpcResponse(line)
	if err != nil || response.Id != command.Id || response.Command != HarnessRpcHello {
		return nil, self.end(fmt.Errorf("%w: the answer is no handshake", ErrHarnessRpcHandshake))
	}
	if !response.Success {
		return nil, self.end(fmt.Errorf("%w: %s", ErrHarnessRpcHandshake, response.Error))
	}
	theirs := &HarnessRpcHelloArgs{}
	if json.Unmarshal(response.Data, theirs) != nil {
		return nil, self.end(fmt.Errorf("%w: the answer states no handshake", ErrHarnessRpcHandshake))
	}
	if mismatch := own.mismatch(theirs); mismatch != "" {
		return nil, self.end(fmt.Errorf("%w: %s", ErrHarnessRpcHandshake, mismatch))
	}
	self.stateLock.Lock()
	self.mode = own.Mode
	self.stateLock.Unlock()
	return theirs, nil
}

// A fresh command id for this end's own commands.
func (self *HarnessRpcCodec) newId() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextId += 1
	return fmt.Sprintf("ur-%d", self.nextId)
}

// The origin a stamped line's member states, refusing one no stamp may carry.
func harnessRpcStamp(raw json.RawMessage) (*HarnessOrigin, error) {
	stamp := struct {
		Kind    HarnessOriginKind `json:"kind"`
		Run     string            `json:"run"`
		Agent   string            `json:"agent"`
		Tainted bool              `json:"tainted"`
	}{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stamp); err != nil {
		return nil, fmt.Errorf("%w: the origin does not read", ErrHarnessAttachOriginInvalid)
	}
	origin := &HarnessOrigin{Kind: stamp.Kind, Tainted: stamp.Tainted}
	if stamp.Run != "" {
		runId, err := ParseId(stamp.Run)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginInvalid, err)
		}
		origin.RunId = &runId
	}
	if stamp.Agent != "" {
		agentId, err := ParseId(stamp.Agent)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginInvalid, err)
		}
		origin.AgentId = &agentId
	}
	if err := harnessOriginCheck(origin); err != nil {
		return nil, err
	}
	return origin, nil
}

// origin as a stamped line's member writes it.
func harnessRpcStampOf(origin *HarnessOrigin) json.RawMessage {
	object := harnessPiObject{}
	object.set("kind", origin.Kind)
	if origin.RunId != nil {
		object.set("run", origin.RunId.String())
	}
	if origin.AgentId != nil {
		object.set("agent", origin.AgentId.String())
	}
	if origin.Kind == HarnessOriginRun {
		object.set("tainted", origin.Tainted)
	}
	encoded, _ := object.MarshalJSON()
	return encoded
}

// Why mode does not take command, empty where it does: an id, a type the mode takes, a manage command's agent, a
// ui_response's request.
func harnessRpcCommandFault(mode HarnessRpcMode, command *HarnessRpcCommand) string {
	if command.Id == "" {
		return "a command needs an id"
	}
	if command.Type == HarnessRpcHello {
		return "the handshake comes once, first"
	}
	switch mode {
	case HarnessRpcModeSession:
		if !slices.Contains(harnessRpcSessionCommands, command.Type) {
			if slices.Contains(harnessRpcManageCommands, command.Type) {
				return command.Type + " is not a session command"
			}
			return "Unknown command: " + command.Type
		}
	case HarnessRpcModeManage:
		if !slices.Contains(harnessRpcManageCommands, command.Type) {
			if slices.Contains(harnessRpcSessionCommands, command.Type) {
				return command.Type + " stays in the session mode"
			}
			return "Unknown command: " + command.Type
		}
		if (slices.Contains(harnessRpcManageAgentCommands, command.Type) || command.Type == HarnessRpcUiResponse) &&
			command.Agent() == "" {
			return command.Type + " names its agent in the management mode"
		}
	default:
		return "the session has not shaken hands"
	}
	if command.Type == HarnessRpcUiResponse && command.fields.str("request_id") == "" {
		return "a ui_response names its request_id"
	}
	return ""
}

// The receiving end's next command, past the handshake, with its origin: the session's where it is carried, the line's
// stamp where it is stamped. A command its mode refuses is answered with a failed response and the error is a
// *HarnessRpcRefusal, the session going on; a line past the bound, or the link's end, ends the session.
func (self *HarnessRpcCodec) ReadCommand() (*HarnessRpcCommand, error) {
	if self.role != HarnessRpcReceiver {
		return nil, fmt.Errorf("%w: only the receiving end reads commands", ErrHarnessRpcMalformed)
	}
	mode := self.Mode()
	line, err := self.readLine()
	if err != nil {
		return nil, err
	}
	if mode == "" {
		self.WriteResponse(NewHarnessRpcFailure("", harnessRpcParseCommand, "the session starts with ur_hello"))
		return nil, self.end(ErrHarnessRpcHandshake)
	}
	command, stamp, err := ParseHarnessRpcCommand(line)
	if err != nil {
		return nil, self.refuse("", harnessRpcParseCommand, "Failed to parse command: "+err.Error())
	}
	if fault := harnessRpcCommandFault(mode, command); fault != "" {
		return nil, self.refuse(command.Id, command.Type, fault)
	}
	switch self.header.Mode {
	case HarnessAttachModeStamped:
		if stamp == nil {
			return nil, self.refuse(command.Id, command.Type, "a stamped session's line carries its origin")
		}
		origin, err := harnessRpcStamp(stamp)
		if err != nil {
			return nil, self.refuse(command.Id, command.Type, err.Error())
		}
		command.Origin = origin
	default:
		if stamp != nil {
			// the session's one origin stands for every line, and no line's writer chooses its own
			return nil, self.refuse(command.Id, command.Type, "a carried session's lines take the session's origin")
		}
		origin := HarnessUnknownOrigin("")
		if self.header.Origin != nil {
			copied := *self.header.Origin
			origin = &copied
		}
		command.Origin = origin
	}
	return command, nil
}

// The calling end writes command with origin, its own Harness's word for whoever sent it: stamped into the line where
// the session is stamped, and none where it is carried, the session's one origin standing. A command its mode would
// refuse is refused here, unsent.
func (self *HarnessRpcCodec) WriteCommand(origin *HarnessOrigin, command *HarnessRpcCommand) error {
	if self.role != HarnessRpcCaller {
		return fmt.Errorf("%w: only the calling end writes commands", ErrHarnessRpcMalformed)
	}
	mode := self.Mode()
	if command.Type == HarnessRpcHello {
		return fmt.Errorf("%w: the handshake is Hello's", ErrHarnessRpcMalformed)
	}
	if fault := harnessRpcCommandFault(mode, command); fault != "" {
		return fmt.Errorf("%w: %s", ErrHarnessRpcRefused, fault)
	}
	encoded, err := command.MarshalJSON()
	if err != nil {
		return err
	}
	switch self.header.Mode {
	case HarnessAttachModeStamped:
		if err := harnessOriginCheck(origin); err != nil {
			return err
		}
		object := harnessPiObject{}
		if err := object.UnmarshalJSON(encoded); err != nil {
			return err
		}
		object.setRaw("origin", harnessRpcStampOf(origin))
		if encoded, err = object.MarshalJSON(); err != nil {
			return err
		}
	default:
		if origin != nil {
			return fmt.Errorf("%w: a carried session's lines take the session's origin", ErrHarnessAttachOriginInvalid)
		}
	}
	return self.writeLine(encoded)
}

// The calling end's next record: a response, or an event, each read whole, an event's unknown members kept.
func (self *HarnessRpcCodec) ReadRecord() (*HarnessRpcResponse, *HarnessEvent, error) {
	if self.role != HarnessRpcCaller {
		return nil, nil, fmt.Errorf("%w: only the calling end reads records", ErrHarnessRpcMalformed)
	}
	line, err := self.readLine()
	if err != nil {
		return nil, nil, err
	}
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(line); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrHarnessRpcMalformed, err)
	}
	if object.str("type") == harnessRpcResponseType {
		response, err := ParseHarnessRpcResponse(line)
		return response, nil, err
	}
	event := &HarnessEvent{}
	if err := event.UnmarshalJSON(line); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrHarnessRpcMalformed, err)
	}
	return nil, event, nil
}
