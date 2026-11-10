// The relay (§5.8, §16.4): `ur mcp`, and bare ur on a pipe, carry a harness's newline-delimited JSON-RPC to the
// instance's daemon, where MCP runs (§16), after §5.8's hello. If no daemon answers, it spawns `ur daemon` detached,
// once, and dials until it answers (commands.go's connectDaemon). It never logs to stdout, which carries only the
// daemon's lines: what it has to say goes to stderr. A daemon of another version is refused, never relayed through.
//
// Lines pass as they are, one at a time each way, but the relay reads enough of each to survive a daemon restart, so a
// harness keeps its MCP server across one (§16.4):
//
//	in flight    each request sent on a connection and not yet answered; when the connection is lost, each is answered
//	             at once with mcp.McpCodeRestarted, retryable, since nothing says whether it ran
//	session      a pre-2026-07-28 peer's initialize, its notifications/initialized and each subscription, each kept once
//	             the daemon answered it with a result; a resources/unsubscribe drops one
//	reconnect    dial again, spawning a daemon where none answers, every RelayReconnectInterval until one does; then
//	             replay the session under the relay's own ids, keeping their answers from the harness, before any new
//	             line goes through; a harness line read meanwhile waits for the new connection
//	2026-07-28   a peer that sends no initialize keeps no session, so nothing replays, and its long-lived
//	             subscriptions/listen is in flight and fails retryably like any call
//
// A harness line past RelayRequestByteCount is answered as an invalid request and goes no further; a daemon line past
// RelayAnswerByteCount counts as the daemon lost. A daemon of another version ends the relay.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// The relay's own ids for the requests it replays, whose answers it keeps from the harness.
const urRelayReplayIdPrefix = "ur-relay-replay-"

// What a request does to the session the relay replays, once the daemon answers it with a result.
type urRelayKind int

const (
	urRelayKindCall urRelayKind = iota
	urRelayKindInitialize
	urRelayKindSubscribe
	urRelayKindUnsubscribe
)

// One request in flight: its id as sent, the connection it went on, and, for a session request, its line and uri.
type urRelayRequest struct {
	id         json.RawMessage
	connection *urRelayConnection
	kind       urRelayKind
	line       []byte
	uri        string
}

// One connection to the daemon.
type urRelayConnection struct {
	client *sidecar.DaemonClient
	stream io.ReadWriter
	// closed once the connection is lost
	done chan struct{}

	writeLock sync.Mutex
}

// Writes one line to the daemon.
func (self *urRelayConnection) write(line []byte) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	_, err := self.stream.Write(append(bytes.Clone(line), '\n'))
	return err
}

// One harness's relay. Safe for concurrent use: the harness's reader, each connection's reader and a reconnect run at
// once, and state is under stateLock, which is never held across a read or a write.
type urRelay struct {
	ctx       context.Context
	cli       *urCli
	hello     *sidecar.DaemonHello
	spawnArgs []string

	// one line at a time to stdout
	stdoutLock sync.Mutex

	stateLock sync.Mutex
	// the connection harness lines go to, nil while one is being made
	current *urRelayConnection
	// closed once current is set again
	connected chan struct{}
	// connections given up on, so a loss is handled once
	lostConnections map[*urRelayConnection]bool
	// requests sent and not answered, by their id's key
	keyRequests map[string]*urRelayRequest
	// a pre-2026-07-28 peer's session: its answered initialize line, whether initialized followed, and its
	// subscriptions in the order taken
	initializeLine    []byte
	initialized       bool
	subscribeUris     []string
	uriSubscribeLines map[string][]byte
	// replayed requests' id keys, each with the channel its answer closes
	replayKeyAnswered map[string]chan struct{}
	nextReplayId      int
	// why the relay cannot go on, nil while it can; stopped closes when it is set
	fatal   error
	stopped chan struct{}
}

// Relays the harness's stdin to the daemon's session of hello's mode and the session's lines to stdout until the
// harness closes stdin, ctx ends, or a daemon of another version answers.
func relayToDaemon(ctx context.Context, cli *urCli, hello *sidecar.DaemonHello, spawnArgs []string) error {
	client, err := cli.connectDaemon(ctx, hello, spawnArgs)
	if err != nil {
		return err
	}
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	relay := &urRelay{
		ctx:               relayCtx,
		cli:               cli,
		hello:             hello,
		spawnArgs:         spawnArgs,
		connected:         make(chan struct{}),
		lostConnections:   map[*urRelayConnection]bool{},
		keyRequests:       map[string]*urRelayRequest{},
		uriSubscribeLines: map[string][]byte{},
		replayKeyAnswered: map[string]chan struct{}{},
		stopped:           make(chan struct{}),
	}
	connection := relay.newConnection(client)
	relay.publish(connection)
	go relay.readDaemon(connection)
	err = relay.readHarness()
	cancel()
	current := func() *urRelayConnection {
		relay.stateLock.Lock()
		defer relay.stateLock.Unlock()
		return relay.current
	}()
	if current != nil {
		current.client.Close()
	}
	return err
}

// A connection over client.
func (self *urRelay) newConnection(client *sidecar.DaemonClient) *urRelayConnection {
	return &urRelayConnection{client: client, stream: client.Stream(), done: make(chan struct{})}
}

// One line to stdout, for the harness.
func (self *urRelay) toHarness(line []byte) {
	self.stdoutLock.Lock()
	defer self.stdoutLock.Unlock()
	self.cli.stdout.Write(append(bytes.Clone(line), '\n'))
}

// Reads the harness's lines and sends each on, until stdin ends, the relay's context ends or the relay stops.
func (self *urRelay) readHarness() error {
	type harnessLine struct {
		line    []byte
		tooLong bool
		err     error
	}
	lines := make(chan harnessLine)
	// stdin cannot be interrupted, so its reader is a goroutine of its own, which at worst ends with the process
	go func() {
		reader := bufio.NewReader(self.cli.stdin)
		for {
			line, tooLong, err := readUrRelayLine(reader, self.cli.settings.RelayRequestByteCount)
			select {
			case lines <- harnessLine{line: line, tooLong: tooLong, err: err}:
			case <-self.ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-self.ctx.Done():
			return self.ctx.Err()
		case <-self.stopped:
			return self.stoppedError()
		case read := <-lines:
			if read.tooLong {
				self.toHarness([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"the request is too large"}}`))
				continue
			}
			if read.err != nil {
				if errors.Is(read.err, io.EOF) {
					// the harness closed stdin
					return nil
				}
				return read.err
			}
			if err := self.send(read.line); err != nil {
				return err
			}
		}
	}
}

// Why the relay stopped.
func (self *urRelay) stoppedError() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.fatal
}

// Sends one harness line on the current connection, waiting for one while the daemon restarts. A connection lost
// before the line is noted is passed over for the next; one lost after answers the line's request as restarted.
func (self *urRelay) send(line []byte) error {
	for {
		connection, err := self.awaitConnection()
		if err != nil {
			return err
		}
		if !self.note(connection, line) {
			continue
		}
		if err := connection.write(line); err != nil {
			self.lose(connection)
		}
		return nil
	}
}

// The current connection, waiting while there is none.
func (self *urRelay) awaitConnection() (*urRelayConnection, error) {
	for {
		connection, connected, fatal := func() (*urRelayConnection, chan struct{}, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.current, self.connected, self.fatal
		}()
		if fatal != nil {
			return nil, fatal
		}
		if connection != nil {
			return connection, nil
		}
		select {
		case <-connected:
		case <-self.stopped:
		case <-self.ctx.Done():
			return nil, self.ctx.Err()
		}
	}
}

// One JSON-RPC message as the relay reads it: enough to track requests and answers.
type urRelayMessage struct {
	Id     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Error  json.RawMessage `json:"error"`
}

// Whether the message is a request: a method and an id that is not null.
func (self *urRelayMessage) isRequest() bool {
	return self.Method != "" && len(self.Id) != 0 && string(self.Id) != "null"
}

// Whether the message answers a request: an id and no method.
func (self *urRelayMessage) isResponse() bool {
	return self.Method == "" && len(self.Id) != 0 && string(self.Id) != "null"
}

// An id's key: its JSON, compacted.
func urRelayIdKey(id json.RawMessage) string {
	compacted := &bytes.Buffer{}
	if json.Compact(compacted, id) != nil {
		return string(id)
	}
	return compacted.String()
}

// A line's messages, and whether it is a batch. A line that is neither an object nor a batch has none, and passes as
// it is.
func urRelayMessages(line []byte) ([]*urRelayMessage, bool) {
	if bytes.HasPrefix(bytes.TrimLeft(line, " \t\r"), []byte("[")) {
		elements := []json.RawMessage{}
		if json.Unmarshal(line, &elements) != nil {
			return nil, false
		}
		messages := []*urRelayMessage{}
		for _, element := range elements {
			message := &urRelayMessage{}
			if json.Unmarshal(element, message) == nil {
				messages = append(messages, message)
			}
		}
		return messages, true
	}
	message := &urRelayMessage{}
	if json.Unmarshal(line, message) != nil {
		return nil, false
	}
	return []*urRelayMessage{message}, false
}

// Notes a harness line about to go on connection: each request in flight on it, and the session's initialized.
// False when the connection was lost already, so the line waits for the next.
func (self *urRelay) note(connection *urRelayConnection, line []byte) bool {
	messages, batch := urRelayMessages(line)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lostConnections[connection] {
		return false
	}
	for _, message := range messages {
		if message.Method == "notifications/initialized" && !message.isRequest() {
			self.initialized = true
			continue
		}
		if !message.isRequest() {
			continue
		}
		request := &urRelayRequest{id: message.Id, connection: connection, kind: urRelayKindCall}
		if !batch {
			switch message.Method {
			case "initialize":
				request.kind = urRelayKindInitialize
				request.line = bytes.Clone(line)
			case "resources/subscribe", "resources/unsubscribe":
				params := struct {
					Uri string `json:"uri"`
				}{}
				if json.Unmarshal(message.Params, &params) == nil && params.Uri != "" {
					request.kind = urRelayKindSubscribe
					if message.Method == "resources/unsubscribe" {
						request.kind = urRelayKindUnsubscribe
					}
					request.line = bytes.Clone(line)
					request.uri = params.Uri
				}
			}
		}
		self.keyRequests[urRelayIdKey(message.Id)] = request
	}
	return true
}

// Reads a connection's lines until it is lost, each to the harness but the answers to the relay's replays.
func (self *urRelay) readDaemon(connection *urRelayConnection) {
	reader := bufio.NewReader(connection.stream)
	for {
		line, tooLong, err := readUrRelayLine(reader, self.cli.settings.RelayAnswerByteCount)
		if err != nil || tooLong {
			break
		}
		if self.fromDaemon(connection, line) {
			self.toHarness(line)
		}
	}
	self.lose(connection)
}

// Notes one daemon line: an answer ends its request, keeping a session request's line when it succeeded. False for
// the answer to one of the relay's replays, which the harness never sees.
func (self *urRelay) fromDaemon(connection *urRelayConnection, line []byte) bool {
	messages, _ := urRelayMessages(line)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, message := range messages {
		if !message.isResponse() {
			continue
		}
		key := urRelayIdKey(message.Id)
		if answered, ok := self.replayKeyAnswered[key]; ok {
			delete(self.replayKeyAnswered, key)
			close(answered)
			return false
		}
		request, ok := self.keyRequests[key]
		if !ok || request.connection != connection {
			continue
		}
		delete(self.keyRequests, key)
		if len(message.Error) != 0 && string(message.Error) != "null" {
			continue
		}
		switch request.kind {
		case urRelayKindInitialize:
			self.initializeLine = request.line
		case urRelayKindSubscribe:
			if _, ok := self.uriSubscribeLines[request.uri]; !ok {
				self.subscribeUris = append(self.subscribeUris, request.uri)
			}
			self.uriSubscribeLines[request.uri] = request.line
		case urRelayKindUnsubscribe:
			delete(self.uriSubscribeLines, request.uri)
			for i, uri := range self.subscribeUris {
				if uri == request.uri {
					self.subscribeUris = append(self.subscribeUris[:i], self.subscribeUris[i+1:]...)
					break
				}
			}
		}
	}
	return true
}

// Gives up on a connection, once: every request in flight on it answers as restarted, and a reconnect starts. Once
// the relay is ending, its harness gone or its daemon of another version, a lost connection answers nothing.
func (self *urRelay) lose(connection *urRelayConnection) {
	failed, reconnect := func() ([]*urRelayRequest, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.lostConnections[connection] {
			return nil, false
		}
		self.lostConnections[connection] = true
		close(connection.done)
		if self.current == connection {
			self.current = nil
			self.connected = make(chan struct{})
		}
		if self.fatal != nil || self.ctx.Err() != nil {
			return nil, false
		}
		failed := []*urRelayRequest{}
		for key, request := range self.keyRequests {
			if request.connection == connection {
				failed = append(failed, request)
				delete(self.keyRequests, key)
			}
		}
		return failed, true
	}()
	connection.client.Close()
	for _, request := range failed {
		self.toHarness(urRelayRestartedAnswer(request.id))
	}
	if reconnect {
		go self.reconnect()
	}
}

// A request's answer once its connection is lost: retryable, since nothing says whether it ran.
func urRelayRestartedAnswer(id json.RawMessage) []byte {
	type answerError struct {
		Code    int64            `json:"code"`
		Message string           `json:"message"`
		Data    mcp.McpErrorData `json:"data"`
	}
	encoded, _ := json.Marshal(&struct {
		JsonRpc string          `json:"jsonrpc"`
		Id      json.RawMessage `json:"id"`
		Error   answerError     `json:"error"`
	}{
		JsonRpc: "2.0",
		Id:      id,
		Error: answerError{
			Code:    mcp.McpCodeRestarted,
			Message: "the daemon restarted while the call was in flight: send it again",
			Data:    mcp.McpErrorData{Retryable: true},
		},
	})
	return encoded
}

// Makes a new connection, replays the session on it, then hands it the harness's lines. A connection lost while
// replaying has started its own reconnect, and this one gives up. A daemon of another version stops the relay.
func (self *urRelay) reconnect() {
	fmt.Fprintln(self.cli.stderr, "ur mcp: the daemon went away; reconnecting")
	for {
		if self.ctx.Err() != nil {
			return
		}
		client, err := self.cli.connectDaemon(self.ctx, self.hello, self.spawnArgs)
		if err != nil {
			var refusal *sidecar.DaemonHelloRefusal
			if errors.As(err, &refusal) {
				fmt.Fprintf(self.cli.stderr, "ur mcp: %s\n", err)
				self.stop(err)
				return
			}
			fmt.Fprintf(self.cli.stderr, "ur mcp: no daemon yet: %s\n", err)
			select {
			case <-self.ctx.Done():
				return
			case <-time.After(self.cli.settings.RelayReconnectInterval):
			}
			continue
		}
		connection := self.newConnection(client)
		go self.readDaemon(connection)
		if err := self.replay(connection); err != nil {
			return
		}
		self.publish(connection)
		return
	}
}

// Stops the relay for good with err.
func (self *urRelay) stop(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fatal == nil {
		self.fatal = err
		close(self.stopped)
	}
}

// Makes connection the current one, unless it was lost already.
func (self *urRelay) publish(connection *urRelayConnection) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lostConnections[connection] {
		return
	}
	self.current = connection
	close(self.connected)
}

// Replays a pre-2026-07-28 peer's session on connection, each request under a relay id whose answer it waits for: the
// initialize, then initialized, then each subscription. A 2026-07-28 peer kept none, so nothing replays.
func (self *urRelay) replay(connection *urRelayConnection) error {
	initializeLine, initialized, subscribeLines := func() ([]byte, bool, [][]byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		subscribeLines := [][]byte{}
		for _, uri := range self.subscribeUris {
			subscribeLines = append(subscribeLines, self.uriSubscribeLines[uri])
		}
		return self.initializeLine, self.initialized, subscribeLines
	}()
	if initializeLine == nil {
		return nil
	}
	if err := self.replayRequest(connection, initializeLine); err != nil {
		return err
	}
	if initialized {
		if err := connection.write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
			return err
		}
	}
	for _, line := range subscribeLines {
		if err := self.replayRequest(connection, line); err != nil {
			return err
		}
	}
	return nil
}

// Sends line on connection under a relay id, and waits for its answer, which the harness never sees.
func (self *urRelay) replayRequest(connection *urRelayConnection, line []byte) error {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(line, &fields); err != nil {
		return err
	}
	answered := make(chan struct{})
	key := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.nextReplayId += 1
		id, _ := json.Marshal(fmt.Sprintf("%s%d", urRelayReplayIdPrefix, self.nextReplayId))
		fields["id"] = id
		key := urRelayIdKey(id)
		self.replayKeyAnswered[key] = answered
		return key
	}()
	replayed, err := json.Marshal(fields)
	if err == nil {
		err = connection.write(replayed)
	}
	if err == nil {
		select {
		case <-answered:
			return nil
		case <-connection.done:
			err = errors.New("the daemon went away while the session replayed")
		case <-self.ctx.Done():
			err = self.ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.replayKeyAnswered, key)
	return err
}

// One line without its newline. A line past maxByteCount is read through to its end and dropped, and tooLong set. A
// last line with no newline counts as a line; io.EOF once the stream has ended.
func readUrRelayLine(reader *bufio.Reader, maxByteCount int64) ([]byte, bool, error) {
	line := []byte{}
	tooLong := false
	for {
		chunk, err := reader.ReadSlice('\n')
		if !tooLong {
			content := chunk
			if err == nil {
				content = chunk[:len(chunk)-1]
			}
			if maxByteCount < int64(len(line)+len(content)) {
				tooLong = true
				line = nil
			} else {
				line = append(line, content...)
			}
		}
		switch {
		case err == nil:
			if tooLong {
				return nil, true, nil
			}
			return line, false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && tooLong:
			return nil, true, nil
		case errors.Is(err, io.EOF) && 0 < len(line):
			return line, false, nil
		}
		return nil, false, err
	}
}
