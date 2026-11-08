//go:build !js && !ios && !android

// DaemonClient, the caller's side of §5.8's local IPC, which ur's commands and relays use, and a desktop sdk's remote
// backend links too (§18.4), so this file and the hello's and wire's are the daemon's only files without
// sdk_mobile_bind's exclusion. It dials the instance's socket or pipe, sends the hello, reads the daemon's answer,
// and then either calls control methods by JSON-RPC 2.0 or hands the stream to a relay (mcp, git).
//
// A refused hello is a *DaemonHelloRefusal, whose version_skew tells a just-upgraded ur to restart the daemon rather
// than relay through it. A client is not safe for concurrent use: one call at a time, as the daemon answers them.

package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// JSON-RPC 2.0's error codes (https://www.jsonrpc.org/specification#error_object), and this daemon's own, which take
// the range the specification leaves to servers.
const (
	daemonRpcParseError     = -32700
	daemonRpcInvalidRequest = -32600
	daemonRpcMethodNotFound = -32601
	daemonRpcInvalidParams  = -32602
	daemonRpcInternalError  = -32603
	// A Confirm method called from any mode but control, or without the confirmation (D-CORE-13).
	DaemonRpcConfirmationRequired = -32001
	// The method's handler failed. Its message is the error's text, which a handler writes knowing a same-user
	// agent may read it.
	DaemonRpcFailed = -32002
	// The method ran past SidecarLocalSettings.RequestTimeout.
	DaemonRpcTimeout = -32003
)

// A JSON-RPC 2.0 request line. ur_confirmed sits beside params, where only a ur sets it.
type daemonRpcRequest struct {
	JsonRpc     string          `json:"jsonrpc"`
	Id          json.RawMessage `json:"id,omitempty"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params,omitempty"`
	UrConfirmed bool            `json:"ur_confirmed,omitempty"`
}

// A JSON-RPC 2.0 response line.
type daemonRpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *DaemonRpcError `json:"error,omitempty"`
}

// A JSON-RPC 2.0 error object, which DaemonClient.Call returns as its error.
type DaemonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// The code and message, as the daemon wrote them.
func (self *DaemonRpcError) Error() string {
	return fmt.Sprintf("daemon rpc %d: %s", self.Code, self.Message)
}

// The daemon refused the hello: Code is version_skew, malformed or mode, and Version the daemon's.
type DaemonHelloRefusal struct {
	Code    string
	Version string
}

// The refusal's code, which holds nothing of the hello.
func (self *DaemonHelloRefusal) Error() string {
	return "daemon refused the hello: " + self.Code
}

// The longest answer line a client reads: far past any result a control method answers, which the daemon bounds
// no tighter, so a broken daemon cannot make a client hold more.
const daemonClientMaxLineByteCount = 64 * 1024 * 1024

// A session with the local daemon.
type DaemonClient struct {
	conn   net.Conn
	reader *bufio.Reader
	nextId int64
}

// Dials socketPath (DaemonSocketPath's for an instance), sends hello and reads the daemon's answer. A refusal is a
// *DaemonHelloRefusal; a daemon that is not there is the dial's error.
func DialDaemon(ctx context.Context, socketPath string, hello *DaemonHello) (*DaemonClient, error) {
	conn, err := dialDaemon(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	client, err := startDaemonClient(conn, hello)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// Sends hello on conn and reads the answer.
func startDaemonClient(conn net.Conn, hello *DaemonHello) (*DaemonClient, error) {
	encoded, err := encodeDaemonHello(hello)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(encoded); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	line, err := readDaemonLine(reader, daemonHelloMaxByteCount)
	if err != nil {
		return nil, fmt.Errorf("daemon hello: %w", err)
	}
	answer := &daemonHelloAnswer{}
	if err := json.Unmarshal(line, answer); err != nil || answer.UrLocal != daemonLocalProtocol {
		return nil, errors.New("daemon hello: not an answer")
	}
	if answer.Error != "" {
		return nil, &DaemonHelloRefusal{Code: answer.Error, Version: answer.Version}
	}
	return &DaemonClient{conn: conn, reader: reader}, nil
}

// Calls method with params, JSON-encoded, and decodes the result into result when it is not nil. confirmed says the
// person confirmed this call on /dev/tty or in an app's UI (D-CORE-13), which only a control session carries. A
// refusal is a *DaemonRpcError. ctx's end closes the session, since an answer still on its way cannot be framed.
func (self *DaemonClient) Call(ctx context.Context, method string, params any, confirmed bool, result any) error {
	self.nextId += 1
	id := json.RawMessage(strconv.FormatInt(self.nextId, 10))
	request := &daemonRpcRequest{JsonRpc: "2.0", Id: id, Method: method, UrConfirmed: confirmed}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return err
		}
		request.Params = encoded
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() {
		self.conn.Close()
	})
	defer stop()
	if _, err := self.conn.Write(append(encoded, '\n')); err != nil {
		return err
	}
	line, err := readDaemonLine(self.reader, daemonClientMaxLineByteCount)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	response := &daemonRpcResponse{}
	if err := json.Unmarshal(line, response); err != nil || string(response.Id) != string(id) {
		return errors.New("daemon rpc: not this call's answer")
	}
	if response.Error != nil {
		return response.Error
	}
	if result != nil {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return fmt.Errorf("daemon rpc: the result does not decode: %w", err)
		}
	}
	return nil
}

// The session's stream after the hello, for a relay of an mcp or git session: reads continue past what the hello's
// answer left buffered.
func (self *DaemonClient) Stream() io.ReadWriter {
	return &daemonSessionStream{reader: self.reader, conn: self.conn}
}

// Ends the session.
func (self *DaemonClient) Close() error {
	return self.conn.Close()
}

// A session's stream past its hello: reads continue from the buffer the hello was read through.
type daemonSessionStream struct {
	reader *bufio.Reader
	conn   net.Conn
}

// Reads past the hello, from the buffer it was read through.
func (self *daemonSessionStream) Read(p []byte) (int, error) {
	return self.reader.Read(p)
}

// Writes to the session's connection.
func (self *daemonSessionStream) Write(p []byte) (int, error) {
	return self.conn.Write(p)
}

// A line past its bound: the session closes, since what follows cannot be framed.
var errDaemonLineTooLong = errors.New("line past its bound")

// One line without its newline, at most maxByteCount bytes; errDaemonLineTooLong past that, and io.EOF for a stream
// that ends before a newline.
func readDaemonLine(reader *bufio.Reader, maxByteCount int64) ([]byte, error) {
	line := []byte{}
	for {
		chunk, err := reader.ReadSlice('\n')
		if int64(len(line)+len(chunk)) > maxByteCount+1 {
			return nil, errDaemonLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}
