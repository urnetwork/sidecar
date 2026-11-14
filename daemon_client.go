//go:build !js && !ios && !android && !ios_extension

// DaemonClient, the caller's side of §5.8's local IPC, which ur's commands and relays use, and a desktop sdk's remote
// backend links too (§18.4), so this file and the hello's and wire's are the daemon's only files without
// sdk_mobile_bind's exclusion. It dials the instance's socket or pipe, sends the hello, reads the daemon's answer,
// and then either calls control methods by JSON-RPC 2.0 or hands the stream to a relay (mcp, git).
//
// A sandboxed macOS app's remote backend cannot reach the instance's socket, so it dials the one in its app-group
// container (daemon_pair.go), whose name DaemonAppGroupSocketName gives both ends; the app supplies the container,
// since a build with sdk_mobile_bind links none of the daemon's own files.
//
// A refused hello is a *DaemonHelloRefusal, whose version_skew tells a just-upgraded ur to restart the daemon rather
// than relay through it. A client is not safe for concurrent use: one call at a time, as the daemon answers them.

package sidecar

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// §5.8's FAILED_PRECONDITION: a network-scoped call with no network to act on, whose message names the networks.
	DaemonRpcFailedPrecondition = -32004
)

// The default instance's socket name in an app-group container, and the prefix of every other's.
const (
	daemonAppGroupDefaultSocketName = "ur"
	daemonAppGroupSocketNamePrefix  = "u"
	daemonAppGroupSocketNameDomain  = "urnetwork-sidecar-v1/app-group-socket/"
)

// The socket's name in an app-group container for instance.
func DaemonAppGroupSocketName(instance string) string {
	if instance == "" || instance == "default" {
		return daemonAppGroupDefaultSocketName
	}
	sum := sha256.Sum256([]byte(daemonAppGroupSocketNameDomain + instance))
	return daemonAppGroupSocketNamePrefix + hex.EncodeToString(sum[:])[:7]
}

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

// What a DaemonClient reads with (QD-702): the bounds of the lines it takes from the daemon.
type DaemonClientSettings struct {
	// The longest hello answer it reads: the daemon's own bound on a hello line, SidecarLocalSettings.HelloByteCount,
	// which both ends share.
	HelloByteCount int64
	// The longest answer line it reads: 64 MiB, far past any result a control method answers, which the daemon bounds
	// no tighter, so a broken daemon cannot make a client hold more.
	AnswerByteCount int64
}

// The defaults, a fresh value each call, the hello's bound read from the daemon's own settings so it has one default.
func DefaultDaemonClientSettings() *DaemonClientSettings {
	return &DaemonClientSettings{
		HelloByteCount:  DefaultSidecarSettings().LocalSettings.HelloByteCount,
		AnswerByteCount: 64 * 1024 * 1024,
	}
}

// A session with the local daemon.
type DaemonClient struct {
	settings *DaemonClientSettings
	conn     net.Conn
	reader   *bufio.Reader
	nextId   int64
}

// Dials socketPath (DaemonSocketPath's for an instance), sends hello and reads the daemon's answer, on
// DefaultDaemonClientSettings. A refusal is a *DaemonHelloRefusal; a daemon that is not there is the dial's error.
func DialDaemon(ctx context.Context, socketPath string, hello *DaemonHello) (*DaemonClient, error) {
	return DialDaemonWithSettings(ctx, socketPath, hello, DefaultDaemonClientSettings())
}

// DialDaemon on settings.
func DialDaemonWithSettings(ctx context.Context, socketPath string, hello *DaemonHello, settings *DaemonClientSettings) (*DaemonClient, error) {
	conn, err := dialDaemon(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	client, err := startDaemonClient(conn, hello, settings)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// Sends hello on conn and reads the answer.
func startDaemonClient(conn net.Conn, hello *DaemonHello, settings *DaemonClientSettings) (*DaemonClient, error) {
	encoded, err := encodeDaemonHello(hello)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(encoded); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	line, err := readDaemonLine(reader, settings.HelloByteCount)
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
	return &DaemonClient{settings: settings, conn: conn, reader: reader}, nil
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
	line, err := readDaemonLine(self.reader, self.settings.AnswerByteCount)
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

// The session's stream after the hello, for a relay of an mcp, git or socket session: reads continue past what the
// hello's answer left buffered. Its CloseWrite ends this side's half (DaemonSessionStream).
func (self *DaemonClient) Stream() DaemonSessionStream {
	return &daemonSessionStream{reader: self.reader, conn: self.conn}
}

// A session's stream past its hello, with the half-close a socket session's relay needs: CloseWrite ends what this
// side sends while it reads on, where the connection has halves (a Unix socket); elsewhere it answers
// ErrDaemonNoHalfClose and the relay ends the session whole.
type DaemonSessionStream interface {
	io.ReadWriter
	CloseWrite() error
}

// The connection has no halves to close one of: a Windows pipe.
var ErrDaemonNoHalfClose = errors.New("the daemon session cannot close one half")

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

// Ends the session's connection, both ways.
func (self *daemonSessionStream) Close() error {
	return self.conn.Close()
}

// Ends what this side writes, reads going on, where the connection has halves.
func (self *daemonSessionStream) CloseWrite() error {
	halves, ok := self.conn.(interface{ CloseWrite() error })
	if !ok {
		return ErrDaemonNoHalfClose
	}
	return halves.CloseWrite()
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
