// ur native-host (§18.8's connectNative path, D-SDK-30): URnetwork's extension reaches the default instance's ur
// daemon through this process until its own Worker (Later). A browser starts it by a manifest (native_host_manifest.go)
// and speaks native messaging's frames on its stdin and stdout (native_host_frame.go); it relays each request to the
// daemon's control mode (§5.8), so the daemon's peer check, its version check and its reply walk hold as for any ur.
//
// It relays only what its allow-list names, a method the extension needs that signs nothing and takes no secret. A
// method an area adds later is refused until it joins the list, so a new Confirm method can never pass by default.
// It never sends ur_confirmed: no call §5.8 signs only on a person's confirmation crosses it, and a request that asks
// for one is refused. A revocation, §5.6's or any call naming one, is answered REVOKE_NOT_CAPABLE here, since the
// extension is alarms-only (§18.4) and not approval-capable (§16.6).
//
// Requests are answered one at a time, in order, on one control session. events (QD-821) long-polls there, so the
// extension's sdk holds one call at a time and reads status between polls. Frames are read a frame ahead, so the
// stream's end is seen while a call runs: a long poll then ends, its session with it, which ends its wait at the
// daemon, and its answer goes nowhere; any other call runs to its answer. A frame that cannot be read ends the session
// once the requests before it are answered.
//
// stdout carries frames and nothing else: every log, refusal and error goes to stderr. A request's reply never holds a
// token, a key or the pass, which the daemon's walk refuses before this process sees it.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The methods the native host relays: the extension's alarms-only surface, each signing nothing and carrying no
// secret either way. status is the state and generation, which the extension shows; events is every event kind of
// the daemon's hosted sidecars, its alarms among them, long-polled past a cursor (QD-821).
var nativeHostRelayedMethods = []string{
	urMethodStatus,
	sidecar.DaemonMethodEvents,
}

// The relayed methods whose call waits on the daemon for an event rather than runs to an answer: the stream's end
// ends such a call at once and closes its session, which ends the wait at the daemon (QD-821), and its answer goes
// nowhere. Every other call runs to its answer, which is written even once the stream has ended.
var nativeHostLongPollMethods = []string{
	sidecar.DaemonMethodEvents,
}

// What a native host answers a revocation, which the extension may not sign (D-SDK-30).
const nativeHostRevokeNotCapable = "REVOKE_NOT_CAPABLE"

func init() {
	registerUrCommand(&urCommand{
		name:    "native-host",
		usage:   "  ur native-host [--parent-window=<window>] [<argument>...]",
		summary: "relay URnetwork's extension to the daemon (a browser runs this)",
		run:     runUrNativeHost,
	})
}

func runUrNativeHost(ctx context.Context, cli *urCli, options docopt.Opts) error {
	arguments, _ := options["<argument>"].([]string)
	ids, err := cli.nativeHostIds()
	if err != nil {
		return err
	}
	if !ids.allowsCaller(arguments) {
		// nothing reaches stdout: a browser that is not URnetwork's extension gets no frame
		return errors.New("the native host serves only URnetwork's extension")
	}
	relay := newNativeHostRelay(cli, nativeHostRelayedMethods)
	defer relay.close()
	return relay.serve(ctx, cli.stdin)
}

// One native host session's relay to the daemon.
type nativeHostRelay struct {
	cli     *urCli
	relayed []string
	// the control session, dialed at the first relayed request and again after it fails
	client *sidecar.DaemonClient
	// ends once the browser's stream does, which a long poll's call ends with; nil before serve
	streamCtx context.Context
}

// A relay of the methods relayed.
func newNativeHostRelay(cli *urCli, relayed []string) *nativeHostRelay {
	return &nativeHostRelay{cli: cli, relayed: relayed}
}

// Ends the control session.
func (self *nativeHostRelay) close() {
	if self.client != nil {
		self.client.Close()
		self.client = nil
	}
}

// Answers each frame reader carries, in order, until it ends between frames, which is a session's normal end. A
// goroutine reads the frames, at most one ahead of the request being answered, so a stream that ends, between frames
// or inside one, ends a long poll in flight at once (nativeHostLongPollMethods). A frame that cannot be read ends the
// session with an error once the requests before it are answered, since the stream cannot be resynced. The reader
// ends with the stream, which in a native host is the process's stdin.
func (self *nativeHostRelay) serve(ctx context.Context, reader io.Reader) error {
	streamCtx, endStream := context.WithCancel(ctx)
	defer endStream()
	self.streamCtx = streamCtx
	type frame struct {
		message []byte
		err     error
	}
	frames := make(chan frame)
	// closed once this returns, so a reader holding a frame nobody takes ends
	served := make(chan struct{})
	defer close(served)
	go func() {
		for {
			message, err := readNativeHostFrame(reader, int(self.cli.settings.NativeHostRequestByteCount))
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// the browser is gone: a long poll in flight ends
				endStream()
			}
			select {
			case frames <- frame{message: message, err: err}:
			case <-served:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		next := <-frames
		if errors.Is(next.err, io.EOF) {
			return nil
		}
		if next.err != nil {
			fmt.Fprintf(self.cli.stderr, "ur native-host: %s\n", next.err)
			return next.err
		}
		id, reply := self.answer(ctx, next.message)
		if reply == nil {
			continue
		}
		if err := writeNativeHostReply(self.cli.stdout, id, reply, self.cli.settings.NativeHostChunkByteCount); err != nil {
			fmt.Fprintf(self.cli.stderr, "ur native-host: %s\n", err)
			return err
		}
	}
}

// A request as the extension sends it: JSON-RPC 2.0, and nothing more, so ur_confirmed or any other field refuses.
type nativeHostRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// A reply as the extension reads it.
type nativeHostResponse struct {
	JsonRpc string                  `json:"jsonrpc"`
	Id      json.RawMessage         `json:"id"`
	Result  json.RawMessage         `json:"result,omitempty"`
	Error   *sidecar.DaemonRpcError `json:"error,omitempty"`
}

// The answer to one message, and its request's id, or a nil answer for a notification, which is neither relayed nor
// answered.
func (self *nativeHostRelay) answer(ctx context.Context, message []byte) (json.RawMessage, []byte) {
	refuse := func(id json.RawMessage, code int, text string) (json.RawMessage, []byte) {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		encoded, err := json.Marshal(&nativeHostResponse{JsonRpc: "2.0", Id: id, Error: &sidecar.DaemonRpcError{Code: code, Message: text}})
		if err != nil {
			return nil, nil
		}
		return id, encoded
	}
	request := &nativeHostRequest{}
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(request); err != nil || decoder.More() {
		return refuse(nil, -32600, "invalid request: JSON-RPC 2.0 with jsonrpc, id, method and params only")
	}
	if self.cli.settings.NativeHostIdByteCount < len(request.Id) {
		return refuse(nil, -32600, fmt.Sprintf("invalid request: an id past %d bytes", self.cli.settings.NativeHostIdByteCount))
	}
	if request.JsonRpc != "2.0" || request.Method == "" {
		return refuse(request.Id, -32600, "invalid request")
	}
	if len(request.Id) == 0 || string(request.Id) == "null" {
		// a notification: no answer, and nothing relayed
		return nil, nil
	}
	if strings.Contains(strings.ToLower(request.Method), "revoke") {
		return refuse(request.Id, sidecar.DaemonRpcFailed, nativeHostRevokeNotCapable)
	}
	if !self.relays(request.Method) {
		return refuse(request.Id, -32601, "the native host does not relay this method")
	}

	result, err := self.call(ctx, request.Method, request.Params)
	if err != nil {
		if self.longPoll(request.Method) && self.streamCtx != nil && self.streamCtx.Err() != nil && ctx.Err() == nil {
			// the stream ended under a long poll: nobody reads its answer
			return nil, nil
		}
		var rpcErr *sidecar.DaemonRpcError
		if errors.As(err, &rpcErr) {
			return refuse(request.Id, rpcErr.Code, rpcErr.Message)
		}
		fmt.Fprintf(self.cli.stderr, "ur native-host: the daemon did not answer %s: %s\n", request.Method, err)
		return refuse(request.Id, sidecar.DaemonRpcFailed, "the daemon did not answer")
	}
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	encoded, err := json.Marshal(&nativeHostResponse{JsonRpc: "2.0", Id: request.Id, Result: result})
	if err != nil {
		return refuse(request.Id, -32603, "internal error")
	}
	return request.Id, encoded
}

// Whether method is on the allow-list.
func (self *nativeHostRelay) relays(method string) bool {
	for _, relayed := range self.relayed {
		if relayed == method {
			return true
		}
	}
	return false
}

// Whether method's call is a long poll, which the stream's end ends.
func (self *nativeHostRelay) longPoll(method string) bool {
	return slices.Contains(nativeHostLongPollMethods, method)
}

// Calls method on the daemon's control session, unconfirmed, dialing one, and spawning a daemon, when none is open. A
// failure other than the daemon's own refusal drops the session, so the next request dials again; a long poll the
// stream's end ended is such a failure, and the daemon's wait ends with the session it drops.
func (self *nativeHostRelay) call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	parent := ctx
	if self.longPoll(method) && self.streamCtx != nil {
		parent = self.streamCtx
	}
	callCtx, cancel := context.WithTimeout(parent, self.cli.settings.CallTimeout)
	defer cancel()
	if self.client == nil {
		client, err := self.cli.connectDaemon(callCtx, self.cli.hello(sidecar.DaemonModeControl), nil)
		if err != nil {
			return nil, err
		}
		self.client = client
	}
	var callParams any
	if 0 < len(params) {
		callParams = params
	}
	result := json.RawMessage{}
	// never confirmed: no call §5.8 signs only on a person's confirmation crosses the native host
	err := self.client.Call(callCtx, method, callParams, false, &result)
	if err != nil {
		var rpcErr *sidecar.DaemonRpcError
		if !errors.As(err, &rpcErr) {
			self.close()
		}
		return nil, err
	}
	return result, nil
}
