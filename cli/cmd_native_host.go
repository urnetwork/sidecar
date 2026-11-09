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
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The methods the native host relays: the extension's alarms-only surface, each signing nothing and carrying no
// secret either way. status is the state and generation, which the extension shows.
var nativeHostRelayedMethods = []string{
	urMethodStatus,
}

// The longest request id the native host keeps, so a chunked reply's envelope stays within a frame: ids are a number
// or a short string in practice.
const nativeHostMaxIdByteCount = 256

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

// Answers each frame reader carries until it ends between frames, which is a session's normal end. A frame that cannot
// be read ends the session with an error, since the stream cannot be resynced.
func (self *nativeHostRelay) serve(ctx context.Context, reader io.Reader) error {
	for {
		message, err := readNativeHostFrame(reader, int(self.cli.settings.NativeHostRequestByteCount))
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			fmt.Fprintf(self.cli.stderr, "ur native-host: %s\n", err)
			return err
		}
		id, reply := self.answer(ctx, message)
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
	if nativeHostMaxIdByteCount < len(request.Id) {
		return refuse(nil, -32600, "invalid request: an id past 256 bytes")
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

// Calls method on the daemon's control session, unconfirmed, dialing one, and spawning a daemon, when none is open. A
// failure other than the daemon's own refusal drops the session, so the next request dials again.
func (self *nativeHostRelay) call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	callCtx, cancel := context.WithTimeout(ctx, self.cli.settings.CallTimeout)
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
