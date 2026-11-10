//go:build !js && !ios && !android && !sdk_mobile_bind

// Package mcp is §16's MCP server inside `ur daemon` (R-MCP-1, R-MCP-3, D-MCP-1, D-MCP-2): one go-sdk ServerSession
// per `ur mcp` relay connection, over IOTransport on the daemon's local socket, so every harness on the host shares one
// client, one keychain and one key set (D-CORE-9). Only `ur` links this package, which cli/ injects as the daemon's
// mcp mode, since the root never imports a child, and so go-sdk reaches no sdk, gomobile or wasm build (D-MCP-1).
//
// The server's half lives here: McpServer holds one go-sdk Server per instructions text, each session connecting to
// the one its value picks at the session's start (D-MCP-29's trap: ServerOptions is copied at NewServer); McpSession
// holds a session's agent, hello and run bindings; limits.go holds §16.4's bounds. The tools, their tiers and the guard
// are MCP-M3-12's, registered through McpServer.Install, so the tool list is one static table; the hooks, run binding
// and coverage lapses are hook*.go's (MCP-M3-15).
//
// Nothing here writes to stdout, which the relay owns, and nothing logs a call's arguments or results (I-13):
// go-sdk's own log reaches the daemon's Logger as its message text alone.

package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/urnetwork/sidecar"
)

// The JSON-RPC errors this server and ur's relay answer, in the range JSON-RPC leaves to servers, clear of go-sdk's
// own (-32002, -32020 to -32022, -32042), and equal to the daemon's control codes where they mean the same.
const (
	// The call ran past SidecarMcpSettings.CallTimeout (§16.4).
	McpCodeTimeout = -32003
	// §5.8's FAILED_PRECONDITION: the call's network is Locked or Unenrolled, or none resolves. The message names what
	// the person runs in their own terminal; MCP never asks for the pass (§16.4).
	McpCodeFailedPrecondition = -32004
	// A W call past the session's rate (§16.4).
	McpCodeRateLimited = -32005
	// ur's relay lost its daemon while the call was in flight, so nothing says whether it ran; the same call may be
	// sent again (§16.4's restarts).
	McpCodeRestarted = -32006
	// The session cannot serve calls: its hello names an agent label that is not one.
	McpCodeInvalidSession = -32007
)

// What each of these errors' data carries.
type McpErrorData struct {
	// Whether the same call may be sent again as it is.
	Retryable bool `json:"retryable"`
}

// err's code and retryable bit when it is a JSON-RPC error, as a handler returns or the wire carries one; ok false
// for any other error. An error without McpErrorData reads not retryable.
func McpErrorCode(err error) (code int64, retryable bool, ok bool) {
	var wire *jsonrpc.Error
	if !errors.As(err, &wire) {
		return 0, false, false
	}
	data := &McpErrorData{}
	if len(wire.Data) != 0 && json.Unmarshal(wire.Data, data) != nil {
		data.Retryable = false
	}
	return wire.Code, data.Retryable, true
}

// A JSON-RPC error of code with constant text, which never echoes a call's input (I-7): go-sdk's wire error, which a
// handler or middleware returns to answer with its code.
func newMcpError(code int64, message string, retryable bool) *jsonrpc.Error {
	data, _ := json.Marshal(&McpErrorData{Retryable: retryable})
	return &jsonrpc.Error{Code: code, Message: message, Data: data}
}

// The context keys of a call.
type mcpSessionContextKey struct{}
type mcpCallContextKey struct{}

// One call's place: the session it came on, the network it acts on, resolved by §5.8's rules before any tool runs,
// and the run it acts in there (hook_bind.go), whose taint Taint and Tainted reach.
type McpCall struct {
	Session   *McpSession
	NetworkId sidecar.Id
	Network   McpNetwork
	// The session's harness process's newest run, or, while no hook has bound it, its placeholder, which reads tainted.
	RunId sidecar.Id
	// RunId first, then each run of a harness above the session, which a taint reaches (hook_bind.go)
	members []sidecar.Id
}

// The session a request came on, which the server's middleware puts in every request's context. Nil outside one.
func McpSessionOf(ctx context.Context) *McpSession {
	session, _ := ctx.Value(mcpSessionContextKey{}).(*McpSession)
	return session
}

// A tools/call or resources/read's call, which the server puts in its context once its network resolves and is
// ready. Nil outside one.
func McpCallOf(ctx context.Context) *McpCall {
	call, _ := ctx.Value(mcpCallContextKey{}).(*McpCall)
	return call
}
