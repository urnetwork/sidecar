//go:build !js && !ios && !android && !sdk_mobile_bind

// McpError (D-MCP-3, I-7): the one error a tool's call answers with, a code, constant text and whether the same call
// may be sent again. go-sdk embeds a returned error's text in the tool's result, so the framework (tool.go) turns
// every error a handler or a check returns into an McpError before go-sdk sees it: one of its own, a JSON-RPC error
// the server already made (mcp.go's newMcpError), a sidecar sentinel it maps to a constant text, or else a constant
// "the tool failed". No text here, nor any the framework writes, holds a call's input, so no error echoes an argument,
// a secret among them.

package mcp

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/urnetwork/sidecar"
)

// The framework's codes, beside mcp.go's, in the range JSON-RPC leaves to servers.
const (
	// The guard, the local allow or the tier refused the call (§16.6's refused-from-MCP table, §8's local allow).
	McpCodeRefused = -32008
	// The result held a credential or a token form, so nothing of it was sent (I-7).
	McpCodeResultRefused = -32009
	// The arguments do not fit the tool's input schema.
	McpCodeInvalidArguments = jsonrpc.CodeInvalidParams
	// The tool failed for a reason it does not say.
	McpCodeFailed = -32010
	// The call needs what this daemon does not offer yet, or cannot read now.
	McpCodeUnavailable = -32011
)

// One tool error: a code, constant text, and whether the same call may be sent again.
type McpError struct {
	Code int64
	// Constant: never a call's input or a value read for it.
	Message   string
	Retryable bool
}

// The text, which is constant.
func (self *McpError) Error() string {
	return self.Message
}

// The wire error go-sdk answers with.
func (self *McpError) wire() *jsonrpc.Error {
	return newMcpError(self.Code, self.Message, self.Retryable)
}

// A tool error of code with constant text.
func NewMcpError(code int64, message string, retryable bool) *McpError {
	return &McpError{Code: code, Message: message, Retryable: retryable}
}

// The refusals the framework answers, each constant.
var (
	errMcpNoCall           = NewMcpError(McpCodeFailed, "the call has no network: send it again", true)
	errMcpNoToolNetwork    = NewMcpError(McpCodeUnavailable, "this daemon cannot check a tool call's grants yet: run ur status in your own terminal", false)
	errMcpInvalidArguments = NewMcpError(McpCodeInvalidArguments, "the arguments do not fit the tool's input schema", false)
	errMcpNoPolicy         = NewMcpError(McpCodeRefused, "no policy is installed to allow the call: run ur status in your own terminal", true)
	errMcpNotAllowed       = NewMcpError(McpCodeRefused, "the network's policy does not allow this call for this sidecar", false)
	errMcpUntaintedUntrust = NewMcpError(McpCodeFailed, "the tool returned untrusted data without tainting its run", false)
	errMcpTaintFailed      = NewMcpError(McpCodeFailed, "the run's taint could not be written, so nothing untrusted is returned", true)
	errMcpResultSecret     = NewMcpError(McpCodeResultRefused, "the result holds a credential or a token, so it is not returned", false)
	errMcpMatcher          = NewMcpError(McpCodeUnavailable, "the daemon's credentials cannot be read to check the result: run ur status in your own terminal", true)
	errMcpTooLarge         = NewMcpError(McpCodeFailed, "the result is too large and names no resource to read it from", false)
	errMcpFailed           = NewMcpError(McpCodeFailed, "the tool failed", false)
	errMcpLocked           = NewMcpError(McpCodeFailedPrecondition, "the keychain is locked: run ur unlock in your own terminal", false)
	errMcpUnenrolled       = NewMcpError(McpCodeFailedPrecondition, "this device is not enrolled in the network: run ur login in your own terminal", false)
	errMcpCanceled         = NewMcpError(McpCodeFailed, "the call was canceled", true)
)

// What reaches go-sdk for err: an McpError's wire form, a JSON-RPC error the server made, a sidecar sentinel's
// constant text, or "the tool failed". nil for nil.
func mcpWireError(err error) error {
	if err == nil {
		return nil
	}
	var mcpError *McpError
	if errors.As(err, &mcpError) {
		return mcpError.wire()
	}
	var wire *jsonrpc.Error
	if errors.As(err, &wire) {
		// the server's own, whose text is constant (mcp.go, limits.go)
		return wire
	}
	switch {
	case errors.Is(err, sidecar.ErrSidecarStoreLocked):
		return errMcpLocked.wire()
	case errors.Is(err, sidecar.ErrSidecarNoIdentity):
		return errMcpUnenrolled.wire()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return errMcpCanceled.wire()
	}
	return errMcpFailed.wire()
}
