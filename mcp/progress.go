//go:build !js && !ios && !android && !sdk_mobile_bind

// A tool call's progress notifications (MCP's progress utility, https://modelcontextprotocol.io/specification/
// 2025-06-18/basic/utilities/progress; §16.10's async row): a handler reports through McpProgress while it runs, and a
// notification goes out only where the request carried a progressToken. The framework closes a call's reporter before
// it answers, waiting for a send in flight, so no notification follows the result.

package mcp

import (
	"context"
	"sync"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// One call's reporter. Safe for concurrent use: a handler may report from goroutines of its own.
type mcpProgress struct {
	session *gomcp.ServerSession
	token   any

	stateLock sync.Mutex
	closed    bool
	// sends in flight, which close waits for
	sending sync.WaitGroup
}

// The reporter of request: one that sends nothing where it carried no progressToken.
func newMcpProgress(request *gomcp.CallToolRequest) *mcpProgress {
	progress := &mcpProgress{}
	if request != nil && request.Params != nil {
		progress.token = request.Params.GetProgressToken()
		progress.session = request.Session
	}
	return progress
}

// Ends the reporter: a send in flight finishes first, and none starts after.
func (self *mcpProgress) close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.sending.Wait()
}

// Sends one notification, unless the reporter ended or the request asked for none.
func (self *mcpProgress) send(ctx context.Context, params *gomcp.ProgressNotificationParams) {
	if self.token == nil || self.session == nil {
		return
	}
	open := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.sending.Add(1)
		return true
	}()
	if !open {
		return
	}
	defer self.sending.Done()
	params.ProgressToken = self.token
	// a notification lost on a closing session costs only that report
	self.session.NotifyProgress(ctx, params)
}

// The context key of a call's reporter.
type mcpProgressContextKey struct{}

// ctx carrying progress.
func withMcpProgress(ctx context.Context, progress *mcpProgress) context.Context {
	return context.WithValue(ctx, mcpProgressContextKey{}, progress)
}

// Reports the progress of the tool call in ctx: progress of total (0 where no total is known), with message, which is
// constant text or numbers alone, never an argument or a result (I-13). Nothing goes out where the request carried no
// progressToken, outside a call, or once the call answered.
func McpProgress(ctx context.Context, progress float64, total float64, message string) {
	reporter, _ := ctx.Value(mcpProgressContextKey{}).(*mcpProgress)
	if reporter == nil {
		return
	}
	reporter.send(ctx, &gomcp.ProgressNotificationParams{Progress: progress, Total: total, Message: message})
}
