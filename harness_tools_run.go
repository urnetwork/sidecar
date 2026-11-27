//go:build !ios_extension && !sidecar_http

// A turn's tool calls (DESIGN-COMPUTE §7.4's Tools and Length stop rows, Pi's executeToolCalls): parallel by default,
// a tool marked sequential making its batch sequential; tool_execution_start in call order, each end as its call
// settles; the writes of a batch, every W and O call, one at a time in call order (the batch's mutation queue), so
// two writes to one file land as the model ordered them; the results journaled and emitted in call order. A response
// cut by length fails every tool call it carries, none run, since their arguments may be truncated.
//
// Each call runs through harnessRunToolCall (harness_tool.go): its profile, its tier and an O call's before-hook, and
// an untrusted result's taint before it returns. A built-in tool's keep: false details are held in memory only: the
// event carries them, the journal never does (§24.9). A call past HarnessSettings.ToolCallSlowAfter calls the turn
// hooks' ToolCallSlow. On a phone no call starts while the app is in the background: the batch pauses at the call
// boundary, and Resume runs what is left.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// What one call came to.
type harnessCallResult struct {
	toolCall   *HarnessPiToolCall
	text       string
	details    json.RawMessage
	keep       bool
	isError    bool
	untrusted  bool
	durationMs *int64
	// whether the tool is built into sidecar, whose keep: false the record honors (§24.9)
	builtIn bool
	// the tool's record stub, SRCH's web search stub, which the journal keeps for a built-in's keep: false result
	searchStub []byte
}

// The tool result message of a settled call; its details left out where they are not to be kept.
func (self *harnessCallResult) message(timestampMs int64, withDetails bool) *HarnessPiMessage {
	details := self.details
	if !withDetails || !self.keep {
		details = nil
	}
	return NewHarnessPiToolResultMessage(self.toolCall.Id, self.toolCall.Name,
		[]*HarnessPiBlock{NewHarnessPiTextBlock(self.text)}, details, self.isError, timestampMs)
}

// The payload a tool_execution_end carries.
func (self *harnessCallResult) payload() *HarnessToolResultPayload {
	return &HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock(self.text)}, Details: self.details}
}

// Runs one call: the tool found in the agent's set, the call built, the hooks told if it runs long.
func (self *harnessAgent) runCall(ctx context.Context, toolCall *HarnessPiToolCall) *harnessCallResult {
	result := &harnessCallResult{toolCall: toolCall, keep: true}
	tool, spec, ok := self.toolSet.tool(toolCall.Name)
	if !ok {
		result.text = fmt.Sprintf("Tool %s not found", toolCall.Name)
		result.isError = true
		return result
	}
	result.builtIn = spec.BuiltIn
	call := NewHarnessCall(&HarnessCallArgs{
		Run:        self.run,
		AgentName:  self.name,
		Profile:    self.profile,
		ToolCallId: toolCall.Id,
		ToolName:   toolCall.Name,
		Emit: func(event *HarnessEvent) error {
			return self.harness.Emit(self.id, event)
		},
		Ask: func(ctx context.Context, request *HarnessUiRequest) (*HarnessUiResponse, error) {
			return self.harness.ui.Ask(ctx, self.run.Id(), self.id, request)
		},
		Attached: func() bool {
			return self.harness.ui.Attached(self.run.Id())
		},
		Workspace: self.workspace,
	})
	stopSlow := self.harness.clock.AfterFunc(self.harness.settings.ToolCallSlowAfter, func() {
		self.hooks(func(hook HarnessTurnHook) { hook.ToolCallSlow(self, toolCall.Id, toolCall.Name) })
	})
	started := self.harness.clock.Now()
	update := func(partial *HarnessToolUpdate) {
		self.emit(NewHarnessToolExecutionUpdateEvent(toolCall.Id, toolCall.Name, toolCall.Arguments,
			&HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock(partial.Text)}, Details: partial.Details}))
	}
	ran, err := harnessRunToolCall(ctx, call, spec, tool, toolCall.Arguments, update)
	stopSlow()
	durationMs := self.harness.clock.Now().Sub(started).Milliseconds()
	result.durationMs = &durationMs
	if err != nil {
		result.text = err.Error()
		result.isError = true
		return result
	}
	result.text = ran.result.Text
	result.details = ran.result.Details
	result.keep = ran.keep
	result.untrusted = ran.result.Trust == HarnessToolUntrusted
	result.searchStub = ran.result.SearchStub
	return result
}

// Whether a call writes: its tool's tier is W or O, or it names no tool the set holds.
func (self *harnessAgent) callWrites(toolCall *HarnessPiToolCall) bool {
	tool, _, ok := self.toolSet.tool(toolCall.Name)
	if !ok {
		return false
	}
	tier := tool.Tier()
	return tier == HarnessToolTierWrite || tier == HarnessToolTierOutward
}

// Whether any call of the batch is a sequential tool's.
func (self *harnessAgent) batchSequential(toolCalls []*HarnessPiToolCall) bool {
	for _, toolCall := range toolCalls {
		if tool, _, ok := self.toolSet.tool(toolCall.Name); ok && tool.Mode() == HarnessToolSequential {
			return true
		}
	}
	return false
}

// Runs a turn's tool calls as the file header says, answering their results in call order. done holds results a
// paused batch already settled, which are kept. errHarnessBackgrounded where the app left the foreground before a call
// started, the batch paused.
func (self *harnessAgent) runTools(ctx context.Context, message *HarnessPiMessage, toolCalls []*HarnessPiToolCall, done []*HarnessPiMessage) ([]*HarnessPiMessage, error) {
	if message.StopReason() == HarnessPiStopLength {
		return self.failTruncated(ctx, toolCalls)
	}
	results := make([]*harnessCallResult, len(toolCalls))
	var emitLock sync.Mutex
	emitEnd := func(result *harnessCallResult) {
		emitLock.Lock()
		defer emitLock.Unlock()
		self.emit(NewHarnessToolExecutionEndEvent(result.toolCall.Id, result.toolCall.Name, result.payload(), result.isError,
			result.durationMs))
	}
	if self.batchSequential(toolCalls) {
		for i, toolCall := range toolCalls {
			if !self.foreground() {
				self.pause(message, toolCalls[i:], done)
				return nil, errHarnessBackgrounded
			}
			self.emit(NewHarnessToolExecutionStartEvent(toolCall.Id, toolCall.Name, toolCall.Arguments))
			results[i] = self.runCall(ctx, toolCall)
			emitEnd(results[i])
			resultMessage, err := self.persistResult(ctx, results[i])
			if err != nil {
				return nil, err
			}
			done = append(done, resultMessage)
		}
		return done, nil
	}
	if !self.foreground() {
		self.pause(message, toolCalls, done)
		return nil, errHarnessBackgrounded
	}
	for _, toolCall := range toolCalls {
		self.emit(NewHarnessToolExecutionStartEvent(toolCall.Id, toolCall.Name, toolCall.Arguments))
	}
	// the batch's mutation queue: each writing call waits for the one before it
	var group sync.WaitGroup
	previousWrite := make(chan struct{})
	close(previousWrite)
	for i, toolCall := range toolCalls {
		writes := self.callWrites(toolCall)
		waitFor := previousWrite
		var finished chan struct{}
		if writes {
			finished = make(chan struct{})
			previousWrite = finished
		}
		group.Add(1)
		go func() {
			defer group.Done()
			if writes {
				defer close(finished)
				select {
				case <-waitFor:
				case <-ctx.Done():
				}
			}
			results[i] = self.runCall(ctx, toolCall)
			emitEnd(results[i])
		}()
	}
	group.Wait()
	for _, result := range results {
		resultMessage, err := self.persistResult(ctx, result)
		if err != nil {
			return nil, err
		}
		done = append(done, resultMessage)
	}
	return done, nil
}

// Journals a settled call's result, before its message's events, its details left out of the journal where they are
// not to be kept, and emits its message_start and message_end with them.
func (self *harnessAgent) persistResult(ctx context.Context, result *harnessCallResult) (*HarnessPiMessage, error) {
	timestampMs := self.harness.clock.Now().UnixMilli()
	journaled := result.message(timestampMs, true)
	tool := &HarnessJournalTool{Name: result.toolCall.Name, BuiltIn: result.builtIn, KeepFalse: !result.keep, SearchStub: result.searchStub}
	if _, err := self.journalMessageOf(ctx, journaled, result.untrusted, "tool "+result.toolCall.Name, tool); err != nil {
		return nil, err
	}
	shown := journaled
	if !result.keep {
		shown = NewHarnessPiToolResultMessage(result.toolCall.Id, result.toolCall.Name,
			[]*HarnessPiBlock{NewHarnessPiTextBlock(result.text)}, result.details, result.isError, timestampMs)
	}
	self.emit(NewHarnessMessageStartEvent(shown))
	self.emit(NewHarnessMessageEndEvent(shown))
	return shown, nil
}

// Fails every tool call of a response cut by length, as Pi does: none runs.
func (self *harnessAgent) failTruncated(ctx context.Context, toolCalls []*HarnessPiToolCall) ([]*HarnessPiMessage, error) {
	messages := []*HarnessPiMessage{}
	for _, toolCall := range toolCalls {
		self.emit(NewHarnessToolExecutionStartEvent(toolCall.Id, toolCall.Name, toolCall.Arguments))
		result := &harnessCallResult{toolCall: toolCall, keep: true, isError: true,
			text: fmt.Sprintf("Tool call %q was not executed: the response hit the output token limit, so its arguments may be truncated. Re-issue the tool call with complete arguments.", toolCall.Name)}
		self.emit(NewHarnessToolExecutionEndEvent(toolCall.Id, toolCall.Name, result.payload(), true, nil))
		message, err := self.persistResult(ctx, result)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

// Keeps what a batch had left when the app left the foreground, for Resume.
func (self *harnessAgent) pause(message *HarnessPiMessage, remaining []*HarnessPiToolCall, done []*HarnessPiMessage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paused = &harnessPause{message: message, remaining: remaining, results: done}
}
