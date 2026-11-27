//go:build !ios_extension && !sidecar_http

// The turn loop (DESIGN-COMPUTE §7.4, Pi's agent-loop.js): a prompt runs turns until no work remains. A turn streams
// one assistant response from InferRouter.Infer, each request rendered from the run's journaled nodes through the
// HarnessContextJournal, so a rebuild equals what was sent; then runs its tool calls (harness_tools_run.go); then
// polls the steering queue. Once no tool call or steer remains, the follow-up queue is polled; with none, the run ends.
//
// Events go out in Pi's order: agent_start, turn_start, the prompt's message_start and message_end, the assistant's
// message_start, its message_update deltas and message_end, the tool calls' events and their results' messages,
// turn_end, and at the end agent_end and agent_settled, which carries the Harness's stop reason.
//
// Journal first (IC-19): each context node is journaled before the call that carries it, and the response's message
// before the event that completes it (message_end), so before any tool it asks for can start; a context that cannot
// be journaled is not sent. A call that failed leaves its partial message journaled off the path, beside the leaf, so
// the record keeps each retry and abort and the next call's context does not carry it.
//
// MaxTurnCount turns per prompt end the run with stop reason max_turns. On a phone the loop starts no model call and
// no tool call while the app is in the background, settling with stop reason backgrounded at the item boundary, and
// Resume takes it up again from what it left.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The prompt's message as the model reads it: the text, with images as blocks.
func (self *harnessAgent) userMessage(input *harnessInput) *HarnessPiMessage {
	images := []*HarnessPiBlock{}
	for _, image := range input.images {
		images = append(images, NewHarnessPiImageBlock(image, harnessImageMediaType(image)))
	}
	return NewHarnessPiUserMessage(input.text, images, self.harness.clock.Now().UnixMilli())
}

// An image's media type by its first bytes: png, jpeg, gif or webp, else application/octet-stream.
func harnessImageMediaType(data []byte) string {
	switch {
	case strings.HasPrefix(string(data), "\x89PNG"):
		return "image/png"
	case strings.HasPrefix(string(data), "\xff\xd8\xff"):
		return "image/jpeg"
	case strings.HasPrefix(string(data), "GIF8"):
		return "image/gif"
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp"
	}
	return "application/octet-stream"
}

// What a run came to.
type harnessRunEnd struct {
	stopReason   string
	aborted      bool
	errorMessage string
}

// Runs one prompt to its end, on its own goroutine, and marks the agent idle. It works only while it holds one of the
// Harness's work slots (§7.9's agents at work), a prompt past them waiting its turn, and an abort while it waits settling
// it aborted.
func (self *harnessAgent) runPrompt(ctx context.Context, input *harnessInput) {
	defer self.endRun()
	if err := self.takeWorkSlot(ctx); err != nil {
		self.settle(nil, self.slotEnd(ctx, err))
		return
	}
	defer self.releaseWorkSlot()
	self.emit(NewHarnessAgentStartEvent())
	self.emit(NewHarnessTurnStartEvent())
	newMessages := []*HarnessPiMessage{}
	message := self.userMessage(input)
	// text from an origin that is not trusted tainted the run before it started, and the model reads it fenced
	untrusted, sender := !input.origin.Trusted(), ""
	if untrusted {
		sender = input.origin.SenderLabel()
	}
	if _, err := self.journalMessage(ctx, message, untrusted, sender); err != nil {
		self.settle(newMessages, &harnessRunEnd{stopReason: HarnessStopError, errorMessage: err.Error()})
		return
	}
	self.emit(NewHarnessMessageStartEvent(message))
	self.emit(NewHarnessMessageEndEvent(message))
	newMessages = append(newMessages, message)
	self.settle(newMessages, self.turns(ctx, &newMessages, nil))
}

// Takes up a run paused at an item boundary when the app left the foreground.
func (self *harnessAgent) Resume(ctx context.Context) error {
	paused := func() *harnessPause {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		paused := self.paused
		self.paused = nil
		return paused
	}()
	if paused == nil {
		return nil
	}
	runCtx, err := self.startRun()
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.paused = paused
		}()
		return err
	}
	go func() {
		defer self.endRun()
		if err := self.takeWorkSlot(runCtx); err != nil {
			self.settle(nil, self.slotEnd(runCtx, err))
			return
		}
		defer self.releaseWorkSlot()
		self.emit(NewHarnessAgentStartEvent())
		newMessages := []*HarnessPiMessage{}
		self.settle(newMessages, self.turns(runCtx, &newMessages, paused))
	}()
	return nil
}

// Emits agent_end and agent_settled with the run's end, keeping the run's last assistant message and stop reason for
// agent_wait (harness_launch.go).
func (self *harnessAgent) settle(newMessages []*HarnessPiMessage, end *harnessRunEnd) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.lastStopReason = end.stopReason
		for i := len(newMessages) - 1; 0 <= i; i-- {
			if newMessages[i].Role() == HarnessPiRoleAssistant {
				self.lastMessage = newMessages[i]
				break
			}
		}
	}()
	self.emit(NewHarnessAgentEndEvent(newMessages, false))
	settled := NewHarnessAgentSettledEvent(end.aborted, end.stopReason)
	if end.errorMessage != "" {
		settled.SetField("errorMessage", end.errorMessage)
	}
	self.emit(settled)
	if err := self.harness.journal.TurnEnd(context.Background(), self.run.Id()); err != nil {
		self.harness.log.Warningf("[harness]the turn's entries did not leave: %v", err)
	}
}

// Delivers queued text as user messages before the next request, text from an origin that is not trusted fenced (its
// run was tainted when it was queued).
func (self *harnessAgent) deliver(ctx context.Context, queued []*harnessQueued, newMessages *[]*HarnessPiMessage) error {
	for _, item := range queued {
		message := NewHarnessPiUserMessage(item.text, nil, self.harness.clock.Now().UnixMilli())
		untrusted, sender := !item.origin.Trusted(), ""
		if untrusted {
			sender = item.origin.SenderLabel()
		}
		if _, err := self.journalMessage(ctx, message, untrusted, sender); err != nil {
			return err
		}
		self.emit(NewHarnessMessageStartEvent(message))
		self.emit(NewHarnessMessageEndEvent(message))
		*newMessages = append(*newMessages, message)
	}
	return nil
}

// The turns of one run, from a fresh prompt or from where a pause left them, until no work remains: what it came to.
func (self *harnessAgent) turns(ctx context.Context, newMessages *[]*HarnessPiMessage, paused *harnessPause) *harnessRunEnd {
	turnCount := 0
	first := paused == nil
	pending := []*harnessQueued{}
	for {
		hasMoreToolCalls := true
		for hasMoreToolCalls || 0 < len(pending) {
			if err := ctx.Err(); err != nil {
				return self.aborted()
			}
			resuming := paused != nil
			if !resuming {
				if 0 < self.maxTurns && self.maxTurns <= turnCount {
					return &harnessRunEnd{stopReason: HarnessStopMaxTurns}
				}
				if !first {
					self.emit(NewHarnessTurnStartEvent())
				}
			}
			first = false
			if err := self.deliver(ctx, pending, newMessages); err != nil {
				return &harnessRunEnd{stopReason: HarnessStopError, errorMessage: err.Error()}
			}
			pending = nil

			var message *HarnessPiMessage
			var toolCalls []*HarnessPiToolCall
			var results []*HarnessPiMessage
			if resuming {
				message, toolCalls, results = paused.message, paused.remaining, paused.results
				paused = nil
			} else {
				turnCount += 1
				self.hooks(func(hook HarnessTurnHook) { hook.TurnStart(self) })
				if !self.foreground() {
					return &harnessRunEnd{stopReason: HarnessStopBackgrounded}
				}
				var end *harnessRunEnd
				message, end = self.respond(ctx)
				if end != nil {
					return end
				}
				*newMessages = append(*newMessages, message)
				toolCalls = message.ToolCalls()
			}

			if 0 < len(toolCalls) {
				batch, err := self.runTools(ctx, message, toolCalls, results)
				if err != nil {
					if errors.Is(err, errHarnessBackgrounded) {
						return &harnessRunEnd{stopReason: HarnessStopBackgrounded}
					}
					if ctx.Err() != nil {
						return self.aborted()
					}
					return &harnessRunEnd{stopReason: HarnessStopError, errorMessage: err.Error()}
				}
				results = batch
				*newMessages = append(*newMessages, results...)
			}
			self.emit(NewHarnessTurnEndEvent(message, results))
			self.hooks(func(hook HarnessTurnHook) { hook.TurnEnd(self) })
			if err := self.harness.journal.TurnEnd(ctx, self.run.Id()); err != nil {
				self.harness.log.Warningf("[harness]the turn's entries did not leave: %v", err)
			}
			hasMoreToolCalls = 0 < len(toolCalls)
			pending = self.takeSteering()
		}
		pending = self.takeFollowUps()
		if len(pending) == 0 {
			return &harnessRunEnd{stopReason: HarnessStopEnded}
		}
	}
}

// The run's end on an abort.
func (self *harnessAgent) aborted() *harnessRunEnd {
	return &harnessRunEnd{stopReason: HarnessStopAborted, aborted: true}
}

// Calls each turn hook.
func (self *harnessAgent) hooks(call func(hook HarnessTurnHook)) {
	for _, hook := range self.harness.turnHooks {
		call(hook)
	}
}

// One block of the response as it streams.
type harnessStreamBlock struct {
	kind     string
	text     strings.Builder
	toolCall *HarnessPiToolCall
	closed   bool
}

// The response as it streams: its blocks, its usage and its charge.
type harnessStream struct {
	agent       *harnessAgent
	model       string
	provider    string
	label       ComputeLabel
	maxOutput   int64
	blocks      []*harnessStreamBlock
	toolIndexes map[string]int
	usage       *HarnessPiUsage
	charge      uint64
	started     bool
}

// The assistant message the blocks make so far, with stopReason.
func (self *harnessStream) message(stopReason string, errorMessage string) *HarnessPiMessage {
	content := []*HarnessPiBlock{}
	for _, block := range self.blocks {
		switch block.kind {
		case HarnessPiBlockText:
			content = append(content, NewHarnessPiTextBlock(block.text.String()))
		case HarnessPiBlockThinking:
			content = append(content, NewHarnessPiThinkingBlock(block.text.String()))
		case HarnessPiBlockToolCall:
			content = append(content, NewHarnessPiToolCallBlock(block.toolCall))
		}
	}
	return NewHarnessPiAssistantMessage(&HarnessPiAssistant{
		Content:      content,
		Api:          HarnessPiApi,
		Provider:     self.provider,
		Model:        self.model,
		Usage:        self.usage,
		StopReason:   stopReason,
		TimestampMs:  self.agent.harness.clock.Now().UnixMilli(),
		ErrorMessage: errorMessage,
	})
}

// Emits message_start once.
func (self *harnessStream) start() {
	if self.started {
		return
	}
	self.started = true
	self.agent.emit(NewHarnessMessageStartEvent(self.message(HarnessPiStopPending, "")))
}

// Emits one message_update.
func (self *harnessStream) update(nested *HarnessAssistantMessageEvent) {
	self.start()
	self.agent.emit(NewHarnessMessageUpdateEvent(self.usage, nested))
}

// Closes the open text or thinking block, emitting its end.
func (self *harnessStream) closeOpen() {
	if len(self.blocks) == 0 {
		return
	}
	index := len(self.blocks) - 1
	block := self.blocks[index]
	if block.closed || block.kind == HarnessPiBlockToolCall {
		return
	}
	block.closed = true
	endType := HarnessAssistantEventTextEnd
	if block.kind == HarnessPiBlockThinking {
		endType = HarnessAssistantEventThinkingEnd
	}
	self.update(&HarnessAssistantMessageEvent{Type: endType, ContentIndex: index, Content: block.text.String()})
}

// Appends a text or thinking delta, opening its block where the last is not one of its kind.
func (self *harnessStream) delta(kind string, text string) {
	index := len(self.blocks) - 1
	if index < 0 || self.blocks[index].kind != kind || self.blocks[index].closed {
		self.closeOpen()
		self.blocks = append(self.blocks, &harnessStreamBlock{kind: kind})
		index = len(self.blocks) - 1
		startType := HarnessAssistantEventTextStart
		if kind == HarnessPiBlockThinking {
			startType = HarnessAssistantEventThinkingStart
		}
		self.update(&HarnessAssistantMessageEvent{Type: startType, ContentIndex: index})
	}
	self.blocks[index].text.WriteString(text)
	deltaType := HarnessAssistantEventTextDelta
	if kind == HarnessPiBlockThinking {
		deltaType = HarnessAssistantEventThinkingDelta
	}
	self.update(&HarnessAssistantMessageEvent{Type: deltaType, ContentIndex: index, Delta: text})
}

// Takes one of the router's events.
func (self *harnessStream) take(event *InferEvent) {
	switch event.Kind {
	case InferEventStart:
		self.start()
	case InferEventText:
		self.delta(HarnessPiBlockText, event.Text)
	case InferEventReasoning:
		self.delta(HarnessPiBlockThinking, event.Text)
	case InferEventToolCallStart:
		self.closeOpen()
		toolCall := &HarnessPiToolCall{Id: event.ToolCall.Id, Name: event.ToolCall.Name}
		self.blocks = append(self.blocks, &harnessStreamBlock{kind: HarnessPiBlockToolCall, toolCall: toolCall})
		index := len(self.blocks) - 1
		self.toolIndexes[toolCall.Id] = index
		self.update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallStart, ContentIndex: index,
			Id: toolCall.Id, ToolName: toolCall.Name})
	case InferEventToolCallArgs:
		index, ok := self.toolIndexes[event.ToolCall.Id]
		if !ok {
			return
		}
		block := self.blocks[index]
		block.text.WriteString(event.ToolCall.Arguments)
		self.update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallDelta, ContentIndex: index,
			Delta: event.ToolCall.Arguments})
	case InferEventToolCallEnd:
		index, ok := self.toolIndexes[event.ToolCall.Id]
		if !ok {
			self.closeOpen()
			self.blocks = append(self.blocks, &harnessStreamBlock{kind: HarnessPiBlockToolCall,
				toolCall: &HarnessPiToolCall{Id: event.ToolCall.Id}})
			index = len(self.blocks) - 1
			self.toolIndexes[event.ToolCall.Id] = index
		}
		block := self.blocks[index]
		if event.ToolCall.Name != "" {
			block.toolCall.Name = event.ToolCall.Name
		}
		arguments := event.ToolCall.Arguments
		if arguments == "" {
			arguments = block.text.String()
		}
		block.toolCall.Arguments = []byte(arguments)
		block.closed = true
		self.update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallEnd, ContentIndex: index,
			ToolCall: block.toolCall})
	case InferEventUsage:
		usage := event.Usage
		self.usage = &HarnessPiUsage{Input: int64(usage.InputTokens), Output: int64(usage.OutputTokens),
			CacheRead: int64(usage.CachedTokens), TotalTokens: int64(usage.InputTokens + usage.OutputTokens)}
		if 0 < usage.ReasoningTokens {
			reasoning := int64(usage.ReasoningTokens)
			self.usage.Reasoning = &reasoning
		}
		self.usage.Cost.Total = float64(usage.ChargeNanoUsd) / 1e9
		self.charge += usage.ChargeNanoUsd
		self.agent.addCharge(usage.ChargeNanoUsd)
		self.agent.emit(NewHarnessUsageEvent(&HarnessUsage{Model: self.model, InputTokens: usage.InputTokens,
			OutputTokens: usage.OutputTokens, CachedTokens: usage.CachedTokens, ReasoningTokens: usage.ReasoningTokens,
			ChargeNanoUsd: usage.ChargeNanoUsd, RunNanoUsd: self.agent.runCharge()}))
	case InferEventAttestation:
		self.agent.emit(NewHarnessAttestationEvent(self.model, self.label, event.Attest))
	}
}

// Whether the response was cut by its output limit: its output tokens reached the request's maximum or, with none
// asked, the model's. The router's end names no stop reason, so the usage tells it.
func (self *harnessStream) cutByLength() bool {
	return self.usage != nil && 0 < self.maxOutput && self.maxOutput <= self.usage.Output
}

// Adds a call's charge to the run's total.
func (self *harnessAgent) addCharge(nanoUsd uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.chargeNanoUsd += nanoUsd
}

// The run's total charge.
func (self *harnessAgent) runCharge() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.chargeNanoUsd
}

// One call: the request rendered from the journal, sent through the router, its stream turned into Pi's events; the
// message journaled before message_end. Answers the message, or the router's error with what streamed so far, or a
// fatal error where the journal or the renderer failed, which no retry cures: nothing that would carry an unjournaled
// context is sent, and the run ends.
func (self *harnessAgent) callOnce(ctx context.Context) (*HarnessPiMessage, *InferError, error) {
	if err := self.applyPendingModel(ctx); err != nil {
		refused := &InferError{}
		if errors.As(err, &refused) {
			return nil, refused, nil
		}
		return nil, nil, err
	}
	model := self.currentModel()
	resolution, err := self.harness.modelEntry(ctx, model)
	if err != nil {
		return nil, &InferError{Code: InferErrorModelRefused, Model: model, Message: "the model does not resolve in the catalog"}, nil
	}
	systemNodeId, leafNodeId := func() (string, string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.systemNodeId, self.leafNodeId
	}()
	request, err := self.harness.journal.Render(ctx, &HarnessRenderArgs{RunId: self.run.Id(), InputNodeId: leafNodeId,
		SystemNodeId: systemNodeId, Model: model})
	if err != nil {
		return nil, nil, fmt.Errorf("the context did not render, so nothing was sent: %w", err)
	}
	runId, agentId := self.run.Id(), self.id
	request.Model = model
	request.RunId = &runId
	request.AgentId = &agentId
	if self.spec.Budget != nil {
		request.Budget = &InferBudgetRef{Kind: InferBudgetHarness, Id: self.spec.Budget.Id}
	}
	maxOutput := int64(request.MaxOutput)
	if maxOutput == 0 {
		maxOutput = resolution.Entry.MaxOutput
	}
	stream := &harnessStream{agent: self, model: model, provider: resolution.Entry.Provider, label: resolution.Entry.Label,
		maxOutput: maxOutput, toolIndexes: map[string]int{}}
	events, err := self.harness.router.Infer(ctx, request)
	if err != nil {
		return nil, inferErrorOf(err), nil
	}
	var failure *InferError
	for event := range events {
		switch event.Kind {
		case InferEventEnd:
		case InferEventError:
			failure = event.Error
			if failure == nil {
				failure = newInferError(InferErrorEngineFailed, "the call failed")
			}
		default:
			stream.take(event)
		}
	}
	stream.closeOpen()
	if failure != nil {
		stopReason := HarnessPiStopError
		if failure.Code == InferErrorCanceled && ctx.Err() != nil {
			stopReason = HarnessPiStopAborted
		}
		partial := stream.message(stopReason, failure.Error())
		// the failed call's partial output is kept beside the leaf, off the context's path
		self.journalAside(partial)
		if stream.started {
			self.emit(NewHarnessMessageEndEvent(partial))
		}
		return nil, failure, nil
	}
	stopReason := HarnessPiStopStop
	if stream.cutByLength() {
		stopReason = HarnessPiStopLength
	} else if 0 < len(stream.toolIndexes) {
		stopReason = HarnessPiStopToolUse
	}
	stream.start()
	message := stream.message(stopReason, "")
	if _, err := self.journalMessage(ctx, message, false, ""); err != nil {
		return nil, nil, err
	}
	self.emit(NewHarnessMessageEndEvent(message))
	return message, nil, nil
}

// Journals a failed call's partial message beside the leaf, leaving the leaf where it was.
func (self *harnessAgent) journalAside(message *HarnessPiMessage) {
	leaf := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.leafNodeId
	}()
	entry := NewHarnessPiMessageEntry(NewHarnessPiEntryId(), leaf, self.harness.clock.Now(), message)
	marks, err := self.run.Marks()
	if err != nil {
		marks = harnessMarkAll
	}
	node := &HarnessJournalNode{RunId: self.run.Id(), AgentId: self.id, Entry: entry, Tainted: self.run.Tainted(), Marks: marks}
	if err := self.harness.journal.Journal(context.Background(), node); err != nil {
		self.harness.log.Warningf("[harness]a failed call's output did not journal: %v", err)
	}
}

// The response of one turn: the call, its retries, compaction and the failure choice (harness_failure.go). Answers the
// message, or the run's end where the turn cannot go on.
func (self *harnessAgent) respond(ctx context.Context) (*HarnessPiMessage, *harnessRunEnd) {
	if err := self.compactIfDue(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, self.aborted()
		}
		return nil, &harnessRunEnd{stopReason: HarnessStopError, errorMessage: fmt.Sprintf("compaction failed: %v", err)}
	}
	return self.callWithRecovery(ctx)
}
