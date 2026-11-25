//go:build !ios_extension && !sidecar_http

// Compaction (DESIGN-COMPUTE §7.4's Compaction row, §24.4): the context compacts when its tokens pass the model's
// window less the reserve, the lesser of HarnessSettings.CompactionReserveTokenCount and CompactionReserveFraction of
// the window, or when a provider refuses a request as too large; it keeps the newest messages up to the lesser of
// CompactionKeepTokenCount and CompactionKeepFraction of the window, never splitting a call from its result, so a
// 32k-token model compacts at 24,576 tokens and keeps 8,192.
//
// The summary comes from a call whose context is exactly what it replaced: the instruction to summarize is journaled
// as a custom_message node hanging from the last replaced message, off the context's path, and the call renders from
// it, so the record's model_call names a context that rebuilds exactly. Pi's compaction entry then joins the path at
// the leaf with the summary, the first kept entry's id and the tokens before; the messages it replaced stay in the
// tree. Tokens are estimated as Pi does, bytes over HarnessSettings.TokenEstimateByteCount.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The instruction a compaction call ends with.
const harnessCompactionInstruction = "Summarize the conversation above for your own later use: the task, what was " +
	"done and found, the decisions made, the files and records touched, and what remains. Keep identifiers exact. " +
	"Write only the summary."

// The customType of the node holding a compaction call's instruction.
const harnessCompactionCustomType = "ur-harness-compaction"

// No message can be compacted: the context is all kept.
var errHarnessNothingToCompact = errors.New("nothing to compact")

// The lesser of count and fraction of window, a non-positive side counting as none.
func harnessWindowShare(window int64, count int64, fraction float64) int64 {
	byFraction := int64(float64(window) * fraction)
	switch {
	case count <= 0 && fraction <= 0:
		return 0
	case count <= 0:
		return byFraction
	case fraction <= 0:
		return count
	}
	return min(count, byFraction)
}

// The tokens past which a window's context compacts, and what a compaction keeps.
func harnessCompactionThresholds(settings *HarnessSettings, window int64) (int64, int64) {
	reserve := harnessWindowShare(window, settings.CompactionReserveTokenCount, settings.CompactionReserveFraction)
	keep := harnessWindowShare(window, settings.CompactionKeepTokenCount, settings.CompactionKeepFraction)
	return window - reserve, keep
}

// The tokens the context takes now: the system message's and every node's after it.
func (self *harnessAgent) contextTokens() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	total := int64(0)
	for _, node := range self.contextNodes {
		total += node.tokens
	}
	return total
}

// Compacts the context where it passes its model's threshold.
func (self *harnessAgent) compactIfDue(ctx context.Context) error {
	resolution, err := self.harness.modelEntry(ctx, self.currentModel())
	if err != nil || resolution.Entry.ContextWindow <= 0 {
		return nil
	}
	threshold, _ := harnessCompactionThresholds(self.harness.settings, resolution.Entry.ContextWindow)
	if self.contextTokens() <= threshold {
		return nil
	}
	err = self.compact(ctx, HarnessCompactionThreshold, "")
	if errors.Is(err, errHarnessNothingToCompact) {
		return nil
	}
	return err
}

// The index of the first node a compaction keeps: the newest nodes whose tokens fit keep, the newest alone where it
// passes keep, then back past every tool result to the message holding its call, so a call is never split from its
// result. 0 where nothing before it can be replaced.
func harnessCompactionCut(nodes []*harnessContextNode, keep int64) int {
	kept := int64(0)
	cut := len(nodes)
	for 0 < cut && kept+nodes[cut-1].tokens <= keep {
		cut -= 1
		kept += nodes[cut].tokens
	}
	if cut == len(nodes) && 0 < keep && 0 < cut {
		// the newest message alone passes what is kept: it is kept whole
		cut -= 1
	}
	for 0 < cut {
		message := nodes[cut].entry.Message()
		if message == nil || message.Role() != HarnessPiRoleToolResult {
			break
		}
		cut -= 1
	}
	return cut
}

// Compacts the context now, as the file header says, for reason, an extra instruction appended where given.
func (self *harnessAgent) compact(ctx context.Context, reason string, instructions string) error {
	resolution, err := self.harness.modelEntry(ctx, self.currentModel())
	if err != nil {
		return err
	}
	_, keep := harnessCompactionThresholds(self.harness.settings, resolution.Entry.ContextWindow)
	if reason == HarnessCompactionManual {
		keep = 0
	}
	nodes := func() []*harnessContextNode {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return append([]*harnessContextNode{}, self.contextNodes...)
	}()
	cut := harnessCompactionCut(nodes, keep)
	if cut == 0 {
		return errHarnessNothingToCompact
	}
	tokensBefore := self.contextTokens()
	self.emit(NewHarnessCompactionStartEvent(reason))
	summary, err := self.summarize(ctx, nodes[cut-1].entry.Id(), instructions)
	if err != nil {
		self.emit(NewHarnessCompactionEndEvent(reason, nil, ctx.Err() != nil, false, err.Error()))
		return err
	}
	firstKept := ""
	if cut < len(nodes) {
		firstKept = nodes[cut].entry.Id()
	}
	leaf := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.leafNodeId
	}()
	entryId := NewHarnessPiEntryId()
	if firstKept == "" {
		// a retain-none compaction names itself, as Pi's does
		firstKept = entryId
	}
	entry := NewHarnessPiCompactionEntry(entryId, leaf, self.harness.clock.Now(), summary, firstKept, tokensBefore)
	if err := self.journalWith(ctx, entry, nil, false, ""); err != nil {
		self.emit(NewHarnessCompactionEndEvent(reason, nil, false, false, err.Error()))
		return err
	}
	summaryNode := &harnessContextNode{entry: entry, tokens: self.entryTokens(entry)}
	tokensAfter := summaryNode.tokens
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		kept := append([]*harnessContextNode{summaryNode}, nodes[cut:]...)
		// a node journaled since the copy stays
		kept = append(kept, self.contextNodes[len(nodes):]...)
		self.contextNodes = kept
		for _, node := range kept[1:] {
			tokensAfter += node.tokens
		}
	}()
	self.emit(NewHarnessCompactionEndEvent(reason, &HarnessCompactionResult{Summary: summary, FirstKeptEntryId: firstKept,
		TokensBefore: tokensBefore, EstimatedTokensAfter: tokensAfter}, false, false, ""))
	return nil
}

// The summary of the context ending at lastId: the instruction journaled as a node hanging from it, off the path, and
// one call rendered from that node, on the agent's model, through the router. Its text is the summary.
func (self *harnessAgent) summarize(ctx context.Context, lastId string, instructions string) (string, error) {
	instruction := harnessCompactionInstruction
	if instructions != "" {
		instruction += "\n\n" + instructions
	}
	request := NewHarnessPiCustomMessageEntry(NewHarnessPiEntryId(), lastId, self.harness.clock.Now(),
		harnessCompactionCustomType, instruction, false)
	marks, err := self.run.Marks()
	if err != nil {
		marks = harnessMarkAll
	}
	if err := self.harness.journal.Journal(ctx, &HarnessJournalNode{RunId: self.run.Id(), AgentId: self.id, Entry: request,
		Tainted: self.run.Tainted(), Marks: marks}); err != nil {
		return "", fmt.Errorf("the compaction's context did not journal: %w", err)
	}
	systemNodeId := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.systemNodeId
	}()
	model := self.currentModel()
	rendered, err := self.harness.journal.Render(ctx, &HarnessRenderArgs{RunId: self.run.Id(), InputNodeId: request.Id(),
		SystemNodeId: systemNodeId, Model: model})
	if err != nil {
		return "", err
	}
	runId, agentId := self.run.Id(), self.id
	rendered.Model = model
	rendered.RunId = &runId
	rendered.AgentId = &agentId
	rendered.Tools = nil
	if self.spec.Budget != nil {
		rendered.Budget = &InferBudgetRef{Kind: InferBudgetHarness, Id: self.spec.Budget.Id}
	}
	events, err := self.harness.router.Infer(ctx, rendered)
	if err != nil {
		return "", err
	}
	text := strings.Builder{}
	var failure *InferError
	for event := range events {
		switch event.Kind {
		case InferEventText:
			text.WriteString(event.Text)
		case InferEventUsage:
			self.addCharge(event.Usage.ChargeNanoUsd)
		case InferEventError:
			failure = event.Error
		}
	}
	if failure != nil {
		return "", failure
	}
	if text.Len() == 0 {
		return "", errors.New("the compaction call answered no summary")
	}
	return text.String(), nil
}
