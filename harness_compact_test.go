//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"strings"
	"testing"
)

// The thresholds §7.4 gives: a 32k-token window compacts at 24,576 and keeps 8,192; a 200k window compacts at 183,616
// and keeps 20,000.
func TestHarnessCompactionThresholds(t *testing.T) {
	settings := DefaultHarnessSettings()
	if threshold, keep := harnessCompactionThresholds(settings, 32768); threshold != 24576 || keep != 8192 {
		t.Fatalf("32k: %d, %d", threshold, keep)
	}
	if threshold, keep := harnessCompactionThresholds(settings, 200000); threshold != 183616 || keep != 20000 {
		t.Fatalf("200k: %d, %d", threshold, keep)
	}

	// the cut never splits a call from its result: a kept span that would start at a tool result starts at its call
	message := func(role string) *harnessContextNode {
		var piMessage *HarnessPiMessage
		switch role {
		case "user":
			piMessage = NewHarnessPiUserMessage("question", nil, 1)
		case "assistant":
			piMessage = NewHarnessPiAssistantMessage(&HarnessPiAssistant{Content: []*HarnessPiBlock{
				NewHarnessPiToolCallBlock(&HarnessPiToolCall{Id: "c", Name: "read", Arguments: []byte(`{}`)})}})
		case "result":
			piMessage = NewHarnessPiToolResultMessage("c", "read", nil, nil, false, 1)
		}
		return &harnessContextNode{entry: NewHarnessPiMessageEntry(NewHarnessPiEntryId(), "", testHarnessTime, piMessage), tokens: 1000}
	}
	nodes := []*harnessContextNode{message("user"), message("assistant"), message("result"), message("result"),
		message("user"), message("assistant"), message("result")}
	// keeping 1,000 tokens would start at the last call's result: the cut moves back to its call
	if cut := harnessCompactionCut(nodes, 1000); cut != 5 {
		t.Fatalf("cut at %d", cut)
	}
	// keeping 3,000 starts at the user message before it
	if cut := harnessCompactionCut(nodes, 3000); cut != 4 {
		t.Fatalf("cut at %d", cut)
	}
	// keeping 4,000 would start at a result of the first call: back to the call
	if cut := harnessCompactionCut(nodes, 4000); cut != 1 {
		t.Fatalf("cut at %d", cut)
	}
	// keeping everything leaves nothing to compact
	if cut := harnessCompactionCut(nodes, 100000); cut != 0 {
		t.Fatalf("cut at %d", cut)
	}

	// through the loop: a 32k window's context past 24,576 tokens compacts before the call, keeping its newest messages
	entry := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelA1, InferEffortHigh)
	entry.ContextWindow = 32768
	router := newHarnessScriptedRouter(t, entry)
	world := newHarnessTestWorld(t, router, nil, nil)
	router.script(harnessTextCall("first"), harnessTextCall("the summary of what came before"), harnessTextCall("after"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	// a 100,000-byte prompt takes 25,000 tokens
	agent.Prompt(context.Background(), strings.Repeat("a", 100000), nil)
	log.until(t, HarnessEventAgentSettled)
	harnessPromptIdle(t, agent, "a short question")
	events := log.until(t, HarnessEventAgentSettled)
	compacted := false
	for _, event := range events {
		if event.Type == HarnessEventCompactionEnd {
			reason := ""
			event.Decode("reason", &reason)
			result := struct {
				Summary string `json:"summary"`
			}{}
			event.Decode("result", &result)
			compacted = reason == HarnessCompactionThreshold && result.Summary == "the summary of what came before"
		}
	}
	if !compacted {
		t.Fatalf("no threshold compaction: %v", harnessEventTypesOf(events))
	}
	requests := router.made()
	if len(requests) != 3 {
		t.Fatalf("%d requests", len(requests))
	}
	// the compaction call's context is exactly what it replaced: the long prompt and the first answer, then the
	// instruction
	compaction := requests[1]
	last := compaction.Messages[len(compaction.Messages)-1]
	if !strings.HasPrefix(last.Text(), "Summarize the conversation above") || len(compaction.Tools) != 0 {
		t.Fatalf("the compaction call ends with %q", last.Text())
	}
	// the next call carries the summary and the kept messages, and not the long prompt
	after := requests[2]
	for _, message := range after.Messages {
		if strings.Contains(message.Text(), strings.Repeat("a", 1000)) {
			t.Fatal("the compacted prompt is still in the context")
		}
	}
	if !strings.Contains(after.Messages[1].Text(), "the summary of what came before") ||
		after.Messages[len(after.Messages)-1].Text() != "a short question" {
		t.Fatalf("after compaction: %q ... %q", after.Messages[1].Text(), after.Messages[len(after.Messages)-1].Text())
	}
}

// A provider refusing a request as too large compacts the context (reason overflow) and calls again.
func TestHarnessCompactionOnTooLargeRefusal(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	// keep only the newest message, so the overflow's compaction replaces the rest
	settings := DefaultHarnessSettings()
	settings.CompactionKeepTokenCount = 1
	world := newHarnessTestWorld(t, router, nil, &HarnessArgs{Settings: settings})
	router.script(harnessTextCall("first"), harnessTextCall("second"),
		&harnessScriptedCall{refuse: &InferError{Code: InferErrorContextLength, Model: harnessTestModel, Message: "too large"}},
		harnessTextCall("summary"), harnessTextCall("after the overflow"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "one", nil)
	log.until(t, HarnessEventAgentSettled)
	harnessPromptIdle(t, agent, "two")
	log.until(t, HarnessEventAgentSettled)
	harnessPromptIdle(t, agent, "three")
	events := log.until(t, HarnessEventAgentSettled)
	reason := ""
	for _, event := range events {
		if event.Type == HarnessEventCompactionStart {
			event.Decode("reason", &reason)
		}
	}
	final := events[len(events)-4].Message()
	if reason != HarnessCompactionOverflow || final == nil || final.Text() != "after the overflow" ||
		harnessStopReason(events[len(events)-1]) != HarnessStopEnded {
		t.Fatalf("an overflow: reason %q, %v", reason, harnessEventTypesOf(events))
	}
}
