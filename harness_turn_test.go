//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Parallel calls start in call order and end as they settle: the second call settles first, its end ahead of the
// first's, and the results are journaled and emitted in call order.
func TestHarnessParallelToolsStartInCallOrder(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	firstRelease := make(chan struct{})
	tools := map[string]*HarnessToolSpec{
		"slow": harnessLoopTool("slow", "", HarnessToolTierRead, func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			<-firstRelease
			return &HarnessToolResult{Text: "slow done", Trust: HarnessToolTrusted}, nil
		}),
		"fast": harnessLoopTool("fast", "", HarnessToolTierRead, func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			return &HarnessToolResult{Text: "fast done", Trust: HarnessToolTrusted}, nil
		}),
	}
	world := newHarnessTestWorld(t, router, tools, nil)
	router.script(harnessToolsCall([3]string{"call_1", "slow", `{}`}, [3]string{"call_2", "fast", `{}`}), harnessTextCall("ok"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "go", nil)
	// the first call is held until an end went out, which only the second's can be; its Execute returning is not
	// enough, since its end is emitted after it returns
	events := log.until(t, HarnessEventToolExecutionEnd)
	close(firstRelease)
	events = append(events, log.until(t, HarnessEventAgentSettled)...)
	sequence := []string{}
	for _, event := range events {
		switch event.Type {
		case HarnessEventToolExecutionStart, HarnessEventToolExecutionEnd:
			id := ""
			event.Decode("toolCallId", &id)
			sequence = append(sequence, string(event.Type)+":"+id)
		case HarnessEventMessageEnd:
			if message := event.Message(); message.Role() == HarnessPiRoleToolResult {
				sequence = append(sequence, "result:"+message.ToolCallId())
			}
		}
	}
	want := []string{"tool_execution_start:call_1", "tool_execution_start:call_2", "tool_execution_end:call_2",
		"tool_execution_end:call_1", "result:call_1", "result:call_2"}
	if !slices.Equal(sequence, want) {
		t.Fatalf("got %v\nwant %v", sequence, want)
	}
}

// A sequential tool makes its batch sequential: each call starts after the one before it ends, its result between.
func TestHarnessSequentialToolMakesBatchSequential(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	var stateLock sync.Mutex
	running := 0
	overlapped := false
	execute := func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
		stateLock.Lock()
		running += 1
		overlapped = overlapped || 1 < running
		stateLock.Unlock()
		defer func() {
			stateLock.Lock()
			running -= 1
			stateLock.Unlock()
		}()
		return &HarnessToolResult{Text: "ok", Trust: HarnessToolTrusted}, nil
	}
	tools := map[string]*HarnessToolSpec{
		"ordered": harnessLoopTool("ordered", HarnessToolSequential, HarnessToolTierRead, execute),
		"free":    harnessLoopTool("free", "", HarnessToolTierRead, execute),
	}
	world := newHarnessTestWorld(t, router, tools, nil)
	router.script(harnessToolsCall([3]string{"call_1", "free", `{}`}, [3]string{"call_2", "ordered", `{}`},
		[3]string{"call_3", "free", `{}`}), harnessTextCall("ok"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "go", nil)
	events := log.until(t, HarnessEventAgentSettled)
	sequence := []string{}
	for _, event := range events {
		switch event.Type {
		case HarnessEventToolExecutionStart:
			sequence = append(sequence, "start")
		case HarnessEventToolExecutionEnd:
			sequence = append(sequence, "end")
		case HarnessEventMessageEnd:
			if event.Message().Role() == HarnessPiRoleToolResult {
				sequence = append(sequence, "result")
			}
		}
	}
	if want := strings.Repeat("start end result ", 3); strings.Join(sequence, " ")+" " != want || overlapped {
		t.Fatalf("a sequential batch: %v (overlapped %v)", sequence, overlapped)
	}
}

// A response cut by length fails every tool call it carries, none run, and the turn goes on.
func TestHarnessLengthStopFailsToolCalls(t *testing.T) {
	entry := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelA1, InferEffortHigh)
	entry.MaxOutput = 100
	router := newHarnessScriptedRouter(t, entry)
	ran := false
	tools := map[string]*HarnessToolSpec{"write_it": harnessLoopTool("write_it", "", HarnessToolTierWrite,
		func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			ran = true
			return &HarnessToolResult{Text: "wrote", Trust: HarnessToolTrusted}, nil
		})}
	world := newHarnessTestWorld(t, router, tools, nil)
	cut := harnessToolsCall([3]string{"call_1", "write_it", `{"content":"half`}, [3]string{"call_2", "write_it", `{}`})
	// the usage reaches the model's output maximum
	for _, event := range cut.events {
		if event.Kind == InferEventUsage {
			event.Usage.OutputTokens = 100
		}
	}
	router.script(cut, harnessTextCall("retrying properly"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "write", nil)
	events := log.until(t, HarnessEventAgentSettled)
	failed := 0
	for _, event := range events {
		if event.Type == HarnessEventMessageEnd {
			message := event.Message()
			if message.Role() == HarnessPiRoleAssistant && 0 < len(message.ToolCalls()) && message.StopReason() != HarnessPiStopLength {
				t.Fatalf("the cut response's stop reason: %q", message.StopReason())
			}
			if message.Role() == HarnessPiRoleToolResult && message.IsError() && strings.Contains(message.Text(), "output token limit") {
				failed += 1
			}
		}
	}
	if ran || failed != 2 {
		t.Fatalf("a cut response's calls: ran %v, %d failed", ran, failed)
	}
}

// MaxTurnCount turns per prompt end the run with stop reason max_turns.
func TestHarnessMaxTurnsStops(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	tools := map[string]*HarnessToolSpec{"again": harnessLoopTool("again", "", HarnessToolTierRead,
		func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			return &HarnessToolResult{Text: "again", Trust: HarnessToolTrusted}, nil
		})}
	world := newHarnessTestWorld(t, router, tools, nil)
	for i := 0; i < 5; i += 1 {
		router.script(harnessToolsCall([3]string{"call", "again", `{}`}))
	}
	agent := world.agent(t, &HarnessAgentSpec{MaxTurnCount: 3})
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "loop", nil)
	events := log.until(t, HarnessEventAgentSettled)
	if reason := harnessStopReason(events[len(events)-1]); reason != HarnessStopMaxTurns {
		t.Fatalf("stop reason %q", reason)
	}
	if requests := len(router.made()); requests != 3 {
		t.Fatalf("%d requests for 3 turns", requests)
	}
	turnStarts, turnEnds := 0, 0
	for _, event := range events {
		switch event.Type {
		case HarnessEventTurnStart:
			turnStarts += 1
		case HarnessEventTurnEnd:
			turnEnds += 1
		}
	}
	if turnStarts != 3 || turnEnds != 3 {
		t.Fatalf("%d turn starts, %d turn ends", turnStarts, turnEnds)
	}
}

// On a phone the loop starts no item while the app is in the background: a batch pauses at the call boundary, the run
// settling with stop reason backgrounded, and Resume runs what is left, from where it stopped.
func TestHarnessPhonePausesAtItemBoundary(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	foreground := &harnessTestForeground{foreground: true}
	ran := []string{}
	var ranLock sync.Mutex
	tools := map[string]*HarnessToolSpec{"step": harnessLoopTool("step", HarnessToolSequential, HarnessToolTierRead,
		func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			ranLock.Lock()
			ran = append(ran, string(args))
			first := len(ran) == 1
			ranLock.Unlock()
			if first {
				// the app leaves the foreground during the first call
				foreground.set(false)
			}
			return &HarnessToolResult{Text: "stepped", Trust: HarnessToolTrusted}, nil
		})}
	world := newHarnessTestWorld(t, router, tools, &HarnessArgs{Foreground: foreground})
	router.script(harnessToolsCall([3]string{"call_1", "step", `{"n":1}`}, [3]string{"call_2", "step", `{"n":2}`}),
		harnessTextCall("both steps done"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "two steps", nil)
	events := log.until(t, HarnessEventAgentSettled)
	if reason := harnessStopReason(events[len(events)-1]); reason != HarnessStopBackgrounded {
		t.Fatalf("stop reason %q", reason)
	}
	ranLock.Lock()
	if !slices.Equal(ran, []string{`{"n":1}`}) {
		t.Fatalf("ran %v before pausing", ran)
	}
	ranLock.Unlock()
	if len(router.made()) != 1 {
		t.Fatalf("%d requests before resuming", len(router.made()))
	}
	foreground.set(true)
	if err := agent.(*harnessAgent).Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	events = log.until(t, HarnessEventAgentSettled)
	if reason := harnessStopReason(events[len(events)-1]); reason != HarnessStopEnded {
		t.Fatalf("after resuming, stop reason %q", reason)
	}
	ranLock.Lock()
	defer ranLock.Unlock()
	if !slices.Equal(ran, []string{`{"n":1}`, `{"n":2}`}) || len(router.made()) != 2 {
		t.Fatalf("after resuming: ran %v, %d requests", ran, len(router.made()))
	}
	// the second request carries both results, in call order
	messages := router.made()[1].Messages
	if messages[len(messages)-1].ToolCallId != "call_2" || messages[len(messages)-2].ToolCallId != "call_1" {
		t.Fatal("the resumed request does not carry both results in call order")
	}
}

// A phone's foreground state as a test sets it.
type harnessTestForeground struct {
	stateLock  sync.Mutex
	foreground bool
}

func (self *harnessTestForeground) Foreground() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.foreground
}

func (self *harnessTestForeground) set(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.foreground = foreground
}
