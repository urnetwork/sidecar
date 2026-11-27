//go:build !ios_extension && !sidecar_http

// The event batcher (DESIGN-COMPUTE §7.6's delivery): it holds one agent's text, thinking and tool call deltas to at
// most HarnessSettings.EventRate message_update events a second, folding the deltas between them, so a phone's UI
// thread is not flooded. Every other event passes at once, after the deltas held before it, so a view sees the
// stream in order; message_end carries the whole message, so a view that dropped an update still ends right.
//
// The flushes run on the batcher's clock, never a sleep. Out is called with no lock held, one event at a time in each
// agent's order; it must not block, as a gomobile callback must not (HARN-M11-10). Safe for concurrent use.

package sidecar

import (
	"sync"
	"time"
)

// One agent's held deltas.
type harnessBatchAgent struct {
	// when its last delta went out
	lastDeltaTime time.Time
	sent          bool
	// deltas folded since, in order: a run of one kind and content block folds into one
	pending []*HarnessEvent
	// stops the flush scheduled for pending, nil for none
	stopFlush func() bool
}

// Folds a stream's deltas to EventRate a second per agent.
type HarnessEventBatcher struct {
	settings *HarnessSettings
	clock    Clock
	out      func(event *HarnessEvent)

	// one delivery at a time, so each agent's events go out in order: never stateLock
	outLock sync.Mutex

	stateLock sync.Mutex
	agents    map[string]*harnessBatchAgent
	closed    bool
}

// A batcher handing events to out, its flushes on clock (nil for real time).
func NewHarnessEventBatcher(settings *HarnessSettings, clock Clock, out func(event *HarnessEvent)) *HarnessEventBatcher {
	return &HarnessEventBatcher{
		settings: settings,
		clock:    clockOrReal(clock),
		out:      out,
		agents:   map[string]*harnessBatchAgent{},
	}
}

// The least time between two deltas of one agent; 0 passes every one.
func (self *HarnessEventBatcher) interval() time.Duration {
	if self.settings.EventRate <= 0 {
		return 0
	}
	return time.Second / time.Duration(self.settings.EventRate)
}

// Whether event is a delta the batcher may hold: a text, thinking or tool call delta.
func harnessEventIsDelta(event *HarnessEvent) (*HarnessAssistantMessageEvent, bool) {
	if event.Type != HarnessEventMessageUpdate {
		return nil, false
	}
	nested := event.AssistantMessageEvent()
	if nested == nil {
		return nil, false
	}
	switch nested.Type {
	case HarnessAssistantEventTextDelta, HarnessAssistantEventThinkingDelta, HarnessAssistantEventToolCallDelta:
		return nested, true
	}
	return nil, false
}

// next folded into last where both are deltas of one kind and one content block: their deltas joined, next's usage.
// nil where they do not fold.
func harnessEventFold(last *HarnessEvent, next *HarnessEvent) *HarnessEvent {
	lastNested, lastIsDelta := harnessEventIsDelta(last)
	nextNested, nextIsDelta := harnessEventIsDelta(next)
	if !lastIsDelta || !nextIsDelta || lastNested.Type != nextNested.Type ||
		lastNested.ContentIndex != nextNested.ContentIndex || last.Agent != next.Agent || last.Enclave != next.Enclave {
		return nil
	}
	usage := &HarnessPiUsage{}
	if !next.Decode("usage", usage) {
		usage = nil
	}
	folded := NewHarnessMessageUpdateEvent(usage, &HarnessAssistantMessageEvent{
		Type:         nextNested.Type,
		ContentIndex: nextNested.ContentIndex,
		Delta:        lastNested.Delta + nextNested.Delta,
	})
	folded.Agent = next.Agent
	folded.Seq = next.Seq
	folded.Enclave = next.Enclave
	return folded
}

// Takes one event of the stream. A delta inside its agent's interval is folded and held until the interval ends;
// anything else goes out at once, after what its agent holds.
func (self *HarnessEventBatcher) Add(event *HarnessEvent) {
	if event == nil {
		return
	}
	self.outLock.Lock()
	defer self.outLock.Unlock()
	sends := func() []*HarnessEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		agent, ok := self.agents[event.Agent]
		if !ok {
			agent = &harnessBatchAgent{}
			self.agents[event.Agent] = agent
		}
		_, isDelta := harnessEventIsDelta(event)
		if !isDelta {
			sends := self.takePendingWithLock(agent)
			return append(sends, event)
		}
		now := self.clock.Now()
		interval := self.interval()
		if len(agent.pending) == 0 && (!agent.sent || !now.Before(agent.lastDeltaTime.Add(interval))) {
			agent.lastDeltaTime = now
			agent.sent = true
			return []*HarnessEvent{event}
		}
		if n := len(agent.pending); 0 < n {
			if folded := harnessEventFold(agent.pending[n-1], event); folded != nil {
				agent.pending[n-1] = folded
			} else {
				agent.pending = append(agent.pending, event)
			}
		} else {
			agent.pending = append(agent.pending, event)
		}
		if agent.stopFlush == nil {
			agentKey := event.Agent
			// for the interval's end itself (QD-1425), and never on this goroutine, which holds the locks the flush
			// takes, should the clock have reached it already
			agent.stopFlush = ClockAfterFuncAtAsync(self.clock, agent.lastDeltaTime.Add(interval), func() {
				self.flushAgent(agentKey)
			})
		}
		return nil
	}()
	for _, send := range sends {
		self.out(send)
	}
}

// What agent holds, now out of it, its scheduled flush stopped. Called with stateLock held.
func (self *HarnessEventBatcher) takePendingWithLock(agent *harnessBatchAgent) []*HarnessEvent {
	if agent.stopFlush != nil {
		agent.stopFlush()
		agent.stopFlush = nil
	}
	pending := agent.pending
	agent.pending = nil
	if 0 < len(pending) {
		agent.lastDeltaTime = self.clock.Now()
		agent.sent = true
	}
	return pending
}

// Sends what one agent holds: its interval ended.
func (self *HarnessEventBatcher) flushAgent(agentKey string) {
	self.outLock.Lock()
	defer self.outLock.Unlock()
	sends := func() []*HarnessEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		agent, ok := self.agents[agentKey]
		if !ok || self.closed {
			return nil
		}
		agent.stopFlush = nil
		return self.takePendingWithLock(agent)
	}()
	for _, send := range sends {
		self.out(send)
	}
}

// Sends everything every agent holds, now.
func (self *HarnessEventBatcher) Flush() {
	self.outLock.Lock()
	defer self.outLock.Unlock()
	sends := func() []*HarnessEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		sends := []*HarnessEvent{}
		for _, agent := range self.agents {
			sends = append(sends, self.takePendingWithLock(agent)...)
		}
		return sends
	}()
	for _, send := range sends {
		self.out(send)
	}
}

// Sends what is held and takes nothing more.
func (self *HarnessEventBatcher) Close() {
	self.Flush()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
}
