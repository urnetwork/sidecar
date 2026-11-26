//go:build !ios_extension && !sidecar_http

// What a view of the Harness reads after the fact (DESIGN-COMPUTE §7.11, DESIGN §5.8's remote mode; HARN-M11-09): each
// agent's newest events as each was emitted, bounded by HarnessSettings' DaemonView fields, so `ur harness` reattaching
// to a run that stayed open after its terminal closed reads what it missed, and a long poll waits for the next.
//
// The log exists only once a view first asks for it (Harness.viewLog), so an app's Harness keeps none. From then on
// Emit feeds it on the emitting goroutine, under the Harness's emit lock and so in each agent's seq order, with an
// append and a wake and nothing that blocks. An agent whose events began before the log did starts at the seq it had
// reached, so a view asking for older ones is told of the gap. A closed agent's events stay until
// DaemonViewClosedAgentCount newer ones closed, so a view sees a closed run's last events and then that it closed.
//
// The person's view also marks the person attached to the run it watches, for the life of its session
// (attachSession), so the run may raise a dialog to them (HarnessUiBroker.Attached).
//
// Safe for concurrent use.

package sidecar

import (
	"encoding/json"
	"sync"
)

// One kept event: its seq and its JSON as emitted, or a stub where it was too large.
type harnessViewEvent struct {
	seq  uint64
	json []byte
}

// One agent's kept events.
type harnessViewRing struct {
	// the seq before the first event this ring could hold: an agent's seq when the ring began
	base uint64
	// oldest first
	events    []*harnessViewEvent
	byteCount int64
	// the newest seq taken, kept or dropped
	seq    uint64
	closed bool
	// when the agent closed, among the closed agents, for dropping the oldest
	closedOrder uint64
}

// Every agent's kept events, and the person's attachments.
type harnessViewLog struct {
	settings *HarnessSettings

	stateLock  sync.Mutex
	agentRings map[Id]*harnessViewRing
	closedNext uint64
	// closed and replaced at each change, so a waiter selects on the channel it read with the log's state
	changed chan struct{}

	// the runs each person's session attached, with their detaches, by the session's done channel
	sessionRunDetaches map[<-chan struct{}]map[Id]func()
	// called once a closed session's runs are detached: a test's hook, nil otherwise
	detachedHook func(session <-chan struct{})
}

// An empty log on settings.
func newHarnessViewLog(settings *HarnessSettings) *harnessViewLog {
	return &harnessViewLog{
		settings:           settings,
		agentRings:         map[Id]*harnessViewRing{},
		changed:            make(chan struct{}),
		sessionRunDetaches: map[<-chan struct{}]map[Id]func(){},
	}
}

// The Harness's view log, made at its first use, from when on every event Emit stamps is kept.
func (self *Harness) viewLog() *harnessViewLog {
	if view := self.view.Load(); view != nil {
		return view
	}
	self.view.CompareAndSwap(nil, newHarnessViewLog(self.settings))
	return self.view.Load()
}

// Tells a view log, where there is one, that the agent closed.
func (self *Harness) viewClosed(agentId Id) {
	if view := self.view.Load(); view != nil {
		view.close(agentId)
	}
}

// Notifies every waiter. With stateLock held.
func (self *harnessViewLog) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// The agent's ring, made where there is none, starting past seq, the agent's seq so far. With stateLock held.
func (self *harnessViewLog) ringWithLock(agentId Id, seq uint64) *harnessViewRing {
	ring, ok := self.agentRings[agentId]
	if !ok {
		ring = &harnessViewRing{base: seq, seq: seq}
		self.agentRings[agentId] = ring
	}
	return ring
}

// Starts keeping the agent's events past seq, its seq so far, where they are not kept already.
func (self *harnessViewLog) open(agentId Id, seq uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ringWithLock(agentId, seq)
}

// The stub kept for an event too large to keep whole: its envelope and its size.
func harnessViewStub(event *HarnessEvent, byteCount int) []byte {
	object := harnessPiObject{}
	object.set("type", event.Type)
	object.set("agent", event.Agent)
	object.set("seq", event.Seq)
	if event.Enclave != "" {
		object.set("enclave", event.Enclave)
	}
	object.set("omitted", byteCount)
	encoded, _ := object.MarshalJSON()
	return encoded
}

// Keeps a stamped event, dropping the agent's oldest past the settings' bounds, and wakes every waiter. Called in Emit:
// it never blocks.
func (self *harnessViewLog) add(agentId Id, event *HarnessEvent) {
	encoded, err := event.Json()
	if err != nil {
		encoded = harnessViewStub(event, 0)
	} else if len(encoded) > self.settings.DaemonViewEventMaxByteCount {
		encoded = harnessViewStub(event, len(encoded))
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ring := self.ringWithLock(agentId, event.Seq-1)
	if event.Seq <= ring.seq {
		// an event the ring already passed: none, since Emit stamps in order, but never kept twice
		return
	}
	ring.seq = event.Seq
	ring.events = append(ring.events, &harnessViewEvent{seq: event.Seq, json: encoded})
	ring.byteCount += int64(len(encoded))
	for 0 < len(ring.events) && (self.settings.DaemonViewEventCount < len(ring.events) ||
		self.settings.DaemonViewEventByteCount < ring.byteCount) {
		ring.byteCount -= int64(len(ring.events[0].json))
		ring.events = ring.events[1:]
	}
	self.notifyWithLock()
}

// Marks the agent closed, dropping the oldest closed agents past DaemonViewClosedAgentCount, and wakes every waiter.
func (self *harnessViewLog) close(agentId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ring, ok := self.agentRings[agentId]
	if !ok || ring.closed {
		return
	}
	ring.closed = true
	self.closedNext += 1
	ring.closedOrder = self.closedNext
	closedCount := 0
	for _, other := range self.agentRings {
		if other.closed {
			closedCount += 1
		}
	}
	for ; self.settings.DaemonViewClosedAgentCount < closedCount; closedCount -= 1 {
		oldestId, oldest := Id{}, (*harnessViewRing)(nil)
		for id, other := range self.agentRings {
			if other.closed && (oldest == nil || other.closedOrder < oldest.closedOrder) {
				oldestId, oldest = id, other
			}
		}
		delete(self.agentRings, oldestId)
	}
	self.notifyWithLock()
}

// What a read of one agent's events found.
type harnessViewRead struct {
	// the events past the seq asked, oldest first, each its JSON as emitted
	events []json.RawMessage
	// the seq of the last event read, else the seq asked
	next uint64
	// the log no longer holds, or never held, some event past the seq asked
	gap bool
	// the agent closed and nothing past next follows
	closed bool
	// the log holds the agent
	known bool
	// closed at the log's next change, read with the state above
	changed <-chan struct{}
}

// The agent's events past after, at most eventCount and byteCount of them but always one where there is one.
func (self *harnessViewLog) read(agentId Id, after uint64, eventCount int, byteCount int) *harnessViewRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	read := &harnessViewRead{next: after, changed: self.changed, events: []json.RawMessage{}}
	ring, ok := self.agentRings[agentId]
	if !ok {
		return read
	}
	read.known = true
	oldest := ring.seq + 1
	if 0 < len(ring.events) {
		oldest = ring.events[0].seq
	}
	if after+1 < oldest || after < ring.base {
		read.gap = true
	}
	total := 0
	for _, event := range ring.events {
		if event.seq <= after {
			continue
		}
		if 0 < len(read.events) && (eventCount <= len(read.events) || byteCount < total+len(event.json)) {
			break
		}
		read.events = append(read.events, json.RawMessage(event.json))
		total += len(event.json)
		read.next = event.seq
	}
	read.closed = ring.closed && ring.seq <= read.next
	return read
}

// Marks the person attached to the run for the life of session, the done channel of the view's session, once for each
// run of a session, detaching every run it attached once session closes. A nil session, a call no session reader
// watches, attaches only until the answer's detach is called.
func (self *harnessViewLog) attachSession(broker *HarnessUiBroker, session <-chan struct{}, runId Id) (detach func()) {
	if session == nil {
		return broker.AttachPerson(runId)
	}
	first, attached := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runDetaches, ok := self.sessionRunDetaches[session]
		if !ok {
			runDetaches = map[Id]func(){}
			self.sessionRunDetaches[session] = runDetaches
		}
		if _, ok := runDetaches[runId]; ok {
			return false, true
		}
		runDetaches[runId] = broker.AttachPerson(runId)
		return len(runDetaches) == 1, false
	}()
	if first && !attached {
		go func() {
			<-session
			runDetaches, hook := func() (map[Id]func(), func(session <-chan struct{})) {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				runDetaches := self.sessionRunDetaches[session]
				delete(self.sessionRunDetaches, session)
				return runDetaches, self.detachedHook
			}()
			for _, detach := range runDetaches {
				detach()
			}
			if hook != nil {
				hook(session)
			}
		}()
	}
	return func() {}
}
