//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's events (§18.5, §5.8; QD-821, question sdk-m8-02-remote-events): one bounded ring a daemon of the core's
// SidecarEvents, from every Sidecar its host attaches, and the control method events that long-polls it, so a
// remote-mode app (the sdk's remote backend) and the extension (through ur native-host) hear every event kind, not
// only the state a status read shows. It is a method, not a hello mode: §5.8's hello table and format stand.
//
//	ring      each event is kept as a DaemonEvent, its wire form, built as it is raised: its kind, its generation and
//	          what §5.4's SidecarEvent carries for its kind (the ids §18.5 lists, its state and reason, its alarm), with
//	          the network and the sidecar that raised it. None of it is a secret, so every reply passes the reply walk
//	          (daemon_rpc.go). Each event takes the next sequence, from 1; EventRingEventCount are kept, the oldest
//	          going past that
//	cursor    "<ring id>:<sequence>", the ring's id minted when the ring starts, so a cursor of a daemon that has since
//	          ended reads as a gap and never as a place in this ring. A caller holds it as opaque and sends back the
//	          last one it took
//	events    {after, wait_ms}. An empty after answers the current cursor at once and no events, so a caller takes its
//	          place before it reads status (subscribe, then read: an event between the two arrives with the next call).
//	          Otherwise: the events past after, oldest first and at most EventReplyEventCount, at once; or, with none
//	          yet, a wait of up to wait_ms, capped at EventWaitTimeout, for the next; or gap with the current cursor
//	          when the ring passed after or after is another ring's, and the caller reads status for where things stand
//	          (§18.5's GetState). A wait that passes answers no events and after again. A wait ends with its session
//	          (DaemonCall.SessionDone) and with the daemon
//	callback  a Sidecar's event callback must not block (SidecarEventFunction): an event is added under the ring's lock,
//	          with an append and the waiters' wake, and nothing else
//
// A path an event names is local to this device and goes only to this user's own callers, as the sdk's local listener
// has it; nothing here logs one (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The control method that long-polls the daemon's events.
const DaemonMethodEvents = "events"

// What separates a cursor's ring id from its sequence.
const daemonEventsCursorSeparator = ":"

var (
	// An after that is no cursor an events reply gave.
	ErrDaemonEventsCursor = errors.New("events takes a cursor an events reply gave")
	// The session of a waiting events call ended, so nobody reads its answer.
	errDaemonEventsSessionEnded = errors.New("the session ended")
)

// events's params.
type DaemonEventsParams struct {
	// The cursor of the last reply taken. Empty: none yet, which answers the current cursor at once and no events.
	After string `json:"after,omitempty"`
	// How long to wait for an event past After when none is there yet, in milliseconds, capped at
	// SidecarLocalSettings.EventWaitTimeout. Zero or less answers at once.
	WaitMs int64 `json:"wait_ms,omitempty"`
}

// events's reply: nothing secret, which the reply walk holds it to.
type DaemonEventsReply struct {
	// The events past After, oldest first, at most EventReplyEventCount: a reply holding that many may leave more,
	// which the next call answers at once. Empty for a gap, a wait that passed and an empty After.
	Events []*DaemonEvent `json:"events"`
	// Where the next call starts: past the last event answered; else After, for a wait that passed; else, for a gap or
	// an empty After, the newest event's.
	Cursor string `json:"cursor"`
	// The events past After are gone: the ring passed After, or After is another ring's, a daemon's that ended. The
	// caller reads status for where things stand (§18.5's GetState) and goes on from Cursor.
	Gap bool `json:"gap,omitempty"`
}

// One SidecarEvent as the events method answers it: its kind and generation and each field SidecarEvent fills for its
// kind, under the field's own name, with the network and the sidecar that raised it. Times are unix milliseconds, zero
// for none, and Evidence's two pins are FirstEvidence and SecondEvidence. Nothing in it is a secret: ids, states,
// reasons, alarms, counts, public pins and a path local to this device.
type DaemonEvent struct {
	// The network of the sidecar that raised it; nil for one not enrolled yet, such as the Sidecar a further
	// network's enrollment takes.
	NetworkId *Id `json:"network_id,omitempty"`
	// That sidecar's own id, which a status row names as its sidecar_id; nil before it has an identity.
	OriginSidecarId *Id    `json:"origin_sidecar_id,omitempty"`
	Kind            string `json:"kind"`
	// The client generation it comes from (§18.5's State block).
	Generation        int64               `json:"generation"`
	State             string              `json:"state,omitempty"`
	Reason            string              `json:"reason,omitempty"`
	GroupId           *Id                 `json:"group_id,omitempty"`
	SidecarId         *Id                 `json:"sidecar_id,omitempty"`
	RepoId            *Id                 `json:"repo_id,omitempty"`
	RefId             *Id                 `json:"ref_id,omitempty"`
	Path              string              `json:"path,omitempty"`
	DropId            *Id                 `json:"drop_id,omitempty"`
	DropState         string              `json:"drop_state,omitempty"`
	NotBeforeMs       int64               `json:"not_before_ms,omitempty"`
	SearchAlarm       string              `json:"search_alarm,omitempty"`
	RequestId         *Id                 `json:"request_id,omitempty"`
	Outcome           string              `json:"outcome,omitempty"`
	SendId            *Id                 `json:"send_id,omitempty"`
	ApprovalId        *Id                 `json:"approval_id,omitempty"`
	HeadAlarm         string              `json:"head_alarm,omitempty"`
	FirstEvidence     []byte              `json:"first_evidence,omitempty"`
	SecondEvidence    []byte              `json:"second_evidence,omitempty"`
	Erasure           *DaemonEventErasure `json:"erasure,omitempty"`
	EvsAlarm          string              `json:"evs_alarm,omitempty"`
	EvsAlarmDetail    string              `json:"evs_alarm_detail,omitempty"`
	Version           uint64              `json:"version,omitempty"`
	PushId            *Id                 `json:"push_id,omitempty"`
	Count             int                 `json:"count,omitempty"`
	VerifiedSinceMs   int64               `json:"verified_since_ms,omitempty"`
	RecordAlarm       string              `json:"record_alarm,omitempty"`
	BridgeAlarm       string              `json:"bridge_alarm,omitempty"`
	DnsAlarm          string              `json:"dns_alarm,omitempty"`
	CtAlarm           string              `json:"ct_alarm,omitempty"`
	MailReceiverAlarm string              `json:"mail_receiver_alarm,omitempty"`
}

// SidecarEvent.Erasure as the events method answers it, its times in unix milliseconds.
type DaemonEventErasure struct {
	ErasureId   Id     `json:"erasure_id"`
	State       string `json:"state"`
	ObjectsLeft int64  `json:"objects_left,omitempty"`
	BytesLeft   int64  `json:"bytes_left,omitempty"`
	NextTryMs   int64  `json:"next_try_ms,omitempty"`
	FinishMs    int64  `json:"finish_ms,omitempty"`
}

// The wire form of event, which the sidecar of networkId whose own id is originSidecarId raised. It shares nothing
// with event, so a callback's copy may go on changing.
func newDaemonEvent(networkId *Id, originSidecarId *Id, event *SidecarEvent) *DaemonEvent {
	idOf := func(id *Id) *Id {
		if id == nil {
			return nil
		}
		copied := *id
		return &copied
	}
	millisOf := func(at time.Time) int64 {
		if at.IsZero() {
			return 0
		}
		return at.UnixMilli()
	}
	bytesOf := func(value []byte) []byte {
		if len(value) == 0 {
			return nil
		}
		return bytes.Clone(value)
	}
	wire := &DaemonEvent{
		NetworkId:         idOf(networkId),
		OriginSidecarId:   idOf(originSidecarId),
		Kind:              string(event.Kind),
		Generation:        event.Generation,
		State:             string(event.State),
		Reason:            string(event.Reason),
		GroupId:           idOf(event.GroupId),
		SidecarId:         idOf(event.SidecarId),
		RepoId:            idOf(event.RepoId),
		RefId:             idOf(event.RefId),
		Path:              event.Path,
		DropId:            idOf(event.DropId),
		DropState:         string(event.DropState),
		NotBeforeMs:       millisOf(event.NotBefore),
		SearchAlarm:       string(event.SearchAlarm),
		RequestId:         idOf(event.RequestId),
		Outcome:           event.Outcome,
		SendId:            idOf(event.SendId),
		ApprovalId:        idOf(event.ApprovalId),
		HeadAlarm:         string(event.HeadAlarm),
		FirstEvidence:     bytesOf(event.Evidence[0]),
		SecondEvidence:    bytesOf(event.Evidence[1]),
		EvsAlarm:          string(event.EvsAlarm),
		EvsAlarmDetail:    string(event.EvsAlarmDetail),
		Version:           event.Version,
		PushId:            idOf(event.PushId),
		Count:             event.Count,
		VerifiedSinceMs:   millisOf(event.VerifiedSince),
		RecordAlarm:       string(event.RecordAlarm),
		BridgeAlarm:       string(event.BridgeAlarm),
		DnsAlarm:          string(event.DnsAlarm),
		CtAlarm:           string(event.CtAlarm),
		MailReceiverAlarm: string(event.MailReceiverAlarm),
	}
	if erasure := event.Erasure; erasure != nil {
		wire.Erasure = &DaemonEventErasure{
			ErasureId:   erasure.ErasureId,
			State:       erasure.State,
			ObjectsLeft: erasure.ObjectsLeft,
			BytesLeft:   erasure.BytesLeft,
			NextTryMs:   millisOf(erasure.NextTry),
			FinishMs:    millisOf(erasure.Finish),
		}
	}
	return wire
}

// What the ring is attached to: a Sidecar, or anything raising events as one does.
type DaemonEventSource interface {
	// Calls callback with each event from here on, until the answer is called (Sidecar.AddEventCallback).
	AddEventCallback(callback SidecarEventFunction) func()
	// The network it is enrolled in, nil before enrollment (Sidecar.NetworkId).
	NetworkId() *Id
	// Its ids, nil before it has an identity (Sidecar.Identity).
	Identity() *SidecarIdentity
}

// One daemon's ring of its attached sources' events, which the events method reads (see the file's comment). Made by
// Daemon.Events.
type DaemonEvents struct {
	settings *SidecarLocalSettings
	clock    Clock
	// minted when the ring starts, and named by every cursor it answers
	ringId Id
	// the events calls waiting now, raised before a wait and lowered after it
	waitingCount *MonitorValue[int]

	stateLock sync.Mutex
	// a circular buffer of count entries, the oldest at head
	entries []daemonEventEntry
	head    int
	count   int
	// the newest event's sequence, 0 before the first
	newestSequence uint64
	// closed and replaced at each event, so a waiter that read the ring under the lock wakes for the next one
	added chan struct{}
}

// One kept event and its sequence.
type daemonEventEntry struct {
	sequence uint64
	event    *DaemonEvent
}

// The daemon's ring of events, made at its first use on the daemon's local settings and clock.
func (self *Daemon) Events() *DaemonEvents {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.events == nil {
		self.events = newDaemonEvents(self.settings.Local, self.clock)
	}
	return self.events
}

// An empty ring on settings' bounds. A count that is not positive, which validation refuses elsewhere, keeps one.
func newDaemonEvents(settings *SidecarLocalSettings, clock Clock) *DaemonEvents {
	return &DaemonEvents{
		settings:     settings,
		clock:        clockOrReal(clock),
		ringId:       NewId(),
		waitingCount: NewMonitorValue(0),
		entries:      make([]daemonEventEntry, max(1, settings.EventRingEventCount)),
		added:        make(chan struct{}),
	}
}

// Keeps source's events from here on, until the answer is called, each stamped as it is raised with the network and
// the id source then names. A host attaches each Sidecar it starts and may leave it attached: a Sidecar that closed
// raises nothing more, and its last events, a logout's state among them, are kept as any other.
func (self *DaemonEvents) Attach(source DaemonEventSource) func() {
	return source.AddEventCallback(func(event SidecarEvent) {
		var originSidecarId *Id
		if identity := source.Identity(); identity != nil {
			sidecarId := identity.SidecarId
			originSidecarId = &sidecarId
		}
		self.add(newDaemonEvent(source.NetworkId(), originSidecarId, &event))
	})
}

// Keeps event as the next sequence, the oldest going once the ring is full, and wakes every waiting call.
func (self *DaemonEvents) add(event *DaemonEvent) {
	testHookBarrier("daemon.events.add.before", "")
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.newestSequence += 1
		entry := daemonEventEntry{sequence: self.newestSequence, event: event}
		capacity := len(self.entries)
		if self.count < capacity {
			self.entries[(self.head+self.count)%capacity] = entry
			self.count += 1
		} else {
			self.entries[self.head] = entry
			self.head = (self.head + 1) % capacity
		}
		close(self.added)
		self.added = make(chan struct{})
	}()
	testHookBarrier("daemon.events.add.after", "")
}

// The cursor of sequence in this ring.
func (self *DaemonEvents) cursorOf(sequence uint64) string {
	return self.ringId.String() + daemonEventsCursorSeparator + strconv.FormatUint(sequence, 10)
}

// The sequence cursor names and whether it is this ring's, or ErrDaemonEventsCursor for what is no cursor.
func (self *DaemonEvents) sequenceOf(cursor string) (uint64, bool, error) {
	ringText, sequenceText, ok := strings.Cut(cursor, daemonEventsCursorSeparator)
	if !ok {
		return 0, false, ErrDaemonEventsCursor
	}
	ringId, err := ParseId(ringText)
	if err != nil {
		return 0, false, ErrDaemonEventsCursor
	}
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil {
		return 0, false, ErrDaemonEventsCursor
	}
	return sequence, ringId == self.ringId, nil
}

// What a call after sequence reads now: the events past it, at most EventReplyEventCount, or a gap when they are gone,
// and the channel the next event closes. ours says sequence is this ring's.
func (self *DaemonEvents) readWithLock(sequence uint64, ours bool) (*DaemonEventsReply, chan struct{}) {
	reply := &DaemonEventsReply{Events: []*DaemonEvent{}}
	// the oldest kept, one past the newest while none is
	oldestSequence := self.newestSequence - uint64(self.count) + 1
	if !ours || self.newestSequence < sequence || sequence+1 < oldestSequence {
		reply.Gap = true
		reply.Cursor = self.cursorOf(self.newestSequence)
		return reply, self.added
	}
	replyEventCount := max(1, self.settings.EventReplyEventCount)
	for next := sequence + 1; next <= self.newestSequence && len(reply.Events) < replyEventCount; next += 1 {
		entry := self.entries[(self.head+int(next-oldestSequence))%len(self.entries)]
		reply.Events = append(reply.Events, entry.event)
	}
	reply.Cursor = self.cursorOf(sequence + uint64(len(reply.Events)))
	return reply, self.added
}

// The events control method over events (§5.8; QD-821), which ur daemon registers beside its own (cli/).
func DaemonEventsMethod(events *DaemonEvents) *DaemonMethod {
	return &DaemonMethod{
		Name: DaemonMethodEvents,
		Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			params := &DaemonEventsParams{}
			if len(call.Params) != 0 {
				decoder := json.NewDecoder(bytes.NewReader(call.Params))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(params); err != nil {
					return nil, errors.New("events takes {after, wait_ms}")
				}
			}
			return events.next(ctx, call.SessionDone, params.After, params.WaitMs)
		},
	}
}

// What one events call answers (see the file's comment). A wait ends with sessionDone, which nil never closes, and
// with ctx, the daemon's context under the request bound.
func (self *DaemonEvents) next(ctx context.Context, sessionDone <-chan struct{}, after string, waitMs int64) (*DaemonEventsReply, error) {
	if after == "" {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return &DaemonEventsReply{Events: []*DaemonEvent{}, Cursor: self.cursorOf(self.newestSequence)}, nil
	}
	sequence, ours, err := self.sequenceOf(after)
	if err != nil {
		return nil, err
	}
	// past the cap a wait is the cap, compared in milliseconds first so a huge wait_ms cannot overflow
	wait := time.Duration(0)
	switch {
	case waitMs <= 0:
	case int64(self.settings.EventWaitTimeout/time.Millisecond) < waitMs:
		wait = self.settings.EventWaitTimeout
	default:
		wait = time.Duration(waitMs) * time.Millisecond
	}
	var timeout <-chan time.Time
	for {
		reply, added := func() (*DaemonEventsReply, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.readWithLock(sequence, ours)
		}()
		if reply.Gap || 0 < len(reply.Events) || wait <= 0 {
			return reply, nil
		}
		if timeout == nil {
			timeout = self.clock.After(wait)
		}
		testHookBarrier("daemon.events.wait", "")
		passed, err := func() (bool, error) {
			self.waitingCount.Update(func(count int) int { return count + 1 })
			defer self.waitingCount.Update(func(count int) int { return count - 1 })
			select {
			case <-added:
				return false, nil
			case <-timeout:
				return true, nil
			case <-sessionDone:
				return false, errDaemonEventsSessionEnded
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}()
		if err != nil {
			return nil, err
		}
		if passed {
			return &DaemonEventsReply{Events: []*DaemonEvent{}, Cursor: after}, nil
		}
	}
}
