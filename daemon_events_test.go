//go:build !js && !ios && !android && !sdk_mobile_bind && !windows

package sidecar

// The daemon's events (QD-821): the ring and its cursors, what the events method answers past a cursor, its waits and
// its gaps, a wait's end with its session and with its daemon, a session's lines read ahead and still answered in
// order, the reply's fields and that none can be a secret, and the stamps a source's events take. Waits run on a test
// clock and on the ring's count of waiting calls, never on sleeps.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A ring on the default local settings as edit changes them, on clock.
func newTestDaemonEvents(edit func(settings *SidecarLocalSettings), clock Clock) *DaemonEvents {
	settings := DefaultSidecarSettings().LocalSettings
	if edit != nil {
		edit(settings)
	}
	return newDaemonEvents(settings, clock)
}

// An event of kind at generation, with an approval id of its own so each is told apart.
func testDaemonEvent(kind SidecarEventKind, generation int64) *DaemonEvent {
	approvalId := NewId()
	return newDaemonEvent(nil, nil, &SidecarEvent{Kind: kind, Generation: generation, ApprovalId: &approvalId})
}

// Waits until count events calls wait. The real-time bound only stops a broken test from hanging.
func awaitTestDaemonEventsWaiting(t *testing.T, events *DaemonEvents, count int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		waiting, changed := events.waitingCount.Get()
		if waiting == count {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d events calls wait, want %d", waiting, count)
		}
	}
}

// One events call's answer, run on its own goroutine.
type testDaemonEventsCall struct {
	reply *DaemonEventsReply
	err   error
}

// Calls next on its own goroutine, answering on the channel.
func goTestDaemonEventsNext(events *DaemonEvents, ctx context.Context, sessionDone <-chan struct{}, after string, waitMs int64) chan testDaemonEventsCall {
	answered := make(chan testDaemonEventsCall, 1)
	go func() {
		reply, err := events.next(ctx, sessionDone, after, waitMs)
		answered <- testDaemonEventsCall{reply: reply, err: err}
	}()
	return answered
}

// The answer on answered. The real-time bound only stops a broken test from hanging.
func awaitTestDaemonEventsCall(t *testing.T, answered chan testDaemonEventsCall) testDaemonEventsCall {
	t.Helper()
	select {
	case call := <-answered:
		return call
	case <-time.After(10 * time.Second):
		t.Fatal("the events call did not answer")
		return testDaemonEventsCall{}
	}
}

// Whether reply holds exactly want, in order.
func testDaemonEventsHold(reply *DaemonEventsReply, want ...*DaemonEvent) bool {
	return reply != nil && !reply.Gap && slices.Equal(reply.Events, want)
}

// The events past a cursor, in order, at once; a cursor a reply answered goes on from its last event, and an empty
// after answers where the ring is now and nothing else.
func TestDaemonEventsAnswersPastTheCursor(t *testing.T) {
	ctx := context.Background()
	events := newTestDaemonEvents(nil, newTokenTestClock())
	start, err := events.next(ctx, nil, "", 0)
	if err != nil || len(start.Events) != 0 || start.Gap || start.Cursor != events.cursorOf(0) {
		t.Fatalf("an empty after: %+v %v", start, err)
	}
	raised := []*DaemonEvent{
		testDaemonEvent(SidecarEventState, 1),
		testDaemonEvent(SidecarEventApprovalPending, 1),
		testDaemonEvent(SidecarEventHeadAlarm, 1),
	}
	for _, event := range raised {
		events.add(event)
	}
	reply, err := events.next(ctx, nil, start.Cursor, 0)
	if err != nil || !testDaemonEventsHold(reply, raised...) || reply.Cursor != events.cursorOf(3) {
		t.Fatalf("past the start: %+v %v", reply, err)
	}
	again, err := events.next(ctx, nil, reply.Cursor, 0)
	if err != nil || !testDaemonEventsHold(again) || again.Cursor != reply.Cursor {
		t.Fatalf("past the last: %+v %v", again, err)
	}
	// a reply takes nothing from the ring: the start still answers all three, and an empty after the newest
	if reply, _ := events.next(ctx, nil, start.Cursor, 0); !testDaemonEventsHold(reply, raised...) {
		t.Fatalf("the start again: %+v", reply)
	}
	if now, _ := events.next(ctx, nil, "", 0); now.Cursor != events.cursorOf(3) || len(now.Events) != 0 {
		t.Fatalf("an empty after past three events: %+v", now)
	}
}

// With nothing past the cursor a call waits, at most the cap, and the next event answers it.
func TestDaemonEventsWaitsForTheNextEvent(t *testing.T) {
	ctx := context.Background()
	clock := newTokenTestClock()
	events := newTestDaemonEvents(nil, clock)
	start, _ := events.next(ctx, nil, "", 0)
	answered := goTestDaemonEventsNext(events, ctx, nil, start.Cursor, 60_000)
	if armed := clock.awaitArmed(t, 1); armed != 25*time.Second {
		t.Fatalf("a 60 s wait armed %s, not EventWaitTimeout's 25 s", armed)
	}
	awaitTestDaemonEventsWaiting(t, events, 1)
	raised := testDaemonEvent(SidecarEventAccessRequest, 2)
	events.add(raised)
	call := awaitTestDaemonEventsCall(t, answered)
	if call.err != nil || !testDaemonEventsHold(call.reply, raised) || call.reply.Cursor != events.cursorOf(1) {
		t.Fatalf("the wait answered %+v %v", call.reply, call.err)
	}
	awaitTestDaemonEventsWaiting(t, events, 0)
}

// A wait that passes answers no events and its own cursor again; a huge wait_ms is the cap, and none answers at once.
func TestDaemonEventsWaitPassesWithNoEvent(t *testing.T) {
	ctx := context.Background()
	clock := newTokenTestClock()
	events := newTestDaemonEvents(nil, clock)
	start, _ := events.next(ctx, nil, "", 0)
	answered := goTestDaemonEventsNext(events, ctx, nil, start.Cursor, 1500)
	if armed := clock.awaitArmed(t, 1); armed != 1500*time.Millisecond {
		t.Fatalf("armed %s", armed)
	}
	awaitTestDaemonEventsWaiting(t, events, 1)
	clock.Advance(1500 * time.Millisecond)
	call := awaitTestDaemonEventsCall(t, answered)
	if call.err != nil || !testDaemonEventsHold(call.reply) || call.reply.Cursor != start.Cursor {
		t.Fatalf("a wait that passed: %+v %v", call.reply, call.err)
	}

	answered = goTestDaemonEventsNext(events, ctx, nil, start.Cursor, math.MaxInt64)
	if armed := clock.awaitArmed(t, 2); armed != 25*time.Second {
		t.Fatalf("the most a wait_ms holds armed %s", armed)
	}
	awaitTestDaemonEventsWaiting(t, events, 1)
	clock.Advance(25 * time.Second)
	if call := awaitTestDaemonEventsCall(t, answered); call.err != nil || !testDaemonEventsHold(call.reply) {
		t.Fatalf("the capped wait: %+v %v", call.reply, call.err)
	}

	for _, waitMs := range []int64{0, -1} {
		if reply, err := events.next(ctx, nil, start.Cursor, waitMs); err != nil || !testDaemonEventsHold(reply) || reply.Cursor != start.Cursor {
			t.Fatalf("wait_ms %d: %+v %v", waitMs, reply, err)
		}
	}
	if armed, _ := clock.armed.Get(); armed != 2 {
		t.Fatalf("a call that waits for nothing armed a wait: %d", armed)
	}
}

// A cursor the ring passed, another ring's or one past the newest answers gap and the current cursor at once; one
// the ring still holds answers what follows it, a reply at a time; what is no cursor is refused.
func TestDaemonEventsGapWhenTheRingPassed(t *testing.T) {
	ctx := context.Background()
	clock := newTokenTestClock()
	events := newTestDaemonEvents(func(settings *SidecarLocalSettings) {
		settings.EventRingEventCount = 4
		settings.EventReplyEventCount = 3
	}, clock)
	start, _ := events.next(ctx, nil, "", 0)
	raised := []*DaemonEvent{}
	for range 6 {
		event := testDaemonEvent(SidecarEventErasure, 1)
		raised = append(raised, event)
		events.add(event)
	}
	gap, err := events.next(ctx, nil, start.Cursor, 60_000)
	if err != nil || !gap.Gap || len(gap.Events) != 0 || gap.Cursor != events.cursorOf(6) {
		t.Fatalf("a passed cursor: %+v %v", gap, err)
	}
	if after, err := events.next(ctx, nil, gap.Cursor, 0); err != nil || !testDaemonEventsHold(after) {
		t.Fatalf("past the gap's cursor: %+v %v", after, err)
	}
	// 3 to 6 are kept: a reader at 2 takes 3, 4 and 5, then 6; one at 1 lost 2
	first, err := events.next(ctx, nil, events.cursorOf(2), 60_000)
	if err != nil || !testDaemonEventsHold(first, raised[2:5]...) || first.Cursor != events.cursorOf(5) {
		t.Fatalf("a reader at the oldest's edge: %+v %v", first, err)
	}
	if second, err := events.next(ctx, nil, first.Cursor, 0); err != nil || !testDaemonEventsHold(second, raised[5]) {
		t.Fatalf("the rest: %+v %v", second, err)
	}
	if lost, _ := events.next(ctx, nil, events.cursorOf(1), 0); !lost.Gap || lost.Cursor != events.cursorOf(6) {
		t.Fatalf("a reader one past the edge: %+v", lost)
	}
	// a daemon that ended had another ring, and nothing reached past the newest
	other := newTestDaemonEvents(nil, clock)
	for _, cursor := range []string{other.cursorOf(6), other.cursorOf(0), events.cursorOf(7)} {
		if reply, err := events.next(ctx, nil, cursor, 60_000); err != nil || !reply.Gap || reply.Cursor != events.cursorOf(6) {
			t.Errorf("%s: %+v %v", cursor, reply, err)
		}
	}
	for _, cursor := range []string{"x", ":", "not-an-id:1", events.ringId.String() + ":-1", events.ringId.String() + ":one", events.ringId.String()} {
		if _, err := events.next(ctx, nil, cursor, 0); !errors.Is(err, ErrDaemonEventsCursor) {
			t.Errorf("%q: %v", cursor, err)
		}
	}
	if armed, _ := clock.armed.Get(); armed != 0 {
		t.Fatalf("a gap waited: %d waits armed", armed)
	}
}

// A waiting call ends once its session does, the session's other calls and the daemon's other sessions going on; and
// one ends once the daemon does. The test clock never fires a wait, so only the session's end or the daemon's can.
func TestDaemonEventsWaitEndsWithTheSession(t *testing.T) {
	ctx := context.Background()
	clock := newTokenTestClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = clock
	})
	events := started.daemon.Events()
	if events != started.daemon.Events() {
		t.Fatal("a daemon made two rings")
	}
	if err := started.daemon.RegisterMethod(DaemonEventsMethod(events)); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	start := &DaemonEventsReply{}
	if err := client.Call(ctx, DaemonMethodEvents, &DaemonEventsParams{}, false, start); err != nil || start.Cursor == "" {
		t.Fatalf("the cursor: %+v %v", start, err)
	}

	waiting := dialTestDaemon(t, started, DaemonModeControl)
	called := make(chan error, 1)
	go func() {
		called <- waiting.Call(ctx, DaemonMethodEvents, &DaemonEventsParams{After: start.Cursor, WaitMs: 60_000}, false, &DaemonEventsReply{})
	}()
	awaitTestDaemonEventsWaiting(t, events, 1)
	waiting.Close()
	awaitTestDaemonEventsWaiting(t, events, 0)
	if err := <-called; err == nil {
		t.Fatal("a closed session's call answered")
	}

	raised := testDaemonEvent(SidecarEventMailSend, 1)
	events.add(raised)
	reply := &DaemonEventsReply{}
	if err := client.Call(ctx, DaemonMethodEvents, &DaemonEventsParams{After: start.Cursor, WaitMs: 60_000}, false, reply); err != nil ||
		len(reply.Events) != 1 || reply.Events[0].Kind != string(SidecarEventMailSend) || *reply.Events[0].ApprovalId != *raised.ApprovalId {
		t.Fatalf("the other session after the close: %+v %v", reply, err)
	}

	go func() {
		called <- client.Call(ctx, DaemonMethodEvents, &DaemonEventsParams{After: reply.Cursor, WaitMs: 60_000}, false, &DaemonEventsReply{})
	}()
	awaitTestDaemonEventsWaiting(t, events, 1)
	started.daemon.Close()
	awaitTestDaemonEventsWaiting(t, events, 0)
	if err := <-called; err == nil {
		t.Fatal("a call answered past the daemon's end")
	}
}

// The session's reader runs a line ahead, and yet each line is answered in order, every one a caller sent before it
// closed its side among them.
func TestDaemonSessionAnswersEveryLineInOrder(t *testing.T) {
	started := startTestDaemon(t, nil)
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.echo", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return json.RawMessage(call.Params), nil
	}}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", started.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello, err := encodeDaemonHello(&DaemonHello{Mode: DaemonModeControl, Version: testDaemonVersion})
	if err != nil {
		t.Fatal(err)
	}
	lines := string(hello)
	for i := 1; i <= 3; i += 1 {
		lines += `{"jsonrpc":"2.0","id":` + strconv.Itoa(i) + `,"method":"synthetic.echo","params":{"n":` + strconv.Itoa(i) + `}}` + "\n"
	}
	if _, err := conn.Write([]byte(lines)); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("the hello's answer: %v", err)
	}
	for i := 1; i <= 3; i += 1 {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		response := &daemonRpcResponse{}
		if err := json.Unmarshal([]byte(line), response); err != nil || string(response.Id) != strconv.Itoa(i) ||
			string(response.Result) != `{"n":`+strconv.Itoa(i)+`}` {
			t.Fatalf("answer %d: %q", i, line)
		}
	}
	if line, err := reader.ReadString('\n'); err == nil {
		t.Fatalf("a fourth answer %q", line)
	}
}

// The wire carries the identity that raised a state even if another listener changes the enrollment before the
// ring receives it. An unenrolled state can still have an identity.
func TestDaemonEventKeepsTheOriginThatRaisedItsState(t *testing.T) {
	running := newTestSidecar(t)
	network, origin, nextNetwork, nextSidecar := NewId(), NewId(), NewId(), NewId()
	running.networkId = &network
	running.identity = &SidecarIdentity{NetworkId: network, SidecarId: origin}
	detachListener := running.AddEventCallback(func(event SidecarEvent) {
		running.stateLock.Lock()
		defer running.stateLock.Unlock()
		running.networkId = &nextNetwork
		running.identity = &SidecarIdentity{NetworkId: nextNetwork, SidecarId: nextSidecar}
	})
	defer detachListener()
	events := newDaemonEvents(DefaultSidecarSettings().LocalSettings, nil)
	detachRing := events.Attach(struct{ *Sidecar }{Sidecar: running})
	defer detachRing()
	running.emitEvent(SidecarEvent{Kind: SidecarEventState, State: SidecarStateUnenrolled, Reason: SidecarReasonRefused})
	reply, err := events.next(t.Context(), nil, events.cursorOf(0), 0)
	if err != nil || len(reply.Events) != 1 {
		t.Fatalf("state events: %v, %v", reply, err)
	}
	event := reply.Events[0]
	if event.LoggedOut || event.NetworkId == nil || *event.NetworkId != network || event.OriginSidecarId == nil || *event.OriginSidecarId != origin {
		t.Fatalf("ordinary unenrolled state with its original identity: %+v", event)
	}
}

// Every SidecarEvent with each field set to something, so a field added to it shows up here unmapped.
func fullTestSidecarEvent(t *testing.T) SidecarEvent {
	t.Helper()
	event := SidecarEvent{}
	value := reflect.ValueOf(&event).Elem()
	at := time.Date(2026, time.November, 14, 15, 16, 17, 0, time.UTC)
	for i := 0; i < value.NumField(); i += 1 {
		field := value.Field(i)
		name := value.Type().Field(i).Name
		switch field.Kind() {
		case reflect.String:
			field.SetString("synthetic-" + strings.ToLower(name))
		case reflect.Int, reflect.Int64:
			field.SetInt(int64(100 + i))
		case reflect.Uint64:
			field.SetUint(uint64(200 + i))
		case reflect.Uint32:
			// a set of bits, such as AuthFeatures, each value a set the event names
			field.SetUint(uint64(1 + i%8))
		case reflect.Pointer:
			switch field.Type() {
			case reflect.TypeFor[*Id]():
				id := NewId()
				field.Set(reflect.ValueOf(&id))
			case reflect.TypeFor[*SidecarErasure]():
				field.Set(reflect.ValueOf(&SidecarErasure{
					ErasureId:   NewId(),
					State:       "waiting",
					ObjectsLeft: 7,
					BytesLeft:   8192,
					NextTry:     at.Add(time.Minute),
					Finish:      at.Add(time.Hour),
				}))
			default:
				t.Fatalf("SidecarEvent.%s's type %s has no synthetic value", name, field.Type())
			}
		case reflect.Struct:
			if field.Type() != reflect.TypeFor[time.Time]() {
				t.Fatalf("SidecarEvent.%s's type %s has no synthetic value", name, field.Type())
			}
			field.Set(reflect.ValueOf(at.Add(time.Duration(i) * time.Second)))
		case reflect.Array:
			if field.Type() != reflect.TypeFor[[2][]byte]() {
				t.Fatalf("SidecarEvent.%s's type %s has no synthetic value", name, field.Type())
			}
			field.Set(reflect.ValueOf([2][]byte{{1, 2, 3}, {4, 5, 6}}))
		default:
			t.Fatalf("SidecarEvent.%s's kind %s has no synthetic value", name, field.Kind())
		}
	}
	return event
}

// Each field of SidecarEvent, by name, and the reply's keys that carry it.
var testDaemonEventKeys = map[string][]string{
	"Kind": {"kind"}, "Generation": {"generation"}, "State": {"state"}, "Reason": {"reason"}, "GroupId": {"group_id"},
	"SidecarId": {"sidecar_id"}, "RepoId": {"repo_id"}, "RefId": {"ref_id"}, "Path": {"path"}, "DropId": {"drop_id"},
	"DropState": {"drop_state"}, "NotBefore": {"not_before_ms"}, "SearchAlarm": {"search_alarm"},
	"RequestId": {"request_id"}, "Outcome": {"outcome"}, "SendId": {"send_id"}, "ApprovalId": {"approval_id"},
	"HeadAlarm": {"head_alarm"}, "Evidence": {"first_evidence", "second_evidence"}, "Erasure": {"erasure"},
	"EvsAlarm": {"evs_alarm"}, "EvsAlarmDetail": {"evs_alarm_detail"}, "Version": {"version"}, "PushId": {"push_id"},
	"Count": {"count"}, "VerifiedSince": {"verified_since_ms"}, "RecordAlarm": {"record_alarm"},
	"BridgeAlarm": {"bridge_alarm"}, "DnsAlarm": {"dns_alarm"}, "CtAlarm": {"ct_alarm"},
	"MailReceiverAlarm": {"mail_receiver_alarm"}, "AuthFeatures": {"auth_features"},
}

// Every field an event carries reaches the reply under its key, its times in milliseconds, and the reply shares
// nothing with the event it was made from.
func TestDaemonEventCarriesEveryEventField(t *testing.T) {
	event := fullTestSidecarEvent(t)
	networkId, originSidecarId := NewId(), NewId()
	wire := newDaemonEvent(&networkId, &originSidecarId, &event)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	keyValues := map[string]any{}
	if err := json.Unmarshal(encoded, &keyValues); err != nil {
		t.Fatal(err)
	}
	eventType := reflect.TypeFor[SidecarEvent]()
	for i := 0; i < eventType.NumField(); i += 1 {
		name := eventType.Field(i).Name
		keys, ok := testDaemonEventKeys[name]
		if !ok {
			t.Errorf("SidecarEvent.%s reaches no key of an events reply", name)
			continue
		}
		for _, key := range keys {
			if value, ok := keyValues[key]; !ok || value == nil || reflect.ValueOf(value).IsZero() {
				t.Errorf("SidecarEvent.%s: the reply's %s is %v", name, key, value)
			}
		}
	}
	if wire.NetworkId == nil || *wire.NetworkId != networkId || wire.OriginSidecarId == nil || *wire.OriginSidecarId != originSidecarId {
		t.Errorf("the source's stamps: %v %v", wire.NetworkId, wire.OriginSidecarId)
	}
	if wire.NotBeforeMs != event.NotBefore.UnixMilli() || wire.VerifiedSinceMs != event.VerifiedSince.UnixMilli() ||
		wire.Erasure.NextTryMs != event.Erasure.NextTry.UnixMilli() || wire.Erasure.FinishMs != event.Erasure.Finish.UnixMilli() ||
		wire.Erasure.ErasureId != event.Erasure.ErasureId || wire.Erasure.ObjectsLeft != 7 || wire.Erasure.BytesLeft != 8192 {
		t.Errorf("times and the erasure: %+v %+v", wire, wire.Erasure)
	}
	// the event's own slices and ids may change after it was raised; the reply's do not
	event.Evidence[0][0] = 9
	*event.GroupId = Id{}
	if wire.FirstEvidence[0] != 1 || *wire.GroupId == (Id{}) {
		t.Error("the reply shares the event's memory")
	}
	// a zero time and an absent erasure are left out
	bare := newDaemonEvent(nil, nil, &SidecarEvent{Kind: SidecarEventState, Generation: 3, State: SidecarStateOnline})
	if encoded, _ := json.Marshal(bare); string(encoded) != `{"kind":"state","generation":3,"state":"online"}` {
		t.Errorf("a bare state event: %s", encoded)
	}
}

// A reply holding every field passes the reply walk, no type it can hold is a secret's, and its keys are the ones
// this test names, so a field added to it is read here before any reply carries it.
func TestDaemonEventsReplyHoldsNoSecret(t *testing.T) {
	event := fullTestSidecarEvent(t)
	networkId, originSidecarId := NewId(), NewId()
	reply := &DaemonEventsReply{Events: []*DaemonEvent{newDaemonEvent(&networkId, &originSidecarId, &event)}, Cursor: "c", Gap: true}
	if err := checkDaemonReply(reply); err != nil {
		t.Fatalf("the walk refused an events reply: %v", err)
	}
	// the walk is no formality: the same reply beside a credential is refused
	if err := checkDaemonReply(&struct {
		Reply *DaemonEventsReply
		Leak  *SidecarEnrollCredential
	}{Reply: reply, Leak: &SidecarEnrollCredential{AuthKey: "synthetic"}}); err == nil {
		t.Fatal("CONTROL FAILED: the walk passed a credential")
	}
	seen := map[reflect.Type]bool{}
	var walk func(valueType reflect.Type)
	walk = func(valueType reflect.Type) {
		if seen[valueType] {
			return
		}
		seen[valueType] = true
		if daemonSecretTypes[valueType] || valueType.Implements(daemonSecretValueType) || reflect.PointerTo(valueType).Implements(daemonSecretValueType) {
			t.Errorf("an events reply can hold a %s", valueType)
		}
		switch valueType.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(valueType.Elem())
		case reflect.Map:
			walk(valueType.Key())
			walk(valueType.Elem())
		case reflect.Struct:
			for i := 0; i < valueType.NumField(); i += 1 {
				walk(valueType.Field(i).Type)
			}
		case reflect.Interface, reflect.Func, reflect.Chan:
			t.Errorf("an events reply can hold a %s, which the walk cannot bound", valueType)
		}
	}
	walk(reflect.TypeFor[DaemonEventsReply]())

	keys := []string{"network_id", "origin_sidecar_id"}
	for _, eventKeys := range testDaemonEventKeys {
		keys = append(keys, eventKeys...)
	}
	encoded, err := json.Marshal(reply.Events[0])
	if err != nil {
		t.Fatal(err)
	}
	keyValues := map[string]any{}
	if err := json.Unmarshal(encoded, &keyValues); err != nil {
		t.Fatal(err)
	}
	encodedKeys := []string{}
	for key := range keyValues {
		encodedKeys = append(encodedKeys, key)
	}
	slices.Sort(keys)
	slices.Sort(encodedKeys)
	if !slices.Equal(keys, encodedKeys) {
		t.Errorf("an event's keys %v, want %v", encodedKeys, keys)
	}
	erasureKeys := []string{}
	for key := range keyValues["erasure"].(map[string]any) {
		erasureKeys = append(erasureKeys, key)
	}
	slices.Sort(erasureKeys)
	if want := []string{"bytes_left", "erasure_id", "finish_ms", "next_try_ms", "objects_left", "state"}; !slices.Equal(erasureKeys, want) {
		t.Errorf("an erasure's keys %v, want %v", erasureKeys, want)
	}
}

// A source the ring is attached to: it raises what a test gives it, naming the network and identity the test sets.
type testDaemonEventSource struct {
	callbacks *CallbackList[SidecarEventFunction]

	stateLock sync.Mutex
	networkId *Id
	identity  *SidecarIdentity
}

func newTestDaemonEventSource() *testDaemonEventSource {
	return &testDaemonEventSource{callbacks: NewCallbackList[SidecarEventFunction]()}
}

func (self *testDaemonEventSource) AddEventCallback(callback SidecarEventFunction) func() {
	callbackId := self.callbacks.Add(callback)
	return func() {
		self.callbacks.Remove(callbackId)
	}
}

func (self *testDaemonEventSource) NetworkId() *Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkId
}

func (self *testDaemonEventSource) Identity() *SidecarIdentity {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.identity
}

// Enrolls it in networkId as sidecarId.
func (self *testDaemonEventSource) enroll(networkId Id, sidecarId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkId = &networkId
	self.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: sidecarId, Generation: 1}
}

// Raises event to every callback, as a Sidecar's emitEvent does.
func (self *testDaemonEventSource) raise(event SidecarEvent) {
	for _, callback := range self.callbacks.Get() {
		callback(event)
	}
}

// An attached source's events are kept in the order raised, across sources, each stamped with the network and the
// identity its source named when it was raised; a detached one's are not.
func TestDaemonEventsAttachStampsTheSource(t *testing.T) {
	ctx := context.Background()
	events := newTestDaemonEvents(nil, newTokenTestClock())
	start, _ := events.next(ctx, nil, "", 0)
	further, hosted := newTestDaemonEventSource(), newTestDaemonEventSource()
	hostedNetworkId, hostedSidecarId := NewId(), NewId()
	hosted.enroll(hostedNetworkId, hostedSidecarId)
	detachFurther := events.Attach(further)
	events.Attach(hosted)

	further.raise(SidecarEvent{Kind: SidecarEventState, Generation: 0, State: SidecarStateUnenrolled})
	hosted.raise(SidecarEvent{Kind: SidecarEventApprovalPending, Generation: 2})
	furtherNetworkId, furtherSidecarId := NewId(), NewId()
	further.enroll(furtherNetworkId, furtherSidecarId)
	further.raise(SidecarEvent{Kind: SidecarEventState, Generation: 1, State: SidecarStateOnline})
	detachFurther()
	further.raise(SidecarEvent{Kind: SidecarEventState, Generation: 1, State: SidecarStateOffline})

	reply, err := events.next(ctx, nil, start.Cursor, 0)
	if err != nil || len(reply.Events) != 3 {
		t.Fatalf("%+v %v", reply, err)
	}
	unenrolled, pending, online := reply.Events[0], reply.Events[1], reply.Events[2]
	if unenrolled.State != string(SidecarStateUnenrolled) || unenrolled.NetworkId != nil || unenrolled.OriginSidecarId != nil {
		t.Errorf("the unenrolled source's event: %+v", unenrolled)
	}
	if pending.Kind != string(SidecarEventApprovalPending) || *pending.NetworkId != hostedNetworkId || *pending.OriginSidecarId != hostedSidecarId {
		t.Errorf("the hosted source's event: %+v", pending)
	}
	if online.State != string(SidecarStateOnline) || *online.NetworkId != furtherNetworkId || *online.OriginSidecarId != furtherSidecarId {
		t.Errorf("the enrolled source's event: %+v", online)
	}
}
