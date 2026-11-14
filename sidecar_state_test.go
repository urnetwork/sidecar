// §5.4's machine, its events and the generation rule (D-SDK-14).

package sidecar

import (
	"sync"
	"testing"
)

// Every state, for tables that walk them all.
var sidecarStates = []SidecarState{
	SidecarStateLocked,
	SidecarStateUnenrolled,
	SidecarStateOffline,
	SidecarStateOnline,
	SidecarStateRevoked,
}

// The reason a move to state carries when none matters, so an edge table reads only the edge.
func plainTransitionTo(state SidecarState, generation int64) sidecarTransition {
	transition := sidecarTransition{to: state, generation: generation}
	if state == SidecarStateRevoked {
		transition.reason = SidecarReasonSigned
		transition.verifiedRevocation = true
	}
	return transition
}

// The lifecycle plainTransitionTo arrives at.
func plainLifecycleAt(state SidecarState, generation int64) sidecarLifecycle {
	lifecycle := sidecarLifecycle{state: state, generation: generation}
	if state == SidecarStateRevoked {
		lifecycle.reason = SidecarReasonSigned
	}
	return lifecycle
}

// Every ordered pair of states, each named legal or illegal. A pair left out of the map fails, so a
// state added later cannot pass unexamined.
func TestSidecarStateTransitions(t *testing.T) {
	type edge struct {
		from SidecarState
		to   SidecarState
	}
	const (
		moves     = sidecarTransitionApplied
		stays     = sidecarTransitionUnchanged
		refuses   = sidecarTransitionRefused
		locked    = SidecarStateLocked
		enrolling = SidecarStateUnenrolled
		offline   = SidecarStateOffline
		online    = SidecarStateOnline
		revoked   = SidecarStateRevoked
	)
	want := map[edge]sidecarTransitionResult{
		{from: locked, to: locked}:    stays,
		{from: locked, to: enrolling}: moves,
		{from: locked, to: offline}:   refuses,
		{from: locked, to: online}:    refuses,
		{from: locked, to: revoked}:   refuses,

		{from: enrolling, to: locked}:    moves,
		{from: enrolling, to: enrolling}: stays,
		{from: enrolling, to: offline}:   moves,
		{from: enrolling, to: online}:    refuses,
		{from: enrolling, to: revoked}:   moves,

		{from: offline, to: locked}:    moves,
		{from: offline, to: enrolling}: moves,
		{from: offline, to: offline}:   stays,
		{from: offline, to: online}:    moves,
		{from: offline, to: revoked}:   moves,

		{from: online, to: locked}:    moves,
		{from: online, to: enrolling}: refuses,
		{from: online, to: offline}:   moves,
		{from: online, to: online}:    stays,
		{from: online, to: revoked}:   moves,

		{from: revoked, to: locked}:    refuses,
		{from: revoked, to: enrolling}: refuses,
		{from: revoked, to: offline}:   refuses,
		{from: revoked, to: online}:    refuses,
		{from: revoked, to: revoked}:   stays,
	}
	for _, from := range sidecarStates {
		for _, to := range sidecarStates {
			wantResult, ok := want[edge{from: from, to: to}]
			if !ok {
				t.Errorf("%s to %s has no row", from, to)
				continue
			}
			current := plainLifecycleAt(from, 3)
			next, result := nextSidecarLifecycle(current, plainTransitionTo(to, 3))
			if result != wantResult {
				t.Errorf("%s to %s: result %d, want %d", from, to, result, wantResult)
			}
			wantNext := current
			if wantResult == moves {
				wantNext = plainLifecycleAt(to, 3)
			}
			if next != wantNext {
				t.Errorf("%s to %s: at %+v, want %+v", from, to, next, wantNext)
			}
		}
	}
}

// D-CORE-8: a claim alone never revokes. Each state that could take the move refuses it unverified,
// and nothing is left half done.
func TestOnlyAVerifiedRevocationRevokes(t *testing.T) {
	for _, from := range []SidecarState{SidecarStateUnenrolled, SidecarStateOffline, SidecarStateOnline} {
		current := plainLifecycleAt(from, 3)
		transition := sidecarTransition{to: SidecarStateRevoked, reason: SidecarReasonSigned, generation: 3}
		next, result := nextSidecarLifecycle(current, transition)
		if result != sidecarTransitionRefused || next != current {
			t.Errorf("%s: result %d, at %+v", from, result, next)
		}
	}
}

// A verifier's flag carries nothing to a state that is not Revoked.
func TestVerifiedFlagMovesNothingElse(t *testing.T) {
	transition := sidecarTransition{to: SidecarStateOnline, generation: 3, verifiedRevocation: true}
	next, result := nextSidecarLifecycle(plainLifecycleAt(SidecarStateLocked, 3), transition)
	if result != sidecarTransitionRefused || next.state != SidecarStateLocked {
		t.Errorf("result %d, at %+v", result, next)
	}
}

// §18.5's reasons, each only on its state.
func TestReasonsBelongToTheirState(t *testing.T) {
	unenrolled := []SidecarStateReason{
		"",
		SidecarReasonExpired,
		SidecarReasonRefused,
		SidecarReasonParentLost,
		SidecarReasonSessionEnded,
		SidecarReasonKeystoreLost,
	}
	for _, reason := range unenrolled {
		transition := sidecarTransition{to: SidecarStateUnenrolled, reason: reason, generation: 3}
		next, result := nextSidecarLifecycle(plainLifecycleAt(SidecarStateOffline, 3), transition)
		if result != sidecarTransitionApplied || next.reason != reason {
			t.Errorf("unenrolled %q: result %d, at %+v", reason, result, next)
		}
	}

	for _, c := range []struct {
		from       SidecarState
		transition sidecarTransition
	}{
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateUnenrolled, reason: SidecarReasonSigned, generation: 3}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateUnenrolled, reason: "invented", generation: 3}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateLocked, reason: SidecarReasonKeystoreLost, generation: 3}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateOnline, reason: SidecarReasonExpired, generation: 3}},
		{from: SidecarStateUnenrolled, transition: sidecarTransition{to: SidecarStateOffline, reason: SidecarReasonRefused, generation: 3}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateRevoked, generation: 3, verifiedRevocation: true}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: SidecarStateRevoked, reason: SidecarReasonRefused, generation: 3, verifiedRevocation: true}},
		{from: SidecarStateOffline, transition: sidecarTransition{to: "invented", generation: 3}},
	} {
		current := plainLifecycleAt(c.from, 3)
		next, result := nextSidecarLifecycle(current, c.transition)
		if result != sidecarTransitionRefused || next != current {
			t.Errorf("%+v from %s: result %d, at %+v", c.transition, c.from, result, next)
		}
	}
}

func TestALaterCauseReplacesTheReason(t *testing.T) {
	current := sidecarLifecycle{state: SidecarStateUnenrolled, reason: SidecarReasonExpired, generation: 3}
	transition := sidecarTransition{to: SidecarStateUnenrolled, reason: SidecarReasonSessionEnded, generation: 3}
	next, result := nextSidecarLifecycle(current, transition)
	if result != sidecarTransitionApplied || next.reason != SidecarReasonSessionEnded {
		t.Errorf("result %d, at %+v", result, next)
	}
}

// A stale input is dropped wherever it points, a legal edge and an illegal one alike, since it reports
// on a client that is gone (D-SDK-14).
func TestOlderGenerationTransitionDropped(t *testing.T) {
	for _, from := range sidecarStates {
		for _, to := range sidecarStates {
			current := plainLifecycleAt(from, 4)
			next, result := nextSidecarLifecycle(current, plainTransitionTo(to, 3))
			if result != sidecarTransitionDropped || next != current {
				t.Errorf("%s to %s: result %d, at %+v", from, to, result, next)
			}
		}
	}
}

// §18.5: re-enrollment and pairing go offline at generation n+1, from wherever the old client was.
func TestANewGenerationBeginsAtOffline(t *testing.T) {
	for _, from := range []SidecarState{SidecarStateUnenrolled, SidecarStateOffline, SidecarStateOnline} {
		next, result := nextSidecarLifecycle(plainLifecycleAt(from, 3), plainTransitionTo(SidecarStateOffline, 4))
		if result != sidecarTransitionApplied || next != plainLifecycleAt(SidecarStateOffline, 4) {
			t.Errorf("from %s: result %d, at %+v", from, result, next)
		}
	}
}

func TestANewGenerationGoesNowhereElse(t *testing.T) {
	for _, from := range sidecarStates {
		for _, to := range sidecarStates {
			if to == SidecarStateOffline && from != SidecarStateLocked && from != SidecarStateRevoked {
				continue
			}
			current := plainLifecycleAt(from, 3)
			next, result := nextSidecarLifecycle(current, plainTransitionTo(to, 4))
			if result != sidecarTransitionRefused || next != current {
				t.Errorf("%s to %s: result %d, at %+v", from, to, result, next)
			}
		}
	}
}

// A base Sidecar over default settings, with its log silenced.
func newTestSidecar(t *testing.T) *Sidecar {
	t.Helper()
	settings := validSidecarSettings()
	settings.Log = NewNoopLogger()
	return newSidecarBase(nil, settings)
}

// Collects what a Sidecar raises.
func recordEvents(sidecar *Sidecar) *[]SidecarEvent {
	events := &[]SidecarEvent{}
	sidecar.eventCallbacks.Add(func(event SidecarEvent) {
		*events = append(*events, event)
	})
	return events
}

// Walks a sidecar to Online at generation.
func driveOnline(t *testing.T, sidecar *Sidecar, generation int64) {
	t.Helper()
	for _, transition := range []sidecarTransition{
		{to: SidecarStateUnenrolled},
		{to: SidecarStateOffline, generation: generation},
		{to: SidecarStateOnline, generation: generation},
	} {
		if !sidecar.applyTransition(transition) {
			t.Fatalf("%+v did not move", transition)
		}
	}
}

func TestNewSidecarBaseStartsLocked(t *testing.T) {
	sidecar := newTestSidecar(t)
	if sidecar.lifecycle != (sidecarLifecycle{state: SidecarStateLocked}) {
		t.Errorf("lifecycle %+v", sidecar.lifecycle)
	}
	if state := sidecar.state.Value(); state != SidecarStateLocked {
		t.Errorf("state %s", state)
	}
}

// Status names, beside a client's state, the generation in that state: the next generation, which a pairing or a
// re-enrollment binds in the keychain while the old client is up, shows once the machine has moved to it, Offline.
// Short of a client the keychain's generation shows as it is read.
func TestStatusNamesTheGenerationOfItsState(t *testing.T) {
	for _, c := range []struct {
		state           SidecarState
		generation      int64
		boundGeneration int64
		wantGeneration  int64
	}{
		{state: SidecarStateOnline, generation: 1, boundGeneration: 2, wantGeneration: 1},
		{state: SidecarStateOffline, generation: 1, boundGeneration: 2, wantGeneration: 1},
		{state: SidecarStateOffline, generation: 2, boundGeneration: 2, wantGeneration: 2},
		{state: SidecarStateOnline, generation: 2, boundGeneration: 2, wantGeneration: 2},
		{state: SidecarStateUnenrolled, generation: 1, boundGeneration: 2, wantGeneration: 2},
		{state: SidecarStateUnenrolled, generation: 0, boundGeneration: 3, wantGeneration: 3},
		{state: SidecarStateLocked, generation: 0, boundGeneration: 3, wantGeneration: 3},
		{state: SidecarStateRevoked, generation: 1, boundGeneration: 2, wantGeneration: 2},
		{state: SidecarStateUnenrolled, generation: 0, boundGeneration: 0, wantGeneration: 0},
	} {
		sidecar := newTestSidecar(t)
		sidecar.lifecycle = plainLifecycleAt(c.state, c.generation)
		if 0 < c.boundGeneration {
			sidecar.setIdentity(nil, &SidecarIdentity{Generation: c.boundGeneration})
		}
		if status := sidecar.Status(); status.State != c.state || status.Generation != c.wantGeneration {
			t.Errorf("%s at %d, the keychain at %d: status %s at %d", c.state, c.generation, c.boundGeneration, status.State, status.Generation)
		}
	}
}

func TestATransitionRaisesItsStateEvent(t *testing.T) {
	sidecar := newTestSidecar(t)
	events := recordEvents(sidecar)
	driveOnline(t, sidecar, 2)
	transition := sidecarTransition{to: SidecarStateOffline, generation: 2}
	if !sidecar.applyTransition(transition) {
		t.Fatal("did not move")
	}
	transition = sidecarTransition{to: SidecarStateUnenrolled, reason: SidecarReasonRefused, generation: 2}
	if !sidecar.applyTransition(transition) {
		t.Fatal("did not move")
	}

	want := []SidecarEvent{
		{Kind: SidecarEventState, State: SidecarStateUnenrolled},
		{Kind: SidecarEventState, State: SidecarStateOffline, Generation: 2},
		{Kind: SidecarEventState, State: SidecarStateOnline, Generation: 2},
		{Kind: SidecarEventState, State: SidecarStateOffline, Generation: 2},
		{Kind: SidecarEventState, State: SidecarStateUnenrolled, Reason: SidecarReasonRefused, Generation: 2},
	}
	if len(*events) != len(want) {
		t.Fatalf("events %+v", *events)
	}
	for i, event := range *events {
		if event.Kind != want[i].Kind || event.State != want[i].State ||
			event.Reason != want[i].Reason || event.Generation != want[i].Generation {
			t.Errorf("event %d: %+v, want %+v", i, event, want[i])
		}
	}
	if state := sidecar.state.Value(); state != SidecarStateUnenrolled {
		t.Errorf("state %s", state)
	}
}

// A waiter on the MonitorValue sees what the machine did, so nothing reads a stale state.
func TestATransitionWakesAStateWaiter(t *testing.T) {
	sidecar := newTestSidecar(t)
	_, changed := sidecar.state.Get()
	sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	select {
	case <-changed:
	default:
		t.Error("the state's channel did not close")
	}
}

// An illegal input leaves everything as it was: no state, no event, no wake.
func TestARefusedTransitionRaisesNothing(t *testing.T) {
	sidecar := newTestSidecar(t)
	events := recordEvents(sidecar)
	_, changed := sidecar.state.Get()
	if sidecar.applyTransition(sidecarTransition{to: SidecarStateOnline}) {
		t.Error("Locked went Online")
	}
	if len(*events) != 0 {
		t.Errorf("events %+v", *events)
	}
	select {
	case <-changed:
		t.Error("the state's channel closed")
	default:
	}
	if sidecar.lifecycle.state != SidecarStateLocked {
		t.Errorf("lifecycle %+v", sidecar.lifecycle)
	}
}

// D-SDK-14's case: a released logout event from the old client must not end the new pairing, and must
// not reach a host either.
func TestOlderGenerationEventDropped(t *testing.T) {
	sidecar := newTestSidecar(t)
	driveOnline(t, sidecar, 2)
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 3}) {
		t.Fatal("generation 3 did not bind")
	}
	events := recordEvents(sidecar)

	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventRefused, Generation: 2})
	if len(*events) != 0 {
		t.Errorf("the old generation's event arrived: %+v", *events)
	}
	stale := sidecarTransition{to: SidecarStateUnenrolled, reason: SidecarReasonRefused, generation: 2}
	if sidecar.applyTransition(stale) {
		t.Error("the old generation's refusal moved the machine")
	}
	if len(*events) != 0 {
		t.Errorf("the old generation's refusal raised %+v", *events)
	}
	if sidecar.lifecycle != (sidecarLifecycle{state: SidecarStateOffline, generation: 3}) {
		t.Errorf("lifecycle %+v", sidecar.lifecycle)
	}

	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventRefused, Generation: 3})
	if len(*events) != 1 {
		t.Errorf("the current generation's event did not arrive: %+v", *events)
	}
}

// An alarm no client raised has no generation to fall behind.
func TestAnEventNamingNoGenerationTakesTheCurrentOne(t *testing.T) {
	sidecar := newTestSidecar(t)
	driveOnline(t, sidecar, 2)
	events := recordEvents(sidecar)
	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork})
	if len(*events) != 1 || (*events)[0].Generation != 2 {
		t.Errorf("events %+v", *events)
	}
}

func TestEveryCallbackGetsTheEvent(t *testing.T) {
	sidecar := newTestSidecar(t)
	first := recordEvents(sidecar)
	second := recordEvents(sidecar)
	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventKeyChanged})
	if len(*first) != 1 || len(*second) != 1 {
		t.Errorf("first %+v, second %+v", *first, *second)
	}
}

// A callback may ask the Sidecar for its state and raise another event, so no lock can be held
// across it. The test's own timeout is what a deadlock here would hit.
func TestACallbackMayCallBackIn(t *testing.T) {
	sidecar := newTestSidecar(t)
	var kinds []SidecarEventKind
	sidecar.eventCallbacks.Add(func(event SidecarEvent) {
		kinds = append(kinds, event.Kind)
		if event.Kind == SidecarEventState {
			sidecar.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
		}
	})
	sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	if len(kinds) != 2 || kinds[1] != SidecarEventRefused {
		t.Errorf("kinds %v", kinds)
	}
}

// Zero never reads as a status that creates anything: an adapter that sets none is Failed.
func TestAKeyStoreStatusLeftUnsetIsFailed(t *testing.T) {
	var status SidecarKeyStoreStatus
	if status != SidecarKeyStoreFailed {
		t.Errorf("zero is %d", status)
	}
}

func TestErrorsNameNoMoreThanTheirIds(t *testing.T) {
	approvalId := Id{1}
	pending := &ApprovalPendingError{ApprovalId: approvalId}
	if want := "approval " + approvalId.String() + " is pending"; pending.Error() != want {
		t.Errorf("error %q", pending.Error())
	}
	refused := &DeviceRevokeError{Code: "REVOKE_STALE", Position: 9}
	if refused.Error() != "REVOKE_STALE" {
		t.Errorf("error %q", refused.Error())
	}
}

// D-SDK-14's order: an older generation's event that a callback held up while a newer generation bound
// reaches no later subscriber after the newer one's, and the newer generation's raiser is not held up.
// The check and the delivery were once apart, so the older event arrived last.
func TestAnOvertakenEventNeverArrivesAfterTheNewerGeneration(t *testing.T) {
	sidecar := newTestSidecar(t)
	driveOnline(t, sidecar, 2)
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 2}) {
		t.Fatal("offline at 2 did not move")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	sidecar.eventCallbacks.Add(func(event SidecarEvent) {
		if event.Kind == SidecarEventState && event.Reason == SidecarReasonRefused && event.Generation == 2 {
			close(entered)
			<-release
		}
	})
	var recordedLock sync.Mutex
	recorded := []SidecarEvent{}
	sidecar.eventCallbacks.Add(func(event SidecarEvent) {
		recordedLock.Lock()
		defer recordedLock.Unlock()
		recorded = append(recorded, event)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled, reason: SidecarReasonRefused, generation: 2})
	}()
	<-entered
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 3}) {
		t.Fatal("generation 3 did not bind")
	}
	close(release)
	<-done
	recordedLock.Lock()
	defer recordedLock.Unlock()
	newest := int64(0)
	for _, event := range recorded {
		if event.Generation < newest {
			t.Errorf("generation %d's %s/%s arrived after generation %d's", event.Generation, event.State, event.Reason, newest)
		}
		newest = max(newest, event.Generation)
	}
	if len(recorded) == 0 || recorded[len(recorded)-1].Generation != 3 {
		t.Errorf("recorded %+v", recorded)
	}
}

// A callback that panics stops its own delivery and nothing after it: the next event raised delivers
// what was left, and itself.
func TestAPanickingCallbackDoesNotStopLaterEvents(t *testing.T) {
	sidecar := newTestSidecar(t)
	panicking := true
	sidecar.eventCallbacks.Add(func(event SidecarEvent) {
		if panicking {
			panicking = false
			panic("synthetic callback panic")
		}
	})
	events := recordEvents(sidecar)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not reach the raiser")
			}
		}()
		sidecar.emitEvent(SidecarEvent{Kind: SidecarEventKeyChanged})
	}()
	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork})
	if len(*events) != 1 || (*events)[0].Kind != SidecarEventHeadAlarm {
		t.Errorf("events %+v", *events)
	}
}
