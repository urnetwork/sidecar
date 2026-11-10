// The floor (DESIGN-DETAILS 4.2.5's restart row, SDK-M8-17): the posture raises it after each commit whose pin rose,
// and a store restored below it, or at it on another chain, or left empty or legacy under it, or read while the floor
// cannot be, is pending with an alarm until a state brings the pin back to the floor on its chain (Fwd.tla's NoFloor
// twin on real code).

package device

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A floor in memory, with faults a test arms. Safe for concurrent use.
type testPostureFloor struct {
	stateLock sync.Mutex
	n         uint64
	chain     []byte
	loadErr   error
	commitErr error
	// every pin committed, in order
	commits []uint64
}

func (self *testPostureFloor) floor() *PostureFloor {
	return &PostureFloor{
		Load: func() (uint64, []byte, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.loadErr != nil {
				return 0, nil, self.loadErr
			}
			return self.n, bytes.Clone(self.chain), nil
		},
		Commit: func(n uint64, chain []byte) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.commitErr != nil {
				return self.commitErr
			}
			self.n, self.chain = n, bytes.Clone(chain)
			self.commits = append(self.commits, n)
			return nil
		},
	}
}

// The pins committed so far.
func (self *testPostureFloor) committed() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.commits)
}

// Settings with floor.
func testPostureSettingsWithFloor(floor *testPostureFloor) *PostureSettings {
	settings := testPostureSettings()
	settings.Floor = floor.floor()
	return settings
}

// The floor rises with each commit whose pin rose, to that pin and its chain, and with nothing else: not a Pending, a
// state at the pin, a lower state, a fork or a commit of the same pin.
func TestTheFloorRisesWithEachCommittedPin(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	posture, _ := NewPosture(newMemoryPostureStore(), settings)
	posture.SetPending(fixture.pending())
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	tick := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(tick, tick)); err != nil {
		t.Fatal(err)
	}
	posture.SetState(fixture.state(tick, true), nil)
	posture.SetState(fixture.state(3, true), nil)
	posture.SetFork(true)
	posture.SetFork(false)
	if commits := floor.committed(); !slices.Equal(commits, []uint64{3, tick}) {
		t.Errorf("committed %v", commits)
	}
	if want := fixture.chain(tick); floor.n != tick || !bytes.Equal(floor.chain, want[:]) {
		t.Errorf("the floor is at %d", floor.n)
	}
}

// A copy of the store from before the last commits, put back under the floor, restores pending and alarms: deltas and
// a state below the floor are refused, and a state that brings the pin back to the floor on its chain restores
// enforcing.
func TestARolledBackStoreIsPending(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	posture, _ := NewPosture(store, settings)
	posture.SetPending(fixture.pending())
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	copied := store.survivor()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	tick := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(revoke, tick)); err != nil {
		t.Fatal(err)
	}
	if floor.n != tick {
		t.Fatalf("the floor is at %d", floor.n)
	}

	// the copy, put back: its pin 3 is below the floor
	posture, decision := NewPosture(copied, settings)
	if decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreRolledBack) || decision.NetworkId == nil {
		t.Fatalf("the copy restored %v, %v", decision.State, decision.Alarms)
	}
	if decision, err := posture.ApplyDeltas(fixture.log(4, tick)); !errors.Is(err, ErrPostureRefused) || decision.State != PosturePending {
		t.Errorf("deltas on the copy: %v, %v", err, decision.State)
	}
	decision, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3))
	if !errors.Is(err, ErrPostureRefused) || decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreRolledBack) {
		t.Errorf("a state below the floor: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	decision, err = posture.SetState(fixture.state(tick, true), fixture.log(1, tick))
	if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != tick {
		t.Fatalf("a state at the floor: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	if _, restored := NewPosture(copied.survivor(), settings); restored.State != PostureEnforcingDocument || len(restored.Alarms) != 0 {
		t.Errorf("restored after the recovery: %v, %v", restored.State, restored.Alarms)
	}
}

// A store at the floor's pin on another chain is a rolled-back store too, and a state on another chain than the
// floor's at its position is refused; a state whose base is past the floor stands on its signed header.
func TestAStoreAtTheFloorOnAnotherChainIsPending(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	posture := func() *Posture {
		fixture.base(fixture.ownerPhone, true)
		fixture.tick()
		fixture.tick()
		posture, _ := NewPosture(store, settings)
		posture.SetPending(fixture.pending())
		if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
			t.Fatal(err)
		}
		return posture
	}()
	// the running posture holds the floor it committed itself; one restored under a floor on another chain does not
	_ = posture
	floor.chain = bytes.Repeat([]byte{0x5a}, 32)
	restored, decision := NewPosture(store.survivor(), settings)
	if decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreRolledBack) {
		t.Fatalf("restored %v, %v", decision.State, decision.Alarms)
	}
	// it refuses a state whose log shows another chain at the floor's position
	tick := fixture.tick()
	if decision, err := restored.SetState(fixture.state(tick, true), fixture.log(1, tick)); !errors.Is(err, ErrPostureRefused) ||
		decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreRolledBack) {
		t.Errorf("a state over the floor's position on another chain: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	// and takes one on a base past the floor, whose signed header carries the chain
	base := fixture.base(fixture.ownerPhone, true)
	if decision, err := restored.SetState(fixture.state(base, true), fixture.log(base, base)); err != nil ||
		decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != base {
		t.Errorf("a state on a base past the floor: %v, %v", err, decision.Alarms)
	}
}

// While the floor cannot be read, a restored store is pending, and a state is refused; once it reads, a state at or
// above it restores enforcing.
func TestAFloorThatCannotBeReadIsPending(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	fixture.enforcing(store, true)
	floor.loadErr = errors.New("the key store is locked")
	posture, decision := NewPosture(store.survivor(), settings)
	if decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreUnreadable) {
		t.Fatalf("restored %v, %v", decision.State, decision.Alarms)
	}
	if decision, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); !errors.Is(err, ErrPostureStoreFailed) ||
		decision.State != PosturePending || !postureAlarmed(decision, PostureAlarmStoreUnreadable) {
		t.Errorf("a state while the floor does not read: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	floor.loadErr = nil
	if decision, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil || decision.State != PostureEnforcingDocument {
		t.Errorf("a state once it reads: %v, %v, %v", err, decision.State, decision.Alarms)
	}
}

// Under a floor above 0, an empty store and a legacy one are rolled back, never legacy: only the sidecar's own
// sign-out, which erases the floor with the keys, makes a device legacy again.
func TestAWipedStoreUnderAFloorIsPending(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	posture, _ := NewPosture(store, settings)
	posture.SetPending(fixture.pending())
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	if _, decision := NewPosture(newMemoryPostureStore(), settings); decision.State != PosturePending ||
		!postureAlarmed(decision, PostureAlarmStoreRolledBack) {
		t.Errorf("an empty store: %v, %v", decision.State, decision.Alarms)
	}
	signOut := fixture.sidecarRevoke(fixture.self, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	if decision, err := posture.ApplyDeltas(fixture.log(signOut, signOut)); err != nil || decision.State != PostureLegacy {
		t.Fatalf("the sign-out: %v, %v", err, decision.State)
	}
	if _, decision := NewPosture(store.survivor(), settings); decision.State != PosturePending ||
		!postureAlarmed(decision, PostureAlarmStoreRolledBack) {
		t.Errorf("a legacy store under the floor: %v, %v", decision.State, decision.Alarms)
	}
	// its owner erases the floor with the keys
	floor.n, floor.chain = 0, nil
	if _, decision := NewPosture(store.survivor(), settings); decision.State != PostureLegacy || len(decision.Alarms) != 0 {
		t.Errorf("a legacy store with the floor erased: %v, %v", decision.State, decision.Alarms)
	}
}

// A floor that cannot be raised alarms and stays where it was, and the commit stands: what is in force is what a
// restart restores.
func TestAFloorThatCannotBeRaisedAlarms(t *testing.T) {
	fixture := newPostureFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	fixture.enforcing(store, true)
	posture, _ := NewPosture(store.survivor(), settings)
	floor.commitErr = errors.New("the key store is locked")
	tick := fixture.tick()
	decision, err := posture.ApplyDeltas(fixture.log(tick, tick))
	if err != nil || decision.Pin.GetVersion() != tick || !postureAlarmed(decision, PostureAlarmStoreFailed) {
		t.Fatalf("%v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	if floor.n != 0 {
		t.Errorf("the floor moved to %d", floor.n)
	}
	floor.commitErr = nil
	next := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(next, next)); err != nil || floor.n != next {
		t.Errorf("the next commit: %v, floor %d", err, floor.n)
	}
}
