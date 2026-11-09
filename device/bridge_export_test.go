// What the external tests of the bridge reach in this package's own tests: posture stores the posture fixture writes,
// so a bridge restores from a verified state carrying the rules a test gives, as on a device.

package device

import (
	"testing"
)

// A store holding a posture taken to enforcing by the fixture's log, whose state carries rules.
func EnforcingPostureStoreForTest(t testing.TB, rules []byte, hasDocument bool) PostureStore {
	t.Helper()
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	fixture.base(fixture.ownerPhone, hasDocument)
	fixture.tick()
	fixture.tick()
	posture, _ := fixture.open(store)
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	state := fixture.state(fixture.tip(), hasDocument)
	state.Rules = rules
	decision, err := posture.SetState(state, fixture.log(1, fixture.tip()))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.State.Enforcing() {
		t.Fatalf("state %v", decision.State)
	}
	return store
}

// A store holding a pending posture: an anchor and no state.
func PendingPostureStoreForTest(t testing.TB) PostureStore {
	t.Helper()
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture, _ := fixture.open(store)
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	return store
}

// A store that holds nothing: a device no sidecar role has enrolled on.
func EmptyPostureStoreForTest() PostureStore {
	return newMemoryPostureStore()
}
