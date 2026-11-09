//go:build sidecar_testhooks

package sidecar

import (
	"testing"
)

// Each refresh passes its barriers, so a fault schedule can hold a refresh in flight (§22.8).
func TestRefreshPassesItsBarriers(t *testing.T) {
	recorder := recordHooks(t)
	clock := newTokenTestClock()
	fixture := newTokenTestFixture(t, testInitialJwt(), refreshAnswer(clock, "barriers"))
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 2)
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, name := range []string{"token.refresh.before", "token.refresh.after"} {
		if !recorder.barriers[name] {
			t.Errorf("no barrier %s", name)
		}
	}
}
