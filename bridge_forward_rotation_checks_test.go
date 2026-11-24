// The Forwarder's judge's reach back to the previous base (§10.9's judged rows; bridge_forward_compile.go's step 1), on
// the root's fakes: a GroupForm pinned between the previous base and the newest is judged, and the admission rule falls
// back to the newest base's estimate.

package sidecar

import (
	"strings"
	"testing"
)

// A re-form's GroupForm pinned between the Forwarder's previous base and its newest, signed by a device §10.6 does not
// let form the config's group, is judged at its pin and not followed, as a long-running member judges it: the compile
// restores at the previous base, so the form's pin lies in its window. Its claim waits with config_key_waiting naming
// the refusal; the owner's form at the same pin is followed and opens the claim. Before, the judge started at the
// newest base, the form's pin counted against no one, and the peer's re-form was followed.
func TestAGroupFormPinnedBeforeTheNewestBaseIsJudged(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	formPin := world.net.log.State().Pin()
	world.ledger.foldLedger(world.net.n, nil)
	if base := world.net.log.State().Base(); base == nil || base.GetVersion() <= formPin.GetVersion() {
		t.Fatalf("the base %v is not past the form's pin %d", base, formPin.GetVersion())
	}
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.replaceForm(world.groupFormBy(world.peer, reformedGroupId, world.groupId, 1, formPin))
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	if status := forwarder.Status(); forwarder.RepoKeyAt(2) != nil || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("the peer's form before the newest base: key %s, status %+v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), status)
	}
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "may not form the group") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("after the interval: %+v", alarm)
	}
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 0 {
		t.Fatalf("a refused signer raised %d forks", forks)
	}

	gkm.replaceForm(world.groupFormBy(world.net.owner, reformedGroupId, world.groupId, 1, formPin))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("the owner's form at the same pin: key %s, status %+v", testForwarderKeyOpened(key), forwarder.Status())
	}
}

// The admission rule takes the first of a compile's sizes it admits, on one reading of the heap: the estimate with the
// previous base's rows where it fits, else the newest base's alone, else neither, which is refused with its alarm.
func TestTheAdmissionRuleFallsBackToTheNewestBasesEstimate(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	shallow := ForwarderCompileSize{RowsByteCount: 1000}
	deep := ForwarderCompileSize{RowsByteCount: world.settings.CompileMemoryMaxByteCount}
	admit := func(sizes ...ForwarderCompileSize) (int, forwarderCompileOutcome) {
		t.Helper()
		var chosen int
		var outcome forwarderCompileOutcome
		if err := forwarder.onRun(func() {
			chosen, outcome = forwarder.admit(world.net.n, sizes...)
		}); err != nil {
			t.Fatal(err)
		}
		return chosen, outcome
	}
	if chosen, _ := admit(shallow, deep); chosen != 0 {
		t.Fatalf("both fit the first: %d", chosen)
	}
	if chosen, _ := admit(deep, shallow); chosen != 1 || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmCompileOverBudget) {
		t.Fatalf("the deeper estimate past the cap: %d, %+v", chosen, forwarder.Status())
	}
	if chosen, outcome := admit(deep, deep); chosen != -1 || outcome != forwarderCompileRefused || !testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmCompileOverBudget) {
		t.Fatalf("neither fits: %d, %d, %+v", chosen, outcome, forwarder.Status())
	}
}
