//go:build sidecar_testhooks

// A re-seed's seal attempt stalled between its step 6 and its step 7 past evacuation's 25 h (the owner's answer
// QD-974; resolve.go, evacuate_resolve.go): the case §11.13 says a fence must cover, "a write that stalled holding the
// key included", held at the seal's head CAS while a run judges its records.

package evsservice

import (
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The ref took an evacuation fence before the seal's attempt arrived, long past the month-old statement's time. The
// attempt reads the parts its calls wrote, writes its seal record and stops before its head CAS, and 25 h on a run
// holds the seal and both parts. The older fence ended no attempt that arrived after it, so each is pending on it,
// not dead by its statement's time: the run raises the ref's fence again, one head CAS that changes no version, then
// drops the three as dead, keeping version 1's record. The attempt's CAS fails on that fence, which is past its
// arrival, so it ends 503 unknown, and nothing commits a version whose records are gone (I-EVS-2). The device sends
// the parts and the seal again, an attempt after the fence, and the push commits at version 2.
func TestEvacuationEndsAReseedSealStalledPastItsFence(t *testing.T) {
	evacuate := newEvacuateFixture(t, nil)
	fixture := reseedFixtureOf(evacuate.pushFixture)
	check := fixture.check
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	fixture.awaitStepEights()
	older, err := fixture.engine.heads.RaiseFence(fixture.paidContext(), fixture.cluster, check.repoId, check.refId)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)
	built := fixture.built(fixture.keptParts(1100))
	places := fixture.reseedParts(built)

	var result *EvacuationResult
	var runErr error
	reached := atBarrierOnce(t, BarrierHeadCasBefore, barrierRefKey(check.repoId, check.refId), func() {
		// the seal's record is written and its head CAS not yet issued
		evacuate.age()
		result, runErr = evacuate.run()
	})
	recorder := fixture.reseed(reseedSealBody(built, places))
	sidecar.SetTestHooks(nil)
	if *reached != 1 || runErr != nil || result == nil {
		t.Fatalf("the seal reached %d head CASes, and the run ended %v", *reached, runErr)
	}
	if head := fixture.head(); head.Version() != 1 {
		t.Fatalf("the stalled seal committed version %d (status %d) after the run dropped its records: %+v", head.Version(), recorder.Code, result)
	}
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if outcome := refusalOf(t, recorder).GetOutcome(); outcome != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatalf("the stalled seal's outcome %s", outcome)
	}
	if result.FenceCount != 1 || result.DeadCount != 3 || result.KeptCount != 1 || result.DuplicateCount != 0 || result.WaitingCount != 0 ||
		result.MinuteWaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if keys := evacuate.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	if head := fixture.head(); head.Head.GetFence() != older.Head.GetFence()+1 || head.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("the run's fence left fence %d fence_ms %d", head.Head.GetFence(), head.Head.GetFenceMs())
	}
	fixture.clock.Advance(time.Second)
	fixture.requireCommitted(fixture.reseedInParts(built), 2)
}
