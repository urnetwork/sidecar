//go:build sidecar_testhooks

package evsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// QD-660 at each point a push attempt runs step 4 or reruns 5 (b-h): a reader leaves the repo after the attempt bound
// its gate view at arrival, so the newest state's holders_shrunk_at excludes generation 1, and the attempt's 5d judges
// that state and refuses 412 GATE_CLOSED, recorded, committing nothing. With the view bound once at arrival each run
// here commits under generation 1. The removal lands with the hooks off, once, at the barrier each case names:
//
//	first step 4  before the attempt's first step 4, after bind's read
//	412           at step 7's head CAS, whose PUT then fails its precondition, so 5 (b-h) reruns on the reread head
//	window        after step 6, with step 7's window passed, so steps 4 and 5 run again from the cluster
//
// A state that moves on without a removal, at the 412, still commits: the rerun refuses only what the newest state
// closes.
func TestPushJudgesTheNewestGateViewAtEachRunOfStepFour(t *testing.T) {
	cases := []struct {
		name    string
		barrier string
		// the head PUT fails its precondition once
		conflict bool
		// the clock passes step 7's window at the barrier
		pastWindow bool
		// the state appended at the barrier shrinks the repo's holders
		removal bool
	}{
		{name: "first step 4", barrier: BarrierPushStep4Before, removal: true},
		{name: "412", barrier: BarrierHeadCasBefore, conflict: true, removal: true},
		{name: "window", barrier: BarrierPushStep6After, pastWindow: true, removal: true},
		{name: "412 with no removal", barrier: BarrierHeadCasBefore, conflict: true},
	}
	for _, c := range cases {
		func() {
			fixture := newPushFixture(t, nil)
			plan := fixture.plan()
			fixture.create(plan, "a")
			body := fixture.body(plan)
			token := fixture.token(fixture.check.signerId)
			if c.conflict {
				if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
					Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition,
				}); err != nil {
					t.Fatal(err)
				}
			}
			reached := atBarrierOnce(t, c.barrier, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
				holdersShrunkAt := uint64(0)
				if c.removal {
					holdersShrunkAt = fixture.check.auth.Pin().GetVersion() + 1
				}
				fixture.check.appendState(holdersShrunkAt, nil)
				if c.pastWindow {
					fixture.clock.Advance(fixture.settings.PushStepSevenWindow)
				}
			})
			recorder := fixture.post(token, body)
			if *reached == 0 {
				t.Fatalf("%s: the attempt never reached %s", c.name, c.barrier)
			}
			if !c.removal {
				fixture.requireCommitted(recorder, 1)
				return
			}
			if recorder.Code != http.StatusPreconditionFailed || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
				t.Errorf("%s: %d (%s), want 412 GATE_CLOSED", c.name, recorder.Code, refusalOf(t, recorder).GetCode())
				return
			}
			if head := fixture.head(); !head.Absent() && head.Version() != 0 {
				t.Errorf("%s: committed at %d under the generation the state excludes", c.name, head.Version())
			}
			// recorded: the same statement again meets its record (5a)
			again := fixture.post(token, body)
			if again.Code != http.StatusPreconditionFailed || !refusalOf(t, again).GetRecorded() {
				t.Errorf("%s: the retry answered %d (%s, recorded %v), want the recorded GATE_CLOSED", c.name, again.Code,
					refusalOf(t, again).GetCode(), refusalOf(t, again).GetRecorded())
			}
		}()
	}
}
