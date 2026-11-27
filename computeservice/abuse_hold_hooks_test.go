//go:build sidecar_testhooks

package computeservice

// The abuse hold's fill on its barriers (CARCH-M12-01): a staff act that commits and projects between an admission's
// read of the row and its projection of what it read leaves the act's newer version standing, so the next admission on
// any broker refuses, and the fill's older write never lifts a hold.

import (
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// The suspension lands between the fill's read, which found the network never held, and its projection of that: the
// admission that read before the act passes, as it arrived first, and every one after it, on either broker, refuses.
func TestAbuseHoldFillLosesToASuspensionBetweenReadAndWrite(t *testing.T) {
	first, firstCounting := newTestAbuseBroker(t, nil, nil)
	second, secondCounting := newTestAbuseBroker(t, first, nil)
	key := sidecar.EvsKeyId(first.networkId)
	acted := 0
	once := sync.Once{}
	sidecar.SetTestHooks(&sidecar.TestHooks{
		Barrier: func(name string, barrierKey string) {
			if name == BarrierComputeAbuseHoldFillAfter && barrierKey == key {
				once.Do(func() {
					testAbuseHoldAct(t, first, model.ComputeAbuseHoldReasonMining, true)
					acted += 1
				})
			}
		},
	})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })

	if recorder := first.serve(http.MethodPost, "/v1/infer/authorize", first.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("the admission that read before the act: %d %s", recorder.Code, recorder.Body.String())
	}
	if acted != 1 {
		t.Fatalf("the act ran %d times at the fill's barrier", acted)
	}
	if value := first.redis.Dump()[model.ComputeAbuseHoldRedisKey(first.networkId)]; string(value) != "1:1" {
		t.Fatalf("the fill's older write replaced the act's: %q", value)
	}
	requireAbuseAdmissions(t, first, firstCounting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	requireAbuseAdmissions(t, second, secondCounting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
}

// The resume lands between a fill's read, which found the network held, and its projection: the fill's write of the
// held version leaves the resume's newer one, and the network is admitted again at once.
func TestAbuseHoldFillLosesToAResumeBetweenReadAndWrite(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	fixture.abuseHolds.set(fixture.networkId, model.ComputeAbuseHoldReasonSpam, true, fixture.clock.Now())
	key := sidecar.EvsKeyId(fixture.networkId)
	once := sync.Once{}
	sidecar.SetTestHooks(&sidecar.TestHooks{
		Barrier: func(name string, barrierKey string) {
			if name == BarrierComputeAbuseHoldFillAfter && barrierKey == key {
				once.Do(func() {
					testAbuseHoldAct(t, fixture, model.ComputeAbuseHoldReasonSpam, false)
				})
			}
		},
	})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })

	requireComputeRefusal(t, fixture.serve(http.MethodPost, "/v1/infer", fixture.token(), "", nil), http.StatusForbidden, ComputeRefusalSuspended)
	if value := fixture.redis.Dump()[model.ComputeAbuseHoldRedisKey(fixture.networkId)]; string(value) != "2:0" {
		t.Fatalf("the fill's held version replaced the resume's: %q", value)
	}
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
}
