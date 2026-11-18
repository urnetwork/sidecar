package sidecartest

import (
	"runtime"
	"testing"
)

// Whoever a plan's channel releases finds what onFire did, since onFire returns before the channel closes.
// onFire here holds its record back while the channel's waiter may already run, the order a loaded machine
// can give: when fire closed the channel first, the waiter TestARedisDelayFiresOnceItsCallIsParked's channel
// released delivered the parked call before onFire looked (dr2-s21-s23, 2026-11-17), and here a channel
// closed first fails every run.
func TestAWaiterOnAFiredPlanFindsWhatOnFireDid(t *testing.T) {
	faults := NewFaultQueue()
	fired, err := faults.Add(&FaultPlan{Op: FaultOpRedis, Result: FailBeforeApply})
	if err != nil {
		t.Fatal(err)
	}
	looked := make(chan struct{})
	recorded := []*FaultPlan{}
	faults.SetOnFire(func(plan *FaultPlan) {
		if isClosed(fired) {
			// the channel's waiter may be running: it looks before the record lands
			<-looked
		}
		recorded = append(recorded, plan)
	})
	taken := make(chan *FaultPlan, 1)
	go func() {
		taken <- faults.take(t.Context(), FaultOpRedis, "", "{a}1", true)
	}()
	<-fired
	recordedCount := len(recorded)
	close(looked)
	if recordedCount != 1 {
		t.Errorf("the plan's channel released its waiter with %d plans recorded", recordedCount)
	}
	if plan := <-taken; plan == nil || plan.Result != FailBeforeApply {
		t.Errorf("taken %v", plan)
	}
}

// The same for a plan another displaced: it fires where its displacer does, without its result, and its
// channel's waiter finds onFire's record of the displacer, the one plan onFire is called with.
func TestAWaiterOnADisplacedPlanFindsWhatOnFireDid(t *testing.T) {
	faults := NewFaultQueue()
	displacedFired, err := faults.Add(&FaultPlan{Op: FaultOpRedis, Result: FailBeforeApply})
	if err != nil {
		t.Fatal(err)
	}
	displacer := &FaultPlan{Op: FaultOpRedis, Result: ApplyThenDrop, Displaces: true}
	if _, err := faults.Add(displacer); err != nil {
		t.Fatal(err)
	}
	looked := make(chan struct{})
	recorded := []*FaultPlan{}
	faults.SetOnFire(func(plan *FaultPlan) {
		if isClosed(displacedFired) {
			// the displaced plan's waiter may be running: it looks before the record lands
			<-looked
		}
		recorded = append(recorded, plan)
	})
	taken := make(chan *FaultPlan, 1)
	go func() {
		taken <- faults.take(t.Context(), FaultOpRedis, "", "{a}1", true)
	}()
	<-displacedFired
	recordedPlans := append([]*FaultPlan{}, recorded...)
	close(looked)
	if len(recordedPlans) != 1 || recordedPlans[0] != displacer {
		t.Errorf("the displaced plan's channel released its waiter with %v recorded", recordedPlans)
	}
	if plan := <-taken; plan != displacer {
		t.Errorf("taken %v", plan)
	}
	if unfired := faults.Unfired(); len(unfired) != 0 {
		t.Errorf("unfired %v", unfired)
	}
}

// A plan's channel closes even when onFire ends the operation's goroutine, as a t.Fatal on a test's own
// call does, so nothing else waiting on the plan hangs for it.
func TestAPlansChannelClosesWhenOnFireEndsItsGoroutine(t *testing.T) {
	faults := NewFaultQueue()
	fired, err := faults.Add(&FaultPlan{Op: FaultOpRedis, Result: FailBeforeApply})
	if err != nil {
		t.Fatal(err)
	}
	faults.SetOnFire(func(plan *FaultPlan) {
		runtime.Goexit()
	})
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		faults.take(t.Context(), FaultOpRedis, "", "{a}1", true)
	}()
	<-ended
	if !isClosed(fired) {
		t.Error("the plan's channel stayed open")
	}
}
