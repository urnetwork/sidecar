package sidecar

import (
	"slices"
	"sync"
	"testing"
)

// Whether the channel has fired, without waiting.
func isClosed(notify chan struct{}) bool {
	select {
	case <-notify:
		return true
	default:
		return false
	}
}

func TestMonitorValueStartsAtItsValue(t *testing.T) {
	monitor := NewMonitorValue(7)
	if monitor.Value() != 7 {
		t.Errorf("value %d", monitor.Value())
	}
	value, notify := monitor.Get()
	if value != 7 || isClosed(notify) {
		t.Errorf("value %d, closed %v", value, isClosed(notify))
	}
}

func TestMonitorValueSetWakesOnlyOnAChange(t *testing.T) {
	monitor := NewMonitorValue(1)
	_, notify := monitor.Get()

	if monitor.Set(1) {
		t.Error("setting the same value reported a change")
	}
	if isClosed(notify) {
		t.Error("setting the same value woke a waiter, so an electing loop would spin")
	}

	if !monitor.Set(2) {
		t.Error("a new value reported no change")
	}
	if !isClosed(notify) {
		t.Error("a new value woke no waiter")
	}
}

func TestMonitorValueGetRearmsAfterAWake(t *testing.T) {
	monitor := NewMonitorValue(1)
	_, first := monitor.Get()
	monitor.Set(2)

	value, second := monitor.Get()
	if value != 2 {
		t.Errorf("value %d", value)
	}
	if first == second || isClosed(second) {
		t.Error("a fired channel was handed out again, which hot spins a loop")
	}
	monitor.Set(3)
	if !isClosed(second) {
		t.Error("the re-armed channel missed a change")
	}
}

func TestMonitorValueUpdateAppliesToTheCurrentValue(t *testing.T) {
	monitor := NewMonitorValue(1)
	_, notify := monitor.Get()

	if monitor.Update(func(value int) int { return value }) {
		t.Error("an unchanged update reported a change")
	}
	if isClosed(notify) {
		t.Error("an unchanged update woke a waiter")
	}
	if !monitor.Update(func(value int) int { return value + 1 }) {
		t.Error("a changing update reported no change")
	}
	if monitor.Value() != 2 || !isClosed(notify) {
		t.Errorf("value %d, closed %v", monitor.Value(), isClosed(notify))
	}
}

func TestMonitorValueUpdatesAreAtomic(t *testing.T) {
	const updateCount = 1000
	monitor := NewMonitorValue(0)
	var wg sync.WaitGroup
	for i := 0; i < 4; i += 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < updateCount; j += 1 {
				monitor.Update(func(value int) int { return value + 1 })
			}
		}()
	}
	wg.Wait()
	if monitor.Value() != 4*updateCount {
		t.Errorf("value %d", monitor.Value())
	}
}

func TestCallbackListKeepsAddOrder(t *testing.T) {
	callbacks := NewCallbackList[string]()
	if len(callbacks.Get()) != 0 {
		t.Errorf("new list holds %v", callbacks.Get())
	}
	callbacks.Add("a")
	callbacks.Add("b")
	callbacks.Add("c")
	if got := callbacks.Get(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("got %v", got)
	}
}

func TestCallbackListRemovesByIdAndNeverReusesOne(t *testing.T) {
	callbacks := NewCallbackList[string]()
	first := callbacks.Add("a")
	second := callbacks.Add("b")
	third := callbacks.Add("c")

	callbacks.Remove(second)
	if got := callbacks.Get(); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("got %v", got)
	}

	fourth := callbacks.Add("d")
	if fourth == first || fourth == second || fourth == third {
		t.Errorf("id %d reused", fourth)
	}
	callbacks.Remove(first)
	callbacks.Remove(third)
	callbacks.Remove(fourth)
	if got := callbacks.Get(); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestCallbackListRemoveOfAnUnknownIdDoesNothing(t *testing.T) {
	callbacks := NewCallbackList[string]()
	callbackId := callbacks.Add("a")
	callbacks.Remove(callbackId + 1)
	callbacks.Remove(callbackId)
	callbacks.Remove(callbackId)
	if got := callbacks.Get(); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestCallbackListSnapshotSurvivesChanges(t *testing.T) {
	callbacks := NewCallbackList[string]()
	callbackId := callbacks.Add("a")
	callbacks.Add("b")

	snapshot := callbacks.Get()
	callbacks.Remove(callbackId)
	callbacks.Add("c")

	// a caller iterating this while another goroutine changes the list must see it whole
	if !slices.Equal(snapshot, []string{"a", "b"}) {
		t.Errorf("snapshot %v", snapshot)
	}
}

func TestCallbackListConcurrentChanges(t *testing.T) {
	callbacks := NewCallbackList[int]()
	var wg sync.WaitGroup
	for i := 0; i < 4; i += 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j += 1 {
				callbackId := callbacks.Add(j)
				for range callbacks.Get() {
				}
				callbacks.Remove(callbackId)
			}
		}()
	}
	wg.Wait()
	if got := callbacks.Get(); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}
