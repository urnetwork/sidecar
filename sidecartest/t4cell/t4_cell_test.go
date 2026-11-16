package t4cell

// The harness's own cases (SDK-M8-15): a transient the timed samples miss is measured by a Sample at its high-water
// mark, and a step's kept bytes count in its steady figure. Every figure here is a lower or upper bound far from the
// allocation's size, so a collector's timing cannot move a verdict.

import (
	"runtime"
	"testing"
	"time"
)

// The transient a step holds.
const testTransientByteCount = 4 * 1024 * 1024

// With the timed samples' interval past the step, a step that drops its bytes and collects before it returns shows no
// peak, while the same step sampling as it holds them shows them; and between steps Sample does nothing.
func TestSampleCatchesATransientTheTimedSamplesMiss(t *testing.T) {
	profile := Ios32Profile()
	profile.HeapSampleInterval = time.Hour
	transient := func(sample bool) *Row {
		cell := NewCell(profile)
		row, err := cell.Measure("transient", testTransientByteCount/2, HoldsPeak, func() (any, error) {
			held := make([]byte, testTransientByteCount)
			for i := range held {
				held[i] = byte(i)
			}
			if sample {
				cell.Sample()
			}
			runtime.KeepAlive(held)
			held = nil
			runtime.GC()
			return nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	if missed := transient(false); missed.PeakByteCount >= testTransientByteCount/2 || !missed.Within() {
		t.Fatalf("CONTROL FAILED: a step that sampled nothing measured %+v", missed)
	}
	if caught := transient(true); caught.PeakByteCount < testTransientByteCount*3/4 || caught.Within() {
		t.Errorf("a sampled transient measured %+v", caught)
	}
	idle := NewCell(profile)
	idle.Sample()
	if rows := idle.Rows(); len(rows) != 0 {
		t.Errorf("a Sample between steps recorded %v", rows)
	}
}

// What a step keeps counts in its steady figure, held to its budget, and CheckWithin names the step past it.
func TestKeptBytesCountSteady(t *testing.T) {
	cell := NewCell(Ios32Profile())
	row, err := cell.Measure("kept", testTransientByteCount/2, HoldsSteady, func() (any, error) {
		kept := make([]byte, testTransientByteCount)
		for i := range kept {
			kept[i] = byte(i)
		}
		return kept, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.SteadyByteCount < testTransientByteCount*3/4 || row.Within() || cell.CheckWithin() == nil {
		t.Errorf("a kept step measured %+v", row)
	}
}
