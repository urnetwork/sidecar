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

// §18.4's search working sets: 4 MiB a search on both phone profiles and 8 MiB in the page Worker, each beside the
// 256 KiB of version-table pages, which no forwarding shares in the page Worker.
func TestProfilesHoldTheSearchWorkingSets(t *testing.T) {
	const mib = 1024 * 1024
	for _, c := range []struct {
		profile    *Profile
		workingSet int64
	}{
		{profile: Ios32Profile(), workingSet: 4 * mib},
		{profile: AndroidProfile(), workingSet: 4 * mib},
		{profile: PageWorkerProfile(), workingSet: 8 * mib},
	} {
		if c.profile.SearchWorkingSetByteCount != c.workingSet || c.profile.VersionPageByteCount != 256*1024 ||
			c.profile.SearchByteCount() != c.workingSet+256*1024 {
			t.Errorf("%s: a search holds %d B beside %d B", c.profile.Name, c.profile.SearchWorkingSetByteCount, c.profile.VersionPageByteCount)
		}
	}
	if worker := PageWorkerProfile(); worker.ForwardingSteadyByteCount != 0 || worker.CompileMemoryMaxByteCount != 0 || worker.SidecarBudgetByteCount != 64*mib {
		t.Errorf("the page Worker's profile: %+v", worker)
	}
}

// FS-109's measure catches a search that holds a per-search collection of keys past its working set, which a sample
// without a forced collection could miss, and passes one that keeps nothing; a search that samples nothing is no
// measure.
func TestMeasureSearchCatchesAPerSearchKeyCollection(t *testing.T) {
	profile := Ios32Profile()
	cell := NewCell(profile)
	search := func(collect bool) *Row {
		row, err := cell.MeasureSearch("a search", profile.SearchByteCount(), func(sample func()) error {
			sample()
			var keys [][16]byte
			if collect {
				// the bug FS-109 exists to catch: every bucket key collected per search, here 500,000 of them
				keys = make([][16]byte, 500000)
				for i := range keys {
					keys[i][0], keys[i][1], keys[i][2] = byte(i), byte(i>>8), byte(i>>16)
				}
			}
			sample()
			runtime.KeepAlive(keys)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	if clean := search(false); !clean.Within() || clean.SampleCount != 2 || clean.BudgetByteCount != profile.SearchByteCount() {
		t.Errorf("CONTROL FAILED: a search that keeps nothing measured %+v", clean)
	}
	if collected := search(true); collected.Within() || collected.PeakByteCount < 7*1024*1024 {
		t.Errorf("a per-search key collection measured %+v", collected)
	}
	if cell.CheckWithin() == nil {
		t.Error("CheckWithin passed a cell holding a per-search key collection")
	}
	if _, err := NewCell(profile).MeasureSearch("nothing sampled", profile.SearchByteCount(), func(sample func()) error { return nil }); err == nil {
		t.Error("a search that sampled nothing measured something")
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
