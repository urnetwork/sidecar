// The Forwarder's settings and admission rule (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5, 12.7).

package sidecar

import (
	"testing"
	"time"
)

// Each host class's defaults are 4.2.5's, and each validates.
func TestForwarderSettingsDefaultsByHostClass(t *testing.T) {
	apple := DefaultForwarderSettings(ForwarderHostApple)
	android := DefaultForwarderSettings(ForwarderHostAndroid)
	desktop := DefaultForwarderSettings(ForwarderHostDesktop)
	if apple.CompileMemoryMaxByteCount != 10*1024*1024 || apple.CompileHeapCeilingByteCount != 30*1024*1024 || !apple.FreeMemoryAfterCompile {
		t.Fatalf("apple: %+v", apple)
	}
	if android.CompileMemoryMaxByteCount != 16*1024*1024 || android.CompileHeapCeilingByteCount != 0 || !android.FreeMemoryAfterCompile {
		t.Fatalf("android: %+v", android)
	}
	if desktop.CompileMemoryMaxByteCount != 64*1024*1024 || desktop.CompileHeapCeilingByteCount != 0 || desktop.FreeMemoryAfterCompile {
		t.Fatalf("desktop: %+v", desktop)
	}
	if unknown := DefaultForwarderSettings("a class this build does not know"); *unknown != *apple {
		t.Fatalf("an unknown class is not the tightest: %+v", unknown)
	}
	for _, settings := range []*ForwarderSettings{apple, android, desktop} {
		if settings.CompileDelay != 2*time.Second || settings.CompileMinInterval != 10*time.Second || settings.CompileRetryInterval != 30*time.Second ||
			settings.CompileRetryMaxInterval != 10*time.Minute || settings.FollowInterval != time.Hour || settings.FollowPageMaxCount != 64 ||
			settings.KeyWaitAlarmInterval != 10*time.Minute || settings.HeadCacheCount != 2 || settings.CompileApplyRunCount != 256 {
			t.Fatalf("the shared defaults: %+v", settings)
		}
		if err := settings.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for name, mutate := range map[string]func(settings *ForwarderSettings){
		"no retry interval":    func(settings *ForwarderSettings) { settings.CompileRetryInterval = 0 },
		"a retry cap below it": func(settings *ForwarderSettings) { settings.CompileRetryMaxInterval = time.Second },
		"no rows factor":       func(settings *ForwarderSettings) { settings.CompileEstimateRowsFactor = 0 },
		"a negative ceiling":   func(settings *ForwarderSettings) { settings.CompileHeapCeilingByteCount = -1 },
		"no run count":         func(settings *ForwarderSettings) { settings.CompileApplyRunCount = 0 },
		"no follow interval":   func(settings *ForwarderSettings) { settings.FollowInterval = 0 },
		"a negative delay":     func(settings *ForwarderSettings) { settings.CompileDelay = -1 },
	} {
		settings := DefaultForwarderSettings(ForwarderHostApple)
		mutate(settings)
		if settings.Validate() == nil {
			t.Fatalf("%s validated", name)
		}
	}
}

// The estimate is 5 x rows + 2 x head + tail + 2 x the last state + 1 MiB, and a size nothing could hold is the
// largest estimate.
func TestForwarderCompileEstimate(t *testing.T) {
	settings := DefaultForwarderSettings(ForwarderHostApple)
	const mib = int64(1024 * 1024)
	if got := settings.CompileEstimate(ForwarderCompileSize{}); got != mib {
		t.Fatalf("nothing: %d", got)
	}
	size := ForwarderCompileSize{RowsByteCount: 1000, HeadByteCount: 300, TailByteCount: 70, StateByteCount: 9}
	if got := settings.CompileEstimate(size); got != 5*1000+2*300+70+2*9+mib {
		t.Fatalf("the estimate: %d", got)
	}
	const most = int64(1<<63 - 1)
	for name, size := range map[string]ForwarderCompileSize{
		"negative rows":  {RowsByteCount: -1},
		"negative state": {StateByteCount: -1},
		"rows past all":  {RowsByteCount: most / 4},
		"a tail past it": {RowsByteCount: 1, TailByteCount: most - 1},
	} {
		if got := settings.CompileEstimate(size); got != most {
			t.Fatalf("%s: %d", name, got)
		}
		if settings.CompileAdmission(size, 0) != ForwarderCompileOverBudget {
			t.Fatalf("%s admitted", name)
		}
	}
}

// 4.2.4's admission rule at the Apple extension's settings: rows of 1.8 MiB compile with the tunnel at its measured
// 19.6 MiB and are deferred under provider load; rows past the cap are over budget whatever the heap; the edges fall
// on the byte. Android and desktop have no ceiling.
func TestForwarderCompileAdmissionRule(t *testing.T) {
	apple := DefaultForwarderSettings(ForwarderHostApple)
	const mib = int64(1024 * 1024)
	fits := ForwarderCompileSize{RowsByteCount: 18 * mib / 10}
	if got := apple.CompileAdmission(fits, 196*mib/10); got != ForwarderCompileAdmitted {
		t.Fatalf("1.8 MiB of rows at 19.6 MiB: %d", got)
	}
	if got := apple.CompileAdmission(fits, 26*mib); got != ForwarderCompileDeferred {
		t.Fatalf("1.8 MiB of rows at 26 MiB: %d", got)
	}
	// the cap, on the byte: 5 x rows + 1 MiB = 10 MiB
	atCap := ForwarderCompileSize{RowsByteCount: 9 * mib / 5}
	if apple.CompileEstimate(atCap) > apple.CompileMemoryMaxByteCount {
		atCap.RowsByteCount -= 1
	}
	for apple.CompileEstimate(ForwarderCompileSize{RowsByteCount: atCap.RowsByteCount + 1}) <= apple.CompileMemoryMaxByteCount {
		atCap.RowsByteCount += 1
	}
	if got := apple.CompileAdmission(atCap, 0); got != ForwarderCompileAdmitted {
		t.Fatalf("at the cap: %d", got)
	}
	pastCap := ForwarderCompileSize{RowsByteCount: atCap.RowsByteCount + 1}
	if got := apple.CompileAdmission(pastCap, 0); got != ForwarderCompileOverBudget {
		t.Fatalf("a byte of rows past the cap: %d", got)
	}
	if got := apple.CompileAdmission(pastCap, 40*mib); got != ForwarderCompileOverBudget {
		t.Fatalf("past the cap under load is over budget, not deferred: %d", got)
	}
	// the last compiled state counts twice (12.7): the same rows with a state that takes the estimate past the cap
	room := apple.CompileMemoryMaxByteCount - apple.CompileEstimate(atCap)
	if got := apple.CompileAdmission(ForwarderCompileSize{RowsByteCount: atCap.RowsByteCount, StateByteCount: room / 2}, 0); got != ForwarderCompileAdmitted {
		t.Fatalf("a state that fits twice: %d", got)
	}
	if got := apple.CompileAdmission(ForwarderCompileSize{RowsByteCount: atCap.RowsByteCount, StateByteCount: room/2 + 1}, 0); got != ForwarderCompileOverBudget {
		t.Fatalf("the last state's size is not counted: %d", got)
	}
	// the ceiling, on the byte
	estimate := apple.CompileEstimate(fits)
	if got := apple.CompileAdmission(fits, apple.CompileHeapCeilingByteCount-estimate); got != ForwarderCompileAdmitted {
		t.Fatalf("at the ceiling: %d", got)
	}
	if got := apple.CompileAdmission(fits, apple.CompileHeapCeilingByteCount-estimate+1); got != ForwarderCompileDeferred {
		t.Fatalf("a byte past the ceiling: %d", got)
	}
	if got := apple.CompileAdmission(fits, -1); got != ForwarderCompileDeferred {
		t.Fatalf("an unread heap: %d", got)
	}
	for _, hostClass := range []ForwarderHostClass{ForwarderHostAndroid, ForwarderHostDesktop} {
		settings := DefaultForwarderSettings(hostClass)
		if got := settings.CompileAdmission(fits, 1024*mib); got != ForwarderCompileAdmitted {
			t.Fatalf("%s has no ceiling: %d", hostClass, got)
		}
		if got := settings.CompileAdmission(ForwarderCompileSize{RowsByteCount: settings.CompileMemoryMaxByteCount}, 0); got != ForwarderCompileOverBudget {
			t.Fatalf("%s past its cap: %d", hostClass, got)
		}
	}
	none := DefaultForwarderSettings(ForwarderHostApple)
	none.CompileMemoryMaxByteCount = 0
	if got := none.CompileAdmission(ForwarderCompileSize{}, 0); got != ForwarderCompileOverBudget {
		t.Fatalf("a cap of zero admits: %d", got)
	}
}

// A retry waits 30 s, then doubles to 10 min and stays there.
func TestForwarderCompileRetryDoublesToItsCap(t *testing.T) {
	settings := DefaultForwarderSettings(ForwarderHostApple)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for retryCount, timeout := range want {
		if got := settings.CompileRetryTimeout(retryCount); got != timeout {
			t.Fatalf("retry %d waits %s", retryCount, got)
		}
	}
	if got := settings.CompileRetryTimeout(-3); got != 30*time.Second {
		t.Fatalf("a negative count waits %s", got)
	}
	if got := settings.CompileRetryTimeout(1 << 20); got != 10*time.Minute {
		t.Fatalf("a huge count waits %s", got)
	}
}
