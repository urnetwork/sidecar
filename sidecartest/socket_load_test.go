// The load harness scaled down for CI (SOCK-M5-17): it drives one engine on FakeSocketStore through its own handler, and
// §22.8's ±25% share against weight holds; the T5 run's numbers are DefaultSocketLoadSettings', on server's store.

package sidecartest

import (
	"testing"
	"time"
)

// A scaled run: 60 listeners in two groups, weights 100 to 300, 300 Finds a simulated second of 10 s streams, and
// every listener's in-flight share within 25% of its weight's share; every Find opens a stream, and every listener
// heartbeats about every 15 s.
func TestSocketLoadKeepsInflightToWeight(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSocketStore(clock, nil, nil)
	settings := DefaultSocketLoadSettings()
	settings.ListenerCount = 60
	settings.GroupCount = 2
	settings.DialerCount = 20
	settings.FindsPerSecond = 300
	settings.Warmup = 20 * time.Second
	settings.Duration = 80 * time.Second
	settings.Seed = 7
	report, err := RunSocketLoad(t.Context(), clock, store, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d Finds, %d opened, refusals %v, %d busy listeners; p50 %v, p99 %v server-side; %.1f registration calls/s; share deviation %.3f",
		report.FindCount, report.FindOkCount, report.FindRefusals, report.ListenerBusyCount, report.FindP50, report.FindP99,
		report.RegistrationCallsPerSecond, report.ShareMaxDeviation)
	if report.FindCount != 300*80 {
		t.Fatalf("%d Finds of %d", report.FindCount, 300*80)
	}
	if report.FindOkCount != report.FindCount {
		t.Fatalf("%d of %d Finds opened nothing: %v", report.FindCount-report.FindOkCount, report.FindCount, report.FindRefusals)
	}
	if 0.25 < report.ShareMaxDeviation {
		t.Fatalf("a listener's in-flight share is %.3f off its weight's", report.ShareMaxDeviation)
	}
	// 60 listeners every 15 s, and eager reports beside them
	if callsPerSecond := report.RegistrationCallsPerSecond; callsPerSecond < 60.0/15 || 60.0/15*4 < callsPerSecond {
		t.Fatalf("%.1f registration calls a second", callsPerSecond)
	}
}
