//go:build sidecar_testhooks && !ios_extension && !js

package sidecartest

// The DBREACH fixture (TEST-M10-03; §22.7's shards row, R-TEST-3): on the index the attacker recovers no code, its
// per-guess advantage reported; without the keyed pad, or with compression on, it recovers one, which proves it works;
// and a run of fewer injections than §22.7's 1,000 is refused rather than passed.

import (
	"strings"
	"testing"
)

func TestDbreachFixtureRecoversNoCodeOnTheIndex(t *testing.T) {
	report, err := NewDbreachFixture(DefaultDbreachSettings(), DbreachModeIndex).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", report)
	if report.RecoveredCount != 0 {
		t.Errorf("the attacker recovered a code from the index's padded sizes: %s", report)
	}
}

func TestDbreachFixtureRecoversTheCodeWithoutTheKeyedPad(t *testing.T) {
	settings := DefaultDbreachSettings()
	report, err := NewDbreachFixture(settings, DbreachModeNoKeyedPad).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", report)
	if report.RecoveredCount == 0 {
		t.Errorf("the attacker recovered no code with Padmé alone on shards: %s", report)
	}
}

func TestDbreachFixtureRecoversTheCodeWithCompressionOn(t *testing.T) {
	settings := DefaultDbreachSettings()
	report, err := NewDbreachFixture(settings, DbreachModeCompressed).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", report)
	if report.RecoveredCount == 0 {
		t.Errorf("the attacker recovered no code with compression on: %s", report)
	}
}

func TestDbreachFixtureRefusesTooFewInjections(t *testing.T) {
	settings := DefaultDbreachSettings()
	settings.InjectionCount = 100
	if _, err := NewDbreachFixture(settings, DbreachModeIndex).Run(t.Context()); err == nil || !strings.Contains(err.Error(), "fewer than §22.7's 1000") {
		t.Errorf("a run of 100 injections: %v", err)
	}
}
