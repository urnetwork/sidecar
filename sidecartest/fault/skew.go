// §22.8's skew rows in a schedule (TEST-M2-16): sidecartest.ClockSkew's pairings, each actor's clock offset by the
// row's skew either way, set by a schedule's first steps. A row builds one schedule per pairing and runs the unskewed
// one beside the rest as their twin (sidecartest/clock_skew.go says why).

package fault

import (
	"github.com/urnetwork/sidecar/sidecartest"
)

type (
	ClockSkew         = sidecartest.ClockSkew
	ClockSkewSettings = sidecartest.ClockSkewSettings
	ClockSkewPairing  = sidecartest.ClockSkewPairing
	ClockSkewOffset   = sidecartest.ClockSkewOffset
)

// A row over actors. settings nil takes the defaults, §22.8's 10 min.
func NewClockSkew(settings *ClockSkewSettings, actors ...string) (*ClockSkew, error) {
	return sidecartest.NewClockSkew(settings, actors...)
}

func DefaultClockSkewSettings() *ClockSkewSettings {
	return sidecartest.DefaultClockSkewSettings()
}

// The steps that put each actor of pairing at its offset, for a schedule's first steps: a step per offset actor, since a
// zero ClockOffset changes nothing and a schedule's actors start on the shared clock.
func ClockSkewSteps(pairing *ClockSkewPairing) []*Step {
	steps := []*Step{}
	for _, offset := range pairing.Offsets {
		if offset.Offset != 0 {
			steps = append(steps, &Step{Actor: offset.Actor, ClockOffset: offset.Offset})
		}
	}
	return steps
}
