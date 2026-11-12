// §22.8's skew rows beyond the schedules (TEST-M2-16; D-TEST-7): "Clocks ±10 min: tickets, skew and expiry hold".
// Each actor of a row runs on a clock of its own, offset from the shared one by the row's skew either way or not at
// all, and every pairing of the actors' offsets runs: one actor fast and its peer slow is the widest gap, twice the
// skew. A row's pairings start with the one where no clock is offset, which is the twin every skewed pairing runs
// beside, so a feature switched off cannot pass a row by refusing every pairing alike.
//
// An actor's offset reaches only what reads its clock (Actor.SetClockOffset is per actor), so each side of a pair needs
// its own: a component built with a clock of its own takes ClockSkewPairing.Clock, and a fake reading the caller's
// actor takes the offset a schedule's step sets (fault.ClockSkewSteps). A server's clock is held within 50 ms of UTC
// (§19.6), so a row offsets the devices and leaves each service on the shared clock.

package sidecartest

import (
	"fmt"
	"strings"
	"time"
)

// What a skew row runs with.
type ClockSkewSettings struct {
	// How far each actor's clock runs from the shared one, either way: §22.8's 10 min.
	Skew time.Duration
}

func DefaultClockSkewSettings() *ClockSkewSettings {
	return &ClockSkewSettings{
		Skew: 10 * time.Minute,
	}
}

// One row's actors, each offset in every pairing. Not safe for concurrent use while its actors change.
type ClockSkew struct {
	// The actors whose clocks the row offsets, in the order a pairing names them.
	Actors   []string
	settings *ClockSkewSettings
}

// A row over actors, which must be at least one and each named once. settings nil takes the defaults.
func NewClockSkew(settings *ClockSkewSettings, actors ...string) (*ClockSkew, error) {
	if settings == nil {
		settings = DefaultClockSkewSettings()
	}
	if settings.Skew <= 0 {
		return nil, fmt.Errorf("a skew row needs a positive skew, not %s", settings.Skew)
	}
	if len(actors) == 0 {
		return nil, fmt.Errorf("a skew row needs an actor")
	}
	seen := map[string]bool{}
	for _, actor := range actors {
		if actor == "" || seen[actor] {
			return nil, fmt.Errorf("a skew row names actor %q twice or not at all", actor)
		}
		seen[actor] = true
	}
	return &ClockSkew{Actors: append([]string{}, actors...), settings: settings}, nil
}

// The skew each actor's clock is offset by, either way.
func (self *ClockSkew) Skew() time.Duration {
	return self.settings.Skew
}

// Every pairing of the actors' offsets, each at -Skew, 0 or +Skew: 3^n of them for n actors, the one with no offset
// first, then in the order of the offsets of the first actor, the second, and so on.
func (self *ClockSkew) Pairings() []*ClockSkewPairing {
	steps := []time.Duration{0, -self.settings.Skew, self.settings.Skew}
	pairings := []*ClockSkewPairing{{}}
	for _, actor := range self.Actors {
		next := make([]*ClockSkewPairing, 0, len(pairings)*len(steps))
		for _, step := range steps {
			for _, pairing := range pairings {
				offsets := append(append([]ClockSkewOffset{}, pairing.Offsets...), ClockSkewOffset{Actor: actor, Offset: step})
				next = append(next, &ClockSkewPairing{Offsets: offsets})
			}
		}
		pairings = next
	}
	return pairings
}

// Every pairing but the unskewed one: what a row runs beside its twin.
func (self *ClockSkew) SkewedPairings() []*ClockSkewPairing {
	pairings := []*ClockSkewPairing{}
	for _, pairing := range self.Pairings() {
		if !pairing.Unskewed() {
			pairings = append(pairings, pairing)
		}
	}
	return pairings
}

// One actor's offset in a pairing.
type ClockSkewOffset struct {
	Actor  string
	Offset time.Duration
}

// What each actor's clock runs at in one run of a row.
type ClockSkewPairing struct {
	// In the row's actor order.
	Offsets []ClockSkewOffset
}

// The offset of actor, 0 for an actor the row does not name.
func (self *ClockSkewPairing) Offset(actor string) time.Duration {
	for _, offset := range self.Offsets {
		if offset.Actor == actor {
			return offset.Offset
		}
	}
	return 0
}

// Whether no actor's clock is offset: the twin.
func (self *ClockSkewPairing) Unskewed() bool {
	for _, offset := range self.Offsets {
		if offset.Offset != 0 {
			return false
		}
	}
	return true
}

// How far apart the two actors' clocks run: b's offset less a's.
func (self *ClockSkewPairing) Gap(a string, b string) time.Duration {
	return self.Offset(b) - self.Offset(a)
}

// actor's view of clock in this pairing: clock itself for an actor with no offset.
func (self *ClockSkewPairing) Clock(clock *FakeClock, actor string) Clock {
	offset := self.Offset(actor)
	if offset == 0 {
		return clock
	}
	return clock.WithOffset(offset)
}

// Sets each named actor's clock on net to its offset, starting the actor if it has not run: what a test that runs its
// actors itself does first, where a schedule takes fault.ClockSkewSteps. An actor at no offset is set to the shared
// clock's time, so a pairing never inherits another's.
func (self *ClockSkewPairing) Apply(net *Net) {
	for _, offset := range self.Offsets {
		net.Actors().Actor(net.Context(), offset.Actor).SetClockOffset(net.Clock(), offset.Offset)
	}
}

// "writer +10m0s reader -10m0s", or "unskewed".
func (self *ClockSkewPairing) String() string {
	if self.Unskewed() {
		return "unskewed"
	}
	parts := []string{}
	for _, offset := range self.Offsets {
		sign := "+"
		if offset.Offset < 0 {
			sign = ""
		}
		parts = append(parts, fmt.Sprintf("%s %s%s", offset.Actor, sign, offset.Offset))
	}
	return strings.Join(parts, " ")
}
