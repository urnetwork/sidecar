// The entries between two pins that shrank a repo's key holders, as a verified state's window keeps them (§7.9's shrink
// row), which §11.6's due row classes a crossing of a REMOVE generation by (evs_epoch.go's EvsClassifyPathEpochDue;
// question evs1-m2-16-due-classification, option 3; QD-949):
//
//	span   the entries in (from, through] that advanced the repo's holders_shrunk_at, which config_coverage.go's rule
//	       advances at exactly the entries that shrink it, and to no other position: S(through)'s holders_shrunk_at
//	       names the newest, and S(s-1)'s the one before s, so the walk reads one state either side of each shrink
//	       and none of the entries between
//	reach  the walk reads only what StateAt serves, the window from the previous base, or from the base a restored
//	       reader started at, to the tip. S(from) must be in it, so a reader that cannot reach the earlier pin walks
//	       nothing; and a state or an entry of the span the window no longer keeps (a newer base moved it on) ends the
//	       walk with ErrConfigPinNotRetained
//	entry  each shrink's kept entry as it took effect at its position: a statement with its body, a tick with its
//	       reaps and activations, or a base, whose own change no statement says
//
// The class rides no row: a long-running reader, a new device and a rows-only gate hold the same kept entries and
// states for every position from the base they started at (D-TEAM-19), and a reader that cannot reach a span classes
// none of it. What it costs is two StateAt rebuilds a shrink, each at most StateAtCheckpointInterval entries.
//
// Safe for concurrent use, as StateAt is: a walk reads immutable states and kept entries. Nothing here creates,
// derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One entry that shrank a repo's key holders, as the window keeps it.
type configShrink struct {
	// its position
	n uint64
	// the entry and how it took effect; nil where the window keeps none
	kept *configKeptEntry
	// S(n-1) and S(n)
	before *ConfigState
	after  *ConfigState
}

// The entries in (from, through] that advanced the repo's holders_shrunk_at, newest first. See the file header. An
// error for a pin StateAt does not serve (ErrConfigPinNotRetained, ErrConfigPinAhead, ErrConfigPinOffChain), a
// state or entry of the span the window no longer keeps (ErrConfigPinNotRetained), or a through below from.
func (self *ConfigState) shrinksBetween(repoId Id, from *bridge.AuthPin, through *bridge.AuthPin) ([]*configShrink, error) {
	if through.GetVersion() < from.GetVersion() {
		return nil, fmt.Errorf("%w: a span from %d to %d", ErrConfigPinOffChain, from.GetVersion(), through.GetVersion())
	}
	if _, err := self.StateAt(from); err != nil {
		return nil, err
	}
	state, err := self.StateAt(through)
	if err != nil {
		return nil, err
	}
	shrinks := []*configShrink{}
	for n := state.ShrunkAt(repoId); from.GetVersion() < n; {
		after := state
		if n != state.n {
			if after, err = self.keptStateAt(n); err != nil {
				return nil, err
			}
		}
		before, err := self.keptStateAt(n - 1)
		if err != nil {
			return nil, err
		}
		shrinks = append(shrinks, &configShrink{n: n, kept: self.history.entryAt(n), before: before, after: after})
		previous := before.ShrunkAt(repoId)
		if n <= previous {
			// holders_shrunk_at at S(n-1) is a position at or below n-1 in any state a log builds
			return nil, fmt.Errorf("%w: holders_shrunk_at %d at %d", ErrConfigPinOffChain, previous, n-1)
		}
		state, n = before, previous
	}
	return shrinks, nil
}

// S(k) from this state's window, k at or below its position.
func (self *ConfigState) keptStateAt(k uint64) (*ConfigState, error) {
	if k == self.n {
		return self, nil
	}
	if self.history == nil || self.n < k {
		return nil, fmt.Errorf("%w: %d", ErrConfigPinNotRetained, k)
	}
	state, ok := self.history.stateAt(k)
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrConfigPinNotRetained, k)
	}
	return state, nil
}

// The entry the window keeps at position k: nil outside it, and at S(0), which no entry made.
func (self *configStateHistory) entryAt(k uint64) *configKeptEntry {
	if self == nil {
		return nil
	}
	view := self.view.Load()
	if view == nil || k < view.from || view.tip.n < k {
		return nil
	}
	return view.entries[k-view.from]
}
