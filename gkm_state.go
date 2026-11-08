// What gkm's client reads of §7.9's verified authorization state S(n). TEAM's ConfigState implements GkmAuthView
// (TEAM-M2-02), TEAM's replay gives At (TEAM-M2-11's ConfigLog.StateAt), and sidecartest's fixtures stand in for
// both until then. §7.9 and §10 need each other, the config repo a group and gkm the log, and this interface is
// where that cycle breaks.
//
// A member judges each commit, rotation and delivery at its own auth pin, never at its tip (§10.9's judged row),
// so a view reaches back along its chain: a pin above the tip waits until the log reaches it, one before what the
// reader retains is not judged and counts against no one, and one off the chain is a fork.
//
// KeyHolders, coverage and the gate (KEYS-M2-03) read more of S(n) than this, and add what they read here.

package sidecar

import (
	"errors"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The pin is above this state's: wait until the log reaches it (§10.9's judged row).
	ErrGkmAuthAhead = errors.New("gkm auth pin ahead of the state")
	// The pin is before what this reader retains (§7.9's retain row): not judged, and held against no one.
	ErrGkmAuthNotRetained = errors.New("gkm auth pin not retained")
	// The pin's chain value is not this chain's at its position: a fork (§5.4's head_alarm).
	ErrGkmAuthOffChain = errors.New("gkm auth pin off the chain")
)

// One verified S(n) as gkm's client reads it. Immutable, so safe for concurrent use.
type GkmAuthView interface {
	// (n, A_n).
	Pin() *bridge.AuthPin
	// The retained state at pin, which is at or below this one's: ErrGkmAuthAhead, ErrGkmAuthNotRetained or
	// ErrGkmAuthOffChain otherwise.
	At(pin *bridge.AuthPin) (GkmAuthView, error)
	// Whether pin lies on this state's chain, at or below this position and within what it retains.
	OnChain(pin *bridge.AuthPin) bool
	// The identity key the log admits for a sidecar, by its SidecarAdmit or, for a network's first device, the
	// Genesis; nil for none. A revoked sidecar keeps it, for what it signed before (§10.9's history row).
	IdentityKey(sidecarId Id) []byte
	// §8.8's row of a repo, holders_shrunk_at among its fields; nil for a repo this state does not hold.
	Repo(repoId Id) *protocol.AclRepo
	// §8.12's RepoReaders: every sidecar that §8.6 lets read the repo.
	RepoReaders(repoId Id) []Id
	// Every sidecar that §8.6 lets write the repo.
	RepoWriters(repoId Id) []Id
}
