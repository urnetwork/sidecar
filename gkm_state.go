// What gkm's client reads of §7.9's verified authorization state S(n). TEAM's ConfigState implements GkmAuthView
// (TEAM-M2-02), TEAM's replay gives At (TEAM-M2-11's ConfigLog.StateAt), and sidecartest's fixtures stand in for
// both until then. §7.9 and §10 need each other, the config repo a group and gkm the log, and this interface is
// where that cycle breaks.
//
// A member judges each commit, rotation and delivery at its own auth pin, never at its tip (§10.9's judged row),
// so a view reaches back along its chain: a pin above the tip waits until the log reaches it, one before what the
// reader retains is not judged and counts against no one, and one off the chain is a fork.
//
// §10.5's KeyHolders, §7.9's coverage and §10.6's gate (gkm_holders.go, gkm_gate.go) read the rest: the readers at a
// given time, the rows of sidecars, members and Delegations, and what §8.6's grants reach for a Delegation's tags.

package sidecar

import (
	"errors"
	"time"

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
	// §8.12's RepoReaders at this state and the time given, sorted: what KeyHolders(R, S, t) reads, so an expiry
	// shows as t passes with no entry (§7.9). A sidecar no longer reads once every grant it reads by has expired or
	// its own not_after has passed, and nothing in one state starts a read later, so the set only shrinks as t grows.
	RepoReadersAt(repoId Id, at time.Time) []Id
	// A sidecar's row, revoked tombstones included; nil for one the state never admitted.
	SidecarRow(sidecarId Id) *bridge.SidecarRow
	// A member's row; nil for an id that names no member of this state.
	Member(memberId Id) *bridge.MemberRow
	// Every Delegation the state holds a row for, ended ones included, by delegation_id.
	Delegations() []*bridge.DelegationRow
	// The repos a read, write or admin grant naming one of the atoms reads at the time given, sorted: the part of
	// §10.5's reach(d) the rows decide for a Delegation's tags.
	ReposGrantedToAtoms(atoms []Id, at time.Time) []Id
	// Whether a record signed by signer (a sidecar_id, a recovery key's hash or a delegation_id) and carried at
	// position at rests on what a compromise cascade voids (§7.9's cascade, D-TEAM-26), as AclAuthView's.
	CascadeVoids(signer []byte, at uint64) bool
}
