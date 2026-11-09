// §7.9's coverage and §10.6's write gate (D-KEYS-6, D-EVS-18), which evs runs at each ref's head CAS (§11.8), a
// depositor before it seals to a drop key (D-KEYS-17) and a writer before it seals new content; and §10.9's cause
// row, which classes a rotation REMOVE for gkm's write budget (§10.6's checks) and for members judging it.
//
//	coverage  generation g, whose GenRotate carries auth pin (n_g, A_g) and time t_g, covers a shrink at n_r iff
//	          n_g >= n_r and A_g lies on the verifier's chain, and an expiry at T_e iff t_g >= T_e
//	pass      a push or deposit declaring g passes only if g covers the repo's holders_shrunk_at in the verifier's
//	          newest state and no key holder of the repo expired in (t_g, now]
//	remove    a rotation from parent p is REMOVE iff the state it is judged at shows a shrink after p's auth pin, or
//	          an expiry after p's time up to the rotation's (or now, for gkm), or p is poisoned (the caller's)
//
// The chain test reads the verifier's view. A pin off the chain is a fork and covers nothing. A pin above the
// verifier's state waits (ErrGkmAuthAhead): nothing about it is known yet, so the gate stays shut until the verifier's
// log reaches it. A pin before what the verifier retains is not judged and counts against no one (GkmAuthView's
// rule): §7.9 keeps A_k only from the retention point on, a day or two of entries, while a generation lives for up to
// 30 days, so reading such a pin as off the chain would shut every repo's gate a day or two after its last shrink.
// The members' rotation checks judged its chain when it was new, and its number still has to reach n_r.
//
// holders_shrunk_at is TEAM's to advance at each entry (TEAM-M2-17, by GkmHoldersDropped); the expiry half is
// computed here from KeyHolders.
//
// Pure, on every leg. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The generation does not cover a shrink or an expiry the verifier's state shows, or its pin is a fork's: writes
	// declaring it are refused until a covering generation is claimed (412 GATE_CLOSED, §11.8).
	ErrGkmGateClosed = errors.New("gkm write gate closed")
	// The verifier's state holds no such repo.
	ErrGkmNoRepo = errors.New("gkm: no such repo in the state")
)

// One of §7.9's causal identities of a key holder's drop from a repo: a shrink, by the position of the entry that
// made it, identity (R, n, A_n), or an authorization expiry, by when the holder left, identity (R, T_e). The zero
// value is no drop.
type GkmHolderDrop struct {
	// A shrink at this log position; zero for none.
	ShrinkAt uint64
	// An expiry at this time; zero for none.
	ExpiredAt time.Time
}

// Where a generation's auth pin stands against the verifier's chain: nil on it, ErrGkmAuthNotRetained before what
// the verifier retains, ErrGkmAuthAhead above its state, ErrGkmAuthOffChain off it.
func gkmPinStanding(view GkmAuthView, pin *bridge.AuthPin) error {
	if pin == nil || len(pin.GetChain()) != gkmAuthChainByteCount {
		return ErrGkmAuthOffChain
	}
	if view.OnChain(pin) {
		return nil
	}
	_, err := view.At(pin)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrGkmAuthAhead):
		return ErrGkmAuthAhead
	case errors.Is(err, ErrGkmAuthNotRetained):
		return ErrGkmAuthNotRetained
	}
	return ErrGkmAuthOffChain
}

// §7.9's coverage: whether the generation whose GenRotate carries auth and generationTime covers the drop, as the
// view judges A_g. A pin above the view's state covers no shrink until the view reaches it, and one before what the
// view retains is held to its number alone.
func GkmGenerationCovers(view GkmAuthView, auth *bridge.AuthPin, generationTime time.Time, drop GkmHolderDrop) bool {
	if 0 < drop.ShrinkAt {
		if auth.GetVersion() < drop.ShrinkAt {
			return false
		}
		if standing := gkmPinStanding(view, auth); standing != nil && !errors.Is(standing, ErrGkmAuthNotRetained) {
			return false
		}
	}
	if !drop.ExpiredAt.IsZero() && generationTime.UnixMilli() < drop.ExpiredAt.UnixMilli() {
		return false
	}
	return true
}

// §10.6's gate at the verifier's newest state: nil when a push or deposit to the repo declaring the generation whose
// GenRotate carries auth and generationTime may commit at now. Otherwise ErrGkmGateClosed, with ErrGkmAuthOffChain
// for a fork's pin; ErrGkmAuthAhead while the pin is above the state; ErrGkmNoRepo; or ErrGkmMalformed for a state
// whose holders cannot be computed, which the expiry half needs whenever now is past generationTime. Every error
// refuses the write.
func GkmGateCheck(view GkmAuthView, repoId Id, auth *bridge.AuthPin, generationTime time.Time, now time.Time) error {
	repo := view.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	switch standing := gkmPinStanding(view, auth); {
	case errors.Is(standing, ErrGkmAuthOffChain):
		return fmt.Errorf("%w: %w", ErrGkmGateClosed, ErrGkmAuthOffChain)
	case errors.Is(standing, ErrGkmAuthAhead):
		return fmt.Errorf("%w: the generation's pin %d is above the state's %d", ErrGkmAuthAhead,
			auth.GetVersion(), view.Pin().GetVersion())
	}
	if shrinkAt := repo.GetHoldersShrunkAt(); auth.GetVersion() < shrinkAt {
		return fmt.Errorf("%w: the generation's pin %d is below holders_shrunk_at %d", ErrGkmGateClosed,
			auth.GetVersion(), shrinkAt)
	}
	expired, err := GkmHolderExpired(view, repoId, generationTime, now)
	if err != nil {
		return err
	}
	if expired {
		return fmt.Errorf("%w: a key holder expired after the generation's time", ErrGkmGateClosed)
	}
	return nil
}

// Whether §10.6's gate passes: GkmGateCheck answers nil.
func GkmGatePasses(view GkmAuthView, repoId Id, auth *bridge.AuthPin, generationTime time.Time, now time.Time) bool {
	return GkmGateCheck(view, repoId, auth, generationTime, now) == nil
}

// §10.9's REMOVE test for a rotation from the parent generation whose GenRotate carries parentAuth and parentTime:
// whether the view's state shows a shrink after the parent's pin, or a key holder of the repo expiring in
// (parentTime, through]. A member judges a GenRotate with the view at its auth pin and through at its time_ms, and
// requires cause REMOVE iff this holds or the parent is poisoned; gkm classes a staged delivery or claim of g+1 as a
// REMOVE rotation's with its newest state and through at its own clock. A compromise retirement shows as a shrink,
// since TEAM advances holders_shrunk_at for one.
func GkmRemoveDue(view GkmAuthView, repoId Id, parentAuth *bridge.AuthPin, parentTime time.Time, through time.Time) (bool, error) {
	repo := view.Repo(repoId)
	if repo == nil {
		return false, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	if parentAuth.GetVersion() < repo.GetHoldersShrunkAt() {
		return true, nil
	}
	return GkmHolderExpired(view, repoId, parentTime, through)
}

// Whether §10.9's cause row requires REMOVE of a rotation from parent to rotate: GkmRemoveDue through rotate's time,
// with the view at rotate's auth pin, or a poisoned parent. What a member does with a cause that differs, a REMOVE
// after a poisoning it did not see among them, is its rotation check's (KEYS-M2-19).
func GkmRotationRemoveRequired(view GkmAuthView, repoId Id, parent *protocol.GenRotate, rotate *protocol.GenRotate, parentPoisoned bool) (bool, error) {
	if parentPoisoned {
		return true, nil
	}
	return GkmRemoveDue(view, repoId, parent.GetAuth(), time.UnixMilli(parent.GetTimeMs()), time.UnixMilli(rotate.GetTimeMs()))
}
