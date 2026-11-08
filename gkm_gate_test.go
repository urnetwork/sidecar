// §7.9's coverage, §10.6's gate and §10.9's REMOVE classification over the holders tests' network: coverage at its
// boundaries and against each standing of a pin, the gate's refusals, and REMOVE due exactly when a shrink or an
// expiry falls after the parent. Pure, on every leg.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Coverage of a shrink needs n_g >= n_r and A_g on the verifier's chain, and of an expiry t_g >= T_e. A fork's pin and
// one above the state cover no shrink; one below what the state retains is held to its number alone.
func TestGkmGenerationCovers(t *testing.T) {
	net := newGkmTestNet()
	view := net.view(t, 6)
	view.retainedFrom = 3
	expiry := aclTestNow.Add(time.Hour)
	shortChain := &bridge.AuthPin{Version: 5, Chain: gkmTestChain(5)[:16]}
	cases := []struct {
		name   string
		auth   *bridge.AuthPin
		time   time.Time
		drop   GkmHolderDrop
		covers bool
	}{
		{name: "no drop", auth: gkmTestPin(1), time: aclTestNow, covers: true},
		{name: "n_g = n_r", auth: gkmTestPin(5), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}, covers: true},
		{name: "n_g = n_r + 1, at the state", auth: gkmTestPin(6), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}, covers: true},
		{name: "n_g = n_r - 1", auth: gkmTestPin(4), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}},
		{name: "a fork's pin", auth: gkmTestForkPin(5), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}},
		{name: "a short chain value", auth: shortChain, time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}},
		{name: "no pin", time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}},
		{name: "above the state", auth: gkmTestPin(7), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5}},
		{name: "not retained, at n_r", auth: gkmTestPin(2), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 2}, covers: true},
		{name: "not retained, below n_r", auth: gkmTestPin(1), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 2}},
		{name: "t_g = T_e", auth: gkmTestPin(1), time: expiry, drop: GkmHolderDrop{ExpiredAt: expiry}, covers: true},
		{name: "t_g = T_e - 1 ms", auth: gkmTestPin(1), time: expiry.Add(-time.Millisecond), drop: GkmHolderDrop{ExpiredAt: expiry}},
		{name: "t_g after T_e", auth: gkmTestPin(1), time: expiry.Add(time.Hour), drop: GkmHolderDrop{ExpiredAt: expiry}, covers: true},
		{name: "no pin, an expiry only", time: expiry, drop: GkmHolderDrop{ExpiredAt: expiry}, covers: true},
		{name: "both, both covered", auth: gkmTestPin(5), time: expiry, drop: GkmHolderDrop{ShrinkAt: 5, ExpiredAt: expiry}, covers: true},
		{name: "both, the shrink not", auth: gkmTestPin(4), time: expiry, drop: GkmHolderDrop{ShrinkAt: 5, ExpiredAt: expiry}},
		{name: "both, the expiry not", auth: gkmTestPin(5), time: aclTestNow, drop: GkmHolderDrop{ShrinkAt: 5, ExpiredAt: expiry}},
	}
	for _, c := range cases {
		if covers := GkmGenerationCovers(view, c.auth, c.time, c.drop); covers != c.covers {
			t.Errorf("%s: covers %t", c.name, covers)
		}
	}
}

// The gate refuses a repo the state lacks, a fork's or a missing pin as closed, waits on a pin above the state, shuts
// below holders_shrunk_at and for an expiry in (t_g, now], open at t_g and closed at now, and refuses a state whose
// holders it cannot compute. A pin below what the state retains passes on its number.
func TestGkmGateCheck(t *testing.T) {
	net := newGkmTestNet()
	net.repoRow(net.repoId).HoldersShrunkAt = 4
	view := net.view(t, 6)
	view.retainedFrom = 3
	expiry := time.UnixMilli(net.fixture.admission(net.uncoveredAgent).Row.GetNotAfter())
	cases := []struct {
		name   string
		repoId Id
		auth   *bridge.AuthPin
		time   time.Time
		now    time.Time
		is     []error
	}{
		{name: "passes", repoId: net.repoId, auth: gkmTestPin(4), time: aclTestNow, now: aclTestNow},
		{name: "at the state's own pin", repoId: net.repoId, auth: gkmTestPin(6), time: aclTestNow, now: aclTestNow},
		{name: "no such repo", repoId: NewId(), auth: gkmTestPin(6), time: aclTestNow, now: aclTestNow, is: []error{ErrGkmNoRepo}},
		{name: "a fork's pin", repoId: net.repoId, auth: gkmTestForkPin(5), time: aclTestNow, now: aclTestNow,
			is: []error{ErrGkmGateClosed, ErrGkmAuthOffChain}},
		{name: "no pin", repoId: net.repoId, time: aclTestNow, now: aclTestNow, is: []error{ErrGkmGateClosed, ErrGkmAuthOffChain}},
		{name: "above the state", repoId: net.repoId, auth: gkmTestPin(7), time: aclTestNow, now: aclTestNow, is: []error{ErrGkmAuthAhead}},
		{name: "below holders_shrunk_at", repoId: net.repoId, auth: gkmTestPin(3), time: aclTestNow, now: aclTestNow, is: []error{ErrGkmGateClosed}},
		{name: "not retained, below holders_shrunk_at", repoId: net.repoId, auth: gkmTestPin(2), time: aclTestNow, now: aclTestNow,
			is: []error{ErrGkmGateClosed}},
		{name: "an expiry in (t_g, now]", repoId: net.repoId, auth: gkmTestPin(5), time: aclTestNow, now: expiry.Add(time.Hour),
			is: []error{ErrGkmGateClosed}},
		{name: "an expiry at now", repoId: net.repoId, auth: gkmTestPin(5), time: aclTestNow, now: expiry, is: []error{ErrGkmGateClosed}},
		{name: "an expiry at t_g", repoId: net.repoId, auth: gkmTestPin(5), time: expiry, now: expiry.Add(time.Hour)},
		{name: "an expiry after now", repoId: net.repoId, auth: gkmTestPin(5), time: aclTestNow, now: expiry.Add(-time.Millisecond)},
		{name: "now before t_g", repoId: net.repoId, auth: gkmTestPin(5), time: expiry.Add(time.Hour), now: aclTestNow},
	}
	for _, c := range cases {
		err := GkmGateCheck(view, c.repoId, c.auth, c.time, c.now)
		if (err == nil) != (len(c.is) == 0) {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, target := range c.is {
			if !errors.Is(err, target) {
				t.Errorf("%s: %v is not %v", c.name, err, target)
			}
		}
		if passes := GkmGatePasses(view, c.repoId, c.auth, c.time, c.now); passes != (err == nil) {
			t.Errorf("%s: passes %t beside %v", c.name, passes, err)
		}
	}

	// below what the state retains, a pin at holders_shrunk_at passes on its number
	net = newGkmTestNet()
	net.repoRow(net.repoId).HoldersShrunkAt = 2
	view = net.view(t, 6)
	view.retainedFrom = 3
	if err := GkmGateCheck(view, net.repoId, gkmTestPin(2), aclTestNow, aclTestNow); err != nil {
		t.Errorf("not retained, at holders_shrunk_at: %v", err)
	}

	// a state that holds no row for a reader names no holders, so its gate refuses
	net = newGkmTestNet()
	view = net.view(t, 6)
	delete(view.view.sidecars, net.memberDevice)
	if err := GkmGateCheck(view, net.repoId, gkmTestPin(6), aclTestNow, aclTestNow.Add(time.Hour)); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a reader with no row: %v", err)
	}
}

// A rotation is REMOVE when the state at its pin shows a shrink above its parent's pin, or a holder expiring after the
// parent's time and by the rotation's, or when the parent is poisoned; otherwise not.
func TestGkmRotationRemoveRequired(t *testing.T) {
	net := newGkmTestNet()
	net.repoRow(net.repoId).HoldersShrunkAt = 4
	view := net.view(t, 6)
	expiry := time.UnixMilli(net.fixture.admission(net.uncoveredAgent).Row.GetNotAfter())
	rotate := func(version uint64, timeMs int64) *protocol.GenRotate {
		return &protocol.GenRotate{Auth: gkmTestPin(version), TimeMs: timeMs}
	}
	cases := []struct {
		name     string
		parent   *protocol.GenRotate
		rotate   *protocol.GenRotate
		poisoned bool
		required bool
	}{
		{name: "nothing since the parent", parent: rotate(4, aclTestNow.UnixMilli()), rotate: rotate(6, aclTestNow.Add(time.Hour).UnixMilli())},
		{name: "a shrink above the parent's pin", parent: rotate(3, aclTestNow.UnixMilli()), rotate: rotate(6, aclTestNow.UnixMilli()),
			required: true},
		{name: "an expiry after the parent", parent: rotate(4, aclTestNow.UnixMilli()), rotate: rotate(6, expiry.UnixMilli()), required: true},
		{name: "an expiry after the rotation", parent: rotate(4, aclTestNow.UnixMilli()), rotate: rotate(6, expiry.UnixMilli()-1)},
		{name: "an expiry at the parent's time", parent: rotate(4, expiry.UnixMilli()), rotate: rotate(6, expiry.Add(time.Hour).UnixMilli())},
		{name: "a poisoned parent", parent: rotate(4, aclTestNow.UnixMilli()), rotate: rotate(6, aclTestNow.UnixMilli()), poisoned: true,
			required: true},
	}
	for _, c := range cases {
		required, err := GkmRotationRemoveRequired(view, net.repoId, c.parent, c.rotate, c.poisoned)
		if err != nil || required != c.required {
			t.Errorf("%s: REMOVE required %t (%v)", c.name, required, err)
		}
		due, err := GkmRemoveDue(view, net.repoId, c.parent.GetAuth(), time.UnixMilli(c.parent.GetTimeMs()), time.UnixMilli(c.rotate.GetTimeMs()))
		if err != nil || due != (c.required && !c.poisoned) {
			t.Errorf("%s: REMOVE due %t (%v)", c.name, due, err)
		}
	}
	if _, err := GkmRotationRemoveRequired(view, NewId(), rotate(4, 0), rotate(6, 0), false); !errors.Is(err, ErrGkmNoRepo) {
		t.Errorf("no such repo: %v", err)
	}
}
