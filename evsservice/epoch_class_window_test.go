// §11.6's due row at evs past the gate's window (QD-1018): gen/<from>'s pin, which evs's gate no longer retains once
// two later bases have moved its window on, is held to its number, as §10.6's gate holds a generation's, so evs classes
// the crossing by the shrinks after it whose states the window holds. An agent's ordinary revocation after those bases
// records a batched due that blocks nothing; the same revocation before them, its states outside the window, an
// immediate one that blocks creation. A client holding the same log, its own window past gen/1's pin too, classes each
// crossing as evs recorded it.

package evsservice

import (
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The agent's ordinary revocation by the owner, which shrinks the repo's holders.
func (self *epochClassFixture) revokeAgent() {
	self.t.Helper()
	self.admission.MustLand(self.admission.Sign(self.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		self.admission.Revocation(self.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
}

// Two later bases, a member's admission between them giving the second a tail to fold, which move the window of the
// gate and of the network's reference reader past every entry before them.
func (self *epochClassFixture) laterBases() {
	self.t.Helper()
	self.admission.Fold(true)
	self.admission.AdmitMember(self.admission.Owner(), "bystander", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.admission.Fold(true)
}

// gen/1's pin, before every window, held to its number at evs and at a client alike: batched when the agent's
// ordinary revocation follows the later bases, immediate when it precedes them.
func TestPathEpochDueHoldsAnUnretainedEarlierPinToItsNumber(t *testing.T) {
	cases := []struct {
		name      string
		span      func(fixture *epochClassFixture)
		immediate bool
	}{
		{name: "an agent's ordinary revocation after two later bases", span: func(fixture *epochClassFixture) {
			fixture.laterBases()
			fixture.revokeAgent()
		}},
		{name: "an agent's ordinary revocation before two later bases", immediate: true, span: func(fixture *epochClassFixture) {
			fixture.revokeAgent()
			fixture.laterBases()
		}},
	}
	for _, c := range cases {
		fixture := newEpochClassFixture(t)
		from, to, commitment := fixture.crossAfter(func() { c.span(fixture) })
		if shrunk := fixture.gateState().Repo(fixture.check.repoId).GetHoldersShrunkAt(); shrunk <= from.GetVersion() || to.GetVersion() < shrunk {
			t.Fatalf("%s: holders_shrunk_at %d, the crossing from %d to %d", c.name, shrunk, from.GetVersion(), to.GetVersion())
		}
		for name, state := range map[string]*sidecar.ConfigState{"the gate": fixture.gateState(), "the client": fixture.admission.State()} {
			if _, err := state.StateAt(from); !errors.Is(err, sidecar.ErrConfigPinNotRetained) {
				t.Fatalf("%s: %s reaches gen/1's pin: %v", c.name, name, err)
			}
		}
		pathEpoch := fixture.head().Head.GetPathEpoch()
		creation := fixture.planPinned(2, commitment, to)
		fixture.create(creation, "new")
		if c.immediate {
			if pathEpoch.GetDueGeneration() != 2 || !pathEpoch.GetDueBlocksCreation() || pathEpoch.GetDueByMs() != fixture.clock.Now().UnixMilli() {
				t.Fatalf("%s: due %v", c.name, pathEpoch)
			}
			fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
			requireRefusal(t, fixture.push(creation), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
		} else {
			if pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() ||
				pathEpoch.GetDueByMs() != fixture.clock.Now().Add(fixture.settings.PathEpochBatchedDelay).UnixMilli() {
				t.Fatalf("%s: due %v", c.name, pathEpoch)
			}
			fixture.requireCommitted(fixture.push(creation), 3)
		}
		if immediate := sidecar.EvsClassifyPathEpochDue(fixture.admission.State(), fixture.check.repoId, from, to); immediate != c.immediate {
			t.Errorf("%s: a client of the same log classes it immediate %t", c.name, immediate)
		}
	}
}
