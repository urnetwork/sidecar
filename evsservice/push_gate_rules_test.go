// QD-803's clause reverted (QD-1032), through the engine on FakeBlobs: with the engine's state holding a rule set for
// the repo above the push's pin, a push that creates a shared ref commits as version 1 with no placeholder and no
// refusal record, a re-creation on a deleted head at the DELETE's pin commits at the version after the DELETE's, and a
// creating push in parts has every part taken and its seal committed. Before the revert each was refused 412
// GATE_CLOSED and recorded (6d143f14).

package evsservice

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Files a rule set for the fixture's repo: the next position of the engine's state holds the repo's row with a set at
// that position. Its pin, the set's own, is returned.
func (self *pushFixture) fileRuleSet() *bridge.AuthPin {
	at := self.check.auth.Pin().GetVersion() + 1
	return self.check.appendRepoState(self.check.rulesRepo(at)).Pin()
}

// On no head: a creation pinned below the set commits as version 1, its head holding no refusal record.
func TestPushCommitsACreationPinnedBelowARuleSet(t *testing.T) {
	fixture := newPushFixture(t, nil)
	setPin := fixture.fileRuleSet()
	token := fixture.token(fixture.check.signerId)

	plan := fixture.plan()
	fixture.create(plan, "a")
	if setPin.GetVersion() <= plan.Auth.GetVersion() {
		t.Fatalf("the push pinned at %d, the set at %d", plan.Auth.GetVersion(), setPin.GetVersion())
	}
	fixture.requireCommitted(fixture.post(token, fixture.body(plan)), 1)
	fixture.awaitStepEights()
	head := fixture.head()
	if head.Version() != 1 || head.Head.GetAuth().GetVersion() != plan.Auth.GetVersion() || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("the creation: version %d, pin %d, %d B of records", head.Version(), head.Head.GetAuth().GetVersion(), len(head.Head.GetRefused()))
	}
}

// On a deleted head, at the DELETE's pin and below the set: the re-creation commits at the version after the DELETE's,
// and the tombstone took no record.
func TestPushCommitsARecreationPinnedBelowARuleSet(t *testing.T) {
	fixture := newPushFixture(t, nil)
	// a shared ref's DELETE needs admin
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	token := fixture.token(fixture.check.signerId, "admin")

	first := fixture.plan()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.post(token, fixture.body(first)), 1)
	fixture.awaitStepEights()
	deletion := fixture.plan()
	deletion.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
	fixture.requireCommitted(fixture.post(token, fixture.body(deletion)), 2)
	fixture.awaitStepEights()

	fixture.fileRuleSet()
	again := fixture.plan()
	fixture.create(again, "b")
	fixture.requireCommitted(fixture.post(token, fixture.body(again)), 3)
	fixture.awaitStepEights()
	if head := fixture.head(); head.Head.GetDeleted() || head.Version() != 3 || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("the re-created head: deleted %t at %d, %d B of records", head.Head.GetDeleted(), head.Version(), len(head.Head.GetRefused()))
	}
}

// A creating push in parts whose parts this engine took before its state held the set: a part posted again after it is
// taken, and the seal commits.
func TestPushSealsACreationInPartsPinnedBelowARuleSet(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(built.Parts) < 2 {
		t.Fatalf("a push in %d parts", len(built.Parts))
	}
	places := fixture.postParts(token, built)
	fixture.fileRuleSet()
	fixture.requirePlace(fixture.postPart(token, built, 0))
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
}
