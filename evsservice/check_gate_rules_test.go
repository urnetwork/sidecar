// DESIGN-DETAILS 16.6's first gate bullet (EVS1-M6-07; QD-803): 5d's rules clause over hand-built push views. A push
// that creates a shared ref, on no head, a placeholder or a deleted head, is held to the position of the repo's newest
// rule set: below it 412 GATE_CLOSED recorded, at it and above it passing, the fence's final refusal first below a
// DELETE's pin. Each kind of creating push is held: a file-mode ref's first, a branch's creating UPDATE, a tag ref's
// IMMUTABLE push, each again after a DELETE, and one carrying FORCE. None of these is held at a pin below the set: an
// owned, a deposit and the erasure ref on no head; a pin push, a DELETE and an ordinary push on a live head at the
// head's pin; a creating push where the repo's row holds no set, and one in a repo that is not general. The greater of
// two positions is compared in either order in the row; a state without the repo's row answers 503; and the push's
// own pin is judged first, above evs's state 503 and off its chain final. The testhooks switch's case is in
// check_gate_off_testhooks_test.go, and the refusal's fate through the engine in push_gate_rules_test.go.

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Appends the state's next position as appendState does, its rows holding the repos given: the fixture's repo with
// the rule sets a test filed, another repo beside it, or none.
func (self *checkFixture) appendRepoState(repos ...*protocol.AclRepo) *sidecartest.FakeGkmAuthView {
	rows := sidecartest.FakeGkmAuthRows(repos...)
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(testId("check member"), self.signerId, self.otherId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	self.auth = self.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			self.signerId: self.signingKey.Public().(ed25519.PublicKey),
			self.otherId:  self.otherKey.Public().(ed25519.PublicKey),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{self.repoId: {self.signerId, self.otherId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{self.repoId: {self.signerId, self.otherId}},
	})
	return self.auth
}

// The fixture's repo as a general repo's row, with a rule set filed at each position given, in that order.
func (self *checkFixture) rulesRepo(ats ...uint64) *protocol.AclRepo {
	repo := &protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	for _, at := range ats {
		repo.PrefixRules = append(repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: self.otherId.Bytes(), At: at})
	}
	return repo
}

// A check fixture whose log holds the repo's row with no set at positions 1 and 2, a set filed at 3, and the same row
// at 4, the newest, which views judge against; and each position's pin, by position.
func newCheckRulesFixture(t *testing.T) (*checkFixture, []*bridge.AuthPin) {
	fixture := newCheckFixture(t)
	pins := []*bridge.AuthPin{nil, fixture.firstView.Pin()}
	pins = append(pins, fixture.appendRepoState(fixture.rulesRepo()).Pin())
	pins = append(pins, fixture.appendRepoState(fixture.rulesRepo(3)).Pin())
	pins = append(pins, fixture.appendRepoState(fixture.rulesRepo(3)).Pin())
	return fixture, pins
}

// The view of a push on the fixture's ref pinned at pin, which adjust shapes first: by default a file-mode shared ref's
// first push, creating one file, on no head. A plan adjust leaves with no change gets that creation.
func (self *checkFixture) rulesView(pin *bridge.AuthPin, adjust func(plan *sidecar.EvsPushPlan)) *PushView {
	self.t.Helper()
	plan := self.plan()
	plan.Auth = pin
	creates := true
	if adjust != nil {
		adjust(plan)
		creates = plan.Changes == nil
	}
	if creates {
		plan.Changes = []*sidecar.EvsPlannedChange{self.change(plan, checkTestPath("a"), 0, plan.BaseVersion+1)}
	}
	return self.view(plan)
}

// Puts a deleted head at version 3 under view, the DELETE's pin deletePin: a tombstone of the push's kind and mode.
func checkRulesTombstone(view *PushView, deletePin *bridge.AuthPin) {
	view.Head = checkTestHead(view, 3)
	view.Head.Deleted = true
	view.Head.Auth = deletePin
	view.HeadFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
}

// Holds a refusal to the clause's, its detail naming the push's pin and the set's position.
func requireRulesRefusal(t *testing.T, name string, refusal *EvsCheckRefusal, pin uint64, at uint64) {
	t.Helper()
	requireCheckRefusal(t, name, refusal, EvsCheckReasonPinBelowRules)
	if refusal == nil || refusal.Reason != EvsCheckReasonPinBelowRules {
		return
	}
	if refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED || !refusal.Recorded() {
		t.Errorf("%s: code %s, recorded %t, want GATE_CLOSED recorded", name, refusal.Code, refusal.Recorded())
	}
	if status, _ := sidecar.EvsRefusalStatus(refusal.Code); status != http.StatusPreconditionFailed {
		t.Errorf("%s: status %d, want 412", name, status)
	}
	if want := fmt.Sprintf("auth pin %d below the repo's newest rule set at %d", pin, at); refusal.Detail != want {
		t.Errorf("%s: detail %q, want %q", name, refusal.Detail, want)
	}
}

// A push creating a shared ref, pinned below, at and above the newest set's position: on no head, on a placeholder,
// and on a deleted head at pins at or above the DELETE's, where below the DELETE's pin the fence's final refusal comes
// first. Through step 5 whole, the refusal is 5d's.
func TestCheckGateHoldsACreatingPushToTheNewestRuleSet(t *testing.T) {
	fixture, pins := newCheckRulesFixture(t)
	heads := []struct {
		name string
		put  func(view *PushView)
	}{
		{name: "no head", put: func(view *PushView) {}},
		// version 0 with no kind or mode, as a refused or fenced creation leaves
		{name: "a placeholder", put: func(view *PushView) { view.Head = &protocol.EvsHead{Fence: 1, RefusedMs: 1} }},
		{name: "a deleted head", put: func(view *PushView) { checkRulesTombstone(view, pins[2]) }},
	}
	for _, head := range heads {
		at := func(pin *bridge.AuthPin) *PushView {
			view := fixture.rulesView(pin, nil)
			head.put(view)
			return view
		}
		requireRulesRefusal(t, head.name+", pinned below the set", CheckGate(at(pins[2])), 2, 3)
		requireCheckPass(t, head.name+", pinned at the set", CheckGate(at(pins[3])))
		requireCheckPass(t, head.name+", pinned above the set", CheckGate(at(pins[4])))
	}

	// below the DELETE's pin the fence settles it, finally, before the clause is asked
	below := fixture.rulesView(pins[1], nil)
	checkRulesTombstone(below, pins[2])
	requireCheckRefusal(t, "a deleted head, pinned below the DELETE's", CheckGate(below), EvsCheckReasonPinBelowHead)

	// step 5 whole: the push passes 5b and 5c and is refused at 5d's clause, and passes at the set
	requireRulesRefusal(t, "step 5, pinned below the set", CheckPush(fixture.rulesView(pins[2], nil)), 2, 3)
	requireCheckPass(t, "step 5, pinned at the set", CheckPush(fixture.rulesView(pins[3], nil)))
}

// Each kind of creating push is held: a file-mode ref's first, a branch's creating UPDATE, a tag ref's IMMUTABLE push,
// each again after a DELETE, and one carrying FORCE, on no head and after a DELETE. Each passes at the set's position.
func TestCheckGateHoldsEachKindOfCreatingPush(t *testing.T) {
	fixture, pins := newCheckRulesFixture(t)
	git := func(plan *sidecar.EvsPushPlan) {
		plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	}
	kinds := []struct {
		name  string
		shape func(plan *sidecar.EvsPushPlan)
	}{
		{name: "a file-mode ref's first push", shape: func(plan *sidecar.EvsPushPlan) {}},
		{name: "a branch's creating UPDATE", shape: git},
		{name: "a tag ref's IMMUTABLE push", shape: func(plan *sidecar.EvsPushPlan) {
			git(plan)
			plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
		}},
		{name: "a creating push carrying FORCE", shape: func(plan *sidecar.EvsPushPlan) {
			plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		}},
		{name: "a git-mode creating push carrying FORCE", shape: func(plan *sidecar.EvsPushPlan) {
			git(plan)
			plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		}},
	}
	for _, kind := range kinds {
		requireRulesRefusal(t, kind.name+" on no head", CheckGate(fixture.rulesView(pins[2], kind.shape)), 2, 3)
		requireCheckPass(t, kind.name+" on no head, at the set", CheckGate(fixture.rulesView(pins[3], kind.shape)))

		again := fixture.rulesView(pins[2], kind.shape)
		checkRulesTombstone(again, pins[1])
		requireRulesRefusal(t, kind.name+" after a DELETE", CheckGate(again), 2, 3)
		passes := fixture.rulesView(pins[3], kind.shape)
		checkRulesTombstone(passes, pins[1])
		requireCheckPass(t, kind.name+" after a DELETE, at the set", CheckGate(passes))
	}
}

// None of these is held, each at a pin below the set: an owned, a deposit and the erasure ref on no head; a pin push,
// a DELETE and an ordinary push on a live head, each at the head's pin; a creating push where the repo's row holds no
// set; and one in a repo that is not general, beside a general repo whose row holds a set above the pin.
func TestCheckGateLeavesWhatTheRulesClauseDoesNotHold(t *testing.T) {
	fixture, pins := newCheckRulesFixture(t)
	signer := fixture.signerId
	refs := []struct {
		name  string
		shape func(plan *sidecar.EvsPushPlan)
	}{
		{name: "an owned ref", shape: func(plan *sidecar.EvsPushPlan) {
			plan.RefKind, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_OWNED, &signer
		}},
		{name: "a deposit ref", shape: func(plan *sidecar.EvsPushPlan) {
			plan.RefKind, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_DEPOSIT, &signer
			plan.RefId = sidecar.EvsDepositRefId(fixture.repoId, signer)
		}},
		{name: "the erasure ref", shape: func(plan *sidecar.EvsPushPlan) {
			plan.RefKind, plan.RefId = protocol.EvsRefKind_EVS_REF_ERASURE, sidecar.EvsErasureRefId(fixture.repoId)
		}},
	}
	for _, ref := range refs {
		requireCheckPass(t, ref.name+" on no head, pinned below the set", CheckGate(fixture.rulesView(pins[2], ref.shape)))
	}

	// a live head at version 3 whose push was pinned at 2, below the set: each push at the head's pin
	onHead := func(shape func(plan *sidecar.EvsPushPlan)) *PushView {
		view := fixture.rulesView(pins[2], func(plan *sidecar.EvsPushPlan) {
			plan.BaseVersion = 3
			shape(plan)
		})
		view.Head = checkTestHead(view, 3)
		return view
	}
	pinPush := onHead(func(plan *sidecar.EvsPushPlan) {
		plan.Changes = []*sidecar.EvsPlannedChange{}
	})
	if 0 < len(pinPush.Payload.Changes) {
		t.Fatalf("the pin push carries %d changes", len(pinPush.Payload.Changes))
	}
	requireCheckPass(t, "a pin push on a live head", CheckGate(pinPush))
	deletion := onHead(func(plan *sidecar.EvsPushPlan) {
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
		plan.Changes = []*sidecar.EvsPlannedChange{}
	})
	requireCheckPass(t, "a DELETE of a live head", CheckGate(deletion))
	ordinary := onHead(func(plan *sidecar.EvsPushPlan) {
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("b"), 0, 4)}
	})
	requireCheckPass(t, "an ordinary push on a live head", CheckGate(ordinary))
	// the same pushes after the head's pin rose past the set are held by the fence, not the clause
	raised := onHead(func(plan *sidecar.EvsPushPlan) {
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("b"), 0, 4)}
	})
	raised.Head.Auth = pins[3]
	requireCheckRefusal(t, "an ordinary push below a head pinned at the set", CheckGate(raised), EvsCheckReasonPinBelowHead)

	// no set in the repo's row, at a later position
	unset := newCheckFixture(t)
	unset.appendRepoState(unset.rulesRepo())
	unset.appendRepoState(unset.rulesRepo())
	requireCheckPass(t, "a creating push where the row holds no set", CheckGate(unset.rulesView(unset.firstView.Pin(), nil)))

	// a repo that is not general holds no set, whatever a general repo of the network holds
	notGeneral := newCheckFixture(t)
	general := testId("check general repo")
	notGeneral.appendRepoState(
		&protocol.AclRepo{RepoId: notGeneral.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT},
		&protocol.AclRepo{RepoId: general.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, PrefixRules: []*protocol.AclRepoPrefixRulesRow{
			{Signer: notGeneral.otherId.Bytes(), At: 2},
		}},
	)
	requireCheckPass(t, "a creating push in a repo that is not general", CheckGate(notGeneral.rulesView(notGeneral.firstView.Pin(), nil)))
}

// Two sets: the greater position is the one compared, in either order in the row.
func TestCheckGateComparesTheNewestOfTwoRuleSets(t *testing.T) {
	for _, order := range [][]uint64{{3, 5}, {5, 3}} {
		fixture := newCheckFixture(t)
		pins := []*bridge.AuthPin{nil, fixture.firstView.Pin()}
		for position := uint64(2); position <= 6; position += 1 {
			ats := []uint64{}
			for _, at := range order {
				if at <= position {
					ats = append(ats, at)
				}
			}
			pins = append(pins, fixture.appendRepoState(fixture.rulesRepo(ats...)).Pin())
		}
		name := fmt.Sprintf("sets at %v", order)
		requireRulesRefusal(t, name+", pinned at the older", CheckGate(fixture.rulesView(pins[3], nil)), 3, 5)
		requireRulesRefusal(t, name+", pinned between", CheckGate(fixture.rulesView(pins[4], nil)), 4, 5)
		requireCheckPass(t, name+", pinned at the newer", CheckGate(fixture.rulesView(pins[5], nil)))
		requireCheckPass(t, name+", pinned above both", CheckGate(fixture.rulesView(pins[6], nil)))
	}
}

// A state that lacks the repo's row answers 503 at the clause, as the predicate does, and the same push of an owned ref
// reaches the predicate's 503.
func TestCheckGateRulesClauseOnAStateLackingTheRepo(t *testing.T) {
	fixture := newCheckFixture(t)
	other := testId("check other repo")
	pin := fixture.appendRepoState(&protocol.AclRepo{RepoId: other.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}).Pin()
	refusal := CheckGate(fixture.rulesView(pin, nil))
	requireCheckRefusal(t, "a creating push of a shared ref", refusal, EvsCheckReasonGateUnknown)
	if refusal != nil && !strings.Contains(refusal.Detail, "lacking the repo's row") {
		t.Errorf("the 503 came from %q, not the clause", refusal.Detail)
	}
	signer := fixture.signerId
	owned := CheckGate(fixture.rulesView(pin, func(plan *sidecar.EvsPushPlan) {
		plan.RefKind, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_OWNED, &signer
	}))
	requireCheckRefusal(t, "a creating push of an owned ref", owned, EvsCheckReasonGateUnknown)
	if owned != nil && strings.Contains(owned.Detail, "lacking the repo's row") {
		t.Error("the clause judged an owned ref")
	}
}

// The push's own pin is judged before the clause: above evs's state 503, and off its chain final, though the pin's
// version lies below the set. A pin before what evs retains is not judged there, and the clause compares its version.
func TestCheckGateJudgesTheOwnPinBeforeTheRulesClause(t *testing.T) {
	fixture, pins := newCheckRulesFixture(t)
	ahead := CheckGate(fixture.rulesView(&bridge.AuthPin{Version: 9, Chain: bytes.Repeat([]byte{3}, 32)}, nil))
	requireCheckRefusal(t, "an auth pin above evs's state", ahead, EvsCheckReasonGateUnknown)
	if ahead != nil && ahead.Detail != "an auth pin above evs's state" {
		t.Errorf("the 503 came from %q, not the own-pin row", ahead.Detail)
	}
	requireCheckRefusal(t, "an auth pin off evs's chain, below the set", CheckGate(fixture.rulesView(sidecartest.FakeGkmForkPin(2), nil)),
		EvsCheckReasonPinForked)

	fixture.authLog.Retain(3)
	requireRulesRefusal(t, "an auth pin before what evs retains", CheckGate(fixture.rulesView(pins[2], nil)), 2, 3)
}
