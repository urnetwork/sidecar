// QD-803's clause reverted (QD-1032): the client-checked prefix write rules moved to Later, and 5d holds no push to the
// repo's rule sets, as it held none before EVS1-M6-07 (e0d318f0). Over hand-built push views whose state's row holds a
// set at a position above the push's pin, every creating push of a shared ref passes 5d and step 5 whole: on no head,
// a placeholder and a deleted head, a file-mode ref's first push, a branch's creating UPDATE, a tag ref's IMMUTABLE
// push and one carrying FORCE. What held a creating push before the clause still does: the fence below a DELETE's pin,
// the own-pin row above evs's state or off its chain, and the predicate's 503 for a state lacking the repo, which no
// longer names the rows. The engine's half is push_gate_rules_test.go's.

package evsservice

import (
	"crypto/ed25519"
	"fmt"
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

// The fixture's repo as a general repo's row, with a rule set filed at each position given, in that order: rows a
// state holds only from a log that ran the rules, which evs reads nothing of now.
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

// A push creating a shared ref, pinned below the newest set's position, at it and above it, passes 5d on no head, on a
// placeholder and on a deleted head at or above the DELETE's pin, and step 5 whole below the set; below the DELETE's
// pin the fence's final refusal is what it always was.
func TestCheckGateHoldsNoCreatingPushToTheRuleSets(t *testing.T) {
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
		for _, pin := range pins[2:] {
			view := fixture.rulesView(pin, nil)
			head.put(view)
			requireCheckPass(t, fmt.Sprintf("%s, pinned at %d against a set at 3", head.name, pin.GetVersion()), CheckGate(view))
		}
	}

	below := fixture.rulesView(pins[1], nil)
	checkRulesTombstone(below, pins[2])
	requireCheckRefusal(t, "a deleted head, pinned below the DELETE's", CheckGate(below), EvsCheckReasonPinBelowHead)

	requireCheckPass(t, "step 5, pinned below the set", CheckPush(fixture.rulesView(pins[2], nil)))
}

// Each kind of creating push that QD-803's clause held passes 5d below the set, on no head and again after a DELETE:
// a file-mode ref's first, a branch's creating UPDATE, a tag ref's IMMUTABLE push, and one carrying FORCE in either
// mode.
func TestCheckGatePassesEachKindOfCreatingPushBelowTheRuleSets(t *testing.T) {
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
		requireCheckPass(t, kind.name+" on no head, below the set", CheckGate(fixture.rulesView(pins[2], kind.shape)))
		again := fixture.rulesView(pins[2], kind.shape)
		checkRulesTombstone(again, pins[1])
		requireCheckPass(t, kind.name+" after a DELETE, below the set", CheckGate(again))
	}
}

// What held a creating push before the clause still holds it, whatever sets the row holds: a state that lacks the
// repo's row answers the predicate's 503, which names no rows; and the push's own pin, above evs's state 503 and off
// its chain final.
func TestCheckGateHoldsACreatingPushAsBeforeTheRulesClause(t *testing.T) {
	fixture := newCheckFixture(t)
	other := testId("check other repo")
	pin := fixture.appendRepoState(&protocol.AclRepo{RepoId: other.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}).Pin()
	refusal := CheckGate(fixture.rulesView(pin, nil))
	requireCheckRefusal(t, "a state lacking the repo's row", refusal, EvsCheckReasonGateUnknown)
	if refusal != nil && strings.Contains(refusal.Detail, "row") {
		t.Errorf("the 503 came from the reverted clause: %q", refusal.Detail)
	}

	ruled, pins := newCheckRulesFixture(t)
	ahead := CheckGate(ruled.rulesView(&bridge.AuthPin{Version: 9, Chain: pins[4].GetChain()}, nil))
	requireCheckRefusal(t, "an auth pin above evs's state", ahead, EvsCheckReasonGateUnknown)
	requireCheckRefusal(t, "an auth pin off evs's chain, below the set", CheckGate(ruled.rulesView(sidecartest.FakeGkmForkPin(2), nil)),
		EvsCheckReasonPinForked)
}
