package gkmschedule

// QD-638 on the real subset (KEYS-M2-32; §10.7's KF1 with its second device, D-KEYS-18, owner decision 8): a tagged
// agent files the RepoCreate of a general repo, places it and stays its admin; it holds no leaf, so a member device
// that gkm's pending hint reaches forms the group, KF1's steps 2 to 4 as the group's creator, epoch 0 its own leaf,
// and wraps generation 1 to the agent, which then activates the repo. A repo an agent creates while no member device
// is online stays keying until one returns; two member devices that act at once leave one group, the loser
// discarding its draft; and a repo whose RepoCreate a member device refuses at its state, its signer revoked since,
// is left keying with an alarm naming the signer.

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The agent's repo's world: the agent d creates the repo; a and b are member devices of the network's Owner, config
// writers and, as the implicit document gives member devices, readers, writers and admins of every repo.
func newGkmAgentRepoWorld(t *testing.T) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b, d)
	world.Creator(d)
	world.Admin(a)
	world.Admin(b)
	world.ConfigWriters(a, b)
	world.Advance()
	world.Publish()
	// the agent places the repo, keying, as evs's PUT does on its RepoCreate
	world.Place(d)
	return world, a, b, d
}

// The agent's side of CreateRepo: generation 1 by its wrap, then the activation.
func (self *FsKeysWorld) agentActivates(agent *FsKeysDevice) bool {
	key, err := agent.Client.CurrentRepoKey(self.Ctx, self.RepoId)
	if err != nil || key.Generation() != 1 {
		return false
	}
	self.GroupId = key.GroupId()
	self.Activate()
	return true
}

// A pending hint that names no group: QD-638's, for a repo with no group yet.
func gkmAgentRepoHint(hint *FsKeysHint) bool {
	return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING && len(hint.Hint.GetGroupId()) == 0
}

// QD-638: with a member device online, gkm's reconciler hints the config writers about the agent's keying repo; the
// first that acts forms the group, its leaf epoch 0's only one and its form carrying its own state's pin; the agent's
// ReaderWrap of generation 1 is staged; the agent then holds generation 1 and activates; and the other member device
// joins by the pending engine's Add.
func TestGkmAgentRepoAMemberDeviceFormsTheGroupOfAnAgentsRepo(t *testing.T) {
	world, a, b, d := newGkmAgentRepoWorld(t)
	reconciler := world.StartReconciler(nil)
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.AwaitHint(a, gkmAgentRepoHint)
	world.AwaitHint(b, gkmAgentRepoHint)
	if hints := world.Hints(d); 0 < len(hints) {
		t.Errorf("the agent was hinted: %d", len(hints))
	}
	if world.agentActivates(d) {
		t.Fatal("the agent holds a generation no member device formed")
	}
	if err := a.Client.FormAgentRepos(world.Ctx); err != nil {
		t.Fatalf("the member device's step: %v", err)
	}
	if world.FormCount() != 1 {
		t.Fatalf("gkm holds %d forms", world.FormCount())
	}
	if !world.agentActivates(d) {
		t.Fatal("the agent does not hold generation 1 once a member device formed the group")
	}
	if world.RepoState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("the repo is %s", world.RepoState())
	}
	if labels := world.Roster(a); labels != "a" {
		t.Errorf("epoch 0's tree: %s", labels)
	}
	form := world.Form(1)
	if form.GetAuth() == nil || form.GetAuth().GetVersion() != world.Log.Tip().Pin().GetVersion() {
		t.Errorf("the creation's form does not carry its signer's state")
	}
	if !world.WrapRecipients(1)[d.SidecarId()] {
		t.Errorf("generation 1 holds no ReaderWrap to the agent")
	}
	// the pending engine adds b, as for any repo
	world.AddPending(a)
	if labels := world.Roster(b); labels != "ab" {
		t.Errorf("the tree after the pending run: %s", labels)
	}
	// b's own step finds the group formed and forms nothing
	if err := b.Client.FormAgentRepos(world.Ctx); err != nil || world.FormCount() != 1 {
		t.Errorf("a second member device's step: %v, %d forms", err, world.FormCount())
	}
}

// QD-638: no member device online: the repo stays keying and the agent holds nothing; once one returns and acts, the
// agent activates.
func TestGkmAgentRepoStaysKeyingUntilAMemberDeviceReturns(t *testing.T) {
	world, a, b, d := newGkmAgentRepoWorld(t)
	a.Offline = true
	b.Offline = true
	world.Advance()
	if world.agentActivates(d) || world.RepoState() != protocol.EvsRepoState_EVS_REPO_KEYING || world.FormCount() != 0 {
		t.Fatal("the agent's repo moved with no member device online")
	}
	b.Offline = false
	b.Take(world.Log.Tip())
	if err := b.Client.FormAgentRepos(world.Ctx); err != nil {
		t.Fatalf("the returning member device's step: %v", err)
	}
	if !world.agentActivates(d) {
		t.Fatal("the agent does not activate once a member device returned")
	}
}

// QD-638: two member devices act at once: b's creation reaches gkm just after a's, and gkm's 409 at the repo's first
// form ends b's, which discards its draft; one group stands, a's.
func TestGkmAgentRepoTwoMemberDevicesRacingLeaveOneGroup(t *testing.T) {
	world, a, b, d := newGkmAgentRepoWorld(t)
	raced := false
	b.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodPost && request.URL.Path == "/gkm/groups" && !raced {
			raced = true
			if err := a.Client.FormAgentRepos(world.Ctx); err != nil {
				t.Errorf("a's step: %v", err)
			}
		}
		return FsKeysFaultNone
	}
	if err := b.Client.FormAgentRepos(world.Ctx); err != nil {
		t.Fatalf("the loser's step: %v", err)
	}
	if !raced || world.FormCount() != 1 {
		t.Fatalf("the race: %v, %d forms", raced, world.FormCount())
	}
	if !world.agentActivates(d) {
		t.Fatal("the agent does not activate")
	}
	if labels := world.Roster(a); labels != "a" {
		t.Errorf("the group that stands is not a's: %s", labels)
	}
	// b holds no group of the repo: it joins the one that stands by the pending engine's Add
	world.AddPending(a)
	if labels := world.Roster(b); labels != "ab" {
		t.Errorf("b did not join the group that stands: %s", labels)
	}
}

// QD-638's trap: the member device judges the RepoCreate first: its signer revoked since, the device forms nothing,
// raises refused naming the signer once for the state, and the repo stays keying.
func TestGkmAgentRepoWhoseRepoCreateTheMemberRefusesStaysKeying(t *testing.T) {
	world, a, _, d := newGkmAgentRepoWorld(t)
	world.Revoke(d)
	world.Advance()
	if err := a.Client.FormAgentRepos(world.Ctx); err != nil {
		t.Fatalf("the member device's step: %v", err)
	}
	if err := a.Client.FormAgentRepos(world.Ctx); err != nil {
		t.Fatalf("the member device's second step: %v", err)
	}
	if world.FormCount() != 0 || world.RepoState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("a refused RepoCreate's repo moved")
	}
	refusals := 0
	for _, alarm := range a.Alarms {
		if alarm.Kind == sidecar.GkmAlarmRefused && alarm.RepoId == world.RepoId && alarm.SidecarId == d.SidecarId() {
			refusals += 1
		}
	}
	if refusals != 1 {
		t.Errorf("%d refusals naming the RepoCreate's signer, want 1: %+v", refusals, a.Alarms)
	}
}
