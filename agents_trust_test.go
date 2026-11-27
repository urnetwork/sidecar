//go:build !ios_extension && !sidecar_http

// A message's trust (§20.7, D-SKILL-4, IC-12): the person's input path, a push bound to no run from an untagged device
// of the member, and an untainted run on one leave the reader untainted; a tainted run's message, a tagged sidecar's, a
// forged from and a version with no provenance taint; a support notice is neither, and one from outside the member is
// refused.

package sidecar

import (
	"testing"
)

func TestTrustClasses(t *testing.T) {
	env := newTestAgentThreadEnv(t)
	world := env.world
	cloud := world.client(world.cloud)
	if _, err := cloud.Register(world.ctx, &AgentRegisterArgs{Name: "scraper", Harness: "codex", Model: "local-gemma"}); err != nil {
		t.Fatal(err)
	}
	opened, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "an untainted run's"})
	if err != nil {
		t.Fatal(err)
	}
	thread, repoId := opened.Message.Thread, opened.RepoId
	again := func(args *AgentSendArgs, client *AgentsClient) *AgentSendResult {
		t.Helper()
		args.Thread, args.ThreadRepoId = thread, repoId
		sent, err := client.Send(world.ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		return sent
	}
	again(&AgentSendArgs{Person: true, To: "fix", Body: "the person's"}, env.phone)
	again(&AgentSendArgs{From: "orchestrator", To: "fix", Body: "a tainted run's", Tainted: true}, env.laptop)
	again(&AgentSendArgs{From: "scraper", To: "fix", Body: "a cloud agent's"}, cloud)
	// the laptop's run writes a message whose from names another agent of the laptop: its provenance names fix
	forged := *opened.Message
	forged.Id, forged.Seq, forged.Body = AgentMessageIdForCall(testConfigId("forger"), "call"), 9, "a forged from"
	forged.From.Name = "fix"
	forgedData, err := EncodeAgentMessage(&forged, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	// and a version evs gives no provenance of
	unknown := forged
	unknown.Id, unknown.Seq, unknown.Body, unknown.From = AgentMessageIdForCall(testConfigId("unknown"), "call"), 10, "no provenance", opened.Message.From
	unknownData, err := EncodeAgentMessage(&unknown, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		repo := world.repo(repoId)
		orchestrator := env.boss.AgentId
		repo.putAs(world.laptop, forged.Path(), forgedData, false, &orchestrator)
		repo.putAs(world.laptop, unknown.Path(), unknownData, false, &orchestrator)
		repo.newest(unknown.Path()).noProvenance = true
	}()
	read, err := env.phone.Thread(world.ctx, repoId, thread)
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]*AgentMessageTrust{}
	for _, message := range read.Messages {
		classes[message.Message.Body] = message.Trust
	}
	want := []struct {
		body     string
		class    AgentMessageTrustClass
		verified bool
	}{
		{body: "an untainted run's", class: AgentMessageTrustMemberRun, verified: true},
		{body: "the person's", class: AgentMessageTrustPerson, verified: true},
		{body: "a tainted run's", class: AgentMessageTrustUntrusted, verified: true},
		{body: "a cloud agent's", class: AgentMessageTrustUntrusted, verified: true},
		{body: "a forged from", class: AgentMessageTrustUntrusted, verified: false},
		{body: "no provenance", class: AgentMessageTrustUntrusted, verified: false},
	}
	for _, c := range want {
		trust := classes[c.body]
		if trust == nil || trust.Class != c.class || trust.FromVerified != c.verified {
			t.Errorf("%s: %+v", c.body, trust)
			continue
		}
		if trust.Taints() == (c.class != AgentMessageTrustUntrusted) {
			t.Errorf("%s: taints %t", c.body, trust.Taints())
		}
	}
	// the forged message is shown by its provenance: the laptop and the agent that pushed it, alarmed
	if forgedTrust := classes["a forged from"]; forgedTrust.Sender.SidecarId != world.laptop || *forgedTrust.Sender.AgentId != env.boss.AgentId {
		t.Errorf("the forged message's sender: %+v", forgedTrust.Sender)
	}
	if world.alarmCount() == 0 {
		t.Error("a forged from raised no alarm")
	}
	// a support notice from a device of the member is neither trusted nor tainting; one from another member is refused
	notice := &AgentMessage{Id: AgentSupportNoticeId(AgentMessageSupportFrom, "100171", 1), Thread: AgentSupportThreadId(AgentMessageSupportFrom, "100171"),
		Seq: 1, From: AgentMessageFrom{Support: true}, To: &AgentAddress{MemberId: world.member, Name: "fix", RepoId: env.fix.InboxRepoId},
		Kind: AgentMessageKindSupport, Created: world.now(),
		Support: &AgentMessageSupport{Product: AgentMessageSupportFrom, Entry: "100171", Seq: 1, Type: "note", Status: "in_progress"}}
	judge := &agentMessageJudge{authority: &testAgentsAuthority{world: world}, memberId: world.member}
	provenance := &EvsPushProvenance{State: EvsProvenanceUnattributed}
	if trust := judge.judge(notice, world.phone, provenance); trust.Class != AgentMessageTrustSupport || trust.Taints() || trust.Trusted() {
		t.Errorf("a member device's notice: %+v", trust)
	}
	if trust := judge.judge(notice, world.otherDevice, provenance); trust.Class != AgentMessageTrustRefused {
		t.Errorf("another member's notice: %+v", trust)
	}
}
