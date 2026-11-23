//go:build !sidecar_http && !js && !ios_extension

// The same-network send's deposit half against §8's state (mail_send_local.go's receipts row; QD-1183): a deposit
// right that is §16.8's receipt deposit carries no mail, so the send side answers what ingest will make of the deposit.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// On a personal network a same-network send from the member's read_only device answers MailSendNoDepositRight to a
// group it reads, where it holds r alone and evs refuses its deposit, and to its own member's mailbox, where its
// deposit is the receipt deposit, whose ref ingest leaves to the record's receipts: no send of its is answered
// delivered. The member's receiver, which is not read_only, is answered delivered at both. Ingest classes each depositor
// as the send side answers: mail where it is delivered, and no mail where it refuses, the read_only line's
// MailDepositorNone in the group and a receipt depositor in the mailbox.
func TestMailSendFromAReadOnlyDeviceHasNoDepositRight(t *testing.T) {
	repos := newMailReposTestWorld(t)
	member, owner := repos.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := repos.fixture.device(member, owner.Bytes())
	pageWorker := repos.fixture.device(member, owner.Bytes())
	repos.fixture.admission(pageWorker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	repos.fixture.configRepo(owner, member)
	mailboxId, mailbox := repos.fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, member)
	mailbox.ConsentedSidecarIds = [][]byte{owner.Bytes(), receiver.Bytes(), pageWorker.Bytes()}
	repos.rebuild()
	groupId := mailReposTestGroupWithMember(t, repos, repos.repos(owner), owner, member)
	state := repos.state()
	engine := NewAclEngine(owner, nil, nil, nil)
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	authority := &MailSendAclAuthority{Engine: engine, Clock: fixedClock{at: aclTestNow}}
	ingest := &MailIngestAclAuthority{Engine: engine, Clock: fixedClock{at: aclTestNow}}
	pin := state.Pin()
	cases := []struct {
		name    string
		sender  Id
		repoId  Id
		outcome MailSendOutcome
		class   MailDepositorClass
	}{
		{name: "the read_only device to the group", sender: pageWorker, repoId: groupId, outcome: MailSendNoDepositRight, class: MailDepositorNone},
		{name: "the read_only device to its member's mailbox", sender: pageWorker, repoId: mailboxId, outcome: MailSendNoDepositRight, class: MailDepositorReceipts},
		{name: "the receiver to the group", sender: receiver, repoId: groupId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "the receiver to its member's mailbox", sender: receiver, repoId: mailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
	}
	for _, c := range cases {
		if outcome := mailSendMayDeposit(state, c.sender, c.repoId, aclTestNow); outcome != c.outcome {
			t.Errorf("%s: %s, not %s", c.name, outcome, c.outcome)
		}
		if outcome := authority.MayDeposit(c.sender, c.repoId); outcome != c.outcome {
			t.Errorf("%s, through the installed engine: %s, not %s", c.name, outcome, c.outcome)
		}
		if class := ingest.DepositorClass(c.repoId, c.sender, pin); class != c.class {
			t.Errorf("%s: ingest classes the depositor %d, not %d", c.name, class, c.class)
		}
	}
}
