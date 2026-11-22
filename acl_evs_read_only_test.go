//go:build !sidecar_http && !js && !ios_extension

// QD-1183 where a read_only sidecar's rights are read: the token exchange mints it r and, only in an owner-bound repo it
// reads, §16.8's receipt deposit, and evs's and gkm's scope gate honors no deposit of its anywhere else, a personal
// network's group among them. One rule, EvsAccess's, so the exchange, the gates, the send side (mail_send_local.go)
// and ingest's read_only line (mail_ingest.go) agree.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The exchange on TEAM's log mints a read_only device no deposit scope on a general repo: not on one members write, not
// on a group inbox members write, whose writers deposit by their write, and not on the config; it mints it r on each,
// and r with the receipt deposit on the Owner's vault shared to it, at evs and at gkm, whose drop-key route takes the
// same check. The member's other device, which is not read_only, keeps the group inbox's deposit its write gives.
func TestAclExchangeScopesMintAReadOnlyDeviceNoDepositOnAGeneralRepo(t *testing.T) {
	net := newAclExchangeNet(t)
	inboxId := testConfigId("exchange group inbox")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("exchange members write the inbox").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: inboxId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_WRITE)},
		})
		rows.Repos = append(rows.Repos, &protocol.AclRepo{RepoId: inboxId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP})
		for _, repo := range rows.Repos {
			if Id(repo.GetRepoId()) == net.vaultId {
				repo.Shares = append(repo.Shares, &protocol.AclRepoShareRow{Subject: net.readOnly.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1})
			}
		}
	})
	notesR, notesDeposit := aclExchangeScope(net.notesId, "r"), aclExchangeScope(net.notesId, "deposit")
	inboxR, inboxDeposit := aclExchangeScope(inboxId, "r"), aclExchangeScope(inboxId, "deposit")
	configR, configDeposit := aclExchangeScope(net.configId, "r"), aclExchangeScope(net.configId, "deposit")
	vaultR, vaultDeposit, vaultRw := aclExchangeScope(net.vaultId, "r"), aclExchangeScope(net.vaultId, "deposit"), aclExchangeScope(net.vaultId, "rw")
	aclExchangeCheck(t, "the read_only device at evs",
		net.exchange(t, net.readOnly, AclTokenAudienceEvs, notesR, notesDeposit, inboxR, inboxDeposit, configR, configDeposit, vaultR, vaultDeposit, vaultRw),
		[]string{notesR, inboxR, configR, vaultR, vaultDeposit}, []string{notesDeposit, inboxDeposit, configDeposit, vaultRw})
	aclExchangeCheck(t, "the read_only device at gkm", net.exchange(t, net.readOnly, AclTokenAudienceGkm, inboxDeposit, vaultDeposit),
		[]string{vaultDeposit}, []string{inboxDeposit})
	aclExchangeCheck(t, "the member's other device", net.exchange(t, net.phone, AclTokenAudienceEvs, inboxDeposit, notesDeposit),
		[]string{inboxDeposit}, []string{notesDeposit})
}

// On a personal network the member's read_only device reads a group group-add joined the member to and holds r alone
// there, though the member's grants give its other devices the group's deposit (QD-1177): evs's and gkm's gate honors
// its r and refuses its deposit, while the member's receiver deposits. In the member's mailbox, an owner-bound repo it
// reads as a consented device, it keeps the receipt deposit, which the gate honors.
func TestAclEvsAccessReadOnlyReadsAPersonalGroupAlone(t *testing.T) {
	repos := newMailReposTestWorld(t)
	member, owner := repos.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := repos.fixture.device(member, owner.Bytes())
	pageWorker := repos.fixture.device(member, owner.Bytes())
	repos.fixture.admission(pageWorker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	repos.fixture.configRepo(owner, member)
	mailboxId, mailbox := repos.fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, member)
	mailbox.ConsentedSidecarIds = [][]byte{owner.Bytes(), receiver.Bytes(), pageWorker.Bytes()}
	repos.rebuild()
	if repos.state().teamNetwork() {
		t.Fatal("the personal network reads as a Team")
	}
	groupId := mailReposTestGroupWithMember(t, repos, repos.repos(owner), owner, member)
	state := repos.state()
	cases := []struct {
		name      string
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{name: "the read_only device in the group", sidecarId: pageWorker, repoId: groupId, rights: AclEvsRead},
		{name: "the member's receiver in the group", sidecarId: receiver, repoId: groupId, rights: AclEvsRead | AclEvsDeposit},
		{name: "the read_only device in the mailbox", sidecarId: pageWorker, repoId: mailboxId, rights: AclEvsRead | AclEvsDeposit},
	}
	for _, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, c.repoId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("%s: %b, want %b", c.name, rights, c.rights)
		}
	}
	gates := []struct {
		name      string
		sidecarId Id
		repoId    Id
		scope     AclEvsRights
		answer    AclScopeAnswer
	}{
		{name: "the read_only device's deposit in the group", sidecarId: pageWorker, repoId: groupId, scope: AclEvsDeposit, answer: AclScopeRefused},
		{name: "the read_only device's r in the group", sidecarId: pageWorker, repoId: groupId, scope: AclEvsRead, answer: AclScopeHonored},
		{name: "the receiver's deposit in the group", sidecarId: receiver, repoId: groupId, scope: AclEvsDeposit, answer: AclScopeHonored},
		{name: "the read_only device's receipt deposit in the mailbox", sidecarId: pageWorker, repoId: mailboxId, scope: AclEvsDeposit, answer: AclScopeHonored},
	}
	for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
		for _, c := range gates {
			if answer := AclHonorScope(state, c.sidecarId, c.repoId, c.scope, audience, aclTestNow); answer != c.answer {
				t.Errorf("%s at %d: %d, want %d", c.name, audience, answer, c.answer)
			}
		}
	}
}
