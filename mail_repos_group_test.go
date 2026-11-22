//go:build !sidecar_http && !js && !ios_extension

// QD-1177's group mail on a personal network, through a receiver: the receiver's depositor (MAIL-M7-14) judging each
// repo by the deposit right its own verified state gives it, as mailEvsDepositRepo does, on a state built by §8's own
// statement rules from what MailRepos files (mail_repos_test.go's world).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Group repos as a receiver's depositor meets them: each repo's right is the world's newest state read as
// mailEvsDepositRepo reads its client's, the exchange's check for repo:<id>:deposit, and a deposit it allows lands.
type mailGroupDepositTestRepos struct {
	world *mailReposTestWorld

	stateLock  sync.Mutex
	plaintexts map[Id][]byte
}

type mailGroupDepositTestRepo struct {
	repos  *mailGroupDepositTestRepos
	repoId Id
}

// See mailDepositRightRepo.
func (self *mailGroupDepositTestRepo) depositRight(depositorId Id) (bool, bool) {
	access := self.repos.world.state().EvsAccess(AclSidecarSubject(depositorId), self.repoId, AclTokenAudienceEvs, aclTestNow)
	return access.Rights.Has(AclEvsDeposit), true
}

func (self *mailGroupDepositTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	plaintext, err := io.ReadAll(args.Body)
	if err != nil {
		return nil, err
	}
	self.repos.stateLock.Lock()
	defer self.repos.stateLock.Unlock()
	self.repos.plaintexts[self.repoId] = plaintext
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: 1}, nil
}

// On a personal network a group one device created takes mail through a receiver on another device of the member
// (QD-1177): the receiver's depositor finds deposit in its own verified state and deposits the message into the group
// repo, its trailer naming the group's recipient and the receiver. A group repo as group-create left it before, with
// group-add's reader grant alone, is refused at once with nothing deposited, the 451 4.3.0 a sender's every retry met.
func TestMailGroupOnAPersonalNetworkTakesMailThroughAReceiverOnAnotherDevice(t *testing.T) {
	world := newMailReposTestWorld(t)
	member, owner := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := world.fixture.device(member, NewId().Bytes())
	world.fixture.configRepo(owner, member)
	world.rebuild()
	groupId := mailReposTestGroupWithMember(t, world, world.repos(owner), owner, member)

	// a group as group-create left one on a personal network before QD-1177: its repo, and the member's reader grant
	readingGroupId := NewId()
	if err := world.file(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		RepoId: readingGroupId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP,
	}); err != nil {
		t.Fatal(err)
	}
	if err := world.file(owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		RepoId: readingGroupId.Bytes(), Subject: member.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	}); err != nil {
		t.Fatal(err)
	}

	repos := &mailGroupDepositTestRepos{world: world, plaintexts: map[Id][]byte{}}
	depositor := newMailDepositor(func(repoId Id) mailDepositRepo {
		return &mailGroupDepositTestRepo{repos: repos, repoId: repoId}
	}, &MailDepositorArgs{ReceiverSidecarId: receiver})
	ctx := context.Background()
	err := depositor.Deposit(ctx, &MailDepositInput{
		Spool:   newMailDepositTestSpool(t, testMailSessionMessage("to the group before")),
		Targets: []*MailDepositTarget{{RepoId: readingGroupId, Recipients: []string{testMailSessionAlice}}},
	})
	if !errors.Is(err, ErrMailDepositFailed) || len(repos.plaintexts) != 0 {
		t.Fatalf("the group with a reader grant alone: %v, %d deposits", err, len(repos.plaintexts))
	}

	message := testMailSessionMessage("to the group")
	err = depositor.Deposit(ctx, &MailDepositInput{
		Spool:   newMailDepositTestSpool(t, message),
		Targets: []*MailDepositTarget{{RepoId: groupId, Recipients: []string{testMailSessionAlice}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotMessage, trailer, err := mailSplitDeposit(repos.plaintexts[groupId], DefaultMailIngestSettings().TrailerMaxByteCount)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotMessage, message) || len(trailer.GetRecipients()) != 1 || trailer.GetRecipients()[0] != testMailSessionAlice ||
		!bytes.Equal(trailer.GetReceiverSidecarId(), receiver.Bytes()) {
		t.Fatalf("the group's deposit: recipients %v, receiver %x", trailer.GetRecipients(), trailer.GetReceiverSidecarId())
	}
}
