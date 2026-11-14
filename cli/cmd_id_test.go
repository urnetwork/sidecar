// ur id and ur mail against a fake daemon: create, ls and rm through the id methods, an action waiting on a person
// printing ur approve and exiting 1, group-create and group-add only after a yes on the terminal and only through a
// confirmed call, enable and status with §15.6's prompt, and the methods served only by a target that runs mail.

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A MailClient as the id and mail methods reach it, as a test sets it.
type testUrMailClient struct {
	stateLock sync.Mutex
	addresses []*sidecar.MailAddressLookup
	created   []string
	removed   []string
	groups    []string
	members   []string
	enables   int
	// an approval every create and remove waits on, while set
	pending *sidecar.Id
	status  *sidecar.MailClientStatus
}

func (self *testUrMailClient) Enable(ctx context.Context) (*sidecar.MailEnabled, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.enables += 1
	return &sidecar.MailEnabled{EnabledTime: time.Date(2026, time.November, 14, 9, 0, 0, 0, time.UTC)}, nil
}

func (self *testUrMailClient) Status(ctx context.Context) (*sidecar.MailClientStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.status == nil {
		return &sidecar.MailClientStatus{}, nil
	}
	copied := *self.status
	return &copied, nil
}

func (self *testUrMailClient) Aliases(ctx context.Context) ([]*sidecar.MailAddressLookup, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.addresses, nil
}

func (self *testUrMailClient) CreateAlias(ctx context.Context, args *sidecar.MailAliasCreateArgs) (*sidecar.MailAddressLookup, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending != nil {
		return nil, &sidecar.ApprovalPendingError{ApprovalId: *self.pending}
	}
	self.created = append(self.created, args.LocalPart)
	lookup := &sidecar.MailAddressLookup{Known: true, Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Address: args.LocalPart + "@acme.root.example"}
	self.addresses = append(self.addresses, lookup)
	return lookup, nil
}

func (self *testUrMailClient) DeleteAlias(ctx context.Context, localPart string, action sidecar.MailConfigActionArgs) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending != nil {
		return &sidecar.ApprovalPendingError{ApprovalId: *self.pending}
	}
	self.removed = append(self.removed, localPart)
	return nil
}

func (self *testUrMailClient) CreateGroup(ctx context.Context, args *sidecar.MailCreateGroupArgs) (*sidecar.EvsRepo, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !args.Confirmed {
		return nil, errors.New("an unconfirmed group")
	}
	self.groups = append(self.groups, args.LocalPart)
	return nil, nil
}

func (self *testUrMailClient) AddGroupMember(ctx context.Context, group string, memberId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.members = append(self.members, group+" "+memberId.String())
	return nil
}

// A daemon target whose hosted network runs mail.
type testUrMailTarget struct {
	testUrDaemonTarget
	client   *testUrMailClient
	networks []string
}

func (self *testUrMailTarget) mailClient(network string) (urMailClient, error) {
	self.networks = append(self.networks, network)
	return self.client, nil
}

// create, ls and rm, each through its method, and --network reaching the target.
func TestUrIdCreateListAndRemove(t *testing.T) {
	target := &testUrMailTarget{client: &testUrMailClient{}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	if code := cli.main(ctx, []string{"ur", "id", "create", "bo", "--network=acme"}); code != urExitOk || !strings.Contains(stdout.String(), "bo@acme.root.example") {
		t.Fatalf("create: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "id", "ls"}); code != urExitOk || !strings.Contains(stdout.String(), "id      bo@acme.root.example") {
		t.Fatalf("ls: exit %d: %q", code, stdout.String())
	}
	if code := cli.main(ctx, []string{"ur", "id", "rm", "bo"}); code != urExitOk {
		t.Fatalf("rm: exit %d", code)
	}
	if strings.Join(target.client.created, ",") != "bo" || strings.Join(target.client.removed, ",") != "bo" {
		t.Fatalf("created %v, removed %v", target.client.created, target.client.removed)
	}
	if len(target.networks) != 3 || target.networks[0] != "acme" || target.networks[1] != "" {
		t.Fatalf("networks %v", target.networks)
	}
}

// An address action waiting on a person prints ur approve <id> and exits 1, and runs nothing.
func TestUrIdCreateWaitingOnApprovalPrintsUrApprove(t *testing.T) {
	approvalId := sidecar.NewId()
	target := &testUrMailTarget{client: &testUrMailClient{pending: &approvalId}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	for _, args := range [][]string{{"ur", "id", "create", "bo"}, {"ur", "id", "rm", "bo"}} {
		stdout.Reset()
		if code := cli.main(context.Background(), args); code != urExitFailed || !strings.Contains(stdout.String(), "ur approve "+approvalId.String()) {
			t.Fatalf("%v: exit %d: %s", args, code, stdout.String())
		}
	}
	if 0 < len(target.client.created) || 0 < len(target.client.removed) {
		t.Fatal("an action that waits on approval ran")
	}
}

// group-create and group-add run only after a yes on the terminal, through Confirm methods that no unconfirmed call
// reaches.
func TestUrIdGroupCommandsAreConfirmedOnTheTerminal(t *testing.T) {
	target := &testUrMailTarget{client: &testUrMailClient{}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(ctx, []string{"ur", "id", "group-create", "team", "--private"}); code != urExitOk || len(target.client.groups) != 0 {
		t.Fatalf("a no created a group: exit %d", code)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(ctx, []string{"ur", "id", "group-create", "team", "--private"}); code != urExitOk || strings.Join(target.client.groups, ",") != "team" {
		t.Fatalf("a yes: exit %d: %s", code, stdout.String())
	}
	member := sidecar.NewId()
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(ctx, []string{"ur", "id", "group-add", "team", member.String()}); code != urExitOk || strings.Join(target.client.members, ",") != "team "+member.String() {
		t.Fatalf("group-add: exit %d, %v", code, target.client.members)
	}
	for _, method := range urIdMethods(target) {
		switch method.Name {
		case urMethodIdGroupCreate, urMethodIdGroupAdd:
			if !method.Confirm {
				t.Errorf("%s runs unconfirmed", method.Name)
			}
		default:
			if method.Confirm {
				t.Errorf("%s asks a confirmation it does not need", method.Name)
			}
		}
	}
}

// enable turns mail on through its method, and status prints the receiver's state and §15.6's prompt while it holds.
func TestUrMailEnableAndStatus(t *testing.T) {
	approvalId := sidecar.NewId()
	client := &testUrMailClient{status: &sidecar.MailClientStatus{
		Enabled:  true,
		Network:  &sidecar.MailNetworkStatus{Enabled: true},
		Receiver: sidecar.MailClientReceiverStatus{Running: true, ApprovalId: &approvalId},
		Prompt:   sidecar.MailIndexerPrompt,
	}}
	target := &testUrMailTarget{client: client}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	if code := cli.main(ctx, []string{"ur", "mail", "enable"}); code != urExitOk || client.enables != 1 {
		t.Fatalf("enable: exit %d", code)
	}
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "mail", "status"}); code != urExitOk {
		t.Fatalf("status: exit %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "mail:       on") || !strings.Contains(out, "ur approve "+approvalId.String()) || !strings.Contains(out, sidecar.MailIndexerPrompt) {
		t.Fatalf("status printed %q", out)
	}
}

// A target that runs no mail serves none of the id or mail methods.
func TestUrIdMethodsNeedATargetWithMail(t *testing.T) {
	if methods := urIdMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Errorf("%d id methods on a target with no mail", len(methods))
	}
	if methods := urMailMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Errorf("%d mail methods on a target with no mail", len(methods))
	}
	if methods := urIdMethods(&testUrMailTarget{client: &testUrMailClient{}}); len(methods) != 5 {
		t.Errorf("%d id methods", len(methods))
	}
}
