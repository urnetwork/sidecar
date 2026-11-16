// ur burner against a fake daemon: create printing the address and the first burner's copy, a creation waiting on a
// person printing ur approve and exiting 1, ls, pause and resume, and burn only after a yes on the terminal through a
// confirmed call.

package main

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A MailClient that makes burners, as a test sets it.
type testUrBurnerClient struct {
	testUrMailClient
	burnerLock sync.Mutex
	sites      []string
	burned     []string
	paused     map[string]bool
	burnerWait *sidecar.Id
}

func (self *testUrBurnerClient) CreateBurner(ctx context.Context, args *sidecar.MailBurnerCreateArgs) (*sidecar.MailBurnerCreated, error) {
	self.burnerLock.Lock()
	defer self.burnerLock.Unlock()
	if self.burnerWait != nil {
		return nil, &sidecar.ApprovalPendingError{ApprovalId: *self.burnerWait}
	}
	self.sites = append(self.sites, args.Site)
	created := &sidecar.MailBurnerCreated{Address: "example@otter-4821.acme.root.example", Label: "otter-4821"}
	if len(self.sites) == 1 {
		created.CoverageCopy = sidecar.MailIndexerPrompt
	}
	return created, nil
}

func (self *testUrBurnerClient) Burn(ctx context.Context, addressOrLabel string) error {
	self.burnerLock.Lock()
	defer self.burnerLock.Unlock()
	self.burned = append(self.burned, addressOrLabel)
	return nil
}

func (self *testUrBurnerClient) PauseBurner(ctx context.Context, addressOrLabel string, paused bool) error {
	self.burnerLock.Lock()
	defer self.burnerLock.Unlock()
	self.paused[addressOrLabel] = paused
	return nil
}

func (self *testUrBurnerClient) Burners(ctx context.Context) ([]*sidecar.MailBurnerInfo, error) {
	return []*sidecar.MailBurnerInfo{{Label: "otter-4821", State: protocol.MailBurnerState_MAIL_BURNER_PAUSED, CreatedMillis: 1794312000000}}, nil
}

// A daemon target whose network's mail makes burners.
type testUrBurnerTarget struct {
	testUrDaemonTarget
	client *testUrBurnerClient
}

func (self *testUrBurnerTarget) mailClient(network string) (urMailClient, error) {
	return self.client, nil
}

// create prints the address and the first burner's copy; a creation waiting on a person prints ur approve and exits
// 1; ls lists; pause and resume reach the client.
func TestUrBurnerCreateListPauseAndResume(t *testing.T) {
	target := &testUrBurnerTarget{client: &testUrBurnerClient{paused: map[string]bool{}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	if code := cli.main(ctx, []string{"ur", "burner", "create", "shop.example.org"}); code != urExitOk ||
		!strings.Contains(stdout.String(), "example@otter-4821.acme.root.example") || !strings.Contains(stdout.String(), sidecar.MailIndexerPrompt) {
		t.Fatalf("create: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "burner", "create", "news.example.org"}); code != urExitOk || strings.Contains(stdout.String(), "note:") {
		t.Fatalf("a second create: exit %d: %s", code, stdout.String())
	}
	approvalId := sidecar.NewId()
	target.client.burnerWait = &approvalId
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "burner", "create", "third.example.org"}); code != urExitFailed || !strings.Contains(stdout.String(), "ur approve "+approvalId.String()) {
		t.Fatalf("a create waiting on a person: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "burner", "ls"}); code != urExitOk || !strings.Contains(stdout.String(), "paused  otter-4821") {
		t.Fatalf("ls: exit %d: %q", code, stdout.String())
	}
	if code := cli.main(ctx, []string{"ur", "burner", "pause", "otter-4821"}); code != urExitOk || !target.client.paused["otter-4821"] {
		t.Fatalf("pause: exit %d", code)
	}
	if code := cli.main(ctx, []string{"ur", "burner", "resume", "otter-4821"}); code != urExitOk || target.client.paused["otter-4821"] {
		t.Fatalf("resume: exit %d", code)
	}
}

// burn runs only after a yes on the terminal, through a Confirm method no unconfirmed call reaches.
func TestUrBurnerBurnIsConfirmedOnTheTerminal(t *testing.T) {
	target := &testUrBurnerTarget{client: &testUrBurnerClient{paused: map[string]bool{}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(ctx, []string{"ur", "burner", "burn", "otter-4821"}); code != urExitOk || len(target.client.burned) != 0 {
		t.Fatalf("a no burned: exit %d", code)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(ctx, []string{"ur", "burner", "burn", "otter-4821"}); code != urExitOk || strings.Join(target.client.burned, ",") != "otter-4821" {
		t.Fatalf("a yes: exit %d", code)
	}
	for _, method := range urBurnerMethods(target) {
		if method.Name == urMethodBurnerBurn && !method.Confirm {
			t.Error("burn is not a Confirm method")
		}
	}
}
