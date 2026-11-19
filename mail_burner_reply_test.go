//go:build !sidecar_http && !js && !ios_extension

// MAIL-M9-03's replies on MAIL-M7-18's send world: a reply from a live burner queues under the gate's key with flag
// BURNER, From and Message-ID under its <blabel>, its Date at UTC minute precision, and marks the burner replying; a
// paused, burned or unknown burner sends nothing; a burn retires this device's selectors for the label, and a device
// that reads a burn another made retires its own.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A device's selectors, recording each domain retired.
type testMailBurnerSelectors struct {
	stateLock sync.Mutex
	domains   []string
	err       error
}

func (self *testMailBurnerSelectors) Retire(ctx context.Context, domain string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.domains = append(self.domains, domain)
	return nil
}

func (self *testMailBurnerSelectors) retired() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.domains)
}

// The send world's parts with the burner world's vault, so a burn marks its vault entries as MAIL-M8-01's does.
type testMailBurnerReplyParts struct {
	*mailSendTestParts
	vaultParts *mailBurnerTestParts
}

func (self *testMailBurnerReplyParts) vault(mailboxId Id, ownerMemberId Id, args *MailVaultArgs) *MailVault {
	return self.vaultParts.vault(mailboxId, ownerMemberId, args)
}

// The send world with one live burner of the member's, its selectors bound: the burner's label.
func newTestMailBurnerReplyWorld(t *testing.T) (*mailClientTestWorld, *testMailBurnerSelectors, *testMailOutboxSigner, string) {
	t.Helper()
	world, parts, mailboxId := newMailSendTestWorld(t)
	world.client.stateLock.Lock()
	world.client.partsOverride = &testMailBurnerReplyParts{
		mailSendTestParts: parts,
		vaultParts: &mailBurnerTestParts{
			mailClientTestParts: parts.mailClientTestParts,
			vaultStore:          &mailBurnerTestVaultStore{mailVaultTestStore: newMailVaultTestStore()},
			authority:           newMailVaultTestAuthority(world.device, world.member),
			clock:               world.client.clock,
		},
	}
	world.client.stateLock.Unlock()
	// the mail component's keychain namespace, which a forward's reverse alias key is kept in
	world.client.secrets = &testMailSecrets{}
	ctx := context.Background()
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: mailboxId})
	if err != nil {
		t.Fatal(err)
	}
	selectors := &testMailBurnerSelectors{}
	signer := newTestMailOutboxSigner(world.device)
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.BurnerSelectors = selectors
	copied.Sign = signer.sign
	world.client.Bind(&copied)
	return world, selectors, signer, info.Label
}

// A reply from a live burner goes through the gate and queues with flag BURNER, its From and its Message-ID under the
// label's domain, its Date at UTC minute precision and no client field; the burner reads replying.
func TestMailBurnerReplyQueuesUnderItsLabel(t *testing.T) {
	world, _, signer, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	domain := label + ".acme.root.example"
	result, err := world.client.Reply(ctx, &MailReplyArgs{
		From: "shop@" + domain, To: []string{"orders@store.example"}, Subject: "Re: your order", Text: "Thanks.",
		InReplyTo: "order-77@store.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendQueued || len(result.EffectKey) == 0 {
		t.Fatalf("the reply %+v", result)
	}
	file := testMailSendOutbox(t, world)[string(result.EffectKey)]
	if file == nil {
		t.Fatal("no entry under the reply's key")
	}
	verified, err := VerifySmtpOutboxEntry(file, func(sidecarId Id) ed25519.PublicKey {
		if sidecarId == world.device {
			return signer.publicKey()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Message.Flags&SmtpFlagBurner == 0 {
		t.Fatal("the entry carries no BURNER flag")
	}
	message := string(file.Message)
	for _, want := range []string{
		"From: shop@" + domain + "\r\n",
		"Message-ID: <" + MailOutboxMessageId(result.SendId, domain) + ">\r\n",
		"In-Reply-To: <order-77@store.example>\r\n",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("no %q in\n%s", want, message)
		}
	}
	dateLine := ""
	for _, line := range strings.Split(message, "\r\n") {
		if strings.HasPrefix(line, "Date: ") {
			dateLine = line
		}
	}
	if !strings.HasSuffix(dateLine, ":00 +0000") {
		t.Fatalf("the date %q is not at UTC minute precision", dateLine)
	}
	burners, err := world.client.Burners(ctx)
	if err != nil || len(burners) != 1 || !burners[0].Replying {
		t.Fatalf("the burner after its reply %+v: %v", burners, err)
	}
}

// A reply from a paused or burned burner, from another member's or from a label no record holds sends nothing.
func TestMailBurnerReplyFromNoLiveBurnerSendsNothing(t *testing.T) {
	world, _, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	domain := label + ".acme.root.example"
	reply := func(from string) error {
		_, err := world.client.Reply(ctx, &MailReplyArgs{From: from, To: []string{"orders@store.example"}, Text: "x"})
		return err
	}
	if err := reply("shop@zebra-0001.acme.root.example"); !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a label no record holds: %v", err)
	}
	if err := reply(testMailSendFrom); !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a member address as a reply's From: %v", err)
	}
	if err := world.client.PauseBurner(ctx, label, true); err != nil {
		t.Fatal(err)
	}
	if err := reply("shop@" + domain); !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a paused burner: %v", err)
	}
	if count := len(testMailSendOutbox(t, world)); count != 0 {
		t.Fatalf("%d entries queued", count)
	}
}

// A burn retires this device's selectors for a replying burner's label; a device reading a burn another made retires
// its own, and one that never replied retires nothing.
func TestMailBurnerBurnRetiresItsSelector(t *testing.T) {
	world, selectors, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	domain := label + ".acme.root.example"
	if _, err := world.client.Reply(ctx, &MailReplyArgs{From: "shop@" + domain, To: []string{"orders@store.example"}, Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := world.client.Burn(ctx, label); err != nil {
		t.Fatal(err)
	}
	if retired := selectors.retired(); !slices.Equal(retired, []string{domain}) {
		t.Fatalf("retired %v", retired)
	}
	// the pass every device runs retires a replying burned label's selectors again, which is no error with none left
	retired, err := world.client.RetireBurnedSelectors(ctx)
	if err != nil || retired != 1 {
		t.Fatalf("the pass retired %d: %v", retired, err)
	}
	burners, err := world.client.Burners(ctx)
	if err != nil || burners[0].State != protocol.MailBurnerState_MAIL_BURNER_BURNED {
		t.Fatalf("burners %+v: %v", burners, err)
	}
}
