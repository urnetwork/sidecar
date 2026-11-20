//go:build !sidecar_http && !js && !ios_extension

// Bounce addresses under strict mode (mail_bounce.go's strict row; QD-1129): the envelope sender of a From in a custom
// domain GET /mail/status names in strict mode is the mailbox's own bounce under b.<domain>, its record in the
// network's mailcfg; a From the set does not name, the network's own zones, a custom domain that is not strict and a
// subdomain of a strict one alike, keeps b.<net>.<root>; the set is read at each call, so a domain whose MX host is
// unmapped between two reads moves back, and a From under the root never reads it; a read that fails holds a custom
// domain's send and nothing else; and another device's reader keeps the record and resolves a DSN's RCPT there to the
// mailbox. Every name is synthetic.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The world's network's bounce zone, and the custom domains of these tests.
const (
	testMailBounceNetworkZone = "b.acme.root.example"
	testMailBounceDomain      = "brand.example"
	testMailBounceSubdomain   = "mail.brand.example"
)

// GET /mail/status as the world's api answers it, its strict domains and a failure as a test sets them, each read
// counted.
type mailBounceTestApi struct {
	MailApi

	stateLock     sync.Mutex
	strictDomains []string
	err           error
	readCount     int
}

func (self *mailBounceTestApi) MailStatus(ctx context.Context) (*MailNetworkStatus, error) {
	status, err := self.MailApi.MailStatus(ctx)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readCount += 1
	if self.err != nil {
		return nil, self.err
	}
	status.StrictDomains = append([]string{}, self.strictDomains...)
	return status, nil
}

// Sets the strict domains the next reads name: the set as a strict-mode MX host's mapping or unmapping leaves it.
func (self *mailBounceTestApi) setStrictDomains(strictDomains ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.strictDomains = strictDomains
}

func (self *mailBounceTestApi) setErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
}

func (self *mailBounceTestApi) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// The client world with mail on, its api's status answered by a mailBounceTestApi.
func newMailBounceTestWorld(t *testing.T) (*mailClientTestWorld, *mailBounceTestApi, Id) {
	t.Helper()
	world := newMailClientTestWorld(t)
	mailboxId := world.enable()
	api := &mailBounceTestApi{MailApi: world.api}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Api = api
	world.client.Bind(&copied)
	return world, api, mailboxId
}

// The envelope sender of a From in fromDomain, failing the test on an error.
func testMailBounceSender(t *testing.T, client *MailClient, fromDomain string) string {
	t.Helper()
	address, err := client.BounceSender(context.Background(), fromDomain)
	if err != nil {
		t.Fatalf("from %s: %v", fromDomain, err)
	}
	return address
}

// The domain of an envelope address.
func testMailBounceDomainOf(t *testing.T, address string) string {
	t.Helper()
	local, domain, ok := SplitSmtpEnvelopeAddress(address)
	if !ok || !strings.HasPrefix(local, mailBouncePrefix) {
		t.Fatalf("no bounce address: %q", address)
	}
	return domain
}

func TestMailBounceSenderFollowsTheStrictDomains(t *testing.T) {
	world, api, _ := newMailBounceTestWorld(t)

	// the network's own zones never read the set: no strict domain is under the root
	network := testMailBounceSender(t, world.client, "acme.root.example")
	if testMailBounceDomainOf(t, network) != testMailBounceNetworkZone {
		t.Fatalf("the network's own From: %s", network)
	}
	if burner := testMailBounceSender(t, world.client, "otter-4821.acme.root.example"); burner != network {
		t.Fatalf("a burner's From: %s, not the network's %s", burner, network)
	}
	if recipient, err := world.client.BounceRecipient(context.Background()); err != nil || recipient != network {
		t.Fatalf("the mailbox's bounce address %s, %v", recipient, err)
	}
	if api.reads() != 0 {
		t.Fatalf("%d reads of the set for Froms under the root", api.reads())
	}

	// a custom domain that is not strict keeps the network's envelope, as the edge's gate gives it
	if custom := testMailBounceSender(t, world.client, testMailBounceDomain); custom != network {
		t.Fatalf("a custom domain not in strict mode: %s", custom)
	}
	if api.reads() != 1 {
		t.Fatalf("%d reads", api.reads())
	}

	// a strict domain takes a bounce of its own, under a token of its own, kept for the next send
	api.setStrictDomains(testMailBounceDomain)
	strict := testMailBounceSender(t, world.client, testMailBounceDomain)
	if testMailBounceDomainOf(t, strict) != "b."+testMailBounceDomain {
		t.Fatalf("a strict domain's envelope: %s", strict)
	}
	networkLocal, _, _ := SplitSmtpEnvelopeAddress(network)
	strictLocal, _, _ := SplitSmtpEnvelopeAddress(strict)
	if strictLocal == networkLocal {
		t.Fatal("the strict domain's bounce shares the network's token")
	}
	if again := testMailBounceSender(t, world.client, "Brand.Example."); again != strict {
		t.Fatalf("a second send, its From spelled in capitals and with a final dot: %s", again)
	}
	if recipient, err := world.client.BounceRecipient(context.Background()); err != nil || recipient != network {
		t.Fatalf("the DSN filing address moved: %s, %v", recipient, err)
	}

	// a subdomain of a strict domain is not strict unless the set names it: the edge matches exactly
	if sub := testMailBounceSender(t, world.client, testMailBounceSubdomain); sub != network {
		t.Fatalf("a subdomain the set does not name: %s", sub)
	}
	api.setStrictDomains(testMailBounceDomain, testMailBounceSubdomain)
	sub := testMailBounceSender(t, world.client, testMailBounceSubdomain)
	if testMailBounceDomainOf(t, sub) != "b."+testMailBounceSubdomain || sub == strict {
		t.Fatalf("a subdomain the set names: %s", sub)
	}

	// the MX host unmapped between two reads: the next read keeps the network's envelope, and mapping it again finds
	// the domain's record as it was
	api.setStrictDomains()
	if unmapped := testMailBounceSender(t, world.client, testMailBounceDomain); unmapped != network {
		t.Fatalf("after the unmapping: %s", unmapped)
	}
	api.setStrictDomains(testMailBounceDomain)
	if mapped := testMailBounceSender(t, world.client, testMailBounceDomain); mapped != strict {
		t.Fatalf("after mapping it again: %s, not %s", mapped, strict)
	}
}

// A set that cannot be read holds a custom domain's send, whatever it might say, and nothing under the root.
func TestMailBounceSenderHoldsACustomDomainWhenTheSetIsNotRead(t *testing.T) {
	world, api, _ := newMailBounceTestWorld(t)
	refused := errors.New("the api is down")
	api.setErr(refused)
	if address, err := world.client.BounceSender(context.Background(), testMailBounceDomain); !errors.Is(err, refused) || address != "" {
		t.Fatalf("a custom domain's envelope with no set: %q, %v", address, err)
	}
	if network := testMailBounceSender(t, world.client, "acme.root.example"); testMailBounceDomainOf(t, network) != testMailBounceNetworkZone {
		t.Fatalf("the network's own From: %s", network)
	}

	// a binding with no api reads no set: refused for a custom domain
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Api = nil
	world.client.Bind(&copied)
	if _, err := world.client.BounceSender(context.Background(), testMailBounceDomain); !errors.Is(err, ErrMailUnbound) {
		t.Fatalf("no api: %v", err)
	}
}

// A DSN's RCPT at a strict domain's bounce resolves to the sending mailbox, as the record stands in the network's
// mailcfg: at this device's reader and at another device's, whose Sync keeps the record. An unknown token there is
// unknown, as anywhere.
func TestMailBounceCustomRecordResolvesAtTheReceiver(t *testing.T) {
	world, api, mailboxId := newMailBounceTestWorld(t)
	api.setStrictDomains(testMailBounceDomain)
	strict := testMailBounceSender(t, world.client, testMailBounceDomain)
	ctx := context.Background()

	resolve := func(client *MailClient, address string) *MailAddressLookup {
		t.Helper()
		recipient, ok := MailReceiverRecipient(testMailIngestRoot, address)
		if !ok {
			t.Fatalf("%q is no recipient", address)
		}
		config, err := client.syncedConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		lookup, err := config.Resolve(ctx, recipient)
		if err != nil {
			t.Fatal(err)
		}
		return lookup
	}
	for _, address := range []string{strict, strings.ToUpper(strict)} {
		lookup := resolve(world.client, address)
		if !lookup.Known || lookup.MailboxRepoId != mailboxId || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE || lookup.Address != strict {
			t.Fatalf("%q resolves to %+v", address, lookup)
		}
	}
	if lookup := resolve(world.client, "bounces+unknowntoken@b."+testMailBounceDomain); lookup.Known {
		t.Fatalf("an unknown token resolves: %+v", lookup)
	}

	// another device of the network reads the repo from the start and keeps the record
	other := world.newClient()
	if lookup := resolve(other, strict); !lookup.Known || lookup.MailboxRepoId != mailboxId {
		t.Fatalf("another reader resolves %+v", lookup)
	}
	config, err := other.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if address, ok := mailBounceAddressOf(config, mailboxId, "b."+testMailBounceDomain); !ok || address != strict {
		t.Fatalf("another reader's bounce under the domain: %q, %t", address, ok)
	}
}

// The records a strict domain's bounce takes: in a network's own mailcfg alone, never a scope's, and never under the
// root, whose bounce zones are the network's.
func TestMailBounceCustomRecordNames(t *testing.T) {
	zone := MailZone{Root: testMailIngestRoot, Net: "acme"}
	address := MailBounceCustomAddress(testMailBounceDomain, "abc123")
	if name, ok := mailConfigAddressName(zone, address); !ok || name.key != address || name.alias != "bounces+abc123" {
		t.Fatalf("the network's mailcfg: %+v, %t", name, ok)
	}
	if _, ok := mailConfigAddressName(MailZone{Root: testMailIngestRoot, Net: "acme", Scope: "ops"}, address); ok {
		t.Fatal("a scope's mailcfg names a custom domain's bounce")
	}
	if _, ok := mailConfigAddressName(zone, strings.ToUpper(address)); ok {
		t.Fatal("a name spelled otherwise than its address")
	}

	world, _, mailboxId := newMailBounceTestWorld(t)
	config, err := world.client.syncedConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"acme.root.example", "root.example", "example", "brand..example"} {
		if _, err := config.CreateCustomBounceAddress(context.Background(), mailboxId, "abc123", domain); !errors.Is(err, ErrMailConfigInvalid) {
			t.Errorf("%q: %v", domain, err)
		}
	}
}
