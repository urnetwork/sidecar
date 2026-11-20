//go:build !sidecar_http && !js

// §14.6's Team custom domains on the sender's side (SMTP-M9-34, D-SMTP-15, D-SMTP-5): a custom domain gets selectors
// of its own, published naming it; a send signs under the From's domain or fails (Z5's literal d=); and at a
// receiver's checker (MAIL-M7-08's, on FakeMailZone), with the customer's _dmarc at adkim=s, the network's selector
// passes DMARC on strict DKIM alignment alone while another network's passes nothing for the domain. The receiver
// finds a selector at <sel>._domainkey.<domain>, which the customer's delegated _domainkey (§12's dns answering from
// the network's own key rows, dnsservice.DelegatedZones) or a per-selector CNAME makes of the record the server
// wrote at <sel>._domainkey.<net>.<root>; the fixture publishes that answer. Every name, key and address is
// synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fixture's names: a Team network n1 and its verified domain, another network of the same root, and n1's
// envelope domain.
const (
	testCustomDomainName     = "brand.example"
	testCustomDomainNetwork  = "n1.root.example"
	testCustomDomainOther    = "n2.root.example"
	testCustomDomainEnvelope = "b." + testCustomDomainNetwork
	// what the customer publishes at _dmarc.<domain> (§14.6: adkim=s)
	testCustomDomainPolicy = "v=DMARC1; p=reject; adkim=s; aspf=s"
)

// When the fixture's signatures are made: mox, whose verifier the checker links, reads x= against the wall clock, so
// the time is past any run's, as mail_burner_reply_dmarc_test.go's is.
var testCustomDomainSignTime = time.Date(2200, time.January, 1, 0, 0, 0, 0, time.UTC)

// One sidecar's keychain namespace, in memory.
type testCustomDomainSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func (self *testCustomDomainSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testCustomDomainSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *testCustomDomainSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testCustomDomainSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.values {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

// POST /smtp/dkim-keys as the server answers a network's publishes: each kept with its domain and key.
type testCustomDomainPublisher struct {
	stateLock sync.Mutex
	published []*sidecar.SmtpDkimKeyPublish
}

func (self *testCustomDomainPublisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	result := &sidecar.SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		self.published = append(self.published, publish)
		result.Published = append(result.Published, publish.Selector)
	}
	for _, retire := range args.Retire {
		result.Retired = append(result.Retired, retire.Selector)
	}
	return result, nil
}

// The key record of a selector as the server writes it (RFC 6376 §3.6.1).
func (self *testCustomDomainPublisher) record(t *testing.T, selector string) string {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, publish := range self.published {
		if publish.Selector == selector {
			return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publish.PublicKey)
		}
	}
	t.Fatalf("selector %s was never published", selector)
	return ""
}

// One sending sidecar's DKIM keys.
func newTestCustomDomainKeys() (*sidecar.SmtpDkimKeys, *testCustomDomainPublisher) {
	publisher := &testCustomDomainPublisher{}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	keys := sidecar.NewSmtpDkimKeys(&testCustomDomainSecrets{values: map[string][]byte{}}, publisher, sidecar.DefaultSmtpSenderSettings(), clock, nil)
	return keys, publisher
}

// A message From the custom domain, as MAIL hands it over.
func testCustomDomainDraft() []byte {
	return []byte(strings.Join([]string{
		"From: Brand <news@" + testCustomDomainName + ">",
		"To: Customer <someone@shop.example>",
		"Subject: The spring catalog",
		"Date: Sun, 08 Nov 2026 12:03:41 +0000",
		"Message-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@" + testCustomDomainName + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"The catalog is out.",
		"",
	}, "\r\n"))
}

// The draft assembled for fromDomain and signed by signer, as §14's sender does after the preamble's OK.
func testCustomDomainSigned(t *testing.T, signer sidecar.SmtpDkimSigner) ([]byte, error) {
	t.Helper()
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
		Message:          testCustomDomainDraft(),
		HeaderFromDomain: testCustomDomainName,
		MessageIdDomain:  testCustomDomainName,
		Now:              testCustomDomainSignTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
		Signer: signer,
		Issued: &sidecar.SmtpIssuedHeaders{
			XUrRef:     "1.ljnfuws2ljnfuws2ljnfuws2ljnfuws2li",
			FeedbackId: "n:t:gmztgmztgmztgmztgmztgmztgm:urnetwork",
		},
		SignTime:      testCustomDomainSignTime,
		ExpireTimeout: sidecar.DefaultSmtpSenderSettings().DkimExpireTimeout,
	})
}

// A receiver's world in which the customer publishes its strict policy, the network SPF for its envelope domain, and
// selectors answer under the custom domain as the customer's delegation or CNAMEs make them.
func newTestCustomDomainWorld(t *testing.T, answered map[string]string) *mailAuthCheckWorld {
	t.Helper()
	world := newMailAuthCheckWorld(t)
	world.zone.AddTxt("_dmarc."+testCustomDomainName, testCustomDomainPolicy)
	world.zone.AddTxt(testCustomDomainEnvelope, "v=spf1 ip4:192.0.2.0/24 -all")
	for selector, record := range answered {
		world.zone.AddTxt(sidecartest.MailDkimKeyName(selector, testCustomDomainName), record)
	}
	return world
}

// A custom domain gets selectors of its own, apart from the network's, each published naming its domain, and a
// second send keeps the first's.
func TestSmtpCustomDomainSelectorIsTheDomainsOwn(t *testing.T) {
	keys, publisher := newTestCustomDomainKeys()
	ctx := context.Background()
	custom, err := keys.Current(ctx, testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Release()
	network, err := keys.Current(ctx, testCustomDomainNetwork)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Release()
	if custom.Selector == network.Selector || bytes.Equal(custom.PublicKey, network.PublicKey) {
		t.Fatal("the custom domain shares the network's selector or key")
	}
	if custom.DkimDomain() != testCustomDomainName || network.DkimDomain() != testCustomDomainNetwork {
		t.Fatalf("domains %s and %s", custom.DkimDomain(), network.DkimDomain())
	}
	published := map[string]string{}
	for _, publish := range publisher.published {
		published[publish.Selector] = publish.Domain
		if _, err := x509.ParsePKIXPublicKey(publish.PublicKey); err != nil {
			t.Errorf("a published key: %v", err)
		}
	}
	if len(published) != 2 || published[custom.Selector] != testCustomDomainName || published[network.Selector] != testCustomDomainNetwork {
		t.Fatalf("published %v", published)
	}
	again, err := keys.Current(ctx, testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Release()
	if again.Selector != custom.Selector || len(publisher.published) != 2 {
		t.Fatalf("a second send took %s after %d publishes", again.Selector, len(publisher.published))
	}
}

// Z5's literal d= is header_from_domain: a custom-domain send signs under that domain, its fixed signature naming it
// with the domain's own selector, or fails, under the network's selector as under any other.
func TestSmtpCustomDomainSignsUnderTheFromsDomainOrFails(t *testing.T) {
	keys, _ := newTestCustomDomainKeys()
	ctx := context.Background()
	custom, err := keys.Current(ctx, testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Release()
	signed, err := testCustomDomainSigned(t, custom)
	if err != nil {
		t.Fatal(err)
	}
	fixed := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=" +
		testCustomDomainName + "; s=" + custom.Selector + ";"
	if bytes.Count(signed, []byte(fixed)) != 1 {
		t.Fatalf("no fixed signature under the custom domain's selector: %s", signed)
	}
	network, err := keys.Current(ctx, testCustomDomainNetwork)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Release()
	if _, err := testCustomDomainSigned(t, network); err == nil {
		t.Fatal("the network's selector signed a message From its custom domain")
	}
}

// The network's selector passes DMARC at the customer's adkim=s on DKIM alone: d= aligns exactly, and SPF, passing
// for the envelope domain b.<net>.<root>, aligns nothing.
func TestSmtpCustomDomainPassesStrictDmarcUnderItsSelector(t *testing.T) {
	keys, publisher := newTestCustomDomainKeys()
	custom, err := keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Release()
	signed, err := testCustomDomainSigned(t, custom)
	if err != nil {
		t.Fatal(err)
	}
	world := newTestCustomDomainWorld(t, map[string]string{custom.Selector: publisher.record(t, custom.Selector)})
	outcome := world.check(t, testMailAuthInput(signed, testCustomDomainEnvelope))
	if outcome.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || outcome.Spf.GetDomain() != testCustomDomainEnvelope {
		t.Errorf("spf %v", outcome.Spf)
	}
	if len(outcome.Dkim) == 0 {
		t.Fatal("no signature was checked")
	}
	for _, result := range outcome.Dkim {
		if result.GetResult() != protocol.DkimVerdict_DKIM_PASS || result.GetDomain() != testCustomDomainName || result.GetSelector() != custom.Selector {
			t.Errorf("dkim %v", result)
		}
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetAdkim() != "s" ||
		outcome.Dmarc.GetAlignment() != sidecar.MailDmarcAlignedDkim {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
}

// Another network's selector passes nothing for the custom domain: its own selector for the domain has no key there,
// since the domain's delegation answers only the network that verified it and its CNAMEs name only that network's
// selectors; a key of its own under the domain's selector name does not verify; and signing under its own domain
// aligns only under rules the customer's adkim=s refuses.
func TestSmtpCustomDomainOtherNetworksSelectorFailsStrictDmarc(t *testing.T) {
	keys, publisher := newTestCustomDomainKeys()
	custom, err := keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.Release()
	world := newTestCustomDomainWorld(t, map[string]string{custom.Selector: publisher.record(t, custom.Selector)})
	// the other network's sidecar, with keys of its own for the domain, which its server write never puts under it
	otherKeys, _ := newTestCustomDomainKeys()
	other, err := otherKeys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	signed, err := testCustomDomainSigned(t, other)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(signed, "b."+testCustomDomainOther))
	for _, result := range outcome.Dkim {
		if result.GetResult() == protocol.DkimVerdict_DKIM_PASS {
			t.Errorf("its own selector under the domain: dkim %v", result)
		}
	}
	if outcome.Dmarc.GetResult() == protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetAlignment() != 0 {
		t.Errorf("its own selector under the domain: dmarc %v", outcome.Dmarc)
	}

	otherKey := sidecartest.MailDkimRsaKey(2048)
	forged := testCustomDomainDraft()
	cases := []struct {
		name     string
		domain   string
		selector string
		dkim     protocol.DkimVerdict
	}{
		// the network's selector name under the domain, where the network's key stands
		{name: "the network's selector", domain: testCustomDomainName, selector: custom.Selector, dkim: protocol.DkimVerdict_DKIM_FAIL},
		// its own domain and selector, published: a pass that aligns with nothing of brand.example's
		{name: "its own domain", domain: testCustomDomainOther, selector: "bbbbbbbbbbbbbbbbbbbbbbbbba", dkim: protocol.DkimVerdict_DKIM_PASS},
	}
	for _, c := range cases {
		signer, err := sidecartest.NewMailDkimSigner(c.domain, c.selector, sidecartest.MailDkimRsaSha256, otherKey)
		if err != nil {
			t.Fatal(err)
		}
		if c.domain == testCustomDomainOther {
			world.zone.AddTxt(sidecartest.MailDkimKeyName(c.selector, c.domain), signer.KeyRecord())
		}
		message, err := signer.Sign(forged)
		if err != nil {
			t.Fatal(err)
		}
		outcome := world.check(t, testMailAuthInput(message, "b."+testCustomDomainOther))
		if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != c.dkim {
			t.Errorf("%s: dkim %v", c.name, outcome.Dkim)
		}
		if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_FAIL || outcome.Dmarc.GetAlignment() != 0 {
			t.Errorf("%s: dmarc %v", c.name, outcome.Dmarc)
		}
	}
}

func TestSmtpEnvelopeDomain(t *testing.T) {
	cases := []struct {
		networkDomain string
		strict        string
		want          string
	}{
		{networkDomain: testCustomDomainNetwork, want: testCustomDomainEnvelope},
		{networkDomain: "N1.Root.Example.", want: testCustomDomainEnvelope},
		{networkDomain: testCustomDomainNetwork, strict: testCustomDomainName, want: "b." + testCustomDomainName},
		{networkDomain: testCustomDomainNetwork, strict: "Brand.Example.", want: "b." + testCustomDomainName},
	}
	for _, c := range cases {
		if got := sidecar.SmtpEnvelopeDomain(c.networkDomain, c.strict); got != c.want {
			t.Errorf("%q, %q: %q, want %q", c.networkDomain, c.strict, got, c.want)
		}
	}
}
