//go:build !sidecar_http && !js && !ios_extension

// The receiver composition's resolver seam (mail_receiver_resolver.go; §15.5, §2.8 ext-3), on its external surface: a
// receiver composed on MailReceiveSettings.ResolverFactory asks that resolver alone, its reception-time checks through
// their stub and mail.strict's chain under the resolver's own anchors; each receiver owns its own resolver and
// releases it once; a factory's refusals leave no receiver; and in this test binary a receiver whose settings name no
// resolver is refused before anything is built, so no test asks the public resolvers production's receivers ask. On
// sidecartest.FakeMailZone, the kit's DKIM signer and sidecartest.MxWorld's signed zones, on one fake clock; every
// name, key and address is synthetic.

package sidecar_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A resolver a test names: the reception-time answers from zone and the DNSSEC-OK ones from signed, either nil for
// none, answering nothing once released, so a receiver still asking it after its release reads no answer.
type testReceiverLookupDoh struct {
	zone   *sidecartest.FakeMailZone
	signed *sidecartest.MxWorld

	stateLock   sync.Mutex
	dnssecCount int
	closed      bool
}

var _ sidecar.MailReceiverDoh = (*testReceiverLookupDoh)(nil)

func (self *testReceiverLookupDoh) released() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

func (self *testReceiverLookupDoh) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	if self.zone == nil || self.released() {
		return nil, false
	}
	return self.zone.Forward(ctx, qType, domain)
}

func (self *testReceiverLookupDoh) ForwardDnssec(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	if self.signed == nil || self.released() {
		return nil, false
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dnssecCount += 1
	}()
	return self.signed.ForwardDnssec(ctx, qType, domain)
}

// The DNSSEC-OK questions asked so far.
func (self *testReceiverLookupDoh) dnssecQuestions() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dnssecCount
}

// A ResolverFactory over zone and signed under anchors, nil taking the DNS root's keys: a resolver of its own at each
// build, each release counted.
type testReceiverLookupResolvers struct {
	zone    *sidecartest.FakeMailZone
	signed  *sidecartest.MxWorld
	anchors *sidecar.SmtpDnssecAnchors

	stateLock     sync.Mutex
	built         []*testReceiverLookupDoh
	releaseCounts []int
}

func (self *testReceiverLookupResolvers) factory() (*sidecar.MailReceiverResolver, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	doh := &testReceiverLookupDoh{zone: self.zone, signed: self.signed}
	index := len(self.built)
	self.built = append(self.built, doh)
	self.releaseCounts = append(self.releaseCounts, 0)
	return &sidecar.MailReceiverResolver{
		Doh:     doh,
		Anchors: self.anchors,
		Close: func() {
			doh.stateLock.Lock()
			doh.closed = true
			doh.stateLock.Unlock()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.releaseCounts[index] += 1
		},
	}, nil
}

// The resolvers built so far, and how many times each was released.
func (self *testReceiverLookupResolvers) snapshot() ([]*testReceiverLookupDoh, []int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.built), slices.Clone(self.releaseCounts)
}

// A receiver's settings naming factory.
func testReceiverLookupSettings(factory func() (*sidecar.MailReceiverResolver, error)) *sidecar.MailReceiveSettings {
	settings := sidecar.DefaultMailSettings().Receive
	settings.ResolverFactory = factory
	return settings
}

// A signed world on clock, under its own root: the zone view's root and a customer whose signed zone lists one MX host,
// whose TLSA holds testMailWatchSpki.
func newTestReceiverSignedWorld(t *testing.T, clock *sidecartest.FakeClock) *sidecartest.MxWorld {
	t.Helper()
	settings := sidecartest.DefaultMxWorldSettings()
	settings.Clock = clock
	world, err := sidecartest.NewMxWorld(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{testMailWatchRoot, "customer.example."} {
		if err := world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.SetMx("customer.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.customer.example"}); err != nil {
		t.Fatal(err)
	}
	tlsa := &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: testMailWatchSpki}
	if err := world.AddMx("mx.customer.example", netip.MustParseAddr("192.0.2.25"), nil, tlsa); err != nil {
		t.Fatal(err)
	}
	return world
}

// A receiver composed on a ResolverFactory checks a message against that resolver alone: SPF, the DKIM key, DMARC and
// the PTR all pass from the fake zone, which knows names no public resolver does, and every name the checks need was
// asked of it. One resolver was built, and the receiver's release releases it once.
func TestMailReceiverChecksAskTheResolverItsSettingsName(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	signer, err := sidecartest.NewMailDkimSigner("sender.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "sender.example"), signer.KeyRecord())
	message, err := signer.Sign(testMailAuthMessage("sender.example", "seam"))
	if err != nil {
		t.Fatal(err)
	}
	resolvers := &testReceiverLookupResolvers{zone: world.zone}
	checker, _, release, err := sidecar.MailReceiverLookupsForTest(testReceiverLookupSettings(resolvers.factory), world.clock)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := checker.Check(context.Background(), testMailAuthInput(message, "sender.example"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || outcome.Spf.GetDomain() != "sender.example" {
		t.Errorf("spf %v", outcome.Spf)
	}
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_PASS || outcome.Dkim[0].GetSelector() != "s1" {
		t.Errorf("dkim %v", outcome.Dkim)
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetP() != "reject" {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
	if outcome.PtrName != "mail.sender.example" || !outcome.SniTlsaLive || outcome.Limits != nil {
		t.Errorf("ptr %q, tlsa %t, limits %v", outcome.PtrName, outcome.SniTlsaLive, outcome.Limits)
	}
	type question struct {
		name  string
		qType dnsmessage.Type
	}
	asked := map[question]bool{}
	for _, query := range world.zone.Queries() {
		asked[question{name: query.Name, qType: query.Type}] = true
	}
	for _, want := range []question{
		{name: "sender.example", qType: dnsmessage.TypeTXT},
		{name: "_dmarc.sender.example", qType: dnsmessage.TypeTXT},
		{name: "s1._domainkey.sender.example", qType: dnsmessage.TypeTXT},
		{name: sidecartest.MailZoneReverseName(netip.MustParseAddr(testMailAuthSender)), qType: dnsmessage.TypePTR},
		{name: "mail.sender.example", qType: dnsmessage.TypeA},
		{name: "_25._tcp." + testMailAuthSni, qType: sidecartest.MailZoneTypeTlsa},
	} {
		if !asked[want] {
			t.Errorf("the resolver was not asked %s %v; it was asked %v", want.name, want.qType, asked)
		}
	}
	built, releases := resolvers.snapshot()
	if len(built) != 1 || releases[0] != 0 {
		t.Fatalf("%d resolvers built, released %v, before the receiver ended", len(built), releases)
	}
	release()
	if _, releases := resolvers.snapshot(); releases[0] != 1 {
		t.Errorf("the receiver's release released its resolver %d times", releases[0])
	}
}

// mail.strict's chain, where no zone watch holds it, validates the resolver's DNSSEC-OK answers to the resolver's own
// anchors: a customer-signed chain under a world's own root holds there, and the same chain under a resolver that names
// no anchors, so under the DNS root's keys, which sign no path to that world, does not, though its questions went to
// the same signed zones.
func TestMailReceiverStrictChainValidatesUnderTheResolversAnchors(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	signed := newTestReceiverSignedWorld(t, clock)
	anchors, err := sidecar.NewSmtpDnssecAnchors(signed.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	chain := func(resolvers *testReceiverLookupResolvers) (bool, int) {
		t.Helper()
		_, strictChain, release, err := sidecar.MailReceiverLookupsForTest(testReceiverLookupSettings(resolvers.factory), clock)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		holds := strictChain(ctx, testMailWatchRoot, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki)
		built, _ := resolvers.snapshot()
		return holds, built[0].dnssecQuestions()
	}
	if holds, questions := chain(&testReceiverLookupResolvers{signed: signed, anchors: anchors}); !holds || questions == 0 {
		t.Errorf("under the world's own anchors the chain holds %t after %d questions", holds, questions)
	}
	if holds, questions := chain(&testReceiverLookupResolvers{signed: signed}); holds || questions == 0 {
		t.Errorf("under the DNS root's keys the chain holds %t after %d questions", holds, questions)
	}
}

// Two receivers composed on the same settings each build a resolver of their own (CODESTYLE's DoH rule), and ending one
// releases its own alone: the other's checks still answer from its resolver.
func TestMailReceiversEachOwnTheirResolver(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	resolvers := &testReceiverLookupResolvers{zone: world.zone}
	settings := testReceiverLookupSettings(resolvers.factory)
	_, _, releaseFirst, err := sidecar.MailReceiverLookupsForTest(settings, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	second, _, releaseSecond, err := sidecar.MailReceiverLookupsForTest(settings, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	built, releases := resolvers.snapshot()
	if len(built) != 2 || built[0] == built[1] {
		t.Fatalf("two receivers built %d resolvers", len(built))
	}
	releaseFirst()
	outcome, err := second.Check(context.Background(), testMailAuthInput(testMailAuthMessage("sender.example", "second"), "sender.example"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || outcome.PtrName != "mail.sender.example" {
		t.Errorf("the second receiver's checks after the first's release: spf %v, ptr %q", outcome.Spf, outcome.PtrName)
	}
	if _, releases = resolvers.snapshot(); releases[0] != 1 || releases[1] != 0 {
		t.Errorf("after the first receiver ended, releases %v", releases)
	}
	releaseSecond()
	if _, releases = resolvers.snapshot(); releases[0] != 1 || releases[1] != 1 {
		t.Errorf("after both ended, releases %v", releases)
	}
}

// In a test binary, a receiver whose settings name no resolver is refused, with no check, chain or release built: the
// default asks connect's public resolvers, and a test sends nothing off the machine. The defaults name none.
func TestMailReceiverInATestRefusesThePublicResolvers(t *testing.T) {
	settings := sidecar.DefaultMailSettings().Receive
	if settings.ResolverFactory != nil {
		t.Fatal("the receive defaults name a resolver of their own")
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	checker, chain, release, err := sidecar.MailReceiverLookupsForTest(settings, clock)
	if !errors.Is(err, sidecar.ErrMailReceiverPublicResolver) || checker != nil || chain != nil || release != nil {
		t.Fatalf("a receiver on the default resolvers in a test: %v", err)
	}
}

// A factory's error comes back as it was given, and a factory answering no resolver, or one without its Doh, leaves the
// receiver unbuilt, the latter released first.
func TestMailReceiverResolverFactoryRefusals(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	refused := errors.New("the test's DNS is not up")
	if _, _, _, err := sidecar.MailReceiverLookupsForTest(testReceiverLookupSettings(func() (*sidecar.MailReceiverResolver, error) {
		return nil, refused
	}), clock); !errors.Is(err, refused) {
		t.Errorf("a factory's error came back as %v", err)
	}
	if _, _, _, err := sidecar.MailReceiverLookupsForTest(testReceiverLookupSettings(func() (*sidecar.MailReceiverResolver, error) {
		return nil, nil
	}), clock); !errors.Is(err, sidecar.ErrMailReceiverInvalid) {
		t.Errorf("no resolver: %v", err)
	}
	releases := 0
	if _, _, _, err := sidecar.MailReceiverLookupsForTest(testReceiverLookupSettings(func() (*sidecar.MailReceiverResolver, error) {
		return &sidecar.MailReceiverResolver{Close: func() { releases += 1 }}, nil
	}), clock); !errors.Is(err, sidecar.ErrMailReceiverInvalid) || releases != 1 {
		t.Errorf("a resolver without its Doh: %v, released %d times", err, releases)
	}
}
