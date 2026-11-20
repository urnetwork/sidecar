//go:build !sidecar_http && !js && !ios_extension

// QD-1130's gate on a Team custom domain's selectors (smtp_dkim_answer.go), over the device DoH's fake
// (sidecartest.FakeMailZone): under CNAME mode a domain's first selector holds the send as deferred and a rotation
// keeps signing under the old selector until the domain answers the new one, then retires the old one alone; under a
// delegated _domainkey the answer comes at once and the selector moves at once; URnetwork's own domains wait on
// nothing; only a key record holding the selector's key is an answer; the lookup ends at its timeout; an awaiting
// selector outlives a restart; and through the sender, a first send from the domain is deferred, then sent signed
// under the selector once the domain answers. The fake answers TXT at <sel>._domainkey.<domain> where a resolver
// would after following the customer's CNAME, or from the delegated zone; one test follows a CNAME chain on the
// wire. Every name, key and address is synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fixture's dns root, under which the network and its burners sit; testCustomDomainName is outside it.
const testDkimAnswerRoot = "root.example"

// POST /smtp/dkim-keys answering every call, each one kept, and onPublish run for each new selector it publishes,
// as dns answering a delegated _domainkey from the row the publish writes.
type testDkimAnswerPublisher struct {
	stateLock sync.Mutex
	calls     []*sidecar.SmtpDkimKeysArgs
	keys      map[string][]byte
	onPublish func(publish *sidecar.SmtpDkimKeyPublish)
}

func newTestDkimAnswerPublisher() *testDkimAnswerPublisher {
	return &testDkimAnswerPublisher{keys: map[string][]byte{}}
}

func (self *testDkimAnswerPublisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{}
	fresh := []*sidecar.SmtpDkimKeyPublish{}
	var onPublish func(publish *sidecar.SmtpDkimKeyPublish)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, args)
		for _, publish := range args.Publish {
			if _, ok := self.keys[publish.Selector]; !ok {
				self.keys[publish.Selector] = bytes.Clone(publish.PublicKey)
				fresh = append(fresh, publish)
			}
			result.Published = append(result.Published, publish.Selector)
		}
		for _, retire := range args.Retire {
			result.Retired = append(result.Retired, retire.Selector)
		}
		onPublish = self.onPublish
	}()
	if onPublish != nil {
		for _, publish := range fresh {
			onPublish(publish)
		}
	}
	return result, nil
}

func (self *testDkimAnswerPublisher) callList() []*sidecar.SmtpDkimKeysArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

// The key record the server writes for selector at <sel>._domainkey.<net>.<root>, which a CNAME or the delegated zone
// answers under the custom domain.
func (self *testDkimAnswerPublisher) record(t *testing.T, selector string) string {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	publicKey, ok := self.keys[selector]
	if !ok {
		t.Fatalf("selector %s was never published", selector)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)
}

// One sending sidecar's keys on secrets, whose custom-domain selectors await the zone's answer.
func newTestDkimAnswerKeys(secrets sidecar.SidecarSecrets, publisher sidecar.SmtpDkimPublisher, zone *sidecartest.FakeMailZone, clock *sidecartest.FakeClock, settings *sidecar.SmtpSenderSettings) *sidecar.SmtpDkimKeys {
	keys := sidecar.NewSmtpDkimKeys(secrets, publisher, settings, clock, nil)
	keys.SetDomainAnswers(&sidecar.SmtpDkimDomainAnswers{Doh: zone, Root: testDkimAnswerRoot + "."})
	return keys
}

// A world of one sidecar's keys over a fresh zone and clock.
type testDkimAnswerWorld struct {
	clock     *sidecartest.FakeClock
	zone      *sidecartest.FakeMailZone
	publisher *testDkimAnswerPublisher
	secrets   *testCustomDomainSecrets
	settings  *sidecar.SmtpSenderSettings
	keys      *sidecar.SmtpDkimKeys
}

func newTestDkimAnswerWorld() *testDkimAnswerWorld {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &testDkimAnswerWorld{
		clock:     clock,
		zone:      sidecartest.NewFakeMailZone(clock),
		publisher: newTestDkimAnswerPublisher(),
		secrets:   &testCustomDomainSecrets{values: map[string][]byte{}},
		settings:  sidecar.DefaultSmtpSenderSettings(),
	}
	world.keys = newTestDkimAnswerKeys(world.secrets, world.publisher, world.zone, clock, world.settings)
	return world
}

// The selector Current answers for domain, released at once: this test's sends hold none.
func (self *testDkimAnswerWorld) current(t *testing.T, domain string) (string, error) {
	t.Helper()
	selector, err := self.keys.Current(context.Background(), domain)
	if err != nil {
		return "", err
	}
	selector.Release()
	return selector.Selector, nil
}

// The customer adds selector's CNAME, which the device's resolver follows to the key record.
func (self *testDkimAnswerWorld) publishCname(t *testing.T, selector string, domain string) {
	t.Helper()
	self.zone.AddTxt(sidecar.SmtpDkimKeyName(selector, domain), self.publisher.record(t, selector))
}

// How many TXT lookups of selector's name under domain the device made.
func (self *testDkimAnswerWorld) lookupCount(selector string, domain string) int {
	count := 0
	for _, query := range self.zone.Queries() {
		if query.Name == sidecar.SmtpDkimKeyName(selector, domain) && query.Type == dnsmessage.TypeTXT {
			count += 1
		}
	}
	return count
}

// The one selector a call published, and the selectors it retired.
func testDkimAnswerCall(t *testing.T, call *sidecar.SmtpDkimKeysArgs) (published []string, retired []string) {
	t.Helper()
	for _, publish := range call.Publish {
		published = append(published, publish.Selector)
	}
	for _, retire := range call.Retire {
		retired = append(retired, retire.Selector)
	}
	return published, retired
}

// Signs under selector and verifies the signature against the key the selector was published with.
func testDkimAnswerSigns(t *testing.T, selector *sidecar.SmtpDkimSelector) {
	t.Helper()
	digest := sha256.Sum256([]byte("synthetic signing input"))
	signature, err := selector.SignDkim(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(selector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(parsed.(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
}

// Under CNAME mode a device's first selector for the domain is published and then signs nothing: the send holds as
// deferred, the publish is never repeated, the domain is looked up at most once each retry interval, and once the
// customer's CNAME answers the selector signs, with no further call.
func TestSmtpDkimCnameDomainFirstSelectorHoldsUntilTheDomainAnswers(t *testing.T) {
	world := newTestDkimAnswerWorld()
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatalf("the first send: %v", err)
	}
	calls := world.publisher.callList()
	if len(calls) != 1 {
		t.Fatalf("%d calls", len(calls))
	}
	published, retired := testDkimAnswerCall(t, calls[0])
	if len(published) != 1 || len(retired) != 0 || calls[0].Publish[0].Domain != testCustomDomainName {
		t.Fatalf("the first call %+v", calls[0])
	}
	first := published[0]
	if world.lookupCount(first, testCustomDomainName) != 1 {
		t.Fatal("no lookup as the publish was answered")
	}

	// within the retry interval: held, with no call and no lookup
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	world.clock.Advance(world.settings.DkimAnswerRetryInterval - time.Second)
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	if world.lookupCount(first, testCustomDomainName) != 1 || len(world.publisher.callList()) != 1 {
		t.Fatalf("%d lookups, %d calls inside the interval", world.lookupCount(first, testCustomDomainName), len(world.publisher.callList()))
	}
	// past it: one more lookup, still unanswered
	world.clock.Advance(time.Second)
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	if world.lookupCount(first, testCustomDomainName) != 2 {
		t.Fatalf("%d lookups", world.lookupCount(first, testCustomDomainName))
	}

	world.publishCname(t, first, testCustomDomainName)
	world.clock.Advance(world.settings.DkimAnswerRetryInterval)
	selector, err := world.keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	if selector.Selector != first || selector.DkimDomain() != testCustomDomainName {
		t.Fatalf("signs under %s for %s", selector.Selector, selector.DkimDomain())
	}
	testDkimAnswerSigns(t, selector)
	if len(world.publisher.callList()) != 1 {
		t.Error("the answer sent a call")
	}
}

// Under CNAME mode a rotation starts 7 days before the 90 are up and publishes the new selector alone: the old one
// stays published, so in DNS, and keeps signing, past its 90 days, until the domain answers the new one; while the
// new one awaits no other rotation is made; the answer moves signing to it and retires the old one in a call of its
// own, a send holding the old one still signing under it.
func TestSmtpDkimCnameDomainRotationKeepsTheOldSelectorUntilTheDomainAnswers(t *testing.T) {
	world := newTestDkimAnswerWorld()
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	old := world.publisher.callList()[0].Publish[0].Selector
	world.publishCname(t, old, testCustomDomainName)
	world.clock.Advance(world.settings.DkimAnswerRetryInterval)
	if selector, err := world.current(t, testCustomDomainName); err != nil || selector != old {
		t.Fatalf("the first selector: %s, %v", selector, err)
	}

	// a send holding the old selector across the rotation
	inFlight, err := world.keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer inFlight.Release()

	early := world.settings.DkimRotateTimeout - world.settings.DkimRetiredKeepTimeout
	world.clock.Advance(early - time.Second)
	if selector, err := world.current(t, testCustomDomainName); err != nil || selector != old || len(world.publisher.callList()) != 1 {
		t.Fatalf("rotated before %v: %s, %v", early, selector, err)
	}
	world.clock.Advance(time.Second)
	if selector, err := world.current(t, testCustomDomainName); err != nil || selector != old {
		t.Fatalf("the rotation dropped the old selector: %s, %v", selector, err)
	}
	calls := world.publisher.callList()
	if len(calls) != 2 {
		t.Fatalf("%d calls", len(calls))
	}
	published, retired := testDkimAnswerCall(t, calls[1])
	if len(published) != 1 || len(retired) != 0 {
		t.Fatalf("the rotation's call %+v retires before the domain answers", calls[1])
	}
	next := published[0]
	if next == old || world.lookupCount(next, testCustomDomainName) != 1 {
		t.Fatalf("the new selector %s, %d lookups", next, world.lookupCount(next, testCustomDomainName))
	}

	// past the 90 days with the new one awaiting: the old one signs, nothing else is published, one lookup an interval
	world.clock.Advance(world.settings.DkimRetiredKeepTimeout + 24*time.Hour)
	for range 3 {
		if selector, err := world.current(t, testCustomDomainName); err != nil || selector != old {
			t.Fatalf("while the new one awaits: %s, %v", selector, err)
		}
	}
	if err := world.keys.Rotate(context.Background(), testCustomDomainName); err != nil {
		t.Fatal(err)
	}
	if len(world.publisher.callList()) != 2 || world.lookupCount(next, testCustomDomainName) != 2 {
		t.Fatalf("%d calls, %d lookups while the new one awaits", len(world.publisher.callList()), world.lookupCount(next, testCustomDomainName))
	}

	world.publishCname(t, next, testCustomDomainName)
	world.clock.Advance(world.settings.DkimAnswerRetryInterval)
	if selector, err := world.current(t, testCustomDomainName); err != nil || selector != next {
		t.Fatalf("after the answer: %s, %v", selector, err)
	}
	calls = world.publisher.callList()
	if len(calls) != 3 {
		t.Fatalf("%d calls", len(calls))
	}
	published, retired = testDkimAnswerCall(t, calls[2])
	if len(published) != 0 || !slices.Equal(retired, []string{old}) || calls[2].Retire[0].Domain != testCustomDomainName {
		t.Fatalf("the answer's call %+v", calls[2])
	}
	// the send that pinned the old selector still signs under it
	testDkimAnswerSigns(t, inFlight)
	// and the next rotation waits for the new one's own 83 days
	world.clock.Advance(early - time.Second)
	if selector, err := world.current(t, testCustomDomainName); err != nil || selector != next || len(world.publisher.callList()) != 3 {
		t.Fatalf("rotated again early: %s, %v", selector, err)
	}
}

// Under a delegated _domainkey.<domain>, dns answers a selector as soon as its publish writes the row, so the first
// selector signs at once and a rotation moves at once, retiring the old selector in the next call.
func TestSmtpDkimDelegatedDomainMovesAtOnce(t *testing.T) {
	world := newTestDkimAnswerWorld()
	world.publisher.onPublish = func(publish *sidecar.SmtpDkimKeyPublish) {
		world.zone.AddTxt(sidecar.SmtpDkimKeyName(publish.Selector, publish.Domain), "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(publish.PublicKey))
	}
	first, err := world.current(t, testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	if world.lookupCount(first, testCustomDomainName) != 1 || len(world.publisher.callList()) != 1 {
		t.Fatalf("%d lookups, %d calls", world.lookupCount(first, testCustomDomainName), len(world.publisher.callList()))
	}
	world.clock.Advance(world.settings.DkimRotateTimeout - world.settings.DkimRetiredKeepTimeout)
	rotated, err := world.current(t, testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("no rotation")
	}
	calls := world.publisher.callList()
	if len(calls) != 3 {
		t.Fatalf("%d calls", len(calls))
	}
	if published, retired := testDkimAnswerCall(t, calls[1]); !slices.Equal(published, []string{rotated}) || len(retired) != 0 {
		t.Fatalf("the rotation's publish %+v", calls[1])
	}
	if published, retired := testDkimAnswerCall(t, calls[2]); len(published) != 0 || !slices.Equal(retired, []string{first}) {
		t.Fatalf("the retire %+v", calls[2])
	}
}

// With answers installed, the network's own domain and a burner's, both under the root, sign once published with no
// lookup, and rotate at 90 days in one call as before.
func TestSmtpDkimDomainsUnderTheRootAwaitNothing(t *testing.T) {
	world := newTestDkimAnswerWorld()
	burner := "quietfox-1234." + testCustomDomainNetwork
	network, err := world.current(t, testCustomDomainNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.current(t, burner); err != nil {
		t.Fatal(err)
	}
	if queries := world.zone.Queries(); len(queries) != 0 {
		t.Fatalf("looked up %+v", queries)
	}
	world.clock.Advance(world.settings.DkimRotateTimeout - world.settings.DkimRetiredKeepTimeout)
	if selector, err := world.current(t, testCustomDomainNetwork); err != nil || selector != network {
		t.Fatalf("rotated early: %s, %v", selector, err)
	}
	world.clock.Advance(world.settings.DkimRetiredKeepTimeout)
	rotated, err := world.current(t, testCustomDomainNetwork)
	if err != nil || rotated == network {
		t.Fatalf("no rotation at 90 days: %s, %v", rotated, err)
	}
	calls := world.publisher.callList()
	if published, retired := testDkimAnswerCall(t, calls[len(calls)-1]); !slices.Equal(published, []string{rotated}) || !slices.Equal(retired, []string{network}) {
		t.Fatalf("the rotation %+v", calls[len(calls)-1])
	}
	if queries := world.zone.Queries(); len(queries) != 0 {
		t.Fatalf("looked up %+v", queries)
	}
}

// A device's DoH answering from a function, so a test writes a reply the zone fake does not: a CNAME chain.
type testDkimAnswerForwarder func(qType dnsmessage.Type, domain string) ([]byte, bool)

func (self testDkimAnswerForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	return self(qType, domain)
}

// A recursive resolver's reply to a TXT question for name: NXDOMAIN when target is empty, else a CNAME from name to
// target, then target's TXT record of text in strings of at most 255 bytes.
func testDkimCnameReply(t *testing.T, name string, target string, text string) []byte {
	t.Helper()
	header := dnsmessage.Header{Response: true, RecursionAvailable: true}
	if target == "" {
		header.RCode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, header)
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if target == "" {
		reply, err := builder.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	cnameHeader := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300}
	if err := builder.CNAMEResource(cnameHeader, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")}); err != nil {
		t.Fatal(err)
	}
	pieces := []string{}
	for 255 < len(text) {
		pieces = append(pieces, text[:255])
		text = text[255:]
	}
	pieces = append(pieces, text)
	txtHeader := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target + "."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 300}
	if err := builder.TXTResource(txtHeader, dnsmessage.TXTResource{TXT: pieces}); err != nil {
		t.Fatal(err)
	}
	reply, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// The customer's CNAME as a resolver answers it: <sel>._domainkey.<domain> to the network's <sel>._domainkey.<net>.<root>,
// whose record the server wrote in strings of 255 bytes, is followed to the key, and a CNAME to another selector's
// record is no answer.
func TestSmtpDkimAnswerFollowsTheCustomersCname(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	publisher := newTestDkimAnswerPublisher()
	settings := sidecar.DefaultSmtpSenderSettings()
	stateLock := sync.Mutex{}
	// which selector's record each selector's CNAME leads to, "" for no CNAME
	leadsTo := map[string]string{}
	forward := testDkimAnswerForwarder(func(qType dnsmessage.Type, domain string) ([]byte, bool) {
		selector, _, _ := strings.Cut(domain, ".")
		stateLock.Lock()
		target := leadsTo[selector]
		stateLock.Unlock()
		if qType != dnsmessage.TypeTXT || target == "" {
			return testDkimCnameReply(t, domain, "", ""), true
		}
		return testDkimCnameReply(t, domain, sidecar.SmtpDkimKeyName(target, testCustomDomainNetwork), publisher.record(t, target)), true
	})
	keys := sidecar.NewSmtpDkimKeys(&testCustomDomainSecrets{values: map[string][]byte{}}, publisher, settings, clock, nil)
	keys.SetDomainAnswers(&sidecar.SmtpDkimDomainAnswers{Doh: forward, Root: testDkimAnswerRoot})

	if _, err := keys.Current(context.Background(), testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	first := publisher.callList()[0].Publish[0].Selector
	// another network's selector, the CNAME pointing at a record of another key
	other := newTestDkimAnswerPublisher()
	otherKeys := sidecar.NewSmtpDkimKeys(&testCustomDomainSecrets{values: map[string][]byte{}}, other, settings, clock, nil)
	otherSelector, err := otherKeys.Current(context.Background(), testCustomDomainNetwork)
	if err != nil {
		t.Fatal(err)
	}
	otherSelector.Release()
	func() {
		publisher.stateLock.Lock()
		defer publisher.stateLock.Unlock()
		publisher.keys[otherSelector.Selector] = bytes.Clone(otherSelector.PublicKey)
	}()
	stateLock.Lock()
	leadsTo[first] = otherSelector.Selector
	stateLock.Unlock()
	clock.Advance(settings.DkimAnswerRetryInterval)
	if _, err := keys.Current(context.Background(), testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatalf("a CNAME to another key answered: %v", err)
	}

	stateLock.Lock()
	leadsTo[first] = first
	stateLock.Unlock()
	clock.Advance(settings.DkimAnswerRetryInterval)
	selector, err := keys.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	if selector.Selector != first {
		t.Fatalf("signs under %s", selector.Selector)
	}
}

// Only a key record holding the selector's key answers: a lookup that fails, is refused, truncated, malformed or
// unusable, NXDOMAIN, a record of another key, one revoked, or one for another algorithm leaves the selector awaiting,
// and the first sends held.
func TestSmtpDkimAnswerRefusesWhatIsNoAnswer(t *testing.T) {
	for _, failure := range []sidecartest.FakeMailZoneFailure{
		sidecartest.FakeMailZoneServFail,
		sidecartest.FakeMailZoneNxDomain,
		sidecartest.FakeMailZoneUnusable,
		sidecartest.FakeMailZoneTruncated,
		sidecartest.FakeMailZoneMalformed,
	} {
		world := newTestDkimAnswerWorld()
		world.publisher.onPublish = func(publish *sidecar.SmtpDkimKeyPublish) {
			name := sidecar.SmtpDkimKeyName(publish.Selector, publish.Domain)
			world.zone.AddTxt(name, "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(publish.PublicKey))
			world.zone.Fail(name, dnsmessage.TypeTXT, failure)
		}
		if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
			t.Errorf("%s answered: %v", failure, err)
		}
	}

	otherKey := testDkimAnswerOtherKey(t)
	for name, record := range map[string]func(publicKey []byte) string{
		"another key": func(publicKey []byte) string {
			return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(otherKey)
		},
		"revoked": func(publicKey []byte) string { return "v=DKIM1; k=rsa; p=" },
		"ed25519": func(publicKey []byte) string {
			return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(publicKey)
		},
		"version": func(publicKey []byte) string {
			return "v=DKIM2; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)
		},
	} {
		world := newTestDkimAnswerWorld()
		world.publisher.onPublish = func(publish *sidecar.SmtpDkimKeyPublish) {
			world.zone.AddTxt(sidecar.SmtpDkimKeyName(publish.Selector, publish.Domain), record(publish.PublicKey))
		}
		if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
			t.Errorf("%s answered: %v", name, err)
		}
	}
}

// An RSA-2048 public key, DER, that no selector here was published with.
func testDkimAnswerOtherKey(t *testing.T) []byte {
	t.Helper()
	world := newTestDkimAnswerWorld()
	selector, err := world.keys.Current(context.Background(), testCustomDomainNetwork)
	if err != nil {
		t.Fatal(err)
	}
	selector.Release()
	return selector.PublicKey
}

// SmtpDkimKeyRecordHolds reads a record as a receiver does: tags in any order with folding white space, a trailing
// semicolon, the key split across character-strings joined; and refuses a tag named twice, another version, key type
// or service, a hash list without sha256, an empty or undecodable p= and a record that is no tag list.
func TestSmtpDkimKeyRecordHolds(t *testing.T) {
	publicKey := testDkimAnswerOtherKey(t)
	encoded := base64.StdEncoding.EncodeToString(publicKey)
	folded := encoded[:100] + " \r\n\t" + encoded[100:]
	for _, record := range []string{
		"v=DKIM1; k=rsa; p=" + encoded,
		"p=" + encoded,
		"v=DKIM1;k=rsa;p=" + encoded + ";",
		"k=RSA; v=DKIM1; p=" + folded,
		"v=DKIM1; h=sha1:sha256; s=email; t=s; p=" + encoded,
		"v=DKIM1; s=*; p=" + encoded,
	} {
		if !sidecar.SmtpDkimKeyRecordHolds(record, publicKey) {
			t.Errorf("%q held nothing", record)
		}
	}
	for _, record := range []string{
		"",
		"v=DKIM1; k=rsa; p=",
		"v=DKIM1; k=rsa",
		"v=DKIM1; k=rsa; p=" + encoded + "; p=" + encoded,
		"v=DKIM2; p=" + encoded,
		"k=ed25519; p=" + encoded,
		"h=sha1; p=" + encoded,
		"s=other; p=" + encoded,
		"p=" + encoded[:len(encoded)-4],
		"p=" + strings.Repeat("!", 8),
		"p " + encoded,
		"=x; p=" + encoded,
	} {
		if sidecar.SmtpDkimKeyRecordHolds(record, publicKey) {
			t.Errorf("%q held the key", record)
		}
	}
	if sidecar.SmtpDkimKeyRecordHolds("p="+encoded, nil) {
		t.Error("held no key")
	}
}

// A lookup that never answers ends at DkimAnswerLookupTimeout on the clock, the send held, and the next lookup waits
// DkimAnswerRetryInterval: both are the settings' values.
func TestSmtpDkimAnswerLookupEndsAtItsTimeout(t *testing.T) {
	world := newTestDkimAnswerWorld()
	world.settings.DkimAnswerLookupTimeout = 3 * time.Second
	world.settings.DkimAnswerRetryInterval = 2 * time.Minute
	world.publisher.onPublish = func(publish *sidecar.SmtpDkimKeyPublish) {
		world.zone.Fail(sidecar.SmtpDkimKeyName(publish.Selector, publish.Domain), dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	}
	start := world.clock.Now()
	ended := make(chan error, 1)
	go func() {
		_, err := world.current(t, testCustomDomainName)
		ended <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := world.zone.AwaitInFlight(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if pending := world.clock.PendingTimers(); !slices.Contains(pending, start.Add(3*time.Second)) {
		t.Fatalf("no timer at the lookup's timeout: %v", pending)
	}
	world.clock.Advance(3 * time.Second)
	if err := <-ended; !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatalf("the hung lookup: %v", err)
	}
	selector := world.publisher.callList()[0].Publish[0].Selector
	world.clock.Advance(2*time.Minute - 3*time.Second - time.Second)
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) || world.lookupCount(selector, testCustomDomainName) != 1 {
		t.Fatalf("looked up again inside the interval: %v", err)
	}
}

// An awaiting selector is kept in the keychain: a restart sends no new publish and looks it up at once, and its
// answer takes it into use.
func TestSmtpDkimAwaitingSelectorOutlivesARestart(t *testing.T) {
	world := newTestDkimAnswerWorld()
	if _, err := world.current(t, testCustomDomainName); !errors.Is(err, sidecar.ErrSmtpDkimSelectorUnanswered) {
		t.Fatal(err)
	}
	selector := world.publisher.callList()[0].Publish[0].Selector
	world.publishCname(t, selector, testCustomDomainName)

	restarted := newTestDkimAnswerKeys(world.secrets, world.publisher, world.zone, world.clock, world.settings)
	current, err := restarted.Current(context.Background(), testCustomDomainName)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Release()
	if current.Selector != selector || len(world.publisher.callList()) != 1 || world.lookupCount(selector, testCustomDomainName) != 2 {
		t.Fatalf("after the restart: %s, %d calls, %d lookups", current.Selector, len(world.publisher.callList()), world.lookupCount(selector, testCustomDomainName))
	}
	testDkimAnswerSigns(t, current)
}

// Through the sender: a device's first send From a CNAME-mode custom domain is deferred before any edge stream, with
// the selector published; once the customer's CNAME answers, the retry sends it signed under that selector for the
// domain.
func TestSmtpSenderHoldsACnameDomainsFirstSendUntilTheDomainAnswers(t *testing.T) {
	publisher := newTestDkimAnswerPublisher()
	world := newTestSenderWorld(t, &testSenderOptions{
		dkim: func(zone *sidecartest.FakeMailZone, clock *sidecartest.FakeClock, settings *sidecar.SmtpSenderSettings) *sidecar.SmtpDkimKeys {
			return newTestDkimAnswerKeys(newTestMemorySecrets(), publisher, zone, clock, settings)
		},
	})
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "A body line.\r\n")
	message.Message = []byte("From: Brand <news@" + testCustomDomainName + ">\r\n" +
		"To: bob@" + testTlsDomain + "\r\n" +
		"Subject: The spring catalog\r\n" +
		"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + testCustomDomainName + ">\r\n" +
		"\r\nThe catalog is out.\r\n")

	held := testDomainOutcome(t, world.send(message), testTlsDomain)
	if held.Outcome != sidecar.SmtpOutcomeDeferred || held.RetryAfter <= 0 {
		t.Fatalf("the first send: %+v", held)
	}
	if transactions := world.mx.Transactions(); len(transactions) != 0 {
		t.Fatalf("the MX took %+v", transactions)
	}
	if world.stub.DialCount() != 0 || len(world.verifier.Sessions()) != 0 {
		t.Fatalf("%d edge dials, %d sessions", world.stub.DialCount(), len(world.verifier.Sessions()))
	}
	calls := publisher.callList()
	if len(calls) != 1 || len(calls[0].Publish) != 1 || calls[0].Publish[0].Domain != testCustomDomainName {
		t.Fatalf("calls %+v", calls)
	}
	selector := calls[0].Publish[0].Selector

	world.tls.zone.AddTxt(sidecar.SmtpDkimKeyName(selector, testCustomDomainName), publisher.record(t, selector))
	world.tls.clock.Advance(held.RetryAfter)
	sent := testDomainOutcome(t, world.send(message), testTlsDomain)
	if sent.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("the retry: %+v", sent)
	}
	transactions := world.mx.Transactions()
	if len(transactions) != 1 || !bytes.Contains(transactions[0].Message, []byte("d="+testCustomDomainName+"; s="+selector+";")) {
		t.Fatalf("the message as taken does not sign under %s: %+v", selector, transactions)
	}
	if len(publisher.callList()) != 1 {
		t.Error("the retry published again")
	}
}
