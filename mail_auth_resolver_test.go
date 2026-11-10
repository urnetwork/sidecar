//go:build !sidecar_http && !js

// MAIL-M7-07's resolver and stub on FakeMailZone and a fake clock: answers in mox's shapes, a 4.9 s answer kept and a
// 5.1 s one temperror, each key answered once a message, every bad reply temperror and never kept, and the stub's
// TTLs, its negative caching only under an SOA, and its bound. Every name and address is synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/adns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Whether err is mox's not found, and whether its temporary.
func testMailDnsErrorKind(err error) (notFound bool, temporary bool) {
	var dnsError *adns.DNSError
	if !errors.As(err, &dnsError) {
		return false, false
	}
	return dnsError.IsNotFound, dnsError.IsTemporary
}

// Each type comes back as mox reads it: TXT records one string each, A and AAAA as addresses, MX hosts and PTR names
// absolute, TLSA's fields; NXDOMAIN and NODATA are not found; a relative name is refused.
func TestMailAuthResolverAnswersAsMoxReadsIt(t *testing.T) {
	world := newMailAuthTestWorld(t)
	ctx := context.Background()
	long := string(bytes.Repeat([]byte("k"), 300))
	world.zone.AddTxt("s1._domainkey.sender.example", "v=DKIM1; p="+long)
	world.zone.AddTxt("sender.example", "v=spf1 ip4:192.0.2.0/24 -all")
	world.zone.AddAddress("mail.sender.example", netip.MustParseAddr("192.0.2.25"))
	world.zone.AddAddress("mail.sender.example", netip.MustParseAddr("2001:db8::25"))
	world.zone.AddMx("sender.example", 10, "mail.sender.example")
	world.zone.AddPtr(netip.MustParseAddr("2001:db8::25"), "mail.sender.example")
	world.zone.AddTlsa("_25._tcp.mx.k3j4h5g6f7.root.example", 3, 1, 1, bytes.Repeat([]byte{0xab}, 32))

	texts, result, err := world.resolver.LookupTXT(ctx, "s1._domainkey.sender.example.")
	if err != nil || len(texts) != 1 || texts[0] != "v=DKIM1; p="+long || result.Authentic {
		t.Errorf("txt %q, %v", texts, err)
	}
	ips, _, err := world.resolver.LookupIP(ctx, "ip", "mail.sender.example.")
	if err != nil || len(ips) != 2 || !ips[0].Equal(net.ParseIP("192.0.2.25")) || !ips[1].Equal(net.ParseIP("2001:db8::25")) {
		t.Errorf("ip %v, %v", ips, err)
	}
	if ips, _, err := world.resolver.LookupIP(ctx, "ip4", "mail.sender.example."); err != nil || len(ips) != 1 {
		t.Errorf("ip4 %v, %v", ips, err)
	}
	exchanges, _, err := world.resolver.LookupMX(ctx, "sender.example.")
	if err != nil || len(exchanges) != 1 || exchanges[0].Host != "mail.sender.example." || exchanges[0].Pref != 10 {
		t.Errorf("mx %v, %v", exchanges, err)
	}
	names, _, err := world.resolver.LookupAddr(ctx, "2001:db8::25")
	if err != nil || !slices.Equal(names, []string{"mail.sender.example."}) {
		t.Errorf("ptr %v, %v", names, err)
	}
	records, _, err := world.resolver.LookupTLSA(ctx, 25, "tcp", "mx.k3j4h5g6f7.root.example.")
	if err != nil || len(records) != 1 || records[0].Usage != 3 || records[0].Selector != 1 || records[0].MatchType != 1 || !bytes.Equal(records[0].CertAssoc, bytes.Repeat([]byte{0xab}, 32)) {
		t.Errorf("tlsa %v, %v", records, err)
	}
	if _, _, err := world.resolver.LookupTXT(ctx, "absent.example."); !testMailNotFound(err) {
		t.Errorf("nxdomain: %v", err)
	}
	if _, _, err := world.resolver.LookupMX(ctx, "mail.sender.example."); !testMailNotFound(err) {
		t.Errorf("nodata: %v", err)
	}
	if _, _, err := world.resolver.LookupTXT(ctx, "sender.example"); !errors.Is(err, sidecar.ErrMailAuthLookupRefused) {
		t.Errorf("a relative name: %v", err)
	}
	if _, err := world.resolver.LookupPort(ctx, "tcp", "smtp"); !errors.Is(err, sidecar.ErrMailAuthLookupRefused) {
		t.Errorf("a port: %v", err)
	}
}

func testMailNotFound(err error) bool {
	notFound, _ := testMailDnsErrorKind(err)
	return notFound
}

// One query's time is 5 s on the clock: an answer at 4.9 s is taken, one at 5.1 s is temperror, which is a DNS
// failure and no bound.
func TestMailAuthResolverAnswersWithinFiveSeconds(t *testing.T) {
	for _, c := range []struct {
		delay    time.Duration
		answered bool
	}{
		{delay: 4900 * time.Millisecond, answered: true},
		{delay: 5100 * time.Millisecond, answered: false},
	} {
		world := newMailAuthTestWorld(t)
		world.zone.AddTxt("slow.sender.example", "v=spf1 -all")
		world.zone.SetDelay("slow.sender.example", c.delay)
		done := make(chan error, 1)
		go func() {
			_, _, err := world.resolver.LookupTXT(context.Background(), "slow.sender.example.")
			done <- err
		}()
		awaitMailZoneDelays(t, world.clock, 1, c.delay)
		world.clock.Advance(c.delay)
		err := <-done
		_, temporary := testMailDnsErrorKind(err)
		if c.answered != (err == nil) || (!c.answered && (!temporary || errors.Is(err, sidecar.ErrMailAuthBound))) {
			t.Errorf("at %s: %v", c.delay, err)
		}
		if !c.answered && world.stub.Len() != 0 {
			t.Error("a timeout was kept")
		}
	}
}

// A message asks each name and type once, however often and however concurrently mox asks it, as it does for a
// selector repeated across signatures.
func TestMailAuthResolverAnswersEachKeyOnce(t *testing.T) {
	world := newMailAuthTestWorld(t)
	world.zone.AddTxt("s1._domainkey.sender.example", "v=DKIM1; p=key")
	world.zone.SetDelay("s1._domainkey.sender.example", time.Second)
	var group sync.WaitGroup
	for range 10 {
		group.Go(func() {
			if _, _, err := world.resolver.WithPriority(sidecar.MailAuthPriorityKeys).LookupTXT(context.Background(), "S1._domainkey.sender.example."); err != nil {
				t.Error(err)
			}
		})
	}
	awaitMailZoneDelays(t, world.clock, 1, time.Second)
	world.clock.Advance(time.Second)
	group.Wait()
	world.resolver.Prefetch([]string{"s1._domainkey.sender.example."}, dnsmessage.TypeTXT)
	if _, _, err := world.resolver.LookupTXT(context.Background(), "s1._domainkey.sender.example."); err != nil {
		t.Fatal(err)
	}
	if queries := world.zone.Queries(); len(queries) != 1 {
		t.Errorf("%d queries", len(queries))
	}
	// a failure is answered once too
	world.zone.Fail("down.sender.example", dnsmessage.TypeTXT, sidecartest.FakeMailZoneServFail)
	for range 3 {
		if _, temporary := testMailDnsErrorKind(func() error {
			_, _, err := world.resolver.LookupTXT(context.Background(), "down.sender.example.")
			return err
		}()); !temporary {
			t.Error("a failure is not temporary")
		}
	}
	if queries := world.zone.Queries(); len(queries) != 2 {
		t.Errorf("%d queries after a failure", len(queries))
	}
}

// A truncated, malformed, failed or unusable reply is temperror, never a panic and never a bound, and none is kept:
// a later message asks again.
func TestMailAuthResolverTakesBadRepliesAsTemperror(t *testing.T) {
	world := newMailAuthTestWorld(t)
	failures := []sidecartest.FakeMailZoneFailure{
		sidecartest.FakeMailZoneTruncated, sidecartest.FakeMailZoneMalformed, sidecartest.FakeMailZoneServFail, sidecartest.FakeMailZoneUnusable,
	}
	for index, failure := range failures {
		name := []string{"truncated", "malformed", "servfail", "unusable"}[index] + ".sender.example"
		world.zone.AddTxt(name, "v=spf1 -all")
		world.zone.Fail(name, dnsmessage.TypeTXT, failure)
		for range 2 {
			_, _, err := world.resolver.LookupTXT(context.Background(), name+".")
			if _, temporary := testMailDnsErrorKind(err); !temporary || errors.Is(err, sidecar.ErrMailAuthBound) || !errors.Is(err, sidecar.ErrMailDnsNoAnswer) {
				t.Errorf("%s: %v", failure, err)
			}
			world.newMessage(t)
		}
	}
	if world.stub.Len() != 0 || len(world.zone.Queries()) != 2*len(failures) {
		t.Errorf("%d kept, %d queries", world.stub.Len(), len(world.zone.Queries()))
	}
}

// A forwarder that answers from a function, so a test writes replies the zone does not: an SOA in the authority
// section, a short TTL, a CNAME.
type mailTestForwarder struct {
	stateLock sync.Mutex
	queries   int
	answer    func(qType dnsmessage.Type, domain string) []byte
}

func (self *mailTestForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	self.stateLock.Lock()
	self.queries += 1
	self.stateLock.Unlock()
	return self.answer(qType, domain), true
}

func (self *mailTestForwarder) queryCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.queries
}

// A reply to domain's qType: rcode, answers of TXT records with ttl at owner, and an SOA of soaTtl and minimum in the
// authority section where soaTtl is not 0.
func testMailDnsReply(t *testing.T, qType dnsmessage.Type, domain string, rcode dnsmessage.RCode, owner string, ttl uint32, soaTtl uint32, minimum uint32) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(domain + ".")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
	builder.StartQuestions()
	builder.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET})
	builder.StartAnswers()
	if owner != "" {
		ownerName := dnsmessage.MustNewName(owner + ".")
		if owner != domain {
			builder.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.CNAMEResource{CNAME: ownerName})
		}
		builder.TXTResource(dnsmessage.ResourceHeader{Name: ownerName, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.TXTResource{TXT: []string{"v=spf1 -all"}})
	}
	builder.StartAuthorities()
	if soaTtl != 0 {
		builder.SOAResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: soaTtl},
			dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("hostmaster.example."), Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: minimum})
	}
	reply, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// The stub keeps an answer by its TTL, at most an hour; NXDOMAIN and NODATA only under an SOA, for the shorter of its
// TTL and minimum and at most 300 s; a CNAME's target's records; and at most StubEntryMaxCount answers, the least
// recently used out.
func TestMailDnsStubKeepsByTtl(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecar.DefaultMailAuthSettings()
	forwarder := &mailTestForwarder{}
	stub := sidecar.NewMailDnsStub(forwarder, clock, settings)
	ask := func(name string) error {
		budget := sidecar.NewMailAuthBudget(clock, settings)
		defer budget.Close()
		_, _, err := sidecar.NewMailAuthResolver(stub, budget, sidecar.MailAuthPriorityDmarc).LookupTXT(context.Background(), name+".")
		return err
	}
	answers := map[string]func(dnsmessage.Type, string) []byte{
		"short.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, domain, 60, 0, 0)
		},
		"long.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, domain, 86400, 0, 0)
		},
		"alias.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, "target.example", 60, 0, 0)
		},
		"gone.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeNameError, "", 0, 3600, 900)
		},
		"nosoa.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeNameError, "", 0, 0, 0)
		},
		"nodata.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, "", 0, 120, 30)
		},
		"lru1.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, domain, 600, 0, 0)
		},
		"lru2.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, domain, 600, 0, 0)
		},
		"lru3.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, domain, dnsmessage.RCodeSuccess, domain, 600, 0, 0)
		},
		"another.example": func(qType dnsmessage.Type, domain string) []byte {
			return testMailDnsReply(t, qType, "elsewhere.example", dnsmessage.RCodeSuccess, "elsewhere.example", 600, 0, 0)
		},
	}
	forwarder.answer = func(qType dnsmessage.Type, domain string) []byte { return answers[domain](qType, domain) }
	// asked twice a little apart, kept or not
	twice := func(name string, apart time.Duration) int {
		before := forwarder.queryCount()
		ask(name)
		clock.Advance(apart)
		ask(name)
		return forwarder.queryCount() - before
	}
	for _, c := range []struct {
		name    string
		apart   time.Duration
		queries int
	}{
		{name: "short.example", apart: 59 * time.Second, queries: 1},
		{name: "short.example", apart: 61 * time.Second, queries: 2},
		{name: "long.example", apart: 3599 * time.Second, queries: 1},
		{name: "long.example", apart: 3601 * time.Second, queries: 2},
		{name: "alias.example", apart: 30 * time.Second, queries: 1},
		{name: "gone.example", apart: 299 * time.Second, queries: 1},
		{name: "gone.example", apart: 301 * time.Second, queries: 2},
		{name: "nosoa.example", apart: time.Second, queries: 2},
		{name: "nodata.example", apart: 29 * time.Second, queries: 1},
		{name: "nodata.example", apart: 31 * time.Second, queries: 2},
		{name: "another.example", apart: time.Second, queries: 2},
	} {
		clock.Advance(2 * time.Hour)
		if queries := twice(c.name, c.apart); queries != c.queries {
			t.Errorf("%s %s apart: %d queries", c.name, c.apart, queries)
		}
	}
	if err := ask("alias.example"); err != nil {
		t.Errorf("a CNAME's target: %v", err)
	}
	if err := ask("another.example"); err == nil {
		t.Error("a reply to another question was taken")
	}
	// two kept at most: the least recently used goes
	settings.StubEntryMaxCount = 2
	small := sidecar.NewMailDnsStub(forwarder, clock, settings)
	stub = small
	clock.Advance(2 * time.Hour)
	before := forwarder.queryCount()
	ask("lru1.example")
	ask("lru2.example")
	ask("lru1.example")
	ask("lru3.example")
	ask("lru1.example")
	ask("lru2.example")
	if queries := forwarder.queryCount() - before; queries != 4 || small.Len() != 2 {
		t.Errorf("%d queries, %d kept", queries, small.Len())
	}
}
