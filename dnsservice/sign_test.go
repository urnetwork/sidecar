package dnsservice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Visibly synthetic P-256 scalars, the test KSK's and ZSKs'. No key here signs anything outside tests.
const (
	testKskScalarHex      = "1111111111111111111111111111111111111111111111111111111111111111"
	testZskScalarHex      = "2222222222222222222222222222222222222222222222222222222222222222"
	testOtherKeyScalarHex = "3333333333333333333333333333333333333333333333333333333333333333"
)

// Where the signing tests' clock stands: a fixed time, so windows and signatures read alike each run.
var testSigningNow = time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)

// A P-256 key from a fixed scalar.
func testP256Key(t testing.TB, scalarHex string) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// key's DNSKEY at root with flags.
func testDnskey(t testing.TB, root string, flags uint16, key crypto.Signer) *dns.DNSKEY {
	t.Helper()
	publicText, ok := dnsP256PublicKeyText(key.Public())
	if !ok {
		t.Fatal("not a P-256 key")
	}
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: root, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  dnsKeyProtocol,
		Algorithm: dnsSigningAlgorithm,
		PublicKey: publicText,
	}
}

// A record's RDATA in presentation form.
func testRdata(record dns.RR) string {
	return strings.TrimPrefix(record.String(), record.Header().String())
}

// What a test signs with: a KSK, a ZSK, and the window the KSK signed over both.
type testSigning struct {
	ksk       *ecdsa.PrivateKey
	zsk       *ecdsa.PrivateKey
	kskRecord *dns.DNSKEY
	zskRecord *dns.DNSKEY
	window    *DnsKeyWindow
	anchors   []*dns.DNSKEY
}

// A window over the KSK and records' ZSK, current at testSigningNow, signed by signer as the KSK.
func newTestWindow(t testing.TB, root string, notBefore time.Time, notAfter time.Time, signer crypto.Signer, records ...*dns.DNSKEY) *DnsKeyWindow {
	t.Helper()
	rrset := []dns.RR{}
	dnskeys := []string{}
	for _, record := range records {
		rrset = append(rrset, record)
		dnskeys = append(dnskeys, testRdata(record))
	}
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: root, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dnsSigningAlgorithm,
		KeyTag:     records[0].KeyTag(),
		SignerName: root,
		Inception:  uint32(notBefore.Unix()),
		Expiration: uint32(notAfter.Unix()),
	}
	if err := rrsig.Sign(signer, rrset); err != nil {
		t.Fatal(err)
	}
	return &DnsKeyWindow{Root: root, NotBefore: notBefore, NotAfter: notAfter, Dnskeys: dnskeys, Rrsigs: []string{testRdata(rrsig)}}
}

// The test KSK and ZSK, with a 14-day window that started a day before testSigningNow.
func newTestSigning(t testing.TB, root string) *testSigning {
	t.Helper()
	self := &testSigning{ksk: testP256Key(t, testKskScalarHex), zsk: testP256Key(t, testZskScalarHex)}
	self.kskRecord = testDnskey(t, root, dns.ZONE|dns.SEP, self.ksk)
	self.zskRecord = testDnskey(t, root, dns.ZONE, self.zsk)
	self.window = newTestWindow(t, root, testSigningNow.Add(-24*time.Hour), testSigningNow.Add(13*24*time.Hour), self.ksk,
		self.kskRecord, self.zskRecord)
	self.anchors = []*dns.DNSKEY{self.kskRecord}
	return self
}

// The key set the feed and secret_files would give.
func (self *testSigning) keySet() *DnsKeySet {
	return &DnsKeySet{Window: self.window, Zsk: self.zsk}
}

// The keys SelfCheck passes for view.
func (self *testSigning) checked(t testing.TB, view *ZoneView) *DnsSigningKeys {
	t.Helper()
	keys, err := SelfCheck(view, self.keySet(), self.anchors, testSigningNow)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// A clock a test moves by hand. Only Now is read by the signer, so its timers never fire.
type testClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (self *testClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *testClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

func (self *testClock) advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
}

// Valid settings for testRoot with signatures_per_second at rate.
func signingTestSettings(t testing.TB, rate int) *DnsSettings {
	t.Helper()
	settings := answerTestSettings(t)
	settings.SignaturesPerSecond = rate
	return settings
}

// The rows the signing tests serve: an apex, a network with a wildcard, an owner beside it, and a copy.
func signingTestRows() []DnsRecordSet {
	return []DnsRecordSet{
		{Owner: testRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"}},
		{Owner: testRoot, Type: dns.TypeNS, Ttl: 86400, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example."}},
		{Owner: "*.net1." + testRoot, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		{Owner: "*.net1." + testRoot, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"10 mx.net1.zone.example."}},
		{Owner: "www.net1." + testRoot, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.44"}},
		{Owner: "blog.net1." + testRoot, Type: DnsCopyType, Kind: DnsRecordKindCopy},
		{Owner: "_sip._tcp.blog.net1." + testRoot, Type: dns.TypeSRV, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"10 5 5060 sip.other.example."}},
	}
}

// One healthy interface, on documentation addresses.
func signingTestHealthy() *HealthySet {
	return NewHealthySet([]DnsLbInterface{{
		Name: "lb-1",
		Ipv4: netip.MustParseAddr("192.0.2.10"),
		Ipv6: netip.MustParseAddr("2001:db8::10"),
	}}, nil)
}

// A query for name as a validating resolver sends it: EDNS at 1232 with DO.
func signedQuery(name string, rrType uint16, tcp bool) *DnsQuery {
	message := testQuery(name, rrType)
	message.SetEdns0(1232, true)
	return &DnsQuery{Message: message, Tcp: tcp}
}

func TestSignerSignsEveryRrsetUnderDo(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	queries := []struct {
		name   string
		rrType uint16
	}{
		{name: testRoot, rrType: dns.TypeSOA},
		{name: testRoot, rrType: dns.TypeNS},
		{name: testRoot, rrType: dns.TypeDNSKEY},
		{name: "www.net1." + testRoot, rrType: dns.TypeA},
		{name: "unknown.net1." + testRoot, rrType: dns.TypeA},
		{name: "unknown.net1." + testRoot, rrType: dns.TypeMX},
		{name: "unknown.net1." + testRoot, rrType: dns.TypeTXT},
		{name: "blog.net1." + testRoot, rrType: dns.TypeMX},
		{name: "nosuch." + testRoot, rrType: dns.TypeA},
		{name: "x.www.net1." + testRoot, rrType: dns.TypeAAAA},
	}
	for _, q := range queries {
		query := signedQuery(q.name, q.rrType, false)
		reply := signer.Answer(query, view, keys, signingTestHealthy())
		if err := verifyDnsSignedReply(reply, query.Message.Question[0], true, false, keys, signing.anchors, testSigningNow); err != nil {
			t.Errorf("%s %s: %v\n%v", q.name, dnsTypeText(q.rrType), err, reply)
		}
	}
}

// Without DO nothing is signed, a denial stays plain and NXDOMAIN keeps its rcode.
func TestSignerLeavesAnAnswerWithoutDoUnsigned(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	for _, rrType := range []uint16{dns.TypeSOA, dns.TypeTXT} {
		query := &DnsQuery{Message: testQuery(testRoot, rrType)}
		reply := signer.Answer(query, view, keys, nil)
		if err := verifyDnsSignedReply(reply, query.Message.Question[0], false, false, keys, signing.anchors, testSigningNow); err != nil {
			t.Errorf("%s: %v", dnsTypeText(rrType), err)
		}
	}
	reply := signer.Answer(&DnsQuery{Message: testQuery("nosuch."+testRoot, dns.TypeA)}, view, keys, nil)
	if reply.Rcode != dns.RcodeNameError || len(reply.Ns) != 1 {
		t.Errorf("an unsigned denial %v", reply)
	}
}

// A wildcard's answer is signed as the queried name: labels count the name, never one fewer, and the
// signature verifies at that name, so nothing shows a wildcard answered.
func TestSignerSignsAWildcardAnswerAsTheQueriedName(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	for _, name := range []string{"a.net1." + testRoot, "a.b.c.net1." + testRoot, "Mixed.Case.NET1." + testRoot} {
		reply := signer.Answer(signedQuery(name, dns.TypeA, false), view, keys, signingTestHealthy())
		if len(reply.Answer) != 2 {
			t.Fatalf("%s: %v", name, reply)
		}
		rrsig, ok := reply.Answer[1].(*dns.RRSIG)
		if !ok {
			t.Fatalf("%s: %v", name, reply.Answer)
		}
		if int(rrsig.Labels) != dns.CountLabel(name) || rrsig.Hdr.Name != name {
			t.Errorf("%s: labels %d, owner %s", name, rrsig.Labels, rrsig.Hdr.Name)
		}
		if err := rrsig.Verify(signing.zskRecord, reply.Answer[:1]); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// signatures_per_second caps only fresh signatures: past it a cached answer still answers, an
// uncached one is TC over UDP and SERVFAIL over TCP, and never unsigned. The cap refills on the clock.
func TestSignerCapsOnlyFreshSignatures(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	clock := newTestClock(testSigningNow)
	// enough for one denial, SOA and NSEC, each second, and the bucket holds what one answer can need
	settings := signingTestSettings(t, 2)
	settings.CnameChainMaxCount = 1
	signer := NewSigner(settings, clock, nil)
	healthy := signingTestHealthy()

	cached := signedQuery("www.net1."+testRoot, dns.TypeA, false)
	if reply := signer.Answer(cached, view, keys, healthy); len(reply.Answer) != 2 {
		t.Fatalf("the first answer %v", reply)
	}
	// the bucket held 4, what one answer can need: one went on www and a first denial's SOA and NSEC
	// take two, then the SOA is cached and each further denial takes one, for its NSEC at a new name
	for _, name := range []string{"random1.zone.example.", "random2.zone.example."} {
		if reply := signer.Answer(signedQuery(name, dns.TypeA, false), view, keys, healthy); len(reply.Ns) != 4 {
			t.Fatalf("%s inside the cap %v", name, reply)
		}
	}
	udp := signer.Answer(signedQuery("random2a.zone.example.", dns.TypeA, false), view, keys, healthy)
	if !udp.Truncated || len(udp.Answer) != 0 || len(udp.Ns) != 0 || udp.Rcode != dns.RcodeSuccess {
		t.Errorf("past the cap over UDP %v", udp)
	}
	tcp := signer.Answer(signedQuery("random3.zone.example.", dns.TypeA, true), view, keys, healthy)
	if tcp.Rcode != dns.RcodeServerFailure || len(tcp.Answer) != 0 || len(tcp.Ns) != 0 {
		t.Errorf("past the cap over TCP %v", tcp)
	}
	again := signer.Answer(cached, view, keys, healthy)
	if err := verifyDnsSignedReply(again, cached.Message.Question[0], true, false, keys, signing.anchors, testSigningNow); err != nil {
		t.Errorf("a cached answer past the cap: %v", err)
	}
	// an unsigned query draws nothing from the cap
	if reply := signer.Answer(&DnsQuery{Message: testQuery("random4.zone.example.", dns.TypeA)}, view, keys, healthy); reply.Rcode != dns.RcodeNameError {
		t.Errorf("an unsigned denial past the cap %v", reply)
	}

	clock.advance(time.Second)
	refilled := signedQuery("random5.zone.example.", dns.TypeA, false)
	reply := signer.Answer(refilled, view, keys, healthy)
	if err := verifyDnsSignedReply(reply, refilled.Message.Question[0], true, false, keys, signing.anchors, clock.Now()); err != nil {
		t.Errorf("after a second: %v", err)
	}
}

// A cached signature serves until it has refresh_s left, then the ZSK signs again.
func TestSignerRefreshesACachedSignatureNearItsEnd(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	clock := newTestClock(testSigningNow)
	settings := signingTestSettings(t, 1000)
	settings.Signing.JitterSeconds = 0
	signer := NewSigner(settings, clock, nil)
	query := signedQuery("www.net1."+testRoot, dns.TypeA, false)
	first := signer.Answer(query, view, keys, nil).Answer[1].(*dns.RRSIG)
	clock.advance(time.Hour)
	if second := signer.Answer(query, view, keys, nil).Answer[1].(*dns.RRSIG); second.Signature != first.Signature {
		t.Error("a cached signature with time left was made again")
	}
	clock.advance(dnsSeconds(settings.Signing.LifetimeSeconds-settings.Signing.RefreshSeconds) - time.Hour + time.Second)
	third := signer.Answer(query, view, keys, nil).Answer[1].(*dns.RRSIG)
	if third.Signature == first.Signature || third.Inception == first.Inception {
		t.Error("a signature near its end was served again")
	}
}

// An RRSIG never outlives the window that publishes its ZSK, and its lifetime is the setting's.
func TestSignerKeepsSignaturesInsideTheWindow(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	signing.window = newTestWindow(t, testRoot, testSigningNow.Add(-time.Hour), testSigningNow.Add(2*24*time.Hour+time.Hour),
		signing.ksk, signing.kskRecord, signing.zskRecord)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	settings := signingTestSettings(t, 1000)
	signer := NewSigner(settings, newTestClock(testSigningNow), nil)
	rrsig := signer.Answer(signedQuery(testRoot, dns.TypeSOA, false), view, keys, nil).Answer[1].(*dns.RRSIG)
	if rrsig.Expiration != uint32(signing.window.NotAfter.Unix()) {
		t.Errorf("expiration %d, window end %d", rrsig.Expiration, signing.window.NotAfter.Unix())
	}
	if rrsig.Inception != uint32(testSigningNow.Add(-time.Hour).Unix()) {
		t.Errorf("inception %d", rrsig.Inception)
	}

	wide := newTestSigning(t, testRoot)
	keys = wide.checked(t, view)
	rrsig = signer.Answer(signedQuery("www.net1."+testRoot, dns.TypeA, false), view, keys, nil).Answer[1].(*dns.RRSIG)
	lifetime := time.Duration(int32(rrsig.Expiration-uint32(testSigningNow.Unix()))) * time.Second
	longest := dnsSeconds(settings.Signing.LifetimeSeconds)
	if lifetime > longest || lifetime < longest-dnsSeconds(settings.Signing.JitterSeconds) {
		t.Errorf("lifetime %v", lifetime)
	}
}

// With no keys, or keys of another root, a DO query is SERVFAIL, never an unsigned answer.
func TestSignerNeverAnswersDoUnsigned(t *testing.T) {
	view := newTestView(t, 100, signingTestRows()...)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	reply := signer.Answer(signedQuery(testRoot, dns.TypeSOA, false), view, nil, nil)
	if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
		t.Errorf("no keys %v", reply)
	}
	other := newTestSigning(t, "other.example.")
	otherSnapshot := DnsSnapshot{Format: DnsFormat, Root: "other.example.", Serial: 1}
	otherSettings := signingTestSettings(t, 1000)
	otherSettings.Roots = []string{"other.example."}
	otherView, err := NewZoneView(otherSettings, NewDnsSnapshotRows(otherSnapshot, []DnsRecordSet{{
		Owner: "other.example.", Type: dns.TypeSOA, Ttl: 3600, Kind: DnsRecordKindSystem,
		Rdata: []string{"ns1.other.example. hostmaster.other.example. 1 7200 3600 1209600 60"},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	reply = signer.Answer(signedQuery(testRoot, dns.TypeSOA, false), view, other.checked(t, otherView), nil)
	if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
		t.Errorf("another root's keys %v", reply)
	}
	if reply := signer.Answer(&DnsQuery{Message: testQuery(testRoot, dns.TypeSOA)}, view, nil, nil); len(reply.Answer) != 1 {
		t.Errorf("without DO %v", reply)
	}
}

// A ZSK that refuses to sign makes SERVFAIL, never an unsigned answer.
func TestSignerAnswersServfailWhenTheZskFails(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	broken := *keys
	broken.zsk = failingSigner{public: signing.zsk.Public()}
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	reply := signer.Answer(signedQuery(testRoot, dns.TypeSOA, false), view, &broken, nil)
	if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
		t.Errorf("%v", reply)
	}
}

// A crypto.Signer with a real public key whose signing fails.
type failingSigner struct {
	public crypto.PublicKey
}

func (self failingSigner) Public() crypto.PublicKey {
	return self.public
}

func (self failingSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("refused")
}

// A crypto.Signer with a real public key that signs with another key, so its signatures do not verify.
type wrongSigner struct {
	public crypto.PublicKey
	other  crypto.Signer
}

func (self wrongSigner) Public() crypto.PublicKey {
	return self.public
}

func (self wrongSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return self.other.Sign(random, digest, options)
}

// A signed answer too big for the client's UDP size goes empty with TC, as an unsigned one does.
func TestSignerTruncatesASignedAnswerPastTheUdpSize(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	rows := signingTestRows()
	big := DnsRecordSet{Owner: "big.net1." + testRoot, Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser}
	for index := range 4 {
		big.Rdata = append(big.Rdata, fmt.Sprintf(`"%s%d"`, strings.Repeat("t", 100), index))
	}
	view := newTestView(t, 100, append(rows, big)...)
	keys := signing.checked(t, view)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	message := testQuery("big.net1."+testRoot, dns.TypeTXT)
	message.SetEdns0(512, true)
	reply := signer.Answer(&DnsQuery{Message: message}, view, keys, nil)
	if !reply.Truncated || len(reply.Answer) != 0 {
		t.Errorf("%v", reply)
	}
	reply = signer.Answer(&DnsQuery{Message: message, Tcp: true}, view, keys, nil)
	if err := verifyDnsSignedReply(reply, message.Question[0], true, false, keys, signing.anchors, testSigningNow); err != nil {
		t.Errorf("over TCP: %v", err)
	}
}

// The cache drops the least recently used past its bound.
func TestSignatureCacheDropsTheLeastRecentlyUsed(t *testing.T) {
	cache := newDnsSignatureCache(2)
	rrsig := &dns.RRSIG{Inception: uint32(testSigningNow.Add(-time.Hour).Unix()), Expiration: uint32(testSigningNow.Add(72 * time.Hour).Unix())}
	keyOf := func(owner string) dnsSignatureKey {
		return dnsSignatureKey{owner: owner, rrType: dns.TypeA}
	}
	cache.put(keyOf("a."), rrsig)
	cache.put(keyOf("b."), rrsig)
	if cache.get(keyOf("a."), testSigningNow, time.Hour) == nil {
		t.Fatal("a held entry missed")
	}
	cache.put(keyOf("c."), rrsig)
	if cache.get(keyOf("b."), testSigningNow, time.Hour) != nil {
		t.Error("the least recently used survived")
	}
	if cache.get(keyOf("a."), testSigningNow, time.Hour) == nil || cache.get(keyOf("c."), testSigningNow, time.Hour) == nil {
		t.Error("a recent entry went")
	}
	if cache.get(keyOf("a."), testSigningNow, 73*time.Hour) != nil {
		t.Error("an entry served past its need")
	}
	if cache.get(keyOf("a."), testSigningNow.Add(-2*time.Hour), time.Hour) != nil {
		t.Error("an entry served before its inception")
	}
}

// Two RRsets digest alike only when what a signature covers is alike.
func TestRrsetDigestCoversTypeTtlAndRdata(t *testing.T) {
	parse := func(text string) dns.RR {
		record, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	digest := func(texts ...string) [32]byte {
		rrset := []dns.RR{}
		for _, text := range texts {
			rrset = append(rrset, parse(text))
		}
		value, ok := dnsRrsetDigest(rrset)
		if !ok {
			t.Fatalf("%v does not digest", texts)
		}
		return value
	}
	base := digest("a.zone.example. 60 IN A 192.0.2.1")
	if digest("A.Zone.Example. 60 IN A 192.0.2.1") != base {
		t.Error("the owner's case changed the digest")
	}
	for _, other := range []string{
		"a.zone.example. 61 IN A 192.0.2.1",
		"a.zone.example. 60 IN A 192.0.2.2",
		"b.zone.example. 60 IN A 192.0.2.1",
		"a.zone.example. 60 IN TXT \"192.0.2.1\"",
	} {
		if digest(other) == base {
			t.Errorf("%s digests as the base", other)
		}
	}
	if digest("a.zone.example. 60 IN A 192.0.2.1", "a.zone.example. 60 IN A 192.0.2.2") == base {
		t.Error("a second record changed nothing")
	}
}
