//go:build !sidecar_http

// §14.4's TLS policy on MxWorld, one send at a time as SMTP-M9-07's driver will run it: the preamble
// through StubSmtpEdge, SmtpTlsPolicy.Authenticate over what the edge named, and FakeSmtpProver's
// handshake under the authentication's VerifyPeer. Each level is reached; a malicious edge that strips
// TLSA under a TL1 pin, or names a host of its own, is refused inside the handshake, so the MX sees no
// command after it; PKIX for the wrong name is no authentication; TL4 is refused with a DSN reason
// until a message's own approval lets it through, labeled; pins rise, hold 90 days, lapse and survive
// a restart. The TLS-level checks then run on their own against a fake DoH for the lookups' edges.
//
// Names are .example and addresses RFC 5737's. The web PKI is a synthetic root of the test's own.

package sidecar_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testTlsDomain    = "mail.example"
	testTlsHost      = "mx.mail.example"
	testTlsOtherZone = "other.example"
	testTlsOtherHost = "mx.other.example"
	testTlsPolicy    = "version: STSv1\r\nmode: enforce\r\nmx: mx.mail.example\r\nmax_age: 604800\r\n"
)

var (
	testTlsStart        = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	testTlsAddress      = netip.MustParseAddr("198.51.100.25")
	testTlsOtherAddress = netip.MustParseAddr("198.51.100.66")
	testTlsCertFrom     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	testTlsCertTo       = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// The test's own web PKI: one synthetic root, which issues MX leaves for TL2 and TL3.
type testTlsPki struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	roots   *x509.CertPool
}

func newTestTlsPki(t *testing.T) *testTlsPki {
	t.Helper()
	root, rootKey := newTestDaneCertificate(t, "Synthetic Test Root", true, nil, nil, testTlsCertFrom, testTlsCertTo)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &testTlsPki{root: root, rootKey: rootKey, roots: roots}
}

// A leaf for name, issued by the root, as an MX serves it.
func (self *testTlsPki) leaf(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	leaf, key := newTestDaneCertificate(t, name, false, self.root, self.rootKey, testTlsCertFrom, testTlsCertTo)
	return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

// mail.example in an MxWorld, its MX mx.mail.example at preference 10, and the device's own DoH, which
// agrees; one fake clock under all of it, so DNSSEC signs at the time a chain is asked for.
type testTlsWorld struct {
	clock    *sidecartest.FakeClock
	world    *sidecartest.MxWorld
	zone     *sidecartest.FakeMailZone
	pki      *testTlsPki
	store    *sidecartest.FakeStore
	settings *sidecar.SmtpSenderSettings
	anchors  *sidecar.SmtpDnssecAnchors
}

func newTestTlsWorld(t *testing.T, options *sidecartest.MxWorldZoneOptions) *testTlsWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(testTlsStart)
	worldSettings := sidecartest.DefaultMxWorldSettings()
	worldSettings.Clock = clock
	world, err := sidecartest.NewMxWorld(worldSettings)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone(testTlsDomain, options); err != nil {
		t.Fatal(err)
	}
	if err := world.SetMx(testTlsDomain, &sidecar.SmtpMxHost{Preference: 10, Host: testTlsHost}); err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone(testTlsOtherZone, nil); err != nil {
		t.Fatal(err)
	}
	zone := sidecartest.NewFakeMailZone(clock)
	zone.AddMx(testTlsDomain, 10, testTlsHost)
	return &testTlsWorld{
		clock:    clock,
		world:    world,
		zone:     zone,
		pki:      newTestTlsPki(t),
		store:    sidecartest.NewFakeStore(),
		settings: sidecar.DefaultSmtpSenderSettings(),
		anchors:  testDnssecAnchors(t, world),
	}
}

// An MX at address for host serving certificate, a self-signed one when nil, with tlsa at
// _25._tcp.<host>.
func (self *testTlsWorld) addMx(t *testing.T, host string, address netip.Addr, certificate *tls.Certificate, tlsa ...*sidecar.SmtpTlsaRecord) *sidecartest.ScriptedMx {
	t.Helper()
	settings := sidecartest.DefaultScriptedMxSettings()
	settings.Certificate = certificate
	mx, err := sidecartest.NewScriptedMx(host, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := self.world.AddMx(host, address, mx, tlsa...); err != nil {
		t.Fatal(err)
	}
	return mx
}

// Publishes an MTA-STS policy for mail.example under id, at its host and in the device's DoH.
func (self *testTlsWorld) publishPolicy(t *testing.T, id string, policy string) {
	t.Helper()
	if err := self.world.SetMtaStsPolicy(testTlsDomain, id, policy); err != nil {
		t.Fatal(err)
	}
	self.zone.AddTxt("_mta-sts."+testTlsDomain, "v=STSv1; id="+id)
}

// A sender's policy over the world's store, built fresh each call, as after a restart.
func (self *testTlsWorld) policy() *sidecar.SmtpTlsPolicy {
	pins := sidecar.NewSmtpPinStore(self.store.Root(), self.settings, self.clock)
	mtaSts := sidecar.NewSmtpMtaSts(self.zone, self.world.MtaStsTransport(), self.store.Root(), self.settings, self.clock)
	dane := sidecar.NewSmtpDane(self.anchors, self.clock, nil)
	return sidecar.NewSmtpTlsPolicy(dane, mtaSts, pins, self.zone, self.pki.roots, self.settings, self.clock)
}

// An honest edge, which resolves, dials and sends its dnssec_chain.
func (self *testTlsWorld) edge(resolver sidecar.SmtpMxResolver) *sidecartest.StubSmtpEdge {
	if resolver == nil {
		resolver = self.world
	}
	return sidecartest.NewStubSmtpEdge(resolver, self.world, sidecartest.NewFakeSmtpProofVerifier(nil), nil)
}

// A malicious edge's resolver that withholds every chain, which is how it strips TLSA: it cannot forge
// one.
type testStrippingResolver struct {
	sidecar.SmtpMxResolver
}

// A malicious edge's resolver that names host as every domain's only MX, unsigned.
type testLyingResolver struct {
	sidecar.SmtpMxResolver
	host string
}

func (self *testLyingResolver) LookupMx(ctx context.Context, domain string) (*sidecar.SmtpMxAnswer, error) {
	return &sidecar.SmtpMxAnswer{Hosts: []*sidecar.SmtpMxHost{{Preference: 10, Host: self.host}}}, nil
}

// One message to bob@mail.example under flags, as SmtpProofJob carries it before the edge's values.
func testTlsJob(flags uint32) *sidecar.SmtpProofJob {
	message := []byte("From: Alice Example <alice@n1.root.example>\r\n" +
		"To: <bob@" + testTlsDomain + ">\r\n" +
		"Subject: A synthetic message\r\n" +
		"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example>\r\n" +
		"\r\n" +
		"A body line.\r\n")
	return &sidecar.SmtpProofJob{
		Preamble: &sidecar.SmtpProofPreamble{
			RecipientDomain:  testTlsDomain,
			RecipientCount:   1,
			MessageId:        "qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example",
			HeaderFromDomain: "n1.root.example",
			MessageByteCount: uint64(len(message)),
			Flags:            flags,
			EnvelopeDomain:   "b.n1.root.example",
		},
		SenderLocal:     "bounce-1",
		RecipientLocals: []string{"bob"},
		Message:         message,
	}
}

// What one send did.
type testTlsSend struct {
	result         *protocol.SmtpPreambleResult
	authentication *sidecar.SmtpTlsAuthentication
	proofResult    *sidecar.SmtpProofResult
	err            error
}

// One send through edge under policy, as SMTP-M9-07's driver will run it, returning once the edge and
// every MX are done.
func (self *testTlsWorld) send(t *testing.T, edge *sidecartest.StubSmtpEdge, policy *sidecar.SmtpTlsPolicy, flags uint32, messageTl4Domains ...string) *testTlsSend {
	t.Helper()
	ctx := context.Background()
	sidecarConn, edgeConn := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	served := make(chan error, 1)
	go func() { served <- edge.Serve(ctx, edgeConn) }()
	defer func() {
		sidecarConn.Close()
		<-served
		self.world.Wait()
	}()
	job := testTlsJob(flags)
	err := sidecar.WriteSmtpPreamble(sidecarConn, &protocol.SmtpPreamble{
		Version:          1,
		RecipientDomain:  job.Preamble.RecipientDomain,
		RecipientCount:   job.Preamble.RecipientCount,
		MessageId:        job.Preamble.MessageId,
		HeaderFromDomain: job.Preamble.HeaderFromDomain,
		MessageByteCount: job.Preamble.MessageByteCount,
		Flags:            flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sidecar.ReadSmtpPreambleResult(sidecarConn)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("the preamble: %+v", result)
	}
	authentication, err := policy.Authenticate(ctx, &sidecar.SmtpTlsRequest{
		RecipientDomain:   testTlsDomain,
		MxHost:            result.MxHost,
		DnssecChain:       result.DnssecChain,
		Flags:             flags,
		MessageTl4Domains: messageTl4Domains,
	})
	if err != nil {
		t.Fatal(err)
	}
	job.SendId = result.SendId
	job.Preamble.MxHost = result.MxHost
	job.Preamble.HeloName = result.HeloName
	job.Preamble.XUrRef = result.XUrRef
	job.Preamble.FeedbackId = result.FeedbackId
	job.VerifyPeer = authentication.VerifyPeer
	proofResult, err := sidecartest.NewFakeSmtpProver(nil).SendSmtp(ctx, sidecarConn, job, edge.ProofChannel(result.SendId))
	if proofResult != nil && proofResult.Mode != 0 {
		if err := authentication.RecordMode(sidecar.SmtpMode(proofResult.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	return &testTlsSend{result: result, authentication: authentication, proofResult: proofResult, err: err}
}

// What an MX has seen inside TLS: commands, and transactions taken.
func testTlsMxSaw(mx *sidecartest.ScriptedMx) (secureCommandCount int, transactionCount int) {
	for _, event := range mx.Events() {
		if event.Secure {
			secureCommandCount += 1
		}
	}
	return secureCommandCount, len(mx.Transactions())
}

// The send went at level and the MX took the message.
func testTlsExpectSent(t *testing.T, send *testTlsSend, level sidecar.SmtpTlsLevel) {
	t.Helper()
	if send.err != nil || send.proofResult == nil || !send.proofResult.Accepted {
		t.Fatalf("not sent: %+v %v (refusal %v)", send.proofResult, send.err, send.authentication.Refusal())
	}
	if got := send.authentication.Level(); got != level || send.authentication.Refusal() != nil {
		t.Errorf("level %d, want %d", got, level)
	}
}

// The send was refused inside the handshake for kind, and nothing reached mx after it.
func testTlsExpectRefused(t *testing.T, send *testTlsSend, kind sidecar.SmtpTlsRefusalKind, mx *sidecartest.ScriptedMx, secureBefore int) {
	t.Helper()
	refusal := send.authentication.Refusal()
	if refusal == nil || refusal.Kind != kind {
		t.Fatalf("refusal %+v, want kind %d", refusal, kind)
	}
	var asRefusal *sidecar.SmtpTlsRefusal
	if !errors.Is(send.err, sidecar.ErrSmtpTlsRefused) || !errors.As(send.err, &asRefusal) || asRefusal.Kind != kind {
		t.Errorf("SendSmtp's error: %v", send.err)
	}
	if send.authentication.Level() != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("a refused send recorded level %d", send.authentication.Level())
	}
	if secure, _ := testTlsMxSaw(mx); secure != secureBefore {
		t.Errorf("%d commands reached the MX inside TLS after a refusal", secure-secureBefore)
	}
}

func testTlsPinLevel(t *testing.T, world *testTlsWorld, host string) sidecar.SmtpTlsLevel {
	t.Helper()
	pin, err := sidecar.NewSmtpPinStore(world.store.Root(), world.settings, world.clock).Pin(host)
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		return sidecar.SmtpTlsLevelUnreached
	}
	return pin.Level
}

// TL1: a self-signed certificate no PKIX root vouches for, matched by TLSA under a chain the edge sent.
func TestSmtpTlsReachesTl1ByDane(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	certificate, err := sidecartest.NewMxCertificate(testTlsHost, false)
	if err != nil {
		t.Fatal(err)
	}
	mx := world.addMx(t, testTlsHost, testTlsAddress, &certificate, sidecartest.MxTlsaFor(certificate.Leaf))
	send := world.send(t, world.edge(nil), world.policy(), 0)
	testTlsExpectSent(t, send, sidecar.SmtpTlsLevelDane)
	if len(send.result.DnssecChain) == 0 {
		t.Error("the honest edge sent no chain")
	}
	if _, transactions := testTlsMxSaw(mx); transactions != 1 {
		t.Errorf("%d transactions", transactions)
	}
	if level := testTlsPinLevel(t, world, testTlsHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("pin %d", level)
	}
	if label := send.authentication.Level().Label(); label != "" {
		t.Errorf("TL1 labeled %q", label)
	}
}

// TL2: an enforced policy the device fetched itself lists the MX, and PKIX holds; the zone is unsigned,
// so no chain could give TL1.
func TestSmtpTlsReachesTl2ByAnEnforcedPolicy(t *testing.T) {
	world := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost))
	world.publishPolicy(t, "20261108", testTlsPolicy)
	send := world.send(t, world.edge(nil), world.policy(), 0)
	testTlsExpectSent(t, send, sidecar.SmtpTlsLevelMtaSts)
	if level := testTlsPinLevel(t, world, testTlsHost); level != sidecar.SmtpTlsLevelMtaSts {
		t.Errorf("pin %d", level)
	}
}

// TL3: no TLSA and no policy, and the device's own MX lookup agrees with the edge, with PKIX for the
// host. The mode the session chose is kept for Check.
func TestSmtpTlsReachesTl3ByTheDevicesOwnMxLookup(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost))
	send := world.send(t, world.edge(nil), world.policy(), 0)
	testTlsExpectSent(t, send, sidecar.SmtpTlsLevelIndependentMx)
	pins := sidecar.NewSmtpPinStore(world.store.Root(), world.settings, world.clock)
	if mode, err := pins.DomainMode(testTlsDomain); err != nil || mode != sidecar.SmtpModeBdat {
		t.Errorf("the domain's mode: %d %v", mode, err)
	}
}

// TL4 is refused with a DSN reason; AllowUnauthenticated cannot yet allow it, holding on its question;
// and the message's own approval, from a verified outbox entry, lets it go, labeled EX4 (I-11).
func TestSmtpTlsReachesTl4OnlyByAnApproval(t *testing.T) {
	world := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	mx := world.addMx(t, testTlsHost, testTlsAddress, nil)
	policy := world.policy()

	send := world.send(t, world.edge(nil), policy, 0)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalUnauthenticated, mx, 0)
	refusal := send.authentication.Refusal()
	if refusal.Level != sidecar.SmtpTlsLevelUnauthenticated || refusal.DowngradeRefused() || send.authentication.DowngradeRefused() {
		t.Errorf("%+v", refusal)
	}
	if reason := refusal.Reason(); !strings.Contains(reason, "could not be authenticated") || !strings.Contains(reason, "not been allowed") ||
		strings.Contains(reason, testTlsDomain) || strings.Contains(reason, testTlsHost) {
		t.Errorf("the DSN's reason: %q", reason)
	}
	if sidecar.SmtpTlsRefusalStatus != "5.7.10" {
		t.Errorf("status %q", sidecar.SmtpTlsRefusalStatus)
	}
	if strings.Contains(refusal.Error(), testTlsDomain) || strings.Contains(refusal.Error(), testTlsHost) {
		t.Errorf("the error names a name: %q", refusal.Error())
	}

	err := policy.AllowUnauthenticated(context.Background(), testTlsDomain, nil)
	if !errors.Is(err, sidecar.ErrSmtpTlsAllowanceHeld) || !strings.Contains(err.Error(), "smtp-m9-06-tl4-allowance-action") {
		t.Errorf("the allowance: %v", err)
	}
	send = world.send(t, world.edge(nil), policy, 0)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalUnauthenticated, mx, 0)

	send = world.send(t, world.edge(nil), policy, 0, "other.example", "MAIL.example.")
	testTlsExpectSent(t, send, sidecar.SmtpTlsLevelUnauthenticated)
	if label := send.authentication.Level().Label(); label != "readable by an active URnetwork edge" {
		t.Errorf("label %q", label)
	}
	if _, transactions := testTlsMxSaw(mx); transactions != 1 {
		t.Errorf("%d transactions", transactions)
	}
}

// A malicious edge strips TLSA from a host pinned at TL1. The device still reaches TL3, PKIX holding, but
// that is below the pin: refused inside the handshake as a downgrade, no data sent, the pin unmoved.
// Ninety days on the pin has lapsed, and the same send goes at TL3, which is then the pin.
func TestSmtpTlsStrippedTlsaUnderATl1PinSendsNoData(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	certificate := world.pki.leaf(t, testTlsHost)
	mx := world.addMx(t, testTlsHost, testTlsAddress, certificate, sidecartest.MxTlsaFor(certificate.Leaf))
	policy := world.policy()
	testTlsExpectSent(t, world.send(t, world.edge(nil), policy, 0), sidecar.SmtpTlsLevelDane)
	secure, _ := testTlsMxSaw(mx)

	stripping := world.edge(&testStrippingResolver{SmtpMxResolver: world.world})
	send := world.send(t, stripping, policy, 0)
	if len(send.result.DnssecChain) != 0 {
		t.Fatal("the stripping edge sent a chain")
	}
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalBelowPin, mx, secure)
	refusal := send.authentication.Refusal()
	if refusal.Level != sidecar.SmtpTlsLevelIndependentMx || refusal.PinLevel != sidecar.SmtpTlsLevelDane || !send.authentication.DowngradeRefused() {
		t.Errorf("%+v", refusal)
	}
	if _, transactions := testTlsMxSaw(mx); transactions != 1 {
		t.Errorf("%d transactions", transactions)
	}
	if level := testTlsPinLevel(t, world, testTlsHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("the refusal moved the pin to %d", level)
	}
	// a message allowed to go unauthenticated is still held to the pin
	secure, _ = testTlsMxSaw(mx)
	send = world.send(t, stripping, policy, 0, testTlsDomain)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalBelowPin, mx, secure)

	world.clock.Advance(world.settings.PinTimeout)
	testTlsExpectSent(t, world.send(t, stripping, policy, 0), sidecar.SmtpTlsLevelIndependentMx)
	if level := testTlsPinLevel(t, world, testTlsHost); level != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("after the lapse, pin %d", level)
	}
}

// The TL1 pin survives a restart: a new policy over the same store refuses the stripped send.
func TestSmtpTlsPinSurvivesARestart(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	certificate := world.pki.leaf(t, testTlsHost)
	mx := world.addMx(t, testTlsHost, testTlsAddress, certificate, sidecartest.MxTlsaFor(certificate.Leaf))
	testTlsExpectSent(t, world.send(t, world.edge(nil), world.policy(), 0), sidecar.SmtpTlsLevelDane)
	secure, _ := testTlsMxSaw(mx)
	send := world.send(t, world.edge(&testStrippingResolver{SmtpMxResolver: world.world}), world.policy(), 0)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalBelowPin, mx, secure)
}

// A malicious edge splices to a host of its own, with a valid certificate for that host's own name and no
// chain. The device's own MX lookup names another host, so TL3 fails, and with no allowance the send is
// refused before any byte of mail.
func TestSmtpTlsEdgeNamingAnotherHostIsRefused(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	honest := world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost))
	attacker := world.addMx(t, testTlsOtherHost, testTlsOtherAddress, world.pki.leaf(t, testTlsOtherHost))
	send := world.send(t, world.edge(&testLyingResolver{SmtpMxResolver: world.world, host: testTlsOtherHost}), world.policy(), 0)
	if send.result.MxHost != testTlsOtherHost {
		t.Fatalf("the edge named %s", send.result.MxHost)
	}
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalUnauthenticated, attacker, 0)
	if secure, transactions := testTlsMxSaw(honest); secure != 0 || transactions != 0 {
		t.Errorf("the honest MX saw %d commands", secure)
	}
}

// PKIX for a name that is not the MX's is no authentication: TL3 fails, and under an enforced policy
// listing the MX the MX is refused outright (RFC 8461 §5).
func TestSmtpTlsPkixForTheWrongNameIsRefused(t *testing.T) {
	world := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	mx := world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, "wrong.mail.example"))
	testTlsExpectRefused(t, world.send(t, world.edge(nil), world.policy(), 0), sidecar.SmtpTlsRefusalUnauthenticated, mx, 0)

	world.publishPolicy(t, "20261108", testTlsPolicy)
	send := world.send(t, world.edge(nil), world.policy(), 0, testTlsDomain)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalMtaSts, mx, 0)
	if send.authentication.Refusal().Level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("%+v", send.authentication.Refusal())
	}
}

// mode: testing is not TL2: a testing policy that does not list the MX refuses nothing, and the send goes
// at TL3. An enforced one that does not list it refuses it though TL3 would pass, and a message's own
// approval for TL4 does not reach past it.
func TestSmtpTlsOnlyAnEnforcedPolicyIsTl2(t *testing.T) {
	world := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	mx := world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost))
	world.publishPolicy(t, "testing1", "version: STSv1\nmode: testing\nmx: mx.backup.example\nmax_age: 86400\n")
	testTlsExpectSent(t, world.send(t, world.edge(nil), world.policy(), 0), sidecar.SmtpTlsLevelIndependentMx)

	enforced := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	mx = enforced.addMx(t, testTlsHost, testTlsAddress, enforced.pki.leaf(t, testTlsHost))
	enforced.publishPolicy(t, "enforce1", "version: STSv1\nmode: enforce\nmx: mx.backup.example\nmax_age: 86400\n")
	testTlsExpectRefused(t, enforced.send(t, enforced.edge(nil), enforced.policy(), 0, testTlsDomain), sidecar.SmtpTlsRefusalMtaSts, mx, 0)
}

// A validated TLSA RRset that matches nothing refuses the MX whatever else would pass: here an enforced
// policy listing it and a certificate PKIX vouches for (RFC 7672 §2.2, RFC 8461 §2).
func TestSmtpTlsDaneMismatchIsNotOverridden(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	other, _ := newTestDaneCertificate(t, testTlsHost, false, nil, nil, testTlsCertFrom, testTlsCertTo)
	mx := world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost), sidecartest.MxTlsaFor(other))
	world.publishPolicy(t, "20261108", testTlsPolicy)
	testTlsExpectRefused(t, world.send(t, world.edge(nil), world.policy(), 0, testTlsDomain), sidecar.SmtpTlsRefusalDaneMismatch, mx, 0)
}

// REQUIRETLS takes TL1 or TL2 only (plan-SMTP-small-readings#12): TL3 and an approved TL4 are refused,
// TL2 goes.
func TestSmtpTlsRequireTlsTakesOnlyTl1OrTl2(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	mx := world.addMx(t, testTlsHost, testTlsAddress, world.pki.leaf(t, testTlsHost))
	send := world.send(t, world.edge(nil), world.policy(), sidecar.SmtpFlagRequireTls)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalRequireTls, mx, 0)
	if send.authentication.Refusal().Level != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("%+v", send.authentication.Refusal())
	}

	unauthenticated := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	mx = unauthenticated.addMx(t, testTlsHost, testTlsAddress, nil)
	send = unauthenticated.send(t, unauthenticated.edge(nil), unauthenticated.policy(), sidecar.SmtpFlagRequireTls, testTlsDomain)
	testTlsExpectRefused(t, send, sidecar.SmtpTlsRefusalRequireTls, mx, 0)

	enforced := newTestTlsWorld(t, &sidecartest.MxWorldZoneOptions{Unsigned: true})
	enforced.addMx(t, testTlsHost, testTlsAddress, enforced.pki.leaf(t, testTlsHost))
	enforced.publishPolicy(t, "20261108", testTlsPolicy)
	testTlsExpectSent(t, enforced.send(t, enforced.edge(nil), enforced.policy(), sidecar.SmtpFlagRequireTls), sidecar.SmtpTlsLevelMtaSts)
}

// The TLS-level checks alone: a policy over the device DoH forwarder doh, and a check readied for
// mx.mail.example with no chain.
func newTestTlsCheck(t *testing.T, world *testTlsWorld, doh sidecar.SmtpDohForwarder, mxHost string) *sidecar.SmtpTlsAuthentication {
	t.Helper()
	pins := sidecar.NewSmtpPinStore(world.store.Root(), world.settings, world.clock)
	mtaSts := sidecar.NewSmtpMtaSts(doh, world.world.MtaStsTransport(), world.store.Root(), world.settings, world.clock)
	policy := sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(world.anchors, world.clock, nil), mtaSts, pins, doh, world.pki.roots, world.settings, world.clock)
	authentication, err := policy.Authenticate(context.Background(), &sidecar.SmtpTlsRequest{RecipientDomain: testTlsDomain, MxHost: mxHost})
	if err != nil {
		t.Fatal(err)
	}
	return authentication
}

// A DoH forwarder answering from a function.
type testDohForwarder func(qType dnsmessage.Type, domain string) ([]byte, bool)

func (self testDohForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	return self(qType, domain)
}

// A DoH response to (question, qType) with rcode and answers.
func testDohResponse(t *testing.T, question string, qType dnsmessage.Type, header dnsmessage.Header, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	header.Response = true
	builder := dnsmessage.NewBuilder(nil, header)
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(question + "."), Type: qType, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, answer := range answers {
		answer.Header.Class = dnsmessage.ClassINET
		var err error
		switch body := answer.Body.(type) {
		case *dnsmessage.MXResource:
			err = builder.MXResource(answer.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = builder.CNAMEResource(answer.Header, *body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	response, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testDohMx(owner string, host string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner + "."), Type: dnsmessage.TypeMX, TTL: 300},
		Body:   &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName(host + ".")},
	}
}

// TL3 reads only an answer to its own question: a failed, refused, truncated, malformed or foreign
// answer, a domain that does not exist and a null MX agree with nothing, so a PKIX-valid MX is refused
// as unauthenticated; a CNAME is followed, and a domain with no MX RRset is its own MX.
func TestSmtpTlsIndependentMxReadsOnlyItsOwnAnswer(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	chain := []*x509.Certificate{world.pki.leaf(t, testTlsHost).Leaf}
	for name, forward := range map[string]testDohForwarder{
		"unusable": func(qType dnsmessage.Type, domain string) ([]byte, bool) { return nil, false },
		"servfail": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, domain, qType, dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure}, testDohMx(domain, testTlsHost)), true
		},
		"nxdomain": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, domain, qType, dnsmessage.Header{RCode: dnsmessage.RCodeNameError}), true
		},
		"truncated": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, domain, qType, dnsmessage.Header{Truncated: true}, testDohMx(domain, testTlsHost)), true
		},
		"malformed": func(qType dnsmessage.Type, domain string) ([]byte, bool) { return []byte{0x00, 0x01, 0xff}, true },
		"another question": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, "other.example", qType, dnsmessage.Header{}, testDohMx("other.example", testTlsHost)), true
		},
		"another owner": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, domain, qType, dnsmessage.Header{}, testDohMx("other.example", testTlsHost)), true
		},
		"null mx": func(qType dnsmessage.Type, domain string) ([]byte, bool) {
			return testDohResponse(t, domain, qType, dnsmessage.Header{}, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(domain + "."), Type: dnsmessage.TypeMX, TTL: 300},
				Body:   &dnsmessage.MXResource{Pref: 0, MX: dnsmessage.MustNewName(".")},
			}), true
		},
	} {
		authentication := newTestTlsCheck(t, world, forward, testTlsHost)
		var refusal *sidecar.SmtpTlsRefusal
		if err := authentication.VerifyPeer(chain); !errors.As(err, &refusal) || refusal.Kind != sidecar.SmtpTlsRefusalUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}

	cname := testDohForwarder(func(qType dnsmessage.Type, domain string) ([]byte, bool) {
		if qType != dnsmessage.TypeMX {
			return nil, false
		}
		return testDohResponse(t, domain, qType, dnsmessage.Header{},
			dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(domain + "."), Type: dnsmessage.TypeCNAME, TTL: 300},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("hosted.other.example.")},
			},
			testDohMx("hosted.other.example", testTlsHost),
		), true
	})
	if err := newTestTlsCheck(t, world, cname, testTlsHost).VerifyPeer(chain); err != nil {
		t.Errorf("an MX behind a CNAME: %v", err)
	}

	implicit := newTestTlsWorld(t, nil)
	noMx := testDohForwarder(func(qType dnsmessage.Type, domain string) ([]byte, bool) {
		return testDohResponse(t, domain, qType, dnsmessage.Header{}), true
	})
	authentication := newTestTlsCheck(t, implicit, noMx, testTlsDomain)
	if err := authentication.VerifyPeer([]*x509.Certificate{implicit.pki.leaf(t, testTlsDomain).Leaf}); err != nil || authentication.Level() != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("the implicit MX: %d %v", authentication.Level(), err)
	}
	authentication = newTestTlsCheck(t, implicit, noMx, testTlsHost)
	if err := authentication.VerifyPeer(chain); !errors.Is(err, sidecar.ErrSmtpTlsRefused) {
		t.Errorf("another host where the domain has no MX: %v", err)
	}
}

// A DoH lookup that never answers ends at TlsLookupTimeout on the clock, and its level is then out of
// reach.
func TestSmtpTlsLookupThatHangsEndsAtItsTimeout(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	world.zone.Fail(testTlsDomain, dnsmessage.TypeMX, sidecartest.FakeMailZoneHang)
	world.zone.Fail("_mta-sts."+testTlsDomain, dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	done := make(chan *sidecar.SmtpTlsAuthentication, 1)
	go func() {
		authentication, err := world.policy().Authenticate(context.Background(), &sidecar.SmtpTlsRequest{RecipientDomain: testTlsDomain, MxHost: testTlsHost})
		if err != nil {
			t.Error(err)
		}
		done <- authentication
	}()
	guard, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := world.clock.AwaitTimers(guard, 2); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(world.settings.TlsLookupTimeout)
	authentication := <-done
	if authentication == nil {
		t.FailNow()
	}
	var refusal *sidecar.SmtpTlsRefusal
	if err := authentication.VerifyPeer([]*x509.Certificate{world.pki.leaf(t, testTlsHost).Leaf}); !errors.As(err, &refusal) || refusal.Kind != sidecar.SmtpTlsRefusalUnauthenticated {
		t.Errorf("%v", err)
	}
}

// A store that cannot answer holds the send: Authenticate fails on a pin file that does not parse, and a
// pin write that fails ends the handshake with the store's error, no level and no refusal recorded.
func TestSmtpTlsStoreThatCannotAnswerHoldsTheSend(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	writer, err := world.store.Root().Create("tls-pins")
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("not json"))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := world.policy().Authenticate(context.Background(), &sidecar.SmtpTlsRequest{RecipientDomain: testTlsDomain, MxHost: testTlsHost}); !errors.Is(err, sidecar.ErrSidecarStoreFailed) {
		t.Errorf("a pin file that does not parse: %v", err)
	}

	world = newTestTlsWorld(t, nil)
	authentication := newTestTlsCheck(t, world, world.zone, testTlsHost)
	world.store.FailWritesAfter(0)
	err = authentication.VerifyPeer([]*x509.Certificate{world.pki.leaf(t, testTlsHost).Leaf})
	if !errors.Is(err, sidecartest.ErrFakeStoreWriteFailed) || errors.Is(err, sidecar.ErrSmtpTlsRefused) {
		t.Errorf("a pin write that failed: %v", err)
	}
	if authentication.Level() != sidecar.SmtpTlsLevelUnreached || authentication.Refusal() != nil {
		t.Errorf("level %d, refusal %v", authentication.Level(), authentication.Refusal())
	}
}

// A connection's peer is checked once; a second call is refused and changes nothing.
func TestSmtpTlsVerifyPeerDecidesOnce(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	authentication := newTestTlsCheck(t, world, world.zone, testTlsHost)
	chain := []*x509.Certificate{world.pki.leaf(t, testTlsHost).Leaf}
	if err := authentication.VerifyPeer(chain); err != nil {
		t.Fatal(err)
	}
	if err := authentication.VerifyPeer(nil); err == nil || errors.Is(err, sidecar.ErrSmtpTlsRefused) {
		t.Errorf("a second check: %v", err)
	}
	if authentication.Level() != sidecar.SmtpTlsLevelIndependentMx || authentication.Refusal() != nil {
		t.Errorf("level %d, refusal %v", authentication.Level(), authentication.Refusal())
	}
}

// What the edge names is held to RFC 5321's Domain, and flags to the ones this version knows.
func TestSmtpTlsRequestIsHeldToItsForm(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	policy := world.policy()
	for _, request := range []*sidecar.SmtpTlsRequest{
		nil,
		{RecipientDomain: testTlsDomain, MxHost: "mx..mail.example"},
		{RecipientDomain: testTlsDomain, MxHost: "mx.mail.example/25"},
		{RecipientDomain: "", MxHost: testTlsHost},
		{RecipientDomain: testTlsDomain, MxHost: testTlsHost, Flags: 8},
	} {
		if _, err := policy.Authenticate(context.Background(), request); !errors.Is(err, sidecar.ErrSmtpTlsRequest) {
			t.Errorf("%+v: %v", request, err)
		}
	}
	if err := policy.AllowUnauthenticated(context.Background(), "not a domain", nil); !errors.Is(err, sidecar.ErrSmtpTlsRequest) {
		t.Errorf("%v", err)
	}
}

// Only TL4 carries a label, EX4's (I-11).
func TestSmtpTlsLevelLabels(t *testing.T) {
	for level, want := range map[sidecar.SmtpTlsLevel]string{
		sidecar.SmtpTlsLevelUnreached:       "",
		sidecar.SmtpTlsLevelDane:            "",
		sidecar.SmtpTlsLevelMtaSts:          "",
		sidecar.SmtpTlsLevelIndependentMx:   "",
		sidecar.SmtpTlsLevelUnauthenticated: "readable by an active URnetwork edge",
	} {
		if got := level.Label(); got != want {
			t.Errorf("level %d: %q", level, got)
		}
	}
}

// A check whose context ended during its lookups answers the context's error, never a check that read
// the cut lookups as a domain with no policy and no MX.
func TestSmtpTlsEndedContextIsNoCheck(t *testing.T) {
	world := newTestTlsWorld(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if authentication, err := world.policy().Authenticate(ctx, &sidecar.SmtpTlsRequest{RecipientDomain: testTlsDomain, MxHost: testTlsHost}); !errors.Is(err, context.Canceled) {
		t.Errorf("%v %v", authentication, err)
	}
}
