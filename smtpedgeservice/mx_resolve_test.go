// MX resolution and the dial (SMTP-M9-12) on MxWorld: preference order, a failing first MX, null and
// implicit MX, the addresses the edge never dials, a bogus chain, a 421's back-off, an MX that offers no
// STARTTLS anywhere, and the dnssec_chain the sidecar validates to the root.

package smtpedgeservice_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A connector in an MX world, the world's sending address usable.
type mxWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	world     *sidecartest.MxWorld
	settings  *smtpedgeservice.SmtpEdgeSettings
	set       *smtpedgeservice.SmtpSendingSet
	quota     *smtpedgeservice.SmtpQuota
	connector *smtpedgeservice.TestMxConnector
}

func newMxWorld(t *testing.T) *mxWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	mxWorldSettings := sidecartest.DefaultMxWorldSettings()
	mxWorldSettings.Clock = clock
	world, err := sidecartest.NewMxWorld(mxWorldSettings)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.AddMx(testHeloName, testSendingAddress, nil); err != nil {
		t.Fatal(err)
	}
	world.SetPtr(testSendingAddress, testHeloName)
	settings := worldSettings()
	set := smtpedgeservice.NewSmtpSendingSet(ctx, settings, clock, host.Metrics, world, world, nil)
	t.Cleanup(set.Close)
	if err := set.AwaitChecks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	quota, err := smtpedgeservice.NewSmtpQuota(ctx, host.ServiceHost(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Breaker().Close)
	t.Cleanup(world.Wait)
	return &mxWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		world:     world,
		settings:  settings,
		set:       set,
		quota:     quota,
		connector: smtpedgeservice.NewTestMxConnector(settings, clock, world, world, set, quota.DestinationCaps()),
	}
}

// A ScriptedMx for host at address, by script (nil the default).
func (self *mxWorld) addMx(host string, address netip.Addr, script *sidecartest.MxScript) *sidecartest.ScriptedMx {
	self.t.Helper()
	mx, err := sidecartest.NewScriptedMx(host, script, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.world.AddMx(host, address, mx); err != nil {
		self.t.Fatal(err)
	}
	return mx
}

func (self *mxWorld) setMx(domain string, hosts ...*sidecar.SmtpMxHost) {
	self.t.Helper()
	if err := self.world.SetMx(domain, hosts...); err != nil {
		self.t.Fatal(err)
	}
}

// Connects to domain and expects code; on OK the connection is closed at the test's end.
func (self *mxWorld) connect(domain string, code protocol.SmtpPreambleCode) (*smtpedgeservice.TestMxConnection, time.Duration, string) {
	self.t.Helper()
	connection, got, retryAfter, reason := self.connector.Connect(self.ctx, domain, proLimits())
	if got != code {
		self.t.Fatalf("%s: answered %d (%s), want %d", domain, got, reason, code)
	}
	if connection != nil {
		self.t.Cleanup(func() {
			connection.Conn.Close()
			connection.Release()
		})
	}
	return connection, retryAfter, reason
}

func TestMxWalksInPreferenceOrder(t *testing.T) {
	m := newMxWorld(t)
	m.addMx("mxa.pref.example", netip.MustParseAddr("192.0.2.31"), nil)
	m.addMx("mxb.pref.example", netip.MustParseAddr("192.0.2.32"), nil)
	m.setMx("pref.example", &sidecar.SmtpMxHost{Preference: 20, Host: "mxb.pref.example"}, &sidecar.SmtpMxHost{Preference: 10, Host: "mxa.pref.example"})
	connection, _, _ := m.connect("pref.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if connection.MxHost != "mxa.pref.example" || connection.MxAddress != netip.MustParseAddr("192.0.2.31") {
		t.Fatalf("reached %s at %v", connection.MxHost, connection.MxAddress)
	}
	if connection.SendingAddress != testSendingAddress {
		t.Fatalf("sent from %v", connection.SendingAddress)
	}
	if !slices.Contains(connection.Keywords, "STARTTLS") {
		t.Fatalf("keywords %q", connection.Keywords)
	}
}

func TestMxFailingFirstFallsBackToTheNext(t *testing.T) {
	m := newMxWorld(t)
	// an address with no server refuses the dial
	if err := m.world.AddMx("mxa.fail.example", netip.MustParseAddr("192.0.2.41"), nil); err != nil {
		t.Fatal(err)
	}
	m.addMx("mxb.fail.example", netip.MustParseAddr("192.0.2.42"), nil)
	m.setMx("fail.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mxa.fail.example"}, &sidecar.SmtpMxHost{Preference: 20, Host: "mxb.fail.example"})
	connection, _, _ := m.connect("fail.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if connection.MxHost != "mxb.fail.example" {
		t.Fatalf("reached %s", connection.MxHost)
	}
	if dials := m.world.Dials(); len(dials) != 2 || dials[0] != netip.MustParseAddr("192.0.2.41") {
		t.Fatalf("dials %v", dials)
	}
}

func TestMxNullMxAnswersNoMx(t *testing.T) {
	m := newMxWorld(t)
	if err := m.world.SetNullMx("null.example"); err != nil {
		t.Fatal(err)
	}
	_, _, reason := m.connect("null.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX)
	if reason != "null_mx" {
		t.Fatalf("reason %q", reason)
	}
	m.connect("nowhere.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX)
	if dials := m.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
}

func TestMxImplicitMxIsTheDomainItself(t *testing.T) {
	m := newMxWorld(t)
	m.addMx("implicit.example", netip.MustParseAddr("192.0.2.51"), nil)
	connection, _, _ := m.connect("implicit.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if connection.MxHost != "implicit.example" {
		t.Fatalf("reached %s", connection.MxHost)
	}
}

func TestMxSkipsAddressesTheEdgeNeverDials(t *testing.T) {
	m := newMxWorld(t)
	// 198.51.100.0/24 stands for a range the edge refuses, an IPv6-only MX is never dialed
	m.addMx("refused.skip.example", netip.MustParseAddr("198.51.100.25"), nil)
	m.addMx("v6.skip.example", netip.MustParseAddr("2001:db8::25"), nil)
	m.addMx("public.skip.example", netip.MustParseAddr("192.0.2.61"), nil)
	m.setMx("skip.example",
		&sidecar.SmtpMxHost{Preference: 10, Host: "refused.skip.example"},
		&sidecar.SmtpMxHost{Preference: 20, Host: "v6.skip.example"},
		&sidecar.SmtpMxHost{Preference: 30, Host: "public.skip.example"},
	)
	connection, _, _ := m.connect("skip.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if connection.MxHost != "public.skip.example" {
		t.Fatalf("reached %s", connection.MxHost)
	}
	if dials := m.world.Dials(); len(dials) != 1 || dials[0] != netip.MustParseAddr("192.0.2.61") {
		t.Fatalf("dials %v", dials)
	}
	// with only what it never dials, a domain has no MX the edge can reach
	m.setMx("onlyrefused.example", &sidecar.SmtpMxHost{Preference: 10, Host: "refused.skip.example"})
	m.connect("onlyrefused.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX)
}

func TestMxDefaultRefusesSpecialRanges(t *testing.T) {
	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	for _, text := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "2001:db8::1"} {
		if _, err := smtpedgeservice.NewSmtpMxNetDialer(settings).DialMx(context.Background(), testSendingAddress, netip.MustParseAddr(text)); err == nil {
			t.Errorf("%s dialable", text)
		}
	}
}

func TestMxBogusChainAnswersTryLater(t *testing.T) {
	m := newMxWorld(t)
	if err := m.world.AddZone("bogus.example.", &sidecartest.MxWorldZoneOptions{BrokenDs: true}); err != nil {
		t.Fatal(err)
	}
	m.addMx("mx.bogus.example", netip.MustParseAddr("192.0.2.71"), nil)
	m.setMx("bogus.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.bogus.example"})
	_, _, reason := m.connect("bogus.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	if reason != "dns" {
		t.Fatalf("reason %q", reason)
	}
	if dials := m.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
}

func TestMxAByteAfterThe220FailsTheMx(t *testing.T) {
	m := newMxWorld(t)
	script := sidecartest.DefaultMxScript()
	script.AfterStartTls = []byte("250 injected\r\n")
	m.addMx("mx.inject.example", netip.MustParseAddr("192.0.2.81"), script)
	m.setMx("inject.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.inject.example"})
	m.connect("inject.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
}

func TestMx421BannerBacksTheMxOff(t *testing.T) {
	m := newMxWorld(t)
	m.addMx("mx.busy.example", netip.MustParseAddr("192.0.2.91"), &sidecartest.MxScript{Banner: "421 mx.busy.example busy"})
	m.setMx("busy.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.busy.example"})
	m.connect("busy.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	_, retryAfter, reason := m.connect("busy.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	if reason != "backoff" || retryAfter <= 0 || m.settings.MxBannerBackoffTimeout < retryAfter {
		t.Fatalf("reason %q, retry %v", reason, retryAfter)
	}
	if dials := m.world.Dials(); len(dials) != 1 {
		t.Fatalf("a backed-off MX dialed again: %v", dials)
	}
	m.clock.Advance(m.settings.MxBannerBackoffTimeout)
	m.connect("busy.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	if dials := m.world.Dials(); len(dials) != 2 {
		t.Fatalf("dials %v after the back-off", dials)
	}
}

func TestMxNoStartTlsAnywhereAnswersNoTls(t *testing.T) {
	m := newMxWorld(t)
	plain := &sidecartest.MxScript{NoStartTls: true, PreTlsKeywords: []string{"PIPELINING"}}
	m.addMx("mxa.plain.example", netip.MustParseAddr("192.0.2.101"), plain)
	m.addMx("mxb.plain.example", netip.MustParseAddr("192.0.2.102"), plain)
	m.setMx("plain.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mxa.plain.example"}, &sidecar.SmtpMxHost{Preference: 20, Host: "mxb.plain.example"})
	m.connect("plain.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS)
	// one MX without STARTTLS beside one that cannot be reached for now is worth a later try
	if err := m.world.AddMx("mxc.mixed.example", netip.MustParseAddr("192.0.2.103"), nil); err != nil {
		t.Fatal(err)
	}
	m.setMx("mixed.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mxa.plain.example"}, &sidecar.SmtpMxHost{Preference: 20, Host: "mxc.mixed.example"})
	m.connect("mixed.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
}

func TestMxChainValidatesToTheRoot(t *testing.T) {
	m := newMxWorld(t)
	mx, err := sidecartest.NewScriptedMx("mx.dane.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.world.AddMx("mx.dane.example", netip.MustParseAddr("192.0.2.111"), mx, sidecartest.MxTlsaFor(mx.Certificate())); err != nil {
		t.Fatal(err)
	}
	m.setMx("dane.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.dane.example"})
	connection, _, _ := m.connect("dane.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if len(connection.Chain) == 0 {
		t.Fatal("no chain")
	}
	anchors, err := sidecar.NewSmtpDnssecAnchors(m.world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := sidecar.ParseSmtpDnssecChain(connection.Chain, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := chain.Validate(anchors, m.clock.Now(), "dane.example", "mx.dane.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != sidecar.SmtpDnssecStatusTlsa || len(result.TlsaRecords) == 0 {
		t.Fatalf("status %d", result.Status)
	}
	// an unsigned zone gives no chain, so TL1 is not offered
	if err := m.world.AddZone("plainzone.example.", &sidecartest.MxWorldZoneOptions{Unsigned: true}); err != nil {
		t.Fatal(err)
	}
	m.addMx("mx.plainzone.example", netip.MustParseAddr("192.0.2.112"), nil)
	m.setMx("plainzone.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.plainzone.example"})
	unsigned, _, _ := m.connect("plainzone.example", protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if len(unsigned.Chain) != 0 {
		t.Fatal("a chain for an unsigned zone")
	}
}

func TestMxDestinationConcurrencyHoldsTheDial(t *testing.T) {
	m := newMxWorld(t)
	m.addMx("mx.cap.example", netip.MustParseAddr("192.0.2.121"), nil)
	m.setMx("cap.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.cap.example"})
	limits := proLimits()
	limits.Limits[smtpedgeservice.SmtpLimitDestinationConcurrency] = 1
	first, code, _, _ := m.connector.Connect(m.ctx, "cap.example", limits)
	if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		t.Fatalf("answered %d", code)
	}
	if _, code, _, reason := m.connector.Connect(m.ctx, "cap.example", limits); code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER || reason != "no_sending_address" {
		t.Fatalf("a second dial to one /24 answered %d %q", code, reason)
	}
	first.Conn.Close()
	first.Release()
	second, code, _, _ := m.connector.Connect(m.ctx, "cap.example", limits)
	if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		t.Fatalf("after a release answered %d", code)
	}
	second.Conn.Close()
	second.Release()
}
