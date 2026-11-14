//go:build !sidecar_http && !ios_extension

package sidecar_test

// The zone watch's mail half (DNS-M7-04; D-TRUST-9, §15.5's strict_chain, QD-145), T2. Mail hosts' MX, addresses and
// TLSA and DKIM selectors are watched on a fake DnsWatchResolver: an operator's change alarms, other receivers' TLSA
// does not. StrictChain runs over sidecartest.MxWorld's DNSSEC-OK answers, C20's stand-in, validated to the world's
// own root on its fake clock: true for a customer-signed chain holding this key, false for a URnetwork-zone host, a
// missing TLSA, a key mismatch, an unsigned zone, a broken chain, an SNI host a domain does not list, a spent budget
// and no forwarder.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testMailWatchRoot  = "zone.example."
	testMailWatchLabel = "lbl0000001"
	testMailWatchApex  = "lbl0000001.zone.example."
	testMailWatchHost  = "mx.lbl0000001.zone.example."
	testMailWatchTlsa  = "_25._tcp.mx.lbl0000001.zone.example."
	// URnetwork's platform zone in these worlds, beside the zone's root
	testMailWatchPlatform = "platform.example."
)

// When every world here signs and validates.
var testMailWatchTime = time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)

// A synthetic receiver key's SPKI SHA-256, and another receiver's.
var (
	testMailWatchSpki      = testMailWatchDigest("synthetic receiver key")
	testMailWatchOtherSpki = testMailWatchDigest("synthetic other receiver key")
)

func testMailWatchDigest(text string) []byte {
	digest := sha256.Sum256([]byte(text))
	return digest[:]
}

// A TLSA 3 1 1 record of spki as the watch reads one.
func testMailWatchTlsaValue(spki []byte) string {
	return "3 1 1 " + strings.ToUpper(hex.EncodeToString(spki))
}

// Two resolvers that answer alike from one table, counting the questions.
type testMailWatchResolver struct {
	stateLock sync.Mutex
	answers   map[string]*sidecar.DnsWatchAnswer
	asked     map[string]int
}

func newTestMailWatchResolver() *testMailWatchResolver {
	return &testMailWatchResolver{answers: map[string]*sidecar.DnsWatchAnswer{}, asked: map[string]int{}}
}

func testMailWatchKey(name string, qType uint16) string {
	return name + " " + strconv.Itoa(int(qType))
}

func (self *testMailWatchResolver) set(name string, qType uint16, values ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers[testMailWatchKey(name, qType)] = &sidecar.DnsWatchAnswer{Values: append([]string{}, values...)}
}

func (self *testMailWatchResolver) setCname(name string, qType uint16, target string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers[testMailWatchKey(name, qType)] = &sidecar.DnsWatchAnswer{Cname: target, Values: []string{}}
}

func (self *testMailWatchResolver) askedCount(name string, qType uint16) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.asked[testMailWatchKey(name, qType)]
}

func (self *testMailWatchResolver) ResolverCount() int {
	return 2
}

func (self *testMailWatchResolver) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*sidecar.DnsWatchAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := testMailWatchKey(name, qType)
	self.asked[key] += 1
	answer, ok := self.answers[key]
	if !ok {
		return &sidecar.DnsWatchAnswer{Values: []string{}}, nil
	}
	copied := *answer
	copied.Values = append([]string{}, answer.Values...)
	return &copied, nil
}

// A watch over resolver for the zone lbl0000001.zone.example., which shows recordSets, with strict as its validator,
// every alarm kept in the answer's slice.
func newTestMailWatch(t *testing.T, resolver sidecar.DnsWatchResolver, strict sidecar.DnsWatchStrictValidator, clock sidecar.Clock, recordSets ...sidecar.DnsZoneRecordSet) (*sidecar.DnsWatch, func() []sidecar.SidecarDnsAlarm) {
	t.Helper()
	return newTestMailWatchUnder(t, testMailWatchRoot, []string{testMailWatchPlatform}, resolver, strict, clock, recordSets...)
}

// newTestMailWatch's watch with the zone under root and platform as URnetwork's other zones.
func newTestMailWatchUnder(t *testing.T, root string, platform []string, resolver sidecar.DnsWatchResolver, strict sidecar.DnsWatchStrictValidator, clock sidecar.Clock, recordSets ...sidecar.DnsZoneRecordSet) (*sidecar.DnsWatch, func() []sidecar.SidecarDnsAlarm) {
	t.Helper()
	var alarmLock sync.Mutex
	alarms := []sidecar.SidecarDnsAlarm{}
	zone := &sidecar.DnsZone{NetworkId: sidecar.NewId(), Root: root, Label: testMailWatchLabel, Version: 7, RecordSets: recordSets}
	settings := sidecar.DefaultDnsWatchSettings()
	settings.UrnetworkZones = platform
	watch, err := sidecar.NewDnsWatch(context.Background(), &sidecar.DnsWatchArgs{
		Resolver: resolver,
		Store:    sidecartest.NewFakeStore().Root(),
		Zone: func(ctx context.Context) (*sidecar.DnsZone, error) {
			return zone, nil
		},
		PublishedHosts: func() []string { return nil },
		Event: func(event sidecar.SidecarEvent) {
			alarmLock.Lock()
			defer alarmLock.Unlock()
			if event.Kind == sidecar.SidecarEventDnsAlarm {
				alarms = append(alarms, event.DnsAlarm)
			}
		},
		Settings: settings,
		Clock:    clock,
		Strict:   strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	return watch, func() []sidecar.SidecarDnsAlarm {
		alarmLock.Lock()
		defer alarmLock.Unlock()
		return append([]sidecar.SidecarDnsAlarm{}, alarms...)
	}
}

// What the resolvers answer for a mail host served by this receiver and one other: the apex's and the wildcard's MX,
// the host's addresses, and both receivers' TLSA.
func testMailWatchHealthy(resolver *testMailWatchResolver) {
	resolver.set(testMailWatchApex, sidecar.DnsWatchTypeMx, "10 "+testMailWatchHost)
	resolver.set("*."+testMailWatchApex, sidecar.DnsWatchTypeMx, "10 "+testMailWatchHost)
	resolver.set(testMailWatchHost, sidecar.DnsWatchTypeA, "192.0.2.25", "192.0.2.26")
	resolver.set(testMailWatchHost, sidecar.DnsWatchTypeAaaa, "2001:db8::25")
	resolver.set(testMailWatchTlsa, sidecar.DnsWatchTypeTlsa, testMailWatchTlsaValue(testMailWatchOtherSpki), testMailWatchTlsaValue(testMailWatchSpki))
}

// A watched mail host passes on the router's addresses, the MX naming it and its TLSA holding this receiver's record
// beside another receiver's, and alarms when the operator's side drops this receiver's record, points the MX
// elsewhere, or answers the host with a CNAME or no address.
func TestDnsWatchMailHostAlarmsOnAnOperatorChange(t *testing.T) {
	resolver := newTestMailWatchResolver()
	testMailWatchHealthy(resolver)
	watch, alarms := newTestMailWatch(t, resolver, nil, sidecartest.NewFakeClock(testMailWatchTime))
	if err := watch.WatchMailHost("mx", testMailWatchSpki); err != nil {
		t.Fatal(err)
	}
	if watch.Pass(context.Background()) || len(alarms()) != 0 {
		t.Fatalf("a healthy mail host alarmed: %v", alarms())
	}
	for _, key := range []struct {
		name  string
		qType uint16
	}{
		{name: testMailWatchApex, qType: sidecar.DnsWatchTypeMx},
		{name: "*." + testMailWatchApex, qType: sidecar.DnsWatchTypeMx},
		{name: testMailWatchHost, qType: sidecar.DnsWatchTypeA},
		{name: testMailWatchHost, qType: sidecar.DnsWatchTypeAaaa},
		{name: testMailWatchHost, qType: sidecar.DnsWatchTypeCaa},
		{name: testMailWatchTlsa, qType: sidecar.DnsWatchTypeTlsa},
	} {
		if resolver.askedCount(key.name, key.qType) == 0 {
			t.Errorf("%s %d was not asked", key.name, key.qType)
		}
	}

	cases := []struct {
		name   string
		change func()
		alarm  sidecar.SidecarDnsAlarm
	}{
		{name: "this receiver's TLSA dropped", change: func() {
			resolver.set(testMailWatchTlsa, sidecar.DnsWatchTypeTlsa, testMailWatchTlsaValue(testMailWatchOtherSpki))
		}, alarm: sidecar.SidecarDnsAlarmUnrequested},
		{name: "the MX pointed elsewhere", change: func() {
			resolver.set(testMailWatchApex, sidecar.DnsWatchTypeMx, "10 mx.elsewhere.example.")
		}, alarm: sidecar.SidecarDnsAlarmUnrequested},
		{name: "the burner wildcard's MX pointed elsewhere", change: func() {
			resolver.set("*."+testMailWatchApex, sidecar.DnsWatchTypeMx, "10 mx.elsewhere.example.")
		}, alarm: sidecar.SidecarDnsAlarmUnrequested},
		{name: "the host a CNAME", change: func() {
			resolver.setCname(testMailWatchHost, sidecar.DnsWatchTypeA, "mx.elsewhere.example.")
		}, alarm: sidecar.SidecarDnsAlarmZoneMismatch},
		{name: "the host with no address", change: func() {
			resolver.set(testMailWatchHost, sidecar.DnsWatchTypeAaaa)
		}, alarm: sidecar.SidecarDnsAlarmZoneMismatch},
		{name: "a CAA at the host", change: func() {
			resolver.set(testMailWatchHost, sidecar.DnsWatchTypeCaa, "0 issue ca.example")
		}, alarm: sidecar.SidecarDnsAlarmUnrequested},
	}
	for _, c := range cases {
		testMailWatchHealthy(resolver)
		resolver.set(testMailWatchHost, sidecar.DnsWatchTypeCaa)
		before := len(alarms())
		c.change()
		if !watch.Pass(context.Background()) {
			t.Errorf("%s: no alarm", c.name)
			continue
		}
		if got := alarms(); len(got) != before+1 || got[before] != c.alarm {
			t.Errorf("%s: alarms %v, want one %s", c.name, got[before:], c.alarm)
		}
	}
}

// Where the device may see the TLSA RRset in GET /dns/zone, a record the zone does not hold alarms, beside this
// receiver's own.
func TestDnsWatchMailHostTlsaHeldToTheZoneWhereTheDeviceSeesIt(t *testing.T) {
	resolver := newTestMailWatchResolver()
	testMailWatchHealthy(resolver)
	watch, alarms := newTestMailWatch(t, resolver, nil, sidecartest.NewFakeClock(testMailWatchTime),
		sidecar.DnsZoneRecordSet{Name: testMailWatchTlsa, Type: "TLSA", Ttl: 300, Kind: "key", Values: []string{
			testMailWatchTlsaValue(testMailWatchSpki), testMailWatchTlsaValue(testMailWatchOtherSpki),
		}})
	if err := watch.WatchMailHost("mx", testMailWatchSpki); err != nil {
		t.Fatal(err)
	}
	if watch.Pass(context.Background()) || len(alarms()) != 0 {
		t.Fatalf("the zone's two keys alarmed: %v", alarms())
	}
	forged := testMailWatchTlsaValue(testMailWatchDigest("synthetic forged key"))
	resolver.set(testMailWatchTlsa, sidecar.DnsWatchTypeTlsa, testMailWatchTlsaValue(testMailWatchSpki), testMailWatchTlsaValue(testMailWatchOtherSpki), forged)
	if !watch.Pass(context.Background()) || len(alarms()) != 1 || alarms()[0] != sidecar.SidecarDnsAlarmZoneMismatch {
		t.Fatalf("a TLSA the zone does not hold: %v", alarms())
	}
}

// A scope's mail host is watched under <scope>, a host that is no mail host is refused, and an unwatched host is
// asked no more.
func TestDnsWatchMailHostOfAScopeAndUnwatched(t *testing.T) {
	resolver := newTestMailWatchResolver()
	scopeDomain := "sales." + testMailWatchApex
	scopeHost := "mx." + scopeDomain
	resolver.set(scopeDomain, sidecar.DnsWatchTypeMx, "10 "+scopeHost)
	resolver.set("*."+scopeDomain, sidecar.DnsWatchTypeMx, "10 "+scopeHost)
	resolver.set(scopeHost, sidecar.DnsWatchTypeA, "192.0.2.27")
	resolver.set(scopeHost, sidecar.DnsWatchTypeAaaa, "2001:db8::27")
	resolver.set("_25._tcp."+scopeHost, sidecar.DnsWatchTypeTlsa, testMailWatchTlsaValue(testMailWatchSpki))
	watch, alarms := newTestMailWatch(t, resolver, nil, sidecartest.NewFakeClock(testMailWatchTime))
	for _, refused := range []string{"www", "mx.a.b", "mx.", "mx.-x", "mail"} {
		if err := watch.WatchMailHost(refused, testMailWatchSpki); !errors.Is(err, sidecar.ErrDnsWatchMailHost) {
			t.Errorf("%q: %v", refused, err)
		}
	}
	if err := watch.WatchMailHost("mx", testMailWatchSpki[:16]); !errors.Is(err, sidecar.ErrDnsWatchMailHost) {
		t.Errorf("a short key: %v", err)
	}
	if err := watch.WatchMailHost("MX.Sales", testMailWatchSpki); err != nil {
		t.Fatal(err)
	}
	if watch.Pass(context.Background()) || len(alarms()) != 0 {
		t.Fatalf("a scope's mail host alarmed: %v", alarms())
	}
	if resolver.askedCount("_25._tcp."+scopeHost, sidecar.DnsWatchTypeTlsa) == 0 || resolver.askedCount(scopeDomain, sidecar.DnsWatchTypeMx) == 0 {
		t.Fatalf("the scope's TLSA or MX was not asked")
	}
	if err := watch.UnwatchMailHost("mx.sales"); err != nil {
		t.Fatal(err)
	}
	asked := resolver.askedCount("_25._tcp."+scopeHost, sidecar.DnsWatchTypeTlsa)
	watch.Pass(context.Background())
	if resolver.askedCount("_25._tcp."+scopeHost, sidecar.DnsWatchTypeTlsa) != asked || watch.Status().NameCount != 0 {
		t.Errorf("an unwatched host is still asked: %+v", watch.Status())
	}
}

// A DKIM selector holds exactly the sender's record, a changed key alarms, and a retired selector alarms only while
// something is still there; Forget drops it.
func TestDnsWatchDkimSelectorHeldExactlyAndRetired(t *testing.T) {
	resolver := newTestMailWatchResolver()
	selector := "s1._domainkey." + testMailWatchApex
	record := "v=DKIM1; k=ed25519; p=c3ludGhldGljIGRraW0ga2V5"
	resolver.set(selector, sidecar.DnsWatchTypeTxt, record)
	watch, alarms := newTestMailWatch(t, resolver, nil, sidecartest.NewFakeClock(testMailWatchTime))
	if err := watch.WatchDkimSelector(selector, `"`+record+`"`); err != nil {
		t.Fatal(err)
	}
	if watch.Pass(context.Background()) || len(alarms()) != 0 {
		t.Fatalf("the sender's own selector alarmed: %v", alarms())
	}
	resolver.set(selector, sidecar.DnsWatchTypeTxt, "v=DKIM1; k=ed25519; p=Zm9yZ2VkIGRraW0ga2V5")
	if !watch.Pass(context.Background()) || len(alarms()) != 1 || alarms()[0] != sidecar.SidecarDnsAlarmUnrequested {
		t.Fatalf("a changed key: %v", alarms())
	}
	if err := watch.RetireDkimSelector(selector); err != nil {
		t.Fatal(err)
	}
	resolver.set(selector, sidecar.DnsWatchTypeTxt)
	if watch.Pass(context.Background()) || len(alarms()) != 1 {
		t.Fatalf("a retired selector gone: %v", alarms())
	}
	resolver.set(selector, sidecar.DnsWatchTypeTxt, record)
	if !watch.Pass(context.Background()) || len(alarms()) != 2 || alarms()[1] != sidecar.SidecarDnsAlarmUnrequested {
		t.Fatalf("a retired selector back: %v", alarms())
	}
	if err := watch.Forget(selector, sidecar.DnsWatchTypeTxt); err != nil {
		t.Fatal(err)
	}
	asked := resolver.askedCount(selector, sidecar.DnsWatchTypeTxt)
	if watch.Pass(context.Background()) || resolver.askedCount(selector, sidecar.DnsWatchTypeTxt) != asked {
		t.Errorf("a forgotten selector is still asked")
	}
}

// The default URnetwork zones are those holding the embedded host list's service hosts, read from the list, so no
// code names the platform.
func TestDnsWatchDefaultUrnetworkZonesComeFromTheHostList(t *testing.T) {
	list, err := sidecar.SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	zones := sidecar.DefaultDnsWatchSettings().UrnetworkZones
	if len(zones) == 0 {
		t.Fatalf("no platform zone")
	}
	for _, entry := range list.Hosts {
		if entry.Service == "" {
			continue
		}
		_, zone, _ := strings.Cut(entry.Host, ".")
		if !slices.Contains(zones, sidecar.CanonicalDnsRecordName(zone)) {
			t.Errorf("%s's zone is not among %v", entry.Host, zones)
		}
	}
}

// A world signed under its own root: URnetwork's root zone (the zone view's) and platform zone, and a customer whose
// signed zone lists one MX host whose TLSA holds this receiver's key.
type testStrictWorld struct {
	world   *sidecartest.MxWorld
	clock   *sidecartest.FakeClock
	anchors *sidecar.SmtpDnssecAnchors
}

func newTestStrictWorld(t *testing.T) *testStrictWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(testMailWatchTime)
	settings := sidecartest.DefaultMxWorldSettings()
	settings.Clock = clock
	world, err := sidecartest.NewMxWorld(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{testMailWatchRoot, testMailWatchPlatform, "customer.example."} {
		if err := world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	self := &testStrictWorld{world: world, clock: clock}
	self.mx(t, "customer.example", "mx.customer.example")
	self.host(t, "mx.customer.example", testMailWatchSpki)
	self.anchors, err = sidecar.NewSmtpDnssecAnchors(world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	return self
}

// domain's MX RRset, hosts by preference.
func (self *testStrictWorld) mx(t *testing.T, domain string, hosts ...string) {
	t.Helper()
	mxHosts := []*sidecar.SmtpMxHost{}
	for index, host := range hosts {
		mxHosts = append(mxHosts, &sidecar.SmtpMxHost{Preference: uint16(10 * (index + 1)), Host: host})
	}
	if err := self.world.SetMx(domain, mxHosts...); err != nil {
		t.Fatal(err)
	}
}

// An MX host with a TLSA 3 1 1 record of each key, or none.
func (self *testStrictWorld) host(t *testing.T, host string, spkis ...[]byte) {
	t.Helper()
	records := []*sidecar.SmtpTlsaRecord{}
	for _, spki := range spkis {
		records = append(records, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: spki})
	}
	if err := self.world.AddMx(host, netip.MustParseAddr("192.0.2.25"), nil, records...); err != nil {
		t.Fatal(err)
	}
}

// A watch whose validator fetches over forwarder under settings, nil for the defaults.
func (self *testStrictWorld) watch(t *testing.T, forwarder sidecar.DnsWatchDnssecForwarder, settings *sidecar.DnsWatchStrictSettings) *sidecar.DnsWatch {
	t.Helper()
	watch, _ := newTestMailWatch(t, newTestMailWatchResolver(), sidecar.NewDnsWatchStrictValidator(forwarder, self.anchors, settings), self.clock)
	return watch
}

// The world's answers, counted.
type testCountingForwarder struct {
	forwarder sidecar.DnsWatchDnssecForwarder
	count     atomic.Int64
}

func (self *testCountingForwarder) ForwardDnssec(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	self.count.Add(1)
	return self.forwarder.ForwardDnssec(ctx, qType, domain)
}

// A customer-signed chain holding this key holds: one domain, two domains through the one host, a domain whose second
// MX host is the customer's too, with a TLSA of another receiver's key, and a domain that is its own host.
func TestDnsWatchStrictChainHoldsForACustomerSignedChain(t *testing.T) {
	strict := newTestStrictWorld(t)
	for _, zone := range []string{"second.example.", "backup.example.", "self.example."} {
		if err := strict.world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	strict.mx(t, "second.example", "mx.customer.example")
	strict.mx(t, "backup.example", "mx.customer.example", "mx2.backup.example")
	strict.host(t, "mx2.backup.example", testMailWatchOtherSpki)
	strict.host(t, "self.example", testMailWatchSpki)
	forwarder := &testCountingForwarder{forwarder: strict.world}
	watch := strict.watch(t, forwarder, nil)
	ctx := context.Background()
	if !watch.StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki) {
		t.Fatalf("a customer-signed chain")
	}
	if forwarder.count.Load() == 0 || int64(sidecar.DefaultDnsWatchStrictSettings().QueryMaxCount) < forwarder.count.Load() {
		t.Errorf("%d queries", forwarder.count.Load())
	}
	if !watch.StrictChain(ctx, "MX.Customer.Example.", []string{"customer.example", "Second.Example"}, testMailWatchSpki) {
		t.Errorf("two domains through one host")
	}
	if !watch.StrictChain(ctx, "mx.customer.example", []string{"backup.example"}, testMailWatchSpki) {
		t.Errorf("a second customer MX host with its own receiver's key")
	}
	if !watch.StrictChain(ctx, "self.example", []string{"self.example"}, testMailWatchSpki) {
		t.Errorf("a domain that is its own host")
	}
}

// A host or domain in a URnetwork zone, the zone view's root or the platform zone, is never customer-signed, however
// well it validates.
func TestDnsWatchStrictChainFalseForAUrnetworkZoneHost(t *testing.T) {
	strict := newTestStrictWorld(t)
	for _, zone := range []string{"teamco.example.", "mixed.example."} {
		if err := strict.world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	strict.mx(t, "teamco.example", testMailWatchHost)
	strict.host(t, testMailWatchHost, testMailWatchSpki)
	strict.mx(t, "mixed.example", "mx.customer.example", "mx.platform.example")
	strict.host(t, "mx.platform.example", testMailWatchSpki)
	if err := strict.world.SetMx(testMailWatchApex, &sidecar.SmtpMxHost{Preference: 10, Host: "mx.customer.example"}); err != nil {
		t.Fatal(err)
	}
	watch := strict.watch(t, strict.world, nil)
	ctx := context.Background()
	if !watch.StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki) {
		t.Fatalf("the customer's own chain does not hold")
	}
	cases := []struct {
		name    string
		sni     string
		domains []string
	}{
		{name: "an MX host under the zone's root", sni: testMailWatchHost, domains: []string{"teamco.example"}},
		{name: "a second MX host in the platform zone", sni: "mx.customer.example", domains: []string{"mixed.example"}},
		{name: "a recipient domain under the zone's root", sni: "mx.customer.example", domains: []string{testMailWatchApex}},
	}
	for _, c := range cases {
		if watch.StrictChain(ctx, c.sni, c.domains, testMailWatchSpki) {
			t.Errorf("%s holds", c.name)
		}
	}
	// the control: under another root and with no platform zone, the same chains validate and hold, so only the
	// zones refused them
	elsewhere, _ := newTestMailWatchUnder(t, "elsewhere.example.", []string{"unrelated.example."}, newTestMailWatchResolver(),
		sidecar.NewDnsWatchStrictValidator(strict.world, strict.anchors, nil), strict.clock)
	if !elsewhere.StrictChain(ctx, testMailWatchHost, []string{"teamco.example"}, testMailWatchSpki) ||
		!elsewhere.StrictChain(ctx, "mx.customer.example", []string{"mixed.example"}, testMailWatchSpki) {
		t.Errorf("the control's chains do not hold")
	}
}

// No TLSA at the SNI host, or at another host the domain lists, leaves DANE out, so no claim.
func TestDnsWatchStrictChainFalseForAMissingTlsa(t *testing.T) {
	strict := newTestStrictWorld(t)
	for _, zone := range []string{"notlsa.example.", "halfway.example."} {
		if err := strict.world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	strict.mx(t, "notlsa.example", "mx.notlsa.example")
	strict.host(t, "mx.notlsa.example")
	strict.mx(t, "halfway.example", "mx.customer.example", "mx.halfway.example")
	strict.host(t, "mx.halfway.example")
	watch := strict.watch(t, strict.world, nil)
	ctx := context.Background()
	if watch.StrictChain(ctx, "mx.notlsa.example", []string{"notlsa.example"}, testMailWatchSpki) {
		t.Errorf("no TLSA at the SNI host holds")
	}
	if watch.StrictChain(ctx, "mx.customer.example", []string{"halfway.example"}, testMailWatchSpki) {
		t.Errorf("no TLSA at a second MX host holds")
	}
	// the control: once each host has its TLSA, both hold
	strict.host(t, "mx.notlsa.example", testMailWatchSpki)
	strict.host(t, "mx.halfway.example", testMailWatchOtherSpki)
	if !watch.StrictChain(ctx, "mx.notlsa.example", []string{"notlsa.example"}, testMailWatchSpki) ||
		!watch.StrictChain(ctx, "mx.customer.example", []string{"halfway.example"}, testMailWatchSpki) {
		t.Errorf("the control's chains do not hold")
	}
}

// The SNI host's TLSA holding only another key is no chain to this receiver.
func TestDnsWatchStrictChainFalseForAKeyMismatch(t *testing.T) {
	strict := newTestStrictWorld(t)
	if err := strict.world.AddZone("otherkey.example.", nil); err != nil {
		t.Fatal(err)
	}
	strict.mx(t, "otherkey.example", "mx.otherkey.example")
	strict.host(t, "mx.otherkey.example", testMailWatchOtherSpki)
	watch := strict.watch(t, strict.world, nil)
	ctx := context.Background()
	if watch.StrictChain(ctx, "mx.otherkey.example", []string{"otherkey.example"}, testMailWatchSpki) {
		t.Errorf("another receiver's key holds")
	}
	if watch.StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchOtherSpki) {
		t.Errorf("a key the TLSA does not name holds")
	}
	// the control: the receiver whose key it is holds
	if !watch.StrictChain(ctx, "mx.otherkey.example", []string{"otherkey.example"}, testMailWatchOtherSpki) {
		t.Errorf("the key the TLSA names does not hold")
	}
}

// An unsigned zone, the domain's or the host's, is not customer-signed; nor is a zone whose signatures expired, whose
// signing key is unpublished, or whose DS names no key.
func TestDnsWatchStrictChainFalseForAnUnsignedZoneOrABrokenChain(t *testing.T) {
	strict := newTestStrictWorld(t)
	zones := []struct {
		zone    string
		options *sidecartest.MxWorldZoneOptions
	}{
		{zone: "plain.example.", options: &sidecartest.MxWorldZoneOptions{Unsigned: true}},
		{zone: "plainhost.example.", options: &sidecartest.MxWorldZoneOptions{Unsigned: true}},
		{zone: "signed.example.", options: nil},
		{zone: "expired.example.", options: &sidecartest.MxWorldZoneOptions{ExpiredSignatures: true}},
		{zone: "wrongkey.example.", options: &sidecartest.MxWorldZoneOptions{WrongKey: true}},
		{zone: "brokends.example.", options: &sidecartest.MxWorldZoneOptions{BrokenDs: true}},
	}
	for _, zone := range zones {
		if err := strict.world.AddZone(zone.zone, zone.options); err != nil {
			t.Fatal(err)
		}
	}
	strict.mx(t, "plain.example", "mx.plain.example")
	strict.host(t, "mx.plain.example", testMailWatchSpki)
	strict.mx(t, "signed.example", "mx.plainhost.example")
	strict.host(t, "mx.plainhost.example", testMailWatchSpki)
	for _, broken := range []string{"expired", "wrongkey", "brokends"} {
		strict.mx(t, broken+".example", "mx."+broken+".example")
		strict.host(t, "mx."+broken+".example", testMailWatchSpki)
	}
	ctx := context.Background()
	cases := []struct {
		name   string
		sni    string
		domain string
		// a broken chain is fetched whole, MX, TLSA and every zone's keys and DS to the root's keys, so the
		// validator is what refuses it
		fetchedWhole bool
	}{
		{name: "an unsigned zone", sni: "mx.plain.example", domain: "plain.example"},
		{name: "a signed domain whose host's zone is unsigned", sni: "mx.plainhost.example", domain: "signed.example"},
		{name: "expired signatures", sni: "mx.expired.example", domain: "expired.example", fetchedWhole: true},
		{name: "an unpublished signing key", sni: "mx.wrongkey.example", domain: "wrongkey.example", fetchedWhole: true},
		{name: "a DS that names no key", sni: "mx.brokends.example", domain: "brokends.example", fetchedWhole: true},
	}
	for _, c := range cases {
		forwarder := &testCountingForwarder{forwarder: strict.world}
		if strict.watch(t, forwarder, nil).StrictChain(ctx, c.sni, []string{c.domain}, testMailWatchSpki) {
			t.Errorf("%s holds", c.name)
		}
		// MX, TLSA, the zone's DNSKEY and DS, example.'s, and the root's DNSKEY
		if c.fetchedWhole && forwarder.count.Load() != 7 {
			t.Errorf("%s: %d queries, not the whole chain's 7", c.name, forwarder.count.Load())
		}
	}
}

// Without a validator, or C20's forwarder, nothing holds; nor does an SNI host a domain does not list, a message
// with no recipient domain or more than the bound, a key that is no SHA-256, or a check past its query budget.
func TestDnsWatchStrictChainFalseWithoutAForwarderOrPastItsBounds(t *testing.T) {
	strict := newTestStrictWorld(t)
	if err := strict.world.AddZone("elsewhere.example.", nil); err != nil {
		t.Fatal(err)
	}
	strict.mx(t, "elsewhere.example", "mx.elsewhere.example")
	strict.host(t, "mx.elsewhere.example", testMailWatchSpki)
	ctx := context.Background()
	unattached, _ := newTestMailWatch(t, newTestMailWatchResolver(), nil, strict.clock)
	if unattached.StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki) {
		t.Errorf("a watch with no validator holds")
	}
	if strict.watch(t, nil, nil).StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki) {
		t.Errorf("a validator with no forwarder holds")
	}
	watch := strict.watch(t, strict.world, nil)
	if watch.StrictChain(ctx, "mx.customer.example", []string{"customer.example", "elsewhere.example"}, testMailWatchSpki) {
		t.Errorf("an SNI host one domain does not list holds")
	}
	if watch.StrictChain(ctx, "mx.customer.example", nil, testMailWatchSpki) {
		t.Errorf("no recipient domain holds")
	}
	if watch.StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki[:20]) {
		t.Errorf("a short key holds")
	}
	bounded := sidecar.DefaultDnsWatchStrictSettings()
	bounded.QueryMaxCount = 3
	forwarder := &testCountingForwarder{forwarder: strict.world}
	if strict.watch(t, forwarder, bounded).StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, testMailWatchSpki) {
		t.Errorf("a check past its query budget holds")
	}
	if 3 < forwarder.count.Load() {
		t.Errorf("%d queries past a budget of 3", forwarder.count.Load())
	}
	fewDomains := sidecar.DefaultDnsWatchStrictSettings()
	fewDomains.RecipientDomainMaxCount = 1
	if strict.watch(t, strict.world, fewDomains).StrictChain(ctx, "mx.customer.example", []string{"customer.example", "elsewhere.example"}, testMailWatchSpki) {
		t.Errorf("more domains than the bound holds")
	}
}
