//go:build !sidecar_http && !js && !ios_extension

package sidecar

// The zone watch's DoH resolver seam and its test guard (dns_watch_doh.go): outside a test binary the resolver builds
// a DohCache of its own over each url, the public ones by default, as production always has; in this test binary those
// urls are refused before any cache is built, nil settings included; a resolver on the forwarders its settings'
// ForwarderFactory gives asks each resolver's forwarder alone, through the same parsing, and releases them once at
// its Close; a watch over it judges each pass on those forwarders' answers alone, a split between them included; and a
// factory's refusals leave no resolver. Every name and address is synthetic, and no DohCache built here is asked a
// question.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// One question a forwarder was asked.
type testDnsWatchSeamQuestion struct {
	qType  dnsmessage.Type
	domain string
}

// One resolver's forwarder a test names: the addresses it holds at each name, given without its final dot, as A and
// AAAA answers, NODATA for any other name or type, every question kept, and nothing once released.
type testDnsWatchSeamForwarder struct {
	stateLock     sync.Mutex
	nameAddresses map[string][]netip.Addr
	questions     []testDnsWatchSeamQuestion
	released      bool
}

var _ DnsWatchForwarder = (*testDnsWatchSeamForwarder)(nil)

func newTestDnsWatchSeamForwarder() *testDnsWatchSeamForwarder {
	return &testDnsWatchSeamForwarder{nameAddresses: map[string][]netip.Addr{}}
}

// Holds addresses at name, lowercase with its final dot, as a watch names it, in place of what it held there.
func (self *testDnsWatchSeamForwarder) set(name string, addresses ...netip.Addr) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameAddresses[strings.TrimSuffix(name, ".")] = addresses
}

func (self *testDnsWatchSeamForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	addresses, released := func() ([]netip.Addr, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.released {
			return nil, true
		}
		self.questions = append(self.questions, testDnsWatchSeamQuestion{qType: qType, domain: domain})
		return slices.Clone(self.nameAddresses[domain]), false
	}()
	if released {
		return nil, false
	}
	reply := func() ([]byte, error) {
		name, err := dnsmessage.NewName(domain + ".")
		if err != nil {
			return nil, err
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess})
		if err := builder.StartQuestions(); err != nil {
			return nil, err
		}
		if err := builder.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET}); err != nil {
			return nil, err
		}
		if err := builder.StartAnswers(); err != nil {
			return nil, err
		}
		for _, address := range addresses {
			header := dnsmessage.ResourceHeader{Name: name, Type: qType, Class: dnsmessage.ClassINET, TTL: 60}
			switch {
			case qType == dnsmessage.TypeA && address.Is4():
				err = builder.AResource(header, dnsmessage.AResource{A: address.As4()})
			case qType == dnsmessage.TypeAAAA && address.Is6():
				err = builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: address.As16()})
			}
			if err != nil {
				return nil, err
			}
		}
		return builder.Finish()
	}
	response, err := reply()
	if err != nil {
		return nil, false
	}
	return response, true
}

// The questions asked so far, in the order they came.
func (self *testDnsWatchSeamForwarder) asked() []testDnsWatchSeamQuestion {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.questions)
}

// A ForwarderFactory over two forwarders of its own at each build, each build kept and each release counted.
type testDnsWatchSeamForwarders struct {
	stateLock     sync.Mutex
	built         [][]*testDnsWatchSeamForwarder
	releaseCounts []int
}

func (self *testDnsWatchSeamForwarders) factory() (*DnsWatchForwarders, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pair := []*testDnsWatchSeamForwarder{newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder()}
	index := len(self.built)
	self.built = append(self.built, pair)
	self.releaseCounts = append(self.releaseCounts, 0)
	return &DnsWatchForwarders{
		Forwarders: []DnsWatchForwarder{pair[0], pair[1]},
		Close: func() {
			for _, forwarder := range pair {
				func() {
					forwarder.stateLock.Lock()
					defer forwarder.stateLock.Unlock()
					forwarder.released = true
				}()
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.releaseCounts[index] += 1
		},
	}, nil
}

// The forwarder pairs built so far, and how many times each was released.
func (self *testDnsWatchSeamForwarders) snapshot() ([][]*testDnsWatchSeamForwarder, []int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.built), slices.Clone(self.releaseCounts)
}

// The defaults' settings naming factory.
func testDnsWatchSeamSettings(factory func() (*DnsWatchForwarders, error)) *DnsWatchDohSettings {
	settings := DefaultDnsWatchDohSettings()
	settings.ForwarderFactory = factory
	return settings
}

// Outside a test binary, the defaults build two DohCaches of the resolver's own, one a url of connect's default remote
// DoH servers, production's (§2.8 ext-3), released at its Close. Neither cache is asked anything. The defaults name no
// factory, and in this test binary the same urls, nil settings' and a test's own alike, are refused before any cache
// is built.
func TestDnsWatchDohResolverOutsideATestIsACacheAUrl(t *testing.T) {
	settings := DefaultDnsWatchDohSettings()
	if settings.ForwarderFactory != nil || settings.ResolverCount != 2 || len(settings.ResolverUrls) != 2 {
		t.Fatalf("the defaults: factory set %t, %d resolvers, urls %v", settings.ForwarderFactory != nil, settings.ResolverCount, settings.ResolverUrls)
	}
	resolver, err := newDnsWatchDohResolver(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if resolver.ResolverCount() != 2 || len(resolver.caches) != 2 || resolver.caches[0] == resolver.caches[1] {
		t.Fatalf("%d resolvers over %d caches", resolver.ResolverCount(), len(resolver.caches))
	}
	for index, forwarder := range resolver.forwarders {
		if cache, ok := forwarder.(*connect.DohCache); !ok || cache != resolver.caches[index] {
			t.Errorf("resolver %d forwards through %T", index, forwarder)
		}
	}
	if _, err := newDnsWatchDohResolver(settings, true); !errors.Is(err, ErrDnsWatchPublicResolver) {
		t.Errorf("the default urls in a test: %v", err)
	}
	if _, err := NewDnsWatchDohResolver(nil); !errors.Is(err, ErrDnsWatchPublicResolver) {
		t.Errorf("nil settings in this test binary: %v", err)
	}
	own := DefaultDnsWatchDohSettings()
	own.ResolverUrls = []string{"https://doh-a.test.example/dns-query", "https://doh-b.test.example/dns-query"}
	if _, err := NewDnsWatchDohResolver(own); !errors.Is(err, ErrDnsWatchPublicResolver) {
		t.Errorf("a test's own urls in this test binary: %v", err)
	}
}

// A resolver on the forwarders its settings' factory gives asks resolver i's forwarder alone, through the same parsing
// a cache's answers take, so each answer is that forwarder's own. One pair was built, and Close releases it once,
// however often it is called, after which the forwarders answer nothing.
func TestDnsWatchDohResolverAsksTheForwardersItsSettingsName(t *testing.T) {
	forwarders := &testDnsWatchSeamForwarders{}
	resolver, err := NewDnsWatchDohResolver(testDnsWatchSeamSettings(forwarders.factory))
	if err != nil {
		t.Fatal(err)
	}
	built, releases := forwarders.snapshot()
	if len(built) != 1 || releases[0] != 0 || resolver.ResolverCount() != 2 {
		t.Fatalf("%d pairs built, released %v, %d resolvers", len(built), releases, resolver.ResolverCount())
	}
	pair := built[0]
	name := "shop.lbl0000001.root.example."
	pair[0].set(name, netip.MustParseAddr("192.0.2.44"))
	pair[1].set(name, netip.MustParseAddr("198.51.100.44"))
	for index, want := range []string{"192.0.2.44", "198.51.100.44"} {
		answer, err := resolver.Lookup(t.Context(), index, name, DnsWatchTypeA)
		if err != nil || answer.NameError || !slices.Equal(answer.Values, []string{want}) {
			t.Errorf("resolver %d: %+v %v", index, answer, err)
		}
	}
	question := testDnsWatchSeamQuestion{qType: dnsmessage.TypeA, domain: "shop.lbl0000001.root.example"}
	for index, forwarder := range pair {
		if asked := forwarder.asked(); !slices.Equal(asked, []testDnsWatchSeamQuestion{question}) {
			t.Errorf("forwarder %d was asked %v", index, asked)
		}
	}
	resolver.Close()
	resolver.Close()
	if _, releases := forwarders.snapshot(); releases[0] != 1 {
		t.Errorf("Close released the forwarders %d times", releases[0])
	}
	if _, err := resolver.Lookup(t.Context(), 0, name, DnsWatchTypeA); !errors.Is(err, errDnsWatchResolverFailed) {
		t.Errorf("a released forwarder answered: %v", err)
	}
}

// A zone watch over a factory's resolver judges each pass on its forwarders alone: both are asked every name and type
// the pass watches and nothing else, two that agree on the edge's addresses pass with no alarm, and one that answers
// another address alarms a split, asked once more first.
func TestDnsWatchOverAFactorysResolverAsksItsForwardersAlone(t *testing.T) {
	forwarders := &testDnsWatchSeamForwarders{}
	resolver, err := NewDnsWatchDohResolver(testDnsWatchSeamSettings(forwarders.factory))
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	built, _ := forwarders.snapshot()
	pair := built[0]
	for _, forwarder := range pair {
		forwarder.set(testDnsWatchHost, netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44"))
	}
	var alarmLock sync.Mutex
	alarms := []SidecarDnsAlarm{}
	zone := &DnsZone{
		NetworkId: NewId(),
		Root:      "root.example.",
		Label:     "lbl0000001",
		Version:   12,
		RecordSets: []DnsZoneRecordSet{
			{Name: testDnsWatchHost, Type: "A", Ttl: 60, Kind: "edge"},
			{Name: testDnsWatchHost, Type: "AAAA", Ttl: 60, Kind: "edge"},
		},
	}
	watch, err := NewDnsWatch(t.Context(), &DnsWatchArgs{
		Resolver: resolver,
		Store:    newTestDnsMemoryStore(),
		Zone: func(ctx context.Context) (*DnsZone, error) {
			return zone, nil
		},
		PublishedHosts: func() []string { return []string{testDnsWatchHost} },
		Event: func(event SidecarEvent) {
			alarmLock.Lock()
			defer alarmLock.Unlock()
			if event.Kind == SidecarEventDnsAlarm {
				alarms = append(alarms, event.DnsAlarm)
			}
		},
		Clock: newTokenTestClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()
	snapshotAlarms := func() []SidecarDnsAlarm {
		alarmLock.Lock()
		defer alarmLock.Unlock()
		return slices.Clone(alarms)
	}
	if watch.Pass(t.Context()) || len(snapshotAlarms()) != 0 || watch.Status().Degraded {
		t.Fatalf("a healthy pass: alarms %v, status %+v", snapshotAlarms(), watch.Status())
	}
	want := []testDnsWatchSeamQuestion{}
	for _, name := range []string{"shop.lbl0000001.root.example", "lbl0000001.root.example"} {
		for _, qType := range []uint16{DnsWatchTypeA, DnsWatchTypeAaaa, DnsWatchTypeCaa} {
			want = append(want, testDnsWatchSeamQuestion{qType: dnsmessage.Type(qType), domain: name})
		}
	}
	for index, forwarder := range pair {
		if asked := forwarder.asked(); !slices.Equal(asked, want) {
			t.Errorf("forwarder %d was asked %v, not %v", index, asked, want)
		}
	}
	pair[1].set(testDnsWatchHost, netip.MustParseAddr("198.51.100.66"), netip.MustParseAddr("2001:db8::44"))
	if !watch.Pass(t.Context()) || !slices.Equal(snapshotAlarms(), []SidecarDnsAlarm{SidecarDnsAlarmSplit}) {
		t.Errorf("a split between the forwarders: alarms %v", snapshotAlarms())
	}
}

// A factory's error comes back as it was given; forwarders that are none, not the settings' count, or one nil leave no
// resolver, released first; and a count that is not positive is refused before any factory is asked.
func TestDnsWatchDohResolverFactoryRefusals(t *testing.T) {
	refused := errors.New("the test's DNS is not up")
	if _, err := NewDnsWatchDohResolver(testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
		return nil, refused
	})); !errors.Is(err, refused) {
		t.Errorf("a factory's error came back as %v", err)
	}
	if _, err := NewDnsWatchDohResolver(testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
		return nil, nil
	})); !errors.Is(err, errInvalidSettings) {
		t.Errorf("no forwarders: %v", err)
	}
	for _, forwarders := range [][]DnsWatchForwarder{
		{newTestDnsWatchSeamForwarder()},
		{newTestDnsWatchSeamForwarder(), nil},
		{newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder()},
	} {
		releases := 0
		if _, err := NewDnsWatchDohResolver(testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
			return &DnsWatchForwarders{Forwarders: forwarders, Close: func() { releases += 1 }}, nil
		})); !errors.Is(err, errInvalidSettings) || releases != 1 {
			t.Errorf("%d forwarders: %v, released %d times", len(forwarders), err, releases)
		}
	}
	asked := 0
	settings := testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
		asked += 1
		return nil, nil
	})
	settings.ResolverCount = 0
	if _, err := NewDnsWatchDohResolver(settings); !errors.Is(err, errInvalidSettings) || asked != 0 {
		t.Errorf("no resolvers: %v, the factory asked %d times", err, asked)
	}
}
